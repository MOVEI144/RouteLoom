"""D03 lab provisioning: RLC1 document, benchcfg/benchsecret console client,
field-boot readback, and the LabProvisionBackend step orchestration.

`SetupConsole` mirrors sdkv1_board_setup.cpp's line contract (staged document
+ secrets, generation-bound commit, durable status readback). `FakeBoards`
stands in for the ROM probe/flash worker; `RecordingOffice` for the
routeloomctl provision-* family plus lab-inventory-import.
"""
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

from routeloom_meshviz import firmware_catalog as catalog
from routeloom_meshviz import provisioning as prov
from routeloom_meshviz.device import Identity, PortLeases
from routeloom_meshviz.provision_plan import ProvisionJob, ProvisionRunner
from routeloom_meshviz.scenario_driver import DeviceDriver
from routeloom_meshviz import scenario as sc
from types import SimpleNamespace

from test_provisioning import FakeConsole, FakeOffice
import pt4m_fixture


# --- console + board doubles ---------------------------------------------------


class SetupConsole(FakeConsole):
    """The D02 setup-console verbs on top of the D03a maintenance console."""

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.staged_doc = None
        self.staged_psk = None
        self.staged_usb = None
        self.staged_generation = None
        self.committed = None  # dict(generation,node,role,security,secrets_generation,fingerprint)
        self.secrets = None    # dict(generation,psk,usb,fingerprint)
        self.setup_lines = []

    def exchange(self, line: str) -> str:
        if line.startswith(('benchcfg ', 'benchsecret ')) or \
                line in ('benchcfg', 'benchsecret'):
            if self.locked:
                return 'ERR locked'
            return self._board(line)
        return super().exchange(line)

    def _board(self, line: str) -> str:
        self.setup_lines.append(line)
        tokens = line.split(' ')
        verb, sub = tokens[0], tokens[1] if len(tokens) > 1 else ''
        if sub == 'status':
            if verb == 'benchcfg':
                if self.committed is None:
                    return 'OK board=none'
                c = self.committed
                fp = c['fingerprint'] if c['secrets_generation'] else '-'
                return (f'OK board=committed generation={c["generation"]} '
                        f'node={c["node"]} role={c["role"]} security={c["security"]} '
                        f'secrets_generation={c["secrets_generation"]} fingerprint={fp}')
            if self.secrets is None:
                return 'OK secrets=none'
            s = self.secrets
            return (f'OK secrets=committed generation={s["generation"]} '
                    f'psk={s["psk"]} usb={s["usb"]} fingerprint={s["fingerprint"]}')
        if verb == 'benchsecret' and sub == 'stage':
            _, _, kind, generation, blob = tokens
            generation = int(generation)
            raw = bytes.fromhex(blob)
            if kind == 'psk':
                if len(raw) != 32:
                    return 'ERR invalid_argument'
                self.staged_psk = raw
            elif kind == 'usb':
                if not 1 <= len(raw) <= 63 or any(b < 0x21 or b > 0x7E for b in raw):
                    return 'ERR invalid_argument'
                self.staged_usb = raw
            else:
                return 'ERR invalid_argument'
            self.staged_generation = generation
            return f'OK staged kind={kind} generation={generation}'
        if verb != 'benchcfg':
            return 'ERR invalid_argument'
        if sub == 'stage':
            self.staged_doc = bytes.fromhex(tokens[2])
            return f'OK staged bytes={len(self.staged_doc)}'
        if sub == 'validate':
            if self.staged_doc is None:
                return 'ERR no_staged'
            doc = self.staged_doc
            node = f'{int.from_bytes(doc[8:16], "big"):016x}'
            role = 'bridge' if doc[23] == 1 else 'reference'
            security = 'devram' if doc[24] == 1 else 'member'
            return f'OK valid node={node} role={role} security={security}'
        if sub == 'commit':
            if self.staged_doc is None:
                return 'ERR no_staged'
            generation = int(tokens[2])
            doc = self.staged_doc
            secrets_gen = 0
            if self.staged_psk is not None or self.staged_usb is not None:
                if self.staged_generation != generation:
                    return 'ERR generation_mismatch'
                fp = hashlib.sha256(
                    b'fp' + generation.to_bytes(4, 'big') +
                    (self.staged_psk or b'') + (self.staged_usb or b'')).hexdigest()
                self.secrets = {
                    'generation': generation,
                    'psk': '1' if self.staged_psk is not None else '0',
                    'usb': '1' if self.staged_usb is not None else '0',
                    'fingerprint': fp,
                }
                secrets_gen = generation
            node = f'{int.from_bytes(doc[8:16], "big"):016x}'
            role = 'bridge' if doc[23] == 1 else 'reference'
            security = 'devram' if doc[24] == 1 else 'member'
            self.committed = {
                'generation': generation, 'node': node, 'role': role,
                'security': security, 'secrets_generation': secrets_gen,
                'fingerprint': self.secrets['fingerprint'] if self.secrets else '',
            }
            self.staged_doc = None
            return f'OK committed generation={generation} node={node}'
        return 'ERR invalid_argument'


class FakeBoards:
    """ROM probe/flash double; flash() records the plan, writes nothing."""

    def __init__(self, identity):
        self.identity = identity
        self.flashed = []
        self.leases = PortLeases()

    def probe(self, port):
        return self.identity

    def flash(self, port, plan):
        self.flashed.append((port, plan))
        return True


class RecordingOffice(FakeOffice):
    def __init__(self):
        super().__init__()
        self.imported = []

    def import_inventory(self, site_dir, node_id, role):
        self.imported.append((site_dir, node_id, role))
        return ''


# --- fixture helpers -----------------------------------------------------------


IDENTITY = Identity('esp32c3', '1', 'a0:85:e3:00:00:01', None,
                    '164020', 4 * 1024 * 1024, False, False)
APP_ELF_SHA = bytes(range(32)).hex()
APP_VERSION = 'd03-test'


def _image_bytes(project: bytes) -> bytes:
    """ESP image header + esp_app_desc_t as verify_bundle/packaging expect."""
    image = bytearray(512)
    image[0] = 0xe9
    image[2:4] = b'\x02\x2f'
    image[12:14] = (5).to_bytes(2, 'little')
    image[14] = 1
    image[15:17] = (1).to_bytes(2, 'little')
    image[17:19] = (199).to_bytes(2, 'little')
    image[32:36] = bytes.fromhex('3254cdab')
    image[48:48 + len(APP_VERSION)] = APP_VERSION.encode()
    image[80:80 + len(project)] = project
    image[176:208] = bytes.fromhex(APP_ELF_SHA)
    return bytes(image)


def _build_bundle(root: Path, name: str, *, role: str, console: bool,
                  security: str = 'DEV_RAM'):
    """Package a signed bundle for `role`; `console` marks the setup image."""
    build = root / f'build-{name}'
    pt4m_fixture.write_build(build, f'{role}.bin', _image_bytes(b'routeloom_boot'),
                             _image_bytes(f'routeloom_{role}'.encode()))
    (build / 'ram-report.json').write_text('{}')
    app = root / 'firmware' / name
    app.mkdir(parents=True)
    (app.parents[1] / 'LICENSE').write_text('test license')
    (app.parents[1] / 'NOTICE').write_text('test notice')
    sdkconfig = (
        'CONFIG_IDF_TARGET="esp32c3"\n'
        'CONFIG_PARTITION_TABLE_CUSTOM=y\n'
        'CONFIG_PARTITION_TABLE_FILENAME="partitions.csv"\n'
        'CONFIG_PARTITION_TABLE_OFFSET=0x8000\n'
        'CONFIG_PARTITION_TABLE_MD5=y\n'
        'CONFIG_BOOTLOADER_OFFSET_IN_FLASH=0x0\n'
        'CONFIG_ESPTOOLPY_FLASHMODE="dio"\n'
        'CONFIG_ESPTOOLPY_FLASHFREQ="80m"\n'
        'CONFIG_ESPTOOLPY_FLASHSIZE="4MB"\n'
        'CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y\n'
        f'CONFIG_ROUTELOOM_SECURITY_MODE_{security}=y\n'
        + ('CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE=y\n' if console else ''))
    (app / 'sdkconfig').write_text(sdkconfig)
    (app / 'partitions.csv').write_text(pt4m_fixture.PARTITIONS_CSV)
    key = root / 'private.pem'
    if not key.exists():
        import shutil
        shutil.copyfile(Path(__file__).resolve().parents[1] /
                        'packaging/dev-signing-key.pem', key)
    bundle = root / name
    catalog.package(app, build, bundle, key, 'esp32c3', role,
                    APP_VERSION, 'a' * 40, 'b' * 64)
    return bundle


def _site(root: Path) -> Path:
    """Minimal lab-site layout: spec next to the dir, keys + usb secret in it."""
    site = root / 'lab'
    (site / 'keys').mkdir(parents=True)
    (site / 'keys' / 'device-ca.key').write_bytes(b'\0' * 32)
    (site / 'usb-dev-secret.key').write_text('a' * 62)
    spec = {'format': 'routeloom-lab-site-spec-v1', 'site_id': '00000000000000aa',
            'device_ca_id': '00000000000000bb', 'site_ca_id': '00000000000000cc',
            'network_low32': '01020304', 'channel': 6,
            'gateways': ['0000000000000001']}
    (root / 'lab.lab-spec.json').write_text(json.dumps(spec))
    return site


def _boot_lines(*, node: int, kid: str, devcert_sha: str, gen: int = 1,
                mac: str = 'a085e3000001', fw: str = APP_VERSION,
                app_sha: str = APP_ELF_SHA):
    return [
        'I (96) boot: ESP-ROM esp32c3',
        f'I (512) sdkv1: sdkv1 identity: node={node} kid={kid} '
        f'devcert_sha256={devcert_sha} key_location=1 flags=0x02 anchors=1 '
        f'devcert=512B',
        f'I (530) boot: routeloom field boot: fw={fw} app_sha256={app_sha}',
        f'I (541) boot: board config: gen={gen} node=0x{node:x} '
        f'secrets_gen={gen} mac={mac}',
    ]


def _backend(tmp: Path, console, boards, office, boot_lines):
    site = _site(tmp)
    bundles = tmp / 'bundles'
    bundles.mkdir()
    _build_bundle(bundles, 'field-bench', role='bench_node', console=False)
    _build_bundle(bundles, 'setup-bench', role='bench_node', console=True)
    _build_bundle(bundles, 'field-bridge', role='bridge_node', console=False)
    _build_bundle(bundles, 'setup-bridge', role='bridge_node', console=True)
    backend = prov.LabProvisionBackend(
        site_dir=site, boards=boards, bundles_dir=bundles,
        office=office, link_factory=lambda port: console,
        boot_capture=lambda port: boot_lines(port))
    return backend


# --- tests ---------------------------------------------------------------------


class Rlc1Tests(unittest.TestCase):
    def test_document_layout(self):
        doc = prov.rlc1_document(
            node_id='0000000000000007', sta_mac='a0:85:e3:00:00:01',
            chip='esp32c3', role='bench', security='dev-ram', channel=6,
            network='01020304')
        self.assertEqual(len(doc), prov.RLC1_DOC_BYTES)
        self.assertEqual(doc[0:4], b'RLC1')
        self.assertEqual(doc[4], 1)
        self.assertEqual(int.from_bytes(doc[6:8], 'big'), 42)
        self.assertEqual(doc[8:16], (7).to_bytes(8, 'big'))
        self.assertEqual(doc[16:22], bytes.fromhex('a085e3000001'))
        self.assertEqual(tuple(doc[22:26]), (1, 2, 1, 6))
        self.assertEqual(doc[26:30], bytes.fromhex('01020304'))
        self.assertEqual(doc[30:38], b'\0' * 8)
        self.assertEqual(doc[38:42],
                         (zlib.crc32(doc[:38]) & 0xFFFFFFFF).to_bytes(4, 'big'))

    def test_document_rejects_bad_fields(self):
        base = dict(node_id='0000000000000007', sta_mac='a0:85:e3:00:00:01',
                    chip='esp32c3', role='bench', security='dev-ram',
                    channel=6, network='01020304')
        for bad in ({'channel': 0}, {'channel': 15}, {'chip': 'esp32'},
                    {'role': 'router'}, {'security': 'production'},
                    {'sta_mac': 'a0:85:e3'}):
            with self.subTest(bad=bad), self.assertRaises(prov.ProvisionError):
                prov.rlc1_document(**{**base, **bad})


class BenchConsoleTests(unittest.TestCase):
    def test_commit_sequence_and_readback(self):
        console = SetupConsole()
        doc = prov.rlc1_document(
            node_id='0000000000000007', sta_mac='a0:85:e3:00:00:01',
            chip='esp32c3', role='bench', security='dev-ram', channel=6,
            network='01020304')
        evidence = prov.board_config_commit(
            console, doc, generation=1, psk_hex='11' * 32)
        self.assertEqual(evidence['node'], '0000000000000007')
        self.assertEqual(evidence['generation'], 1)
        self.assertEqual(evidence['secrets_generation'], '1')
        self.assertEqual(console.staged_psk, bytes.fromhex('11' * 32))
        # Commands went in order: secret staged before the document commit.
        order = [line.split()[1] for line in console.setup_lines]
        self.assertEqual(order,
                         ['stage', 'stage', 'validate', 'commit', 'status',
                          'status'])

    def test_commit_without_needed_psk_still_commits_client_side(self):
        # The device refuses a DevRam config without secrets
        # (secrets_required); the client only stages what the caller passed.
        console = SetupConsole()
        doc = prov.rlc1_document(
            node_id='0000000000000007', sta_mac='a0:85:e3:00:00:01',
            chip='esp32c3', role='bench', security='dev-ram', channel=6,
            network='01020304')
        evidence = prov.board_config_commit(console, doc, generation=1)
        self.assertEqual(evidence['secrets_generation'], '0')

    def test_node_echo_mismatch_fails(self):
        class Lying(SetupConsole):
            def _board(self, line):
                reply = super()._board(line)
                if reply.startswith('OK committed'):
                    return reply.replace('node=', 'node=ff', 1)
                return reply
        console = Lying()
        doc = prov.rlc1_document(
            node_id='0000000000000007', sta_mac='a0:85:e3:00:00:01',
            chip='esp32c3', role='bench', security='dev-ram', channel=6,
            network='01020304')
        with self.assertRaises(prov.ProvisionError):
            prov.board_config_commit(console, doc, generation=1)


class FieldBootTests(unittest.TestCase):
    def test_parse_full_boot(self):
        kid = 'ab' * 32
        devcert = 'cd' * 32
        boot = prov.parse_field_boot(_boot_lines(node=7, kid=kid,
                                                 devcert_sha=devcert))
        self.assertEqual(boot.identity, 'sealed')
        self.assertEqual(boot.node, '0000000000000007')
        self.assertEqual(boot.kid, kid)
        self.assertEqual(boot.devcert_sha256, devcert)
        self.assertEqual(boot.fw, APP_VERSION)
        self.assertEqual(boot.app_sha256, APP_ELF_SHA)
        self.assertEqual(boot.config_node, '0000000000000007')
        self.assertEqual(boot.config_generation, 1)
        self.assertEqual(boot.secrets_generation, 1)
        self.assertEqual(boot.config_mac, 'a085e3000001')
        self.assertFalse(boot.config_required)

    def test_missing_markers_stay_none(self):
        boot = prov.parse_field_boot(['I (1) boot: hello'])
        self.assertIsNone(boot.identity)
        self.assertIsNone(boot.kid)
        self.assertIsNone(boot.config_generation)
        self.assertFalse(boot.config_required)

    def test_config_required_flagged(self):
        lines = _boot_lines(node=7, kid='ab' * 32, devcert_sha='cd' * 32)
        lines.append('E (700) boot: CONFIG_REQUIRED: board configuration required')
        self.assertTrue(prov.parse_field_boot(lines).config_required)

    def test_unprovisioned_identity(self):
        boot = prov.parse_field_boot(['sdkv1 identity: none provisioned'])
        self.assertEqual(boot.identity, 'none')


class LabBackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.console = SetupConsole()
        self.boards = FakeBoards(IDENTITY)
        self.office = RecordingOffice()
        self.boot = None  # set per test
        self.backend = _backend(self.tmp, self.console, self.boards,
                                self.office,
                                lambda port: self.boot)

    def _job(self, role='bench', node='0000000000000007'):
        return ProvisionJob('/dev/ttyUSB0', 'esp32c3', IDENTITY.base_mac,
                            role, node, steps={'plan': 'done'})

    def _expected_boot(self, job):
        office = self.office
        issued = prov.Provisioner(
            self.backend._journals(), office)
        journal = prov.ProvisionJournal.load(
            self.backend._journals() / f'node-{job.node_id}.journal.json')
        kid = journal.latest('issued')['kid']
        devcert = journal.latest('issued')['devcert_sha256']
        return _boot_lines(node=int(job.node_id, 16), kid=kid,
                           devcert_sha=devcert)

    def test_full_bench_flow_reaches_ready(self):
        job = self._job()
        runner = ProvisionRunner(self.backend, [job])

        def capture(port):
            # The boot log can only name the issued identity after _issue ran.
            self.boot = self._expected_boot(job)
            return self.boot

        self.backend._boot_capture = capture
        runner.run_job(job)
        self.assertEqual(job.steps.get('readback'), 'done')
        self.assertTrue(job.ready)
        self.assertEqual(job.steps.get('inventory'), 'done')
        self.assertEqual(job.steps.get('join'), 'waiting')
        self.assertEqual(len(self.office.confirmed), 1)
        self.assertEqual(self.office.imported,
                         [(str(self.backend.site_dir), job.node_id, 'endpoint')])
        # The write happened twice: setup image, then the field image.
        self.assertEqual(len(self.boards.flashed), 2)
        self.assertEqual(len(self.boards.flashed[0][1].images), 4)
        self.assertEqual([image.offset for image in self.boards.flashed[1][1].images],
                         [0x10000, prov.APP_IMAGE_OFFSET])
        journal = prov.ProvisionJournal.load(
            self.backend._journals() / f'node-{job.node_id}.journal.json')
        self.assertTrue(journal.done)
        self.assertTrue(journal.has('board_config'))
        self.assertTrue(journal.has('field'))
        self.assertTrue(journal.has('written'))
        self.assertTrue(journal.has('inventory'))

    def test_scenario_provision_uses_readback_and_inventory(self):
        node = '0000000000000007'
        job = self._job(node=node)
        self.backend._boot_capture = lambda port: self._expected_boot(job)
        field = self.backend._bundle('field', job, IDENTITY.chip)['path']
        bundle = {
            'digest': 'sha256:' + hashlib.sha256(
                (field / 'manifest.json').read_bytes()).hexdigest(),
            'signature': json.loads((field / 'signature.json').read_text())['signature'],
        }
        nodes = {node: {'port': job.board, 'role': job.role,
                        'chip': job.chip, 'base_mac': job.base_mac}}
        driver = DeviceDriver(None, provision_backend=self.backend, nodes=nodes)
        scenario = sc.ScenarioRunner.arm({
            'schema': sc.SCHEMA, 'network': '0000000000000001',
            'nodes': nodes, 'steps': [
                {'kind': 'flash_provision', 'targets': [node], 'bundle': bundle}],
        }, self.tmp / 'scenario-journal', now_ms=0)
        call = scenario.due(0)[0]
        reply = driver.execute(call)
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(reply['result']['readback']['node'], node)
        self.assertEqual(reply['result']['inventory']['node'], node)
        self.assertEqual(len(self.office.imported), 1)
        self.assertEqual(len(self.boards.flashed), 2)
        scenario.on_reply(call.tag, reply, 1)
        scenario.due(2)
        self.assertEqual(scenario.state, 'Completed')
        self.assertEqual(scenario.steps[0].detail['provisioned'][0]['readback']['node'], node)
        self.assertTrue(any(entry.get('result', {}).get('readback', {}).get('node') == node
                            for entry in scenario.journal.entries))

        interrupted = sc.ScenarioRunner.arm(scenario.doc,
                                             self.tmp / 'interrupted', now_ms=0)
        pending = interrupted.due(0)[0]
        self.assertTrue(driver.execute(pending)['ok'])
        resumed = sc.ScenarioRunner.resume(
            sc.ScenarioJournal.load(interrupted.journal.path), now_ms=20_000,
            capacity={})
        receipt = driver.reconcile_provision(resumed.outstanding[pending.tag])
        self.assertTrue(receipt['ok'])
        resumed.on_reply(pending.tag, receipt, 20_001)
        resumed.due(20_002)
        self.assertEqual(resumed.state, 'Completed')
        self.assertEqual(len(self.boards.flashed), 2)

        other = dict(bundle, digest='sha256:' + '0' * 64)
        refused = driver.execute(SimpleNamespace(
            method='provision', params={'node': node, 'bundle': other}))
        self.assertFalse(refused['ok'])
        self.assertEqual(len(self.boards.flashed), 2)

        upper = 'ABCDEF0000000007'
        upper_driver = DeviceDriver(None, provision_backend=self.backend,
                                    nodes={upper: nodes[node]})
        refused = upper_driver.execute(SimpleNamespace(
            method='provision', params={'node': upper.lower(), 'bundle': other}))
        self.assertEqual(refused['error']['code'], 'PROVISION_INCOMPLETE')

    def test_readback_mismatch_never_reaches_inventory(self):
        job = self._job()
        self.boot = _boot_lines(node=int(job.node_id, 16), kid='00' * 32,
                                devcert_sha='11' * 32)
        ProvisionRunner(self.backend, [job]).run_job(job)
        self.assertEqual(job.steps.get('readback'), 'failed')
        self.assertFalse(job.ready)
        self.assertEqual(self.office.confirmed, [])
        self.assertEqual(self.office.imported, [])
        journal = prov.ProvisionJournal.load(
            self.backend._journals() / f'node-{job.node_id}.journal.json')
        self.assertFalse(journal.done)
        self.assertFalse(journal.has('written'))

    def test_inventory_failure_is_visible_after_readback(self):
        job = self._job()
        self.backend._boot_capture = lambda port: self._expected_boot(job)

        def reject_import(site_dir, node_id, role):
            raise prov.ProvisionError('inventory_failed', 'inventory import refused')

        self.office.import_inventory = reject_import
        ProvisionRunner(self.backend, [job]).run_job(job)
        self.assertTrue(job.ready)
        self.assertEqual(job.steps.get('inventory'), 'failed')
        self.assertIn('失敗', prov.job_status_text(job))

    def test_config_required_fails_readback(self):
        job = self._job()

        def capture(port):
            return self._expected_boot(job) + [
                'E (800) boot: CONFIG_REQUIRED: board identity mismatch']

        self.backend._boot_capture = capture
        ProvisionRunner(self.backend, [job]).run_job(job)
        self.assertEqual(job.steps.get('readback'), 'failed')
        self.assertFalse(job.ready)

    def test_foreign_identity_needs_attention(self):
        self.console.sealed = {'node': '0000000000000099', 'kid': 'ee' * 32,
                               'serial': 1, 'devcert_sha256': '0' * 64,
                               'fw': APP_VERSION}
        job = self._job()
        ProvisionRunner(self.backend, [job]).run_job(job)
        self.assertEqual(job.steps.get('status'), 'attention')
        self.assertFalse(job.ready)
        self.assertEqual(self.boards.flashed[0][0], '/dev/ttyUSB0')

    def test_bridge_stages_usb_secret(self):
        job = self._job(role='bridge', node='0000000000000001')
        self.boot = None

        def capture(port):
            return self._expected_boot(job)

        self.backend._boot_capture = capture
        ProvisionRunner(self.backend, [job]).run_job(job)
        self.assertTrue(job.ready)
        staged = [line for line in self.console.setup_lines
                  if line.startswith('benchsecret stage usb')]
        self.assertEqual(len(staged), 1)
        # The per-gateway HostLink secret, not the site-wide dev secret, and
        # the same bytes in the host's 0600 credential file.
        secret = bytes.fromhex(staged[0].split()[4]).decode()
        self.assertNotEqual(secret, 'a' * 62)
        credential = self.backend.site_dir / 'hostlink' / '0000000000000001.key'
        self.assertEqual(credential.read_text(), secret)
        self.assertEqual(credential.stat().st_mode & 0o777, 0o600)
        import base64
        self.assertEqual(len(base64.urlsafe_b64decode(secret + '=' * (-len(secret) % 4))), 32)
        self.assertEqual(self.office.imported[0][2], 'gateway')

    def test_hostlink_retry_refuses_invalid_existing_credential(self):
        directory = self.backend.site_dir / 'hostlink'
        directory.mkdir(mode=0o700)
        credential = directory / '0000000000000001.key'
        credential.write_text('short', encoding='ascii')
        credential.chmod(0o600)
        with self.assertRaises(prov.ProvisionError):
            self.backend._hostlink_secret('0000000000000001')
        credential.unlink()
        directory.chmod(0o755)
        with self.assertRaises(prov.ProvisionError):
            self.backend._hostlink_secret('0000000000000001')

    def test_hostlink_file_survives_short_write(self):
        write = os.write

        def short_write(fd, data):
            return write(fd, data[:7])

        with mock.patch.object(prov.os, 'write', side_effect=short_write):
            secret = self.backend._hostlink_secret('0000000000000002')
        credential = self.backend.site_dir / 'hostlink' / '0000000000000002.key'
        self.assertEqual(credential.read_text(encoding='ascii'), secret)

    def test_missing_bundles_fail_closed(self):
        job = self._job(role='bridge')  # C3 bridge bundles exist; try missing chip
        job = ProvisionJob('/dev/ttyUSB0', 'esp32s3', 'ff:ee:dd:cc:bb:aa',
                           'bench', '0000000000000009', steps={'plan': 'done'})
        boards = FakeBoards(Identity('esp32s3', '1', 'ff:ee:dd:cc:bb:aa', None,
                                   '164020', 4 * 1024 * 1024, False, False))
        backend = _backend(self.tmp / 'second', self.console, boards,
                           self.office, lambda port: [])
        result = backend.run('preflight', job)
        self.assertEqual(result.state, 'failed')
        self.assertIn('bundle', result.detail)

    def test_reference_bundles_serve_non_bridge_boards(self):
        site = _site(self.tmp / 'ref')
        bundles = self.tmp / 'ref' / 'bundles'
        bundles.mkdir()
        _build_bundle(bundles, 'field-ref', role='reference_node', console=False)
        _build_bundle(bundles, 'setup-ref', role='reference_node', console=True)
        backend = prov.LabProvisionBackend(
            site_dir=site, boards=self.boards, bundles_dir=bundles, office=self.office,
            link_factory=lambda port: self.console, boot_capture=lambda port: [])
        result = backend.run('preflight', self._job())
        self.assertEqual(result.state, 'done', result.detail)
        self.assertIn('reference_node', result.detail)

    def test_setup_security_must_match_field_before_flash(self):
        site = _site(self.tmp / 'mixed')
        bundles = self.tmp / 'mixed' / 'bundles'
        bundles.mkdir()
        _build_bundle(bundles, 'field-ref', role='reference_node', console=False,
                      security='MEMBER_EDHOC')
        _build_bundle(bundles, 'setup-ref', role='reference_node', console=True)
        backend = prov.LabProvisionBackend(
            site_dir=site, boards=self.boards, bundles_dir=bundles, office=self.office,
            link_factory=lambda port: self.console, boot_capture=lambda port: [])
        result = backend.run('preflight', self._job())
        self.assertEqual(result.state, 'failed')
        self.assertIn('security', result.detail)
        self.assertEqual(self.boards.flashed, [])

    def test_reference_setup_may_match_the_selected_field_security(self):
        site = _site(self.tmp / 'paired')
        bundles = self.tmp / 'paired' / 'bundles'
        bundles.mkdir()
        _build_bundle(bundles, 'field-bench-member', role='bench_node',
                      console=False, security='MEMBER_EDHOC')
        _build_bundle(bundles, 'setup-bench-devram', role='bench_node', console=True)
        _build_bundle(bundles, 'setup-ref-member', role='reference_node',
                      console=True, security='MEMBER_EDHOC')
        backend = prov.LabProvisionBackend(
            site_dir=site, boards=self.boards, bundles_dir=bundles, office=self.office,
            link_factory=lambda port: self.console, boot_capture=lambda port: [])
        job = self._job()
        result = backend.run('preflight', job)
        self.assertEqual(result.state, 'done', result.detail)
        self.assertEqual(backend._ctx_for(job)['setup_bundle']['manifest']['role'],
                         'reference_node')

    def test_reference_pair_does_not_downgrade_selected_field_security(self):
        site = _site(self.tmp / 'no-downgrade')
        bundles = self.tmp / 'no-downgrade' / 'bundles'
        bundles.mkdir()
        _build_bundle(bundles, 'field-bench-member', role='bench_node',
                      console=False, security='MEMBER_EDHOC')
        _build_bundle(bundles, 'field-ref', role='reference_node', console=False)
        _build_bundle(bundles, 'setup-ref', role='reference_node', console=True)
        backend = prov.LabProvisionBackend(
            site_dir=site, boards=self.boards, bundles_dir=bundles, office=self.office,
            link_factory=lambda port: self.console, boot_capture=lambda port: [])
        result = backend.run('preflight', self._job())
        self.assertEqual(result.state, 'failed')
        self.assertIn('security', result.detail)

    def test_duplicate_bundle_selection_is_refused(self):
        _build_bundle(self.backend.bundles_dir, 'field-bench-alt',
                      role='bench_node', console=False)
        result = self.backend.run('preflight', self._job())
        self.assertEqual(result.state, 'failed')
        self.assertIn('multiple', result.detail)

    def test_office_gets_identity_spec_with_site_ca_anchor(self):
        site = self.backend.site_dir
        (site / 'site-authority.json').write_text(json.dumps(
            {'format': 'routeloom-site-authority-v1', 'site_ca_pubkey_hex': 'ab' * 64}))
        spec = json.loads(self.backend._identity_spec_path().read_text())
        self.assertEqual(spec['format'], 'routeloom-identity-spec-v1')
        self.assertEqual(spec['anchors'], [{'anchor_id': '00000000000000cc',
                                            'kind': 'site-ca', 'status': 'active',
                                            'pubkey_hex': 'ab' * 64}])

    def test_restart_after_field_write_never_uses_console(self):
        """D03 resume: a restart after the field image was written must not
        dial the maintenance console — the field image serves none. The
        journal answers the status/identity steps and the boot readback
        closes the run."""
        job = self._job()
        journal_path = (self.backend._journals() /
                        f'node-{job.node_id}.journal.json')

        def past_field_write():
            return (journal_path.exists()
                    and prov.ProvisionJournal.load(journal_path).has('field'))

        # First process: stops once the field write is journaled (host died
        # between the write and the boot readback).
        runner = ProvisionRunner(self.backend, [job],
                                 should_cancel=past_field_write)
        runner.run_job(job)
        self.assertEqual(job.steps.get('field'), 'done')
        self.assertEqual(job.resume_from, 'readback')
        self.assertFalse(job.ready)
        self.assertEqual(len(self.boards.flashed), 2)

        # Restart: a fresh backend has an empty step ctx — every step re-runs
        # from the journal. The console is dead: any exchange is the bug.
        class DeadConsole(SetupConsole):
            def exchange(self, line):
                raise AssertionError(f'console used post-field: {line}')

        backend2 = prov.LabProvisionBackend(
            site_dir=self.backend.site_dir, boards=self.boards,
            bundles_dir=self.backend.bundles_dir, office=self.office,
            link_factory=lambda port: DeadConsole(),
            boot_capture=lambda port: self._expected_boot(job))
        job2 = ProvisionJob('/dev/ttyUSB0', 'esp32c3', IDENTITY.base_mac,
                            'bench', job.node_id, steps={'plan': 'done'})
        ProvisionRunner(backend2, [job2]).run_job(job2)
        self.assertTrue(job2.ready)
        self.assertEqual(job2.steps.get('inventory'), 'done')
        self.assertEqual(len(self.boards.flashed), 2)  # no re-flash
        self.assertEqual(len(self.office.confirmed), 1)
        journal = prov.ProvisionJournal.load(journal_path)
        self.assertTrue(journal.done)
        self.assertTrue(journal.has('written'))

    def test_cli_provision_completes_full_flow(self):
        """D03 CLI: `provisioned` is printed only after the field write,
        boot readback and inventory all completed — never at identity seal."""
        def capture(port):
            return self._expected_boot(
                ProvisionJob('/dev/ttyUSB0', 'esp32c3', IDENTITY.base_mac,
                             'bench', '0000000000000007'))

        self.backend._boot_capture = capture
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = prov.main(
                ['provision', '--port', '/dev/ttyUSB0',
                 '--node-id', '0000000000000007', '--role', 'bench',
                 '--site-dir', str(self.backend.site_dir),
                 '--bundles-dir', str(self.backend.bundles_dir)],
                backend=self.backend)
        self.assertEqual(rc, 0)
        self.assertIn('provisioned node=0000000000000007', out.getvalue())
        self.assertEqual(len(self.boards.flashed), 2)
        self.assertTrue(self.console.locked)
        self.assertEqual(
            self.office.imported,
            [(str(self.backend.site_dir), '0000000000000007', 'endpoint')])

    def test_cli_provision_does_not_claim_partial(self):
        """A stop before a matching readback must not print `provisioned`."""
        self.backend._boot_capture = lambda port: _boot_lines(
            node=7, kid='00' * 32, devcert_sha='11' * 32)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            rc = prov.main(
                ['provision', '--port', '/dev/ttyUSB0',
                 '--node-id', '0000000000000007', '--role', 'bench',
                 '--site-dir', str(self.backend.site_dir),
                 '--bundles-dir', str(self.backend.bundles_dir)],
                backend=self.backend)
        self.assertEqual(rc, 1)
        self.assertNotIn('provisioned', out.getvalue())
        self.assertIn('provision stopped', err.getvalue())
        self.assertEqual(self.office.imported, [])


if __name__ == '__main__':
    unittest.main()

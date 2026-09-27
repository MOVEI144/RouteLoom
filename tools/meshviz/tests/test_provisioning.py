"""Host tests for the provisioning orchestrator (D03a/D03b).

`FakeConsole` mirrors the sdkv1_maintenance.cpp line contract: RAM-only
pending key, idempotent seal for the identical bundle, lock exemption,
single-use deprovision challenges, and store impairment. `FakeOffice` stands
in for the routeloomctl provision-* commands with deterministic issue output.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from routeloom_meshviz import provisioning as prov


def _kid(seed: bytes) -> str:
    return hashlib.sha256(seed).hexdigest()


def _bundle_json(node_id: str, pubkey: str, kid: str, serial: int, fw: str = 'dev') -> bytes:
    return json.dumps(
        {
            'format': 'routeloom-identity-bundle-v1',
            'node_id': node_id,
            'flags': 0,
            'kid_hex': kid,
            'pubkey_hex': pubkey,
            'anchors': [],
            'devcert_hex': ('00' * 8) + serial.to_bytes(4, 'big').hex() + fw.encode().hex(),
        }
    ).encode()


class FakeConsole:
    """A device maintenance console faithful to sdkv1_maintenance.cpp."""

    def __init__(self, node_id='0000000000000000', fw='dev'):
        self.fw = fw
        self.store_ok = True
        self.locked = False
        self.sealed = None  # dict(node,kid,serial,devcert_sha256)
        self.pending = None  # dict(node,pubkey,challenge)
        self.challenge = None  # dict(node,kid,nonce)
        self._nonces = 0
        self._keygens = 0
        self.confirms = []
        self.keygen_count = 0
        self.identity_attempts = []
        self.deprovision_count = 0

    # --- fault injection ---------------------------------------------------
    def reboot(self):
        """Console restart: pending key and nonce die with the RAM state."""
        self.pending = None
        self.challenge = None

    # --- transport ---------------------------------------------------------
    def exchange(self, line: str) -> str:
        if self.locked and line.split()[0] not in ('status', 'lock', 'deprovision',
                                                 'deprovision_confirm'):
            return 'ERR locked'
        verb, _, rest = line.partition(' ')
        handler = {
            'status': self._status,
            'keygen': lambda: self._keygen(*rest.split()),
            'identity': lambda: self._identity(rest),
            'lock': lambda: self._lock(rest),
            'deprovision': self._deprovision,
            'deprovision_confirm': lambda: self._deprovision_confirm(*rest.split()),
        }.get(verb)
        if handler is None:
            return 'ERR unknown_verb'
        if not self.store_ok and verb not in ('deprovision', 'deprovision_confirm'):
            return 'ERR store_unavailable'
        return handler()

    # --- verbs -------------------------------------------------------------
    def _status(self) -> str:
        pending = '1' if self.pending else '0'
        locked = '1' if self.locked else '0'
        if self.sealed:
            s = self.sealed
            return (f'OK identity=sealed pending={pending} locked={locked} '
                    f'node={s["node"]} kid={s["kid"]} serial={s["serial"]} '
                    f'devcert_sha256={s["devcert_sha256"]} fw={s["fw"]}')
        return f'OK identity=none pending={pending} locked={locked} fw={self.fw}'

    def _keygen(self, node: str, challenge: str) -> str:
        if self.sealed:
            return 'ERR identity_committed'
        if self.pending:
            return 'ERR pending_exists'
        if len(node) != 16 or len(challenge) != 64:
            return 'ERR bad_args'
        pubkey = 'pub-' + node + '-' + str(self._keygens)
        self._keygens += 1
        self.keygen_count += 1
        pop = hashlib.sha256((pubkey + challenge).encode()).hexdigest() * 2
        self.pending = {'node': node, 'pubkey': pubkey, 'challenge': challenge}
        return f'OK pop_hex={pop}'

    def _identity(self, bundle_hex: str) -> str:
        self.identity_attempts.append(bundle_hex)
        try:
            bundle = json.loads(bytes.fromhex(bundle_hex))
        except (ValueError, json.JSONDecodeError):
            return 'ERR bad_bundle'
        if self.sealed:
            if (bundle['node_id'] == self.sealed['node']
                    and bundle['kid_hex'] == self.sealed['kid']):
                return f'OK sealed kid={self.sealed["kid"]}'
            return 'ERR already_provisioned'
        if self.pending is None:
            return 'ERR no_pending_key'
        if bundle['node_id'] != self.pending['node']:
            return 'ERR node_mismatch'
        if bundle['pubkey_hex'] != self.pending['pubkey']:
            return 'ERR key_mismatch'
        devcert = bytes.fromhex(bundle['devcert_hex'])
        self.sealed = {
            'node': bundle['node_id'],
            'kid': bundle['kid_hex'],
            'serial': int.from_bytes(devcert[8:12], 'big'),
            'devcert_sha256': hashlib.sha256(devcert).hexdigest(),
            'fw': self.fw,
        }
        self.pending = None
        return f'OK sealed kid={self.sealed["kid"]}'

    def _lock(self, kid: str) -> str:
        if self.sealed is None:
            return 'ERR identity_uncommitted'
        if kid != self.sealed['kid']:
            return 'ERR key_mismatch'
        self.locked = True
        return f'OK locked kid={kid}'

    def _deprovision(self) -> str:
        self._nonces += 1
        nonce = hashlib.sha256(f'nonce{self._nonces}'.encode()).hexdigest()
        node = self.sealed['node'] if self.sealed else 'none'
        kid = self.sealed['kid'] if self.sealed else 'none'
        self.challenge = {'node': node, 'kid': kid, 'nonce': nonce}
        self.deprovision_count += 1
        return f'OK deprovision node={node} kid={kid} nonce={nonce}'

    def _deprovision_confirm(self, nonce: str, kid: str) -> str:
        self.confirms.append(nonce)
        if self.challenge is None:
            return 'ERR no_challenge'
        if nonce != self.challenge['nonce']:
            return 'ERR bad_nonce'
        if kid != self.challenge['kid']:
            return 'ERR target_mismatch'
        node = self.challenge['node']
        self.challenge = None
        self.sealed = None
        self.pending = None
        self.locked = False
        return f'OK deprovisioned node={node}'


class FakeOffice:
    """Deterministic stand-in for `routeloomctl provision-*`."""

    def __init__(self):
        self._challenges = 0
        self.issues = 0
        self.confirmed = []

    def pop_challenge(self, node_id: str) -> str:
        self._challenges += 1
        return hashlib.sha256(f'challenge{self._challenges}:{node_id}'.encode()).hexdigest()

    def issue_devcert(self, plan, challenge_hex: str, pop_hex: str) -> prov.Issued:
        # Office rule: a published bundle binds (node, serial) to the PoP key;
        # a replayed issue for the same work must name the same pubkey.
        out = Path(plan.out_dir)
        bundle_path = out / 'identity-bundle.json'
        pubkey = 'pub-' + plan.node_id + '-' + str(self.issues)
        if bundle_path.exists():
            prior = json.loads(bundle_path.read_text())
            pubkey = prior['pubkey_hex']  # adopt: deterministic reissue
        else:
            self.issues += 1
        kid = _kid(pubkey.encode())
        devcert = b'\x00' * 8 + plan.serial.to_bytes(4, 'big') + plan.fw.encode()
        out.mkdir(parents=True, exist_ok=True)
        bundle_path.write_bytes(_bundle_json(plan.node_id, pubkey, kid, plan.serial, plan.fw))
        (out / 'devcert.cwt').write_bytes(devcert)
        (out / 'inventory.json').write_text(json.dumps({
            'format': 'routeloom-inventory-v1',
            'node_id': plan.node_id,
            'kid': kid,
            'cert_serial': plan.serial,
            'device_ca_id': '0000000000000001',
            'office_status': 'issued',
        }))
        return prov.Issued(kid=kid, devcert_sha256=hashlib.sha256(devcert).hexdigest(),
                           out_dir=str(out))

    def bundle_hex(self, out_dir: str) -> str:
        return (Path(out_dir) / 'identity-bundle.json').read_bytes().hex()

    def confirm_written(self, node_id: str, devcert_sha256: str, out_dir: str) -> None:
        inv = json.loads((Path(out_dir) / 'inventory.json').read_text())
        inv['office_status'] = 'written'
        (Path(out_dir) / 'inventory.json').write_text(json.dumps(inv))
        self.confirmed.append(node_id)


def _plan(out_dir: Path, node='0000000000000007', serial=42, fw='dev') -> prov.BoardProvisionPlan:
    return prov.BoardProvisionPlan(
        site_id='00000000000000aa',
        work_id=f'w-{node[-4:]}',
        board_uuid='uuid-' + node,
        base_mac='a0:85:e3:00:00:01',
        node_id=node,
        serial=serial,
        role='reference_node',
        out_dir=str(out_dir),
        fw=fw,
    )


class TestProvisioning(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.journal_dir = self.tmp / 'journals'
        self.console = FakeConsole()
        self.office = FakeOffice()
        self.prov = prov.Provisioner(self.journal_dir, self.office)

    def plan(self, node='0000000000000007', **kw):
        return _plan(self.tmp / 'out' / node[-4:], node=node, **kw)

    # --- console contract ---------------------------------------------------

    def test_status_parse_none(self):
        st = prov.DeviceStatus.parse(self.console.exchange('status'))
        self.assertEqual(st.identity, 'none')
        self.assertFalse(st.pending)
        self.assertFalse(st.locked)

    # --- happy path -----------------------------------------------------------

    def test_happy_path_provisions_and_finalize_requires_readback(self):
        plan = self.plan()
        journal = self.prov.run(plan, self.console)
        self.assertTrue(journal.has('sealed'))
        self.assertTrue(journal.has('locked'))
        self.assertTrue(self.console.locked)
        self.assertFalse(journal.done)  # not Ready before readback
        journal = self.prov.finalize(plan, self.console)
        self.assertTrue(journal.done)
        self.assertEqual(self.office.confirmed, [plan.node_id])

    def test_key_material_never_exported(self):
        plan = self.plan()
        journal = self.prov.run(plan, self.console)
        text = journal.path.read_text()
        self.assertNotIn('priv', text)
        for entry in json.loads(text)['stages']:
            for key in entry:
                self.assertNotIn('secret', key)
                self.assertNotIn('private', key)

    # --- resume semantics -----------------------------------------------------

    def test_resume_after_seal_adopts_device_state(self):
        plan = self.plan()
        self.prov.run(plan, self.console)
        # Crash after seal committed but before the journal could be read:
        # simulate by deleting the sealed/locked evidence lines.
        journal = self.prov.journal(plan.work_id)
        journal._doc['stages'] = [
            e for e in journal._doc['stages'] if e['stage'] not in ('sealed', 'locked')
        ]
        journal._write()
        attempts_before = len(self.console.identity_attempts)
        journal2 = self.prov.run(plan, self.console)
        # status shows sealed with the issued kid → adopt, re-lock idempotently,
        # and never resend identity.
        self.assertEqual(len(self.console.identity_attempts), attempts_before)
        self.assertTrue(journal2.has('sealed'))
        self.assertTrue(journal2.has('locked'))

    def test_pending_lost_rekeygens_with_fresh_challenge(self):
        plan = self.plan()
        self.prov.run(plan, self.console)
        # Forge a journal that stopped right after keygen (issued absent).
        journal = self.prov.journal(plan.work_id)
        journal._doc['stages'] = [
            e for e in journal._doc['stages']
            if e['stage'] in ('plan', 'status', 'keygen')
        ]
        journal._write()
        self.console = FakeConsole()  # device rebooted: sealed none, pending none
        self.console.reboot()
        journal2 = self.prov.run(plan, self.console)
        self.assertTrue(journal2.has('sealed'))
        self.assertEqual(self.console.keygen_count, 1)  # fresh device: 1 keygen
        keygens = [e for e in journal2._doc['stages'] if e['stage'] == 'keygen']
        stale = [e for e in journal2._doc['stages'] if e['stage'] == 'keygen_stale']
        self.assertEqual(len(keygens), 2)
        self.assertEqual(len(stale), 1)
        self.assertNotEqual(keygens[0]['challenge'], keygens[1]['challenge'])

    def test_plan_mismatch_refuses_journal_reuse(self):
        plan = self.plan()
        self.prov.run(plan, self.console)
        other = _plan(self.tmp / 'out2', node='0000000000000007')
        other = prov.BoardProvisionPlan(**{**other.as_dict(), 'serial': 99})
        with self.assertRaises(prov.ProvisionError) as cm:
            self.prov.run(other, FakeConsole())
        self.assertEqual(cm.exception.reason, 'plan_mismatch')

    def test_board_probe_mismatch_stops_before_console(self):
        plan = self.plan()
        with self.assertRaises(prov.ProvisionError) as cm:
            self.prov.run(plan, self.console, board_probe=lambda: 'ff:ff:ff:ff:ff:ff')
        self.assertEqual(cm.exception.reason, 'board_mismatch')
        self.assertIsNone(self.console.sealed)

    # --- refusal paths ---------------------------------------------------------

    def test_foreign_sealed_device_refused(self):
        plan = self.plan()
        foreign = FakeConsole()
        foreign.sealed = {'node': '0000000000000099', 'kid': _kid(b'x'), 'serial': 1,
                          'devcert_sha256': '0' * 64, 'fw': 'dev'}
        with self.assertRaises(prov.ProvisionError) as cm:
            self.prov.run(plan, foreign)
        self.assertEqual(cm.exception.reason, 'already_provisioned')

    def test_same_node_foreign_kid_refused(self):
        plan = self.plan()
        foreign = FakeConsole()
        foreign.sealed = {'node': plan.node_id, 'kid': _kid(b'other'), 'serial': plan.serial,
                          'devcert_sha256': '1' * 64, 'fw': 'dev'}
        with self.assertRaises(prov.ProvisionError) as cm:
            self.prov.run(plan, foreign)
        self.assertEqual(cm.exception.reason, 'already_provisioned')

    def test_journal_sealed_but_device_none_is_contradiction(self):
        plan = self.plan()
        journal = self.prov.run(plan, self.console)
        wiped = FakeConsole()  # swapped board or wiped store
        with self.assertRaises(prov.ProvisionError) as cm:
            self.prov.run(plan, wiped)
        self.assertEqual(cm.exception.reason, 'state_contradiction')

    def test_pending_lost_after_issue_is_manual(self):
        plan = self.plan()
        journal = self.prov.journal if False else None
        self.prov.run(plan, self.console)
        j = self.prov.journal(plan.work_id)
        # Keep only evidence up to 'issued'; device reboot wiped pending+seal.
        j._doc['stages'] = [e for e in j._doc['stages']
                            if e['stage'] in ('plan', 'status', 'keygen', 'issued')]
        j._write()
        fresh = FakeConsole()  # rebooted: identity=none pending=0
        with self.assertRaises(prov.ProvisionError) as cm:
            self.prov.run(plan, fresh)
        self.assertEqual(cm.exception.reason, 'pending_lost_after_issue')

    def test_finalize_requires_lock_and_matches_receipt(self):
        plan = self.plan(fw='dev')
        # finalize without run() must refuse.
        with self.assertRaises(prov.ProvisionError) as cm:
            self.prov.finalize(plan, self.console)
        self.assertEqual(cm.exception.reason, 'no_journal')
        self.prov.run(plan, self.console)
        # Wrong expected fw → readback mismatch, journal stays open.
        bad = _plan(Path(plan.out_dir), fw='v999')
        with self.assertRaises(prov.ProvisionError) as cm:
            self.prov.finalize(bad, self.console)
        self.assertEqual(cm.exception.reason, 'readback_mismatch')
        self.assertFalse(self.prov.journal(plan.work_id).done)

    def test_finalize_field_writer_digest(self):
        plan = self.plan()
        self.prov.run(plan, self.console)
        writes = []
        self.prov.finalize(plan, self.console,
                           field_writer=lambda: writes.append('x') or 'ab' * 32)
        journal = self.prov.journal(plan.work_id)
        self.assertTrue(journal.done)
        field_entry = journal.latest('field')
        self.assertEqual(field_entry['digest'], 'ab' * 32)


class TestDeprovision(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.journal_dir = self.tmp / 'journals'
        self.console = FakeConsole()
        self.deprov = prov.Deprovisioner(self.journal_dir)

    def _sealed_console(self, node='0000000000000007', kid=None):
        console = FakeConsole()
        kid = kid or _kid(b'k' + node.encode())
        console.sealed = {'node': node, 'kid': kid, 'serial': 42,
                          'devcert_sha256': '0' * 64, 'fw': 'dev'}
        return console, kid

    def _plan(self, node='0000000000000007', kid=None, **kw):
        kw.setdefault('expected_kid', kid or '')
        return prov.DeprovisionPlan(
            work_id='dp-' + node[-4:],
            expected_node_id=node,
            **kw,
        )

    def test_happy_path_wipes_and_readbacks(self):
        console, kid = self._sealed_console()
        journal = self.deprov.run(self._plan(kid=kid), console)
        self.assertTrue(journal.done)
        self.assertIsNone(console.sealed)
        self.assertEqual(console.deprovision_count, 1)
        self.assertEqual(len(console.confirms), 1)

    def test_target_mismatch_refuses_before_wipe(self):
        console, _kidv = self._sealed_console(node='0000000000000099')
        with self.assertRaises(prov.ProvisionError) as cm:
            self.deprov.run(self._plan(node='0000000000000007'), console)
        self.assertEqual(cm.exception.reason, 'target_mismatch')
        self.assertIsNotNone(console.sealed)  # never wiped the wrong board
        self.assertEqual(console.deprovision_count, 0)

    def test_kid_mismatch_refuses(self):
        console, _kidv = self._sealed_console()
        with self.assertRaises(prov.ProvisionError):
            self.deprov.run(self._plan(kid=_kid(b'different')), console)
        self.assertIsNotNone(console.sealed)

    def test_nonce_loss_reissues_challenge_once(self):
        console, kid = self._sealed_console()
        # Burn the first confirm: swap nonce so the stored one is stale.
        original = console._deprovision_confirm

        def flaky(nonce, k):
            if len(console.confirms) == 0:
                console.confirms.append(nonce)
                console.challenge = None  # challenge burned without wipe
                return 'ERR no_challenge'
            return original(nonce, k)

        console._deprovision_confirm = flaky
        journal = self.deprov.run(self._plan(kid=kid), console)
        self.assertTrue(journal.done)
        self.assertEqual(console.deprovision_count, 2)  # fresh challenge, no replay
        self.assertIsNone(console.sealed)

    def test_stale_nonce_never_replayed_on_resume(self):
        console, kid = self._sealed_console()
        plan = self._plan(kid=kid)
        # First run dies mid-confirm.
        console._deprovision_confirm = lambda n, k: (_ for _ in ()).throw(
            prov.ProvisionError('link_lost'))
        with self.assertRaises(prov.ProvisionError):
            self.deprov.run(plan, console)
        console._deprovision_confirm = FakeConsole._deprovision_confirm.__get__(console)
        journal = self.deprov.run(plan, console)
        self.assertTrue(journal.done)
        # The second run issued a brand-new challenge+confirm pair.
        self.assertEqual(console.deprovision_count, 2)

    def test_already_wiped_is_idempotent_done(self):
        console = FakeConsole()  # identity=none
        journal = self.deprov.run(self._plan(), console)
        self.assertTrue(journal.done)
        self.assertEqual(console.deprovision_count, 0)

    def test_impaired_store_requires_explicit_flag(self):
        console = FakeConsole()
        console.store_ok = False
        with self.assertRaises(prov.ProvisionError) as cm:
            self.deprov.run(self._plan(), console)
        self.assertEqual(cm.exception.reason, 'store_unavailable')
        journal = self.deprov.run(
            self._plan(expected_kid='', wipe_unverifiable=True), console)
        self.assertTrue(journal.done)

    def test_impaired_store_resume_allowed_with_journal(self):
        console = FakeConsole()
        console.store_ok = False
        plan = self._plan(expected_kid='', wipe_unverifiable=True)
        self.deprov.run(plan, console)
        # Resume a done journal is a no-op wipe check.
        console2 = FakeConsole()
        console2.store_ok = False
        journal = self.deprov.run(plan, console2)
        self.assertTrue(journal.done)


if __name__ == '__main__':
    unittest.main()

"""Release assembly and rejection boundaries; synthetic archives are not HIL evidence."""
import copy
import hashlib
import io
import json
import re
import subprocess
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import release

ROOT = release.ROOT


def metadata_fixture():
    lock = tomllib.loads((ROOT / 'host/Cargo.lock').read_text())
    licenses = {(name, version): license for name, version, license in re.findall(
        r'^Cargo: (\S+) (\S+) \| (.+)$', (ROOT / 'NOTICE').read_text(), re.M)}
    return {'workspace_members': [], 'packages': [
        {'id': p['name'] + p['version'], 'name': p['name'], 'version': p['version'],
         'source': p['source'], 'license': licenses[p['name'], p['version']]}
        for p in lock['package'] if 'source' in p]}


class ReleaseTests(unittest.TestCase):
    def check_signing_hooks(self, out, root):
        key = root / 'key.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)], check=True)
        hook = root / 'sign-hook'
        hook.write_text('#!/bin/sh\n'
                        'exec openssl pkeyutl -sign -rawin -inkey "$1" -in "$2" -out "$3"\n')
        hook.chmod(0o700)
        release.sign(out, key, hook)
        subprocess.run(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin',
                        '-inkey', str(out / 'signing-public.pem'),
                        '-in', str(out / 'SHA256SUMS.txt'),
                        '-sigfile', str(out / 'SHA256SUMS.sig')], check=True, stdout=subprocess.PIPE)
        hook.write_text('#!/usr/bin/env python3\nimport subprocess, sys\n'
                        f'key = {str(key)!r}\n'
                        'subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-out", sys.argv[4]], check=True)\n'
                        'subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", sys.argv[2], "-out", sys.argv[3]], check=True)\n')
        release.sign(out, None, hook)
        dev = ROOT / 'tools/meshviz/src/routeloom_meshviz/dev-signing-public.pem'
        hook.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\nimport sys\n'
                        f'Path(sys.argv[4]).write_bytes(Path({str(dev)!r}).read_bytes())\n'
                        'Path(sys.argv[3]).write_bytes(b"synthetic signature")\n')
        with self.assertRaisesRegex(ValueError, 'development signing key'):
            release.sign(out, None, hook)

    def test_notice_and_metadata_require_exact_locked_dependencies(self):
        metadata = metadata_fixture()
        lock = tomllib.loads((ROOT / 'host/Cargo.lock').read_text())
        notice = (ROOT / 'NOTICE').read_text()
        vendors = json.loads((ROOT / 'components/routeloom/third_party/VENDORED.json').read_text())
        self.assertGreater(len(release.inventory(metadata, lock, notice, vendors)), 84)
        unknown = {'id': 'unknown', 'name': 'unknown', 'version': '1.0.0',
                   'source': 'registry+https://github.com/rust-lang/crates.io-index', 'license': 'MIT'}
        metadata['packages'].append(unknown)
        with self.assertRaisesRegex(ValueError, 'Cargo.lock'):
            release.inventory(metadata, lock, notice, vendors)
        lock['package'].append({**unknown, 'checksum': 'a' * 64})
        with self.assertRaisesRegex(ValueError, 'NOTICE'):
            release.inventory(metadata, lock, notice, vendors)
        with self.assertRaisesRegex(ValueError, 'vendored'):
            release.inventory(metadata_fixture(), tomllib.loads((ROOT / 'host/Cargo.lock').read_text()),
                              notice.replace(vendors['components'][0]['commit'], 'unknown'), vendors)

    def test_product_image_rejects_development_key_provider_and_mode(self):
        member = ['CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y']
        self.assertEqual(release.firmware_errors(b'clean', ['MemberScopeProvider'], member, 'member'), [])
        key = bytes.fromhex('524f5554454c4f4f4d2d444556454c4f504d454e542d4b45592d4f4e4c592121')
        for image, symbols, settings in (
                (b'image' + key, [], member), (key.hex().upper().encode(), [], member),
                (b'clean', ['_ZN9routeloom5sdkv116DevGroupProviderE'], member),
                (b'clean', [], ['CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y']),
                (b'clean', [], member + ['CONFIG_ROUTELOOM_DEV_KCONFIG_IDENTITY=y']),
                (b'custom' + b'\x55' * 32, [], member +
                 ['CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX="' + '55' * 32 + '"'])):
            with self.subTest(image=len(image), symbols=symbols):
                self.assertTrue(release.firmware_errors(image, symbols, settings, 'member'))
        self.assertEqual(release.firmware_errors(key, ['DevGroupProvider'],
                         ['CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y'], 'devram'), [])

    def test_signing_rejects_meshviz_key_by_public_identity(self):
        with self.assertRaisesRegex(ValueError, 'development signing key'):
            release.check_signing_key(ROOT / 'tools/meshviz/packaging/dev-signing-key.pem')
        with self.assertRaisesRegex(ValueError, 'development signing key'):
            release.check_signing_key(ROOT / 'tools/meshviz/src/routeloom_meshviz/dev-signing-public.pem',
                                      public=True)

    def test_tag_mismatch_is_rejected_before_building(self):
        release.check_tag('v' + release.manifest()['sdk_version'])
        with self.assertRaisesRegex(ValueError, 'manifest'):
            release.check_tag('v9.9.9')
        matrix = release.firmware_matrix()
        self.assertEqual(len(matrix), 24)
        self.assertEqual(len({e['id'] for e in matrix}), 24)

    def test_complete_assembly_provenance_promotion_and_corruption(self):
        data = copy.deepcopy(release.manifest())
        data['sdk_version'] = '2.0.0-rc.1'
        tag = 'v' + data['sdk_version']
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory() as directory, patch.object(release, 'manifest', return_value=data):
            root = Path(directory)
            metadata = root / 'metadata.json'
            release.write_json(metadata, metadata_fixture())
            out = root / 'dist'
            release.make_inventory(tag, metadata, out)
            for name in release.required_names(tag) - {p.name for p in out.iterdir()}:
                (out / name).write_bytes(b'synthetic artifact')
            for entry in release.firmware_matrix():
                files = {'sdkconfig': b'synthetic config',
                         f'routeloom_{entry["app"]}.bin': b'synthetic image',
                         'partition_table/partition-table.bin': b'synthetic partition'}
                record = {'entry': entry, 'toolchain': data['toolchain'], 'commit': commit,
                          'tag': tag, 'partition_id': 'PT-4M-v2',
                          'sdkconfig_sha256': hashlib.sha256(files['sdkconfig']).hexdigest(),
                          'app_sha256': hashlib.sha256(files[f'routeloom_{entry["app"]}.bin']).hexdigest(),
                          'partition_sha256': hashlib.sha256(files['partition_table/partition-table.bin']).hexdigest()}
                files['release.json'] = json.dumps(record).encode()
                with tarfile.open(out / release.archive_name(tag, entry), 'w:gz') as tar:
                    for name, raw in files.items():
                        info = tarfile.TarInfo(name)
                        info.size = len(raw)
                        tar.addfile(info, io.BytesIO(raw))
            sbom = out / f'routeloom-{tag}-sbom.json'
            original = sbom.read_bytes()
            bom = json.loads(original)
            bom['components'].append({'name': 'unknown', 'type': 'library'})
            release.write_json(sbom, bom)
            with self.assertRaisesRegex(ValueError, 'SBOM'):
                release.finalize(tag, out)
            sbom.write_bytes(original)
            release.finalize(tag, out)
            before = {p.name: p.read_bytes() for p in out.iterdir()}
            release.promote(out, 'v2.0.0', commit, tag)
            self.assertEqual(before, {p.name: p.read_bytes() for p in out.iterdir()})
            with self.assertRaisesRegex(ValueError, 'identical'):
                release.promote(out, 'v2.0.0', '0' * 40, tag)
            self.check_signing_hooks(out, root)
            (out / 'NOTICE').write_text('tampered')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                release.verify(out)


if __name__ == '__main__':
    unittest.main()

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


def write_archive(path, files):
    with tarfile.open(path, 'w:gz') as tar:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))


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
        signature = out / 'SHA256SUMS.sig'
        raw = signature.read_bytes()
        signature.unlink()
        signature.symlink_to(key)
        with self.assertRaisesRegex(ValueError, 'invalid signing output'):
            release.verify(out)
        signature.unlink()
        signature.write_bytes(raw)
        original = {p.name: p.read_bytes() for p in out.iterdir()}
        hook.write_text('#!/usr/bin/env python3\n'
                        'import hashlib, json, sys\nfrom pathlib import Path\n'
                        'out = Path(sys.argv[2]).parent\n'
                        '(out / "NOTICE").write_text("replaced by hook")\n'
                        'provenance = json.loads((out / "provenance.json").read_text())\n'
                        'for subject in provenance["subject"]:\n'
                        '    subject["digest"]["sha256"] = hashlib.sha256((out / subject["name"]).read_bytes()).hexdigest()\n'
                        '(out / "provenance.json").write_text(json.dumps(provenance))\n'
                        'names = [line.split("  ")[1] for line in Path(sys.argv[2]).read_text().splitlines()]\n'
                        'Path(sys.argv[2]).write_text("".join(hashlib.sha256((out / name).read_bytes()).hexdigest() + "  " + name + "\\n" for name in names))\n')
        with self.assertRaisesRegex(ValueError, 'changed release artifacts'):
            release.sign(out, None, hook)
        for name, raw in original.items():
            (out / name).write_bytes(raw)
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

    def test_candidate_jobs_use_the_prepared_source_commit(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        for job in ('source', 'host', 'firmware', 'assemble'):
            block = workflow.split(f'\n  {job}:', 1)[1].split('\n  promote:', 1)[0]
            checkout = block.split('ref:', 1)[1].splitlines()[0].strip()
            with self.subTest(job=job):
                self.assertEqual(checkout, '${{ needs.prepare.outputs.commit }}')

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
            packages = metadata_fixture()
            for package in packages['packages']:
                source = root / 'crates' / (package['name'] + '-' + package['version'])
                source.mkdir(parents=True)
                (source / 'LICENSE').write_text('synthetic upstream license: ' + package['name'])
                package['manifest_path'] = str(source / 'Cargo.toml')
            release.write_json(metadata, packages)
            out = root / 'dist'
            release.make_inventory(tag, metadata, out)
            self.assertIn('synthetic upstream license: crossterm',
                          (out / 'THIRD_PARTY_LICENSES.txt').read_text())
            license_path = root / 'crates/crossterm-0.28.1/LICENSE'
            raw = license_path.read_bytes()
            license_path.unlink()
            with self.assertRaisesRegex(ValueError, 'missing upstream license text'):
                release.make_inventory(tag, metadata, out)
            license_path.write_bytes(raw)
            for name in release.required_names(tag) - {p.name for p in out.iterdir()}:
                (out / name).write_bytes(b'synthetic artifact')
            licenses = {name: (out / name).read_bytes() for name in
                        ('LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.txt')}
            write_archive(out / f'routeloom-{tag}-linux-x86_64.tar.gz', {
                f'routeloom-{tag}-linux-x86_64/{name}': raw for name, raw in licenses.items()})
            for entry in release.firmware_matrix():
                files = {'sdkconfig': b'synthetic config',
                         f'routeloom_{entry["app"]}.bin': b'synthetic image',
                         'partition_table/partition-table.bin': b'synthetic partition',
                         'bootloader/bootloader.bin': b'synthetic bootloader',
                         'ota_data_initial.bin': b'synthetic OTA data'}
                flash_files = {'0x2000' if entry['target'] == 'esp32c5' else '0x0':
                               'bootloader/bootloader.bin',
                               '0x8000': 'partition_table/partition-table.bin',
                               '0x10000': 'ota_data_initial.bin',
                               '0x40000': f'routeloom_{entry["app"]}.bin'}
                files['flasher_args.json'] = json.dumps({
                    'flash_files': flash_files,
                    'extra_esptool_args': {'chip': entry['target']}}).encode()
                record = {'entry': entry, 'toolchain': data['toolchain'], 'commit': commit,
                          'tag': tag, 'partition_id': 'PT-4M-v2',
                          'flasher_args_sha256': hashlib.sha256(files['flasher_args.json']).hexdigest(),
                          'flash_sha256': {name: hashlib.sha256(files[name]).hexdigest()
                                           for name in flash_files.values()},
                          'sdkconfig_sha256': hashlib.sha256(files['sdkconfig']).hexdigest(),
                          'app_sha256': hashlib.sha256(files[f'routeloom_{entry["app"]}.bin']).hexdigest(),
                          'partition_sha256': hashlib.sha256(files['partition_table/partition-table.bin']).hexdigest()}
                files['release.json'] = json.dumps(record).encode()
                files.update(licenses)
                write_archive(out / release.archive_name(tag, entry), files)
            archive = out / release.archive_name(tag, entry)
            original_archive = archive.read_bytes()
            files['bootloader/bootloader.bin'] = b'changed bootloader'
            write_archive(archive, files)
            with self.assertRaisesRegex(ValueError, 'flash image hash'):
                release.finalize(tag, out)
            archive.write_bytes(original_archive)
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

"""Offline signed firmware and build safety regression scenarios."""
import os
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from routeloom_meshviz import firmware_catalog as catalog
from routeloom_meshviz import flash_worker
from routeloom_meshviz.device import FlashPlan, Identity, Image
from routeloom_meshviz.flash_worker import flash


class BundleTests(unittest.TestCase):
    @staticmethod
    def fixture(root):
        build = root / 'build'
        (build / 'bootloader').mkdir(parents=True)
        (build / 'partition_table').mkdir()
        header = bytearray(128)
        header[0] = 0xe9
        header[2:4] = b'\x02\x1f'
        header[12:14] = (5).to_bytes(2, 'little')
        header[14] = 1
        header[15:17] = (1).to_bytes(2, 'little')
        header[17:19] = (199).to_bytes(2, 'little')
        header[32:36] = bytes.fromhex('3254cdab')
        header[80:80 + len(b'routeloom_reference_node')] = b'routeloom_reference_node'
        entries = []
        for name, kind, subtype, offset, size in (
                ('nvs', 1, 2, 0x9000, 0x6000),
                ('phy_init', 1, 1, 0xf000, 0x1000),
                ('factory', 0, 0, 0x10000, 0x180000),
                ('rlsec', 1, 2, 0x190000, 0x10000)):
            entry = bytearray(32)
            entry[:2] = bytes.fromhex('aa50')
            entry[2:4] = bytes((kind, subtype))
            entry[4:8] = offset.to_bytes(4, 'little')
            entry[8:12] = size.to_bytes(4, 'little')
            entry[12:12 + len(name)] = name.encode()
            entries.append(bytes(entry))
        partition = b''.join(entries)
        partition += b'\xeb\xeb' + b'\xff' * 14 + hashlib.md5(partition).digest()
        partition += b'\xff' * (0xc00 - len(partition))
        for name, image in (('bootloader/bootloader.bin', bytes(header)),
                            ('partition_table/partition-table.bin', partition),
                            ('reference_node.bin', bytes(header))):
            (build / name).write_bytes(image)
        (build / 'flasher_args.json').write_text(json.dumps({
            'flash_files': {'0x0': 'bootloader/bootloader.bin',
                            '0x8000': 'partition_table/partition-table.bin',
                            '0x10000': 'reference_node.bin'},
            'extra_esptool_args': {'chip': 'esp32c3'},
            'flash_settings': {'flash_mode': 'dio', 'flash_freq': '80m', 'flash_size': '2MB'},
            'write_flash_args': ['--flash-mode', 'dio', '--flash-size', '2MB', '--flash-freq', '80m'],
            'bootloader': {'encrypted': 'false'},
            'partition-table': {'encrypted': 'false'},
            'app': {'encrypted': 'false'}}))
        (root / 'LICENSE').write_text('test license')
        (root / 'NOTICE').write_text('test notice')
        app = root / 'firmware' / 'reference_node'
        app.mkdir(parents=True)
        (app / 'sdkconfig').write_text(
            'CONFIG_IDF_TARGET="esp32c3"\n'
            'CONFIG_PARTITION_TABLE_CUSTOM=y\n'
            'CONFIG_PARTITION_TABLE_FILENAME="partitions.csv"\n'
            'CONFIG_PARTITION_TABLE_OFFSET=0x8000\n'
            'CONFIG_PARTITION_TABLE_MD5=y\n'
            'CONFIG_BOOTLOADER_OFFSET_IN_FLASH=0x0\n'
            'CONFIG_ESPTOOLPY_FLASHMODE="dio"\n'
            'CONFIG_ESPTOOLPY_FLASHFREQ="80m"\n'
            'CONFIG_ESPTOOLPY_FLASHSIZE="2MB"\n'
            'CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y\n')
        (app / 'partitions.csv').write_text(
            'nvs,data,nvs,0x9000,0x6000\n'
            'phy_init,data,phy,0xf000,0x1000\n'
            'factory,app,factory,0x10000,0x180000\n'
            'rlsec,data,nvs,0x190000,0x10000\n')
        (build / 'ram-report.json').write_text('{}')
        key = root / 'private.pem'
        shutil.copyfile(Path(__file__).resolve().parents[1] /
                        'packaging/dev-signing-key.pem', key)
        public = root / 'public.pem'
        catalog.export_public_key(key, public)
        return app, build, key, public

    @staticmethod
    def resign(bundle, key):
        manifest = json.loads((bundle / 'manifest.json').read_text())
        (bundle / 'manifest.json').write_bytes(catalog._json(manifest))
        (bundle / 'signature.json').write_bytes(catalog._json(catalog._sign(manifest, key)))
        (bundle / 'SHA256SUMS').write_text(''.join(
            f'{catalog._hash((bundle / name).read_bytes())}  {name}\n'
            for name in sorted([e['path'] for e in manifest['files']] +
                               list(manifest['auxiliary']) + ['manifest.json'])))

    def test_offline_bundle_and_catalog_detect_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            header = (build / 'reference_node.bin').read_bytes()
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            index = root / 'catalog.json'
            catalog.create_catalog([bundle], index, key)
            manifest = catalog.verify_bundle(bundle, public)
            self.assertEqual(catalog.verify_catalog(index, public, [bundle])[0]['bundle_id'],
                             manifest['bundle_id'])
            class ROM:
                CHIP_NAME = 'ESP32-C3'
                def __init__(self):
                    self._port = self
                def close(self):
                    pass
                def read_mac(self, kind):
                    return bytes.fromhex('aabbccddee01')
                def flash_id(self):
                    return 0x164020
                def get_chip_revision(self):
                    return 1
                def get_security_info(self, cache=False):
                    return {'parsed_flags': {'SECURE_BOOT_EN': False}, 'flash_crypt_cnt': 0}
            class API:
                __version__ = '5.4.0'
                def __init__(self):
                    self.rom = ROM()
                    self.written = None
                def detect_chip(self, **kwargs):
                    return self.rom
                def attach_flash(self, esp):
                    pass
                def write_flash(self, esp, images, **kwargs):
                    self.written = images
                def verify_flash(self, esp, images):
                    self.verified = images
            identity = Identity('esp32c3', '1', 'aa:bb:cc:dd:ee:01', None,
                                '164020', 4 * 1024 * 1024, False, False)
            images = tuple(Image(e['offset'], bundle / e['path'], e['size'], e['sha256'])
                           for e in manifest['files'])
            api = API()
            flash('COM1', FlashPlan(identity, 'esp32c3', images, True,
                                   identity.base_mac, True, bundle), api)
            self.assertEqual(api.written, api.verified)
            self.assertEqual(len(api.written), 3)
            # A signed app exceeding the factory partition must not overwrite rlsec.
            oversized = bytes(header) + b'\0' * (0x180001 - len(header))
            app_image = bundle / 'images/application.bin'
            app_image.write_bytes(oversized)
            oversized_manifest = {**manifest, 'files': [
                {**e, 'size': len(oversized), 'sha256': catalog._hash(oversized)}
                if e['offset'] == 0x10000 else e for e in manifest['files']]}
            (bundle / 'manifest.json').write_bytes(catalog._json(oversized_manifest))
            (bundle / 'signature.json').write_bytes(catalog._json(catalog._sign(oversized_manifest, key)))
            (bundle / 'SHA256SUMS').write_text(''.join(
                f'{catalog._hash((bundle / name).read_bytes())}  {name}\n'
                for name in sorted([e['path'] for e in oversized_manifest['files']] +
                                   list(oversized_manifest['auxiliary']) + ['manifest.json'])))
            api = API()
            with self.assertRaises(ValueError):
                flash('COM1', FlashPlan(identity, 'esp32c3', tuple(
                    Image(e['offset'], bundle / e['path'], e['size'], e['sha256'])
                    for e in oversized_manifest['files']), True, identity.base_mac, True, bundle), api)
            self.assertIsNone(api.written)
            app_image.write_bytes(bytes(header))
            (bundle / 'manifest.json').write_bytes(catalog._json(manifest))
            (bundle / 'signature.json').write_bytes(catalog._json(catalog._sign(manifest, key)))
            (bundle / 'SHA256SUMS').write_text(''.join(
                f'{catalog._hash((bundle / name).read_bytes())}  {name}\n'
                for name in sorted([e['path'] for e in manifest['files']] +
                                   list(manifest['auxiliary']) + ['manifest.json'])))
            # Signed compatibility constraints must be enforced before writing.
            original_manifest = (bundle / 'manifest.json').read_bytes()
            original_sums = (bundle / 'SHA256SUMS').read_bytes()
            original_sig = (bundle / 'signature.json').read_bytes()
            for change in ({'chip_revision_range': [2, 3]},
                           {'minimum_flash_bytes': 8 * 1024 * 1024}):
                restricted = {**manifest, **change}
                (bundle / 'manifest.json').write_bytes(catalog._json(restricted))
                (bundle / 'signature.json').write_bytes(catalog._json(catalog._sign(restricted, key)))
                (bundle / 'SHA256SUMS').write_bytes(original_sums.replace(
                    catalog._hash(original_manifest).encode(),
                    catalog._hash(catalog._json(restricted)).encode()))
                api = API()
                with self.subTest(change=change), self.assertRaises(ValueError):
                    flash('COM1', FlashPlan(identity, 'esp32c3', images, True,
                                           identity.base_mac, True, bundle), api)
                self.assertIsNone(api.written)
            (bundle / 'manifest.json').write_bytes(original_manifest)
            (bundle / 'SHA256SUMS').write_bytes(original_sums)
            (bundle / 'signature.json').write_bytes(original_sig)
            # A correctly signed bundle must not distribute a personalized USB
            # credential inside its public resolved sdkconfig.
            config_file = bundle / 'sdkconfig'
            original_config = config_file.read_bytes()
            private_config = original_config + b'CONFIG_ROUTELOOM_USB_DEV_SECRET="private-usb-password"\n'
            config_file.write_bytes(private_config)
            private_manifest = {**manifest, 'auxiliary': {
                **manifest['auxiliary'], 'sdkconfig': catalog._hash(private_config)}}
            (bundle / 'manifest.json').write_bytes(catalog._json(private_manifest))
            (bundle / 'signature.json').write_bytes(catalog._json(catalog._sign(private_manifest, key)))
            (bundle / 'SHA256SUMS').write_text(''.join(
                f'{catalog._hash((bundle / name).read_bytes())}  {name}\n'
                for name in sorted([e['path'] for e in manifest['files']] +
                                   list(manifest['auxiliary']) + ['manifest.json'])))
            api = API()
            with self.assertRaises(ValueError):
                flash('COM1', FlashPlan(identity, 'esp32c3', images, True,
                                       identity.base_mac, True, bundle), api)
            self.assertIsNone(api.written)
            config_file.write_bytes(original_config)
            (bundle / 'manifest.json').write_bytes(original_manifest)
            (bundle / 'SHA256SUMS').write_bytes(original_sums)
            (bundle / 'signature.json').write_bytes(original_sig)
            # Even correctly signed partition bytes must not map persistent data
            # into the factory image that will be written by this bundle.
            partition_image = bundle / 'images/partition_table/partition-table.bin'
            original_partition = partition_image.read_bytes()
            overlapping = bytearray(32)
            overlapping[:4] = b'\xaa\x50\x01\x02'
            overlapping[4:8] = (0x180000).to_bytes(4, 'little')
            overlapping[8:12] = (0x20000).to_bytes(4, 'little')
            partition_image.write_bytes(original_partition + overlapping)
            overlap_manifest = {**manifest, 'files': [
                {**e, 'size': partition_image.stat().st_size,
                 'sha256': catalog._hash(partition_image.read_bytes())}
                if e['offset'] == 0x8000 else e for e in manifest['files']]}
            (bundle / 'manifest.json').write_bytes(catalog._json(overlap_manifest))
            (bundle / 'signature.json').write_bytes(catalog._json(catalog._sign(overlap_manifest, key)))
            (bundle / 'SHA256SUMS').write_text(''.join(
                f'{catalog._hash((bundle / name).read_bytes())}  {name}\n'
                for name in sorted([e['path'] for e in overlap_manifest['files']] +
                                   list(overlap_manifest['auxiliary']) + ['manifest.json'])))
            api = API()
            with self.assertRaises(ValueError):
                flash('COM1', FlashPlan(identity, 'esp32c3', tuple(
                    Image(e['offset'], bundle / e['path'], e['size'], e['sha256'])
                    for e in overlap_manifest['files']), True, identity.base_mac, True, bundle), api)
            self.assertIsNone(api.written)
            partition_image.write_bytes(original_partition)
            (bundle / 'manifest.json').write_bytes(original_manifest)
            (bundle / 'SHA256SUMS').write_bytes(original_sums)
            (bundle / 'signature.json').write_bytes(original_sig)
            rogue = root / 'rogue.pem'
            catalog.generate_key(rogue)
            signature_file = bundle / 'signature.json'
            original_signature = signature_file.read_bytes()
            signature_file.write_bytes(catalog._json(catalog._sign(manifest, rogue)))
            api = API()
            with self.assertRaises(ValueError):
                flash('COM1', FlashPlan(identity, 'esp32c3', images, True,
                                       identity.base_mac, True, bundle), api)
            self.assertIsNone(api.written)
            signature_file.write_bytes(original_signature)
            from hil import flash as hil_flash
            cmd, files, fallback = hil_flash.build_write_flash_cmd(
                str(bundle), 'COM1', 'esptool', 'esp32c3', 460800, False)
            self.assertFalse(fallback)
            self.assertEqual(len(files), 3)
            self.assertIn('--flash-mode', cmd)
            for file in ('images/application.bin', 'sdkconfig', 'flasher_args.json', 'manifest.json'):
                path = bundle / file
                original = path.read_bytes()
                path.write_bytes(original + b'evil')
                with self.assertRaises(ValueError, msg=file):
                    catalog.verify_bundle(bundle, public)
                with patch.object(hil_flash, 'preflight_board') as probe:
                    board = type('Board', (), {'chip': 'esp32c3', 'app': 'reference_node'})()
                    with self.assertRaises(ValueError):
                        hil_flash.flash_board(board, 'COM1', str(root / 'logs'),
                                              repo=str(Path(__file__).resolve().parents[3]),
                                              image_dir=str(bundle))
                    probe.assert_not_called()
                path.write_bytes(original)
            data = json.loads(index.read_text())
            data['catalog']['entries'][0]['manifest_sha256'] = '0' * 64
            data['signature'] = catalog._sign(data['catalog'], key)
            index.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                catalog.verify_catalog(index, public, [bundle])
            data['catalog']['entries'][0]['chip'] = 'esp32s3'
            index.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                catalog.verify_catalog(index, public)

    def test_spoofed_signature_claim_never_writes(self):
        class API:
            __version__ = '5.4.0'
            def __init__(self):
                self.writes = 0
            def detect_chip(self, **kwargs):
                raise AssertionError('unsigned plan reached ROM')
            def write_flash(self, *args, **kwargs):
                self.writes += 1
        identity = Identity('esp32c3', '1', 'aa:bb:cc:dd:ee:01', None, '164020',
                            4 * 1024 * 1024, False, False)
        api = API()
        with self.assertRaises(ValueError):
            flash('COM1', FlashPlan(identity, 'esp32c3', (), True, identity.base_mac, True), api)
        self.assertEqual(api.writes, 0)

    def test_signed_partition_layout_matches_csv_and_role(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            catalog.verify_bundle(bundle, public)
            csv_file = bundle / 'partition-table.csv'
            csv_file.write_text(csv_file.read_text().replace(
                'rlsec,data,nvs,0x190000,0x10000', 'rlsec,data,nvs,0x190000,0x20000'))
            manifest = json.loads((bundle / 'manifest.json').read_text())
            manifest['partition_layout_id'] = catalog._hash(csv_file.read_bytes())
            manifest['auxiliary']['partition-table.csv'] = manifest['partition_layout_id']
            (bundle / 'manifest.json').write_bytes(catalog._json(manifest))
            self.resign(bundle, key)
            with self.assertRaises(ValueError):
                catalog.verify_bundle(bundle, public)

    def test_signed_partition_bytes_match_role_layout(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            path = bundle / 'images/partition_table/partition-table.bin'
            table = bytearray(path.read_bytes())
            table[96 + 8:96 + 12] = (0x8000).to_bytes(4, 'little')
            table[128 + 16:128 + 32] = hashlib.md5(table[:128]).digest()
            path.write_bytes(table)
            manifest = json.loads((bundle / 'manifest.json').read_text())
            for entry in manifest['files']:
                if entry['offset'] == 0x8000:
                    entry['sha256'] = catalog._hash(table)
            (bundle / 'manifest.json').write_bytes(catalog._json(manifest))
            self.resign(bundle, key)
            with self.assertRaises(ValueError):
                catalog.verify_bundle(bundle, public)

    def test_signed_revision_range_cannot_exceed_image_headers(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            manifest = catalog.package(app, build, bundle, key, 'esp32c3',
                                       'reference_node', 'test-1', 'a' * 40, 'b' * 64)
            self.assertEqual(manifest['chip_revision_range'], [1, 199])
            manifest['chip_revision_range'] = [0, 255]
            (bundle / 'manifest.json').write_bytes(catalog._json(manifest))
            self.resign(bundle, key)
            with self.assertRaises(ValueError):
                catalog.verify_bundle(bundle, public)

    def test_catalog_pins_actual_manifest_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            manifest_file = bundle / 'manifest.json'
            manifest = json.loads(manifest_file.read_text())
            manifest_file.write_text(json.dumps(manifest, indent=2))
            (bundle / 'SHA256SUMS').write_text(''.join(
                f'{catalog._hash((bundle / name).read_bytes())}  {name}\n'
                for name in sorted([e['path'] for e in manifest['files']] +
                                   list(manifest['auxiliary']) + ['manifest.json'])))
            catalog.verify_bundle(bundle, public)
            index = root / 'catalog.json'
            catalog.create_catalog([bundle], index, key)
            self.assertEqual(len(catalog.verify_catalog(index, public, [bundle])), 1)

    def test_signed_application_role_matches_image(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            csv_file = app / 'partitions.csv'
            csv_file.write_text(csv_file.read_text().replace(
                'rlsec,data,nvs,0x190000,0x10000', 'rlsec,data,nvs,0x190000,0x20000'))
            table_file = build / 'partition_table/partition-table.bin'
            table = bytearray(table_file.read_bytes())
            table[96 + 8:96 + 12] = (0x20000).to_bytes(4, 'little')
            table[128 + 16:128 + 32] = hashlib.md5(table[:128]).digest()
            table_file.write_bytes(table)
            with self.assertRaises(ValueError):
                catalog.package(app, build, root / 'wrong-role', key, 'esp32c3',
                                'bridge_node', 'test-1', 'a' * 40, 'b' * 64)

    def test_c5_bootloader_uses_chip_specific_offset(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            config = app / 'sdkconfig'
            config.write_text(config.read_text().replace('esp32c3', 'esp32c5').replace(
                'CONFIG_BOOTLOADER_OFFSET_IN_FLASH=0x0',
                'CONFIG_BOOTLOADER_OFFSET_IN_FLASH=0x2000'))
            args_file = build / 'flasher_args.json'
            args = json.loads(args_file.read_text())
            args['flash_files']['0x2000'] = args['flash_files'].pop('0x0')
            args['extra_esptool_args']['chip'] = 'esp32c5'
            args_file.write_text(json.dumps(args))
            for name in ('bootloader/bootloader.bin', 'reference_node.bin'):
                path = build / name
                data = bytearray(path.read_bytes())
                data[12:14] = (23).to_bytes(2, 'little')
                path.write_bytes(data)
            bundle = root / 'bundle'
            manifest = catalog.package(app, build, bundle, key, 'esp32c5',
                                       'reference_node', 'test-1', 'a' * 40, 'b' * 64)
            self.assertEqual(manifest['files'][0]['offset'], 0x2000)
            catalog.verify_bundle(bundle, public)

    def test_profile_metadata_follows_resolved_config(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            manifest = catalog.package(app, build, bundle, key, 'esp32c3',
                                       'reference_node', 'test-1', 'a' * 40, 'b' * 64)
            self.assertEqual(manifest['security_profile'], 'dev-ram')
            self.assertEqual(manifest['power_profile'], 'always-on')
            manifest['security_profile'] = 'member-edhoc'
            (bundle / 'manifest.json').write_bytes(catalog._json(manifest))
            self.resign(bundle, key)
            with self.assertRaises(ValueError):
                catalog.verify_bundle(bundle, public)

    def test_signed_image_header_flash_mode_must_match_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            image = bundle / 'images/application.bin'
            data = bytearray(image.read_bytes())
            data[2] = 0  # QIO while the signed config and manifest specify DIO.
            image.write_bytes(data)
            manifest = json.loads((bundle / 'manifest.json').read_text())
            for entry in manifest['files']:
                if entry['offset'] == 0x10000:
                    entry['sha256'] = catalog._hash(data)
            (bundle / 'manifest.json').write_bytes(catalog._json(manifest))
            self.resign(bundle, key)
            with self.assertRaises(ValueError):
                catalog.verify_bundle(bundle, public)

    def test_flash_header_and_resolved_settings_must_agree(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            config = app / 'sdkconfig'
            config.write_text(config.read_text().replace(
                'CONFIG_ESPTOOLPY_FLASHMODE="dio"', 'CONFIG_ESPTOOLPY_FLASHMODE="qio"'))
            with self.assertRaises(ValueError):
                catalog.package(app, build, root / 'wrong-mode', key, 'esp32c3',
                                'reference_node', 'test-1', 'a' * 40, 'b' * 64)
            config.write_text(config.read_text().replace(
                'CONFIG_ESPTOOLPY_FLASHMODE="qio"', 'CONFIG_ESPTOOLPY_FLASHMODE="dio"'))
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            manifest = json.loads((bundle / 'manifest.json').read_text())
            manifest['flash_mode'] = 'qio'
            (bundle / 'manifest.json').write_bytes(catalog._json(manifest))
            self.resign(bundle, key)
            with self.assertRaises(ValueError):
                catalog.verify_bundle(bundle, public)

    def test_header_flash_capacity_is_required_at_preflight(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            config = app / 'sdkconfig'
            config.write_text(config.read_text().replace(
                'CONFIG_ESPTOOLPY_FLASHSIZE="2MB"', 'CONFIG_ESPTOOLPY_FLASHSIZE="4MB"'))
            args_file = build / 'flasher_args.json'
            args = json.loads(args_file.read_text())
            args['flash_settings']['flash_size'] = '4MB'
            args['write_flash_args'][3] = '4MB'
            args_file.write_text(json.dumps(args))
            for name in ('bootloader/bootloader.bin', 'reference_node.bin'):
                path = build / name
                header = bytearray(path.read_bytes())
                header[3] = 0x2f
                path.write_bytes(header)
            bundle = root / 'bundle'
            manifest = catalog.package(app, build, bundle, key, 'esp32c3',
                                       'reference_node', 'test-1', 'a' * 40, 'b' * 64)
            self.assertGreaterEqual(manifest['minimum_flash_bytes'], 4 * 1024 * 1024)
            catalog.verify_bundle(bundle, public)

    def test_dev_ram_deep_sleep_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            config = app / 'sdkconfig'
            config.write_text(config.read_text() + 'CONFIG_ROUTELOOM_DEEP_SLEEP=y\n')
            with self.assertRaises(ValueError):
                catalog.package(app, build, root / 'invalid-sleep', key, 'esp32c3',
                                'reference_node', 'test-1', 'a' * 40, 'b' * 64)

    def test_signed_hil_flash_uses_verified_image_snapshot(self):
        from hil import flash as hil_flash
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            original = (bundle / 'images/application.bin').read_bytes()
            board = type('Board', (), {'name': 'ref', 'chip': 'esp32c3',
                                      'app': 'reference_node', 'flash_baud': 460800,
                                      'console': 'none'})()
            flashed = []
            def preflight(*args, **kwargs):
                (bundle / 'images/application.bin').write_bytes(b'evil')
                return {'chip': 'esp32c3', 'mac': 'aa:bb:cc:dd:ee:01'}
            def run(cmd, **kwargs):
                flashed.append(Path(cmd[cmd.index('0x10000') + 1]).read_bytes())
                return subprocess.CompletedProcess(cmd, 0, '', '')
            with patch.object(hil_flash, 'preflight_board', side_effect=preflight), \
                    patch.object(hil_flash.subprocess, 'run', side_effect=run):
                result = hil_flash.flash_board(board, 'COM1', str(root / 'logs'),
                                               image_dir=str(bundle), boot_seconds=0)
            self.assertTrue(result['ok'])
            self.assertEqual(flashed, [original])

    def test_hil_snapshot_uses_its_own_signed_flash_requirement(self):
        from hil import flash as hil_flash
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            board = type('Board', (), {'chip': 'esp32c3',
                                      'app': 'reference_node'})()
            original_verify = catalog.verify_bundle
            calls = 0

            def replace_after_initial_verify(path, public_key):
                nonlocal calls
                manifest = original_verify(path, public_key)
                calls += 1
                if calls == 1:
                    replacement = dict(manifest)
                    replacement['minimum_flash_bytes'] = 8 * 1024 * 1024
                    (bundle / 'manifest.json').write_bytes(catalog._json(replacement))
                    self.resign(bundle, key)
                return manifest

            def simulated_flash(*args, **kwargs):
                self.assertEqual(args[-1], (1, 199))
                if args[-2] <= 4 * 1024 * 1024:
                    return {'wrote': True}
                raise hil_flash.FlashError('board flash is too small')

            with patch.object(catalog, 'verify_bundle',
                              side_effect=replace_after_initial_verify), \
                    patch.object(hil_flash, '_flash_board_from_dir',
                                 side_effect=simulated_flash):
                with self.assertRaises(hil_flash.FlashError):
                    hil_flash.flash_board(board, 'COM1', str(root / 'logs'),
                                          image_dir=str(bundle))
            self.assertEqual(calls, 2)

    def test_hil_signed_bundle_rejects_app_only_without_partition_readback(self):
        from hil import flash as hil_flash
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            board = type('Board', (), {'chip': 'esp32c3',
                                      'app': 'reference_node'})()
            with patch.object(hil_flash, '_flash_board_from_dir',
                              return_value={'wrote': True}) as writer:
                with self.assertRaises(hil_flash.FlashError):
                    hil_flash.flash_board(board, 'COM1', str(root / 'logs'),
                                          image_dir=str(bundle), app_only=True)
                writer.assert_not_called()

    def test_oversized_bundle_file_is_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            image = bundle / 'images/application.bin'
            with image.open('ab') as fh:
                fh.truncate(3 * 1024 * 1024)
            original_read = Path.read_bytes
            def guard(path):
                if path == image:
                    raise AssertionError('oversized untrusted image was read')
                return original_read(path)
            with patch.object(Path, 'read_bytes', guard), self.assertRaises(ValueError):
                catalog.verify_bundle(bundle, public)

    def test_oversized_catalog_is_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'catalog.json'
            with path.open('wb') as fh:
                fh.truncate(3 * 1024 * 1024)
            original_read = Path.read_bytes
            def guard(candidate):
                if candidate == path:
                    raise AssertionError('oversized untrusted catalog was read')
                return original_read(candidate)
            with patch.object(Path, 'read_bytes', guard), self.assertRaises(ValueError):
                catalog.verify_catalog(path, Path(td) / 'unused-public.pem')

    def test_hil_snapshot_copy_remains_bounded_after_verification(self):
        from hil import flash as hil_flash
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app, build, key, public = self.fixture(root)
            bundle = root / 'bundle'
            catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node',
                            'test-1', 'a' * 40, 'b' * 64)
            image = bundle / 'images/application.bin'
            original_verify = catalog.verify_bundle
            def grow_after_verify(path, public_key):
                manifest = original_verify(path, public_key)
                with image.open('ab') as fh:
                    fh.truncate(3 * 1024 * 1024)
                return manifest
            original_read = Path.read_bytes
            def guard(path):
                if path == image:
                    raise AssertionError('unbounded snapshot read')
                return original_read(path)
            board = type('Board', (), {'chip': 'esp32c3', 'app': 'reference_node'})()
            with patch.object(catalog, 'verify_bundle', side_effect=grow_after_verify), \
                    patch.object(Path, 'read_bytes', guard), self.assertRaises(ValueError):
                hil_flash.flash_board(board, 'COM1', str(root / 'logs'),
                                      image_dir=str(bundle))

    def test_hil_signed_preflight_rejects_flash_smaller_than_bundle(self):
        from hil import flash as hil_flash
        board = type('Board', (), {'name': 'ref', 'chip': 'esp32c3',
                                  'mac': 'aa:bb:cc:dd:ee:01'})()
        identity = 'Chip type: ESP32-C3 (revision v0.4)\nMAC: aa:bb:cc:dd:ee:01\n'
        responses = [subprocess.CompletedProcess([], 0, identity, ''),
                     subprocess.CompletedProcess([], 0, identity +
                                                 'Secure Boot: Disabled\n'
                                                 'Flash Encryption: Disabled\n', ''),
                     subprocess.CompletedProcess([], 0, identity +
                                                 'Detected flash size: 2MB\n', '')]
        with tempfile.TemporaryDirectory() as td:
            with patch.object(hil_flash.subprocess, 'run', side_effect=responses) as run:
                with self.assertRaises(hil_flash.FlashError):
                    hil_flash.preflight_board(board, 'COM1', 'esptool', td,
                                              minimum_flash_bytes=4 * 1024 * 1024)
                self.assertEqual(run.call_count, 3)

    def test_hil_signed_preflight_rejects_incompatible_chip_revision(self):
        from hil import flash as hil_flash
        board = type('Board', (), {'name': 'ref', 'chip': 'esp32c3',
                                  'mac': 'aa:bb:cc:dd:ee:01'})()
        with tempfile.TemporaryDirectory() as td:
            for revision, passes in (('0.2', False), ('0.4', True)):
                identity = (f'Chip type: ESP32-C3 (revision v{revision})\n'
                            'MAC: aa:bb:cc:dd:ee:01\n')
                responses = [subprocess.CompletedProcess([], 0, identity, ''),
                             subprocess.CompletedProcess([], 0, identity +
                                                         'Secure Boot: Disabled\n'
                                                         'Flash Encryption: Disabled\n', ''),
                             subprocess.CompletedProcess([], 0, identity +
                                                         'Detected flash size: 4MB\n', '')]
                with self.subTest(revision=revision), \
                        patch.object(hil_flash.subprocess, 'run',
                                     side_effect=responses) as run:
                    if passes:
                        hil_flash.preflight_board(board, 'COM1', 'esptool', td,
                                                  minimum_flash_bytes=4 * 1024 * 1024,
                                                  chip_revision_range=(3, 199))
                        self.assertEqual(run.call_count, 3)
                    else:
                        with self.assertRaises(hil_flash.FlashError):
                            hil_flash.preflight_board(board, 'COM1', 'esptool', td,
                                                      chip_revision_range=(3, 199))
                        self.assertLessEqual(run.call_count, 2)

    def test_trust_anchor_is_in_installed_package(self):
        self.assertEqual(flash_worker.PUBLIC_KEY.parent,
                         Path(flash_worker.__file__).resolve().parent)
        self.assertTrue(flash_worker.PUBLIC_KEY.is_file())

    def test_resolved_config_rejects_boot_fuse_and_private_credentials(self):
        base = 'CONFIG_IDF_TARGET="esp32c3"\n'
        for line in ('CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y',
                     'CONFIG_FLASH_ENCRYPTION_MODE_RELEASE=y',
                     'CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y',
                     'CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX="1234"',
                     'CONFIG_ROUTELOOM_DISCOVERY_SCOPE_KEY_HEX="1234"',
                     'CONFIG_ROUTELOOM_USB_DEV_SECRET="private-usb-password"'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                catalog.check_config(base + line + '\n', 'esp32c3')

    def test_resolved_partition_offset_must_match_flash_files(self):
        with self.assertRaises(ValueError):
            catalog.check_config('CONFIG_IDF_TARGET="esp32c3"\n'
                                 'CONFIG_PARTITION_TABLE_CUSTOM=y\n'
                                 'CONFIG_PARTITION_TABLE_FILENAME="partitions.csv"\n'
                                 'CONFIG_PARTITION_TABLE_OFFSET=0x9000\n'
                                 'CONFIG_PARTITION_TABLE_MD5=y\n'
                                 'CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM=y\n', 'esp32c3')

    def test_source_build_rejects_fuse_options_before_docker(self):
        script = Path(__file__).resolve().parents[2] / 'hil' / 'build_image.sh'
        with tempfile.TemporaryDirectory() as td:
            for option in ('CONFIG_SECURE_BOOT=y', 'CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y',
                           'CONFIG_SECURE_FLASH_ENC_ENABLED=y', 'CONFIG_FLASH_ENCRYPTION_MODE_RELEASE=y',
                           'CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y\nCONFIG_SECURE_BOOT=y'):
                result = subprocess.run(['bash', str(script), 'reference_node', 'esp32c3',
                                         str(Path(td) / 'bundle'), option], capture_output=True)
                self.assertNotEqual(result.returncode, 0, option)
                self.assertFalse((Path(td) / 'bundle').exists())

    def test_source_digest_snapshot_contains_build_backend(self):
        script = Path(__file__).resolve().parents[1] / 'build_bundle.sh'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / 'staged.txt'
            rsync = root / 'rsync'
            rsync.write_text('#!/bin/bash\n'
                             '/usr/bin/rsync "$@"\n'
                             'for argument in "$@"; do destination=$argument; done\n'
                             'if test -f "$destination/tools/meshviz/build_bundle.sh"; '
                             'then echo present > "$STAGE_MARKER"; '
                             'else echo missing > "$STAGE_MARKER"; fi\n')
            rsync.chmod(0o755)
            docker = root / 'docker'
            docker.write_text('#!/bin/sh\nexit 1\n')
            docker.chmod(0o755)
            env = {**os.environ, 'PATH': f'{root}:{os.environ["PATH"]}',
                   'STAGE_MARKER': str(marker)}
            subprocess.run([str(script), 'reference_node', 'esp32c3',
                            str(root / 'bundle'), str(root / 'key'), 'test'],
                           env=env, capture_output=True, check=False)
            self.assertEqual(marker.read_text().strip(), 'present')

    def test_builder_uses_snapshot_for_image_pin(self):
        script = Path(__file__).resolve().parents[1] / 'build_bundle.sh'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / 'image.txt'
            rsync = root / 'rsync'
            rsync.write_text(
                '#!/bin/bash\n'
                '/usr/bin/rsync "$@"\n'
                'for argument in "$@"; do destination=$argument; done\n'
                'python3 - "$destination/tools/meshviz/src/routeloom_meshviz/'
                'firmware_catalog.py" <<\'PY\'\n'
                'from pathlib import Path\n'
                'import re\n'
                'path = Path(__import__("sys").argv[1])\n'
                'text = path.read_text()\n'
                'path.write_text(re.sub(r"^IDF_IMAGE = .*?$", '
                '\"IDF_IMAGE = \'snapshot-image\'\", text, flags=re.M))\n'
                'PY\n')
            rsync.chmod(0o755)
            docker = root / 'docker'
            docker.write_text('#!/bin/bash\n'
                              'for argument in "$@"; do '
                              'if [[ $argument == snapshot-image ]]; then '
                              'echo snapshot > "$IMAGE_MARKER"; fi; done\n'
                              'exit 7\n')
            docker.chmod(0o755)
            env = {**os.environ, 'PATH': f'{root}:{os.environ["PATH"]}',
                   'IMAGE_MARKER': str(marker)}
            result = subprocess.run([str(script), 'reference_node', 'esp32c3',
                                     str(root / 'bundle'), str(root / 'key'), 'test'],
                                    env=env, capture_output=True, check=False)
            self.assertEqual(result.returncode, 7, result.stderr.decode())
            self.assertEqual(marker.read_text().strip(), 'snapshot')

    def test_source_digest_rejects_unhashed_symlink_inputs(self):
        script = Path(__file__).resolve().parents[1] / 'build_bundle.sh'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            rsync = root / 'rsync'
            rsync.write_text('#!/bin/bash\n'
                             '/usr/bin/rsync "$@"\n'
                             'for argument in "$@"; do destination=$argument; done\n'
                             'ln -s /etc/hosts "$destination/firmware/reference_node/'
                             'unhashed-link"\n')
            rsync.chmod(0o755)
            docker = root / 'docker'
            docker.write_text('#!/bin/sh\nexit 7\n')
            docker.chmod(0o755)
            env = {**os.environ, 'PATH': f'{root}:{os.environ["PATH"]}'}
            result = subprocess.run([str(script), 'reference_node', 'esp32c3',
                                     str(root / 'bundle'), str(root / 'key'), 'test'],
                                    env=env, capture_output=True)
            self.assertIn(b'symlink input', result.stderr)

    def test_hil_experimental_c6_still_reaches_build_backend(self):
        script = Path(__file__).resolve().parents[2] / 'hil' / 'build_image.sh'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            docker = root / 'docker'
            docker.write_text('#!/bin/sh\nexit 7\n')
            docker.chmod(0o755)
            env = {**os.environ, 'PATH': f'{root}:{os.environ["PATH"]}'}
            result = subprocess.run([str(script), 'reference_node', 'esp32c6',
                                     'review-c6'], env=env, capture_output=True)
            self.assertEqual(result.returncode, 7, result.stderr.decode())

    def test_hil_quickstart_uses_current_bundle_path(self):
        root = Path(__file__).resolve().parents[3]
        guide = (root / 'docs/hil.md').read_text()
        self.assertIn('--image-dir artifacts/hil/images/ref-a', guide)

    def test_experimental_c6_bundle_does_not_enter_mesh_lab_worker(self):
        identity = Identity('esp32c6', '1', 'aa:bb:cc:dd:ee:01', None, '164020',
                            4 * 1024 * 1024, False, False)
        class API:
            __version__ = '5.4.0'
            def detect_chip(self, **kwargs):
                raise AssertionError('experimental C6 reached ROM')
        plan = FlashPlan(identity, 'esp32c6', (), True, identity.base_mac, True,
                         Path('experimental-bundle'))
        with patch.object(flash_worker, 'verify_bundle', return_value={'chip': 'esp32c6'}):
            with self.assertRaises(ValueError):
                flash('COM1', plan, API())

    def test_c6_rom_capability_does_not_enable_secure_boot(self):
        with tempfile.TemporaryDirectory() as td:
            app, build, key, public = self.fixture(Path(td))
            config = (app / 'sdkconfig').read_text().replace('esp32c3', 'esp32c6')
            config += 'CONFIG_ESP_ROM_SUPPORT_SECURE_BOOT_FAST_WAKEUP=y\n'
            self.assertEqual(catalog.check_config(config, 'esp32c6')[0], 'dev-ram')
            with self.assertRaises(ValueError):
                catalog.check_config(config + 'CONFIG_SECURE_BOOT=y\n', 'esp32c6')

    def test_c5_secure_boot_warning_symbol_is_not_activation(self):
        with tempfile.TemporaryDirectory() as td:
            app, build, key, public = self.fixture(Path(td))
            config = (app / 'sdkconfig').read_text().replace('esp32c3', 'esp32c5').replace(
                'CONFIG_BOOTLOADER_OFFSET_IN_FLASH=0x0',
                'CONFIG_BOOTLOADER_OFFSET_IN_FLASH=0x2000')
            config += 'CONFIG_SECURE_BOOT_V2_ECDSA_INSECURE=y\n'
            self.assertEqual(catalog.check_config(config, 'esp32c5')[0], 'dev-ram')
            with self.assertRaises(ValueError):
                catalog.check_config(config + 'CONFIG_SECURE_BOOT_V2_FORCE_ENABLE_ECDSA=y\n',
                                     'esp32c5')


if __name__ == '__main__':
    unittest.main()

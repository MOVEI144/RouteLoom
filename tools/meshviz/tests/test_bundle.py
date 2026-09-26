"""Offline signed firmware and build safety regression scenarios."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from routeloom_meshviz import firmware_catalog as catalog
from routeloom_meshviz.device import FlashPlan, Identity, Image
from routeloom_meshviz.flash_worker import flash


class BundleTests(unittest.TestCase):
    def test_offline_bundle_and_catalog_detect_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            build = root / 'build'
            (build / 'bootloader').mkdir(parents=True)
            (build / 'partition_table').mkdir()
            header = bytearray(32)
            header[0] = 0xe9
            header[12:14] = (5).to_bytes(2, 'little')
            partition = bytearray(32)
            partition[:4] = b'\xaa\x50\x00\x00'
            partition[4:8] = (0x10000).to_bytes(4, 'little')
            partition[8:12] = (0x180000).to_bytes(4, 'little')
            for name, image in (('bootloader/bootloader.bin', bytes(header)),
                                ('partition_table/partition-table.bin', bytes(partition)),
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
            (app / 'sdkconfig').write_text('CONFIG_IDF_TARGET="esp32c3"\n')
            (app / 'partitions.csv').write_text('nvs,data,nvs,0x9000,0x6000\nfactory,app,factory,0x10000,0x180000\n')
            (build / 'ram-report.json').write_text('{}')
            key = root / 'private.pem'
            shutil.copyfile(Path(__file__).resolve().parents[1] /
                            'packaging/dev-signing-key.pem', key)
            public = root / 'public.pem'
            catalog.export_public_key(key, public)
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

    def test_resolved_config_rejects_boot_fuse_and_private_credentials(self):
        base = 'CONFIG_IDF_TARGET="esp32c3"\n'
        for line in ('CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y',
                     'CONFIG_FLASH_ENCRYPTION_MODE_RELEASE=y',
                     'CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y',
                     'CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX="1234"',
                     'CONFIG_ROUTELOOM_DISCOVERY_SCOPE_KEY_HEX="1234"'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                catalog.check_config(base + line + '\n', 'esp32c3')

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


if __name__ == '__main__':
    unittest.main()

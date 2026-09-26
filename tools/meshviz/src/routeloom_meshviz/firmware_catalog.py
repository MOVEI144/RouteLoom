"""Development Ed25519 firmware bundles. The signing key is not a production key."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

IDF_COMMIT = '76f5dedd9950a3012fee8fb7d5586df21fc67802'
CHIPS = ('esp32c3', 'esp32s3', 'esp32c5')


def _json(data):
    return (json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _read(root, name):
    # Never follow symlinks or accept paths escaping the bundle directory.
    if not isinstance(name, str) or not name or Path(name).is_absolute() or any(
            part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('unsafe bundle path')
    path = root / name
    if any(p.is_symlink() for p in (path, *path.parents) if p != root and root in p.parents):
        raise ValueError('symlink in bundle')
    return path.read_bytes()


def _private(path):
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('Ed25519 signing key required')
    return key


def generate_key(path):
    path = Path(path)
    if path.exists():
        raise ValueError('key already exists')
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)


def export_public_key(private, public):
    Path(public).write_bytes(_private(private).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def _sign(data, key):
    return {'algorithm': 'Ed25519', 'signature': _private(key).sign(_json(data)).hex()}


def _verify(data, signature, public):
    try:
        if signature['algorithm'] != 'Ed25519':
            raise ValueError('unsupported signature')
        key = serialization.load_pem_public_key(Path(public).read_bytes())
        key.verify(bytes.fromhex(signature['signature']), _json(data))
    except (InvalidSignature, KeyError, TypeError, AttributeError) as exc:
        raise ValueError('invalid signature') from exc


def check_config(text, chip):
    if chip not in CHIPS or f'CONFIG_IDF_TARGET="{chip}"' not in text.splitlines():
        raise ValueError('resolved target mismatch')
    # All security-boot/flash-encryption variants are denied, not just the
    # top-level switches: some modes program eFuses on the first boot.
    for line in text.splitlines():
        # Shared development credentials are public; never export a personalized key.
        if line.startswith('CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX=') and line != (
                'CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX='
                '"524f5554454c4f4f4d2d444556454c4f504d454e542d4b45592d4f4e4c592121"'):
            raise ValueError('private development key in bundle')
        if line.startswith('CONFIG_ROUTELOOM_DISCOVERY_SCOPE_KEY_HEX=') and line != (
                'CONFIG_ROUTELOOM_DISCOVERY_SCOPE_KEY_HEX=""'):
            raise ValueError('private discovery key in bundle')
        passive = ('CONFIG_SOC_', 'CONFIG_SECURE_BOOT_V2_RSA_SUPPORTED=',
                   'CONFIG_SECURE_BOOT_V2_PREFERRED=', 'CONFIG_SECURE_BOOT_IMAGE_DIGEST_LEN=',
                   'CONFIG_SECURE_BOOT_ROM_FAST_WAKE_RESERVE_SIZE=',
                   'CONFIG_EFUSE_MAX_BLK_LEN=', 'CONFIG_ESP_EFUSE_BLOCK_REV_')
        if not line.startswith(passive) and re.match(
                r'^CONFIG_[A-Z0-9_]*(?:SECURE_BOOT|FLASH_ENCRYPT|SECURE_FLASH_ENC|EFUSE|ANTI_ROLLBACK|SECURE_VERSION)[A-Z0-9_]*=', line):
            if not line.endswith('=n'):
                raise ValueError(f'security fuse build setting forbidden: {line}')


def _flash_files(args, build):
    files = args.get('flash_files')
    if not isinstance(files, dict) or len(files) != 3:
        raise ValueError('bootloader, partition and app required')
    settings = args.get('flash_settings', {})
    if (settings.get('flash_mode') not in ('dio', 'dout', 'qio', 'qout') or
            settings.get('flash_freq') not in ('40m', '80m') or
            settings.get('flash_size') not in ('2MB', '4MB', '8MB', '16MB') or
            args.get('write_flash_args') != ['--flash-mode', settings['flash_mode'],
                                             '--flash-size', settings['flash_size'],
                                             '--flash-freq', settings['flash_freq']] or
            any(args.get(section, {}).get('encrypted') != 'false'
                for section in ('bootloader', 'partition-table', 'app'))):
        raise ValueError('unreviewed flash parameters')
    result = []
    names = {0: 'images/bootloader/bootloader.bin',
             0x8000: 'images/partition_table/partition-table.bin',
             0x10000: 'images/application.bin'}
    for raw, src in files.items():
        offset = int(raw, 0)
        if offset not in names or type(src) is not str or not src.endswith('.bin'):
            raise ValueError('unexpected flash layout')
        data = _read(build, src)
        result.append((offset, names[offset], data))
    if set(o for o, _, _ in result) != set(names):
        raise ValueError('missing flash image')
    return sorted(result)


def package(app, build, out, private, chip, role, version, sdk_commit, source_digest):
    app, build, out = Path(app), Path(build), Path(out)
    if out.exists() or chip not in CHIPS or role not in ('bridge_node', 'reference_node'):
        raise ValueError('invalid output or profile')
    config = _read(app, 'sdkconfig').decode()
    check_config(config, chip)
    args = json.loads(_read(build, 'flasher_args.json'))
    if args.get('extra_esptool_args', {}).get('chip') != chip:
        raise ValueError('flasher chip mismatch')
    images = _flash_files(args, build)
    csv = _read(app, 'partitions.csv')
    if b'0x10000' not in csv or b'0x180000' not in csv:
        raise ValueError('unknown partition layout')
    out.mkdir(parents=True)
    entries = []
    for offset, name, data in images:
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entries.append({'offset': offset, 'path': name, 'size': len(data), 'sha256': _hash(data)})
    normalized = {'flash_files': {hex(o): name for o, name, _ in images},
                  'app': {'offset': '0x10000', 'file': 'images/application.bin'},
                  'extra_esptool_args': {'chip': chip},
                  'write_flash_args': ['--flash-mode', 'keep', '--flash-freq', 'keep',
                                       '--flash-size', 'keep']}
    auxiliary = {'flasher_args.json': _json(normalized), 'sdkconfig': config.encode(),
                 'partition-table.csv': csv, 'ram-report.json': _read(build, 'ram-report.json')}
    info = {'sdk_commit': sdk_commit, 'idf_commit': IDF_COMMIT,
            'idf_image': 'espressif/idf:v6.0.3', 'chip': chip, 'role': role,
            'firmware_version': version, 'toolchain': 'ESP-IDF v6.0.3',
            'source_digest': source_digest, 'origin': 'local-build'}
    auxiliary['build-info.json'] = _json(info)
    auxiliary['LICENSES/LICENSE'] = _read(app.parents[1], 'LICENSE')
    auxiliary['LICENSES/NOTICE'] = _read(app.parents[1], 'NOTICE')
    for name, data in auxiliary.items():
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = {'schema_version': 'firmware-bundle-v1', 'bundle_id': f'{version}-{role}-{chip}',
                **info, 'chip_revision_range': [0, 255], 'board_compatibility': [chip],
                'security_profile': 'resolved-sdkconfig', 'power_profile': 'resolved-sdkconfig',
                'capabilities': [], 'minimum_flash_bytes': 0x1b0000,
                'flash_mode': args['flash_settings']['flash_mode'],
                'flash_frequency': args['flash_settings']['flash_freq'],
                'partition_layout_id': _hash(csv), 'config_schema': 0,
                'files': entries, 'forbidden_security_features_disabled': True,
                'auxiliary': {name: _hash(data) for name, data in auxiliary.items()}}
    (out / 'manifest.json').write_bytes(_json(manifest))
    (out / 'SHA256SUMS').write_text(''.join(
        f'{_hash(_read(out, name))}  {name}\n' for name in sorted([e['path'] for e in entries] +
                                                list(auxiliary) + ['manifest.json'])))
    (out / 'signature.json').write_bytes(_json(_sign(manifest, private)))
    return manifest


def verify_bundle(root, public):
    root = Path(root)
    manifest = json.loads(_read(root, 'manifest.json'))
    _verify(manifest, json.loads(_read(root, 'signature.json')), public)
    if (manifest.get('schema_version') != 'firmware-bundle-v1' or
            manifest.get('idf_commit') != IDF_COMMIT or
            manifest.get('chip') not in CHIPS or
            manifest.get('flash_mode') not in ('dio', 'dout', 'qio', 'qout') or
            manifest.get('flash_frequency') not in ('40m', '80m') or
            type(manifest.get('minimum_flash_bytes')) is not int or
            manifest['minimum_flash_bytes'] <= 0 or
            type(manifest.get('chip_revision_range')) is not list or
            len(manifest['chip_revision_range']) != 2 or
            any(type(n) is not int or n < 0 for n in manifest['chip_revision_range']) or
            manifest['chip_revision_range'][0] > manifest['chip_revision_range'][1]):
        raise ValueError('unsupported bundle')
    chip = manifest['chip']
    check_config(_read(root, 'sdkconfig').decode(), chip)
    if _hash(_read(root, 'partition-table.csv')) != manifest['partition_layout_id']:
        raise ValueError('partition mismatch')
    entries = manifest['files']
    expected = {0: 'images/bootloader/bootloader.bin', 0x8000: 'images/partition_table/partition-table.bin',
                0x10000: 'images/application.bin'}
    if (type(entries) is not list or len(entries) != 3 or
            {e['offset']: e['path'] for e in entries} != expected):
        raise ValueError('unexpected image layout')
    for entry in entries:
        data = _read(root, entry['path'])
        if len(data) != entry['size'] or _hash(data) != entry['sha256']:
            raise ValueError('image digest mismatch')
        if entry['offset'] in (0, 0x10000) and (
                len(data) < 24 or data[0] != 0xe9 or
                int.from_bytes(data[12:14], 'little') != {'esp32c3': 5, 'esp32s3': 9,
                                                          'esp32c5': 23}[chip]):
            raise ValueError('image header does not match chip')
        if entry['offset'] == 0x8000 and not any(
                data[i:i+2] == b'\xaa\x50' and data[i+2:i+4] == b'\x00\x00' and
                int.from_bytes(data[i+4:i+8], 'little') == 0x10000 and
                int.from_bytes(data[i+8:i+12], 'little') == 0x180000
                for i in range(0, len(data) - 31, 32)):
            raise ValueError('partition table missing factory layout')
    args = json.loads(_read(root, 'flasher_args.json'))
    if (args.get('flash_files') != {hex(o): p for o, p in expected.items()} or
            args.get('app') != {'offset': '0x10000', 'file': 'images/application.bin'} or
            args.get('extra_esptool_args') != {'chip': chip} or
            args.get('write_flash_args') != ['--flash-mode', 'keep', '--flash-freq', 'keep',
                                             '--flash-size', 'keep']):
        raise ValueError('flasher args mismatch')
    for name, digest in manifest['auxiliary'].items():
        if _hash(_read(root, name)) != digest:
            raise ValueError('auxiliary digest mismatch')
    sums = ''.join(f'{_hash(_read(root, name))}  {name}\n' for name in sorted(
        [e['path'] for e in entries] + list(manifest['auxiliary']) + ['manifest.json']))
    if _read(root, 'SHA256SUMS') != sums.encode():
        raise ValueError('checksums mismatch')
    return manifest


def create_catalog(bundles, path, private):
    entries = []
    for bundle in bundles:
        m = json.loads(_read(Path(bundle), 'manifest.json'))
        entries.append({'bundle_id': m['bundle_id'], 'chip': m['chip'], 'role': m['role'],
                        'version': m['firmware_version'], 'manifest_sha256': _hash(_json(m))})
    index = {'schema_version': 1, 'entries': entries}
    Path(path).write_bytes(_json({'catalog': index, 'signature': _sign(index, private)}))


def verify_catalog(path, public, bundles=()):
    doc = json.loads(Path(path).read_bytes())
    _verify(doc['catalog'], doc['signature'], public)
    if doc['catalog'].get('schema_version') != 1:
        raise ValueError('unsupported catalog')
    entries = doc['catalog']['entries']
    if len({e['bundle_id'] for e in entries}) != len(entries):
        raise ValueError('duplicate bundle ID')
    for bundle in bundles:
        manifest = verify_bundle(bundle, public)
        matches = [e for e in entries if e == {
            'bundle_id': manifest['bundle_id'], 'chip': manifest['chip'],
            'role': manifest['role'], 'version': manifest['firmware_version'],
            'manifest_sha256': _hash(_read(Path(bundle), 'manifest.json'))}]
        if len(matches) != 1:
            raise ValueError('bundle not pinned by catalog')
    return entries


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('package')
    for name in ('app', 'build', 'out', 'key', 'chip', 'role', 'version', 'sdk_commit', 'source_digest'):
        p.add_argument(name)
    p = sub.add_parser('catalog')
    p.add_argument('out'); p.add_argument('key'); p.add_argument('bundles', nargs='+')
    p = sub.add_parser('verify')
    p.add_argument('bundle'); p.add_argument('public')
    p = sub.add_parser('verify-catalog')
    p.add_argument('catalog'); p.add_argument('public'); p.add_argument('bundles', nargs='+')
    args = parser.parse_args()
    if args.command == 'package':
        package(args.app, args.build, args.out, args.key, args.chip, args.role,
                args.version, args.sdk_commit, args.source_digest)
    elif args.command == 'catalog':
        create_catalog(args.bundles, args.out, args.key)
    elif args.command == 'verify':
        verify_bundle(args.bundle, args.public)
    else:
        verify_catalog(args.catalog, args.public, args.bundles)


if __name__ == '__main__':
    main()

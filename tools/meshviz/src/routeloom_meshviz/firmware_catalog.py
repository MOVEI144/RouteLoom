"""Development Ed25519 firmware bundles. The signing key is not a production key."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

IDF_COMMIT = '76f5dedd9950a3012fee8fb7d5586df21fc67802'
IDF_IMAGE = 'espressif/idf@sha256:54278f2c01e6e759502e2f04c9103589c17528923426f4d63193490c7a08f555'
CHIPS = ('esp32c3', 'esp32s3', 'esp32c5', 'esp32c6')
BOOTLOADER_OFFSETS = {'esp32c3': 0, 'esp32s3': 0,
                      'esp32c5': 0x2000, 'esp32c6': 0}
DEV_PUBLIC_KEY = Path(__file__).with_name('dev-signing-public.pem')
PARTITIONS = {
    role: (('nvs', 1, 2, 0x9000, 0x6000),
           ('phy_init', 1, 1, 0xf000, 0x1000),
           ('factory', 0, 0, 0x10000, 0x180000),
           ('rlsec', 1, 2, 0x190000, rlsec_size))
    for role, rlsec_size in (('reference_node', 0x10000), ('bridge_node', 0x20000))
}
AUXILIARY_FILES = frozenset(('flasher_args.json', 'sdkconfig', 'partition-table.csv',
                             'ram-report.json', 'build-info.json', 'LICENSES/LICENSE',
                             'LICENSES/NOTICE'))
INFO_FIELDS = ('sdk_commit', 'idf_commit', 'idf_image', 'chip', 'role',
               'firmware_version', 'toolchain', 'source_digest', 'origin')
MAX_FILE_BYTES = 2 * 1024 * 1024
FLASH_MODES = {'qio': 0, 'qout': 1, 'dio': 2, 'dout': 3}
FLASH_FREQUENCIES = {'40m': 0, '80m': 15}
FLASH_SIZES = {'2MB': 0x10, '4MB': 0x20, '8MB': 0x30, '16MB': 0x40}


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
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
        raise ValueError('bundle file is not a bounded regular file')
    with path.open('rb') as fh:
        data = fh.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError('bundle file grew beyond limit')
    return data


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
    config = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_'):
            name, sep, value = line.partition('=')
            if not sep or name in config:
                raise ValueError('duplicate or malformed resolved config')
            config[name] = value
    if chip not in CHIPS or config.get('CONFIG_IDF_TARGET') != f'"{chip}"':
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
        # The resolved sdkconfig is distributed verbatim, so only the public
        # legacy USB development secret may be exported with bridge images.
        if line.startswith('CONFIG_ROUTELOOM_USB_DEV_SECRET=') and line != (
                'CONFIG_ROUTELOOM_USB_DEV_SECRET="routeloom-dev-secret"'):
            raise ValueError('private USB secret in bundle')
        passive = ('CONFIG_SOC_', 'CONFIG_SECURE_BOOT_V2_RSA_SUPPORTED=',
                   'CONFIG_SECURE_BOOT_V2_ECC_SUPPORTED=',
                   'CONFIG_SECURE_BOOT_V2_ECDSA_INSECURE=',
                   'CONFIG_SECURE_BOOT_V2_PREFERRED=', 'CONFIG_SECURE_BOOT_IMAGE_DIGEST_LEN=',
                   'CONFIG_SECURE_BOOT_ROM_FAST_WAKE_RESERVE_SIZE=',
                   'CONFIG_ESP_ROM_SUPPORT_SECURE_BOOT_FAST_WAKEUP=',
                   'CONFIG_EFUSE_MAX_BLK_LEN=', 'CONFIG_ESP_EFUSE_BLOCK_REV_')
        if not line.startswith(passive) and re.match(
                r'^CONFIG_[A-Z0-9_]*(?:SECURE_BOOT|FLASH_ENCRYPT|SECURE_FLASH_ENC|EFUSE|ANTI_ROLLBACK|SECURE_VERSION)[A-Z0-9_]*=', line):
            if not line.endswith('=n'):
                raise ValueError(f'security fuse build setting forbidden: {line}')
    required = {'CONFIG_PARTITION_TABLE_CUSTOM': 'y',
                'CONFIG_PARTITION_TABLE_FILENAME': '"partitions.csv"',
                'CONFIG_PARTITION_TABLE_OFFSET': '0x8000',
                'CONFIG_PARTITION_TABLE_MD5': 'y',
                'CONFIG_BOOTLOADER_OFFSET_IN_FLASH': hex(BOOTLOADER_OFFSETS[chip])}
    if any(config.get(name) != value for name, value in required.items()):
        raise ValueError('resolved partition-table configuration mismatch')
    modes = {'CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM': 'dev-ram',
             'CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC': 'member-edhoc',
             'CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE': 'legacy-fixture'}
    selected = [profile for name, profile in modes.items() if config.get(name) == 'y']
    if len(selected) != 1:
        raise ValueError('resolved security profile missing or ambiguous')
    deep_sleep = config.get('CONFIG_ROUTELOOM_DEEP_SLEEP') == 'y'
    if deep_sleep and selected[0] == 'dev-ram':
        raise ValueError('DevRam deep sleep is unsupported')
    flash_mode = config.get('CONFIG_ESPTOOLPY_FLASHMODE', '').strip('"')
    flash_frequency = config.get('CONFIG_ESPTOOLPY_FLASHFREQ', '').strip('"')
    flash_size = config.get('CONFIG_ESPTOOLPY_FLASHSIZE', '').strip('"')
    if (flash_mode not in FLASH_MODES or flash_frequency not in FLASH_FREQUENCIES or
            flash_size not in FLASH_SIZES):
        raise ValueError('resolved flash settings unsupported')
    return (selected[0], 'deep-sleep' if deep_sleep else 'always-on',
            flash_mode, flash_frequency, flash_size)


def _check_image_header(data, chip, flash_mode, flash_frequency, flash_size, role=None):
    frequency_bits = 0 if chip == 'esp32c6' and flash_frequency == '80m' else (
        FLASH_FREQUENCIES[flash_frequency])
    if (len(data) < 24 or data[0] != 0xe9 or
            data[2] != FLASH_MODES[flash_mode] or
            data[3] != FLASH_SIZES[flash_size] + frequency_bits or
            int.from_bytes(data[12:14], 'little') != {
                'esp32c3': 5, 'esp32s3': 9, 'esp32c5': 23, 'esp32c6': 13}[chip]):
        raise ValueError('image header does not match chip')
    if role is not None:
        if (len(data) < 112 or data[32:36] != b'\x32\x54\xcd\xab' or
                data[80:112].split(b'\0', 1)[0] != f'routeloom_{role}'.encode()):
            raise ValueError('application image does not match role')
    low = int.from_bytes(data[15:17], 'little')
    high = int.from_bytes(data[17:19], 'little')
    if low > high:
        raise ValueError('invalid image chip revision range')
    return low, high


def _check_partition_csv(data, role):
    names = {'data': 1, 'app': 0}
    subtypes = {'nvs': 2, 'phy': 1, 'factory': 0}
    lines = (line.split('#', 1)[0] for line in data.decode().splitlines())
    entries = []
    try:
        for row in csv.reader(io.StringIO('\n'.join(line for line in lines if line.strip()))):
            if len(row) != 5:
                raise ValueError('invalid partition CSV')
            name, kind, subtype, offset, size = (field.strip() for field in row)
            entries.append((name, names[kind], subtypes[subtype],
                            int(offset, 0), int(size, 0)))
    except (KeyError, UnicodeDecodeError) as exc:
        raise ValueError('invalid partition CSV') from exc
    if tuple(entries) != PARTITIONS[role]:
        raise ValueError('partition CSV does not match role layout')


def _check_partition_table(data, role):
    if len(data) > 0x1000 or len(data) % 32:
        raise ValueError('invalid partition table size')
    entries = []
    for i in range(0, len(data), 32):
        entry = data[i:i + 32]
        if entry[:2] == b'\xeb\xeb':
            if (entry[2:16] != b'\xff' * 14 or
                    entry[16:32] != hashlib.md5(data[:i]).digest() or
                    data[i + 32:] != b'\xff' * (len(data) - i - 32)):
                raise ValueError('invalid partition table checksum')
            if tuple(entries) != PARTITIONS[role]:
                raise ValueError('partition table does not match role layout')
            return
        if entry[:2] != b'\xaa\x50':
            raise ValueError('invalid partition entry')
        name = entry[12:28].split(b'\0', 1)[0].decode('ascii')
        entries.append((name, entry[2], entry[3],
                        int.from_bytes(entry[4:8], 'little'),
                        int.from_bytes(entry[8:12], 'little')))
        if entry[28:32] != b'\0' * 4:
            raise ValueError('unsupported partition flags')
    raise ValueError('partition table checksum missing')


def _flash_files(args, build, chip):
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
    bootloader_offset = BOOTLOADER_OFFSETS[chip]
    names = {bootloader_offset: 'images/bootloader/bootloader.bin',
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
    # Keep bootloader, partition table and factory app inside their own regions;
    # overflowing the factory image would erase persistent rlsec data.
    limits = {bootloader_offset: 0x8000 - bootloader_offset,
              0x8000: 0x1000, 0x10000: 0x180000}
    if any(not data or len(data) > limits[offset] for offset, _, data in result):
        raise ValueError('image exceeds flash partition')
    return sorted(result)


def package(app, build, out, private, chip, role, version, sdk_commit, source_digest):
    app, build, out = Path(app), Path(build), Path(out)
    if out.exists() or chip not in CHIPS or role not in ('bridge_node', 'reference_node'):
        raise ValueError('invalid output or profile')
    config = _read(app, 'sdkconfig').decode()
    security_profile, power_profile, flash_mode, flash_frequency, flash_size = check_config(config, chip)
    if role == 'bridge_node' and power_profile == 'deep-sleep':
        raise ValueError('bridge deep sleep is unsupported')
    args = json.loads(_read(build, 'flasher_args.json'))
    if args.get('extra_esptool_args', {}).get('chip') != chip:
        raise ValueError('flasher chip mismatch')
    if args.get('flash_settings') != {'flash_mode': flash_mode,
                                      'flash_freq': flash_frequency,
                                      'flash_size': flash_size}:
        raise ValueError('resolved flash settings mismatch')
    images = _flash_files(args, build, chip)
    csv = _read(app, 'partitions.csv')
    _check_partition_csv(csv, role)
    revisions = []
    for offset, _, data in images:
        if offset == 0x8000:
            _check_partition_table(data, role)
        else:
            revisions.append(_check_image_header(
                data, chip, flash_mode, flash_frequency, flash_size,
                role if offset == 0x10000 else None))
    revision_low = max(low for low, _ in revisions)
    revision_high = min(high for _, high in revisions)
    if revision_low > revision_high:
        raise ValueError('bootloader and application revision ranges do not overlap')
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
            'idf_image': IDF_IMAGE, 'chip': chip, 'role': role,
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
                **info, 'chip_revision_range': [revision_low, revision_high],
                'board_compatibility': [chip],
                'security_profile': security_profile, 'power_profile': power_profile,
                'capabilities': [], 'minimum_flash_bytes': max(
                    max(offset + size for _, _, _, offset, size in PARTITIONS[role]),
                    int(flash_size[:-2]) * 1024 * 1024),
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
            manifest.get('idf_image') != IDF_IMAGE or
            manifest.get('chip') not in CHIPS or
            manifest.get('role') not in PARTITIONS or
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
    role = manifest['role']
    security_profile, power_profile, flash_mode, flash_frequency, flash_size = check_config(
        _read(root, 'sdkconfig').decode(), chip)
    if (manifest.get('board_compatibility') != [chip] or
            manifest.get('security_profile') != security_profile or
            manifest.get('power_profile') != power_profile or
            manifest.get('flash_mode') != flash_mode or
            manifest.get('flash_frequency') != flash_frequency or
            (role == 'bridge_node' and power_profile == 'deep-sleep') or
            manifest.get('forbidden_security_features_disabled') is not True or
            manifest['minimum_flash_bytes'] < max(
                max(offset + size for _, _, _, offset, size in PARTITIONS[role]),
                int(flash_size[:-2]) * 1024 * 1024)):
        raise ValueError('bundle profile or flash capacity mismatch')
    partition_csv = _read(root, 'partition-table.csv')
    _check_partition_csv(partition_csv, role)
    if _hash(partition_csv) != manifest['partition_layout_id']:
        raise ValueError('partition mismatch')
    entries = manifest['files']
    bootloader_offset = BOOTLOADER_OFFSETS[chip]
    expected = {bootloader_offset: 'images/bootloader/bootloader.bin',
                0x8000: 'images/partition_table/partition-table.bin',
                0x10000: 'images/application.bin'}
    if (type(entries) is not list or len(entries) != 3 or
            {e['offset']: e['path'] for e in entries} != expected):
        raise ValueError('unexpected image layout')
    revisions = []
    for entry in entries:
        data = _read(root, entry['path'])
        limits = {bootloader_offset: 0x8000 - bootloader_offset,
                  0x8000: 0x1000, 0x10000: 0x180000}
        if (type(entry['size']) is not int or not 0 < entry['size'] <= limits[entry['offset']] or
                len(data) != entry['size'] or _hash(data) != entry['sha256']):
            raise ValueError('image digest or partition size mismatch')
        if entry['offset'] == 0x8000:
            _check_partition_table(data, role)
        else:
            revisions.append(_check_image_header(
                data, chip, flash_mode, flash_frequency, flash_size,
                role if entry['offset'] == 0x10000 else None))
    if (manifest['chip_revision_range'][0] < max(low for low, _ in revisions) or
            manifest['chip_revision_range'][1] > min(high for _, high in revisions)):
        raise ValueError('signed chip revisions exceed image compatibility')
    args = json.loads(_read(root, 'flasher_args.json'))
    if (args.get('flash_files') != {hex(o): p for o, p in expected.items()} or
            args.get('app') != {'offset': '0x10000', 'file': 'images/application.bin'} or
            args.get('extra_esptool_args') != {'chip': chip} or
            args.get('write_flash_args') != ['--flash-mode', 'keep', '--flash-freq', 'keep',
                                             '--flash-size', 'keep']):
        raise ValueError('flasher args mismatch')
    if set(manifest['auxiliary']) != AUXILIARY_FILES:
        raise ValueError('required bundle file missing')
    for name, digest in manifest['auxiliary'].items():
        if _hash(_read(root, name)) != digest:
            raise ValueError('auxiliary digest mismatch')
    build_info = json.loads(_read(root, 'build-info.json'))
    if build_info != {name: manifest[name] for name in INFO_FIELDS}:
        raise ValueError('build information mismatch')
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
                        'version': m['firmware_version'],
                        'manifest_sha256': _hash(_read(Path(bundle), 'manifest.json'))})
    index = {'schema_version': 1, 'entries': entries}
    Path(path).write_bytes(_json({'catalog': index, 'signature': _sign(index, private)}))


def verify_catalog(path, public, bundles=()):
    path = Path(path)
    doc = json.loads(_read(path.parent, path.name))
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

#!/usr/bin/env python3
"""Assemble, check and promote release artifacts without rebuilding them."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.check import development_key_errors  # noqa: E402


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest() -> dict:
    return json.loads((ROOT / 'protocol/manifest.json').read_text())


def check_tag(tag: str) -> dict:
    data = manifest()
    if tag != 'v' + data['sdk_version']:
        raise ValueError('tag does not match protocol/manifest.json sdk_version')
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[a-z0-9.]+)?', tag):
        raise ValueError('invalid release tag')
    return data


def firmware_matrix() -> list[dict]:
    cells = json.loads((ROOT / 'tools/ci/cells.json').read_text())['cells']
    matrix = []
    for target in ('esp32c3', 'esp32s3', 'esp32c5', 'esp32c6'):
        for role, app in (('bridge', 'bridge_node'), ('relay', 'reference_node'),
                          ('endpoint', 'reference_node')):
            for mode in ('member', 'devram'):
                security = 'MEMBER_EDHOC' if mode == 'member' else 'DEV_RAM'
                wanted = [f'CONFIG_ROUTELOOM_SECURITY_MODE_{security}=y']
                matches = [c for c in cells if c['target'] == target and c['app'] == app
                           and (c['overlay'] == wanted or not c['overlay'])
                           and wanted[0] in c['overlay'] + c.get('expect', []) and
                           (c['id'].endswith('-owner_member') or c['id'].endswith('-member')
                            if mode == 'member' else c['id'].endswith('-normal-off-off') or
                            c['id'].endswith('-devram'))]
                if len(matches) != 1:
                    raise ValueError(f'release cell missing or ambiguous: {app}/{target}/{mode}')
                cell = matches[0]
                overlay = list(cell['overlay'])
                if role == 'endpoint':
                    overlay += ['CONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT=y',
                                'CONFIG_ROUTELOOM_ROLE_ENDPOINT=y']
                # Release selection is explicit for both security modes.
                if f'CONFIG_ROUTELOOM_SECURITY_MODE_{security}=y' not in overlay:
                    overlay.append(f'CONFIG_ROUTELOOM_SECURITY_MODE_{security}=y')
                matrix.append({'id': f'{role}-{target}-{mode}', 'app': app,
                               'target': target, 'mode': mode, 'role': role,
                               'cell': cell['id'], 'overlay': overlay})
    return matrix


def archive_name(tag: str, entry: dict) -> str:
    return f'routeloom-{tag}-firmware-{entry["id"]}.tar.gz'


def firmware_errors(image: bytes, symbols: list[str], settings: list[str], mode: str) -> list[str]:
    lines = set(settings)
    selected = 'MEMBER_EDHOC' if mode == 'member' else 'DEV_RAM'
    other = 'DEV_RAM' if mode == 'member' else 'MEMBER_EDHOC'
    errors = []
    if (f'CONFIG_ROUTELOOM_SECURITY_MODE_{selected}=y' not in lines or
            f'CONFIG_ROUTELOOM_SECURITY_MODE_{other}=y' in lines):
        errors.append('release security mode disagrees with sdkconfig')
    if mode == 'member':
        errors += development_key_errors(image, settings)
        if 'CONFIG_ROUTELOOM_DEV_KCONFIG_IDENTITY=y' in lines:
            errors.append('product image enables development identity')
        # Inspect the linked ELF: config alone cannot prove a provider was removed.
        if any(re.search(r'Dev(Psk|Group|Scope|Session).*Provider|DevelopmentPskSecurityProvider|'
                         r'DevMembershipHooks|DevPskAuthenticator|DevConfigAuthorityVerifier',
                         name) for name in symbols):
            errors.append('product image links a development provider')
    if 'CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE=y' in lines:
        errors.append('release image enables the provisioning maintenance console')
    return errors


def release_flash_files(args: dict, entry: dict) -> dict[str, str]:
    files = args['flash_files']
    offsets = {int(offset, 0): name for offset, name in files.items()}
    boot_offset = 0x2000 if entry['target'] == 'esp32c5' else 0
    expected = {boot_offset: 'bootloader/bootloader.bin',
                0x8000: 'partition_table/partition-table.bin',
                0x10000: 'ota_data_initial.bin', 0x40000: f'routeloom_{entry["app"]}.bin'}
    if len(files) != 4 or offsets != expected:
        raise ValueError('release flash files disagree with the inspected app / PT-4M-v2')
    if args['extra_esptool_args']['chip'] != entry['target']:
        raise ValueError('release flash target disagrees with the matrix')
    return files


def inventory(metadata: dict, lock: dict, notice: str, vendors: dict) -> list[dict]:
    external = [p for p in metadata['packages'] if p['id'] not in metadata['workspace_members']]
    resolved = {(p['name'], p['version'], p.get('source')) for p in external}
    locked = {(p['name'], p['version'], p.get('source')) for p in lock['package'] if 'source' in p}
    if resolved != locked:
        raise ValueError('cargo metadata does not match Cargo.lock dependencies')
    reviewed = set(re.findall(r'^Cargo: (\S+) (\S+) \| (.+)$', notice, re.M))
    expected = {(p['name'], p['version'], (p.get('license') or '').replace('/', ' OR '))
                for p in external}
    if reviewed != expected or any(not row[2] for row in expected):
        raise ValueError('NOTICE Cargo inventory differs from resolved dependencies/licenses')
    checksums = {(p['name'], p['version']): p['checksum'] for p in lock['package'] if 'source' in p}
    components = [{'type': 'library', 'name': p['name'], 'version': p['version'],
                   'purl': f'pkg:cargo/{p["name"]}@{p["version"]}',
                   'hashes': [{'alg': 'SHA-256', 'content': checksums[p['name'], p['version']]}],
                   'licenses': [{'expression': p['license'].replace('/', ' OR ')}]}
                  for p in sorted(external, key=lambda p: (p['name'], p['version']))]
    names = {'micro-ecc'} | {v['directory'] for v in vendors['components']}
    directories = {p.name for p in (ROOT / 'components/routeloom/third_party').iterdir()
                   if p.is_dir()}
    if names != directories:
        raise ValueError('unregistered vendor directory')
    reviewed_vendors = set(re.findall(r'^Vendor: (\S+) (\S+) \| (.+) \| ([0-9a-f]{40})$',
                                      notice, re.M))
    if reviewed_vendors != {(v['name'], v['version'], v['license'], v['commit'])
                            for v in vendors['components']}:
        raise ValueError('NOTICE vendored inventory differs from VENDORED.json')
    for v in vendors['components']:
        if any(value not in notice for value in (v['name'], v['commit'], v['upstream'])):
            raise ValueError('NOTICE missing vendored dependency')
        components.append({'type': 'library', 'name': v['name'], 'version': v['version'],
                           'purl': 'pkg:generic/' + v['directory'] + '@' + v['commit'],
                           'licenses': [{'expression': v['license']}],
                           'properties': [{'name': 'upstream', 'value': v['upstream']}]})
    if 'micro-ecc' not in notice or manifest()['toolchain']['esp_idf_commit'] not in notice:
        raise ValueError('NOTICE missing micro-ecc or ESP-IDF pin')
    components += [
        {'type': 'library', 'name': 'micro-ecc', 'licenses': [{'expression': 'BSD-2-Clause'}],
         'hashes': [{'alg': 'SHA-256', 'content': digest(
             ROOT / 'components/routeloom/third_party/micro-ecc/uECC.c')}]},
        {'type': 'framework', 'name': 'esp-idf',
         'version': manifest()['toolchain']['esp_idf_tag'],
         'purl': 'pkg:github/espressif/esp-idf@' + manifest()['toolchain']['esp_idf_commit'],
         'licenses': [{'expression': 'Apache-2.0'}]},
        {'type': 'library', 'name': 'SQLite',
         'description': 'Amalgamation bundled by the locked libsqlite3-sys crate',
         'licenses': [{'license': {'name': 'Public Domain'}}]},
    ]
    return components


def license_bundle(metadata: dict) -> str:
    packages = [p for p in metadata['packages'] if p['id'] not in metadata['workspace_members']]
    # The two Windows import-library crates inherit the license files of winapi.
    inherited = {'winapi-i686-pc-windows-gnu', 'winapi-x86_64-pc-windows-gnu'}
    groups = []
    for package in sorted(packages, key=lambda p: (p['name'], p['version'])):
        source = package
        if package['name'] in inherited:
            source = next(p for p in packages if p['name'] == 'winapi')
        groups.append((f'Cargo: {package["name"]} {package["version"]}',
                       Path(source['manifest_path']).parent))
    vendors = json.loads((ROOT / 'components/routeloom/third_party/VENDORED.json').read_text())
    for directory in ['micro-ecc'] + [v['directory'] for v in vendors['components']]:
        groups.append(('Vendor: ' + directory, ROOT / 'components/routeloom/third_party' / directory))
    texts = {}
    for credit, directory in groups:
        files = sorted(p for p in directory.iterdir() if p.is_file() and
                       p.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'UNLICENSE')))
        if not files:
            raise ValueError('missing upstream license text: ' + credit)
        for path in files:
            texts.setdefault(path.read_text(), []).append(f'===== {credit} / {path.name} =====')
    return '\n'.join('\n'.join(credits) + '\n' + raw + '\n'
                     for raw, credits in texts.items())


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def make_inventory(tag: str, metadata_path: Path, out: Path) -> None:
    check_tag(tag)
    metadata = json.loads(metadata_path.read_text())
    components = inventory(metadata,
                           tomllib.loads((ROOT / 'host/Cargo.lock').read_text()),
                           (ROOT / 'NOTICE').read_text(),
                           json.loads((ROOT / 'components/routeloom/third_party/VENDORED.json').read_text()))
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / f'routeloom-{tag}-sbom.json', {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'metadata': {'component': {'type': 'application', 'name': 'RouteLoom', 'version': tag}},
        'components': components})
    (out / 'THIRD_PARTY_LICENSES.txt').write_text(license_bundle(metadata))
    shutil.copyfile(metadata_path, out / 'cargo-metadata.json')
    for name in ('NOTICE', 'LICENSE'):
        shutil.copyfile(ROOT / name, out / name)


def source_archive(tag: str, out: Path) -> None:
    check_tag(tag)
    out.mkdir(parents=True, exist_ok=True)
    # All tracked source is included so firmware/examples can be rebuilt from the archive.
    raw = subprocess.check_output(['git', 'archive', '--format=tar',
                                   f'--prefix=routeloom-{tag}/', 'HEAD'], cwd=ROOT, timeout=60)
    (out / f'routeloom-{tag}-src.tar.gz').write_bytes(gzip.compress(raw, mtime=0))


def required_names(tag: str) -> set[str]:
    return {archive_name(tag, entry) for entry in firmware_matrix()} | {
        f'routeloom-{tag}-src.tar.gz', f'routeloom-{tag}-linux-x86_64.tar.gz',
        f'routeloom-{tag}-sbom.json', 'cargo-metadata.json', 'NOTICE', 'LICENSE',
        'THIRD_PARTY_LICENSES.txt'}


def finalize(tag: str, out: Path) -> None:
    data = check_tag(tag)
    names = {p.name for p in out.iterdir()}
    if names != required_names(tag) or any(not p.is_file() or p.is_symlink() for p in out.iterdir()):
        raise ValueError('release artifact set is incomplete or contains unexpected files')
    bom = json.loads((out / f'routeloom-{tag}-sbom.json').read_text())
    expected = inventory(json.loads((out / 'cargo-metadata.json').read_text()),
                         tomllib.loads((ROOT / 'host/Cargo.lock').read_text()),
                         (out / 'NOTICE').read_text(),
                         json.loads((ROOT / 'components/routeloom/third_party/VENDORED.json').read_text()))
    if bom['components'] != expected or bom['metadata']['component']['version'] != tag:
        raise ValueError('SBOM differs from dependency inventory')
    licenses = {name: (out / name).read_bytes()
                for name in ('LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.txt')}
    with tarfile.open(out / f'routeloom-{tag}-linux-x86_64.tar.gz') as tar:
        for name, raw in licenses.items():
            if tar.extractfile(f'routeloom-{tag}-linux-x86_64/{name}').read() != raw:
                raise ValueError('host archive license texts differ from release inventory')
    firmware = []
    for entry in firmware_matrix():
        with tarfile.open(out / archive_name(tag, entry)) as tar:
            for name, raw in licenses.items():
                if tar.extractfile(name).read() != raw:
                    raise ValueError('firmware archive license texts differ from release inventory')
            record = json.load(tar.extractfile('release.json'))
            flash_files = release_flash_files(json.load(tar.extractfile('flasher_args.json')), entry)
            flash_hashes = {name: hashlib.sha256(tar.extractfile(name).read()).hexdigest()
                            for name in flash_files.values()}
            if flash_hashes != record['flash_sha256']:
                raise ValueError('firmware flash image hash differs from archive content')
            for name, field in (('flasher_args.json', 'flasher_args_sha256'),
                                ('sdkconfig', 'sdkconfig_sha256'),
                                (f'routeloom_{entry["app"]}.bin', 'app_sha256'),
                                ('partition_table/partition-table.bin', 'partition_sha256')):
                if hashlib.sha256(tar.extractfile(name).read()).hexdigest() != record[field]:
                    raise ValueError('firmware provenance hash differs from archive content')
        if (record['entry'] != entry or record['tag'] != tag or
                record['toolchain'] != data['toolchain'] or record['partition_id'] != 'PT-4M-v2'):
            raise ValueError('firmware provenance disagrees with manifest/matrix')
        firmware.append(record)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True,
                                     timeout=15).strip()
    if any(record['commit'] != commit for record in firmware):
        raise ValueError('firmware source commit differs from release source')
    subjects = [{'name': name, 'digest': {'sha256': digest(out / name)}} for name in sorted(names)]
    write_json(out / 'provenance.json', {
        '_type': 'https://in-toto.io/Statement/v1', 'subject': subjects,
        'predicateType': 'https://slsa.dev/provenance/v1',
        'predicate': {'buildDefinition': {
            'buildType': 'https://github.com/MOVEI144/RouteLoom/blob/main/.github/workflows/release.yml',
            'externalParameters': {'tag': tag},
            'resolvedDependencies': [{'uri': 'git+https://github.com/MOVEI144/RouteLoom',
                                      'digest': {'gitCommit': commit}}],
            'internalParameters': {'manifest_sha256': digest(ROOT / 'protocol/manifest.json'),
                                   'toolchain': data['toolchain'], 'firmware': firmware}},
            'runDetails': {'builder': {'id': 'RouteLoom release workflow'}}}})
    (out / 'SHA256SUMS.txt').write_text(''.join(
        f'{digest(path)}  {path.name}\n' for path in sorted(out.iterdir())))
    verify(out)


def verify(out: Path) -> dict:
    lines = (out / 'SHA256SUMS.txt').read_text().splitlines()
    names = set()
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        if not match or match[2] in names:
            raise ValueError('invalid or duplicate checksum entry')
        names.add(match[2])
        path = out / match[2]
        if path.is_symlink() or digest(path) != match[1]:
            raise ValueError('artifact checksum mismatch')
    provenance = json.loads((out / 'provenance.json').read_text())
    tag = provenance['predicate']['buildDefinition']['externalParameters']['tag']
    if names != required_names(tag) | {'provenance.json'}:
        raise ValueError('checksum inventory is incomplete')
    subjects = provenance['subject']
    if len(subjects) != len(names) - 1 or {s['name'] for s in subjects} != names - {'provenance.json'}:
        raise ValueError('provenance subject inventory is incomplete')
    for subject in subjects:
        if subject['digest']['sha256'] != digest(out / subject['name']):
            raise ValueError('provenance subject mismatch')
    actual = {p.name for p in out.iterdir()}
    if actual - names - {'SHA256SUMS.txt', 'SHA256SUMS.sig', 'signing-public.pem'}:
        raise ValueError('unexpected release asset')
    signing = actual & {'SHA256SUMS.sig', 'signing-public.pem'}
    if signing and len(signing) != 2:
        raise ValueError('incomplete signing outputs')
    for name in signing:
        path = out / name
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise ValueError('invalid signing output')
    if 'signing-public.pem' in actual:
        check_signing_key(out / 'signing-public.pem', public=True)
    return provenance


def check_signing_key(key: Path, public: bool = False) -> bytes:
    argv = ['openssl', 'pkey', '-in', str(key)] + (['-pubin'] if public else [])
    der = subprocess.check_output(argv + ['-pubout', '-outform', 'DER'], stderr=subprocess.PIPE,
                                  stdin=subprocess.DEVNULL, timeout=15)
    dev = subprocess.check_output(['openssl', 'pkey', '-pubin', '-in', str(
        ROOT / 'tools/meshviz/src/routeloom_meshviz/dev-signing-public.pem'),
        '-pubout', '-outform', 'DER'], stderr=subprocess.PIPE, timeout=15)
    if der == dev:
        raise ValueError('meshviz development signing key is forbidden for releases')
    return der


def sign(out: Path, key: Path | None, hook: Path) -> None:
    verify(out)
    original = {p.name: digest(p) for p in out.iterdir()
                if p.name not in {'SHA256SUMS.sig', 'signing-public.pem'}}
    public = out / 'signing-public.pem'
    if key is not None:
        check_signing_key(key)
        public.write_bytes(subprocess.check_output(
            ['openssl', 'pkey', '-in', str(key), '-pubout'], stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, timeout=15))
    subprocess.run([str(hook.resolve()), str(key.resolve()) if key else '-',
                    str((out / 'SHA256SUMS.txt').resolve()),
                    str((out / 'SHA256SUMS.sig').resolve()), str(public.resolve())],
                   check=True, timeout=120)
    if any(not (out / name).is_file() or (out / name).is_symlink() or
           digest(out / name) != value for name, value in original.items()):
        raise ValueError('signing hook changed release artifacts')
    verify(out)


def promote(out: Path, tag: str, commit: str, from_tag: str) -> None:
    provenance = verify(out)
    definition = provenance['predicate']['buildDefinition']
    candidate = definition['externalParameters']['tag']
    match = re.fullmatch(r'(v\d+\.\d+\.\d+)-rc\.\d+', candidate)
    if (not match or candidate != from_tag or tag != match[1] or
            definition['resolvedDependencies'][0]['digest']['gitCommit'] != commit):
        raise ValueError('promotion requires the RC base version and identical source commit')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    for name in ('matrix', 'source', 'inventory', 'finalize', 'verify', 'sign', 'promote'):
        sub = subs.add_parser(name)
        if name in ('matrix', 'source', 'inventory', 'finalize', 'promote'):
            sub.add_argument('--tag', required=True)
        if name != 'matrix':
            sub.add_argument('--out', type=Path, required=True)
        if name == 'inventory':
            sub.add_argument('--metadata', type=Path, required=True)
        if name == 'sign':
            sub.add_argument('--key', type=Path)
            sub.add_argument('--hook', type=Path, required=True)
        if name == 'promote':
            sub.add_argument('--commit', required=True)
            sub.add_argument('--from-tag', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'matrix':
            data = check_tag(args.tag)
            print(json.dumps({'include': firmware_matrix(), 'toolchain': data['toolchain']}))
        elif args.command == 'source':
            source_archive(args.tag, args.out)
        elif args.command == 'inventory':
            make_inventory(args.tag, args.metadata, args.out)
        elif args.command == 'finalize':
            finalize(args.tag, args.out)
        elif args.command == 'verify':
            verify(args.out)
        elif args.command == 'sign':
            sign(args.out, args.key, args.hook)
        else:
            promote(args.out, args.tag, args.commit, args.from_tag)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        parser.exit(1, f'release: {exc}\n')


if __name__ == '__main__':
    main()

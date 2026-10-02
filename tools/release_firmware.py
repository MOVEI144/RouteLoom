#!/usr/bin/env python3
"""Stage a firmware release with the paths used by flasher_args.json."""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.check import elf_symbols  # noqa: E402
from tools.release import (ROOT, check_tag, digest, firmware_errors,
                           firmware_matrix, release_flash_files, write_json)  # noqa: E402


def check_release_firmware(build: Path, sdkconfig: Path, entry: dict, tag: str) -> dict:
    data = check_tag(tag)
    flash_files = release_flash_files(json.loads((build / 'flasher_args.json').read_text()), entry)
    settings = sdkconfig.read_text().splitlines()
    image = build / f'routeloom_{entry["app"]}.bin'
    elf = image.with_suffix('.elf')
    errors = firmware_errors(image.read_bytes(), elf_symbols(elf), settings, entry['mode'])
    for line in entry['overlay']:
        if line not in settings:
            errors.append('release overlay missing from sdkconfig: ' + line)
    if f'CONFIG_IDF_TARGET="{entry["target"]}"' not in settings:
        errors.append('release target differs from sdkconfig')
    if errors:
        raise ValueError('; '.join(errors))
    if image.stat().st_size > int(0x1D0000 * 0.8):
        raise ValueError('release app exceeds 80% of the PT-4M-v2 OTA slot')
    report = json.loads((build / 'ram-report.json').read_text())
    if not report['guard']['passed']:
        raise ValueError('release static RAM guard failed')
    return {'entry': entry, 'tag': tag, 'toolchain': data['toolchain'],
            'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
                                              text=True, timeout=15).strip(),
            'sdkconfig_sha256': digest(sdkconfig), 'app_sha256': digest(image),
            'flasher_args_sha256': digest(build / 'flasher_args.json'),
            'flash_sha256': {name: digest(build / name) for name in flash_files.values()},
            'partition_id': 'PT-4M-v2',
            'partition_sha256': digest(build / 'partition_table/partition-table.bin'),
            'static_free_bytes': report['guard']['free']}


def package_firmware(build: Path, sdkconfig: Path, stage: Path) -> None:
    build = Path(build)
    stage = Path(stage)
    args = json.loads((build / "flasher_args.json").read_text())
    flash_files = args["flash_files"]
    offsets = {int(offset, 0) for offset in flash_files}
    if len(flash_files) != 4 or offsets not in (
            {0, 0x8000, 0x10000, 0x40000},
            {0x2000, 0x8000, 0x10000, 0x40000}):
        raise ValueError("release flash files do not match PT-4M-v2")
    stage.mkdir(parents=True)
    for name in flash_files.values():
        source = build / name
        if (Path(name).is_absolute() or '..' in Path(name).parts or
                not source.is_file() or not source.resolve().is_relative_to(build.resolve())):
            raise ValueError(f"invalid flash image path: {name}")
        destination = stage / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    for pattern in ("*.bin", "*.elf", "*.map"):
        for source in build.glob(pattern):
            shutil.copyfile(source, stage / source.name)
    for name in ("flasher_args.json", "flash_args", "size-report.txt",
                 "size.json", "ram-report.json"):
        source = build / name
        if source.is_file():
            shutil.copyfile(source, stage / name)
    shutil.copyfile(sdkconfig, stage / "sdkconfig")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("sdkconfig", type=Path)
    parser.add_argument("stage", type=Path)
    parser.add_argument("--release-id")
    parser.add_argument("--tag")
    args = parser.parse_args()
    record = None
    if bool(args.release_id) != bool(args.tag):
        parser.error('release-id and tag must be supplied together')
    if args.release_id:
        entry = next((e for e in firmware_matrix() if e['id'] == args.release_id), None)
        if entry is None or not args.tag:
            parser.error('release packaging requires a known release-id and tag')
        try:
            record = check_release_firmware(args.build, args.sdkconfig, entry, args.tag)
        except (ValueError, OSError, KeyError) as exc:
            parser.exit(1, f'release firmware: {exc}\n')
    package_firmware(args.build, args.sdkconfig, args.stage)
    if record is not None:
        write_json(args.stage / 'release.json', record)


if __name__ == "__main__":
    main()

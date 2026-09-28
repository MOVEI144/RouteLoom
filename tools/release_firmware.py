#!/usr/bin/env python3
"""Stage a firmware release with the paths used by flasher_args.json."""

import argparse
import json
import shutil
from pathlib import Path


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
    stage.mkdir(parents=True, exist_ok=True)
    for name in flash_files.values():
        source = build / name
        if not source.is_file() or not source.resolve().is_relative_to(build.resolve()):
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
    args = parser.parse_args()
    package_firmware(args.build, args.sdkconfig, args.stage)


if __name__ == "__main__":
    main()

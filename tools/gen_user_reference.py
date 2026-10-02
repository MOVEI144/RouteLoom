#!/usr/bin/env python3
"""Generate user references from public headers, component Kconfig and API1 dispatch."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADERS = (
    'components/routeloom_device/include/routeloom/device.hpp',
    'components/routeloom_device/include/routeloom/device.h',
    'components/routeloom/include/routeloom/routeloom.h',
)


def outputs(root: Path) -> dict[str, str]:
    generated = '生成元を編集し、`python3 tools/gen_user_reference.py` で更新する。\n\n'
    files = {}
    for header in HEADERS:
        name = Path(header).name
        text = (root / header).read_text()
        files[f'docs/api/{name}.md'] = (
            f'# {name} 宣言 reference\n\n' + generated
            + f'[{header}](../../{header}) の全宣言と契約コメント。\n'
            + '使い方は [API 案内](README.md)。HTML reference は Doxygen artifact を参照。\n\n'
            + f'```{"c" if name.endswith(".h") else "cpp"}\n{text}```\n')
    rows = ['# Component Kconfig reference', '', generated.rstrip(), '',
            '条件付き default は上から評価する。実効値は `sdkconfig` と capability で確認する。',
            'app 固有の Kconfig は対象外。秘密の値は reference に展開しない。', '']
    for source in sorted((root / 'components').glob('*/Kconfig')):
        rows += [f'## {source.parent.name}', '',
                 f'生成元：[{source.relative_to(root)}](../../{source.relative_to(root)})', '']
        blocks = re.split(r'(?m)^\s*(?:menuconfig|config|choice)\s+(\w+)\s*$', source.read_text())
        for name, body in zip(blocks[1::2], blocks[2::2]):
            body = re.split(r'(?m)^\s*(?:endmenu|endchoice|menu |choice|endif)', body)[0]
            lines = body.strip().splitlines()
            # Preserve help and conditional defaults rather than inventing effective values.
            label = f'choice {name}' if re.search(rf'(?m)^\s*choice\s+{name}\s*$', source.read_text()) else f'CONFIG_{name}'
            rows += [f'### {label}', '', '```text', *lines, '```', '']
    files['docs/api/kconfig.md'] = '\n'.join(rows).rstrip() + '\n'
    main = (root / 'host/routeloom-host/src/api1.rs').read_text()
    site = (root / 'host/routeloom-host/src/api1/site.rs').read_text()
    dispatch = main.split('let dispatch:', 1)[1].split('match dispatch', 1)[0]
    site_methods = site.split('SITE_METHODS', 1)[1].split('];', 1)[0]
    methods = sorted(set(re.findall(r'"([a-z_]+\.[a-z_.]+)"', dispatch + site_methods)))
    files['docs/api/api1-methods.md'] = (
        '# API1 method reference\n\n' + generated
        + '実装の dispatch 一覧。Site Authority の method は `--site-authority` が必要。\n'
        + '各引数・認可・結果は [host 契約](../spec/host.md)、[契約 kit](api1.md) を参照。\n'
        + 'capability の `methods` を毎接続で確認する。受付と最終成功は別である。\n\n'
        + '| Method | 契約 |\n|---|---|\n'
        + ''.join(f'| `{m}` | [host](../spec/host.md) |\n' for m in methods))
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    stale = []
    for path, text in outputs(ROOT).items():
        file = ROOT / path
        if args.check:
            if not file.exists() or file.read_text() != text:
                stale.append(path)
        else:
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(text)
    if stale:
        print('stale user references: ' + ', '.join(stale))
    return bool(stale)


if __name__ == '__main__':
    raise SystemExit(main())

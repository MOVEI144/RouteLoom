#!/usr/bin/env python3
"""Render Unreleased fragments for review; never delete fragments or tag a release."""
from pathlib import Path

SECTIONS = ('Added', 'Changed', 'Deprecated', 'Removed', 'Fixed', 'Security')


def render(directory: Path) -> str:
    sections = {name: [] for name in SECTIONS}
    for file in sorted(directory.glob('*.md')):
        if file.name == 'README.md':
            continue
        section = None
        for line in file.read_text().splitlines():
            if line.startswith('### '):
                section = line[4:]
                if section not in sections:
                    raise ValueError(f'{file}: unknown section {section}')
            elif line.strip():
                if section is None:
                    raise ValueError(f'{file}: content before section')
                sections[section].append(line)
    out = ['## [Unreleased]', '']
    for name, lines in sections.items():
        if lines:
            out += [f'### {name}', '', *lines, '']
    return '\n'.join(out)


if __name__ == '__main__':
    print(render(Path(__file__).resolve().parents[1] / 'changelog.d'))

#!/usr/bin/env python3
"""Generate documented tables from design manifests, not from real hardware."""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path


def sections(root: Path):
    def load(path):
        return json.loads((root / path).read_text(encoding='utf-8'))
    radio = load('docs/reference/radio-defaults.json')
    board_data = load('docs/reference/boards.json')['boards']
    boards = [b for b in board_data if 'gpio_d0_to_d10' in b]
    pins = ['| XIAO端子 | C3 GPIO | S3 GPIO | C5 GPIO |', '|---|---:|---:|---:|']
    labels = ['D0','D1','D2','D3','D4 / SDA','D5 / SCL','D6 / TX','D7 / RX','D8 / SCK','D9 / MISO','D10 / MOSI']
    for i,label in enumerate(labels):
        pins.append('| '+label+' | '+' | '.join(str(b['gpio_d0_to_d10'][i]) for b in boards)+' |')
    yield 'docs/hardware/README.md','pins','\n'.join(pins)
    targets = radio['performance_targets_ms']
    perf = ['| 指標 | 目標 |','|---|---|']
    for key,title,condition in [
        ('reliable_1hop_p95','1hop RELIABLE','、send→END_RECEIPT'),
        ('reliable_5hop_p95','5hop RELIABLE',''),
        ('reliable_10hop_p95','10hop RELIABLE',''),
        ('wake_report_p95','Deep Sleepから報告','、warm条件。cold/auth/recoveryは別系列'),
        ('known_backup_repair_p95_from_observation','既知代替への復旧','、最初の故障観測→最終receipt'),
        ('same_channel_repair_p95','同channel探索修復','を目標、物理経路が存在'),
        ('preapproved_join_p95','自動承認済み同channel Join','を目標、単独入場'),
        ('cold_join_p95','cold Join','を目標、単独入場・常時受信入口あり'),
        ('cutover_gap_p95','切替そのものの空白','を目標、認定された移行拡張・準備済み群')]:
        perf.append(f'| {title} | P95 {targets[key]}ms以内{condition} |')
    yield 'docs/spec/acceptance.md','performance','\n'.join(perf)
    resources = load('docs/reference/resource-profiles.json')['profiles']
    lines=['| Profile | RX / TX | Active destinations | Dedup | SDK概算 / 上限 (bytes) | 実測 |','|---|---:|---:|---:|---:|---|']
    for name,p in resources.items():
        lines.append(f"| {name} | {p['rx_frames']} / {p['tx_frames']} | {p['active_destinations']} | {p['dedup_entries']} | {sum(p['budget_bytes'].values())} / {p['sdk_budget_ceiling_bytes']} | 未実測 |")
    yield 'docs/spec/resource-profiles.md','resources','\n'.join(lines)
    semantic=load('protocol/semantics.json')
    lines=['| ローカル状態 | 型の上限（条件付き） |','|---|---|']
    for state,types in semantic['membership_allowlist'].items():
        lines.append(f"| {state} | {', '.join(types) if types else '通常通信禁止。明示再provisioningは別経路'} |")
    yield 'docs/spec/identity-membership.md','join','\n'.join(lines)


def pattern(name: str) -> str:
    return r'<!-- generated:'+re.escape(name)+r':start -->\n.*?<!-- generated:'+re.escape(name)+r':end -->'


def check(root: Path) -> list[str]:
    errors=[]
    for path,name,body in sections(root):
        text=(root/path).read_text(encoding='utf-8')
        expected=f'<!-- generated:{name}:start -->\n{body}\n<!-- generated:{name}:end -->'
        match=re.search(pattern(name),text,re.S)
        if not match or match.group()!=expected:
            errors.append(f'{path}: generated {name} differs from manifest')
    return errors


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    if args.check:
        errors=check(args.root); print('\n'.join(errors) if errors else 'Generated tables match.')
        return bool(errors)
    for path,name,body in sections(args.root):
        p=args.root/path; text=p.read_text(encoding='utf-8')
        replacement=f'<!-- generated:{name}:start -->\n{body}\n<!-- generated:{name}:end -->'
        result,count=re.subn(pattern(name),lambda _:replacement,text,flags=re.S)
        if count!=1:
            raise ValueError(f'{path}: expected one generated marker pair for {name}')
        p.write_text(result,encoding='utf-8')
    return 0

if __name__=='__main__':
    raise SystemExit(main())

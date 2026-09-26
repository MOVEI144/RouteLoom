"""Qt-free board assignment checks and write-plan preview for the boards screen.

The preview only explains; the flash worker repeats every identity, signature and
protection check in the same ROM session before writing.
"""
from dataclasses import dataclass, field
from pathlib import Path

from .device import FlashPlan, Identity, Image

ROLES = ('bridge_node', 'reference_node')


@dataclass
class BoardRow:
    port: str
    usb: str = ''
    identity: Identity | None = None
    role: str | None = None
    node_id: str | None = None
    state: str = 'Enumerated'
    message: str = ''
    history: list = field(default_factory=list)


def normalize_node_id(text):
    """NodeIds are 64-bit; accept 1..16 hex digits and display them as 16 hex."""
    if not isinstance(text, str):
        return None
    text = text.strip().lower().removeprefix('0x')
    if not 1 <= len(text) <= 16 or any(char not in '0123456789abcdef' for char in text):
        return None
    value = int(text, 16)
    return f'{value:016x}' if 0 < value < 2**64 - 1 else None


def bundle_image_node_id(bundle):
    """Read the resolved NodeId from an already verified bundle's signed sdkconfig."""
    config = (Path(bundle) / 'sdkconfig').read_text(encoding='utf-8')
    values = [line.partition('=')[2].strip() for line in config.splitlines()
              if line.startswith('CONFIG_ROUTELOOM_NODE_ID=')]
    if len(values) != 1:
        return None
    try:
        value = int(values[0], 0)
    except ValueError:
        return None
    return normalize_node_id(f'{value:x}') if 0 < value < 2**64 - 1 else None


def assignment_errors(rows):
    """port → reasons. Duplicate NodeIds or boards are rejected, never resolved by order."""
    errors = {row.port: [] for row in rows}
    node_ids, macs = {}, {}
    for row in rows:
        if row.node_id is not None:
            node = normalize_node_id(row.node_id)
            if node is None:
                errors[row.port].append('NodeId は 1..16 桁の hex（0 以外）')
            else:
                node_ids.setdefault(node, []).append(row.port)
        if row.identity is not None:
            macs.setdefault(row.identity.base_mac.lower(), []).append(row.port)
        if row.role is not None and row.role not in ROLES:
            errors[row.port].append('役割が不正')
    for node, ports in node_ids.items():
        if len(ports) > 1:
            for port in ports:
                errors[port].append(f'NodeId {node} が重複')
    for mac, ports in macs.items():
        if len(ports) > 1:
            for port in ports:
                errors[port].append(f'同じ基板（MAC {mac}）が複数 port に見える')
    bridges = [row.port for row in rows if row.role == 'bridge_node']
    if len(bridges) > 1:
        for port in bridges:
            errors[port].append('稼働 bridge は 1 台まで')
    return errors


def preview(row: BoardRow, manifest: dict | None, bundle: Path | None, *, quiesced: bool,
            assignment_problems=(), image_node_id=None):
    """(FlashPlan or None, reasons, notes). Any reason blocks writing this board."""
    reasons = list(assignment_problems)
    notes = []
    identity = row.identity
    if identity is None:
        reasons.append('ROM 検査が未実施（chip・MAC・flash が未確定）')
    if manifest is None or bundle is None:
        reasons.append('署名検証済みの bundle が未選択')
    if row.role is None:
        reasons.append('役割が未割当て')
    if normalize_node_id(row.node_id) is None:
        reasons.append('NodeId が未割当て')
    if manifest is not None:
        if image_node_id is None:
            reasons.append('署名付き bundle の Kconfig NodeId を確認できない')
        elif normalize_node_id(row.node_id) != image_node_id:
            reasons.append(f'割当て NodeId と image の Kconfig NodeId {image_node_id} が不一致')
    if not quiesced:
        reasons.append('この port を使う daemon／console の停止（quiesce）が未確認')
    if manifest is not None:
        if manifest['chip'] == 'esp32c6':
            reasons.append('C6 は実験的 HIL 対象のため書込み不可')
        if row.role is not None and manifest['role'] != row.role:
            reasons.append(f'bundle の役割 {manifest["role"]} と割当て {row.role} が不一致')
        if identity is not None:
            if identity.chip != manifest['chip']:
                reasons.append(f'chip 不一致: board {identity.chip} / bundle {manifest["chip"]}')
            low, high = manifest['chip_revision_range']
            if not identity.revision.isdecimal() or not low <= int(identity.revision) <= high:
                reasons.append(f'chip revision {identity.revision} は bundle 対応範囲 {low}..{high} 外')
            if identity.flash_bytes < manifest['minimum_flash_bytes']:
                reasons.append(f'flash {identity.flash_bytes} B は必要量 '
                               f'{manifest["minimum_flash_bytes"]} B 未満')
        notes.append(f'bundle {manifest.get("bundle_id", "?")}: {manifest["chip"]} '
                     f'{manifest["role"]} {manifest.get("firmware_version")} '
                     f'({manifest.get("security_profile")})')
        for entry in manifest['files']:
            notes.append(f'  0x{entry["offset"]:06x} {entry["size"]:>8} B {entry["sha256"][:16]}… '
                         f'{entry["path"]}')
        # Generic runtime config (PR 03a) is not available: images keep Kconfig NodeIds.
        notes.append('個体別設定は未対応。bundle の resolved Kconfig NodeId を照合する')
    if identity is not None:
        if identity.secure_boot is not False or identity.flash_encryption is not False:
            reasons.append('secure boot／flash 暗号化の状態が無効と確認できない')
        notes.append(f'識別根拠: ROM probe chip={identity.chip} rev={identity.revision} '
                     f'base MAC={identity.base_mac} flash_id={identity.flash_id}')
    if reasons:
        return None, reasons, notes
    images = tuple(Image(entry['offset'], Path(bundle) / entry['path'], entry['size'], entry['sha256'])
                   for entry in manifest['files'])
    # verified_signature reflects the GUI's verify_bundle; the worker re-verifies regardless.
    plan = FlashPlan(identity, manifest['chip'], images, True, identity.base_mac, quiesced,
                     Path(bundle), image_node_id)
    return plan, [], notes

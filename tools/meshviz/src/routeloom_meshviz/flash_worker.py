"""Isolated esptool 5.4.0 adapter. No arbitrary command or eFuse write API."""
from dataclasses import asdict
import json
import sys
from pathlib import Path

from .device import FlashPlan, Identity, Image
from .board_setup import bundle_image_node_id
from .firmware_catalog import DEV_PUBLIC_KEY, verify_bundle


PUBLIC_KEY = DEV_PUBLIC_KEY


def flash(port: str, plan: FlashPlan, api=None):
    # A caller's verified_signature flag is never cryptographic evidence.
    if plan.bundle is None:
        raise ValueError('trusted bundle signature verifier unavailable')
    manifest = verify_bundle(plan.bundle, PUBLIC_KEY)
    if (plan.assigned_node_id is not None and
            bundle_image_node_id(plan.bundle) != plan.assigned_node_id):
        raise ValueError('assigned NodeId differs from signed image configuration')
    if manifest['chip'] == 'esp32c6':
        raise ValueError('C6 is experimental HIL only')
    if manifest['chip'] != plan.chip or tuple(
            (e['offset'], Path(plan.bundle) / e['path'], e['size'], e['sha256'])
            for e in manifest['files']) != tuple(
            (i.offset, i.path, i.size, i.sha256) for i in plan.images):
        raise ValueError('flash plan differs from signed bundle')
    api = _api(api)
    esp = api.detect_chip(port=port, connect_attempts=1)
    try:
        measured = _measure(esp, api)
        flash_bytes = measured.flash_bytes
        # A matching chip alone cannot authorize a revision or flash size the
        # signed image did not declare compatible.
        revision = measured.revision
        low, high = manifest['chip_revision_range']
        if (not revision.isdecimal() or not low <= int(revision) <= high or
                flash_bytes < manifest['minimum_flash_bytes']):
            raise ValueError('bundle incompatible with measured board')
        images = plan.verified_images(port, measured)
        api.write_flash(esp, images, flash_mode='keep', flash_freq='keep', flash_size='keep')
        api.verify_flash(esp, images)
    finally:
        esp._port.close()


def _api(api):
    if api is None:
        import esptool as api
    if api.__version__ != '5.4.0':
        raise ValueError('unreviewed esptool version')
    return api


def _measure(esp, api):
    chip = esp.CHIP_NAME.lower().replace('-', '')
    base = ':'.join(f'{byte:02x}' for byte in esp.read_mac('BASE_MAC'))
    # The ROM base MAC is not a field STA MAC attestation.
    sta = None
    api.attach_flash(esp)
    flash_id = esp.flash_id()
    # JEDEC size exponent; unknown/non-standard flash must not be written.
    size_exponent = flash_id >> 16
    flash_bytes = 1 << size_exponent if 20 <= size_exponent <= 26 else 0
    security = esp.get_security_info(cache=False)
    flags = security['parsed_flags']
    secure_boot = flags.get('SECURE_BOOT_EN')
    crypt_cnt = security.get('flash_crypt_cnt')
    # Missing or malformed read-only protection data must not become "disabled".
    encryption = (bool(crypt_cnt.bit_count() % 2)
                  if type(crypt_cnt) is int and crypt_cnt >= 0 else None)
    return Identity(chip, str(esp.get_chip_revision()), base, sta,
                    f'{flash_id:06x}', flash_bytes, secure_boot, encryption)


def probe(port: str, api=None) -> Identity:
    """Read-only ROM identification (resets the board); never writes flash."""
    api = _api(api)
    esp = api.detect_chip(port=port, connect_attempts=1)
    try:
        return _measure(esp, api)
    finally:
        esp._port.close()


def main():
    try:
        request = json.load(sys.stdin)
        if request.get('op') == 'probe':
            print(json.dumps({'ok': True, 'identity': asdict(probe(request['port']))}))
            return 0
        # The trust anchor is packaged with the worker, never supplied by JSON.
        root = Path(request['bundle'])
        manifest = verify_bundle(root, PUBLIC_KEY)
        identity = Identity(**request['expected'])
        images = tuple(Image(e['offset'], root / e['path'], e['size'], e['sha256'])
                       for e in manifest['files'])
        plan = FlashPlan(identity, manifest['chip'], images, True,
                         request['expected_mac'], request['quiesced'], root,
                         request.get('assigned_node_id'))
        flash(request['port'], plan)
        print(json.dumps({'ok': True}))
        return 0
    except (ValueError, KeyError, TypeError, OSError, ImportError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        return 1


if __name__ == '__main__':
    sys.exit(main())

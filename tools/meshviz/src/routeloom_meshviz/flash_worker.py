"""Isolated esptool 5.4.0 adapter. No arbitrary command or eFuse write API."""
import json
import sys
from pathlib import Path

from .device import FlashPlan, Identity, Image
from .firmware_catalog import verify_bundle


PUBLIC_KEY = Path(__file__).resolve().parents[2] / 'packaging' / 'dev-signing-public.pem'


def flash(port: str, plan: FlashPlan, api=None):
    # A caller's verified_signature flag is never cryptographic evidence.
    if plan.bundle is None:
        raise ValueError('trusted bundle signature verifier unavailable')
    manifest = verify_bundle(plan.bundle, PUBLIC_KEY)
    if manifest['chip'] != plan.chip or tuple(
            (e['offset'], Path(plan.bundle) / e['path'], e['size'], e['sha256'])
            for e in manifest['files']) != tuple(
            (i.offset, i.path, i.size, i.sha256) for i in plan.images):
        raise ValueError('flash plan differs from signed bundle')
    if api is None:
        import esptool as api
    if api.__version__ != '5.4.0':
        raise ValueError('unreviewed esptool version')
    esp = api.detect_chip(port=port, connect_attempts=1)
    try:
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
        measured = Identity(chip, str(esp.get_chip_revision()), base, sta,
                            f'{flash_id:06x}', flash_bytes, secure_boot, encryption)
        images = plan.verified_images(port, measured)
        api.write_flash(esp, images, flash_mode='keep', flash_freq='keep', flash_size='keep')
        api.verify_flash(esp, images)
    finally:
        esp._port.close()


def main():
    try:
        request = json.load(sys.stdin)
        # The trust anchor is packaged with the worker, never supplied by JSON.
        root = Path(request['bundle'])
        manifest = verify_bundle(root, PUBLIC_KEY)
        identity = Identity(**request['expected'])
        images = tuple(Image(e['offset'], root / e['path'], e['size'], e['sha256'])
                       for e in manifest['files'])
        plan = FlashPlan(identity, manifest['chip'], images, True,
                         request['expected_mac'], request['quiesced'], root)
        flash(request['port'], plan)
        print(json.dumps({'ok': True}))
        return 0
    except (ValueError, KeyError, TypeError, OSError, ImportError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        return 1


if __name__ == '__main__':
    sys.exit(main())

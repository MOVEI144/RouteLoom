"""Isolated esptool 5.4.0 adapter. No arbitrary command or eFuse write API."""
import json
import sys

from .device import FlashPlan, Identity, Image
from pathlib import Path


def flash(port: str, plan: FlashPlan, api=None):
    if api is None:
        import esptool as api
    if api.__version__ != '5.4.0':
        raise ValueError('unreviewed esptool version')
    esp = api.detect_chip(port=port, connect_attempts=1)
    try:
        chip = 'esp32' + esp.CHIP_NAME.lower().replace('-', '')
        base = ':'.join(f'{byte:02x}' for byte in esp.read_mac('BASE_MAC'))
        # The ROM base MAC is not a field STA MAC attestation.
        sta = base
        flash_id = esp.flash_id()
        # JEDEC size exponent; unknown/non-standard flash must not be written.
        size_exponent = flash_id >> 16
        flash_bytes = 1 << size_exponent if 20 <= size_exponent <= 26 else 0
        security = esp.get_security_info(cache=False)
        flags = security['parsed_flags']
        measured = Identity(chip, str(esp.get_chip_revision()), base, sta,
                            f'{flash_id:06x}', flash_bytes,
                            flags['SECURE_BOOT_EN'], bool(security['flash_crypt_cnt'].bit_count() % 2))
        plan.verify(port, measured)
        images = [(image.offset, str(image.path)) for image in plan.images]
        api.write_flash(esp, images, flash_mode='keep', flash_freq='keep', flash_size='keep')
        api.verify_flash(esp, images)
    finally:
        esp._port.close()


def main():
    # Only one bounded JSON plan enters this GPL worker process; no shell/argv injection.
    try:
        request = json.loads(sys.stdin.buffer.readline(65537))
        expected = Identity(**request['expected'])
        images = tuple(Image(i['offset'], Path(i['path']), i['size'], i['sha256'])
                       for i in request['images'])
        # The trust store arrives with the signed bundle backend in PR 03b.
        # A JSON boolean supplied by a client is not signature evidence.
        plan = FlashPlan(expected, request['chip'], images,
                         False, request['expected_mac'])
        if not plan.verified_signature:
            raise ValueError('no trusted bundle signature verifier configured')
        flash(request['port'], plan)
        print(json.dumps({'ok': True}))
    except (ValueError, OSError, KeyError, ImportError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

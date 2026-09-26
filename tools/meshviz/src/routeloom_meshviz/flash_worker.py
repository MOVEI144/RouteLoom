"""Isolated esptool 5.4.0 adapter. No arbitrary command or eFuse write API."""
import json
import sys

from .device import FlashPlan, Identity


def flash(port: str, plan: FlashPlan, api=None):
    if api is None:
        raise ValueError('trusted bundle signature verifier unavailable')
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
    # A client-provided plan cannot supply signature evidence.
    print(json.dumps({'ok': False, 'error': 'no trusted bundle signature verifier configured'}))
    return 1


if __name__ == '__main__':
    sys.exit(main())

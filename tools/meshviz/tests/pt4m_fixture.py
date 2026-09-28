"""PT-4M-v2 build outputs shared by the bundle and provisioning tests."""
import hashlib
import json

from routeloom_meshviz import firmware_catalog as catalog

PARTITIONS_CSV = (
    'nvs,data,nvs,0x9000,0x6000\n'
    'phy_init,data,phy,0xf000,0x1000\n'
    'otadata,data,ota,0x10000,0x2000\n'
    'rlcfg,data,nvs,0x12000,0x6000\n'
    'rlkeys,data,nvs,0x18000,0x3000\n'
    'rlsec,data,nvs,0x20000,0x20000\n'
    'ota_0,app,ota_0,0x40000,0x1d0000\n'
    'ota_1,app,ota_1,0x210000,0x1d0000\n'
    'coredump,data,coredump,0x3e0000,0x10000\n')
# Byte offset of the MD5 row that follows the partition entries.
MD5_ROW = 32 * len(catalog.PT_4M_V2)


def partition_table():
    entries = []
    for name, kind, subtype, offset, size in catalog.PT_4M_V2:
        entry = bytearray(32)
        entry[:2] = bytes.fromhex('aa50')
        entry[2:4] = bytes((kind, subtype))
        entry[4:8] = offset.to_bytes(4, 'little')
        entry[8:12] = size.to_bytes(4, 'little')
        entry[12:12 + len(name)] = name.encode()
        entries.append(bytes(entry))
    table = b''.join(entries)
    table += b'\xeb\xeb' + b'\xff' * 14 + hashlib.md5(table).digest()
    return table + b'\xff' * (0xc00 - len(table))


def write_build(build, app_file, bootloader, app):
    """Writes the idf.py outputs of a 4 MB PT-4M-v2 esp32c3 build."""
    (build / 'bootloader').mkdir(parents=True)
    (build / 'partition_table').mkdir()
    for name, data in (('bootloader/bootloader.bin', bootloader),
                       ('partition_table/partition-table.bin', partition_table()),
                       ('ota_data_initial.bin', b'\xff' * 0x2000),
                       (app_file, app)):
        (build / name).write_bytes(data)
    (build / 'flasher_args.json').write_text(json.dumps({
        'flash_files': {'0x0': 'bootloader/bootloader.bin',
                        '0x8000': 'partition_table/partition-table.bin',
                        '0x10000': 'ota_data_initial.bin',
                        '0x40000': app_file},
        'extra_esptool_args': {'chip': 'esp32c3'},
        'flash_settings': {'flash_mode': 'dio', 'flash_freq': '80m', 'flash_size': '4MB'},
        'write_flash_args': ['--flash-mode', 'dio', '--flash-size', '4MB', '--flash-freq', '80m'],
        'bootloader': {'encrypted': 'false'},
        'partition-table': {'encrypted': 'false'},
        'otadata': {'encrypted': 'false'},
        'app': {'encrypted': 'false'}}))

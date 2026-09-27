"""RLB1 bench application wire codec (design-devflow.md §5.2).

Python mirror of `host/routeloom-protocol/src/bench.rs` — the host-side
half speaks this to `firmware/bench_node` over the public SDK data path.
Byte-identical framing; `protocol/bench-golden` vectors pin both
implementations:

    0   magic   4B  "RLB1"
    4   version 1B  = 1
    5   opcode  1B
    6   flags   u16 (big-endian)
    8   run_uuid 16B — one host-side run; commands for a dead/foreign run
                       are late
   24   sequence u32 — ordinal inside the run
   28   body CRC32 — ISO HDLC over the body bytes only
   32   body

Host-originated commands stay within the 96 B HostOps command bound
(header + body <= 64 B body) so they survive either lane; device replies
only ever ride unicast DATA.
"""

import zlib

MAGIC = b'RLB1'
PROTOCOL_VERSION = 1
HEADER_SIZE = 32
MAX_UNICAST_PAYLOAD = 128                     # SDK kMaxApplicationPayload
MAX_GROUP_PAYLOAD = 127
MAX_BODY = MAX_UNICAST_PAYLOAD - HEADER_SIZE  # 96
MAX_GROUP_BODY = MAX_GROUP_PAYLOAD - HEADER_SIZE  # 95
MAX_COMMAND_BODY = 96 - HEADER_SIZE           # 64 — fits the HostOps lane
RUN_UUID_SIZE = 16
NULL_RUN = b'\x00' * RUN_UUID_SIZE

INVALID_NODE = 0


class Opcode:
    HELLO = 0x01
    CAPABILITIES = 0x02
    ECHO_REQUEST = 0x10
    ECHO_REPLY = 0x11
    COUNT_ONLY = 0x20
    COUNT_GET = 0x21
    COUNT_STATUS = 0x22
    ROLLCALL = 0x30
    STATUS_GET = 0x40
    STATUS = 0x41
    PEER_SEND_START = 0x50
    PEER_SEND_STATUS = 0x51
    PEER_SEND_STOP = 0x52
    COUNTER_RESET = 0x60
    FAULT_SET = 0x61
    RESET_REQUEST = 0x70
    RESET_ACK = 0x71


# Opcodes a device answers with — replies always carry FLAG_RESPONSE.
REPLY_OPCODES = frozenset({Opcode.CAPABILITIES, Opcode.ECHO_REPLY,
                           Opcode.COUNT_STATUS, Opcode.STATUS,
                           Opcode.PEER_SEND_STATUS, Opcode.RESET_ACK})

FLAG_RESPONSE = 0x0001    # device answers a request; never re-dispatched
FLAG_DUPLICATE = 0x0002   # request already answered inside the run window
FLAG_LATE = 0x0004        # run retired/unknown, or control for a dead boot
FLAG_FAULT = 0x0008       # sender-side marker: a constrained fault is armed


class DecodeError(ValueError):
    TRUNCATED = 'truncated'
    BAD_MAGIC = 'bad_magic'
    UNSUPPORTED_VERSION = 'unsupported_version'
    CRC_MISMATCH = 'crc_mismatch'


def decode(wire: bytes) -> dict:
    """Decode one wire message. opcode stays a raw byte — an unknown opcode
    is well formed at this layer; the application decides."""
    if len(wire) < HEADER_SIZE:
        raise DecodeError(DecodeError.TRUNCATED)
    if wire[:4] != MAGIC:
        raise DecodeError(DecodeError.BAD_MAGIC)
    if wire[4] != PROTOCOL_VERSION:
        raise DecodeError(DecodeError.UNSUPPORTED_VERSION)
    body = wire[HEADER_SIZE:]
    crc = int.from_bytes(wire[28:32], 'big')
    if zlib.crc32(body) != crc:
        raise DecodeError(DecodeError.CRC_MISMATCH)
    return {'opcode': wire[5],
            'flags': int.from_bytes(wire[6:8], 'big'),
            'run': bytes(wire[8:24]),
            'sequence': int.from_bytes(wire[24:28], 'big'),
            'body': body}


def encode(opcode: int, flags: int, run: bytes, sequence: int,
           body: bytes) -> bytes:
    """Encode one wire message; the caller picks the lane's body bound."""
    if len(run) != RUN_UUID_SIZE:
        raise ValueError('run_uuid must be 16 bytes')
    if len(body) > MAX_BODY:
        raise ValueError('body over 96-byte unicast bound')
    if not 0 <= opcode <= 0xFF or not 0 <= flags <= 0xFFFF:
        raise ValueError('opcode/flags out of range')
    if not 0 <= sequence <= 0xFFFFFFFF:
        raise ValueError('sequence out of range')
    return (MAGIC + bytes((PROTOCOL_VERSION, opcode)) +
            flags.to_bytes(2, 'big') + run +
            sequence.to_bytes(4, 'big') +
            zlib.crc32(body).to_bytes(4, 'big') + body)


def _reader(body: bytes):
    """(read(n), finish()) over a fixed-layout body — trailing bytes fail."""
    pos = [0]

    def take(n: int) -> bytes:
        if len(body) - pos[0] < n:
            raise ValueError('truncated')
        out = body[pos[0]:pos[0] + n]
        pos[0] += n
        return out

    def finish():
        if pos[0] != len(body):
            raise ValueError('trailing garbage')

    return take, finish


def _capabilities(caps: dict) -> bytes:
    """Encode a CAPABILITIES body (used by the fake bench_node fixture)."""
    opcodes = caps['opcodes']
    if len(opcodes) > 24:
        raise ValueError('opcode list over 24')
    return (bytes((caps['app_protocol'], caps['app_version'],
                  caps['max_unicast_body'], caps['max_group_body'],
                  caps['max_command_body'], caps['run_slots'],
                  caps['reply_queue'], caps['generator_max_inflight'])) +
            caps['boot_incarnation'].to_bytes(8, 'big') +
            caps['firmware_digest'].to_bytes(4, 'big') +
            caps['config_digest'].to_bytes(4, 'big') +
            bytes((len(opcodes),)) + bytes(opcodes))


def decode_capabilities(body: bytes) -> dict:
    """CAPABILITIES body (HELLO reply / once-per-join announce)."""
    take, finish = _reader(body)
    out = {'app_protocol': take(1)[0], 'app_version': take(1)[0],
           'max_unicast_body': take(1)[0], 'max_group_body': take(1)[0],
           'max_command_body': take(1)[0], 'run_slots': take(1)[0],
           'reply_queue': take(1)[0], 'generator_max_inflight': take(1)[0],
           'boot_incarnation': int.from_bytes(take(8), 'big'),
           'firmware_digest': int.from_bytes(take(4), 'big'),
           'config_digest': int.from_bytes(take(4), 'big')}
    count = take(1)[0]
    if count > 24:                           # CAPABILITIES_OPCODES_MAX
        raise ValueError('opcode count over 24')
    out['opcodes'] = list(take(count))
    finish()
    return out


# COUNT_STATUS `state` field values.
COUNT_UNKNOWN = 0    # the run never existed on this incarnation
COUNT_ACTIVE = 1
COUNT_RETIRED = 2
COUNT_STALE_BOOT = 3  # bound to a boot that is not this incarnation


def encode_count_status(body: dict) -> bytes:
    """COUNT_STATUS body (37 B) — encoder exists for the fake fixture."""
    out = bytes((body['state'],))
    for name in ('unique_packets', 'unique_bytes', 'duplicates',
                 'crc_invalid', 'first_ms', 'last_ms', 'window_base'):
        out += body[name].to_bytes(4, 'big')
    return out + body['window'].to_bytes(8, 'big')


def decode_count_status(body: bytes) -> dict:
    take, finish = _reader(body)
    out = {'state': take(1)[0]}
    for name in ('unique_packets', 'unique_bytes', 'duplicates',
                 'crc_invalid', 'first_ms', 'last_ms', 'window_base'):
        out[name] = int.from_bytes(take(4), 'big')
    out['window'] = int.from_bytes(take(8), 'big')
    finish()
    return out


# ROLLCALL / STATUS_GET page selector; 0xFF asks for none.
ROLLCALL_NO_PAGE = 0xFF


def encode_page_body(page: int) -> bytes:
    return bytes((page,))


def encode_peer_send_start(*, expected_boot: int, expected_dest_boot: int,
                           destination: int, sequence_begin: int, count: int,
                           payload_len: int, seed: int, interval_ms: int,
                           ttl_ms: int, max_inflight: int) -> bytes:
    """PEER_SEND_START body (44 B). `expected_boot` pins the command to the
    source's own incarnation; `expected_dest_boot` binds the run to the
    destination's — both learned via HELLO beforehand."""
    return (expected_boot.to_bytes(8, 'big') +
            expected_dest_boot.to_bytes(8, 'big') +
            destination.to_bytes(8, 'big') +
            sequence_begin.to_bytes(4, 'big') +
            count.to_bytes(2, 'big') +
            bytes((payload_len,)) +
            seed.to_bytes(4, 'big') +
            interval_ms.to_bytes(4, 'big') +
            ttl_ms.to_bytes(4, 'big') +
            bytes((max_inflight,)))


def decode_peer_send_start(body: bytes) -> dict:
    take, finish = _reader(body)
    out = {'expected_boot': int.from_bytes(take(8), 'big'),
           'expected_dest_boot': int.from_bytes(take(8), 'big'),
           'destination': int.from_bytes(take(8), 'big'),
           'sequence_begin': int.from_bytes(take(4), 'big'),
           'count': int.from_bytes(take(2), 'big'),
           'payload_len': take(1)[0],
           'seed': int.from_bytes(take(4), 'big'),
           'interval_ms': int.from_bytes(take(4), 'big'),
           'ttl_ms': int.from_bytes(take(4), 'big'),
           'max_inflight': take(1)[0]}
    finish()
    return out


# PEER_SEND_STATUS `result` field values.
PS_QUERY = 0
PS_STARTED = 1
PS_DUPLICATE = 2        # same (origin, run, seq) seen — run not restarted
PS_STALE_BOOT = 3       # expected_boot mismatch — never restarts
PS_BUSY = 4             # another generator run lives
PS_INVALID = 5
PS_STOPPED = 6
PS_NOT_RUNNING = 7

# PEER_SEND_STATUS `state` field values (device generator state).
GEN_IDLE = 0
GEN_RUNNING = 1
GEN_COMPLETE = 2
GEN_STOPPED = 3
GEN_TIME_BOUND = 4     # stopped by the 60 s run bound
GEN_PEER_RESET = 5     # bound destination reset mid-run
GEN_TERMINAL = frozenset({GEN_COMPLETE, GEN_STOPPED, GEN_TIME_BOUND,
                          GEN_PEER_RESET})


def decode_peer_send_status(body: bytes) -> dict:
    take, finish = _reader(body)
    out = {'result': take(1)[0], 'state': take(1)[0]}
    for name in ('planned', 'submitted', 'admitted', 'delivered', 'failed',
                 'unknown'):
        out[name] = int.from_bytes(take(2), 'big')
    out['first_ms'] = int.from_bytes(take(4), 'big')
    out['last_ms'] = int.from_bytes(take(4), 'big')
    finish()
    return out


def encode_peer_send_status(body: dict) -> bytes:
    """PEER_SEND_STATUS body (22 B) — encoder exists for the fake fixture."""
    out = bytes((body['result'], body['state']))
    for name in ('planned', 'submitted', 'admitted', 'delivered', 'failed',
                 'unknown'):
        out += body[name].to_bytes(2, 'big')
    return (out + body['first_ms'].to_bytes(4, 'big') +
            body['last_ms'].to_bytes(4, 'big'))


def encode_expected_boot(expected_boot: int) -> bytes:
    """Shared scalar body for PEER_SEND_STOP / COUNTER_RESET."""
    return expected_boot.to_bytes(8, 'big')


# STATUS page ids (design §5.3 categories, bounded per page).
STATUS_PAGE_IDENTITY = 0
STATUS_PAGE_PARTICIPATION = 1
STATUS_PAGE_COUNTERS = 2
STATUS_PAGE_RUN0 = 3
STATUS_PAGE_RUN1 = 4
STATUS_PAGE_GENERATOR = 5
STATUS_PAGE_RESOURCES = 6
STATUS_PAGE_COUNT = 7


def decode_status_head(body: bytes) -> tuple[dict, bytes]:
    """STATUS body head + remaining page bytes."""
    take, _ = _reader(body)
    head = {'sample_seq': int.from_bytes(take(2), 'big'),
            'boot_incarnation': int.from_bytes(take(8), 'big'),
            'page': take(1)[0], 'page_count': take(1)[0]}
    return head, body[12:]

/*
 * Static sizes of one RouteLoom EDHOC session (routeloom/edhoc.hpp).
 *
 * Plain C so that components/routeloom/src/edhoc/edhoc_port.c — the only
 * translation unit that sees libedhoc's internal context layout — can check
 * them at compile time against sizeof(struct edhoc_context) and the libedhoc
 * build configuration (src/edhoc/edhoc_config.h). A mismatch is a build
 * error, never a runtime overflow.
 *
 * Sized from tests/cpp/test_edhoc.cpp, which reports and checks them: the
 * arena's high-water mark over every handshake in the test (RFC 9529 §3,
 * the method-0 RLCW1 round trip, 256-byte CRED_x — the RLCW1 maximum —
 * with 32-byte kids on both sides, and the zero-touch join exchange with the
 * DevCert/SiteCert in the Credential EAD item plus the join EAD, P3-1) is
 * 1440 bytes in at most 6 live blocks; the test requires >= 25 % headroom.
 * P2-1 sized the arena at 1280 bytes (888 without EAD); the join exchange
 * exhausted it while composing message_3, so P3-1 raised it to 2048. At
 * most 6 key handles are live at once (the local long-term key included).
 * Whole session: 3880 bytes on LP64 hosts, about 3.5 KB on ILP32
 * (context 576 + arena 2160 + keys 364 + hashes ...).
 */
#ifndef ROUTELOOM_EDHOC_STORAGE_H
#define ROUTELOOM_EDHOC_STORAGE_H

#include <stdint.h>

/* sizeof(struct edhoc_context) under src/edhoc/edhoc_config.h is 920 bytes
 * on LP64 hosts and 556 bytes on ILP32 targets (measured for x86-64,
 * RISC-V32, i686 and Thumb; the Xtensa ILP32 ABI lays these types out the
 * same way). It is pointer-heavy (callback tables), hence two figures; the
 * storage rounds up to 16 bytes plus a small margin. */
#if UINTPTR_MAX > 0xFFFFFFFFu
#define ROUTELOOM_EDHOC_CONTEXT_BYTES 928
#else
#define ROUTELOOM_EDHOC_CONTEXT_BYTES 576
#endif
#define ROUTELOOM_EDHOC_CONTEXT_ALIGN 8

#define ROUTELOOM_EDHOC_ARENA_BYTES 2048
#define ROUTELOOM_EDHOC_ARENA_BLOCKS 12
#define ROUTELOOM_EDHOC_KEY_SLOTS 10

/* Must equal CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID and
 * CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES (checked in edhoc_port.c). */
#define ROUTELOOM_EDHOC_CONN_ID_MAX 4
#define ROUTELOOM_EDHOC_SUITES_MAX 2

#endif /* ROUTELOOM_EDHOC_STORAGE_H */

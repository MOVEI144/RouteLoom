/*
 * Compile-time contract between routeloom/edhoc.hpp and the vendored
 * libedhoc. This is the only RouteLoom translation unit that includes
 * libedhoc's internal context header (C11: C++ cannot include it), so the
 * static storage reserved for `struct edhoc_context` inside
 * routeloom::edhoc::Session is checked here against the real layout, on
 * every target the component is built for (64-bit host, 32-bit ESP32).
 */
#include "edhoc_config.h"
#include "edhoc_context_internal.h"
#include "routeloom/edhoc_storage.h"

#include <stdalign.h>
#include <stddef.h>
#include <string.h>

_Static_assert(sizeof(struct edhoc_context) <= ROUTELOOM_EDHOC_CONTEXT_BYTES,
	       "ROUTELOOM_EDHOC_CONTEXT_BYTES is smaller than the libedhoc context");
_Static_assert(alignof(struct edhoc_context) <= ROUTELOOM_EDHOC_CONTEXT_ALIGN,
	       "ROUTELOOM_EDHOC_CONTEXT_ALIGN is weaker than the libedhoc context");
_Static_assert(CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID == ROUTELOOM_EDHOC_CONN_ID_MAX,
	       "edhoc_config.h and edhoc_storage.h disagree on the C_I/C_R size");
_Static_assert(CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES == ROUTELOOM_EDHOC_SUITES_MAX,
	       "edhoc_config.h and edhoc_storage.h disagree on the suite count");
_Static_assert(CONFIG_LIBEDHOC_KEY_ID_LEN == 4,
	       "routeloom::edhoc::KeyStore handles are 4 bytes");
_Static_assert(CONFIG_LIBEDHOC_MEM_BACKEND == 2,
	       "RouteLoom routes libedhoc allocations to its bounded arena");

/* Exact size, for the test report and the documentation. */
size_t routeloom_edhoc_context_sizeof(void);
size_t routeloom_edhoc_context_sizeof(void)
{
	return sizeof(struct edhoc_context);
}

/*
 * The peer's negotiated connection identifier (C_I on a responder after
 * message 1, C_R on an initiator after message 2). Returns the identifier
 * length in bytes, or 0 when none was negotiated yet; copies the bytes only
 * when they fit. The member profile (P4 §5.1) accepts exactly 4 bytes —
 * that policy lives in the caller, this is only the read-out so no C++
 * translation unit has to include the internal context header.
 */
size_t routeloom_edhoc_peer_cid(const struct edhoc_context *ctx, uint8_t *out,
				size_t capacity);
size_t routeloom_edhoc_peer_cid(const struct edhoc_context *ctx, uint8_t *out,
				size_t capacity)
{
	const struct connection_id *cid;

	if (ctx == NULL || !ctx->is_init) {
		return 0;
	}
	cid = &ctx->negotiation.peer_connection_id;
	if (cid->length == 0 || cid->length > CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID) {
		return 0;
	}
	if (out != NULL && capacity >= cid->length) {
		memcpy(out, cid->value, cid->length);
	}
	return cid->length;
}

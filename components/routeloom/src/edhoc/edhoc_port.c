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

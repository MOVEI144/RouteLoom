/*
 * Test-only window into libedhoc's internal key-slot table, so
 * tests/cpp/test_edhoc.cpp can compare intermediate PRKs (PRK_3e2m,
 * PRK_4e3m, PRK_out, PRK_exporter) with RFC 9529 byte for byte. C, because
 * libedhoc's internal context header is C11 only.
 */
#include "edhoc_config.h"
#include "edhoc_context_internal.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum {
	ROUTELOOM_PROBE_PRK_2E = EDHOC_KEY_SLOT_PRK_2E,
	ROUTELOOM_PROBE_PRK_3E2M = EDHOC_KEY_SLOT_PRK_3E2M,
	ROUTELOOM_PROBE_PRK_4E3M = EDHOC_KEY_SLOT_PRK_4E3M,
	ROUTELOOM_PROBE_PRK_OUT = EDHOC_KEY_SLOT_PRK_OUT,
	ROUTELOOM_PROBE_PRK_EXPORTER = EDHOC_KEY_SLOT_PRK_EXPORTER,
};

int routeloom_edhoc_probe_slot(const struct edhoc_context *ctx, int slot,
			       uint8_t handle[CONFIG_LIBEDHOC_KEY_ID_LEN]);
int routeloom_edhoc_probe_slot_id(const char *name);

int routeloom_edhoc_probe_slot_id(const char *name)
{
	if (0 == strcmp(name, "PRK_2e")) {
		return ROUTELOOM_PROBE_PRK_2E;
	}
	if (0 == strcmp(name, "PRK_3e2m")) {
		return ROUTELOOM_PROBE_PRK_3E2M;
	}
	if (0 == strcmp(name, "PRK_4e3m")) {
		return ROUTELOOM_PROBE_PRK_4E3M;
	}
	if (0 == strcmp(name, "PRK_out")) {
		return ROUTELOOM_PROBE_PRK_OUT;
	}
	if (0 == strcmp(name, "PRK_exporter")) {
		return ROUTELOOM_PROBE_PRK_EXPORTER;
	}
	return -1;
}

/* 1 and the slot's backend handle when the slot holds a live key, else 0. */
int routeloom_edhoc_probe_slot(const struct edhoc_context *ctx, int slot,
			       uint8_t handle[CONFIG_LIBEDHOC_KEY_ID_LEN])
{
	if (NULL == ctx || slot < 0 || slot >= (int)EDHOC_KEY_SLOT_COUNT) {
		return 0;
	}
	const struct edhoc_key_slot *key_slot = &ctx->key_slots[slot];
	if (!key_slot->present) {
		return 0;
	}
	memcpy(handle, key_slot->key_id, CONFIG_LIBEDHOC_KEY_ID_LEN);
	return 1;
}

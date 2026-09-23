#pragma once

// libedhoc's public C API for RouteLoom C++ translation units.
//
// The vendored headers are C11 and stay unmodified. Two of them state
// invariants with the C11 `_Static_assert` keyword at file scope, which C++17
// spells `static_assert` (GCC has no C++ `_Static_assert`; Clang accepts it
// only as an extension that -Wpedantic rejects). The macro maps one onto the
// other for exactly these includes and is removed right after. The internal
// context header is not C++ (compound literals) and is only used from C
// (src/edhoc/edhoc_port.c, tests/cpp/edhoc_probe.c).

#include <cstddef>
#include <cstdint>

#include "edhoc_config.h"

// Some C libraries' C++ headers already provide the mapping (picolibc's
// sys/cdefs.h on ESP-IDF defines _Static_assert for C++): only define it, and
// only undefine it, when it is not already there. The C library headers are
// pulled in first so their definition (if any) is always seen before ours.
#ifndef _Static_assert
#define _Static_assert static_assert
#define ROUTELOOM_DEFINED_STATIC_ASSERT_MAP 1
#endif
extern "C" {
#include <edhoc/edhoc.h>
}
#ifdef ROUTELOOM_DEFINED_STATIC_ASSERT_MAP
#undef _Static_assert
#undef ROUTELOOM_DEFINED_STATIC_ASSERT_MAP
#endif

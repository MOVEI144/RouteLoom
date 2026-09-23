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

#include "edhoc_config.h"

#define _Static_assert static_assert
extern "C" {
#include <edhoc/edhoc.h>
}
#undef _Static_assert

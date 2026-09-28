// Test-only ESP-IDF stand-in: no Kconfig on host builds. Every CONFIG_*
// reference in the linked firmware translation units is an `#if` (an
// undefined macro tests as 0) or an `#ifdef` (false), so an empty file is
// the honest stub — no firmware sdkconfig value is ever implied.
#pragma once

#pragma once

#include "routeloom/sdkv1_store.hpp"

namespace routeloom::bridge_node {

// The mesh header uses the low word, but USB authentication must bind to the
// committed Member epoch after a cutover. A gateway still awaiting its first
// Join has no site record and uses its provisioned bootstrap network.
inline NetworkId usb_boot_network(const sdkv1::SiteStore& site,
                                  NetworkId bootstrap_network) noexcept {
  return site.has_site() ? site.site().network : bootstrap_network;
}

}  // namespace routeloom::bridge_node

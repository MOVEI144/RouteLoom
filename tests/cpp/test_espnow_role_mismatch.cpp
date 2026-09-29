#include <cstdio>
#include <cstring>

#include "routeloom/espnow_runtime.hpp"

#include "idf_stubs.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

int main() {
  using namespace routeloom;
  using namespace routeloom::espnow;
  idf_stub::reset();
  routeloom_test::TestSecurity security;
  routeloom_test::CapturingObserver observer;
  EspNowRuntimeConfig config{};
  config.node.network = 7;
  config.node.node = 1;
  config.node.message_session = 1;
  config.node.boot_incarnation = 1;
  config.channel = 6;
  config.max_tx_power_qdbm = 80;
  EspNowRuntime runtime(config, security, observer);
  const Status status = runtime.initialize();
  if (status.code != StatusCode::Unsupported ||
      std::strcmp(status.detail, "RESOURCE_PROFILE_ROLE_MISMATCH") != 0 ||
      idf_stub::peer_count() != 0) {
    std::fprintf(stderr, "profile/role mismatch reached RF initialization\n");
    return 1;
  }
  return 0;
}

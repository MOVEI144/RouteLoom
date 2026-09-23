#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>

#include "routeloom/routeloom.h"

int main(void) {
  rl_node_config_t config;
  rl_send_options_t options;
  rl_node_config_init(&config);
  rl_send_options_init(&options);
  if (config.abi_version != RL_ABI_VERSION || options.abi_version != RL_ABI_VERSION) return 1;
  if (rl_context_size() == 0 || rl_context_alignment() > alignof(max_align_t)) return 2;
  if (rl_status_code_name(RL_STATUS_OK) == NULL) return 3;
  /* Tail extension: full struct by default, flat routing profile. */
  if (config.struct_size != sizeof(config) || config.struct_size <= RL_NODE_CONFIG_SIZE_BASE) return 4;
  if (config.route_gateway_count != 0 || config.route_gateways[0] != 0 ||
      config.route_gateways[RL_MAX_ROUTE_GATEWAYS - 1] != 0 || config.route_refresh_ticks == 0) {
    return 5;
  }
  if (rl_route_gateways(NULL, NULL, 0) != 0) return 6;
  return 0;
}

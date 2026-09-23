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
  /* Group delivery: additive symbols, ABI version unchanged. */
  {
    rl_group_send_options_t group_options;
    rl_group_result_t result;
    rl_message_id_t id = {0, 0};
    rl_group_send_options_init(&group_options);
    if (group_options.abi_version != RL_ABI_VERSION ||
        group_options.struct_size != sizeof(group_options) || options.ordered != 0) {
      return 7;
    }
    if (rl_send_group(NULL, RL_GROUP_ALL, NULL, 0, &group_options, 0, &id) !=
            RL_STATUS_INVALID_ARGUMENT ||
        rl_get_group_result(NULL, id, &result) != RL_STATUS_INVALID_ARGUMENT ||
        rl_set_group_membership(NULL, NULL, 0) != RL_STATUS_INVALID_ARGUMENT) {
      return 8;
    }
    if (RL_SECURITY_GROUP != 2 || RL_GROUP_PAYLOAD_MAX != 127u) return 9;
  }
  return 0;
}

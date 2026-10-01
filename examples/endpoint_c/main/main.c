/* RouteLoom endpoint example in C: an application on the Device C API
   (routeloom/device.h). rl_dev_start() boots the node on its own Owner task
   from the component Kconfig. The app logs what arrives and the membership
   changes and, from another task, posts one greeting a minute to
   EXAMPLE_DESTINATION through rl_dev_post(), the only call that may come
   from outside the Owner task. */

#include <inttypes.h>
#include <stdint.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "routeloom/device.h"

static const char* const kTag = "RouteLoomExampleC";
static rl_dev_t* s_device;

static void on_message(void* user, rl_node_id_t origin, rl_message_id_t id,
                       const uint8_t* payload, size_t payload_size) {
  (void)user;
  (void)payload;
  ESP_LOGI(kTag, "received %u bytes from 0x%" PRIx64 " (session %" PRIu32 ")",
           (unsigned)payload_size, origin, id.session);
}

static void on_delivery(void* user, const rl_delivery_result_t* result) {
  (void)user;
  ESP_LOGI(kTag, "delivery %" PRIu64 ": state %u %s", result->id.sequence,
           (unsigned)result->state, result->reason);
}

static void on_membership(void* user, const rl_dev_membership_t* snapshot, uint16_t cause) {
  (void)user;
  ESP_LOGI(kTag, "membership stage %u (reason %u)", (unsigned)snapshot->stage, (unsigned)cause);
}

/* Runs on the Owner task: the only place that may call rl_dev_send(). */
static void send_greeting(rl_dev_t* device, void* ctx) {
  static const uint8_t kGreeting[] = {'h', 'e', 'l', 'l', 'o'};
  rl_dev_send_options_t options;
  rl_message_id_t id;
  (void)ctx;
  rl_dev_send_options_init(&options);
  const rl_status_code_t sent = rl_dev_send(device, CONFIG_EXAMPLE_DESTINATION, kGreeting,
                                            sizeof kGreeting, &options, &id);
  ESP_LOGI(kTag, "greeting from 0x%" PRIx64 ": %s", rl_dev_node_id(device),
           rl_status_code_name(sent));
}

static void app_task(void* arg) {
  (void)arg;
  if (CONFIG_EXAMPLE_DESTINATION == 0) vTaskDelete(NULL);
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(60000));
    if (rl_dev_post(s_device, send_greeting, NULL) != RL_STATUS_OK) {
      ESP_LOGW(kTag, "post queue full");
    }
  }
}

void app_main(void) {
  rl_dev_observer_t observer;
  rl_dev_struct_init(&observer, sizeof observer);
  observer.on_message = on_message;
  observer.on_delivery = on_delivery;
  observer.on_membership = on_membership;
  s_device = rl_dev_start(&observer);
  xTaskCreate(app_task, "example", 3072, NULL, 1, NULL);
}

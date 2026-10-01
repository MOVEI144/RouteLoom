// Radio diagnosis only; raw public markers are not SDK acceptance traffic.
#include <stdio.h>
#include <string.h>
#include "esp_event.h"
#include "esp_log.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

static const uint8_t macs[3][6] = {
  {0x94,0xa9,0x90,0x7a,0x26,0xac},
  {0x10,0xbd,0xa3,0xb1,0x48,0xa8},
  {0x10,0xbd,0xa3,0xb1,0x47,0x54}
};
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
static unsigned ok[3], fail[3], rx[3], pending;
static int self;
static int index_of(const uint8_t *mac) {
  for (int i=0;i<3;++i) if (memcmp(mac,macs[i],6)==0) return i;
  return -1;
}
static void sent(const esp_now_send_info_t *info, esp_now_send_status_t result) {
  int i=index_of(info->des_addr);
  portENTER_CRITICAL(&mux);
  if(i>=0) { if(result==ESP_NOW_SEND_SUCCESS) ++ok[i]; else ++fail[i]; }
  pending=0;
  portEXIT_CRITICAL(&mux);
}
static void received(const esp_now_recv_info_t *info,const uint8_t *data,int len) {
  if(len!=128 || memcmp(data,"STAB-RF",7)!=0) return;
  int i=index_of(info->src_addr);
  portENTER_CRITICAL(&mux);
  if(i>=0) ++rx[i];
  portEXIT_CRITICAL(&mux);
}
void app_main(void) {
  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_init_config_t init=WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&init));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  wifi_country_t country={.cc="JP",.schan=1,.nchan=13,.max_tx_power=10,
                          .policy=WIFI_COUNTRY_POLICY_MANUAL};
  ESP_ERROR_CHECK(esp_wifi_set_country(&country));
  ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_STA,
                 WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR));
  ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA,WIFI_BW20));
  ESP_ERROR_CHECK(esp_wifi_start());
  ESP_ERROR_CHECK(esp_wifi_set_max_tx_power(40));
  uint8_t own[6]; ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA,own));
  self=index_of(own); if(self<0) {ESP_LOGE("PROBE","unrecognized MAC");return;}
  ESP_ERROR_CHECK(esp_now_init());
  ESP_ERROR_CHECK(esp_now_register_send_cb(sent));
  ESP_ERROR_CHECK(esp_now_register_recv_cb(received));
  for(int i=0;i<3;++i) if(i!=self) {
    esp_now_peer_info_t p={0}; memcpy(p.peer_addr,macs[i],6);
    p.ifidx=WIFI_IF_STA;p.channel=0;
    ESP_ERROR_CHECK(esp_now_add_peer(&p));
  }
  const struct {uint8_t channel;int8_t power;bool lr500;} phases[] = {
    {6,40,false},{1,40,false},{1,8,false},{6,8,false},
    {1,40,true},{6,40,true},{1,8,true},{6,8,true}
  };
  uint8_t payload[128]={0};memcpy(payload,"STAB-RF",7);
  int64_t started_us=esp_timer_get_time();
  for(unsigned phase=0;phase<sizeof(phases)/sizeof(phases[0]);++phase) {
    ESP_ERROR_CHECK(esp_wifi_set_channel(phases[phase].channel,WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_STA, true ?
      WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR : WIFI_PROTOCOL_LR));
    ESP_ERROR_CHECK(esp_wifi_set_max_tx_power(phases[phase].power));
    esp_now_rate_config_t rate={0};
    rate.phymode=WIFI_PHY_MODE_LR;
    rate.rate=phases[phase].lr500?WIFI_PHY_RATE_LORA_500K:WIFI_PHY_RATE_LORA_250K;
    for(int i=0;i<3;++i) if(i!=self)
      ESP_ERROR_CHECK(esp_now_set_peer_rate_config(macs[i],&rate));
    vTaskDelay(pdMS_TO_TICKS(2000));
    portENTER_CRITICAL(&mux);
    memset(ok,0,sizeof(ok));memset(fail,0,sizeof(fail));memset(rx,0,sizeof(rx));
    portEXIT_CRITICAL(&mux);
    uint8_t ch,protocol;wifi_second_chan_t secondary;int8_t power;
    ESP_ERROR_CHECK(esp_wifi_get_channel(&ch,&secondary));
    ESP_ERROR_CHECK(esp_wifi_get_protocol(WIFI_IF_STA,&protocol));
    ESP_ERROR_CHECK(esp_wifi_get_max_tx_power(&power));
    ESP_LOGI("PROBE","begin node=%d phase=%u ch=%u lr500=%d protocol=%u power=%d",self+1,phase,ch,phases[phase].lr500,protocol,power);
    unsigned admitted[3]={0},errors[3]={0};
    for(unsigned n=0;n<20;++n) {
      for(int i=0;i<3;++i) if(i!=self) {
        portENTER_CRITICAL(&mux);pending=1;portEXIT_CRITICAL(&mux);
        esp_err_t e=esp_now_send(macs[i],payload,sizeof(payload));
        if(e==ESP_OK) ++admitted[i]; else {
          ++errors[i];portENTER_CRITICAL(&mux);pending=0;portEXIT_CRITICAL(&mux);
        }
        for(unsigned wait=0;wait<50;++wait) {
          portENTER_CRITICAL(&mux);unsigned active=pending;portEXIT_CRITICAL(&mux);
          if(!active) break;
          vTaskDelay(pdMS_TO_TICKS(10));
        }
        vTaskDelay(pdMS_TO_TICKS(100));
      }
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
    for(int i=0;i<3;++i) if(i!=self) {
      portENTER_CRITICAL(&mux);unsigned o=ok[i],f=fail[i],r=rx[i];portEXIT_CRITICAL(&mux);
      ESP_LOGI("PROBE","result node=%d peer=%d phase=%u ch=%u lr500=%d admitted=%u errors=%u ok=%u fail=%u rx=%u",self+1,i+1,phase,ch,phases[phase].lr500,admitted[i],errors[i],o,f,r);
    }
    const int64_t boundary=started_us+(phase+1)*30000000LL;
    if(esp_timer_get_time()>boundary) {ESP_LOGE("PROBE","phase overrun");return;}
    while(esp_timer_get_time()<boundary) vTaskDelay(pdMS_TO_TICKS(10));
  }
  ESP_LOGI("PROBE","done");
}

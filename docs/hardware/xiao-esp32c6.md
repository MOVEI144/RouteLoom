# Seeed Studio XIAO ESP32-C6

確認：2026-09-28。C3やC5の同じbin／GPIO定義を流用しない。v2では正式対象（全appのCI cellは `tools/ci/cells.json`）。

## 1. 公式リンク

- [Seeed Getting Started・Pin Map](https://wiki.seeedstudio.com/xiao_esp32c6_getting_started/)
- [Espressif ESP32-C6データシート](https://documentation.espressif.com/esp32-c6_datasheet_en.html)
- [ESP-IDF C6 ESP-NOW](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/network/esp_now.html)
- [USB Serial/JTAG](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-guides/usb-serial-jtag-console.html)
- [Sleep modes](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/system/sleep_modes.html)

## 2. 構成

HP core RISC-V 32bit最大160MHz、LP core最大20MHz。HP SRAM512KB、標準board flash4MB、PSRAMなし。2.4GHz Wi-Fi 6、Bluetooth LE、802.15.4を持つが、RouteLoomはESP-NOW LRだけを使う。LP coreはRouteLoomでは使わない。

## 3. 端子

| 端子 | GPIO | 基準用途 |
|---|---:|---|
| D0 | 0 | ADC/GPIO |
| D1 | 1 | ADC/GPIO |
| D2 | 2 | ADC/GPIO |
| D3 | 21 | GPIO |
| D4 | 22 | I2C SDA |
| D5 | 23 | I2C SCL |
| D6 | 16 | UART TX |
| D7 | 17 | UART RX |
| D8 | 19 | SPI SCK |
| D9 | 20 | SPI MISO |
| D10 | 18 | SPI MOSI |

BOOTはGPIO9、USER LEDはGPIO15。USB Serial/JTAGはGPIO12/13（D−/D＋）を使う。GPIO3はRF switchの有効化（Lowで有効）、GPIO14はantenna選択（Low：基板上アンテナ、High：U.FL外部）で、自由な端子として扱わない。SDK の `Device` 起動は Wi-Fi 初期化前に GPIO3 を出力 Low、GPIO14 を出力 Low に自動設定し、基板上アンテナを選ぶ。U.FL 外部アンテナを使う場合は component の Kconfig `CONFIG_ROUTELOOM_BOARD_C6_EXTERNAL_ANTENNA=y`（既定 n）で GPIO14 を High にする。起動 log は `rf switch: enabled, antenna: internal|external`。GPIO 設定が失敗した場合は Wi-Fi を初期化しない。外部アンテナの適合条件を確認する。

## 4. 電源

USB側5VとBATの1セル充電池系を区別し、一次電池をBATへ接続しない。WikiのDeep Sleep約15µA、Light-sleep約3.1mA、Modem-sleep約30mAはboard条件付きの参考値。電池電圧の測定はA0へ外付け分圧（200kΩ×2）を足す例があるだけで、SDKは残量%を算出しない。

## 5. RouteLoom受入

4MBにbootloader、partition、NVS、鍵保存、firmware、OTA 2面が収まること（v2の `PT-4M-v2`）。C3↔C6、S3↔C6、C6↔C6を方向別に試験し、C6の結果をC5の代用にしない。

# Seeed Studio XIAO ESP32-C3

確認：2026-09-17。対象は標準XIAO ESP32-C3。外観が似たC6/C5とは別profile。

## 1. 公式リンク

- [Seeed Getting Started・Pin Map](https://wiki.seeedstudio.com/XIAO_ESP32C3_Getting_Started/)
- [Seeed回路図 v1.3、2026-01版](https://files.seeedstudio.com/wiki/XIAO_WiFi/Resources/XIAO_ESP32C3_v1.3_SCH_260116.pdf)
- [Espressif ESP32-C3データシート](https://documentation.espressif.com/esp32-c3_datasheet_en.html)
- [ESP-IDF C3 ESP-NOW](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/network/esp_now.html)
- [USB Serial/JTAG](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-guides/usb-serial-jtag-console.html)
- [Sleep modes](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/sleep_modes.html)

## 2. 構成

RISC-V 32bit単核、最大160MHz。SoC SRAM400KB、標準board flash4MB。PSRAMを前提にしない。2.4GHz 802.11b/g/nとBluetooth LEを搭載するが、RouteLoomはBLEを無効にしてESP-NOW LRを使う。

基板は21×17.8mm級、USB-C、外部アンテナ用U.FL。USBの有無はインターネット機能を意味しない。SoC内部のGPIO数とXIAO端子11本は別。

## 3. 端子

| 端子 | GPIO | 基準機能・注意 |
|---|---:|---|
| D0 | 2 | ADC1、boot strap条件に注意 |
| D1 | 3 | ADC1 |
| D2 | 4 | ADC1 |
| D3 | 5 | ADC2。Wi-Fi利用時の制約を確認 |
| D4 | 6 | I2C SDA |
| D5 | 7 | I2C SCL |
| D6 | 21 | UART TX |
| D7 | 20 | UART RX |
| D8 | 8 | SPI SCK、strap |
| D9 | 9 | SPI MISO、BOOT/strap |
| D10 | 10 | SPI MOSI |

GPIO2/8/9は起動時の外部pullや接続回路に注意する。BOOTはGPIO9、ENはreset。USB Serial/JTAGはGPIO18/19を使う。USBを使用中に通常GPIOへ転用しない。充電LEDをアプリLEDとみなさない。標準boardに自由なuser LEDはない。

Deep SleepのGPIO起床には機種固有制約がある。公開端子ではD0〜D3を候補とし、対象IDF・電源domain・外部信号の保持を実機確認する。S3のEXT0/EXT1使用例をそのままコピーしない。

## 4. 電源

USB側5V、BATは公称3.7Vの1セル充電池系。充電回路を持つため一次電池をBATへ接続しない。3V3は出力として扱い、外から同時に電圧を押し込む配線を標準例にしない。

**公式資料の食い違い**：Wikiの3.3V供給能力には500mAと700mAの記載があり、古い比較表の充電ICと2026年の回路図の部品にも差がある。確認したv1.3回路図はTLV75733 regulator、XC6802系充電IC、VBUS側500mA fuseを含む。レギュレーター単体の電流を外部負荷へ全量使える保証にしない。実物revisionと温度、USB入力、ESP32自身のpulseを含めて許容負荷を決める。

WikiのDeep Sleep約44µA、Wi-Fi active約75mAはboard条件付きの参考値。SoC単体のDeep Sleep5µAやTX peakと同じ指標ではない。USB接続、LED、GPIO、ADC divider、外部センサーを含む実電源で再測定する。

## 5. RouteLoom側の必須確認

4MBにbootloader、partition、NVS、安全な鍵保存、firmware、必要なら二OTA slotとspoolが収まること。通常DATAのためにPSRAMを要求しないこと。認証・100node table・64frame queueでheapが枯渇しないこと。

board-specificな電池測定回路は標準の前提にしない。外付け分圧を追加する場合はADC範囲、入力抵抗、settling、常時消費を計算する。付属アンテナと異なるものを使うなら適合条件を再確認する。

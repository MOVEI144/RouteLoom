# 公式資料と参照実装

確認基準日：2026-09-17。メーカーの公開資料、IETF仕様、実装の提供元を優先する。記載したリンクの資料はRouteLoomの再配布物ではない。

## Espressif

| 資料 | 用途 |
|---|---|
| [ESP-IDF v6.0.3](https://github.com/espressif/esp-idf/releases/tag/v6.0.3) | 固定tag。commit 76f5dedd9950a3012fee8fb7d5586df21fc67802 |
| [esp_now.h固定版](https://github.com/espressif/esp-idf/blob/v6.0.3/components/esp_wifi/include/esp_now.h) | Peer、rate、callback、channel API |
| [Wi-Fi types固定版](https://github.com/espressif/esp-idf/blob/v6.0.3/components/esp_wifi/include/esp_wifi_types_generic.h) | LRの列挙、送受信metadata |
| [ESP-NOW C3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/network/esp_now.html) | driver契約とcallbackの制約 |
| [ESP-NOW S3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/network/esp_now.html) | S3版API |
| [ESP-NOW C5](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-reference/network/esp_now.html) | C5版API |
| [C5 Wi-Fi driver/LR](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-guides/wifi-driver/overview.html) | 2.4GHz LRとbandの区別 |
| [C3 Wi-Fi API](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/network/esp_wifi.html) | 設定・受信metadata |
| [C3 datasheet](https://documentation.espressif.com/esp32-c3_datasheet_en.html) | SoCメモリ・USB・strap・電気条件 |
| [S3 datasheet](https://documentation.espressif.com/esp32-s3_datasheet_en.html) | S3のSoC仕様参照 |
| [C5 datasheet](https://documentation.espressif.com/esp32-c5_datasheet_en.html) | C5のSoC仕様とpackage差 |
| [OTA](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/ota.html) | image管理・rollback |
| [C3 Sleep](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/sleep_modes.html) | sleepとwakeの制約 |
| [USB Serial/JTAG](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-guides/usb-serial-jtag-console.html) | host接続 |

stable/latestは資料確認の入口で、再現buildのpinではない。リンク取得環境により別版がcacheされるため、API採用は固定sourceと実機の両方で確認する。

## Seeed Studio

| 資料 | 対応する文書 |
|---|---|
| [C3 Wiki](https://wiki.seeedstudio.com/XIAO_ESP32C3_Getting_Started/) | C3 board仕様・pins・電源 |
| [C3回路図](https://files.seeedstudio.com/wiki/XIAO_WiFi/Resources/XIAO_ESP32C3_v1.3_SCH_260116.pdf) | 2026年公開v1.3。電源部を図面で照合 |
| [S3 Wiki](https://wiki.seeedstudio.com/xiao_esp32s3_getting_started/) | 標準/Sense/Plusの区別 |
| [S3回路図](https://files.seeedstudio.com/wiki/SeeedStudio-XIAO-ESP32S3/new-res/202003751_XIAO%20ESP32S3_v1.4_SCH_260226.pdf.pdf) | 内部Revとファイル名の差を記録 |
| [C5 Wiki](https://wiki.seeedstudio.com/xiao_esp32c5_getting_started/) | board仕様・pin table。メモリ現物照合要 |
| [C5回路図](https://files.seeedstudio.com/wiki/XIAO_ESP32C5/res/Seeed_Studio_XIAO_ESP32C5.pdf) | Rev1.1の電源・main回路を確認 |
| [C5 Wi-Fi](https://wiki.seeedstudio.com/xiao_esp32c5_wifi_usage/) | Arduino説明とdriver契約の区別 |
| [S3＋SX1262 kit](https://wiki.seeedstudio.com/wio_sx1262_with_xiao_esp32s3_kit/) | B2Bとheader variant、kit帯域 |
| [Wio module](https://wiki.seeedstudio.com/wio_sx1262/) | module側の参考仕様 |
| [Wio B2B回路図](https://files.seeedstudio.com/products/SenseCAP/Wio_SX1262/Schematic_Diagram_Wio-SX1262_for_XIAO.pdf) | SPI/BUSY/IRQ/LED/buttonを図面で照合 |
| [Single-channel gateway](https://wiki.seeedstudio.com/wio_sx1262_xiao_esp32s3_for_single_channel_gateway/) | SX1262とconcentratorの区別 |

資料の差異は[hardware](../hardware/README.md)へ記録する。メーカーWiki内の数字でも別revision、SoC単体、board全体を混ぜない。GPIO表はSDK実機配線の自動承認ではない。

## 標準とアルゴリズム

- [RFC 8966 Babel](https://www.rfc-editor.org/rfc/rfc8966.html)：route採用可能条件、撤回、sequence。
- [RFC 6719 MRHOF](https://www.rfc-editor.org/rfc/rfc6719.html)：小さな改善での親変更を抑える考え方。
- [RFC 6206 Trickle](https://www.rfc-editor.org/rfc/rfc6206.html)：安定時の制御通信削減。
- [RFC 9528 EDHOC](https://www.rfc-editor.org/rfc/rfc9528.html)：制約機器向け相互認証鍵交換。
- [RFC 8613 OSCORE](https://www.rfc-editor.org/rfc/rfc8613.html)：保護context、nonce、replay、再起動の参考。
- [Raft](https://raft.github.io/)：選挙と永続logの合意。term-only制御ではない。
- [Minstrel](https://wireless.docs.kernel.org/en/latest/en/developers/documentation/mac80211/ratecontrol/minstrel.html)：成功率と時間によるrate選択の参考。

## 実装を参照する際の範囲

[espressif/esp-nowのespnow.c](https://github.com/espressif/esp-now/blob/f1289da7916078b49947380acc17c09b7521ab76/src/espnow/src/espnow.c)は独自送信lock、forward、channel巡回等を持つ。RouteLoomはこの転送engineを重ねずlow-level driverを使用する。

[babeld route.c](https://github.com/jech/babeld/blob/master/route.c)はfeasibility、撤回、平滑化の分離の参考。参照はコード流用許諾を意味しない。

[Seeed one_channel_hub](https://github.com/Seeed-Studio/one_channel_hub)はSemtech LoRaWAN one-channel hubのESP-IDF実装例。確認時masterで、READMEはESP-IDF5.2.1を試験基盤として記載。RouteLoomのv6.0.3をその例に合わせて変更しない。

[Semtech SX1262比較](https://www.semtech.com/products/wireless-rf/end-nodes-ics)と[Semtech driver](https://github.com/Lora-net/sx126x_driver)は将来LoRa追加時の入口。現時点でそのRF試験を行ったという意味ではない。

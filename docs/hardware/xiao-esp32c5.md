# Seeed Studio XIAO ESP32-C5

確認：2026-09-17。C3やC6の同じbin／GPIO定義を流用しない。

## 1. 公式リンク

- [Seeed Getting Started・Pin Map](https://wiki.seeedstudio.com/xiao_esp32c5_getting_started/)
- [Seeed Wi-Fi利用](https://wiki.seeedstudio.com/xiao_esp32c5_wifi_usage/)
- [Seeed回路図](https://files.seeedstudio.com/wiki/XIAO_ESP32C5/res/Seeed_Studio_XIAO_ESP32C5.pdf)
- [ESP32-C5データシート](https://documentation.espressif.com/esp32-c5_datasheet_en.html)
- [ESP-IDF C5 Wi-Fi / LR](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-guides/wifi-driver/overview.html)
- [ESP-IDF C5 ESP-NOW](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-reference/network/esp_now.html)
- [C5 USB接続](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/get-started/establish-serial-connection.html)

## 2. CPU・メモリ・無線

RISC-V 32bit単核最大240MHz。SoC資料ではmain SRAM384KB、ROM320KB、low-power SRAMを区別する。2.4/5GHz Wi-Fi 6機能を持つが、RouteLoom v1は2.4GHz固定、LR250/500だけを使用する。dual bandを二つの同時独立radioと呼ばない。

Seeed Wiki比較表は8MB Flash＋8MB PSRAMと記載する。**このPSRAM値はメーカーWebの記載値であり、RouteLoomが現物を検証した値ではない。** SoC package variant、公開回路図のgenericな型番、実BOMを合わせ、起動時検出とメモリ試験でboard profileを確定する。確認前にPSRAM必須の資源配置を採用しない。

21×17.8mm級、USB-C、U.FL外部アンテナ構成。付属dual-bandアンテナでも2.4GHz側の配置と適合条件を確認する。

## 3. Pin Map

| 端子 | GPIO | 基準用途 |
|---|---:|---|
| D0 | 1 | ADC/GPIO |
| D1 | 0 | GPIO |
| D2 | 25 | GPIO、strap注意 |
| D3 | 7 | GPIO、strap注意 |
| D4 | 23 | SDA |
| D5 | 24 | SCL |
| D6 | 11 | UART TX |
| D7 | 12 | UART RX |
| D8 | 8 | SPI SCK |
| D9 | 9 | SPI MISO |
| D10 | 10 | SPI MOSI |

BOOT GPIO28、USER LED GPIO27、battery ADC GPIO6、測定回路enable GPIO26。USB D−/D＋はGPIO13/14。背面JTAG padはGPIO2〜5に関係する。SoCのstrap関連GPIO2/3/7/25/26/27/28はreset時の条件を確認する。

Wikiのpin表にあるTOUCH等の付加表記を、SoCの未確認機能としてSDKへ宣言しない。ADC channel総数とedgeで利用できるADC端子数を混同しない。

## 4. 電池電圧測定

公開回路図／WikiではGPIO26で測定回路を有効化しGPIO6へ分圧して読む。100kΩ＋100kΩなら理想倍率2だが、ADC校正・settling・抵抗誤差を含めて測る。起床直後に即readして正確とみなさない。未測定時は回路をOFFにする。

GPIO26は他用途・strapにも関係するため、外部回路と共用しない。SDK自身は電池の化学種から残量%を勝手に算出せず、アプリまたはPower Providerの較正モデルを使う。

## 5. 電源と基板revision

確認した回路図は5page、Rev1.1／2025-12-25。SGM6029電源、TPS2116 power mux、SGM40567-4.2充電系等が示される。部品定格をそのままboard外部負荷保証にしない。

USB5Vとsingle-cell充電池系のBATを区別し、一次電池を充電回路へ接続しない。3V3_OUTへの外部給電やUSBとの並列接続は回路確認なしに行わない。

board全体のDeep Sleep実測値はこの文書では未認定。C3の44µAやS3の14µAをC5へ転記しない。USB・LED・分圧・PSRAM・電源選択回路を含めて測る。

## 6. RouteLoom受入

C3↔C5、S3↔C5、C5↔C5を方向別に試験する。Wi-Fi 6対応を理由にLR性能や互換性を推定しない。Peer別rate、2.4GHz固定、unicast/broadcast、USB再起動、sleep wake、実Flash/PSRAM、GPIO制約を認定する。

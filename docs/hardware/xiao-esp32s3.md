# Seeed Studio XIAO ESP32-S3

確認：2026-09-17。標準版を基準にし、Sense/Plusは別board profileとする。

## 1. 公式リンク

- [Seeed Getting Started・比較・Pin Map](https://wiki.seeedstudio.com/xiao_esp32s3_getting_started/)
- [Seeed公開回路図](https://files.seeedstudio.com/wiki/SeeedStudio-XIAO-ESP32S3/new-res/202003751_XIAO%20ESP32S3_v1.4_SCH_260226.pdf.pdf)
- [ESP32-S3データシート](https://documentation.espressif.com/esp32-s3_datasheet_en.html)
- [ESP-IDF S3 ESP-NOW](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/network/esp_now.html)
- [S3 Sleep](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/system/sleep_modes.html)

## 2. 構成とvariant

標準版はESP32-S3R8、Xtensa LX7二核最大240MHz、8MB Flash＋8MB PSRAM。SoC内蔵SRAMと外部／package PSRAMは別。2.4GHz Wi-Fi/BLE、USB-C、外部U.FLアンテナ、21×17.8mm級。

Senseのcamera/microphone/microSD拡張やPlusの追加pin・Flash容量を標準版へ混ぜない。RouteLoomの基準boardは標準版。Senseの周辺やSX1262はpinと電力の競合検証が別途必要。

## 3. Pin Map

| 端子 | GPIO | 基準用途 |
|---|---:|---|
| D0 | 1 | ADC/GPIO |
| D1 | 2 | ADC/GPIO |
| D2 | 3 | ADC/GPIO、strap注意 |
| D3 | 4 | ADC/GPIO |
| D4 | 5 | SDA |
| D5 | 6 | SCL |
| D6 | 43 | UART TX |
| D7 | 44 | UART RX |
| D8 | 7 | SCK |
| D9 | 8 | MISO |
| D10 | 9 | MOSI |

USB D−/D＋はGPIO19/20。BOOTはGPIO0、標準USER LEDはGPIO21（Low点灯）。strap関連GPIO0/3/45/46に外部強制レベルを与える前にSoC資料を確認する。

B2B/padのD11=GPIO42、D12=GPIO41等は11本のedge端子と別。Wiki表のAnalog表記を根拠にGPIO41/42へADCを期待しない。camera/PDM/SPI用途と共有する。GPIOのmatrix機能と電源domain・ADC対応は別に検査する。

## 4. B2Bと拡張

標準boardには30pin B2Bがあり、SPI、GPIO38〜42、追加camera用信号等を引き出す。Wio-SX1262 B2Bはこれを使用する。コネクタ図は嵌合面／基板面で左右が変わるため、pin番号の見た目だけで配線を決めない。

SPI GPIO7/8/9とGPIO38〜42等の周辺割当がぶつかる構成を同時に有効化しない。Sense拡張とLoRa拡張を機械的に積めることは電気的共存の証明ではない。

## 5. 電源・省電力

USB5V、公称3.7V Li-ion/LiPo系のBAT、4.2V充電終止系を区別する。公開回路図ではSGM6029電源とSGM40567-4.2充電系、約110mAの充電設定注記がある。kit説明の100mAは別の公称記述なので、充電安全設計は実物revisionで確認する。

Wikiの標準版Deep Sleep約14µAは条件付き参考値。Sense拡張付き、LED点灯、USB、PSRAM設定、外部moduleでは変わる。無線報告1回のエネルギーを実battery-sideで測る。

## 6. 資料revisionの注意

リンク先PDFのファイル名はv1.4、内部title blockはRev V1.3／2026-02-10、sheetファイル名にはV1.5の文字がある。これだけで販売品のrevisionを断定しない。board写真の刻印・BOM・導通を記録し、同じファイル名でもhashを保存する。

## 7. RouteLoom受入

通常LRとUSBを同時に使う構成、PSRAMに依存しないhot path、deep sleep→peer復帰、GPIO起床、USER LED消灯、Flash/PSRAM初期化失敗を試験する。メモリ容量が多いこととRF到達性がC3より良いことは別。

[Wio-SX1262併用](xiao-esp32s3-wio-sx1262.md)／[共通注意](power-rf-compliance.md)

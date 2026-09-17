# Seeed Studioボード資料

確認日：2026-09-17。メーカー公開情報を整理したもので、RouteLoomのRF実機認定ではない。標準XIAO、Sense、Plus、B2B kitを混同しない。

| 対象 | CPU | 公開されている主なメモリ | RouteLoom初期利用 |
|---|---|---|---|
| [XIAO ESP32-C3](xiao-esp32c3.md) | RISC-V単核160MHz | 400KB SRAM、4MB Flash | ESP-NOW LR、PSRAM非依存基準 |
| [XIAO ESP32-S3](xiao-esp32s3.md) | Xtensa LX7二核240MHz | 標準版8MB Flash＋8MB PSRAM | ESP-NOW LR |
| [XIAO ESP32-C5](xiao-esp32c5.md) | RISC-V単核240MHz | Wikiは8MB Flash＋8MB PSRAMと記載。現物照合が必要 | 2.4GHz ESP-NOW LRのみ |
| [S3＋Wio-SX1262 B2B](xiao-esp32s3-wio-sx1262.md) | S3に別SX1262を追加 | S3本体に依存 | Wi-Fi側だけ。LoRaは将来 |

値はboardとSoCを分けて扱う。CPUの上限周波数は電池設定で常に使う周波数ではない。最大無線TX出力、最大RF速度、一般的な距離をRouteLoomの性能保証にしない。

## 端子比較

| XIAO端子 | C3 GPIO | S3 GPIO | C5 GPIO |
|---|---:|---:|---:|
| D0 | 2 | 1 | 1 |
| D1 | 3 | 2 | 0 |
| D2 | 4 | 3 | 25 |
| D3 | 5 | 4 | 7 |
| D4 / SDA | 6 | 5 | 23 |
| D5 / SCL | 7 | 6 | 24 |
| D6 / TX | 21 | 43 | 11 |
| D7 / RX | 20 | 44 | 12 |
| D8 / SCK | 8 | 7 | 8 |
| D9 / MISO | 9 | 8 | 9 |
| D10 / MOSI | 10 | 9 | 10 |

同じD番号でも数値GPIOは違う。GPIO電圧は3.3V系で、5V tolerantとして配線しない。USBデータ、flash/PSRAM、boot strap、B2Bが使うGPIOは自由な端子とは扱わない。

## board profileに記録するもの

メーカー型式、購入品の基板revision、SoC型番/リビジョン、実flash容量、実PSRAM容量、端子表、充電IC、regulator、USB方式、アンテナと認証情報、使用中拡張、電源構成、sleep測定条件。

Wikiの値と回路図・現物が違うときは大きい値を選ばない。board profileを未認定にし、BOM・現物・メーカー確認で閉じる。特にC3出力電流、S3の回路図ファイル名と内部revision、C5のPSRAM表記を個別に記録した。

[電源とRFの共通注意](power-rf-compliance.md)／[機械可読な端子資料](../reference/boards.json)／[公式リンク一覧](../references/official-sources.md)

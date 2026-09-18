# RouteLoom

**Adaptive mesh networking SDK for embedded devices.**  
機器の参加、経路修復、配送、省電力、無線調整をアプリケーションから分離する組み込み向け通信SDK。

> **現在は仕様策定段階です。** このリポジトリの文書は実装契約と受入条件を定義します。動作するファームウェア、公開済みC ABI、RF性能や電池寿命の保証を示すものではありません。

## 設計の入口

- [文書一覧・読み順](docs/README.md)
- [全体仕様と責任境界](docs/spec/overview.md)
- [組み込みSDK API](docs/spec/sdk-api.md)
- [無線仕様：ESP-NOW / Wi-Fi LR](docs/spec/radio.md)
- [PC接続サービス・USB・CLI/TUI](docs/spec/host.md)
- [Seeed Studio対応ボード資料](docs/hardware/README.md)
- [実装状況・リリース条件](docs/STATUS.md)

## 初期対象

ESP32-C3 / ESP32-S3 / ESP32-C5、2.4 GHz ESP-NOW、Wi-Fi LR 250/500 kbps。最初の実装基準は固定channel／LR250です。LR500適応、管理HA、自動channel移行等は設計を維持し、別の機能認定を経て有効化します。LoRaは将来拡張であり、現時点の送受信実装には含めません。

組み込み側はESP-IDF / C++とC API、PC側はRustサービスとCLI/TUIを設計対象にします。仕様バージョンとソフトウェアのリリースバージョンは別に管理します。

[レビュー反映と残るゲート](docs/reviews/2026-09-17-response.md)／[実装プロファイル](docs/spec/release-profiles.md)。

## 実装状況

`CORE_FIXED_250`の実装を開始しています。portable C++ core、C ABI、ESP-IDF向けLR250 adapter、実験用AES-GCM Provider、reference firmware、Rust host framing/daemon/CLI、CIを含みます。これは**prototype**であり、Wire互換性・本番Identity Security・RF/HILは未認定です。

- [v0.1実装の内容と非保証](docs/implementation/README.md)
- [現在の成熟度と残るGate](docs/STATUS.md)

## ライセンス

公開時点でライセンスは未選定です。正式なオープンソースリリース前にライセンスと第三者素材の扱いを確定します。文書中の公式資料へのリンクは、その資料の再配布許諾を意味しません。

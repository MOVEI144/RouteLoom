# RouteLoom

**組み込み向け mesh networking SDK。**
機器の参加、経路修復、配送、省電力、無線調整をアプリケーションから分離する組み込み向け通信SDK。

> **SDK 2.0.0-dev（pre-release）です。** portable C++ core・C ABI・ESP-IDF firmware・Rust host は実装済みで、host試験とfirmware buildをCIで継続確認しています。実機試験は進行中で、RF性能・電池寿命・本番security profileはまだ認定していません。最初の正式版はv2.0.0です（[v2の位置付け](docs/STATUS.md)）。

## 利用の入口

- [入門（C/C++・2 台の疎通・host sim）](docs/user/quickstart.md)
- [利用・運用ガイド](docs/user/guide.md)／[API reference と契約 kit](docs/api/README.md)
- [v2 への移行](MIGRATING-v2.md)
- [文書サイトの公開手順](docs/user/pages.md)（有効化は利用者）
- [文書一覧・読み順](docs/README.md)
- [全体仕様と責任境界](docs/spec/overview.md)
- [組み込みSDK API](docs/spec/sdk-api.md)
- [無線仕様：ESP-NOW / Wi-Fi LR](docs/spec/radio.md)
- [PC接続サービス・USB・CLI/TUI](docs/spec/host.md)
- [Seeed Studio対応ボード資料](docs/hardware/README.md)
- [実装状況・リリース条件](docs/STATUS.md)

## 対象

ESP32-C3 / ESP32-C6 / ESP32-S3 / ESP32-C5、2.4 GHz ESP-NOW、Wi-Fi LR 250/500 kbps。C3・C6・S3は実機の回に合格したものを認定とし、C5は実機確認待ちとして出します。最初の実装基準は固定channel／LR250です。LR500適応、管理HA、自動channel移行等は設計を維持し、別の機能認定を経て有効化します。LoRaは将来拡張であり、現時点の送受信実装には含めません。

組み込み側はESP-IDF v6.0.3 / C++とC API、PC側はRustサービスとCLI/TUIです。SDKの版と各面（C ABI、Wire、HostLink、保存形式）の版は[`protocol/manifest.json`](protocol/manifest.json)で管理します。

[レビュー反映と残るゲート](docs/reviews/2026-09-17-response.md)／[実装プロファイル](docs/spec/release-profiles.md)。

## 実装状況

`CORE_FIXED_250`を実装済みです：portable C++ core、core C ABI 3、Device C/C++ API、ESP-IDF向けLR250 adapter、DevRamとSDK v1 MemberEdhoc（ゼロタッチ参加・group鍵・失効）、reference／bridge／bench firmware、Rust host daemon・CLI・Site Authority、Mesh Lab（meshviz）、CI。Wire major 2 と前方互換規則、HostLink v2 の認証を実装しています。sleep 一本化・crypto worker・賢い参加・AppObject は[文書 index](docs/README.md)の pending 表を参照してください。本番security profile・RF・長期HILは未認定です。

- [実装の内容と非保証](docs/implementation/README.md)
- [現在の成熟度と残るGate](docs/STATUS.md)
- [変更履歴](CHANGELOG.md)／[作業規約](AGENTS.md)

## ライセンス

Apache-2.0（[LICENSE](LICENSE)）。第三者素材の帰属は[NOTICE](NOTICE)を参照。脆弱性報告は[SECURITY.md](SECURITY.md)、互換性・版管理ポリシーは[docs/spec/compatibility.md](docs/spec/compatibility.md)を参照。文書中の公式資料へのリンクは、その資料の再配布許諾を意味しません。

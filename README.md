# RouteLoom

ESP-NOW／Wi-Fi LR の mesh SDK。機器の参加、複数 hop の配送、経路修復、省電力をアプリから使えます。
組み込み側は heap を使わない portable C++17 core、C ABI、ESP-IDF Device C/C++ API。PC 側は Rust daemon・CLI/TUI です。

**v2.0 向けの開発版（manifest は 2.0.0-dev）です。** 実装と host 試験・firmware build、実機の資格は別です。
H2／H3／H4 は実施予定で、RF 性能・電池寿命・本番 security は未認定です。[現在の条件と証拠](docs/STATUS.md)を確認してください。

## はじめる

1. [quick start](docs/user/quickstart.md)：host sim → DevRam 2 台 → C/C++ アプリ → MemberEdhoc と daemon。
2. [利用ガイド](docs/user/guide.md)：送信・group・所属・sleep・遠隔設定・AppObject。
3. [運用](docs/user/operations.md)と [Kconfig の選び方](docs/user/configuration.md)：権限・鍵・容量・backup。

旧開発版からは [v1 → v2 移行ガイド](docs/user/migrating-v2.md)。[変更履歴](CHANGELOG.md)、[API reference](docs/api/README.md)、[文書索引](docs/README.md)も参照してください。

## v2 でできること

- 認証済み unicast、Reliable／APPLIED、group／ALL 配送、経路修復。
- MemberEdhoc の参加・失効・再参加、所属と接続の観測、耐久 leave、賢い参加（opt-in）。
- DevRam／Member の保存を伴う sleep、期限と通知による Owner 実行。
- 遠隔設定、Member の署名付き手動 channel plan、指定 gateway 配送。
- AppObject（既定 OFF、最大 4096 B の unicast）。通常 payload の 128 B 上限は変わりません。
- USB HostLink protocol 2、daemon の耐久 operation、API1 の受信・cursor、CLI/TUI と Mesh Lab。

reference／bridge／bench の既定は MemberEdhoc（Candidate）。component と quick start／examples は DevRam（Development）です。
製品は機器 identity と BoardConfig を provision し、USB gateway には個別 HostLink secret を用意します。固定の開発値は試験専用です。
[security ガイド](docs/user/security.md)、[examples](examples/endpoint_cpp/README.md)を参照してください。

## 対象と未完了の範囲

ESP32-S3／C3／C6、2.4 GHz ESP-NOW・固定 channel・Wi-Fi LR250 が入口です。**C5 は build 対応、実機確認待ち**です。
ESP-IDF v6.0.3 を使い、[build cell](tools/ci/cells.json)ごとの role・容量・機能を確認します。
過去の実機結果は構成ごとの記録であり、全 chip・全機能の認定ではありません。

crypto worker（V2-16）、IP gateway、UART coprocessor、メッシュ経由 OTA は v2.1 に回します。
LR500 適応、管理 HA、自動移設、圧縮、LoRa は v2.0 の提供機能に含めません。
人による第三者レビュー #100 は非ブロッキングで追跡します。[リリース条件](docs/STATUS.md)が正本です。

版と番号は [manifest](protocol/manifest.json)、互換の保証範囲は [compatibility](docs/spec/compatibility.md)で管理します。
[配布物の検証と RC 昇格](docs/releases.md)、[Pages 公開](docs/user/pages.md)は maintainer／利用者が行います。

## ライセンス

Apache-2.0（[LICENSE](LICENSE)）。第三者素材は [NOTICE](NOTICE)、脆弱性の非公開報告は [SECURITY.md](SECURITY.md)を参照してください。

# RouteLoom 文書案内

v2.0 向けの利用者入口。現 manifest は **2.0.0-dev**。
ESP32-S3／C3／C6 が対象で、C5 は build 対応・実機確認待ちです。
実装、host 試験、build、実機の資格を分けて読みます。H2／H3／H4 は実施予定です。

## 最初に読む

1. [quick start](user/quickstart.md)：host sim、DevRam 2 台、C/C++、MemberEdhoc と daemon。
2. [利用ガイド](user/guide.md)：配備・所属・送信・group・sleep・AppObject。
3. [security](user/security.md)、[Host 運用](user/operations.md)、[Kconfig の選び方](user/configuration.md)。
4. [v1 → v2 移行](user/migrating-v2.md)、[変更履歴](../CHANGELOG.md)、[状態とリリース条件](STATUS.md)。
5. [API reference](api/README.md)、[Kconfig 全宣言](api/kconfig.md)、[API1 契約 kit](api/api1.md)。

## v2 の機能

| 範囲 | 利用できるもの | 条件・案内 |
|---|---|---|
| Device C/C++ | 起動、所属・接続、参加・leave、送信、group、APPLIED ticket、sleep | [SDK API](spec/sdk-api.md)。別 task は post、callback の再入は Busy |
| security | reference／bridge／bench は MemberEdhoc が既定。開発 examples は DevRam | [security](user/security.md)。Candidate／Development を Production と読まない |
| wire と host | wire v2、C ABI 3、HostLink 2、API1、daemon・CLI/TUI | [互換性](spec/compatibility.md)、[Host 運用](user/operations.md) |
| 賢い参加 | 受信先行・有限探索・最大 3 件の参加予定 mark | opt-in。[所属](spec/identity-membership.md) |
| 大きいデータ | AppObject、認証済み unicast 最大 4096 B | 既定 OFF。[配送](spec/delivery-storage.md)。通常 send は 128 B |
| sleep と期限 | 既存 coordinator に保存・ticket・復元を統一 | [power](spec/power.md)。RTC・電流の実測は H2 |
| 管理 | 遠隔設定、Member の手動 channel plan、指定 gateway | [遠隔管理](spec/remote-management.md)、[channel](spec/channel-migration.md)。実機再受入待ち |
| 配布基盤 | source／host／firmware、SBOM／license／hash／provenance、RC 昇格 | [release](releases.md)。正確な RC の実機再現は H4 |
| examples | [C++](../examples/endpoint_cpp/README.md)、[C](../examples/endpoint_c/README.md)、[standalone](../examples/standalone_gateway/README.md)、[group](../examples/group_send/README.md)、[sleep](../examples/sleep/README.md)、[consumer](../examples/display_consumer/README.md) | DevRam の固定値は試験専用 |

sleep・賢い参加・AppObject・配布基盤は実装済みです。
crypto worker（V2-16）、IP gateway、UART coprocessor、メッシュ OTA（#103／#171）は v2.1。
人による第三者レビュー #100 は非ブロッキングで残します。実機の未合格と未実施は [STATUS](STATUS.md) に集めます。

## 仕様を読む

- [全体仕様](spec/overview.md)、[アーキテクチャ](spec/architecture.md)、[SDK API](spec/sdk-api.md)、[配送と保存](spec/delivery-storage.md)、[host](spec/host.md)。
- [Identity・参加](spec/identity-membership.md)、[security](spec/security.md)、[管理合意](spec/control-plane.md)。
- [無線](spec/radio.md)、[channel 移行](spec/channel-migration.md)、[routing](spec/routing.md)、[sleep](spec/power.md)。
- [wire](spec/wire-protocol.md)、[USB](spec/usb-protocol.md)、[遠隔管理](spec/remote-management.md)、[診断](spec/diagnostics.md)。
- [受入試験](spec/acceptance.md)、[実装 profile](spec/release-profiles.md)、[電源断・期限](spec/crash-time-resources.md)、[資源](spec/resource-profiles.md)、[判断](spec/decisions.md)、[用語](spec/glossary.md)。

## ハードウェアと開発

[ボード一覧](hardware/README.md)、[C3](hardware/xiao-esp32c3.md)、[S3](hardware/xiao-esp32s3.md)、[C6](hardware/xiao-esp32c6.md)、[C5](hardware/xiao-esp32c5.md)、[S3＋Wio-SX1262](hardware/xiao-esp32s3-wio-sx1262.md)、[電源・RF](hardware/power-rf-compliance.md)。

[component 配布](implementation/component-distribution.md)、[HIL runbook](hil.md)、[設計原則](development/design-principles.md)、[コーディング規約](development/coding-standards.md)、[Pages 公開](user/pages.md)。

## 正本と履歴

版と理由番号は [manifest](../protocol/manifest.json)。機械可読な設計値は [radio-defaults](reference/radio-defaults.json)、[boards](reference/boards.json)、[requirements](reference/requirements.json)、[resource profiles](reference/resource-profiles.json)。実効値は source・sdkconfig・capability を確認します。

文書の **目標** と **受入条件** は達成済みの実測値ではありません。公式資料は [参照先](references/official-sources.md)から読みます。
過去の [実装案内](implementation/README.md)、[レビュー](reviews/2026-09-17-response.md)、[自律 mesh Draft](design/autonomous-mesh/README.md)、[host/security Draft](design/host-security-readiness/README.md)、[SDK v1 設計](design/sdk-v1/README.md)は作成時点の記録です。現在の入口と資格は本索引と [STATUS](STATUS.md) を使います。

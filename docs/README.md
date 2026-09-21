# RouteLoom 文書案内

文書基準日：2026-09-17。統合仕様版：1.1。**ソフトウェアのv1.0リリースではない。**

RouteLoomは用途非依存の組み込みMesh SDKである。製品の機器台帳、設備の意味、画面、センサー判定、業務DBは所有しない。

## 読み順

1. [実装案内](implementation/README.md) → [全体仕様](spec/overview.md) → [アーキテクチャ](spec/architecture.md) → [状態とリリース条件](STATUS.md)
2. [SDK API](spec/sdk-api.md) → [配送と保存](spec/delivery-storage.md) → [PCサービス](spec/host.md)
3. [参加とIdentity](spec/identity-membership.md) → [セキュリティ](spec/security.md) → [管理合意](spec/control-plane.md)
4. [無線](spec/radio.md) → [チャンネル移行](spec/channel-migration.md) → [経路](spec/routing.md) → [省電力](spec/power.md)
5. [Wire契約](spec/wire-protocol.md) → [USB契約](spec/usb-protocol.md) → [遠隔管理・更新](spec/remote-management.md)
6. [診断](spec/diagnostics.md) → [受入試験](spec/acceptance.md) → [実装計画](spec/implementation-plan.md)

## ハードウェア

[一覧と比較](hardware/README.md)、[C3](hardware/xiao-esp32c3.md)、[S3](hardware/xiao-esp32s3.md)、[C5](hardware/xiao-esp32c5.md)、[S3＋Wio-SX1262 B2B](hardware/xiao-esp32s3-wio-sx1262.md)、[電源・RF・適合確認](hardware/power-rf-compliance.md)。

## 補助資料

- [判断記録・旧案との差異](spec/decisions.md)
- [互換性・版管理ポリシー](spec/compatibility.md)
- [将来の無線追加](spec/transport-extension.md)
- [用語](spec/glossary.md)
- [公式資料と参照実装](references/official-sources.md)
- [機械可読な初期値](reference/radio-defaults.json)
- [ボードの基礎情報](reference/boards.json)
- [要求と受入の対応](reference/requirements.json)

## 文書の強さ

**必須／禁止**は実装が守る契約、**既定値**は版管理された初期パラメーター、**目標**は実測で評価する性能、**受入ゲート**は機能を有効にしてよい条件である。公式資料からの事実とRouteLoom独自の設計判断を分ける。

文書間で数値・意味が矛盾したら多数決で選ばない。該当機能のリリースを止め、[判断記録](spec/decisions.md)と初期値を同時改訂する。外部リンクのstable/latestは将来変わるので、ビルドは固定commitを記録する。

本書群は全体の実装契約を定義する。暗号Providerの実装選定・golden vector・最終バイト列・実機での機能認定は[STATUS](STATUS.md)の明示的な未完了ゲートであり、文書があることを完了証拠にしない。


## 2026-09-17レビュー反映

[採否と根拠・残る作業](reviews/2026-09-17-response.md)、[実装プロファイル](spec/release-profiles.md)、[電源断・期限・資源](spec/crash-time-resources.md)、[資源予算](spec/resource-profiles.md)、[意味の正本](../protocol/README.md)。Wireの完全凍結と、実装時の必須安全契約を分けた改訂。

## 2026-09-19 自律Mesh拡張の設計Draft

[Issues #3・#4・#5の設計と実装バックログ](design/autonomous-mesh/README.md)：近隣発見、輻輳制御・経路負荷回避、チャンネル調査・協調移行。設計専用パラメーターと40件の未実行受入シナリオを含む。現行runtimeの既定値や実装成熟度を変更するものではない。

## Issue #7〜#12の追加設計（Draft）

[Host連携・容量・本番認証・実機試験計画・APPLIED](design/host-security-readiness/README.md)。既存main、PR #2、実装が進んだPR #6を区別して接続点を設計する。新機能を実装済み・認定済みにするものではない。

## 2026-09-20 Scope・Gateway・Small Config設計Draft

[Issues #14・#16・#17の仕様・実装計画](design/scope-gateway-config/README.md)：Scope filter、指定Gateway/Host受領、認可された小設定更新。Wire/API宣言案、資源計算、失敗状態、設計例と46件の受入ケース（39件はportable/hostで実行済み、7件は実機等の証拠待ち）を含む。**このbranchではEXPERIMENTALのruntime実装済み**（codec・portable core・Host配線・dev profile、opt-in flag/capability付き）だが、dev HMAC/scope keyはproduction identityではなく、COSE検証・実機・資格は未完了。実装状況と証拠の区別は同READMEのmaturity節を読む。

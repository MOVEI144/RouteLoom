# RouteLoom 文書案内

SDK **2.0.0-dev** の利用者向け文書。日本語で説明し、API・Kconfig・method の識別子は English を使う。長距離・多数台・高速の mesh を安定して使うため、台数の容量、実際の配送、security の認定を区別する。

## 利用者の読み順

1. [入門：host sim → 2 台 → C/C++ app → Member と daemon](user/quickstart.md)
2. [利用ガイド：配備・容量・所属・送信・sleep・config・channel](user/guide.md)
3. [security の段階と責任](user/security.md)、[daemon・backup・更新・診断](user/operations.md)
4. [API reference](api/README.md)、[API1 契約 kit](api/api1.md)
5. [v2 移行](../MIGRATING-v2.md)、[変更履歴](../CHANGELOG.md)、[現在の証拠とゲート](STATUS.md)

## main の機能と pending

2026-10-02 の `origin/main`（`4a931258`）を確認。文書の存在や frame 番号の予約は実装・認定の証拠ではない。未マージ機能を入門の必須手順に含めない。

| 範囲 | main での扱い | 追跡先 |
|---|---|---|
| Device C/C++、所属・接続・leave、coalesce、APPLIED ticket | V2-14／V2-17 merged。MemberEdhoc は Candidate、examples は DevRam | [SDK API](spec/sdk-api.md) |
| 製品既定の MemberEdhoc 切替 | **pending：V2-17b／H2**。現 reference／bridge／examples は DevRam | [V2-17 の変更](../changelog.d/v2-17.md) |
| HostLink v2、core C ABI 3、role/profile、Member の remote config／手動 channel | merged。実機の資格は別 | [API reference](api/README.md) |
| 実 Owner mesh harness／Topology／scenarios.json | V2-20a merged。live と planned を区別 | [scenario 一覧](../tests/e2e/scenarios.json) |
| 期限駆動・sleep 一本化 | **pending：V2-15**。既存 power 契約だけを参照 | [power](spec/power.md) |
| crypto worker／Owner 25 ms | **pending：V2-16**。実測の達成を約束しない | [最新 HIL](hil/2026-10-01-stab-fix.md) |
| 賢い参加 | **pending：V2-18**。予定一覧の利用手順は merge 後 | [所属](spec/identity-membership.md) |
| AppObject（大きいデータ） | **pending：V2-19**。通常 payload 上限を維持 | [配送](spec/delivery-storage.md) |
| 表示板の 5 台／3-hop workload | **未合格：K01-D**。DevRam でも warm-up が期限切れ。直接構成の smoke と区別する | [scenario](../tests/e2e/scenarios.json) |
| Member の API1 payload read | **host-tested：K05-M**。full network の ACL／cursor で保存・再読込・epoch 変更を検査。実機は未実施 | [API1 scope](api/api1.md) |
| release 配布物・provenance・本番鍵検査 | **pending：V2-22／H4** | [互換性](spec/compatibility.md) |
| IP gateway／UART coprocessor／自動移設／圧縮 | v2.0 対象外。将来の設計を現在の機能と読まない | [transport](spec/transport-extension.md) |

S3/C3/C6 は各 HIL の合否を記録ごとに確認する。C5 は実機確認待ち。[最新の安定化記録](hil/2026-10-01-stab-fix.md)には復帰・channel 切替の未合格項目がある。Pages 公開は利用者が設定するまで未有効。[公開手順](user/pages.md)参照。

## 読み順

1. [実装案内](implementation/README.md) → [全体仕様](spec/overview.md) → [アーキテクチャ](spec/architecture.md) → [状態とリリース条件](STATUS.md)
2. [SDK API](spec/sdk-api.md) → [配送と保存](spec/delivery-storage.md) → [PCサービス](spec/host.md)
3. [参加とIdentity](spec/identity-membership.md) → [セキュリティ](spec/security.md) → [管理合意](spec/control-plane.md)
4. [無線](spec/radio.md) → [チャンネル移行](spec/channel-migration.md) → [経路](spec/routing.md) → [省電力](spec/power.md)
5. [Wire契約](spec/wire-protocol.md) → [USB契約](spec/usb-protocol.md) → [遠隔管理・更新](spec/remote-management.md)
6. [診断](spec/diagnostics.md) → [受入試験](spec/acceptance.md) → [実装計画](spec/implementation-plan.md)

## ハードウェア

[一覧と比較](hardware/README.md)、[C3](hardware/xiao-esp32c3.md)、[S3](hardware/xiao-esp32s3.md)、[C5](hardware/xiao-esp32c5.md)、[C6](hardware/xiao-esp32c6.md)、[S3＋Wio-SX1262 B2B](hardware/xiao-esp32s3-wio-sx1262.md)、[電源・RF・適合確認](hardware/power-rf-compliance.md)。

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


## 過去の設計・レビュー記録

以下の記録の「このbranch」「未実装」は各文書の作成時点の説明。現在の利用手順と実装状況は上の案内を優先する。

### 2026-09-17レビュー反映

[採否と根拠・残る作業](reviews/2026-09-17-response.md)、[実装プロファイル](spec/release-profiles.md)、[電源断・期限・資源](spec/crash-time-resources.md)、[資源予算](spec/resource-profiles.md)、[意味の正本](../protocol/README.md)。Wireの完全凍結と、実装時の必須安全契約を分けた改訂。

### 2026-09-19 自律Mesh拡張の設計Draft

[Issues #3・#4・#5の設計と実装バックログ](design/autonomous-mesh/README.md)：近隣発見、輻輳制御・経路負荷回避、チャンネル調査・協調移行。設計専用パラメーターと40件の未実行受入シナリオを含む。現行runtimeの既定値や実装成熟度を変更するものではない。

### Issue #7〜#12の追加設計（Draft）

[Host連携・容量・本番認証・実機試験計画・APPLIED](design/host-security-readiness/README.md)。既存main、PR #2、実装が進んだPR #6を区別して接続点を設計する。新機能を実装済み・認定済みにするものではない。

### 2026-09-20 Scope・Gateway・Small Config設計Draft

[Issues #14・#16・#17の仕様・実装計画](design/scope-gateway-config/README.md)：Scope filter、指定Gateway/Host受領、認可された小設定更新。Wire/API宣言案、資源計算、失敗状態、設計例と46件の受入ケース（39件はportable/hostで実行済み、7件は実機等の証拠待ち）を含む。**このbranchではEXPERIMENTALのruntime実装済み**（codec・portable core・Host配線・dev profile、opt-in flag/capability付き）だが、dev HMAC/scope keyはproduction identityではなく、COSE検証・実機・資格は未完了。実装状況と証拠の区別は同READMEのmaturity節を読む。

### 2026-09-23 SDK v1設計Draft（ゼロタッチ参加・機器鍵・削除・#37）

[統合先KGuardの要求とIssue #37の設計](design/sdk-v1/README.md)：事務所では現場非依存のidentityだけを書き、EDHOCでSite Authorityへ参加してKGuardが可否を決める手順、機器鍵からのlink/E2E鍵とnetwork group鍵、失効集合と世代、ピアごとの永続counter/replay recordを不要にするRAM context＋固定slot再開cache、高速再参加、API1/USB/事務所toolingの変更、PR単位の計画。**設計Draftであり、このbranchで実装したのはHKDF-SHA-256（RFC 5869 vector付き）だけ**。

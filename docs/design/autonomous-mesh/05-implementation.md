# 実装バックログ・受入・Draft PRの進め方

状態：設計案。以下のチェックボックスは未実装の仕事であり、設計PRで実施済みにしない。

## 1. 最初の作業

- [ ] PR #2の修正を採用したmainをこのbranchへ取り込む。未マージPRを暗黙に本番基点としない。
- [ ] 読み取り基準 `cdcf0fe33b51854d4b62478e7fbc193cc8c386d8` と差分を確認し、今回のcode mapを更新する。
- [ ] PR #2のfirmware matrixを取り込む。C3/S3/C5それぞれで `reference_node × normal/deep_sleep` と `bridge_node × normal` の計9構成を維持する。独立build dir/sdkconfigでON/OFFを検査し、各artifactへ設定を保存する。この設計branchの現行SDK CIは旧matrixであり、9構成の検証済みとは表示しない。
- [ ] 既存Wire/USB golden vectorと、Sleep保存・Message ID・期限・FD・ledger復旧・USB順序の回帰を再実行する。
- [ ] C3/S3/C5の実装能力とHIL資格を分離し、本番G-SECやライセンスが完了したように表示しない。

設計だけを先にmainへマージする場合もIssue #3〜#5はopenのまま。実装を積む場合は以下を独立コミットにし、設計と実装の変更点をPR本文で追跡する。

## 2. コードへの具体的な接続点

| 現在の場所 | 追加・変更すること |
|---|---|
| `espnow_runtime.hpp/.cpp` | raw RX metadata、callback用read-only分類、broadcast Peer、Peer lease、単一Owner request queue、runtime channel操作 |
| `node.hpp/.cpp` | Neighbor lifecycle入力、typed telemetry、scheduler、BUSY/feedback dispatch、link cost更新、用途別pause |
| `routing.hpp/.cpp` | advertised costを保持したまま再計算、選択時の最新feasibility、selected metricとFD/広告の整合 |
| `admission.hpp`、`types.hpp`、`protocol/semantics.json` | 所属6状態とtype 1〜7を再利用し、coarse allowlistを同期。文脈付きadmissionをRX/TX/proxy/組立完了で共用。Unknown/revokedは既定拒否 |
| `security.hpp`とProvider | NeighborAuthenticator、VerifiedBinding、capability transcript、AuthorityPlan verifier。Production/Developmentを分離 |
| `authority.hpp/.cpp`とNVS adapter | channel operation種別、plan blob hashとの結合、restart時の確定/適用の区別 |
| `power.hpp/.cpp`、`espnow_power.cpp` | bounded discoveryへ接続、authoritative channel復元、活動予算とticket失効、保存ID/期限保持 |
| `wire.hpp/.cpp`、`routeloom-wire` | 通常Wire v1は保持、新control payloadのversionと共通vector |
| `host/routeloom-protocol`、host/CLI/TUI | 同じAPIにneighbor/pressure/channel-plan診断を追加。別のUSB所有者を作らない |
| `firmware/reference_node` | 起動時の静的Peer設定を互換経路として残し、MAC未指定の動作例・認定profileを追加 |
| `tests/cpp`とRust tests | 実装classを使う故障注入、双方向byte stream、single-radio fake、seed固定負荷モデル |

pathは既存 `components/routeloom*` と `host/` の構造を使う。純粋policyを大きいruntime.cppへ埋め込まず、必要に応じ `discovery.hpp/.cpp`, `peer_directory.hpp/.cpp`, `congestion.hpp/.cpp`, `channel_plan.hpp/.cpp` へ分ける。クラスの数を増やすこと自体を目的にしない。

## 3. コミット単位の実装順序

### P0 — 共通契約とテスト土台

- [ ] 有界RawRx、Binding/PeerLease、Observation、有効期限付きoperation結果の型。
- [ ] OwnerのRX/TX/control event順序と、callback overflow/世代の契約。
- [ ] [所属・admission契約](06-membership-admission.md)に従い、MembershipState/NeighborPhaseを別型で所有し、既存helperと意味allowlistの差を解消する。
- [ ] 新payloadのregistryとC++/Rust共有vector。RLD1のkindは既存FrameTypeを再利用し、Member応答、pending確定、fragment再判定、carrier取り違えの負例を含める。既存DATA vector不変を確認。
- [ ] fake clock/storage/entropy/radioを既存testsへ接続。未対応機能はUNSUPPORTED。

### P1 — #3 固定channel上の安全な発見

- [ ] MAC未登録RXのbootstrap lane、LR250 broadcast再登録。
- [ ] 相手別CANDIDATE→AUTH→BIND→双方向確認。自NodeのMember状態は再bindingで変えない。制限付きbootstrap contextでは承認前DATA不可。
- [ ] 認証・承認・commitを別の証拠として扱い、取り消されたtransactionや失効後に遅着したFINISH/ResultでMember/REACHABLEへ昇格しない。
- [ ] dev opt-inの実暗号challengeとProduction Provider境界。
- [ ] static登録互換、binding切替、Peer枠保護、失効、密度backoff。
- [ ] PowerPortのbounded discoveryを本体へ接続。単なるsuccess stubは禁止。

### P2 — #4 キューとbackpressure

- [ ] pool-index scheduler、DRR、予約control、admission rollback。
- [ ] Busy/NeighborResult payloadと受信dispatch。USB creditを流用しない。
- [ ] peer window、BUSY上限、loss/BUSY/予定不在の別会計。
- [ ] 既存DATA/ACKの意味を保持した負荷試験。

### P3 — #4 負荷を考慮した安全な経路変更

- [ ] 集約観測、reference cost、queue penalty、double-count防止。
- [ ] cost変更で広告leaseを延ばさず、選択・FD・広告を同じ状態から生成。
- [ ] 平常hysteresis/重大不通のfast repair、同時switchの分散。
- [ ] 100origin/page/budget/leaseの量的試験と、旧FD反例を含むloop検査。

### P4 — #5 Observeと手動survey

- [ ] 読み取り中心health統計、権限付き短時間survey。
- [ ] PauseMask、時計mapping、不在通知、帰還watchdog、Radio Ownerへの設定依頼。
- [ ] 稼働中set_channel/readback/全Peer LR再適用。アプリから直接set_channelさせない。
- [ ] 保護対象graphとfreshness。plannerメモリ不足なら部分結果をPASSにしない。

### P5 — #5 Manual migrationとrecovery

- [ ] 正当なplan証拠、hash-addressed blob、Authority ledger結合、復旧時の状態表。
- [ ] PREPARE/READY/COMMIT、cutover、VERIFY、helper/scoutと署名snapshot配布。
- [ ] Sleep端末の世代飛ばし、legacy遮断、callback遅着、全store境界cutを試験。
- [ ] rollback新epoch、Authority停止時の既存計画継続・新計画停止。

### P6 — AutoGuardedとSDK利用体験

- [ ] AutoGuardedのpreconditionsを一つのvalidatorで返す。なぜ拒否したかを説明可能にする。
- [ ] Host/CLI/TUIに同じoperation stateと観測証拠を表示。
- [ ] 固定250 baselineとの差分で、成功率・遅延・送信回数・電力proxy・資源を評価。
- [ ] C3/S3/C5のdiscovery/congestion/migration enabled buildを別matrixにする。
- [ ] 実機認定前の実効feature enableは明示EXPERIMENTAL。自動でqualifiedにしない。

## 4. required tests

[scenarios.json](scenarios.json)はD3/D4/D5/Xの47シナリオ。全項目は `planned_not_run`。実装テストはこのIDを結果へ含める。

portable testsでは「mockしたsuccess callbackを受けた」だけでなく、実装codec、実装RouteTable、実装Owner制御、実装storeを結んだ検証を行う。property testのseed、失敗trace、モデルが仮定したloss/clock/容量を保存する。

single-radio fakeは訪問中homeのpacketを受け取れない。callback結果は遅着/欠落/重複可能、未認証frameや時刻不明も投入する。実機のCCAやcapture効果まで再現したと主張しない。

## 5. 負荷・資源の受入

通常負荷：30/50/100node、各40DATA/時＋30分heartbeat、64Bと128B、平均1/3/5hopを別計測。burstは100node同時1件、transit集中、複数origin、最大10hopを別ケースにする。

成功率の分母に拒否・期限切れ・結果不明を含める。RF損失と自発的入場拒否は別内訳。平均遅延だけでなくP95/P99、hotspotのqueue、Peer枠、route切替回数を報告する。

発見100応答者のslot単独成功を単純モデルで検算するなら `n*(1-1/s)^(n-1)`。これはCSMA/hidden-terminalの物理simulatorではなく、固定slotだけで到達を保証できないことの検査に使う。

LR250でbody248Bの単純直列化は、body外を43Bとする仮定なら9.312ms。preamble/MAC ACK/CCA/retryは別。このため10ms応答slotを衝突しない予約や実PHY完了時間と呼ばない。

plannerは必要なcurrent/candidate/recoveryの疎グラフ最大300edgeを初期上限にし、24KiB追加予算内へ収める設計対象とする。全100node×32neighborを無条件保持しない。上限超過時に重要edgeを捨てて成功判定しない。大きいprofileか外部Plannerを要求する。

## 6. 実装公開とIssueの完了条件

| Issue | ソフトウェア完了の証拠 | 別に残す実機資格 |
|---|---|---|
| #3 | 未登録MAC→認証→近隣利用の実経路、Core/Runtime/Power接続、D3全合格 | C3/S3/C5方向別RF、dense discovery、交換・Sleep |
| #4 | FIFO置換とBusy受信/送信、最新FD維持、D4負荷・再送試験 | hidden terminal、実Airtime、都市部混雑 |
| #5 | runtime切替、plan store/証拠、復旧loop、D5全合格、設定別build | single-radio切替時間、clock、COMMIT損失、実干渉 |

単なるenum/API/type追加やMarkdownのみではIssueをcloseしない。実装完了時は実code差分、CI run、機能別artifactをPRへ紐付ける。Draft解除前に未実装stubを一覧にし、残る本番G-SECやHILをコード未完了と混同しない。

## 7. 設計として残す最小の確認事項

未完了を曖昧な『後で最適化』にしない。実装開始時に固定するのは新control payloadの正規byte列とvector、profile固有のSecurity Provider。実測で置き換えるのはprobe/切替時間・queue閾値・RAM予算・helper転送bound。

routingのfeasibility、安全counter、元のMessage ID/期限、Authority証拠、受理前資源予約は実測待ちを理由に省略できない。

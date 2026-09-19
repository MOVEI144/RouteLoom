# 共通設計 — 所有権・API・資源・互換性

状態：設計案。参照コードのSHAと外部根拠は[sources](sources.md)。ここで示す新しい型・関数は追加実装の契約案であり、既存APIとして使用できるものではない。

## 1. コードを読んで確認した出発点

PR #2の参照SHAでは `EspNowRuntime::enqueue_rx()` が未登録MACからのframeを破棄（早期return）し、受信metadataはRSSI中心である。`register_neighbor()` はNodeIdとMACを登録し、Coreの近隣へ追加する。`initialize_wifi()` は起動時channelを設定し、実行中の切替APIはない。

`MeshNode` はFIFO `FixedQueue<TxJob,32>`、awaiting-hop 8件、delivery 8件を持つ。`FrameType::Busy` の番号はあるが受信dispatchでは未処理。Issue #4のcreditという表現と、実装済みUSB creditを区別する。**USB累積creditがあることを無線hopの輻輳制御実装済みとは扱わない。**

`RouteCandidate::advertised` と選択時のfeasibility再評価は修正後コードにある。これを負荷分散のために迂回しない。`EspNowPowerPort::start_discovery()` は明示UNSUPPORTEDであり、#3で接続する対象になる。

## 2. 構成と責任

```text
アプリ／Host API：用途、配送条件、権限、電力・停止許可
                          │
                 AutonomyPolicy
                          │
          ┌───────────────┼────────────────┐
      NeighborDiscovery   CongestionPolicy   ChannelCoordinator
      候補を探し確認       送信量・費用      計画・調査・回復
          │               │                 │
          └─────── MeshNode / RadioOwner ──┘
                   既存Core・唯一の無線実行者
                          │
                   ESP-NOW Adapter
```

三機能のために三つの無線taskや三つの再送engineを作らない。純粋な状態遷移／判断はportable、driver呼出しは既存runtimeのOwner taskへ集約する。承認はMembership Provider、本人確認はSecurity Provider、管理確定はControlAuthorityの責任。

既存の `MembershipState`（Node×Network）を所属状態の正本として維持する。新しい `NeighborPhase` は相手radioごとの一時的な接続状態で、所属状態を置き換えない。既存 `frame_allowed()` と `protocol/semantics.json` の不一致、型番号1〜7の再利用、追加の文脈付きgateは [所属・admission対応契約](06-membership-admission.md)で規定する。認証・承認が済んでいない新しい相手のために、既存Member自身をDiscoveringへ戻してはならない。

`RadioOwner` は責任名であり、別クラスを増やすこと自体を要件にしない。現在のEspNowRuntimeを明確なowner event loopへ整える方針でよい。

## 3. Ownerへ渡す共通契約

### 3.1 RX

`RawRxEnvelope` はsrc/dstアドレス、radio_id、採取時channel、local_radio_generation、timestamp、rssi値＋valid、lengthと最大250Bを所有する。callback内でNodeIdを決定せず、短いcopyと有界enqueueだけを行う。

既知MAC用laneとbootstrap laneを分離する。callbackが参照するMAC分類表はimmutable snapshotか短いcritical sectionで更新し、Ownerの変更途中を読ませない。既知MACであることも認証済みの証拠ではないためworkerで必ず検証する。

TX完了用予約枠は候補RX floodと別。予約枠喪失なら結果不明へ落ち、次TXの成功と混ぜない。不正RXと「期待peerの認証済み応答」は別counterで扱う。

### 3.2 TX

`TxIntent` はrecipient（VerifiedBindingまたは限定BootstrapAddress）、用途、期限、priority、radio generation、必要なPeer lease、encoded状態を持つ。DATA用APIが任意MACを指定して認証を迂回することは禁止。

Ownerだけが実送信順でlink counterを取得し、sealし、送信する。通常DATAの待ち中に別機能がesp_now_sendを直呼びしない。radio設定変更で待機jobを再評価し、暗号counterは使い回さず、Message ID／round／元期限は保つ。

### 3.3 設定操作

`request_radio_operation(kind, deadline, constraints)` → token → `APPLIED / REJECTED / FAILED / INDETERMINATE`。調査・移行・Sleepを一つのoperation arbiterで排他する。

| 状況 | 継続するもの | 止めるもの |
|---|---|---|
| 通常 | DATA、ACK、少量の観測 | 無制限probe |
| 経路故障 | 局所repairと必要control | 改善試験、新survey |
| survey訪問 | 予定した試験・期限での帰還 | homeでの受信を装うこと |
| 移行準備 | plan配送・必要ACK・認証 | 独立survey、鍵/Identity同時変更 |
| cutover | plan実行と復旧control | 新DATA受付または無線投入 |
| Sleep準備 | drain・保存 | 新しい探索・新しい改善試験 |

通常の `set_draining(true)` はroute/controlも止めるため、そのままchannel準備に流用しない。`PauseReason` と許可traffic maskを設け、移行に必要な制御まで止まるdeadlockを避ける。

## 4. ID・証拠・永続状態

`NodeId` は物理MACではない。`BindingId` は認証された相手・双方radio address・Network・security context・binding generationを結ぶ。`CandidateId` は未認証候補専用で、Coreへ渡さない。

`radio_generation` はローカル設定/callbackの整合性、`channel_epoch` は正式計画、`binding_generation` はアドレスと相手session、`feedback_sequence` は負荷通知、`route generation/sequence` は経路安全性である。どれもnonce counterやMessage IDの代用にしない。

Peer evictionでnonce予約・replay floor・所属を消さない。channel移行でroute feasibility frontierを初期化しない。candidateのRSSIやqueueの履歴は失われても安全なcache、正式planと安全counterは耐電断状態として分離する。

## 5. 公開APIの意味

```text
rl_set_autonomy_policy(policy, expected_revision)
rl_discovery_request(scope, budget)          → operation token
rl_neighbors_snapshot()                    → candidate/verified/availableを区別
rl_congestion_snapshot()                    → 観測窓、分母、原因の確度
rl_channel_survey(request)                  → 部分結果も表現
rl_channel_plan_propose(request)            → 提案受付、まだ切替確定ではない
rl_operation_get(token) / cancel(token)     → 最終証拠を照会
```

既存のsend契約は変更しない。受付時に容量不足なら `WOULD_BLOCK`。受理済みなら期限内で処理し、負荷回避を理由に宛先やMessage IDを変えない。優先度はアプリ指定、protocol用control classはSDK専用。

C structの追記はsize/version方式、既存呼出しの既定値は固定250・静的動作を維持する。Host/CLI/TUIは同じdiagnostic schemaを消費する。TUIがUSBやradioを直接所有しない。

## 6. Wire拡張の方針

PR #2のWire v1はheader88B、アプリpayload128B、二tag32Bで最大248B。新機能のために通常DATA headerや既存type番号を再解釈しない。

- 未所属/未知MACへの局所rendezvousと初期認証は `RLD1` carrierを使う。kindは別の番号体系を作らず、既存 `FrameType` の1/2/3/5/6を再利用する。PROVE/CONFIRM/FINISHは `BootstrapAuth=3` 内の論理phaseである。
- 所属照会/確定は `MembershipQuery=7 / MembershipResult=4` を認証済みのWire v1 bootstrap経路で運び、RLD1で確定させない。全1〜7の役割・carrier・fragment制約は [対応表](06-membership-admission.md)を正本とする。
- `RLD1` は先頭2byteが `RL` と共通。完全なmagic/版でcarrierを一度だけ分類し、通常Wireのopen_link失敗からpublic parserへfallbackしない。
- 認証後は既存type `NeighborProbe=40 / NeighborResult=41 / Busy=20 / TimeSync=23 / ChannelNotice=24 / ControlObject=49 / ObjectChunk=50 / ObjectAck=51` の型番号を維持し、payloadに拡張version/subtypeを置く。
- capability交渉前には新payloadを送り付けない。旧nodeは固定channelの既存Wire動作を維持できるが、移行参加capabilityがなければ自動移行を阻止する。
- 新controlの終端は明示する。link負荷は1hop認証、全体planはAuthorityの暗号学的証拠が必要。
- 大きなplanは最大2048Bの認証済みobjectか署名manifest＋有界chunk。decoderの最大長を無制限に増やさない。

新しいpayload offset/type-subtype registryは実装最初の変更でC++/Rustの共通vectorと一緒に固定する。本設計のschemaは意味と最大長を決めるもので、本番G-SEC完了の代用ではない。

## 7. 小型機器の資源契約

[contracts.json](contracts.json)の値は追加実装用の予算案。既存ResourceProfileの枠を二重に確保するのではなく、置換／共用箇所をlink mapで確認する。

| 資源 | leaf | relay/gatewayの設計上限 |
|---|---:|---:|
| 未確認candidate | 4 | 16 |
| 同時auth handshake | 1 | 1（global） |
| discovery専用RX slots | 4 | 4 |
| 論理neighbor records | 8 | 32 |
| 物理Peer | broadcast1を含む最大20 | broadcast1 + 通常16 + 一時3 |
| スケジューラーflow descriptor | 4 | 32。payloadは既存poolを参照 |
| 生の無制限RF統計 | 禁止 | 集約counter/EWMAのみ |

12KiBをrelayの追加常駐予算、24KiBをplanner-capable profileの追加予算の初期上限とする。**sizeof/heap実測値ではない。** 認証演算scratchとWi-Fi/IDF領域を除外したまま「C3に収まる」と判定しない。

候補グラフ全体・100台の調査履歴は全C3へ複製しない。MigrationPlannerをS3またはPCの明示capabilityへ置ける。C3は局所観測・plan参加・証拠検証を担当する。Planner不在でも既存DATAは継続する。

## 8. 時間・メトリック・失敗の型

`QueueDelayMs`, `DriverServiceUs`, `EstimatedAirtimeUs`, `RouteMetric`, `TxPowerQuarterDbm`等を区別する。driver callbackまでの時間を全て電波占有として計上しない。国設定の値やradio全体の送信上限をpeerごとの能力と混ぜない。

全leaseは受信時の単調時計と上限TTLで扱う。遠端timestampをローカル時刻へ直比較しない。完全電源断で経過不明のworkを新しい期限で復活させない。

主要理由：`DISCOVERY_BUDGET_EXHAUSTED / AUTH_REQUIRED / APPROVAL_REQUIRED / BINDING_CONFLICT / PEER_CAPACITY / CONGESTED / REMOTE_BUSY / NO_FEASIBLE_ALTERNATIVE / SURVEY_REQUIRES_OUTAGE_PERMISSION / LEGACY_PARTICIPANT / CLOCK_UNCERTAIN / PLAN_NOT_COMMITTED / RECOVERY_REQUIRED`。

## 9. 三機能を横断する禁止事項

発見のたびに起動sessionを変えない。BUSYをMAC損失へ数えない。広告metricが変わるたびにFDを消さない。性能悪化一回で全channelを巡回しない。mainのdefaultやqualifiedを設計追加だけで変えない。

一般の自動処理は全てoperation/event/reasonで説明できるようにする。測れていないRSSI、busy率、metric confidenceはunknownのまま扱う。

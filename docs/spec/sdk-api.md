# 組み込みSDK APIの契約

本書はC APIの設計契約である。以下の関数は現時点でインストールして使えるライブラリではない。最終C ABIのheader配置・型layoutは実装時に互換性試験と共に固定する。

実装済みの core C ABI 3（`routeloom/routeloom.h`）は移植と試験のための面で、規則（struct_size／version、`rl_get_capabilities`、`rl_next_deadline`、APPLIED の非同期 ticket、`reason_id`）と layout の golden は [compatibility §4](compatibility.md) を正本とする。所属・sleep・本番の security は core ではなく Device API に置く。以下の表はその Device API を含む設計の契約である。

## 1. 利用モデル

```text
初期化 → ポリシー登録 → 開始
                 │
                 ├ 非同期send → token → 結果event
                 ├ 受信callback → アプリ処理 → app_result
                 ├ 診断snapshot
                 └ sleep_prepare → sleep_enter
```

アプリはradioのchannelや隣接MACを通常指定しない。Node/サービス宛先と期限を指定する。radio直接操作の診断APIは管理権限と明示的な保守モードを必要とし、通常の自動制御と競合させない。

## 2. 主要型

| 型 | 意味 |
|---|---|
| rl_context_t | SDK instanceのopaque handle |
| rl_node_id_t | 機器Identity。MAC/USBポートと別 |
| rl_network_id_t | 所属先 |
| rl_destination_t | NODE / GATEWAY / ANY_GATEWAY / SERVICEと許可集合 |
| rl_send_options_t | deadline、配送クラス、優先度、保存方針、failover可否 |
| rl_token_t | 同一SDK session内の非同期仕事識別子 |
| rl_message_id_t | 再送・再起動をまたぐ論理message識別子 |
| rl_event_t | 状態変化と結果。版とサイズを持つ |
| rl_capabilities_t | 実装・受入済み機能と資源上限 |
| rl_sleep_ticket_t | state整理後に得る一回限りのsleep許可 |

public structにはstruct_size/versionを置く。整数幅、enum値、reservedの規則を明示し、ポインターをwireへ送らない。文字列は長さを持ちUTF-8を明示する。無制限なJSONをC APIの基本表現にしない。

## 3. Device API（`routeloom::Device`）

ESP-IDF の機器は `components/routeloom_device` の `routeloom::Device` を使う。C からは `routeloom/device.h` の `rl_dev_*`（Device C API 1）を使う。C 版は同じ Device の薄い wrapper で、状態を持たない（下の「Device C API」）。Device は所属・経路・session の写しを持たず、呼出しごとに Owner と MeshNode から読む。持つのは自分の event のための最小の記録（最後に通知した段階と接続状態とその時刻、進行中の操作 1 件）だけである。

呼べるのは Owner task（poll hook と post した job）だけで、他の task は `post()` を使う（8 件、満杯は Busy）。Device の callback（`NodeObserver`、`DeviceObserver`）の中から Device を呼ぶと Busy を返し、何も変えない。

`DeviceConfig::usb` を接続する場合は HostLink secret（`usb_secret`）が必要。未設定（NULL または長さ 0）なら `begin()` は Owner／radio 起動前に InvalidArgument（`USB_SECRET_REQUIRED`）で拒否する。DevRam の Kconfig identity 経路は USB secret を持たないので gateway は BoardConfig と紐づく secret を provision して起動する。

| 関数 | 契約 |
|---|---|
| `send(dst, payload, options, id)` | 受付だけ。結果は `on_delivery` と `delivery(id)`。`options.coalesce_key`（0 以外）は BEST_EFFORT のみ：同じ宛先・同じ key のまだ無線に渡していない仕事を置き換え、古い方は `CANCELLED_SUPERSEDED`（CancelledBeforeTx）で終わる。無線に渡した仕事は置き換えない。RELIABLE・APPLIED・sleep 保存との組合せは `InvalidArgument` |
| `send_applied(dst, payload, lease, options, id)` | APPLIED。lease は相手の現在の lease（StaleLease の返事に入る）。payload は 112 B まで |
| `set_applied_sink(sink)`／`complete_applied(ticket, reply)` | 受信側。sink は `AppliedReply::deferred` で判定を後回しにでき、後で `complete_applied` を呼ぶ。同時に開ける ticket は 4 件（`kAppliedTicketMax`）で、5 件目の要求は endpoint を呼ばずに Capacity で拒否する。期限後の完了は Expired、二度目・別の boot・送信元の失効・離脱で取り消した ticket は NotFound で、どちらも適用しない。その間の QUERY には Pending と答える |
| `membership()` | 段階（Unprovisioned／Joining／PendingAuthority／Member／Removed／Recovery／Leaving）、site_id、64 bit の network、NodeId、割当の世代、認められた役割、`since_ms`（同じ boot の単調時計）、boot、最後の変化の理由 ID、進行中の OperationId |
| `connectivity()` | 自現場の gateway に届くか（scope = SiteGateway）。Unknown／Reachable／Degraded／Isolated／Sleeping、`since_ms`、boot、最後の gateway の証拠の時刻、理由 ID。証拠は gateway 本人から直接受けた認証済みの通信と、E2E の検証に通った gateway の message・制御返信・END_RECEIPT（RSSI、表への登録、中継機による経路 lease の更新は数えない）。証拠が 60 s 以内で経路があれば Reachable、それより古いか経路が無ければ Degraded、120 s 無ければ Isolated。所属とは独立で、Isolated でも所属は捨てない。gateway 自身は Reachable。Sleeping は sleep の経路（V2-15）が設定する |
| `request_join(op)` | 未所属：zero-touch の scan の待ちを今終える（避ける一覧は守る）。所属済み：既存の所属を site に再検証させる。結果は `on_operation`（JOINED／JOIN_DENIED／JOIN_PENDING／JOIN_TIMEOUT（60 s）／RECOVERY_REQUIRED）。DevRam は Unsupported |
| `leave(op)` | RLX1 に LocalLeave の意図（schema 2）を書いてから消す。消すのは rlsite・rlrevo・rlres2・受付方針と RAM の session、残すのは本人（RLI1）・rlboot・rlcfg・rlkeys・JoinPolicy。自分から離れたので holdoff も RLV1 も残さない。意図の保存後は戻る前に新規受付と送信を止める。消去の失敗は Recovery と RECOVERY_REQUIRED で通知し、耐久 intent は再起動から再開できる。未送信の仕事は `CANCELLED_LEAVE`、送信済みは Indeterminate で終わる。どの段で電源が切れても次の起動で先へ進めて完了する。完了すると `on_membership(LEFT)` と `on_operation(LEFT)` を出して未所属で再起動する。旧現場への通知はしない（host の台帳は変えない） |
| `set_join_policy(policy, expected_revision, revision)`／`join_policy(policy, revision)` | 下の JoinPolicy。範囲外は InvalidArgument、revision の不一致は Conflict。RLJP1（rlmaint の `j0`）に書いて読み戻してから次の判断に効かせる。再起動と leave の後も残る |
| `bind_sleep(power, cause, elapsed, now)` | firmware は ROUTELOOM_DEEP_SLEEP の構成のみ有効。`mesh()` と同じ MeshNode を持つ caller-owned PowerCoordinator を adoption 後に一度だけ接続する。Owner-aware PowerPort と耐久 PowerStorage／PowerEvents は呼出元が保有し、Device より長く生存させる。未読 slot の RecoveryRequired は接続を解除せず保持する |
| `prepare_sleep(request)`／`sleep_ticket()`／`enter_sleep(ticket)`／`abort_sleep()` | DevRam／Member 共通の二段階 sleep。step が security park と耐久 pending の精算を駆動し、commit／readback と radio quiesce 後に ticket を返す。post／受信待ち／radio 世代変更は entry 前に ticket を無効化する。未接続は Unsupported |
| `wake(cause, elapsed, now)`／`wake_info()` | simulation の in-process wake と ResumeOutcome。実機の再起動では bind_sleep の begin 経路を使う。Member の RTC session image と耐久 pending image の形式は変えない |
| `capabilities()` | 役割、MemberEdhoc か、`security_profile`（DevRam は Development、MemberEdhoc は Candidate）、USB gateway、payload の上限など |

`DeviceObserver` の `on_membership(snapshot, cause)` と `on_connectivity(snapshot)` は、変化ごとに 1 回だけ Owner task で呼ぶ。起動時の最初の状態は変化ではないので通知しない。JoinPolicy の孤立の通知時間を過ぎて Isolated が続くと、理由 ISOLATION_NOTICE で `on_connectivity` を 1 回出す（自動では離脱しない）。受信の `DeliveryAssurance` には、送信元の検証結果に加えて、MemberEdhoc では送信元の資格が認める役割（`source_role`）が入る。

### Device C API（`routeloom/device.h`）

C++ の各関数に対応する `rl_dev_*` を置く（`rl_dev_send`、`rl_dev_send_group`、`rl_dev_cancel`、`rl_dev_delivery`、`rl_dev_send_applied`、`rl_dev_complete_applied`、`rl_dev_applied_lease`、`rl_dev_applied_result`、`rl_dev_membership`、`rl_dev_connectivity`、`rl_dev_request_join`、`rl_dev_leave`、`rl_dev_set_join_policy`、`rl_dev_join_policy`、`rl_dev_capabilities`、`rl_dev_node_id`）。規則は C++ と同じで、違うのは次だけである。

- 起動は `rl_dev_start(observer)`：component の Kconfig から Device を Owner task で起動し、handle を返す。image に Device は 1 つで、handle も 1 つ。不正な observer header と二度目の起動は NULL を返し、task を起動しない。
- callback 内の状態取得も `RL_STATUS_BUSY`。`rl_dev_post` と読み取り専用の `rl_dev_node_id` は callback 内でも使える。
- callback は `rl_dev_observer_t`（`on_message`、`on_delivery`、`on_membership`、`on_connectivity`、`on_operation`、`on_applied_request`、`on_poll`）。`on_poll` は Owner の pass ごとに callback の外で呼ぶので、そこから Device を呼べる。
- APPLIED の受信側は常に非同期：`on_applied_request` で ticket を受け、callback の後で `rl_dev_complete_applied` を呼ぶ。`on_applied_request` が NULL なら NoEndpoint で拒否する。
- 他の task からは `rl_dev_post(job, ctx)` だけ（8 件、満杯は `RL_STATUS_BUSY`）。
- 全 struct の先頭に `{struct_size, version}`。version は `RL_DEV_API_VERSION`（1）、struct_size は header の宣言以上でなければ `RL_STATUS_INVALID_ARGUMENT`。大きい struct_size は受けて末尾を無視する。1.x は末尾の追加と関数の追加だけで、layout は `protocol/abi-golden/device-api1.json`（ILP32 と LP64）で固定する。共通の値の型（`rl_message_id_t`、`rl_delivery_result_t`、`rl_applied_*_t`、`rl_group_send_options_t`）は core ABI 3 のものを使い、version は `RL_ABI_VERSION`。
- sleep の C wrapper は V2-17 の対象であり、まだ提供しない。

### JoinPolicy

| 項目 | 既定 | 範囲 |
|---|---|---|
| `avoid_not_here_s`（断られた現場を避ける時間） | 21600（6 h） | 300〜86400 |
| `avoid_blocked_s` | 86400（24 h） | 3600〜604800 |
| `removal_holdoff_s`（撤去の後の holdoff、RLV1 と再起動までの待ち） | 600 | 60〜3600 |
| `retry_max_s`（探索・失敗 backoff と retry_after hint の上限） | 600 | 60〜3600 |
| `isolation_notice_s` | 0（無効） | 0 または 300〜2592000 |
| `start_jitter_ms`（未所属で起動したときの開始の散らし） | 0 | 0〜60000 |
| `role`（名乗る役割の bit、0 は image の既定） | 0 | endpoint／relay、gateway は gateway の image だけ |

既定は方針ができる前の固定値と同じで、既定のままなら挙動は変わらない。有界の backoff と撤去後の holdoff を無効にする値は範囲検査で拒否する。避ける一覧そのものは RAM に置き、再起動で消える。

### 設計のみ（未実装）

| 関数案 | 契約 |
|---|---|
| rl_stop(ctx, deadline) | drainして停止。未完了結果を明示 |
| rl_get_diagnostics(ctx, snapshot) | 実測・推定・不明を含むsnapshot |
| rl_sleep_prepare(ctx, request, ticket) | 通信整理と保存。直ちに眠らない |
| rl_sleep_enter(ctx, ticket) | ticketとapp許可を再確認してsleep |

## 4. 宛先と成功

明示Gatewayの宛先を途中で別Gatewayへ変えない。ANY_GATEWAY/SERVICEは許可集合内でoriginがproviderを固定する。APPLIEDではアプリが結果を返す必要があり、SDK受領だけで自動APPLIEDを出さない。

`Device::gateway()`のendpoint（Descriptor）のleaseは15 s（`kGatewayDescriptorLeaseMs`）。sendのlifetimeは残りのleaseに収まる必要があり、収まらなければ`ENDPOINT_LEASE_TOO_SHORT`で拒否する（黙って短くしない）。lifetimeをleaseの20 %（3 s）以下にすれば、再resolveはleaseの80 %（12 s）を越えてからで足りる。GATEWAY_SDK_RAMの受領はgatewayの有界mailbox（8件）に入り、読まれるか60 sで消えるまで枠を占める。USB gatewayはappを持たないので、hostが未登録のときは新しいresolve／submitを`HOST_UNAVAILABLE`で拒否する。受領したpayloadはhostのReceiveLogへ渡し、保存ACKの後に枠を空ける。既に受領したpayloadはUSB sessionを失っても60 sの保持期限までは再送できる。

sendがOKでもTX受付だけ。最終結果はEND_RECEIVED、APP_APPLIED、EXPIRED、REJECTED、CANCELLED_BEFORE_TX、INDETERMINATE等。遅いreceiptは同じMessage IDへ結び、呼出元が期限後に結果を照会できる保持方針を設ける。

## 5. bufferとthread

成功したsendは入力dataをコピーするため、呼出元は復帰後に解放できる。受付エラーでは仕事は存在しない。受信dataはcallback期間だけ有効で、保持は明示copy/retain。callback中のblocking send、Flash長時間書込み、sleep_enterは禁止。

APIをISRから直接呼ばない。アプリはISRでイベントを積み通常taskから呼ぶ。SDK workerとユーザーcallback executorを分ける。thread-safeとするAPI群、owner-task限定群をheaderに注記する。

## 6. ポリシー

RelayPolicy：許可、中継する時間、最大仕事数、電力予算。
PowerPolicy：ALWAYS_RX / DEEP_SLEEP_REPORT、起床予算、sleep許可callback。
JoinPolicy：§3 の表（Device API で実装済み）。
DeliveryPolicy：deadline、保存、priority、failover を明示。最新値の置換は `SendOptions::coalesce_key`（§3）。
RadioPolicy：認定profile、固定250/適応、survey停止許可、管理権限。

ポリシー変更を途中で受けても新旧snapshotを混ぜない。予定sleepと新DATAが競合したらticketを無効化し、再prepareする。

## 7. Provider interface

Clock（単調時刻と不確かさ）、Entropy、Storage、Security、ControlAuthority、RadioAdapter、EventSink、Approvalを境界にする。既定実装を提供し、アプリ独自Providerは契約検査を通す。秘密key materialをアプリcallbackへ無用に渡さない。

## 8. 互換性とエラー

未対応版はUNSUPPORTED_VERSION、必須未知fieldは拒否、optional fieldは規約に従い無視する。大きいpayloadを勝手に切り詰めずPAYLOAD_TOO_LARGEを返す。

基本理由：NO_ROUTE、AUTH_PENDING、AUTH_REJECTED、REVOKED、PEER_CAPACITY、REMOTE_BUSY、LOCAL_NO_MEM、RX_WINDOW_CLOSED、CLOCK_UNCERTAIN、NO_QUORUM、PLAN_NOT_COMMITTED、PLAN_STALE、PLAN_CONFLICT、RF_PROFILE_UNAPPROVED、DRIVER_RESULT_UNKNOWN、DEADLINE_EXPIRED、UNSUPPORTED。

API正常戻りとイベント意味、memory lifetime、取消race、再起動後照会を受入試験に含める。


## 9. 改訂1.1の必須オプションと拒否

Send optionsにdeadline_policy、max_message_lifetime、保存class、provider_failover（既定false）、必要なidempotency domainを明記する。元のmessage寿命を再送roundや再起動で再付与しない。30秒を超える通常messageは別profileなしでは拒否する。

APPLIEDのprovider変更は、shared idempotency domainまたは明示duplicate-effect許容がない限り拒否。既送信timeoutは未適用の証拠ではなくINDETERMINATEになり得る。[配送と電源断](crash-time-resources.md)。

Entropy Providerにはinitialize、ready、fill、reseed、failureを要求し、READY以外で鍵生成を拒否する。SDKの初期化で秘密を乱数不足のまま仮作成しない。

capabilityは設計予定／実装／認定／有効を別に返す。[feature manifest](../reference/feature-profiles.json)。公開ABIの数値・struct layoutは未凍結。今回のJSONとPython小モデルはC ABIの代替ではない。

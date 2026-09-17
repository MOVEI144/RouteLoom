# 組み込みSDK APIの契約

本書はC APIの設計契約である。以下の関数は現時点でインストールして使えるライブラリではない。最終C ABIのheader配置・型layoutは実装時に互換性試験と共に固定する。

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

public structにはstruct_size/abi_versionを置く。整数幅、enum値、reservedの規則を明示し、ポインターをwireへ送らない。文字列は長さを持ちUTF-8を明示する。無制限なJSONをC APIの基本表現にしない。

## 3. 関数群

| 関数案 | 契約 |
|---|---|
| rl_init(config, providers, out_ctx) | 必須Provider・profile・資源を検査。TX開始しない |
| rl_start(ctx) | 認定済みRF条件と所属から起動。完了はevent |
| rl_stop(ctx, deadline) | drainして停止。未完了結果を明示 |
| rl_send(ctx, dst, data, len, options, out_token) | コピー領域確保後に非同期受付 |
| rl_cancel(ctx, token) | 未送信取消または既送信不明。遠端undoではない |
| rl_get_delivery(ctx, message_id, out) | 保存範囲内の証拠を照会 |
| rl_set_receive_handler(ctx, handler) | 検証済みpayloadだけ通知 |
| rl_report_application_result(ctx, message_id, result) | APPLIED待ちへアプリ結果を返す |
| rl_set_policy(ctx, policy, expected_revision) | capabilityとrevisionを検査し適用結果を通知 |
| rl_get_capabilities(ctx, out) | 未実装／未認定機能をenabledとして返さない |
| rl_get_diagnostics(ctx, snapshot) | 実測・推定・不明を含むsnapshot |
| rl_request_join(ctx, policy) | Discoveryから承認まで。同期ブロックしない |
| rl_leave(ctx, options) | 保留仕事と鍵・所属の扱いを明示 |
| rl_sleep_prepare(ctx, request, ticket) | 通信整理と保存。直ちに眠らない |
| rl_sleep_enter(ctx, ticket) | ticketとapp許可を再確認してsleep |

## 4. 宛先と成功

明示Gatewayの宛先を途中で別Gatewayへ変えない。ANY_GATEWAY/SERVICEは許可集合内でoriginがproviderを固定する。APPLIEDではアプリが結果を返す必要があり、SDK受領だけで自動APPLIEDを出さない。

sendがOKでもTX受付だけ。最終結果はEND_RECEIVED、APP_APPLIED、EXPIRED、REJECTED、CANCELLED_BEFORE_TX、INDETERMINATE等。遅いreceiptは同じMessage IDへ結び、呼出元が期限後に結果を照会できる保持方針を設ける。

## 5. bufferとthread

成功したsendは入力dataをコピーするため、呼出元は復帰後に解放できる。受付エラーでは仕事は存在しない。受信dataはcallback期間だけ有効で、保持は明示copy/retain。callback中のblocking send、Flash長時間書込み、sleep_enterは禁止。

APIをISRから直接呼ばない。アプリはISRでイベントを積み通常taskから呼ぶ。SDK workerとユーザーcallback executorを分ける。thread-safeとするAPI群、owner-task限定群をheaderに注記する。

## 6. ポリシー

RelayPolicy：許可、中継する時間、最大仕事数、電力予算。
PowerPolicy：ALWAYS_RX / DEEP_SLEEP_REPORT、起床予算、sleep許可callback。
JoinPolicy：承認Provider、対象Network制約、探索予算。
DeliveryPolicy：deadline、保存、priority、failover、coalescingを明示。
RadioPolicy：認定profile、固定250/適応、survey停止許可、管理権限。

ポリシー変更を途中で受けても新旧snapshotを混ぜない。予定sleepと新DATAが競合したらticketを無効化し、再prepareする。

## 7. Provider interface

Clock（単調時刻と不確かさ）、Entropy、Storage、Security、ControlAuthority、RadioAdapter、EventSink、Approvalを境界にする。既定実装を提供し、アプリ独自Providerは契約検査を通す。秘密key materialをアプリcallbackへ無用に渡さない。

## 8. 互換性とエラー

未対応版はUNSUPPORTED_VERSION、必須未知fieldは拒否、optional fieldは規約に従い無視する。大きいpayloadを勝手に切り詰めずPAYLOAD_TOO_LARGEを返す。

基本理由：NO_ROUTE、AUTH_PENDING、AUTH_REJECTED、REVOKED、PEER_CAPACITY、REMOTE_BUSY、LOCAL_NO_MEM、RX_WINDOW_CLOSED、CLOCK_UNCERTAIN、NO_QUORUM、PLAN_NOT_COMMITTED、PLAN_STALE、PLAN_CONFLICT、RF_PROFILE_UNAPPROVED、DRIVER_RESULT_UNKNOWN、DEADLINE_EXPIRED、UNSUPPORTED。

API正常戻りとイベント意味、memory lifetime、取消race、再起動後照会を受入試験に含める。

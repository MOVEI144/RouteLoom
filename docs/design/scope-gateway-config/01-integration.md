# 1. 共通契約と接続点

## 1.1 既存の何を使うか

基点は[README](README.md)に固定したSHA。以下は読んだ実装の観測であり、未実装部の完成宣言ではない。

| 既存 | 観測と追加接続 |
|---|---|
| types.hpp | NodeId/NetworkIdはu64。FrameType 1〜7、Service=21、Control=22、ControlObject/Chunk/Ack=49/50/51を再利用 |
| wire.hpp | header88B、通常payload128B、link/end tag各16Bで最大248B。Wire v1はNetwork上位32bitを受け付けない |
| autonomy_wire.hpp | RLD1 header44B＋body最大116B、総160B。flagsは0。object kindはChannelPlan=1/RecoverySnapshot=2 |
| discovery.cpp | DISCOVERはbody空、OFFERは36B/v1。hint照合前のdensity加算をScope導入時に修正する |
| admission.hpp / discovery.hpp | MembershipStateとNeighborPhaseを別軸で維持。Scope検証はAuthenticatedPeerProofを発行しない |
| node.cpp | `send(NodeId,...)`とDATA/EndReceiptの配送。Service/Control専用の終端配送を追加し、通常DATAへの偽装をしない |
| authority.hpp | RemoteConfig操作型と永続SingleAuthorityあり。`bind_operation_payload`は非暗号学的と明記され、正式署名には使えない |
| usb_bridge.cpp / PR #13 Host | 既存一daemon・累積credit・OperationStore・ReceiveLogへ接続。別USB所有daemonは作らない |
| power / radio owner / migration | SleepTicket、drain、単調時刻、maintenance排他を再利用し、直接の並行radio操作を増やさない |

### 現在の型を全部凍結し直さない

既存のC API/enum番号、Wire header、通常Node配送は維持する。本設計の拡張payload番号は新しい設計登録であり、既存runtimeがdecode可能という意味ではない。実装前に先行PRとの差分を再確認し、衝突があれば本設計側を改訂する。

## 1.2 責任と所有権

```text
アプリ / Host client
  ├ Discovery policy → ScopeProvider → NeighborDiscovery → 既存Admission
  ├ Explicit destination → GatewayDelivery → Mesh delivery → GatewayAcceptance
  └ config request → Authority outbox → ConfigCoordinator → ConfigProvider
                                      │
                 Storage / Clock / Security / Radio Owner
```

- ScopeProviderは鍵handle・MAC計算だけを所有する。本人認証/承認は既存Provider。
- GatewayDeliveryは指定終端と結果を所有する。ルーティングは既存のfeasibility条件で選ぶ。
- ConfigCoordinatorは版・認可・保存・applyの順序を所有する。設定の意味は登録されたConfigProvider。
- Owner taskへ有界command/eventを渡す。Wi-Fi callbackでHMAC、Flash commit、JSON、アプリ処理を行わない。
- APIが受理成功を返す前にpayloadと処理枠を確保する。失敗ならtokenは無効で送信義務はない。borrowed bufferはcallback中のみ有効、非同期継続にはcopy/retainを要する。

## 1.3 IDと時間

Node identity、Network、Gateway identity、Host principal、endpoint incarnation、MessageKey、Host OperationId、USB request/session、Authority global sequence、target config revisionは別物。

GatewayIdは初期profileではGateway roleを持つNodeIdそのもの（新しい割当サービスなし）。Host principalはOS入力の任意文字列でなく、USB/機器配備で認証する相手。論理Gatewayの無停止交換は初期対象外で、新機器は新しいNodeIdとして明示的に選び直す。

時間は同じbootの単調時計を基準にする。Host realtime巻戻り、deep sleep、完全電源断は別事象。元deadlineをrenewしない。停止区間が不明ならTIME_UNCERTAIN、未確定の作用はINDETERMINATE。管理の署名時刻だけでローカルの有効性を推測しない。

NetworkIdは署名/MAC文脈で8B全幅を結合する。ただしWire v1へ送る初期profileの値域は1..0xffffffff。上位bitを無言で切り捨てるAPIは禁止。Scopeを知っていてもNetworkへの所属許可にはならない。

## 1.4 Security gate

本番のScopeは標準HMAC、Gatewayは認証済みrole/終端記述、Configは署名済み操作と権限を要する。Scope KeyをDATA鍵・Authority鍵・Node identityへ転用しない。

開発用Providerは明示EXPERIMENTALの隔離profileだけで利用可能。本番ProviderがないときはAUTH_PROFILE_UNAVAILABLE。`bool verified=true`を公開アプリが渡せる構造にはせず、検証器が発行するopaque証拠をCoordinatorが受け取る。

## 1.5 一括予約と公平性

機能ごとの増分予算（未測定）を[数値正本](contracts.json)へ置く。実装は静的容量の構成とsizeof/heap peak試験を伴う。

| 機能 | 増分の基準 |
|---|---|
| Scope | dedup32件・8秒、MAC入力scratch最大256B、現行candidate16/transient3/handshake1は増やさない |
| Gateway | descriptor4、同時delivery8、終端結果32・60秒。Host転送queueも同じ8件分の所有権へ結合 |
| Config target | 同時transaction1、署名object最大1024B、patch最大512B、field16、結果8・最低300秒 |
| Config issuer | 未送信outbox4、全体maintenance1、Targetごとの発行を1分1件・burst1に制限 |

満杯は既存NoCapacity/Busy/WouldBlockと詳細reasonで拒否する。保護中のdedup/commit証拠をLRUで消さない。Gatewayの初期受付も1秒1件・burst8以内とし、60秒保持32件では持続1件/秒を保証しない。認定用基準は**1分20件・burst8、最大同時8**（20＋8＋保留最大4=32）とする。これはこのendpoint結果表の容量profileであり、自網全体のRF上限ではない。

Configの結果保持は1分1件×5分＋実行中1＋余裕1=7件を8枠に収める。新規受付とduplicate照会の予算を分け、duplicateで保持期限を無限延長しない。境界式と実測の双方でprofileを認定する。

## 1.6 変更する場所

新しいportable modules案：`discovery_scope.hpp/.cpp`、`gateway.hpp/.cpp`、`config.hpp/.cpp`、`endpoint_wire.hpp/.cpp`。ESP-IDF adapter案：`psa_scope_provider`、`nvs_config_store`。既存object転送とAuthority storageを再利用し、コピーした第二の実装を作らない。

Hostの追加はPR #13の`api1.rs`、`canonical.rs`、`dispatch.rs`、`receive_log.rs`、`send_store.rs`へ責任別に接続し、巨大なmain.rsへ全て継ぎ足さない。詳細な作業順序は[実装計画](07-implementation.md)。

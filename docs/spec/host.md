# Edge PC接続サービスとクライアントAPI

## 1. 成果物と配置

Rust製routeloom-hostがUSB adapterを所有し、routeloomctlとTUI、利用アプリが同じHost APIへ接続する。PC上のアプリをESP32へ載せる必要はない。ESP32側にはGateway bridge＋通常Mesh SDKをビルドする。

v0.1実装の状況：daemonは`--socket`（既定`/tmp/routeloom.sock`）の行指向Unix socket APIを提供する。USB（HostLink v2）の資格情報は`--hostlink-credentials DIR`（0700のdirectory）で親機ごとの0600の通常ファイル`DIR/<NodeId 16桁hex>.key`（ASCII 1〜63バイト、改行なし）から読む。fileはHelloAckが名乗ったNodeIdで選び、無い・不正なら認証せずHELLOの再試行を待つ。開発profileは`--usb-dev-secret-file PATH`（全親機で1つの鍵、同じfile形式）で、`--hostlink-credentials`とは併用できない。指定したfileが不正なら起動を拒否し、既知の共通鍵に戻さない。どちらも無い時だけ公開の開発用固定鍵を使う（本番認証ではない）。コマンドは`STATUS`／`DIAGNOSTICS`（カウンタJSON）、`SEND <node> <hex>`、`ADAPTER`（機器・session・credit・カウンタ）、`NODES`（観測node一覧）、`DELIVERIES`（配送追跡）、`EVENTS`（有界event ring）、`AUTHORITY`（現状unknown返却）、`AUTONOMY`（EXPERIMENTAL：機器がDiagnostic経由で実際に報告した発見／migration event由来のmode・phase・判定・gate detail。未報告fieldはnull）、`QUIT`。これに加えてAPI1 JSON request面（`API1 <json>`）が§3のmethod一部を実装済み：`capabilities.get`、`capacity.get`（admission profile・store容量・payload/queue上限を実測値で返す、無引数）、`messages.read/submit/subscribe/unsubscribe/subscriptions`、`operations.open_epoch/get/get_by_key/cancel`、`gateway.resolve/get`、`config.challenge/status/propose/get`（EXPERIMENTAL・dev profile。device capability未交渉・ACL不足・未登録はhonest拒否）、`link.get`、`nodes.list/get`（§9）、`group.send/get`（§10、EXPERIMENTAL）、`lab.rollcall.start/update/stop/status`（常時点呼service、EXPERIMENTAL）、`diagnostics.snapshot`（RF snapshotをobserver／peer指定で取得、EXPERIMENTAL）、SDK v1 Site Authorityの`site.status`・`join.policy.get/set`・`join.requests.list`・`join.decide`・`devices.discovered.list`・`members.list/get`・`membership.revoke`・`membership.archive`・`membership.cutover`・`group_keys.status/rotate`・`site.channel_plan.sign/status/offer/release`（§11、EXPERIMENTAL、`--site-authority`指定時）。

admissionは`--admission-profile normal|bench-v1|control`で起動時に選ぶ。`normal`は`messages.submit`と`operations.open_epoch`を2 calls/分・burst 16に制限する既定契約。`bench-v1`は開発site向けに600 calls/分・burst 8へ上げ、呼出側にinflight4・60秒あたり64送信のclient disciplineを要求する（開発siteでだけ起動できる）。`control`は`normal`に最新値の受付laneを足す：`queue_mode:"LATEST_PER_DESTINATION"`の`messages.submit`だけが通常の予算の代わりにこのlaneを使い、宛先（network・種別・id）ごとに12 calls/分・burst 4、principalごとに300 calls/分・burst 32、daemon（site）全体で600 calls/分・burst 32。どれかが尽きると`RATE_LIMITED`（retryable）で、`detail.scope`（`destination`／`principal`／`global`）と`retry_after_ms`を返す。FIFOの送信と`operations.open_epoch`は`normal`と同じ予算のまま——有効profileは`capacity.get`の`admission.profile`が報告し（`control`では`admission.latest`にlaneの上限、他は`null`）、API引数では変更できない。profile変更はstore quota・dedup・firmware上限・RF送出rateを変えない。

`messages.submit`の`options.queue_mode`は`FIFO`（既定）または`LATEST_PER_DESTINATION`。後者は`delivery:"BEST_EFFORT"`かつ`storage:"RAM_ONLY"`でのみ受理され、同principal/network/宛先の未送出recordだけを新規recordへ置き換える（supersede）。外部write境界を越えたrecordは対象外で、`superseded_by`が履歴を残す。表示板の制御など「宛先あたり最新値だけが意味を持つ」用途向けで、表示系は12 msg/分/宛先以上を維持する。

`NODES`は機器がnode_status_v1（[USB §7](usb-protocol.md)）で報告した接続状態・RSSI・直結hop数を返し、報告の無いnodeだけ`unknown`とする。`routeloomctl`は1コマンド接続、`routeloom-tui`は同一JSONをpollして全画面を描画する観測者で、USB deviceは開かない。これは版管理RPC schema（§3）の前段の開発profileであり、authority・承認済みmembership等daemonに情報源が無いfieldは`unknown`として返す。

旧式の`SEND`を追う`DELIVERIES`は、機器の終端`DeliveryEvent`を受け取れない場合、受付から15秒（既定のmesh lifetime 5秒＋USB/event余裕10秒）で非終端状態を`indeterminate`／`DELIVERY_EVENT_TIMEOUT`へ進める。これは配送失敗の証明ではなく、遅れて届いた終端証拠は結果を更新できる。機器が`RESULT_EXPIRED`を返した送信（同じkeyが既に終端し、gatewayが記録を回収した。[USB §5](usb-protocol.md)）は再実行されておらず、成功とも失敗とも言えないため`indeterminate`／`RESULT_EXPIRED`にする。

一つのdaemonが複数USB adapterと複数ネットワークを扱える。adapter、Network、Gateway、host serviceを別の識別子にする。相互転送は明示許可がある場合だけで、v1は異Networkの透過bridgeを提供しない。

## 2. 必須責任

USB検出、機器Identity照合、再接続、protocol/capability照合、送受信credit、pending仕事、配送結果、diagnostic ring、設定と参加承認の受け渡しを担当する。通常のradio経路選択は行わない。

Linux常駐、macOS/Windows開発利用を設計対象にする。USB device path、COM番号、ポート列挙順を永続Identityにしない。同じUIDが二つ現れたら競合として隔離する。

## 3. Host API

初期の操作意味は以下とし、RPC schemaを版管理する。

| 操作 | 意味 |
|---|---|
| adapters.list/watch | 接続機器と能力・session |
| networks.list/get | 所属網とchannel/管理状態 |
| nodes.list/get | Nodeの観測・認証・可用性 |
| messages.send/cancel/get | 非同期配送と証拠 |
| messages.subscribe | 認証済み受信とcursor |
| services.register/renew/remove | host受信先とlease |
| membership.approve/revoke | 権限付き参加操作 |
| config.propose/get | expected revision付き設定 |
| diagnostics.snapshot/watch | 指標と理由付きevent |
| radio.survey/migrate | 正式権限と計画に基づく要求 |
| objects.transfer/status | bounded保守転送 |

API受付のoperation IDと無線Message IDは別に返す。idempotency keyはhost再接続後も指定scope内で有効。操作成功、管理commit、機器へのapplyを別stateで返す。

**capabilities互換方針**。`capabilities.get` の応答文書は版付き（`caps_version`、現在 2。2 は `join.policy` の `decision_mode` の出力値を `"kguard"` から `"external"` に改めた版）で、field・method は additive-only（追加のみ。改名・削除は版上げと仕様更新を伴う）。client は未知の field・method を ignore unknown（無視）し、文書全体の厳密一致で判定しない。版と方針の正本は [mesh-profiles.json](../reference/mesh-profiles.json) の `capabilities`。

**profile 3軸**。security（`DEV_RAM`／`MEMBER_EDHOC`）、routing（`FLAT`／`GATEWAY_SCOPED`）、resource（`leaf-small`／`relay-c3`／`gateway-s3`）。名前・値・成熟度（main／pr／proposal）の契約と根拠への参照は mesh-profiles.json が正本。これは repository の実装・提案状況を表し、接続中の gateway の構成や本番認定（Production 表示）を示さない。現行 capabilities.get は gateway の実効 security profile を広告しない。

**受信記録の assurance**。`messages.read` と購読通知の `assurance` は、session が 0x08 受信保証を交渉済みで DataFromMesh が証拠 tail 付きの時だけ `{"profile":"member_edhoc"|"dev_ram"|"unknown","origin":"verified"|"unverified","site_epoch":u32}` を返す（profile は health の `sec_profile` と同一 registry、`origin` は gateway の open_end 判定、`site_epoch` は配送 header の end_epoch。素性不明な現物は `unknown`・`unverified` と正直に読む）。未交渉 session・legacy 形・group 配送・GATEWAY_INGRESS の記録は従来どおり `{"profile":"UNKNOWN","origin":"unverified"}` を返す。`UNKNOWN` は daemon に本人確認の証拠がないという意味であり、検証失敗を示す値ではない。Site Authority の有無や台帳登録から DevRam／Member を推測せず、Member の security 判定に合格としない。USB 面は[USB §11](usb-protocol.md)。

**診断の正本**。失敗 `reason` は領域ごと（送信結果の `device_outcome`、group の `REFUSED` reason、event ring の `rx_drop` 等）で語彙が異なり、横断の共通 enum は設けない。欠落は `CURSOR_GAP`（cursor 読出し）、購読の in-band `gap` marker（追い出し範囲）、capture の `UncleanEnd`（未完了末尾）を使い分ける。`diagnostics.snapshot` は RF telemetry の on-demand 照会であり、legacy `DIAGNOSTICS`（daemon 内部 counter）とは別物。RF 取得路は telemetry lane、機器状態の購読は `events` stream が正本。

## 4. ローカル接続と認可

既定はローカルIPC（Unix socket／対応するWindows IPC）で、OS権限を用いる。TCPを使う開発構成もloopback限定で認証する。LAN公開、リモート管理、ブラウザアクセスは既定OFF。明示TLS/認証/認可なしで0.0.0.0へbindしない。

WindowsのNamed Pipeは所有者SIDに接続を限定し、remote接続を拒否する。接続元SIDをOSから取得できなければ受け入れない。認可と永続操作・site判定の主体は、Unix UIDとWindows SIDを区別する版付きの識別子で照合・保存する。

権限はread diagnostics、send application data、approve membership、change config、update firmware等を分離する。CLIだから管理者という扱いにしない。秘密鍵exportは標準APIに設けない。

## 5. 接続と再起動

接続時HELLOでUSB protocol version、機器ID、boot session、firmware hash、capabilities、Network、RF状態を取得する。必要な認証とchallengeを行い、新しいUSB sessionを発行する。

旧sessionの結果は新sessionのtokenへ結び付けない。daemon再起動時は安定Message IDを照会し、重複再送しても意味が増えないようにする。受信streamのcursorが巻き戻ったらloss/dup可能性を明示する。

サービス停止はleaseを失効させる。Gateway無線が正常でもservice not availableを表す。明示Gateway宛ての要求を勝手に別PCで受けて完了にしない。

## 6. 保管

RAM／任意の永続spoolを有界にする。message単位で保存方針、容量超過、expiryを定める。指定された永続受理は実store commit後にのみ返す。daemonがACKを返した直後に落ちる試験を行う。

複数クライアントへ通知するとき、一つの遅いsubscriberでUSB受信を停止しない。各subscriberにcursor、有限queue、overflow通知を設ける。TUIは観測者であり、終了してもspoolや通信が停止しない。

## 7. 実装公開前

ここにあるコマンドやservice名は仕様案であり、cargo installで取得できる配布物ではない。package、RPC IDL、OSごとのinstaller、再起動試験をG-SYSTEMで認定する。

[USB](usb-protocol.md)／[CLI・診断](diagnostics.md)／[配送](delivery-storage.md)


## 8. idempotency・受理・client上限

operation identityは `(authenticated principal, Network, operation class, idempotency key)`。同identity異payload hashはCONFLICT。同じ操作の再送は保存済み状態を返し、別Networkや別principalを同じkey文字列で混同しない。hashは意味をcanonical化した要求（宛先・期限方針・保存・権限scope含む）から作る。

初期host保持契約は完了結果24時間（最大4096件／32MiB）、未確定操作は自動再実行せずINDETERMINATEとして保持する。容量不足なら新操作を拒否し、保護中entryを追い出さない。保持を終えた古いkeyの再送を新操作と誤認しないよう、principal単位の受付epochを用いる。expiry前に照会し、epoch終了後の旧keyはIDEMPOTENCY_WINDOW_EXPIRED。新epochでの新操作は明示的な再発行であり自動retryではない。

client初期上限：同時operation8、subscription4、各subscriber queue128eventsかつ256KiB、1event8KiB以下。遅いreaderへcursor gapを通知し、別clientや無線を停止しない。quotaはprincipalとglobal（32clients、8MiB subscriber総量）の両方を検査する。

HostAuthのtranscript／COMMAND保護は[USB](usb-protocol.md)に従う。DATA受領の意味と永続spool commitを分け、requestを記録せず副作用を先に実行しない。

## 9. アプリ向け4操作契約とnode status（EXPERIMENTAL）

組込み先アプリはtransportを知らずに次の4操作だけを使う（group／ALL配送は4操作を変えずに足した任意の操作で§10）。同じ契約をWi-Fi等の別transportも実装できるよう、Rust crate `routeloom-client`がtrait `MeshTransport`として定義し、RouteLoom実装`api1::RouteLoomTransport`はAPI1の薄いclientに留める。

| 操作 | trait | RouteLoom（API1） |
|---|---|---|
| 1. 送信 | `send(dest, payload, &SendOptions) -> SendHandle` | `operations.open_epoch`（初回のみ、cache）＋`messages.submit` |
| 2. 受信 | `receive() -> MessageStream` | `messages.subscribe {stream:"messages", from:"latest"}` |
| 3. 参加／離脱 | `membership() -> MembershipStream`（Joined／Left／LinkChanged） | `messages.subscribe {stream:"events", filter:{kinds:["node_joined","node_left","link_changed"]}}` |
| 4. link状態 | `link_status(node)`／`links()` | `nodes.get`（NOT_FOUNDは`LinkStatus::unknown`＝未接続）／`nodes.list`（`next_after`で全件） |

`SendHandle`は受付（HOST_QUEUED）の証拠で、到達の証拠ではない。`LinkStatus.connected=false`をアプリの「通信なし」表示・表示盤の青帯の唯一の根拠にする。値が無いfieldは`None`/`null`で、0を推測で埋めない。

**情報源**。gatewayがHelloAck bit 2（host_ops_v1）とbit 6を広告すると、daemonのnode status laneが[USB §7](usb-protocol.md)の0x40 pageで全nodeを取得し（初回pageでSUBSCRIBE）、以後0x42 eventを適用し、10秒毎に全件再同期する。`connected`は「gatewayが当該nodeへのfeasible routeを選択している」ことを意味し、gateway自身はUSB sessionが認証済みの間connected（`role:"gateway"`、`hops:0`）。joined／left／link_changedはdaemonが自分の表の遷移から生成するため、機器eventを落としても再同期で必ず1回だけ出る。USB session喪失時は全connected nodeが`node_left{reason:"gateway_lost"}`となる。

**時刻の基準**。API・eventの時刻はすべてhostのUNIX epoch ms（`"clock":"host_unix_ms"`、event ringの`ms`と同一軸）。機器は絶対時刻を送らず経過時間`heard_age_ms`だけを送り、daemonが`last_heard_ms = 受信時刻 − heard_age_ms`を計算する（USB遅延分だけ古めに見える上限値）。`updated_ms`はgatewayが最後に記録を確認した時刻、`changed_ms`は最後のconnected遷移時刻。

**API1**（ACL不要、`link.get`と同じ診断区分。payloadは含まない）：

- `nodes.list` params `{connected?:bool, after?:"16hex", limit?:1..128}` → `{"source":{...},"nodes":[node...],"next_after":"16hex"|null}`
- `nodes.get` params `{node:"16hex"}` → `{"source":{...},"node":node}`、未報告nodeは`NOT_FOUND`（`detail.source`付き、retryable）
- `source`：`{"state":"unavailable|unsupported|syncing|live","gateway":"16hex"|null,"session_id":n|null,"synced_ms":n|null,"tracked":n,"evicted":n,"clock":"host_unix_ms"}`
- `node`：`{"node","role":"peer|gateway","connected","connectivity","listed","neighbor","direct","hops":0|1|null,"next_hop","route_metric","link_cost","rssi_dbm","rssi_avg_dbm","telemetry_stale","last_heard_ms","heard_age_ms","updated_ms","changed_ms"}`。多hopのhop数はroute metricから推測せずnull。`connectivity`はgatewayから見た接続状態で、Device APIと同じ語彙（`reachable`：経路があり本人からの認証済み直接通信またはE2E検証済み受信が60 s以内／証拠が古いか経路が無ければ`degraded`／証拠または経路が120 s無ければ`isolated`／証拠が無い間は`unknown`。中継された経路の登録だけでは到達性を証明しない。期間はhostの単調時計で判定し、表示の壁時計の跳びは判定を変えない）。hostはsleepを知らないので`sleeping`は返さない。`listed:false`（消滅・gateway喪失後）のnodeはlink系fieldがnullで、`last_heard_ms`だけ残る（「最終通信 xx」表示用）。
- event（`stream:"events"`）：`{"seq","ms","kind":"node_joined|node_left|link_changed","node":"16hex","gateway","reason"|"change","status":node}`。reasonは`route_up`／`route_down`／`sync`／`vanished`／`gateway_attached`／`gateway_lost`、changeは`neighbor_up`／`neighbor_down`／`next_hop`。

daemon表は最大512件（機器側は最大160 node）で、溢れたら最も古い未接続記録から追い出す。

**routeloomctlでの例**：

```sh
routeloomctl nodes                                  # 全node（最大128件/page）
routeloomctl nodes --connected false                # 通信なしのnodeだけ
routeloomctl nodes --after 0000000000000080 --limit 64
routeloomctl node-get --node 0000000000000002       # 1台のlink状態
routeloomctl node-events                            # joined/left/link_changedを流し続ける
routeloomctl submit --network 0000000000000007 --epoch <16hex> --to 0000000000000002 --payload 0102
routeloomctl receive --network 0000000000000007 --from latest
```

**Rustからの例**：

```rust
use routeloom_client::{api1::RouteLoomTransport, MeshTransport, MembershipKind, SendOptions};

let mesh = RouteLoomTransport::new("/tmp/routeloom.sock", 0x7);
let handle = mesh.send(0x2, b"unlock", &SendOptions::default())?;
if !mesh.link_status(0x2)?.connected { /* 表示盤を青帯にする */ }
for event in mesh.membership()? {
    let event = event?;
    if event.kind == MembershipKind::Left { /* 管理画面に「通信なし」 */ }
}
```

制約：開発profile（dev PSK）のEXPERIMENTAL機能で、RSSIはgatewayが直接受信したnodeのみ（多hop nodeはnull）、membership承認状態（信頼・失効）はこの面に含まれない。

## 10. group／ALL配送（group_delivery_v1、EXPERIMENTAL）

アプリが1回の呼び出しで全機器（ALL）や機器の群へ同じpayloadを下ろし、何台が受理したかを知るための面。配送そのものはgatewayのportable core（[設計](../design/sdk-v1/group-delivery.md)）が行い、daemonは[USB §8](usb-protocol.md)のHostOps 0x50〜0x52を中継して結果を有界表に保持する。gatewayがHelloAck bit 7（`0x80`）とbit 2（host_ops_v1）の両方を広告し、gateway-scoped profileのroute gatewayである時だけ使える。

**権限の選択**。`group.send`はSEND（`messages.submit`と同じ。多数のnodeへアプリdataを送るので、より弱い権限にはしない）、`group.get`はREAD_OPERATION（`operations.get`と同じ。権限の無いprincipalには存在を明かさず`NOT_FOUND`）。principalはsocket peerのOS credentialだけから決まる（§4）。`messages.submit`の受付token bucket（2件/分・burst 16）は**課金しない**：URGENTのALARMが表示更新のburstの後ろで待たされないため。代わりにgroup表の上限（host待ち8件・未決着16件、超過は`NO_CAPACITY` retryable）、gatewayの送信元表（3件、超過は`REFUSED`／`GROUP_QUEUE_FULL`）、gatewayのgroup air-time bucket（設計§7）で有界にする。group送信には利用者（principal）別の受付上限を**付けない**（#101の決定）：無線の占有は送信元ごとのair-time bucketとsite全体の表の上限で抑え、利用者別の枠は増やさない。

**API1**：

- `group.send` params `{network:"16hex", group:1..65535|"ALL", key:"32hex", payload_hex, payload_len(≤127), options?:{priority:"BULK|NORMAL|MANAGEMENT|URGENT"(既定NORMAL), ordered:bool(既定false), ttl_ms:1..30000(既定5000), hop_limit:1..254(既定10)}, wait_ms?:0..15000}` → group record。`wait_ms`を付けると、gatewayが受理または拒否するまで（最大その時間）待ってから答える。
- `group.get` params `{group_op:"grp"+16hex, wait_ms?:0..15000}` → group record。`wait_ms`を付けると`final:true`になるまで待つ。
- group record：`{"group_op","network","group","all","state","final","result","reason","message":{"session":"8hex","sequence":"16hex"}|null,"gateway","rounds","delivered","nonmember","missing_total","unaccounted","missing":["16hex"...],"missing_truncated","priority","ordered","ttl_ms","hop_limit","payload_len","submitted_ms","admitted_ms","settled_ms","clock":"host_unix_ms"}`。台数・round・`missing`はgatewayが報告するまで`null`（0を推測で埋めない）。`missing`は最大12件で、`missing_total`がそれを超えると`missing_truncated:true`。
- Site Authority稼働時、`group.send.network`は現行Siteの64bit値を受け付け、下位32bit指定も同じSiteとidempotency identityへ正規化する。旧epochの64bit値は新規送信を拒否し、cutover時の未送信分は`NETWORK_CHANGED`で止める。ACLの64bit grantはepochを含めて照合し、下位32bit grantと`*`は従来どおりwire networkに適用する。recordの`network`は正規化後のSite値を返す。
- `state`：`HOST_QUEUED`（daemon受理、未送信）→`DEVICE_PENDING`（0x50送信済み、受理応答待ち）→gatewayの配送状態（`QUEUED`／`WAITING_FOR_END_RECEIPT`等）→終端。終端は`DELIVERED`（既知の全nodeを確認）、`FAILED`（`GROUP_INCOMPLETE`等、未確認idを列挙）、`EXPIRED`、`CANCELLED_BEFORE_TX`、`INDETERMINATE`（gatewayの判定）と、host側の`REFUSED`（何も送信されていない。`result`＝`UNSUPPORTED`／`BUSY`／`INVALID`等、`reason`＝`GROUP_REQUIRES_GATEWAY_SCOPED`／`GROUP_SOURCE_NOT_GATEWAY`／`GROUP_QUEUE_FULL`／`GROUP_CAPABILITY_ABSENT`等）、`NOT_SENT`（機器へ届かなかった：`HOST_DEADLINE`＝ttl内に送れず、`NETWORK_CHANGED`）、`INDETERMINATE`（送られたか分からない：`NO_ADMISSION_REPLY`、`SESSION_LOST_BEFORE_ADMISSION`、`GROUP_RESULT_RECLAIMED`、`NO_FINAL_STATUS`、送出後の`NETWORK_CHANGED`）。**送られたか分からない送信を自動で再送しない**（ALARMの二重送信は再送ではなく別messageになる）。
- event（`stream:"events"`、kind `group_settled`）：recordが終端になった時に**1件だけ**出る。本体はrecordと同じfield（`kind`・`seq`・`ms`付き、設定値fieldは除く）。

**APIエラー**：SEND無し→`AuthorizationFailed`、引数→`INVALID_ARGUMENT`、127B超→`PAYLOAD_TOO_LARGE`、認証済みsessionが無い／別networkのgateway→`GATEWAY_UNAVAILABLE`（retryable、`detail.reason`＝`no_session`／`network_mismatch`。groupはUSB切断を跨いでqueueしない）、gatewayがbit 7（またはbit 2）を広告しない→`UNSUPPORTED`（retryable false、`detail.required_capability:"group_delivery_v1"`、`detail.capability`）、同じkeyで別内容→`CONFLICT`（`detail.existing_group_op`）、追い出し済みkey→`IDEMPOTENCY_WINDOW_EXPIRED`、表満杯→`NO_CAPACITY`。flat profile等でgatewayが拒否した場合はAPIエラーではなく`state:"REFUSED"`のrecord（`wait_ms`付きならその場で返る）。

**idempotency**：identityは`(principal, network, key)`（§8）。同じidentity・同じ内容の再送は既存recordを返し（gatewayが切断中でも）、内容が違えば`CONFLICT`。保持はRAMのみ：record最大256件（終端済みを古い順に追い出す）、追い出したidentityは1024件まで墓標として覚え、その再送は新しい送信ではなく`IDEMPOTENCY_WINDOW_EXPIRED`になる。daemon再起動で全て失う（op tokenはdaemon起動ごとのtag付きで、再起動前のtokenは別opに解決されない）。

**daemonの動き**：group laneのthreadがqueueの先頭から0x50を送り、同じrequest idの即時0x51で受理／拒否を確定し、受理後はFINAL付き0x51で決着する。FINALはsession単位でgatewayの保持枠も3件なので、未決着の間は2秒ごとに0x52で読み直す（FINALの喪失・USB再接続・push枠不足を吸収）。再接続後は新sessionで直ちに0x52を送る。受理応答が3秒来なければ`NO_ADMISSION_REPLY`、寿命＋30秒でもFINALが無ければ`NO_FINAL_STATUS`で打ち切る。laneのrequest idは専用範囲（上位16bit `0x4752`）で、そのidを持つUSB Error frameもlaneへ戻す。

**membership**：groupへの加入はnode側（firmwareの`set_group_membership`、最大8 group＋ALL）で決まり、USB HostOpsに遠隔設定は無いのでAPI1にも無い（`capabilities.get`の`group.membership_set:false`）。送信元は誰がmemberかを事前に知らず、結果の台数で知る。

`capabilities.get`は`methods`に`group.send`/`group.get`、`group:{dispatch:"usb_group_delivery_v1", gateway_capable:true|false|null, payload_max_bytes:127, priority[...], ttl_ms{...}, hop_limit{...}, records_max:256, queue_max:8, unsettled_max:16, memberships_per_node:8, membership_set:false, events:["group_settled"], storage_durable:false}`を返す（`gateway_capable`は認証済みsessionが無ければnull）。

**アプリ向け（`routeloom-client`）**：4操作契約（§9）は変えず、任意の5番目として`MeshTransport::send_group(group, payload, &GroupSendOptions) -> GroupHandle`と`group_result(id, wait_ms) -> GroupResult`を追加した。group配送を持たないtransportは既定実装で`Rejected{code:"UNSUPPORTED"}`を返すので、既存の実装はそのままcompileし振る舞いも変わらない。RouteLoom実装は`group.send`（新しいkeyを生成、I/O失敗時は同じkeyで1回だけ再試行＝replay）と`group.get`の薄いclient。gatewayが送信前に拒否した場合は`Rejected{code:<reason>}`（`GROUP_QUEUE_FULL`だけretryable）。

```rust
use routeloom_client::{api1::RouteLoomTransport, GroupSendOptions, GroupState, MeshTransport, GROUP_ALL};

let mesh = RouteLoomTransport::new("/tmp/routeloom.sock", 0x7);
let alarm = mesh.send_group(GROUP_ALL, b"PUMP3 OVERTEMP", &GroupSendOptions::alarm())?;
let result = mesh.group_result(&alarm.id, 15_000)?; // FINALまで最大15秒待つ
if result.state != GroupState::Delivered { /* result.missing に未確認の板 */ }
mesh.send_group(7, b"MODE:2F", &GroupSendOptions::ordered_update())?; // 2階の板の群へ順序付き
```

```sh
routeloomctl group-send --network 0000000000000007 --group ALL --priority URGENT --payload 50554d5033204f56455254454d50 --wait-ms 2000
routeloomctl group-send --network 0000000000000007 --group 7 --ordered --payload 4d4f44453a3246
routeloomctl group-get --id grp00000001000000a1 --wait-ms 15000
```

制約：開発profileのEXPERIMENTAL機能。host試験（lane状態機械・API1・USB golden byte一致・daemon配線）のみで、実機のbridge_nodeとの疎通・実RFは未確認。表・墓標・結果はRAMのみ。

## 11. Site Authority（SDK v1ゼロタッチ参加、EXPERIMENTAL）

現場PCのdaemonがSDK v1のSite Authority（[設計07](../design/sdk-v1/07-host-api-tooling.md)、[02 §8](../design/sdk-v1/02-zero-touch-join.md)）を兼ねる。SAKはESP32に置かない。参加する機器とEDHOC（RFC 9528 method 0、suite 2）を直接行い、身元（DevCert）を検証してからアプリ（外部の判断者、`decision_mode:"external"`）に参加可否を聞き、答えをMemberCert・SitePackage・RemovalNoticeとして暗号的に執行する。

**開発 site 作成**：`routeloomctl lab-site-init --spec FILE --out DIR`（spec format `routeloom-lab-site-spec-v1`、16桁hex `site_id`/`device_ca_id`/`site_ca_id`、8桁hex `network_low32`、`channel` 1..14、`gateways` 16桁hex 1..4件）。空の DIR のみ許可し、site ごとの CA・SAK・USB secret を別鍵として保存する。鍵・manifest・inventory.db は所有者だけが読み書きできる。既存の完了済み DIR は上書きせず、同じ spec の作成途中 DIR は private journal に記録した鍵を再読込して再開する。manifest 公開直後の中断は同じ内容を検証して完了記録を補う。記録済み鍵の欠損・不一致は拒否する。provision receipt を `provision-confirm-written` で ledger に記録した後、発行済み `devcert.cwt` が ledger の出力先に残り、当該 site の Device CA 署名・NodeId・kid・serial・digest が一致するときだけ `lab-inventory-import --site DIR --ledger FILE --node <16hex> --role endpoint|relay|gateway` で追加する。import site への自動承認は許さない。

**起動**：`routeloom-host --site-authority DIR`。`DIR/site-authority.json`（`routeloom-site-authority-v1`：SiteCert、任意でSite CA公開鍵、Device CA id・公開鍵、channel、channel_epoch、gateway 1〜4台）、`DIR/sak.key`（`routeloom-root-key-v1`、0600、root_id＝site_id。開発用custodyで本番のHSM/TPMではない）、`DIR/site.db`（初回に0600で作成）。SAKとSiteCertの鍵・site_idが一致しない、別の現場の台帳、hash chainの破損はいずれも起動エラー。指定しなければSite Authorityは無く、各methodは`SITE_AUTHORITY_UNAVAILABLE`。

**権限**：ACL file（§4）の新しいgrant `MEMBERSHIP_READ`（一覧・状態・event）、`MEMBERSHIP_DECIDE`（`join.decide`、`membership.revoke`）、`MEMBERSHIP_ADMIN`（`join.policy.*`）を、SiteCertのnetwork下位32bit（またはワイルドカード`*`）に対して与える。既存のSEND等からは導かれない。

**API1**：

- `site.status` → 現場の識別（site_id、network、site_epoch、SAK fingerprint）、rs_epoch、gk_epoch／staged、member・removed・未確認・発見済み・参加要求の数、policy、counters、`usb{configured,attached,join_relay:"ready|not_ready"}`
- `join.policy.get` / `join.policy.set {zero_touch_open?, decision_mode?:"external|closed|lab_inventory", decision_timeout_ms?:500..5000, pending_retry_after_s?:30..3600}`。`lab_inventory` は `lab-site-init` 由来の development manifest・DB binding を持つ site だけに設定できる。閉鎖時は新規参加を pending にする。DevCert と JoinRequest の認証後、当該 site の written receipt を `lab-inventory-import` した (NodeId,kid,role,Device CA) だけ通常の `join.decide` で allow する。daemon 再起動で新 revision を読込む。`decision_mode=lab_inventory` を明示設定したときから単調時計で最大1時間だけ enrollment を開き、失効・時計逆行・daemon 再起動時は pending（同じ値を明示再設定して再開）。DB書込み失敗時は再起動して DB を読み直すまで自動 enrollment を閉じる。`join.policy.get` の `lab_enrollment_active` が実効状態を示す。import/production site では設定を拒否する。`external`（既定）は `join.request` を出してアプリの判断を待つ。v1 の入力値 `"kguard"` は `"external"` の非推奨の別名として受け付け（daemon と `routeloomctl` は警告を出す）、応答・読出しは常に `"external"`。SQLite の保存値（0）は変わらない。内容が変わる set は `policy_generation` を上げ、Relay／Gateway の役割を持つ member（proxy）へ authority envelope 型 9 の ProxyPolicySet（世代と `zero_touch_open`）を、ACK（保存済みの世代）が返るまで5秒ごとに送る（channel が無ければ Wake で起こす）。閉じた proxy は未所属の機器の ZeroTouch DISCOVER に OFFER を返さない（この現場を優先する所属済みの機器の再参加・撤去通知・cutover の救済は止めない）。lease は無く、offline の proxy は最後に適用した方針を保ち、接続が戻れば再送される。ACK は site store の `policy_acks` に残る。`join.policy.get` と `site.status` の `policy` は `radio_distributed_generation`（ACK 済みの proxy の最小の世代、未 ACK なら null）と `radio_distribution {proxies, applied, pending, unknown}`（現世代を ACK した／送ったが未 ACK／channel 無し）を返す。
- `join.requests.list` → `requests[]`（`join_request_id`＝`jr-`＋16hex、device・kid・model・hw_rev・cert_serial・fw_version・capability・requested_role・previously_removed・kid_conflict・via・attempt・remaining_ms・`state:"awaiting|decided"`、≤256）
- `join.decide {join_request_id, device_id, verdict:"allow"|"pending"|"deny", role|retry_after_s|reason, idempotency_key}` → allowは台帳commit後に`{"state":"committed","generation","member_cert_serial","operation_id","applied"}`、pending/denyは`"state":"recorded"`。`applied`は待っている試行へ届いた（`current_attempt`）か次の試行で効く（`next_attempt`）か
- `devices.discovered.list {after?, limit?:1..128}` → `devices[]`、`next_after`、`total`（≤1024、last_seenのLRU）。検証に失敗した機器は載らない
- `members.list {after?, limit?, include_removed?}` / `members.get {device_id}` → generation、role、MemberCert serial、`confirm_state`（`allowed_unconfirmed`／`active`、削除済みはnull）、`delivered`、時刻、削除理由
- `membership.revoke {device_id, expected_generation, reason:"removed|lost|replaced|blocked", idempotency_key}` → `{"operation_id","state":"committed","rs_epoch","gk_rotation":{"from","to","state":"staged"},"distribution":"not_implemented"}`
- `site.channel_plan.status`（READ）→ `{report, last, busy, required}`：gatewayの最新の0x69 report（`age_ms`、phase、active_channel／epoch、ready、released、cooldown_ms、gateway_now_ms、ledger_sequence、offered_plan_hex）と直近の要求の結果。呼ぶたびに新しい読取りを1件queueする。`site.channel_plan.offer {new_channel:1..13, lead_ms?:10000..600000}`（ADMIN、既定30 s）は5 s以内のreportの台帳の先頭・現在のchannel／epoch・gatewayの時計から次のplanを作り、SAKで署名してgatewayへ送る（`dispatched:true`）。reportが古い・plan進行中・cooldown中・要求が進行中は`BUSY`。`site.channel_plan.release`（ADMIN）は5 s以内のgateway reportが示す未解放planのcommitを解放する（daemon再起動後もSTATUSで復元できる）。hostはそのreportが自分の最後にofferしたplanのもので、READYがplan authority以外の全member（`required`、上限8）に揃うまで`NOT_READY`で拒否する。releaseに必須member ID集合を渡し、gatewayも現plan hashのREADYをIDごとに確かめてから解放する。offerを送ると前のplanのreportは捨てる。`site.channel_plan.sign {plan_blob_hex}`（ADMIN）は署名だけで送らない。1件ずつ、RAMだけ（永続の状態はgatewayの台帳）。usb §12
- `operations.get {operation_id:"op-…"}` → approve（`committed`→`delivered`→`confirmed`）／revoke（`committed`、配布は`not_implemented`で全memberを`unknown`と数える）

JSONの例は[07 §2.4](../design/sdk-v1/07-host-api-tooling.md)。idempotencyのidentityは`(principal, idempotency_key)`で、同じkey・同じ内容は保存済みの答え、内容違いは`CONFLICT`。決定済みの要求に別のverdict、`expected_generation`の不一致、kid conflictのallowも`CONFLICT`。台帳・判断のcommitに失敗すれば`STORE_FAILURE`（retryable、そのcommitの状態は変えない）で、成功に変換しない。

発見・発見済み判定・参加要求の終了は、補助記録のstore commit後にRAMへ反映する。発見記録の保存失敗は機器へ`AuthorityBusy`を返す。pending／denyの判定表示を保存できない場合、判断本体が未commitなら`AuthorityBusy`として次の参加試行で再評価し、判断本体がcommit済みならその判断を機器へ届ける（表示記録のRAM／storeは旧状態のまま）。要求の終了を保存できなければRAMとstoreの両方に残し、次の試行または期限切れ処理で終了を再試行する。

**event**（`stream:"events"`、`filter.kinds`で選択）：`join.request`、`join.decided`、`device.discovered`、`member.reissued`、`member.confirmed`、`member.revoked`、`member.readmitted`（失効履歴のあるNodeIdをより大きい世代で再allowし、新しいGKをstageしてRRS1の`readmit_gk_epoch`に記した）、`policy.applied`／`policy.refused`（proxyのProxyPolicySet ACK）、`member.removal_notified`、`rrs.published`、`gk.staged`、`authority.error`、`site.session_drop`、`join_relay_failed`（`source`＋`reason`＋gateway/proxy/relay_id/joiner＋`stage`＋判明分の`device`／`join_request`）。直近の失敗は`site.status`の`recent_relay_failures`（最大16件）でも照会できる。

**参加の中継**：機器のEDHOC messageはproxy→gateway→USB HostOps 0x60/0x61/0x62（[02 §7](../design/sdk-v1/02-zero-touch-join.md)、応答は0x63）でsite laneに届く。laneは認証済みsession＋CAP_JOIN_RELAY_V2（bit 9；bit 8はv1 historyで不受理）のgatewayにだけ中継を開き、phase 4だけSite Authorityへ渡す（phase 5はP3-5未対応として0x62で拒否）。Authorityの応答は有界queue（8件・1件≤1005 B・TTL 20 s）経由で送り（downは0x61、中止はfull token付き0x62のみ）、受付失敗は試行を失敗終了する。ただしphase 7 RRS1の下りが同じrelayのlaneを占有中にfinal EDHOC m4へ返る0x63 Busyは、requestとrelay tokenを照合し、元のTTL内に同一bytesを再送する。結線状態は`capabilities.get`の`site.join_relay:"ready|not_ready"`。

**アプリ向け（`routeloom-client`）**：`site::SiteAdmin` trait（`site_status`、`join_requests`、`decide`、`discovered`、`members`／`member`、`revoke`、`site_events`）をRouteLoomTransportが実装する。`examples/assignment_table.rs`（crateの公開APIではない）は割当表（ここ→allow、他現場→deny not_here、禁止→deny blocked、未知→pending）で未決定の要求に答える最小の判断者で、host試験もこれを使う。

```rust
use routeloom_client::{api1::RouteLoomTransport, site::{Role, SiteAdmin}};
// Assignment / AssignmentTable: examples/assignment_table.rs

let site = RouteLoomTransport::new("/tmp/routeloom.sock", 0x0a1b2c3d);
let table = AssignmentTable::default();
table.assign(0x00a1_0000_0000_1234, Assignment::Here(Role::Endpoint));
for event in site.site_events()? {
    if event?.kind == "join.request" { table.serve_once(&site)?; }
}
```

制約：EXPERIMENTAL（本番Profileではない）。host試験のみで、実機のgateway・proxyとの疎通は無い。GKの配布・更新とauthority channel（JoinConfirm、P5）、RRS1の配布（P6）、site_epoch cutover、SiteCert発行tool（P7-2）は未実装。DAMS・GKはDB fileの0600で守るだけでhost鍵の封緘は無い。

## 12. 機器観測（observation_v1、EXPERIMENTAL）

USB直結gateway自身のread-only snapshotをAPI1で読む面（USB面は[USB §10](usb-protocol.md)）。M2で遠隔観測が開いた：`observer`が直結gateway自身ならlocal USB路（gatewayがHelloAck bit 11＝observation_v1とbit 2を広告する時のみ）、他nodeならgateway転送の遠隔路（gatewayがHelloAck bit 5＝m1 diagnosticsとbit 2を広告する時のみ。現物を欠くbit不足は`UNSUPPORTED`）。遠隔路はpull専用（`subscribe:true`は`INVALID_ARGUMENT`、`max_age_ms`は無視して毎回取得）で、1呼1 section・routes 2件・neighbors 3件までのpage、`outcome:reject`はmesh拒否の素通し。経路・lease・広告の状態は変えない。local USB照会は従来の診断区分、遠隔照会は接続networkのACL `OBSERVE` が必要（diagnostics capabilityだけでは不可）。payload・秘密鍵は含まない。

**API1**：

- `health.get` params `{observer:\"16hex\", section?:\"system\"|\"tables\"|\"milestones\"(既定system), network?:\"16hex\", max_age_ms?:0..60000(既定10000、0は新規取得), subscribe?:bool}` → `{\"outcome\":\"snapshot\",\"scope\":{\"observer\"},\"snapshot\":{...}}`
- `topology.get` params `{observer:\"16hex\", section:\"routes\"|\"neighbors\"|\"summary\", network?, destination?:\"16hex\"(routes/neighbors専用・1宛先/peer), cursor?:\"page token\"(routes/neighbors専用・revision/boot/sessionに束縛、destinationと排他), max_age_ms?, subscribe?}` → 同上。`neighbors`は近隣 snapshot の1 page（peer・heard age・lease残・link cost・phase・RSSI、peer昇順）。
- `snapshot`：`{\"schema\":1,\"section\",\"source\":{\"gateway\",\"usb_session\",\"observer\",\"observer_boot\",\"transport\":\"usb_local\"|\"mesh_remote\"},\"revision\",\"sampled_at_device_ms\",\"sampled_unix_ms_earliest\",\"sampled_unix_ms_latest\",\"received_unix_ms\",\"age_ms\",\"age_uncertainty_ms\",\"stale\":false,\"complete\",\"armed\",\"radio_queries\":0|1, section本体|\"entries\"+\"next_cursor\"}`。`revision`はmilestones＝milestone世代、summary/routes＝route digest、neighbors＝neighbor digest。routesは1呼で1 page（最大8件、`next_cursor`で継続、`complete`が終端）。`next_cursor`は最後のNodeIdとrevision・observer/gateway boot・USB session・observer/sectionを束縛する。継続時にrevisionやbootが変わる、pageが空のまま非終端を主張する、またはentryがcursorより進まなければ`SNAPSHOT_CHANGED`で拒否し、先頭から再取得する。`destination`指定は照会先NodeIdとの一致を検査した`present:true|false`付きの0/1件（未選択は`present:false`）。失効（`valid:false`）entryはretraction identity（generation/sequence）だけを持ち、next_hop・metric・remainingは`null`。`transport`は応答路、`radio_queries`はこの呼のmesh消費（local路は0、遠隔路は新規query 1・共有/拒否cache 0）。
- 遠隔snapshotの`sampled_at_device_ms`はobserverのboot内単調時計で採取した時刻。hostは送信前から受信までの単調時計RTTを転送時間の上限として扱い、`age_ms`を「受信後経過＋RTT」の保守的上限、`age_uncertainty_ms`をRTTとして返す。`sampled_unix_ms_earliest/latest`は受信壁時計時刻からRTTを引いた下限と受信時刻の上限で、機器時計とhost時計を一点に同一視しない。local USBにはdevice採取stampがないため`sampled_at_device_ms:null`、`age_uncertainty_ms:0`。壁時計の逆行でageを減らさない。

- 不明値は`null`（heap不明・未到達のmilestone時刻・未adoptの`adopted_node`）。機器のageは`received_unix_ms`起点の上限値に写像する（node statusの`last_heard_ms`と同じ約束）。`confirmed_at_ms`を含むmilestone時刻はboot内のミリ秒精度で保持し、49日を超えても周回・飽和しない。`system.reset`の`panic`はmask-ROM直読では`software`と読む（IDF hint未使用の既知の限定）。`network`指定がsessionと違えば`GATEWAY_UNAVAILABLE`（`detail.reason:\"network_mismatch\"`）。機器の非Ok結果は`device_result`付きの正直なAPIエラー（`Unsupported`→`UNSUPPORTED`等）。
- event（`stream:\"events\"`、要`subscribe:true`の(再)arm）：`topology.changed`（`mask`・両digest）、`milestone.advanced`（`generation`）、`observation.gap`（`expected`・`received`・`lost`）。(再)armは機器のevent sequenceを1に戻すため、daemonはSUBSCRIBE付きqueryの送信時にwatermarkを再同期する。

**daemonの動き**：observation laneのthreadが0x70を送り（同時最大4件、超過は`NO_CAPACITY`、応答待ち2秒・lane timeout 1.5秒）、同request idの0x71で決着する（laneのrequest idは上位16bit `0x4F42`の専用範囲）。singleton（system/tables/milestones/summary）は`(session, boot)`にpinしたcacheを持ち、`max_age_ms`以内なら再queryしない（0x72のdirty・gap・boot変化で失効）。routes・neighborsはcacheせず毎回queryする。遠隔路は別lane（request id上位`0x524F`）が0x30 subtype 7を送り、0x31 subtype 8／診断拒否で決着する（同時最大4件を受け付けるが、telemetryと共通のdaemon無線予算は2秒に1 transaction・送信済みoutstanding 1。応答待ち6秒・lane timeout 5.5秒）。同一queryの同時呼はin-flight行を共有し（singleflight）、直近のmesh失敗は同一USB sessionに限り陰性cacheから応答して無線を叩かない（Unsupported・timeoutは60秒、その他の拒否は5秒）。内側のmesh相関idはgatewayが振り直すため、hostはUSB request id＋observer/section一致だけで照合する。

`capabilities.get`は`methods`に`health.get`/`topology.get`、`observation:{telemetry,topology,health,board:false,remote,limits:{routes_page_max:8,neighbors_page_max:8,max_in_flight:4,max_age_ms_max:60000,api_wait_ms:2000},events:[\"topology.changed\",\"milestone.advanced\",\"observation.gap\"]}`を返す（可否は接続中のsessionのcapabilityに連動、未接続はfalse。`remote`はm1 diagnostics bitの有無＝遠隔路の可否）。

```sh
routeloomctl health --observer 0000000000000abc --section milestones --subscribe
routeloomctl topology --observer 0000000000000abc --section routes
routeloomctl topology --observer 0000000000000abc --section routes --cursor 0000000000000003
routeloomctl topology --observer 0000000000000abc --section routes --destination 0000000000000009
```

meshvizのAPI1 client（`tools/meshviz/src/routeloom_meshviz/api1_adapter.py`の`encode_health_request`／`encode_topology_request`／`parse_observation_snapshot`）からも同じ契約で取れる（画面変更なし、fixtureは`fake_api1.py`の`observation`引数）。\n\n制約：開発profileのEXPERIMENTAL機能。host試験（lane・API1・daemon配線・固定byte一致）とmeshviz fixtureのみで、実機との疎通・実RFは未確認。

reference field firmwareのread-only consoleは`obs1 health`を受け、同じsystem fillから`OBS1 `接頭辞の1行JSONを返す（512B以内、1秒1応答、単一owner loop）。書込みverbと独立し、機器のboot・uptime・heap・reset・modeをconsole logと照合できる。

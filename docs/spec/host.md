# Edge PC接続サービスとクライアントAPI

## 1. 成果物と配置

Rust製routeloom-hostがUSB adapterを所有し、routeloomctlとTUI、利用アプリが同じHost APIへ接続する。PC上のアプリをESP32へ載せる必要はない。ESP32側にはGateway bridge＋通常Mesh SDKをビルドする。

v0.1実装の状況：daemonは`--socket`（既定`/tmp/routeloom.sock`）の行指向Unix socket APIを提供する。コマンドは`STATUS`／`DIAGNOSTICS`（カウンタJSON）、`SEND <node> <hex>`、`ADAPTER`（機器・session・credit・カウンタ）、`NODES`（観測node一覧）、`DELIVERIES`（配送追跡）、`EVENTS`（有界event ring）、`AUTHORITY`（現状unknown返却）、`AUTONOMY`（EXPERIMENTAL：機器がDiagnostic経由で実際に報告した発見／migration event由来のmode・phase・判定・gate detail。未報告fieldはnull）、`QUIT`。これに加えてAPI1 JSON request面（`API1 <json>`）が§3のmethod一部を実装済み：`capabilities.get`、`messages.read/submit`、`operations.open_epoch/get/get_by_key/cancel`、`gateway.resolve/get`、`config.challenge/status/propose/get`（EXPERIMENTAL・dev profile。device capability未交渉・ACL不足・未登録はhonest拒否）、`link.get`、`nodes.list/get`（§9）、`group.send/get`（§10、EXPERIMENTAL）、`diagnostics.snapshot`（RF snapshotをobserver／peer指定で取得、EXPERIMENTAL）、SDK v1 Site Authorityの`site.status`・`join.policy.get/set`・`join.requests.list`・`join.decide`・`devices.discovered.list`・`members.list/get`・`membership.revoke`（§11、EXPERIMENTAL、`--site-authority`指定時）。`NODES`は機器がnode_status_v1（[USB §7](usb-protocol.md)）で報告した接続状態・RSSI・直結hop数を返し、報告の無いnodeだけ`unknown`とする。`routeloomctl`は1コマンド接続、`routeloom-tui`は同一JSONをpollして全画面を描画する観測者で、USB deviceは開かない。これは版管理RPC schema（§3）の前段の開発profileであり、authority・承認済みmembership等daemonに情報源が無いfieldは`unknown`として返す。

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

## 4. ローカル接続と認可

既定はローカルIPC（Unix socket／対応するWindows IPC）で、OS権限を用いる。TCPを使う開発構成もloopback限定で認証する。LAN公開、リモート管理、ブラウザアクセスは既定OFF。明示TLS/認証/認可なしで0.0.0.0へbindしない。

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

組込み先アプリ（KGuard等）はtransportを知らずに次の4操作だけを使う（group／ALL配送は4操作を変えずに足した任意の操作で§10）。同じ契約をWi-Fi等の別transportも実装できるよう、Rust crate `routeloom-client`がtrait `MeshTransport`として定義し、RouteLoom実装`api1::RouteLoomTransport`はAPI1の薄いclientに留める。

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
- `node`：`{"node","role":"peer|gateway","connected","listed","neighbor","direct","hops":0|1|null,"next_hop","route_metric","link_cost","rssi_dbm","rssi_avg_dbm","telemetry_stale","last_heard_ms","heard_age_ms","updated_ms","changed_ms"}`。多hopのhop数はroute metricから推測せずnull。`listed:false`（消滅・gateway喪失後）のnodeはlink系fieldがnullで、`last_heard_ms`だけ残る（「最終通信 xx」表示用）。
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

KGuardが1回の呼び出しで全表示板（ALL）や板の群へ同じpayloadを下ろし、何台が受理したかを知るための面。配送そのものはgatewayのportable core（[設計](../design/sdk-v1/group-delivery.md)）が行い、daemonは[USB §8](usb-protocol.md)のHostOps 0x50〜0x52を中継して結果を有界表に保持する。gatewayがHelloAck bit 7（`0x80`）とbit 2（host_ops_v1）の両方を広告し、gateway-scoped profileのroute gatewayである時だけ使える。

**権限の選択**。`group.send`はSEND（`messages.submit`と同じ。多数のnodeへアプリdataを送るので、より弱い権限にはしない）、`group.get`はREAD_OPERATION（`operations.get`と同じ。権限の無いprincipalには存在を明かさず`NOT_FOUND`）。principalはsocket peerのOS credentialだけから決まる（§4）。`messages.submit`の受付token bucket（2件/分・burst 16）は**課金しない**：URGENTのALARMが表示更新のburstの後ろで待たされないため。代わりにgroup表の上限（host待ち8件・未決着16件、超過は`NO_CAPACITY` retryable）、gatewayの送信元表（3件、超過は`REFUSED`／`GROUP_QUEUE_FULL`）、gatewayのgroup air-time bucket（設計§7）で有界にする。

**API1**：

- `group.send` params `{network:"16hex", group:1..65535|"ALL", key:"32hex", payload_hex, payload_len(≤127), options?:{priority:"BULK|NORMAL|MANAGEMENT|URGENT"(既定NORMAL), ordered:bool(既定false), ttl_ms:1..30000(既定5000), hop_limit:1..254(既定10)}, wait_ms?:0..15000}` → group record。`wait_ms`を付けると、gatewayが受理または拒否するまで（最大その時間）待ってから答える。
- `group.get` params `{group_op:"grp"+16hex, wait_ms?:0..15000}` → group record。`wait_ms`を付けると`final:true`になるまで待つ。
- group record：`{"group_op","network","group","all","state","final","result","reason","message":{"session":"8hex","sequence":"16hex"}|null,"gateway","rounds","delivered","nonmember","missing_total","unaccounted","missing":["16hex"...],"missing_truncated","priority","ordered","ttl_ms","hop_limit","payload_len","submitted_ms","admitted_ms","settled_ms","clock":"host_unix_ms"}`。台数・round・`missing`はgatewayが報告するまで`null`（0を推測で埋めない）。`missing`は最大12件で、`missing_total`がそれを超えると`missing_truncated:true`。
- `state`：`HOST_QUEUED`（daemon受理、未送信）→`DEVICE_PENDING`（0x50送信済み、受理応答待ち）→gatewayの配送状態（`QUEUED`／`WAITING_FOR_END_RECEIPT`等）→終端。終端は`DELIVERED`（既知の全nodeを確認）、`FAILED`（`GROUP_INCOMPLETE`等、未確認idを列挙）、`EXPIRED`、`CANCELLED_BEFORE_TX`、`INDETERMINATE`（gatewayの判定）と、host側の`REFUSED`（何も送信されていない。`result`＝`UNSUPPORTED`／`BUSY`／`INVALID`等、`reason`＝`GROUP_REQUIRES_GATEWAY_SCOPED`／`GROUP_SOURCE_NOT_GATEWAY`／`GROUP_QUEUE_FULL`／`GROUP_CAPABILITY_ABSENT`等）、`NOT_SENT`（機器へ届かなかった：`HOST_DEADLINE`＝ttl内に送れず、`NETWORK_CHANGED`）、`INDETERMINATE`（送られたか分からない：`NO_ADMISSION_REPLY`、`SESSION_LOST_BEFORE_ADMISSION`、`GROUP_RESULT_RECLAIMED`、`NO_FINAL_STATUS`）。**送られたか分からない送信を自動で再送しない**（ALARMの二重送信は再送ではなく別messageになる）。
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

現場PCのdaemonがSDK v1のSite Authority（[設計07](../design/sdk-v1/07-host-api-tooling.md)、[02 §8](../design/sdk-v1/02-zero-touch-join.md)）を兼ねる。SAKはESP32に置かない。参加する機器とEDHOC（RFC 9528 method 0、suite 2）を直接行い、身元（DevCert）を検証してからKGuardに参加可否を聞き、答えをMemberCert・SitePackage・RemovalNoticeとして暗号的に執行する。

**開発 site 作成**：`routeloomctl lab-site-init --spec FILE --out DIR`（spec format `routeloom-lab-site-spec-v1`、16桁hex `site_id`/`device_ca_id`/`site_ca_id`、8桁hex `network_low32`、`channel` 1..14、`gateways` 16桁hex 1..4件）。空の DIR のみ許可し、site ごとの CA・SAK・USB secret を別鍵として保存する。鍵・manifest・inventory.db は所有者だけが読み書きできる。既存の完了済み DIR は上書きせず、同じ spec の作成途中 DIR は private journal に記録した鍵を再読込して再開する。記録済み鍵の欠損・不一致は拒否する。provision receipt を `provision-confirm-written` で ledger に記録した後だけ `lab-inventory-import --site DIR --ledger FILE --node <16hex> --role endpoint|relay|gateway` で追加する。import site への自動承認は許さない。

**起動**：`routeloom-host --site-authority DIR`。`DIR/site-authority.json`（`routeloom-site-authority-v1`：SiteCert、任意でSite CA公開鍵、Device CA id・公開鍵、channel、channel_epoch、gateway 1〜4台）、`DIR/sak.key`（`routeloom-root-key-v1`、0600、root_id＝site_id。開発用custodyで本番のHSM/TPMではない）、`DIR/site.db`（初回に0600で作成）。SAKとSiteCertの鍵・site_idが一致しない、別の現場の台帳、hash chainの破損はいずれも起動エラー。指定しなければSite Authorityは無く、各methodは`SITE_AUTHORITY_UNAVAILABLE`。

**権限**：ACL file（§4）の新しいgrant `MEMBERSHIP_READ`（一覧・状態・event）、`MEMBERSHIP_DECIDE`（`join.decide`、`membership.revoke`）、`MEMBERSHIP_ADMIN`（`join.policy.*`）を、SiteCertのnetwork下位32bit（またはワイルドカード`*`）に対して与える。既存のSEND等からは導かれない。

**API1**：

- `site.status` → 現場の識別（site_id、network、site_epoch、SAK fingerprint）、rs_epoch、gk_epoch／staged、member・removed・未確認・発見済み・参加要求の数、policy、counters、`usb{configured,attached,join_relay:"ready|not_ready"}`
- `join.policy.get` / `join.policy.set {zero_touch_open?, decision_mode?:"kguard|closed|lab_inventory", decision_timeout_ms?:500..5000, pending_retry_after_s?:30..3600}`。`lab_inventory` は `lab-site-init` 由来の development manifest・DB binding を持つ site だけに設定できる。閉鎖時は新規参加を pending にする。DevCert と JoinRequest の認証後、当該 site の written receipt を `lab-inventory-import` した (NodeId,kid,role,Device CA) だけ通常の `join.decide` で allow する。daemon 再起動で新 revision を読込む。`decision_mode=lab_inventory` を明示設定したときから単調時計で最大1時間だけ enrollment を開き、失効・時計逆行・daemon 再起動時は pending（同じ値を明示再設定して再開）。`join.policy.get` の `lab_enrollment_active` が実効状態を示す。import/production site では設定を拒否する。
- `join.requests.list` → `requests[]`（`join_request_id`＝`jr-`＋16hex、device・kid・model・hw_rev・cert_serial・fw_version・capability・requested_role・previously_removed・kid_conflict・via・attempt・remaining_ms・`state:"awaiting|decided"`、≤256）
- `join.decide {join_request_id, device_id, verdict:"allow"|"pending"|"deny", role|retry_after_s|reason, idempotency_key}` → allowは台帳commit後に`{"state":"committed","generation","member_cert_serial","operation_id","applied"}`、pending/denyは`"state":"recorded"`。`applied`は待っている試行へ届いた（`current_attempt`）か次の試行で効く（`next_attempt`）か
- `devices.discovered.list {after?, limit?:1..128}` → `devices[]`、`next_after`、`total`（≤1024、last_seenのLRU）。検証に失敗した機器は載らない
- `members.list {after?, limit?, include_removed?}` / `members.get {device_id}` → generation、role、MemberCert serial、`confirm_state`（`allowed_unconfirmed`／`active`、削除済みはnull）、`delivered`、時刻、削除理由
- `membership.revoke {device_id, expected_generation, reason:"removed|lost|replaced|blocked", idempotency_key}` → `{"operation_id","state":"committed","rs_epoch","gk_rotation":{"from","to","state":"staged"},"distribution":"not_implemented"}`
- `operations.get {operation_id:"op-…"}` → approve（`committed`→`delivered`→`confirmed`）／revoke（`committed`、配布は`not_implemented`で全memberを`unknown`と数える）

JSONの例は[07 §2.4](../design/sdk-v1/07-host-api-tooling.md)。idempotencyのidentityは`(principal, idempotency_key)`で、同じkey・同じ内容は保存済みの答え、内容違いは`CONFLICT`。決定済みの要求に別のverdict、`expected_generation`の不一致、kid conflictのallowも`CONFLICT`。storeが書けなければ`STORE_FAILURE`（retryable、何も変えていない）で、成功に変換しない。

**event**（`stream:"events"`、`filter.kinds`で選択）：`join.request`、`join.decided`、`device.discovered`、`member.reissued`、`member.confirmed`、`member.revoked`、`member.removal_notified`、`rrs.published`、`gk.staged`、`authority.error`、`site.session_drop`、`join_relay_failed`（`source`＋`reason`＋gateway/proxy/relay_id/joiner＋`stage`＋判明分の`device`／`join_request`）。直近の失敗は`site.status`の`recent_relay_failures`（最大16件）でも照会できる。

**参加の中継**：機器のEDHOC messageはproxy→gateway→USB HostOps 0x60/0x61/0x62（[02 §7](../design/sdk-v1/02-zero-touch-join.md)、応答は0x63）でsite laneに届く。laneは認証済みsession＋CAP_JOIN_RELAY_V2（bit 9；bit 8はv1 historyで不受理）のgatewayにだけ中継を開き、phase 4だけSite Authorityへ渡す（phase 5はP3-5未対応として0x62で拒否）。Authorityの応答は有界queue（8件・1件≤1005 B・TTL 20 s）経由で送り（downは0x61、中止はfull token付き0x62のみ）、受付失敗は試行を失敗終了する。結線状態は`capabilities.get`の`site.join_relay:"ready|not_ready"`。

**アプリ向け（`routeloom-client`）**：`site::SiteAdmin` trait（`site_status`、`join_requests`、`decide`、`discovered`、`members`／`member`、`revoke`、`site_events`）をRouteLoomTransportが実装する。`site::KGuardMock`は割当表（ここ→allow、他現場→deny not_here、禁止→deny blocked、未知→pending）で未決定の要求に答える試験用の実装。

```rust
use routeloom_client::{api1::RouteLoomTransport, site::{Assignment, KGuardMock, Role, SiteAdmin}};

let site = RouteLoomTransport::new("/tmp/routeloom.sock", 0x0a1b2c3d);
let kguard = KGuardMock::default();
kguard.assign(0x00a1_0000_0000_1234, Assignment::Here(Role::Endpoint));
for event in site.site_events()? {
    if event?.kind == "join.request" { kguard.serve_once(&site)?; }
}
```

制約：EXPERIMENTAL（本番Profileではない）。host試験のみで、実機のgateway・proxyとの疎通は無い。GKの配布・更新とauthority channel（JoinConfirm、P5）、RRS1の配布（P6）、site_epoch cutover、SiteCert発行tool（P7-2）は未実装。DAMS・GKはDB fileの0600で守るだけでhost鍵の封緘は無い。

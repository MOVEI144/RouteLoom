# USB／Serial transport契約

改訂1.3。フレーミング・認証（RLU1 protocol 2＝HostLink v2）・認可・creditの意味を定義する。最終field offsetは未凍結。Rust host codecと携帯可能C++ device bridge（session、credit、MeshNode統合）は実装済みで、`protocol/usb-golden`の共有vectorでbyte相互検証済み。実USB driverのHIL認定は別。

## 1. フレームと境界

COBS＋0 delimiterを基準。decoded最大4096B、body最大はheader・保護・CRCを差し引く。CRCはCRC-32/ISO-HDLC（reflected polynomial 0xEDB88320、init/xorout 0xFFFFFFFF、check("123456789")=0xCBF43926）、他fieldと同じくbig-endian32bitで末尾へ置く。CRC対象はdecoded CRC直前のbytes、CRC自体とCOBSは除く。CRCは認証ではない。

最大符号化長は保守的にn+floor(n/254)+2（delimiter込み）。decoded overlengthを検出しても次delimiterまで有界に捨て、再同期する。部分frameは最後のbyteから1000msで破棄する。実USB伝送速度と相互待ちで達成可能かを認定する。

bootログ混入へ同期復旧は必要だが、通常binary streamへprintfを流さない。4096B USB frameをそのまま250B RFへ送れるとはしない。

## 2. 認証とsession

HELLOは未認証。device/host credential、nonces、protocol範囲、選択版、期待Node、Network scope、host principal/roles、boot、capability digestを認証transcriptへ結び付ける。AUTH後の全COMMAND・DATA・CREDITもそのsessionの完全性とreplay保護を必要とする。

firmware hashの自己申告はattestationではない。COM番号やUSB serial文字列を機器本人証明にしない。Networkを切り替える場合も認証scopeと再認可を確認する。未認証のCREDITを送信許可として処理しない。

再接続は新sessionで、partial frame、grant、consumed、request tokenを再使用しない。stable Message IDやhost idempotency identityだけを明示的に再照会する。

**HostLink v2（RLU1 protocol 2）**：親機ごとの hostlink secret（機器は rlkeys の USB secret、host は `--hostlink-credentials` の NodeId ごとの file。ASCII 1〜63 B）を両端が持つ。

- 鍵：`K = HKDF-SHA-256(salt=空, IKM=secret, info="RouteLoom/v2/hostlink", L=32)`。
- transcript（121 B、big-endian）：`"RLU1TRN2" || host_nonce u64 || device_nonce u64 || min_version u8 || max_version u8 || version u8 || carrier u8 || binding 32B || node u64 || boot u64 || network u64（完全な64 bit） || capability u32 || plen u8 || principal（32 Bまで0埋め）`。carrierはUSB/serialが0、bindingは安全なchannelを結び付けるcarrier用の予約でUSBでは全0。
- session値はすべて `HMAC-SHA-256(K, label || 0x00 || transcript)`：`key-h2d`・`key-d2h`（各32 B、方向別のframe MAC鍵）、`hello`・`auth`・`auth-ok`（先頭16 Bのtag）、`session-id`（先頭8 BのBE u64）。
- 手順：HELLO（`host_nonce || min || max || plen || principal`）→ HelloAck（`device_nonce || version || node || boot || network || capability || hello_tag`）→ host が hello_tag を検証し AUTH（Hello＋flag AUTH、`auth_tag`）→ AUTH_OK（HelloAck＋flag AUTH、`auth_ok_tag || session_id`）。tagの比較は定数時間。
- 版：機器はprotocol 2だけを受ける。範囲に2を含まないHELLOは`VERSION_UNSUPPORTED`で拒否し、protocol 1への自動fallbackはしない。hostが出した範囲はtranscriptに入るため、途中で書き換えた範囲はAUTHで失敗する。
- frame：`counter u64 || tag 16B || inner`。`tag = HMAC-SHA-256(方向の鍵, dir u8 || counter u64 || kind u8 || flags u16 || request u64 || inner)` の先頭16 B。counterは方向ごとにsession開始時0から始まり、機器は期待値と一致しないframeを`REPLAY_REJECTED`で拒否する（sessionごとに窓を初期化）。最大値（2^64−1）は送受信せず、到達したsessionは作り直す。
- 暗号化はしない（完全性・相互認証・replay保護のみ）。`payload_hash`（idempotencyの同一性）はSHA-256の先頭16 B。

### 2.1 理由ID

Error（`code u16 || request u64 || reason`）とDeliveryEvent（`… || state u8 || reason || [operation_id 24B]`）の`reason`は `reason_id u16 || detail_len u8 || detail`。`protocol/manifest.json`に登録した理由（hostlink領域0x0400〜・delivery領域0x0100〜）はIDだけを送り（detail_len 0）、未登録の理由はID 0と印字可能ASCIIの文字列（最大64 B）を送る。hostはIDを登録表の文字列（`api1`があればそれ、無ければname）に戻すので、API1のJSONに出る理由の文字列は変わらない。

## 3. credit：方向・session別の累積許可

各方向はuint64の `grant_frames, grant_bytes, consumed_frames, consumed_bytes` を持つ。受信側grantは**累積送信許可の上限**であり「今の空き」「差分＋4」ではない。初期grantは専用buffer容量以内。

認証済み同session通知は各grantのmaxを採用。duplicateや古い小grantは追加許可にならない。送信条件は両軸で `consumed + next_cost <= grant`。新frameの最初のbyteをwriteする前にframe1件と完全なdecoded保護frame長（CRC含む、COBS/delimiter除外）を一度だけ課金する。partial write継続で再課金しない。

受信側は予約bufferを解放した分だけgrantを進める。累積grant値が大きいことと同時buffer容量が大きいことは別。grantを取り消して縮小せず、止めたいときは増額を止める。wrap前にsessionをdrainして作り直す。

破損frameでgrantの正確な会計が復元できない場合、無制限credit返却は行わず認証された同期手順または新sessionに戻す。新sessionで旧の未完送信の結果を成功としない。

## 4. zero-creditの回復

通常DATA/BULKとは別にCONTROL予約を最大4frame×256B設ける。AUTH後のcredit query、grant、keepalive、close等だけ、全相手合算10frame/s burst4以下。CONTROLにCONTROL ACKを無限要求しない。初期AUTHにもさらに有界なpreauth quotaが必要。

zero-credit時のqueryは500ms以上の間隔で最大3回、応答が無ければCONNECTION_STALLED。CONTROL予約で通常DATAを迂回しない。

## 5. 操作identityと結果

USB request IDはsession内一意、Message IDは論理配送の寿命、host idempotency identityは `(principal, network, operation_class, key)`。同identity・同canonical payload hashは既存結果、同identity・異hashはCONFLICT。

COMMAND_ACCEPTEDは機器受付だけ。管理確定、PC永続保存、アプリ適用は別event。再接続で信用先が変わったら旧認可を引き継がない。

開発profileのHostOps `SUBMIT` が `MeshRejected` を返す場合、固定長 `RECEIPT` の32B hash位置は `RLFR`（4B）＋理由長（1B）＋印字可能ASCII理由（最大27B）＋ゼロ埋めになる。旧機器のcanonical hash echoや形式不正は理由として扱わない。受理された送信の終端失敗では、`DeliveryEvent` の `reason` の後に24B `operation_id` を付ける。hostはそのidと `msg_session/msg_seq` をともに照合して当該操作に理由を保存する。末尾の無い旧eventは観測eventとして残すが、操作の理由には結び付けない。

## 6. 検査

CRC既知vector、1byte分割、COBS境界、overlength、部分timeout、grant duplicate／stale／別session、2軸不足、partial write一度課金、zero-credit相互待ちを検査する。小モデルで累積creditが通ってもUSB暗号・実driver相互運用が認定されたことにはならない。

## 7. Node status（node_status_v1、EXPERIMENTAL）

HelloAck capability bit 6（`0x40`、`kCapNodeStatusV1`／`CAP_NODE_STATUS_V1`）を広告するbridgeだけがHostOps `0x40`〜`0x42`を扱う。HostOps carrier自体がhost_ops_v1（bit 2）を要するため、hostはbit 2とbit 6が共に広告された時だけqueryする。bitはHello transcriptに結合され、未広告の機器へのqueryは`result=Unsupported`の空pageで返る。形式はgateway/config系と同じ `schema:u8=1 || sub:u8 || payload_len:u16 || payload`（big-endian、長さ完全一致）。

| sub | 向き | payload |
|---|---|---|
| `0x40` NODE_STATUS_QUERY | H→G | `after:u64`（排他cursor、0=先頭）、`max_entries:u8`（1〜16）、`flags:u8`（bit0 SUBSCRIBE：このsessionのevent streamを(再)armしてからpageを取る） |
| `0x41` NODE_STATUS_PAGE | G→H（同request id） | `result:u16`（ConfigOpsResult空間）、`flags:u8`（bit0 MORE、bit1 EVENTS_ARMED）、`count:u8`、`next_after:u64`、`event_seq:u32`、`count×entry` |
| `0x42` NODE_EVENT | G→H（非要求、request id 0） | `sequence:u32`（arm毎に1から連続）、`kind:u8`（1 NeighborUp／2 NeighborDown／3 RouteUp／4 RouteDown／5 RouteChanged）、`reserved:u8=0`、`entry` |

entry（28B）は `node:u64、flags:u8、rssi_last:i8、rssi_ewma:i16（Q8.8）、link_cost:u16、route_metric:u16、next_hop:u64、heard_age_ms:u32`。flagsはbit0 neighbor record有、bit1 active neighbor、bit2 reachable（選択済みfeasible route）、bit3 direct、bit4 RSSI有効、bit5 heard有効、bit6 telemetry stale、bit7予約0。到達不能entryのnext_hopは0、metricは`0xFFFF`＝無し。pageはnode id昇順で、decoderは順序違反・cursor不一致・予約bitを拒否する。機器は時刻を送らず経過時間（`heard_age_ms`）だけを送る。

pageはMeshNodeの近隣表・経路表・telemetryから割当なしで組み立てる（最大128経路＋32近隣＝160 node）。eventは250ms毎の有界diff（1回最大4件、data queueの半分はapplication用に予約）で、拒否されたeventは同じsequenceで次回再送されるため欠落しない。session teardownでarmは解除される。共有vectorは`protocol/usb-golden/node-status`（C++ bridge replayとRust codecが同一byteを検証）。host側の扱いは[Host §9](host.md)。

## 8. Group配送（group_delivery_v1、EXPERIMENTAL）

HelloAck capability bit 7（`0x80`、`kCapGroupDeliveryV1`／`CAP_GROUP_DELIVERY_V1`）を広告するbridgeだけがHostOps `0x50`〜`0x52`を扱う（bit 2も必要）。bridgeのnodeがgateway-scoped profileのroute gatewayである時だけ送信が受理される（[設計](../design/sdk-v1/group-delivery.md)）。形式はnode status系と同じ4B head＋payload（big-endian、長さ完全一致）。

| sub | 向き | payload |
|---|---|---|
| `0x50` GROUP_SEND | H→G | `group:u16`（1〜0xFFFF、0xFFFF＝ALL）、`priority:u8`（0 Bulk〜3 Urgent）、`flags:u8`（bit0 ORDERED）、`lifetime_ms:u32`（1〜30000）、`hop_limit:u8`（1〜254）、`reserved:u8=0`、`data_len:u16`（≤127）、`data` |
| `0x51` GROUP_STATUS | G→H（0x50／0x52と同request id） | `result:u16`（ConfigOpsResult空間）、`session:u32`、`sequence:u64`、`group:u16`、`state:u8`（DeliveryState）、`rounds:u8`、`delivered:u16`、`nonmember:u16`、`missing_total:u16`、`unaccounted:u16`、`flags:u8`（bit0 TRUNCATED＝missing_total＞missing_count、bit1 FINAL＝終端状態）、`missing_count:u8`（≤12）、`reason_len:u8`（≤32）、`reserved:u8=0`、`missing:u64×n`、`reason`（印字可能ASCII） |
| `0x52` GROUP_QUERY | H→G | `session:u32`、`sequence:u64`（bit63必須） |

`0x50`にはすぐ受理結果の`0x51`を返す（`Ok`＋その時点のsummary、または拒否：`Unsupported`＝未attach・flat profile・gateway以外、`Busy`＝source表満杯／node停止中、`Invalid`＝引数、idとcountsは0、`reason`に理由）。受理したmessageが終端状態になると、同じrequest idで**FINAL付きの`0x51`をもう1回だけ**送る。この対応付けはsession単位（最大3件＝node側のsource表と同数）で、再接続後のhostは`0x52`で読む。機器が既に回収したidへの`0x52`は`Ok`／state 0／`NOT_FOUND`。flagsはencoderが導出し、decoderは不一致・予約id・印字不能reasonを拒否する。このnodeが**受信した**group messageは通常の`DataFromMesh`（sequenceのbit63でgroupと分かる）で届く。共有vectorは`protocol/usb-golden/group-ops`（2 node gateway-scoped meshでのC++ bridge replayとRust codec）。daemonはこれをAPI1 `group.send`／`group.get`と`group_settled` eventとして公開する（[host §10](host.md)：未決着の間は`0x52`で読み直し、laneのrequest idは上位16bit `0x4752`の専用範囲）。

## 9. 参加中継（join_relay_v1、EXPERIMENTAL）

SDK v1ゼロタッチ参加で、member proxyが中継する未割当機器のEDHOC／RLRES1交換をgatewayとhostのSite Authorityの間で運ぶ（[sdk-v1/02 §7](../design/sdk-v1/02-zero-touch-join.md)）。HelloAck capability bit 8（`0x100`、`kCapJoinRelayV1`／`CAP_JOIN_RELAY_V1`）を広告するbridgeだけがHostOps `0x60`〜`0x63`を扱う（bit 2も必要）。bitはbridge ownerが`attach_join_relay`でgatewayの`JoinRelayGateway`を渡した時だけ立ち、未attachの`0x61`/`0x62`は`Unsupported`の`0x63`で答える。設計案の`0x40`〜`0x42`とbit 6はnode status（§7）と衝突するためSDK v1のsite-authority族は`0x60`〜`0x6F`に置いた（[02 §7.4](../design/sdk-v1/02-zero-touch-join.md)）。形式は§7と同じ4B head＋payload（big-endian、長さ完全一致）。`relay object`は`RelayHeader 24B`（`ver=1 | dir 1 up/2 down | relay_id u32 | proxy u64 | joiner MAC 6B | step | status 0継続/1最終/2中止 | joiner_rssi_dbm i8 | phase 4 EDHOC/5 RLRES1`）＋EDHOC/RLRES1 message 1〜960B（中止は`status u8 | retry_after_ms u32`）で、codecが全体を検査する。

| sub | 向き | payload |
|---|---|---|
| `0x60` JOIN_RELAY_UP | G→H（非要求、request id 0） | `gateway:u64`、`from_proxy:u64`（meshで検証済みの送信元、objectのproxyと一致）、`hops:u8`（1〜254）、`relay object`（dir up） |
| `0x61` JOIN_RELAY_DOWN | H→G | `to_proxy:u64`、`relay object`（dir down、proxy＝to_proxy）。最終の下りはstatus 1、authority側の打切りは中止object |
| `0x62` JOIN_RELAY_ABORT | H→G／G→H（非要求、request id 0） | `proxy:u64`、`relay_id:u32`（≠0）、`reason:u8`（1 proxy_aborted、2 gateway_expired、3 delivery_failed、4 host_aborted。H→Gは4だけ） |
| `0x63` JOIN_RELAY_RESULT | G→H（0x61／0x62と同request id） | `result:u16`（ConfigOpsResult空間：`Ok`＝Wire laneへ渡した、`Unsupported`、`Busy`＝gateway slot無し、`Denied`＝gatewayがMemberでない、`Invalid`＝不整合・知らないrelay、`NoRoute`、`Indeterminate`）、`proxy:u64`、`relay_id:u32` |

`Ok`は機器への配送を意味しない（配送の結果は次の上り、または`0x62`の`delivery_failed`で分かる）。gatewayは分割されたobjectを2件まで同時に組み立て／送信し、hostが居ない（sessionが無い・queue満杯）間の上りはproxyへ`authority_unreachable`の中止を返して捨てる。形式不正はError frame（ProtocolError）、`0x60`/`0x63`をhostが送ればdirection違反。共有vectorは`protocol/usb-golden/join-relay-v2`（gateway 1・proxy 2の交換をC++ bridgeがbyte一致で再生、Rust `routeloom-protocol::join_relay`が復号）とrelay objectの`protocol/sdkv1-golden/join-transport`。Site Authority側（daemon）はP3-3。

## 10. 観測（observation_v1、EXPERIMENTAL）

USBで直結したnode自身のread-only snapshot：system health、table占有、参加milestone、topology summary、選択経路のpage。経路・lease・広告の状態は一切変えない。HelloAck capability bit 11（`0x800`、`kCapObservationV1`／`CAP_OBSERVATION_V1`）を広告する機器だけがHostOps `0x70`〜`0x72`を扱う（bit 2も必要）。形式は§7と同じ4B head＋payload（big-endian、長さ完全一致）。

| sub | 向き | payload |
|---|---|---|
| `0x70` OBSERVATION_QUERY | H→G | `section:u8`（0 system／1 tables／2 milestones／3 summary／4 routes／5 neighbors）、`flags:u8`（bit0 SUBSCRIBE：pageを取る前にevent streamを(再)arm、bit1 EXACT：routes/neighbors専用で`after`をcursorではなく1宛先/peer指定）、`max_entries:u8`（1〜8、singletonは常に1）、`reserved:u8=0`、`after:u64`（排他cursor。`u64::MAX`不可） |
| `0x71` OBSERVATION_PAGE | G→H（同request id） | `result:u16`（ConfigOpsResult空間）、`section:u8`、`flags:u8`（bit0 MORE、bit1 ARMED）、`count:u8`、`reserved:u8=0`、`boot_id:u64`、`revision:u32`、`next_after:u64`、`body` |
| `0x72` OBSERVATION_EVENT | G→H（非要求、request id 0） | `sequence:u32`（arm毎に1から連続）、`kind:u8`（1 topology／2 milestone）、`mask:u8`（topologyのみ：bit0 neighbors／bit1 routes変化、milestoneは0）、`reserved:u16=0`、`boot_id:u64`、`revision:u32`（topology＝route digest、milestone＝milestone世代）、`extra:u32`（topology＝neighbor digest、milestone＝0） |

section bodyは固定長（system 28B：`uptime_ms:u64`・heap free/min/largest:u32・reset/power/coord/profile:u8・予約u32／tables 36B：neighbor・route・link/end session・dedup resident/terminal/cap・tx used/cap・group trees/origins・dedup refused/evicted・予約u16／milestones 44B：mode/membership/joiner/flags:u8・attempts:u32・join_started/adopted/confirmedのage:u64・adopted_node:u64・予約u32／summary 24B：neighbor/route digest:u32・各active/total:u16・milestone_gen:u32・予約u32）とroutes可変長（30B entry×count：`destination:u64、next_hop:u64、generation:u32、sequence:u16、metric:u16、valid:u8(0/1)、reserved:u8=0、remaining_ms:u32`）・neighbors可変長（24B entry×count：`peer:u64、heard_age_ms:u32、lease_remaining_ms:u32、link_cost:u16、rssi_ewma_q8_8:i16、phase:u8（discovery phase＋1、0＝不明）、flags:u8（bit0 active／bit1 rssi有効／bit2 heard有効）、rssi_last_dbm:i8、reserved:u8=0`）。milestoneのageはboot内のミリ秒精度で保持し、49日を超えても周回・飽和しない。reset_codeはmask-ROMのreset reason直読（IDFのhint精製を使わないためpanic起因のSW resetはsoftwareと読む）。pageの`revision`はmilestones＝milestone世代、summary/routes＝route digest、neighbors＝neighbor digest、system/tables＝0。非Ok pageはcount 0・空body。routes/neighbors pageのentryは宛先/peer昇順で、`next_after`は末尾entryの宛先/peer（空pageはqueryの`after`）。機器は絶対時刻を送らずuptime・age（milestoneは`u64::MAX`、neighborは`u32::MAX`が不明）だけを送り、hostが受信時刻から逆算する。

(再)armはevent sequenceを1に戻す。hostはSUBSCRIBE付きqueryの送信時に自前のwatermarkを再同期し、sequenceの飛びを欠落（再pull）として扱う。page/eventはowner loop内で組み立て、無線callbackで表走査やJSON化をしない。共有vectorはC++／Rustの固定byte試験（`tests/cpp/test_observation.cpp`の`test_fixed_vectors`と`routeloom-protocol::observation`の`fixed_vectors_match_device_encoder`が同一byteを検証）。host側の扱いは[Host §12](host.md)。

**遠隔路（M2）**：gateway以外のnodeのsectionはDiagnostic `0x30`/`0x31`のsubtype 7（query）／8（snapshot）で取る。gatewayがHelloAck bit 5（m1 diagnostics）とbit 2を広告する時のみ。query 24B＝`ver:u8=1、sub:u8=7、予約u16=0、request_id:u32≠0、section:u8、max_entries:u8、flags:u8（bit0 EXACT：routes/neighbors専用・`after`はcursorでなく1宛先/peer）、予約u8=0、after:u64（`u64::MAX`不可）、予約u32=0`。snapshot 40B head＋section body（全体128B以下）＝`ver:u8=1、sub:u8=8、予約u16=0、request_id:u32、observer:u64、observer_boot:u64、section:u8、flags:u8（bit0 MORE）、count:u8、予約u8=0、revision:u32、sampled_ms:u64（応答nodeのboot内単調時計）`＋0x71と同一byteのsection body。section bodyは0x71と同一encoder（hostは両路を同一codecで読む）。128B boundのpageはroutes 2件・neighbors 3件まで、singletonはcount 1。gateway宛のqueryは自sectionで即応答し、他node宛はmesh転送する（内側相関idはgatewayが振り直してverbatim中継するため、hostはUSB request id＋observer/section一致で照合し、内側idでは照合しない）。応答nodeはopt-in＋所属時のみ応答し、それ以外・経路なし・不明sectionは診断拒否（subtype 6）で返す。pull専用（change通知は無線を越えない）。

## 11. 受信保証（rx_assurance_v1、EXPERIMENTAL）

DataFromMeshごとのorigin検証証拠：gatewayの実効security profile・open_end判定・site epoch。HelloAck capability bit 12（`0x1000`、`kCapRxAssuranceV1`／`CAP_RX_ASSURANCE_V1`）を広告するbridgeだけがHostOps `0x08`を扱う（bit 2も必要）。bitはbridge ownerが`set_rx_assurance_profile`で実効profile（observation `kProfile*`）を渡した時だけ立つ。

| sub | 向き | payload |
|---|---|---|
| `0x08` RX_ASSURANCE_ENABLE | H→G | 空（head 2Bのみ。存在がenable） |
| `0x08` | G→H（同request id） | `result:u8`（HostOpsResult。`Ok`で当該sessionの拡張ingressをarm、`Unsupported`でlegacy継続） |

enableはsession scoped（再接続で解除、再enableが必要。profile idはboot scopedで残る）。arm済みsessionの証拠付き配送はDataFromMeshのframe flags bit `0x0002`（`kFlagIngressAssurance`）を立て、payloadの後に8B tail（`flags:u16`＝bit0 VERIFIED、残り予約0／`profile:u8`＝実効profile id 0〜2（3は撤去したdev-PSK fixtureの予約で、送らず受け付けない）／`reserved:u8=0`／`site_epoch:u32`＝配送headerのend_epoch）を付ける。20B headのoffsetは両形で同一。group配送（3引数`on_message`経路）はgroup鍵検証であってorigin END証明ではないため、arm済みでもlegacy形のまま送る。hostはflag付きでtail長に満たない・tail異常のframeをmalformedとして落とす（証拠なしへの格下げはしない）。host側の扱いは[Host §3](host.md)。

## 12. 手動channel plan（channel_plan_v1、EXPERIMENTAL）

MemberEdhoc専用（DevRamはSite Authorityが無く固定channel、[channel移行](channel-migration.md)）。MemberEdhocのsiteで、hostのSite AuthorityがSAKで署名したchannel planをgatewayへ渡し、gatewayがsiteのplan authorityとして各memberへ配る（issue #5の手動移行）。HelloAck capability bit 13（`0x2000`、`kCapChannelPlanV1`／`CAP_CHANNEL_PLAN_V1`）を広告するbridgeだけがHostOps `0x68`／`0x69`を扱う（bit 2も必要）。bitはbridge ownerが`attach_channel_plan`でplan authorityを渡した時だけ立ち、未attachの`0x68`はUnsupportedのError frameで返る。形式は§7と同じ4B head＋payload（big-endian、長さ完全一致）。

| sub | 向き | payload |
|---|---|---|
| `0x68` CHANNEL_PLAN | H→G | `action:u8`（1 STATUS／2 OFFER／3 RELEASE）、`reserved:u8=0`。OFFERは続けて`blob_len:u16`（1〜384）、plan blob、`commit_signature[64]`。RELEASEは`plan_hash[32]` |
| `0x69` CHANNEL_PLAN_REPORT | G→H（同request id） | 96 B：`result:u16`（ConfigOpsResult空間）、`detail:u8`（機器のStatusCode）、`phase:u8`（gateway参加者のParticipantPhase）、`active_channel:u8`、`ready:u8`（提示中のplanにREADYを返したmember数）、`flags:u8`（bit0 commit解放済み）、`reserved:u8=0`、`active_epoch:u32`、`cooldown_ms:u32`（plan間cooldownの残り）、`gateway_now_ms:u64`（planの時刻の領域）、`ledger_sequence:u64`、`ledger_state[32]`、`offered_plan[32]`（無ければ0） |

gatewayは採用済みsiteのSAK（`SiteCommitVerifier`）で署名を検証してから台帳（`rlmauth`）へcommitし、planを配る。USB sessionはhostを認証するだけで、planの正しさは保証しない。偽の署名・署名なしは`Denied`（detail＝AuthenticationFailed）で、何も配らない。commitの証拠はRELEASEまで保持し、gatewayはOFFER時に認証済みの直接peerを固定して、その全員のREADYまでRELEASEを拒否する。解放後もそのpeerの結果を待ち、全員の結果または期限後に成否を確定する。hostはreportの`ready`を確認してから解放する。site全体のrequired集合や切替時に不在だったmemberの復旧は未実装。hostはSTATUSのreport（台帳の先頭、現在のchannelとepoch、gatewayの時計）から次のplanを組み立てるので、5 sより古いreportでは提示しない。回復用のsigned snapshotは配らない（snapshotはcommit証拠そのもので、READYの関門を越えてしまう）。daemon側はAPI1 `site.channel_plan.status/offer/release`（[Host §11](host.md)）。

[Host](host.md)／[Wire](wire-protocol.md)／[電源断](crash-time-resources.md)

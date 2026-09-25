# 無線Wire形式と版管理

## 1. 契約の段階

本書はframeの意味・上限・保護境界を定義する。CORE_FIXED_250 profileのbyte offset・固定field割当・frame type番号は**Wire v2として凍結済み**で、`components/routeloom/include/routeloom/wire.hpp`のoffset表と`protocol/semantics.json`の`frame_numeric_ids`が正本である。C++・Rust共通golden vectorは[protocol/golden](../../protocol/golden/README.md)に置く。暗号suiteと本番credentialは引き続きG-SECで凍結する。未確定のバイト列を公開互換プロトコルとして実装者に配布しない。

一方、以下の長さ、再送ID、mutable/immutable分離、未知版の拒否、通常DATA非分割は変更管理された必須契約である。

## 2. サイズ

ESP-NOWへ渡すbodyは最大250B。通常アプリpayload最大128B。Routing、Identity参照、長さ、期限、session、認証・暗号tagを含む全envelopeに122B以下を予約する。空中の802.11/ESP-NOWヘッダはこの250Bとは別。

frame長区分は32/64/128Bアプリpayloadと最大250B全bodyで試験する。v2の1470Bを使わず、暗号を省いて128Bを達成しない。暗号Profileで収まらなければプロファイルの再設計または互換性を伴う上限改訂が必要。

## 3. 通常frameの意味

| 区分 | 必須の意味 |
|---|---|
| 形式 | magic/識別、protocol version、frame type、flags、header/body長 |
| 所属 | Network識別と必要なmembership/key世代参照 |
| 送受信 | source、固定destination、origin session、message sequence |
| 配送 | delivery round、hop remaining、priority、残deadline |
| hop保護 | 直前送信者context、nonce/counter、mutable headerの完全性 |
| end保護 | 不変なorigin/destination/messageとpayloadの認証暗号 |

NodeIDは長期credentialへ結び付く。short handleを使用する場合は所属世代と割当証拠で復元し、handle衝突を無視しない。生MACを認証済みIdentityとしない。

remaining deadline、hop、前回送信者などは中継で変わり得る。end署名対象の不変部を書き換えず、hop保護を作り直す。変更時にnonceを再使用しない。

## 4. フレーム種類

DISCOVER/OFFER、BOOTSTRAP_AUTH/CHUNK/REPLY、MEMBERSHIP_QUERY/RESULT、NEIGHBOR_PROBE/NEIGHBOR_RESULT、ROUTE_UPDATE/ROUTE_WITHDRAW/ROUTE_REQUEST/SEQNO_REQUEST、DATA、GROUP_DATA/GROUP_REPORT、HOP_ACCEPT/BUSY、END_RECEIPT、APP_RESULT、SERVICE、CONTROL/CONTROL_OBJECT、OBJECT_CHUNK/OBJECT_ACK、TIME_SYNC、CHANNEL_NOTICE、DIAGNOSTICの意味を区別する。完全な識別子と凍結済みnumeric type IDはsemantics.jsonの`frame_numeric_ids`を参照（Wire v2でもv1から不変）。未知typeは復号を拒否する。

未所属ではDISCOVER/OFFERと、[参加状態別allowlist](identity-membership.md)に記載した当該transactionのbootstrapだけを許す。認証や承認を終える前のDATA／route／serviceは拒否する。bootstrapを発見と同義にしない。HOP_ACCEPTはそれ自体を再帰ACKしない。END_RECEIPTは新アプリmessageとしてreceiptを要求しない。

## 5. エンコーディング

C/C++ packed structのmemcpyをwire ABIにしない。固定幅、network byte order、enum予約範囲、上限、未知type処理を明示したencoder/decoderを持つ。len検証前にポインターを進めない。integer overflow、重複TLV、reserved bit、末尾ゴミをfuzz試験する。

暗号Providerの正規化方式と完全性対象を一意にする。同じ意味に複数canonical byte列がある場合の署名検証曖昧性を避ける。

## 6. 管理object

通常DATAは自動fragmentしない。認証済みcredential/control/configの上限は最大2048B、同時4object、10秒組立timeout。役割別profileはその下位の同時枠を選ぶ。未所属Joinのbootstrapは別枠で最大1024B、同時1、3秒まで。token、owner、total length、offset、chunk length、object digest、期限を検証する。

範囲外、重複、順不同、異なるpayloadの同offset、古いsessionを拒否または規定通り扱う。2048Bより大きいcertificate/log/OTAは、一つの無制限objectへ拡大せず、認証したmanifest＋bounded chunk streamへ分ける。snapshot/commit証拠もサイズ設計を行う。

**SDK v1参加の搬送（EXPERIMENTAL、[sdk-v1/02 §5.4・§7.4](../design/sdk-v1/02-zero-touch-join.md)）**：未所属Joinの1024B objectはBootstrapAuth phase 4〜6として実装した。chunkは`ver=1 | sub=phase<<4|step | id u32 | offset u16 | total u16 | data`（RLD1は106B、Wireは118Bの格子、単一frameに入るobjectは分割しない）、replyは10B（連続受信byte数と0 progress／1 complete／2 aborted）。順不同は受理、同一重複は再応答、同offsetの異なるpayloadとtotalの変化は破棄、同時1件、3秒で破棄。member proxyとgatewayの間ではWire FrameType 3（上り・継続の下り）、4（最終・中止の下り、1 frameに入る場合）、5/6（分割とその受領）がrelay object（RelayHeader 24B＋message≤960B）専用で、hopごとのlink保護で運び`kFlagEndProtected`は付けない。宛先はproxyのgatewayだけ（`zt_admit_relay`）。byte列は`protocol/sdkv1-golden/join-transport/`が固定する。#116でこのWire relay区間だけをv2化した（RelayHeader 32B＋両service epoch、18B chunk／reply、24B epoch Query／Reply。byte列は`protocol/sdkv1-golden/join-relay-v2/`、[sdk-v1/02 §7.5](../design/sdk-v1/02-zero-touch-join.md)）。MeshNodeのrouted転送へ配線済み（G-SEC P4 §7.4：`send_bootstrap`でlink-only送信、終端は`BootstrapSink`、中継はRelay/Gateway roleを持つmemberのみ、lane上限は全体8件・peer毎2件、hop認証はorigin認証ではない）。member間end-session objectは12B header＋message≤960Bの別envelopeでtype 3（単一frame）／type 5・6（lane bit `0x80`付きsubの分割と受領）に乗り、type 4には乗らない。end laneのWire chunk／replyはv2 head（epoch byteは予約0）を共有する。byte列は`protocol/sdkv1-golden/handshake/`の`end_object`／`end_sub`が固定する。

## 7. 互換性

protocol majorが合わなければ参加拒否。minor featureは双方capabilityで交渉し、必須securityをdown-gradeしない。データMTUはpath制約として扱い、将来LoRa追加で大packetを黙って落とさない。

完全なgolden vectorには正常DATA128B、最短ACK、最大管理object、未知version、改ざん、再送round、別hopでの外側暗号、再起動を含める。

根拠：[ESP-NOW frame形式](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/network/esp_now.html)。暗号契約は[Security](security.md)、USBは[別文書](usb-protocol.md)。


### Wire v2（v1からの変更）

v1はlink／end epochを16bitとし、firmwareは起動（deep-sleep wakeを含む）ごとにepochを1消費していた。65,535回の起動でwrapすると、ピアのreplay floorとroute tableが当該ノードを恒久拒否し、自身のTX counter leaseも「古いepoch」を拒否して送信不能になった（issue #29/#48）。v2は次のとおり改める。major versionは2、v1 frameは`unsupported wire header`で拒否する。

| field | v1 | v2 |
|---|---|---|
| link epoch（offset 68） | u16 | u32 |
| end epoch | u16（offset 70） | u32（offset 72） |
| link crypto counter | u64（offset 72） | u48（offset 76） |
| end crypto counter | u64（offset 80） | u48（offset 82） |
| ROUTE_UPDATE record | dest u64＋generation u16＋seq u16＋metric u16＝14B（9件/frame） | generation u32で16B（7件/frame） |
| APPLIED execution lease | magic u16＋session u32＋end epoch u16＋incarnation u64 | session u32＋end epoch u32＋incarnation u64（16Bのまま） |

headerは88Bのまま、payload上限128Bも変えない。counterを48bitに狭めても1 epochあたり2.8×10^14 frameで、使い切ったcontextは同じ鍵で巻き戻さず新しいepochへ移る（`kMaxCryptoCounter`）。AEAD nonce（12B）はscope u8＋方向u8＋epoch u32＋counter u48。firmwareはepochとroute generationを32bitの永続boot sessionから直接導出する。

### broadcast ROUTE_UPDATE（P5-2、scoped opt-inで配線済み）

専用payload（version 1、24B/record、最大5件）は[routing-scale](../design/sdk-v1/routing-scale.md)を参照。Wireは`next_hop=destination=broadcast`のときRouteUpdateだけを認め、`origin=previous_hop`（通常node ID）、hop=1、BestEffort、round=0、end保護なし、end counter=0を強制する。送信時はGroupLink ProviderからbootとGK epochを同時に取得し（無ければUnsupported）、`link_epoch=boot`、`end_epoch=GK`でGroupLink封止する。受信のbroadcast openは専用dispatchだけが明示指定し、送信者gate（opt-in・観測MAC・active隣接・Link usable・V2 metadataとOwner snapshotの現在binding）を先に通す。未知GKの未認証headerは分1回までのpull hintに留め、既知GKだけGroupLinkでopenする。通常のMeshNode受信経路は既定で拒否する。GroupLink tagはpeer本人性の証明ではなく、route適用だけを行いcapability・telemetry・resume確認には使わない。送信先適格性は別途pairwiseのnonce-bound capability grant（bit7）で判定する。

### ROUTE_REQUEST payload（type 35、gateway-scoped routing）

予約済みtype 35にpayloadを定義した（headerは不変、[設計](../design/sdk-v1/routing-scale.md)）。ROUTE_UPDATE／SEQNO_REQUESTと同じくlink保護のみの1hop frame（`hop_remaining=1`、destination＝next_hop＝受信隣接、BestEffort）で、多hopの種類はhopごとに作り直し、TTLはpayloadに持つ。固定38B、big-endian：

| offset | field | 型 | 意味 |
|---:|---|---|---|
| 0 | kind | u8 | 1＝Neighbor（1hop pull）、2＝Discover、3＝Reply。他は拒否 |
| 1 | ttl | u8 | 1〜10（hop上限）。Neighborは常に1 |
| 2 | requester | u64 | transactionを始めたnode。0／broadcastは拒否 |
| 10 | target | u64 | 経路を求める宛先。requesterと同一は拒否 |
| 18 | request_id | u32 | requester単位のid。(requester, request_id, kind)で重複抑止 |
| 22 | record | 16B | ROUTE_UPDATE recordと同一形式（destination u64＋generation u32＋sequence u16＋metric u16） |

recordのdestinationはNeighbor／Discoverでrequester、Replyでtargetに一致しなければならない（不一致は拒否）。受信側はrecordを送信隣接を次hopとする通常の経路広告として`RouteTable::consider()`へ渡し、送信側は有限metricのrecordを出す前にFDを更新する（`mark_advertised`）。したがってROUTE_REQUESTは採用可能条件を迂回しない。golden vectorは[route_request.json](../../protocol/golden/valid/route_request.json)（C++ encoderとRust generatorのpayload一致をtest_routing_scaleで確認）。host（Rust）はこのpayloadを解釈しない。

### GROUP_DATA（type 25）とGROUP_REPORT（type 26）：group配送

新規type 25／26を割り当てた（headerは不変、[設計](../design/sdk-v1/group-delivery.md)）。gateway-scoped profileでのみ使い、送信元は設定済みroute gatewayに限る。

**GROUP_DATA**はhopごとのlink保護に加え、end保護を**group scope**（`SecurityScope::Group`＝2、sender＝origin、receiver＝`kBroadcastNodeId`（site group domain）。宛先groupはend AADで認証）で行う。headerの意味：

| field | 値 |
|---|---|
| destination | group address＝`0xFFFF_FFFF_FFFF_0000 + group_id`（group 0は予約、`0xFFFF`＝ALL＝`kBroadcastNodeId`）。このnamespaceのNodeIdは機器に付けない |
| message sequence | bit63を立てたgroup stream番号（送信元boot sessionごとのu32）。unicastのMessage IDと衝突しない。end AADで認証済みなので、各nodeは**開封前に**重複排除と順序判断ができる |
| delivery | RELIABLE |
| delivery_round | bit0〜6＝round番号（0＝初回、1以上＝repair）、bit7＝REFRESH（全relayが全ての子へ再送し、部分木を新しく数え直す）。hop可変field |
| hop_remaining | 子への転送ごとに1減る（通常のforward） |

end保護されたpayloadは`flags u8 ‖ アプリpayload（0〜127B）`。flagsはbit0 ORDERED、bit1〜2 優先度（0 Bulk〜3 Urgent）、他は0（それ以外は拒否）。送信元はend層を**1回だけ**封止し（`wire::seal_group`）、全ての子・全てのroundはlink層だけ作り直した同じend暗号文を運ぶ。受信側は`wire::open_group`で開く（宛先への束縛はない。`open_end`はgroup frameを拒否する）。各子へは1台ずつMAC ACK付きunicastで送り、HOP_ACCEPTは使わない。

**GROUP_REPORT**はROUTE_UPDATEと同じlink保護のみの1hop frame（子→木の親、`hop_remaining=1`、destination＝next_hop）。固定29B＋missing_count×8B、big-endian：

| offset | field | 型 | 意味 |
|---:|---|---|---|
| 0 | source | u64 | group messageの送信元 |
| 8 | session | u32 | 同Message IDのsession |
| 12 | sequence | u64 | 同sequence（bit63必須） |
| 20 | round | u8 | 応答するround番号（REFRESH bitなし） |
| 21 | flags | u8 | bit0 NOT_CHILD（別の親に従っている：countsは全て0）、bit1 TRUNCATED（missing_total＞missing_count）。他は0 |
| 22 | delivered | u16 | 送信元以下の部分木で、memberとして受理したnode数 |
| 24 | nonmember | u16 | 届いたがmemberでないnode数 |
| 26 | missing_total | u16 | 部分木で未確認のnode数 |
| 28 | missing_count | u8 | 続くid数（最大12） |
| 29 | missing | u64×n | 未確認nodeのid |

decoderは長さの完全一致、予約id（0とgroup namespace）の拒否、NOT_CHILDのcounts＝0、TRUNCATEDとcountの整合を検査する。golden vectorは[group_data.json](../../protocol/golden/valid/group_data.json)（relayでのforward込み）と[group_report.json](../../protocol/golden/valid/group_report.json)。Rustは`host/routeloom-wire/src/group.rs`が同じbyte列を生成・解釈する。

永続化するTX counter record（32B、layout 2）とreplay floor record（layout 2）も32bit epochへ移行した。v1のrecordは推測で拡張せず`IntegrityError`で拒否する（fail closed）。v1 firmwareを書き込んだ機器をv2へ更新する際はNVSを消去する。

## 8. 凍結しなくても守る接続契約

[semantics.json](../../protocol/semantics.json)が状態許可と保護範囲を定義する。numeric type IDとfield幅はWire v2として凍結済み（type IDは`frame_numeric_ids`、end AADの順序と幅は`end_aad_fields`）だが、crypto suiteは未凍結のまま残し、意味の規約と本番Profileを混同しない。

end不変部はNetwork、origin、Message ID、固定終端、配送契約、元の最大寿命、payload。hop可変部は前後hop、残hop、残forwarding予算、round、hop crypto counter。可変fieldをend AADへ入れて中継で破壊しない。remaining予算をhop側だけで保護する場合、侵害Relayによる虚偽の延長は終端の独立した時刻／認可検査がない限り完全には防げない。

Provider変更時は終端contextとdestination bindingを再検証する。Message ID不変でも新しいAADを同じnonceで再暗号化しない。実encoderは88B header＋128B payload＋2×16B tag＝248Bが250Bに収まることをstatic_assertとgolden vectorで確認済み（test cipher使用）。本番crypto Profileでの再検証はG-SECに残す。122Bは実証済み長ではなく予算。

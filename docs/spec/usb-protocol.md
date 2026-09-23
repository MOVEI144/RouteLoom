# USB／Serial transport契約

改訂1.2。フレーミング・認可・creditの意味を定義する。最終field offset／暗号Profile／IDLは未凍結。Rust host codecと携帯可能C++ device bridge（session、credit、MeshNode統合）は実装済みで、`protocol/usb-golden`の共有vectorでbyte相互検証済み。ただし開発profile認証であり、実USB driver・HIL・本番Profileは未認定。

## 1. フレームと境界

COBS＋0 delimiterを基準。decoded最大4096B、body最大はheader・保護・CRCを差し引く。CRCはCRC-32/ISO-HDLC（reflected polynomial 0xEDB88320、init/xorout 0xFFFFFFFF、check("123456789")=0xCBF43926）、他fieldと同じくbig-endian32bitで末尾へ置く。CRC対象はdecoded CRC直前のbytes、CRC自体とCOBSは除く。CRCは認証ではない。

最大符号化長は保守的にn+floor(n/254)+2（delimiter込み）。decoded overlengthを検出しても次delimiterまで有界に捨て、再同期する。部分frameは最後のbyteから1000msで破棄する。実USB伝送速度と相互待ちで達成可能かを認定する。

bootログ混入へ同期復旧は必要だが、通常binary streamへprintfを流さない。4096B USB frameをそのまま250B RFへ送れるとはしない。

## 2. 認証とsession

HELLOは未認証。device/host credential、nonces、protocol範囲、選択版、期待Node、Network scope、host principal/roles、boot、capability digestを認証transcriptへ結び付ける。AUTH後の全COMMAND・DATA・CREDITもそのsessionの完全性とreplay保護を必要とする。

firmware hashの自己申告はattestationではない。COM番号やUSB serial文字列を機器本人証明にしない。Networkを切り替える場合も認証scopeと再認可を確認する。未認証のCREDITを送信許可として処理しない。

再接続は新sessionで、partial frame、grant、consumed、request tokenを再使用しない。stable Message IDやhost idempotency identityだけを明示的に再照会する。認証方式と最終byte vectorはG-SEC/G-USBに残す。

現行実装は**EXPERIMENTALな開発profile**として、共有secretと決定的なtranscript結合MAC（label分離domain、u64 wrap演算）でHELLO/AUTH/session frame tagを検証する。本番Identity・真正暗学suiteではなく、G-SECの責務である。

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

`0x50`にはすぐ受理結果の`0x51`を返す（`Ok`＋その時点のsummary、または拒否：`Unsupported`＝未attach・flat profile・gateway以外、`Busy`＝source表満杯／node停止中、`Invalid`＝引数、idとcountsは0、`reason`に理由）。受理したmessageが終端状態になると、同じrequest idで**FINAL付きの`0x51`をもう1回だけ**送る。この対応付けはsession単位（最大3件＝node側のsource表と同数）で、再接続後のhostは`0x52`で読む。機器が既に回収したidへの`0x52`は`Ok`／state 0／`NOT_FOUND`。flagsはencoderが導出し、decoderは不一致・予約id・印字不能reasonを拒否する。このnodeが**受信した**group messageは通常の`DataFromMesh`（sequenceのbit63でgroupと分かる）で届く。共有vectorは`protocol/usb-golden/group-ops`（2 node gateway-scoped meshでのC++ bridge replayとRust codec）。daemon API1への公開は未実装（設計のfollow-up）。

[Host](host.md)／[Wire](wire-protocol.md)／[電源断](crash-time-resources.md)

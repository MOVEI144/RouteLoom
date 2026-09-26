# 02 — 本文を取得する受信API（Issue #7）

## 1. 採用方式

既存daemonにNetwork単位の有界ReceiveLogを追加し、`messages.read`によるcursor付きpollのみを初期採用する。EVENTSは診断のまま、TUIも観測者のまま。別のメッセージbroker、各利用アプリ用の全件コピー、push購読基盤は作らない。

既存DataFromMeshのorigin(8)+session(4)+sequence(8)+本文を、認証済みUSB sessionのNetwork・Gatewayと結び付ける。受信前の長さ/認証検査は維持する。初期はGatewayを無線の終端とする**gateway_mirror**であり、PCサービス終端を名乗らない。

## 2. レコードと具体例

```json
{"v":1,"network":"0000000000000001","gateway":"0000000000000002","origin":"0000000000000003","message":{"session":"00000004","sequence":"0000000000000005"},"payload_hex":"00ff80","payload_len":3,"cursor":"opaque-token","endpoint_kind":"gateway_mirror","evidence":"HOST_RAM_RETAINED","assurance":{"profile":"UNKNOWN","origin":"unverified"}}
```

本文はbyte列。非UTF-8や0x00を変換・置換しない。現行 USB 受信本文にフレームごとの security profile と origin↔credential 検証結果がないため、assurance は Site Authority／台帳の状態にかかわらず `UNKNOWN`。これは検証失敗ではなく、host に検証証拠が届いていないことを表す。将来は gateway が認証済みの結果を伝え、payload 内の自己申告をコピーしない。

```text
API1 {"v":1,"request_id":"r1","method":"messages.read","params":{"network":"0000000000000001","from":"earliest","limit":32}}
API1 {"v":1,"request_id":"r2","method":"messages.read","params":{"network":"0000000000000001","cursor":"<前応答のnext_cursor>","limit":32}}
```

成功応答のresultは`records[], next_cursor, oldest_cursor, tail_cursor, more, retention{seconds,entries,bytes}`。最初の要求はfrom=earliest/latestを明示しcursorとは排他。latestは現tailを返し過去レコードを返さない。limitは1〜32、既定32。空の正常応答は「現在追加なし」であり、過去の欠落なしという追加保証ではない。

## 3. Cursor契約

opaque tokenのdecoded値はversion、Network、ACL view revision、ReceiveLog epoch128bit、last_scanned_sequence64bit。上限96B、base64url（paddingなし）。tokenは権限ではなく位置表現であり、毎回OS主体のACLを再確認する。初期版はNetwork全体への権限のみでorigin filterなし。異なるview間のcursor流用を拒否する。

ReceiveLog epochは起動時に新しく作る。seqは1から単調増加し、そのepoch内で再利用しない。daemon再起動でRAM logが失われたら新epoch、旧cursorはCURSOR_EPOCH_CHANGED。永続受信logは後続機能であり、RAM版に対して耐電断を要求したらUnsupported。

| 入力/状態 | 応答と利用者の次の操作 |
|---|---|
| 範囲内cursor | 指定位置の次から最大limit。再要求は保持範囲内で同じ本文を返せる |
| 同じ応答を二度受信 | 同じcursor/MessageKey。利用者が重複排除する |
| 古いcursor（次位置が現oldestより前） | CURSOR_GAP、欠落sequence範囲、oldest/tail。自動で先へ飛ばさず明示fromを要求 |
| 別epoch | CURSOR_EPOCH_CHANGED、loss_count=null。前epochの件数を捏造しない |
| tailより未来/構文不正 | INVALID_CURSOR。番号を丸めない |
| Network/ACL viewが違う | CURSOR_SCOPE_MISMATCH/AuthorizationFailed |
| USB再接続のみ | daemon log epochは維持。既存cursorは継続可 |
| 利用者が遅い | その利用者だけGAP。別利用者のlog/USBは止めない |

同じMessageKey・同じ不変payload hashの重複は60秒のdedup範囲内なら同じレコードへ集約する。異内容はCONFLICTを診断し本文を上書きしない。dedupとlog retentionは別資源であり、60秒を超える重複を無期限に排除したとは言わない。

## 4. 容量・解放・欠落

1 Network当たり4096レコードかつ2MiB、最大保持300秒、record課金512B、最大4 Networkかつ全体8MiB。最初に到達する上限で古いReceiveLog recordを回収できる。これは再取得用RAM観測履歴であり、無線の保護中dedup記録とは別。回収境界をsequenceで保持するため遅い利用者はGAPを検知できる。

32接続まで、主体ごと4接続、同時read1/接続、応答65536B、待ち書込み最大2秒。遅いsocketは切断し中央ReceiveLogをpinしない。取得処理はbounded batchをコピーしてlockを解放してからsocketへ書く。payloadへのアクセス権を持たないTUIには要約だけを返す。

USB→Hostに届く前のlossはcursorだけでは検知できない。新しいrx_events_v1 capabilityではDataFromMeshを既存形式と混同しない選択済みschemaへ拡張し、`gateway_boot_lease128 + rx_event_seq64`を付ける。Gatewayのイベント入場番号はqueue投入前に進め、dropは後続gap/counterで報告する。最後のdrop後に通信が止まった場合、全件数を証明できないためcoverage=unknown。旧firmwareではingress_loss_observable=falseを返す。

拡張bodyはformat:u8=1、bootlease16、eventseq:u64、origin:u64、session:u32、sequence:u64、length:u16、payload[0..128]（47+payload B）。Networkはsessionへ結合。未交渉相手へこのbodyを旧20Bヘッダとして送らない。新形式を認証後かつ長さ検証後だけ採用する。

## 5. 受領境界

GatewayのEND_RECEIPTはGateway SDKまで。Hostが受信してRAM logへコピーできたことをHOST_RAM_RETAINEDとする。アプリへのsocket書込み、アプリでのread、アプリでの保存、処理成功は同じでない。

RAM logが溢れて古い観測履歴を失っても、すでに発行したGateway受領証拠をPCアプリ受領証拠にすり替えない。PCサービスを本当の最終宛先にする将来profileは、service lease、PCの受理予約、終端credential、PC側receipt発行まで必要。この設計の初期capabilityはpc_service_destination=falseで要求拒否とする。

耐電断受信はUnsupported。アプリが業務DBへ保存することは禁止しないが、SDKがそのDBを所有・検証しない。アプリread-ACKを追加してexactly-onceを名乗る案も採らない。

## 6. 実装と互換性

`routeloom-host::DataFromMesh`処理にbounded ReceiveLogを接続し、IPC methodだけを追加。既存EVENTS/DELIVERIESは診断互換として残す。`routeloomctl receive --network ... --cursor ...`は新APIの薄いclient（まだ未実装）。TUIに独自USB接続を作らない。

受入：RX01〜RX08。0/1/128B、非UTF-8、二重読出し、履歴expiry、daemon/USB別再起動、32clients、遅いreader、別Network、偽assurance、不正長、Gateway側dropを共通fixtureにする。初期CLIで空hex引数を表せない問題は新APIのlength=0で処理し、旧CLIで黙って落とさない。

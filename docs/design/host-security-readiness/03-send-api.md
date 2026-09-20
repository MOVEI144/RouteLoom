# 03 — 条件付き送信と同じ依頼の追跡（Issue #8）

## 1. 採用API

先に`operations.open_epoch`で現在の受付epochを取得し、callerが選んだ128bit keyを`messages.submit`へ渡す。単純なCLIは新規keyを生成して表示してよいが、ライブラリはcallerのkeyを勝手に変更しない。再提出は同じepoch/key、照会はOperationIdまたはepoch/keyで行う。

```text
API1 {"v":1,"request_id":"s1","method":"messages.submit","params":{"network":"0000000000000001","admission_epoch":"0000000000000012","key":"00112233445566778899aabbccddeeff00","destination":{"kind":"node","id":"0000000000000003"},"payload_hex":"00ff80","payload_len":3,"options":{"delivery":"RELIABLE","priority":"NORMAL","ttl_ms":5000,"deadline_policy":"WALL_ELAPSED_VALIDITY","storage":"HOST_DURABLE","hop_limit":10}}}
```

受付応答例：`{"v":1,"request_id":"s1","ok":true,"result":{"operation_id":"<store-lineage128>:0000000000000001","dispatch_state":"HOST_QUEUED","evidence":["HOST_DURABLE_RETAINED"],"message_key":null}}`。これは配送完了ではない。受付応答喪失後は`operations.get_by_key`へ同じscope/keyを渡す。

## 2. Options表

| 項目 | 既定/範囲 | 初期対応・SDKへの写像 |
|---|---|---|
| destination | 必須、Nodeまたは明示Gateway | 既存NodeId。service/anycast/failoverはUnsupported |
| payload | 必須hex、0〜128B | bytesを変換せずsend |
| delivery | RELIABLE | 既存0/1に対応。APPLIED=2は#12完成・両端cap確認までUnsupported |
| priority | NORMAL | 既存Normal=1。P0にenumがあるだけでは他priorityを広告しない。scheduler統合・認可・試験後のみ追加 |
| ttl_ms | 5000、1〜30000 | Host受付からの総予算。bridgeは残予算をSendOptions.lifetime_msへ |
| deadline_policy | WALL_ELAPSED_VALIDITYのみ | 経過不明はTimeUncertain、再接続で延長なし |
| storage | HOST_DURABLE | HostのローカルStoreを要求。未実装/保存失敗は拒否。RAM_ONLYは明示opt-inで別保証 |
| hop_limit | 10、1〜10 | 既存SendOptions.hop_limit。3hopを保証する数ではない |
| persist_across_sleep | false | 本版のHost APIではtrueはUnsupported。Host保存と端末Sleep保存を混同しない |

`HOST_DURABLE`はHost受付・結果の耐電断保存であり、Gateway・中継・宛先アプリの耐電断ではない。永続化できないdaemonでRAMへ黙って降格しない。現行SENDは明示legacy modeで維持できるが、強い再照会・長期key保護を広告せず、新API側へ古い受理を移植しない。

## 3. 意味の一致とCONFLICT

operation identityは`(OS/ACLで認証したprincipal, Network, SEND, admission_epoch, caller_key)`。同一identityの既存recordを最初に調べ、同じnormalized requestなら最新状態と同じOperationIdを返す。異なるならCONFLICT。閉鎖済みepochでも保護中の既知key照会/同一再提出は可能だが、新しいkeyの受付は禁止。

canonical_requestは以下を順に固定幅big-endian連結する：schema:u8=1、network:u32、destination_kind:u8（Node=0/Gateway=1）、destination:u64、delivery:u8、priority:u8、deadline_policy:u8=0、storage:u8（RAM=0/HOST_DURABLE=1）、ttl:u32、hop:u8、persist_sleep:u8=0、payload_len:u16、payload。**26+payload B**。SHA-256をhashに使う。

省略optionsは既定補完後に比較、hex大小文字はbytesとして同一。JSON object順序、request_id、USB request、採番時刻、queue残時間はhashに入れない。再提出のttlは元の要求値のままで、再受付して時刻を更新しない。unknown optionや型違いは比較前に拒否する。

## 4. DeadlineをUSB越しに守る

Host受付時刻Hと期限D=H+ttlを保存。Host待ち、USB待ち、再認証、RF再送を全て引く。HostとESP32の単調時計は直接比較しない。

保護sessionの時刻照会でdevice時刻dがHostの[h0,h1]間に採られたと分かる時だけ、保守的なdevice期限 `d + max(0,D-h1) - drift_margin` を使う。時刻mappingの有効期間は5秒、許容時計誤差は実装profileの測定上限（初期設計1000ppm＋量子化1ms）。時刻応答を遅らせれば残寿命は減るだけ。下限を選ぶことで転送待ちを無料にしない。

新SUBMIT bodyはdevice_boot_leaseとdevice_deadlineを持ち、deviceは受信後もqueue/pop時に比較する。CPU停止やUSB buffer滞留で遅れた要求も期限後は出さない。TimeSampleは保護session、boot、query nonceへ結合し、順不同/旧sampleを拒否する。USBの最大遅延を仮定して単に固定100msを引く方式は採らない。

Cold rebootで経過時間の上界を得られなければ、未dispatchのdurable要求はTIME_UNCERTAINで保留、dispatch済みは結果照会のみ。新しいbootへ元のttlを付け直して再送しない。明示したtrusted checkpointを後で得る場合も上界だけを引く。API期限は新規送信を止める契約で、侵害Relayや物理作用の期限を無条件に保証するものではない。

## 5. 状態・取消・遅い証拠

| 状態 | 意味と許可操作 |
|---|---|
| HOST_QUEUED | Storeへ受付確定済み、未dispatch。get/cancel可能 |
| DISPATCH_PREPARED | Gateway/BootLease/seq/hashを永続記録。外部送信直前または送信有無不明 |
| GATEWAY_ACCEPTED | 安定MessageKeyが判明。再接続は照会のみ、別keyで再発行しない |
| END_SDK_RECEIVED | 正当な最終SDKの受領証拠。APPLIEDの成功ではない |
| EXPIRED_BEFORE_DISPATCH / CANCELLED_BEFORE_DISPATCH | 外部送信開始前だと証明できた終端 |
| REJECTED_NOT_ACCEPTED | 対象Gatewayが入場前拒否と証明した結果 |
| INDETERMINATE | 送信/作用の有無や結果が不明。失敗したので自動再実行とはしない |
| TIME_UNCERTAIN | 残寿命を証明できない。新dispatch禁止 |

IPC writeが戻っただけでGATEWAY_ACCEPTEDを出さない。BEST_EFFORT完了は`MAC_ATTEMPT_REPORTED`等の証拠で、END_SDK_RECEIVEDへ上げない。late receiptは同じOperationIdへ追記し、`observation.deadline_elapsed=true`も残す。

cancelはdispatcherと同じ状態transactionで線形化する。USBへの外部writeが始まる前だけCANCELLED_BEFORE_DISPATCH。開始済みはCANCEL_TOO_LATE/INDETERMINATEとし、遠端undoを約束しない。getはread-onlyで保持期限を延長しない。

## 6. USBとSDKへの写像

既存COBS/CRC外枠、保護session、累積creditを維持。`host_ops_v1`を相互に交渉した場合だけ既存Command kind内のsubcommandを使う。旧DataToMeshに新bodyを足さない。

提案subcommand：0x01 SUBMIT、0x02 QUERY_DISPATCH、0x03 RETIRE_THROUGH、0x04 SKIP、0x05 TIME_SAMPLE。実装開始時に共有USB正本へ一回だけ登録する。識別済み別subcommandと衝突したら本設計を改訂し、勝手に別番号を採らない。

SUBMIT bodyの順序：schema:u8、subcommand:u8、boot_lease:16B、dispatcher_id:16B、dispatch_seq:u64、operation_id:24B、canonical_hash:32B、device_deadline:u64、canonical_length:u16、canonical_request。固定部108B、最大262B。無線payloadはこの中の0〜128Bだけ。4096B USB frameの上限内だが、262Bを無線250Bへそのまま送る設計ではない。

RECEIPTには同じdispatch identity/hash、入場結果、MessageKey、証拠の段階を含める。QUERYには読出し以外の副作用を持たせず、過去cache消失時はNOT_RETAINEDとして再実行しない。全要求のcounter割当・seal・実writeは既存の一つのwriterに統合する。

## 7. 後続実装条件

HostからC++ sendまでの条件が働く結合試験を追加する。旧daemon/旧deviceはlegacyのみ、新daemon/旧deviceは新API Unsupported、新同士でもversion/cap/boot不一致は拒否。PR #6の型追加だけでAPI実装済みとしない。

受入：TX01〜TX10。要求正規化、同時同key、異条件CONFLICT、response直前切断、USB再接続、daemon/device別再起動、遅延時刻応答、期限後USB到着、取消race、late receiptを固定fixtureへする。

# 07 — APPLIED配送と結果照会（Issue #12）

## 1. 意味と後続化

APPLIEDは宛先アプリが定義した結果まで確認する配送。機器の物理動作、業務DB、一般的なexactly-onceをSDKが判定・保証するものではない。初期のHost APIはRELIABLEまででよく、アプリ自身が別RELIABLE messageで結果を返信する使い方も維持する。

既存DeliveryClass::Applied=2、FrameType::AppResult=19を使う。別protocol番号を作らず、未対応の間はsendでUnsupported。END_RECEIPTはSDK受領のままで、callbackがreturnした理由で成功へ昇格しない。

## 2. 終端と送信側の状態

| 終端state | 処理・停止時の扱い |
|---|---|
| RESERVED | ingress/dedup/実行ticket/結果保存枠を一括予約、未受理 |
| ACCEPTED | 受付記録commit済み。END_RECEIPT可能、アプリは未dispatch |
| DISPATCH_INTENT | アプリへ渡す意図を記録。これ以後のcrashは実行有無不明になり得る |
| EXECUTING | callbackへ通知済み。SDK taskを待たせない |
| RESULT_COMMITTED | 成功/失敗結果を保存した。再送はこの同一結果だけ |
| EXPIRED_UNDISPATCHED | dispatch前だと証明できる期限切れ |
| INDETERMINATE | 作用有無/結果不明。自動再dispatchしない |

送信側はEND_SDK_RECEIVED→APPLICATION_PENDING→APPLICATION_SUCCESSまたはAPPLICATION_FAILURE。期限/取消で結果を失った場合はINDETERMINATE。遅い正当な結果は同じOperationId/MessageKeyへ追記し、lateという観測も残す。

正常：DATA→終端受付→END_RECEIPT→非同期アプリ→結果保存→APP_RESULT→RESULT_ACK。アプリ失敗も同じ経路で失敗結果を運ぶ。無応答はSDK成功へ変換しない。

## 3. C/C++ APIと所有権

受信APPLIEDに対し、SDKは`rl_application_request_t`（version/size、完全なMessageKey、宛先、request_digest32、残期限、payload view、opaque result ticket）を専用app executorへ渡す。ticketはNetwork/origin/MessageId/destination/要求hash/実行世代に結合し、呼出者は捏造できない。payloadはcallback内有効、保持するなら明示copy/retainしてquotaを使う。

提案API：`rl_report_application_result(ctx, ticket, result, out_token)`。resultは`struct_size, version, outcome(success/failure), application_code:u32, data:length+bytes[0..48]`。受付時にSDKがcopyし、完了は結果保存eventで返す。呼出しが成功してもoriginへ配送完了した意味ではない。

存在しないticketはNotFound、別Network/主体はAuthorizationFailed、古い実行世代はStale、同じ結果は既存token/状態、異結果はConflict、長さ超過はPayloadTooLarge、結果保持終了はResultWindowExpired。最初のcommit済み結果を二回目で上書きしない。エラー値はP0の共通Statusへ追加登録し、CとRustで別番号を発明しない。

app callback内はnonblockingなresult受付/照会を許すが、同期send待ち・sleep・NVS長時間commitはしない。結果保存workerとradio進行は分離し、queue満杯は明示返却。アプリが結果を永続化する前に外部機器へ副作用を起こす場合、その間のクラッシュは原理的にSDKだけで解決できない。

## 4. Wire payload（提案固定表）

AppResult=19のbody内subtypeを1=RESULT、2=QUERY、3=RESULT_ACK、4=STATUSとする。数値は共有正本へ登録し、Wire v1のheaderや他typeを振り直さない。いずれも通常DATA同等のhop/end保護を必須とし、memberのhop鍵だけで最終発行者を認めない。

RESULT body順序：version:u8=1、subtype:u8=1、outcome:u8(0success/1failure)、flags:u8=0、network:u32、original_origin:u64、original_session:u32、original_sequence:u64、original_destination:u64、request_digest:32B、application_code:u32、result_len:u16、result[0..48]。固定部74B、最大122B、二層保護を含むWireは88+122+32=242B。

QUERY/ACK/STATUSは共通の先頭68B（application_code直前まで）を利用し、outcome欄はQUERY/ACKで0、STATUSでpending/indeterminate/expired/not-retainedを区別。QUERY末尾にquery_nonce:u64（計76B）、ACK末尾にresult_digest32（計100B）、STATUS末尾にquery_nonce:u64（計76B）。各subtypeの長さを個別に検査する。RESULTの74B条件でQUERYを捨てる実装にしない。

original MessageKey、Network、要求の不変digestと固定destinationをE2E主体へ結び付ける。digestはAPPLIED要求の元DATA不変header＋元payloadのSHA-256（mutable next-hop、round、残期限、link counter除外）。Host canonical request hashとは別で混同しない。NodeIDだけ一致してもcredential/Grantの対応が違うなら拒否する。

結果のWire originは元の実行宛先、Wire destinationは元の送信元。QUERYは逆方向。AppResult carrier自体はAPPLIED要求にしない。必要なHOP_ACCEPTはあるが、RESULT_ACKへ終端ACKを再帰生成しない。

## 5. 再送・照会・容量

同MessageKeyのDATA再送は、処理中なら同じ受付状態、結果ありなら同じAPP_RESULT、crash不明ならINDETERMINATEを返す。再送を新しいapp callbackへ渡さない。新しい経路は許可するが、実行する宛先の変更は既定禁止。

結果送信は初回込み最大3回、originによるQUERYは最大2回。双方のretryは元deadline＋late窓の同一終了時刻で打ち切る。RESULT_ACKを失った場合も保存結果を再送するだけでアプリを再実行しない。queryは既存記録を読むだけでcache寿命や仕事を作り直さない。

profile：処理中4件、結果cache32件、record設計予算256B=8KiB、result最大48B、通常message最大寿命30秒、late result30秒、終端dedup/結果記録の最低保持60秒。受付時に結果枠を予約し、保護中を追い出して新規受付しない。この容量は全nodeへ強制せず、未搭載profileはAPPLIED capability=false。

deadline後でも、期限内に正当にdispatchされた仕事はlate30秒窓内で結果報告可能。ただし新規実行は開始しない。snapshot後の待機・Sleepを含む時刻を減算し、time unknownで期限を復活させない。遅い結果がwindow後ならResultWindowExpired、アプリは独自の結果通信を利用できるが同じSDK cacheが残る保証はない。

## 6. RAMとdurable終端

RAM_ONLYは同boot内の重複処理抑止だけ。冷再起動時に古いAPPLIEDを新しい仕事として再実行しないよう、宛先execution_boot_leaseを要求digest/結果ticketへ結び付ける。初回要求前に認証済みleaseを照会し、旧leaseの要求はStale/Indeterminate。sourceは新leaseへ同じ論理依頼を自動移さない。payload予算に追加16Bが必要な場合はAPPLIED request上限112Bとしてcapabilityを下げ、通常RELIABLE128Bを削らない。

DURABLE_TERMINALは受理枠予約→受付record commit→dispatch intent commit→app callback→result commit→result送信。旧recordのhash/epochが不明なら隔離し、台帳を空にして再実行しない。DISPATCH_INTENT以降で結果が未保存のcrashはINDETERMINATE。アプリ側の照会・冪等な業務キーがなければ自動解決できない。

RESULT_COMMITTED後の再起動は同じ結果を再送できる。recordの保存と実際の外部機器への作用を一般的な一つのtransactionと呼ばない。RAM_ONLY/DURABLEを送信時に相互capabilityで選び、拒否を勝手に降格しない。

## 7. Host接続・互換性

Host operationsのAPP evidenceとして同じOperationIdへ対応づける。Hostアプリを実終端にするpc_service_destinationは#7初期版ではUnsupportedのため、本機能の最初の実行対象はNodeアプリ。Gateway上で実行した結果をPCアプリ実行結果と呼ばない。

`operations.get`はapplication_outcome、code、result bytes、late、evidence profileを返す。結果の最終発行者を許可集合に照合する。APPLIED非対応old nodeへ要求する前に拒否、old RELIABLE/BEST_EFFORTの受付/receiptは変更しない。

受入AP01〜AP10：成功/失敗/無応答、二重報告/矛盾、不正発行元、DATA/RESULT/ACK喪失、同IDでの再接続、全保存境界のcrash、cold boot lease差、期限/取消、結果満杯、旧版拒否。fixtureはpayload表現の設計例で、C++/Rust codecや暗号vectorの実行済み証拠ではない。

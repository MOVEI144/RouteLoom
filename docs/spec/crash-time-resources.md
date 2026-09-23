# 電源断・時刻・受理資源の横断契約

改訂1.1。独自の暗号方式を定義する文書ではない。Storage/Security/Delivery/Powerが同じ順序で失敗を扱うための規範。

## 1. 送信nonceの予約

予約recordは `(context_id, key_epoch, direction, high_water_exclusive, record_generation, integrity)`。Storage Providerの一つのlogical atomic recordとしてcommitする。複数NVS keyの個別書込みを任意transactionのatomicityと呼ばない。

1. 現在のhigh-water Hを読み、上限overflowを検査する。
2. 次区間[H,H+B)のend=H+Bを耐電断commitする。予約blockの初期候補B=256、suiteのcounter上限が優先。
3. commit成功後だけRAM cursor=Hから使用する。保存応答が不明なら使用しない。
4. 再起動後は旧予約の未使用分も捨て、保存されたendから次区間を予約する。

commit前に落ちれば未予約区間では一度も送っていない。commit後・利用前ならその区間を捨てるだけ。利用中に落ちても次はend以降。失敗時にcursorを0へ戻さない。counter枯渇は新contextへ正規再確立する。

Message ID、round、crypto counterは別。保存済み同一ciphertextをそのまま再送することと、新AAD／平文で同nonceを再利用することを分ける。宛先が変わったend保護は新context／新counter条件を満たす。

## 2. 受信replayと破損

受信windowまたはkey/contextの整合性が不明ならそのcontextでDATAを受けず、相互再確立する。Deep Sleep RTCが完全に検証できる場合の継続と、cold bootでの損失を区別する。

| store | 破損／整合性不明時 |
|---|---|
| 秘密鍵・membership | SECURITY_RECOVERY_REQUIRED。無認証再Joinへ降格しない |
| nonce予約・rx replay | 旧contextを無効化。正規再確立までDATA禁止 |
| Authority/voter | 管理発行／投票停止。QUARANTINED_NON_VOTER等 |
| route frontier | 当該sourceの選択・有限広告停止。回復はrouting.md §11のorigin generation＋tombstone dwell規則で行う（portable model凍結） |
| spool/dedup | 該当record隔離、結果不明通知。別IDの新イベントにしない |
| 単なる候補cache | 廃棄して再探索。ただし鍵・所属まで消さない |

完全な古いsnapshotの悪意ある復元はCRCだけでは検出できない。この小モデルのpower-cut試験はその攻撃へのantirollback証明ではない。

## 3. 期限

既定WALL_ELAPSED_VALIDITYは停止時間も寿命に含む。通常message寿命は最大30000ms、roundでも延長しない。portable coreの送信API（`send`／`send_applied`／`resume_delivery`／`send_service`／`resend_service`）は30000ms（`kMaxMessageLifetimeMs`）を超える寿命を短縮せずInvalidArgumentで拒否する。信頼できる経過時間の区間が[lo,hi]ならremainingからhiを差し引く安全側判定を使う。hiが寿命を超えたらEXPIRED（安全側）で送信しない。区間そのものが得られなければTIME_UNCERTAINで保留し、経過不明を0にしない。

RUNNING_TIME_ONLYを明示的に選ぶ場合は停電中を数えない別契約。古い副作用命令への既定にせず、終端も最大保持・認可条件を受け入れたprofileでだけ提供する。非対応ならUNSUPPORTED。

受信時の残forwarding予算だけでは、侵害Relayの虚偽や完全停止中の時間を証明できない。厳密な終端有効期限には独立に信頼できる時計／checkpointまたはアプリ照会を要求する。

## 4. dedup・receiptと副作用

max lifetime30000ms＋late result30000msを通常retentionの設計値60000msとする（`kTerminalRetentionMs`。APPLIED結果保持、gateway receipt保持も同じ値から導出し、60000のliteralを散在させない）。retentionは初回受理からで、duplicateで無限延長しない。接続context、入場rate、容量も制限する。期限前のprotected entryはLRUで追い出さない。時間不明の記録はそのまま容量を占め、新規admissionを止め得る。

dedup記録の保持は役割で分ける（issue #39）。期限はadmission時に `min(初回受理＋60000ms, horizon＋slack)` で決め、horizonは受信frame自身の残forwarding deadline（hop滞留を差し引き、30000msで頭打ち）とする。

| 役割 | 責務 | slack | 最長 |
|---|---|---|---|
| 終端（自ノード宛DATAのpin） | アプリへのexactly-once。originの最終round・sleep復帰再送は全てorigin期限以前に届くので、期限後もlate result分保持 | 30000ms | 60000ms（max lifetimeのmessage） |
| 非終端（中継の転送DATA・END_RECEIPT、originが消費したreceipt、component宛routed） | 同roundの二重forward抑止・再ACKと下流TransitFailureの中継。frameが有効な間だけ（routedはcomponent側dedupが二段目） | 5000ms（報告予算3000ms＋drain余裕） | 35000ms |

中継記録を60000ms固定にすると、Reliable 1件でDATA＋END_RECEIPTの2記録を消費するため64記録の中継上限は約0.5msg/sだった。frame期限基準（既定寿命5000msで約10秒）では1中継の定常占有は約 `2×r×(L＋5秒)`、終端pinは約 `r×min(L＋30秒, 60秒)`（r：通過message率、L：寿命）。中継記録を早く手放しても、後続nodeの記録と終端pinがアプリへの二重配送を止める（中継での余分な再forwardは有界・計数付き）。

容量はbuild時のresource profile定数とする（`dedup_entries`：leaf-small 32、relay-c3 96、gateway-s3 256。既定はrelay）。動的確保はしない。終端pinはpoolの7/8まで（残り1/8は非終端用予備）で、判定はpin数による。poolが満杯でもpin数が上限未満なら、期限切れ→Resolved→Evidenceの順で非終端記録を回収してpinを受理する。前hopごとの非終端記録は3/8までで、上限到達時はその前hop自身の回収可能な記録から回収する（他の前hopの記録は追い出さない）。転送中（Live）と終端pinは追い出さず、回収先がなければBUSY／計数付きdropで拒否する。

既定のWALL_ELAPSED_VALIDITYでは寿命は停止時間を含み最大30000msなので、送信側が60000msを超えてsleepした永続pendingは復帰時に必ずEXPIREDとなり、元IDで再送しない。受信側pinが満了した後に同じMessageが届くことはない。60000ms以内の復帰再送は受信側pin（origin期限＋30000ms）の内側に届き抑止される。RUNNING_TIME_ONLY（§3）はこの保証の外で、長時間停止後の再送は受信側pin満了後に届き得る。

同じMessageで不変payload／宛先のhashが変わればCONFLICT。終端DELIVEREDは新roundでも再適用せずreceiptを再送。同roundのduplicateは二重forwardしないが、FAILED後の新roundは再forward可能。

Durable terminalの順序：領域予約→ACCEPTED記録commit→アプリへdispatch（dispatch intent保存）→アプリ結果取得→結果record commit→APP_RESULT。dispatch intent後のcrashは実作用有無を確定できないのでINDETERMINATE。アプリの冪等処理／照会なしに自動再実行しない。真の外部作用exactly-onceとは呼ばない。

APPLIED provider failoverは既定false。変更を許すのはshared idempotency domain、または利用者がduplicate effectを明示許容した場合。routeだけの迂回はprovider変更ではない。

## 5. 受理前の一括予約

認証済み候補DATAについて、frame・dedup・transaction・reply Peer lease・ACK queue slotを固定順で予約し、全成功時だけ受理とする。一つでも失敗したら全予約を戻し、HOP_ACCEPT・アプリdispatch・forwardを行わない。待ちながら一部だけ保持する方式は使わない。

物理Wi-Fi callbackの受信bufferはまだSDK配送受理ではない。未認証frameはcheap parse→global ingress quota→cookie/transaction→bounded assembly→暗号確認→member admissionの順。cookieだけでは機器認証ではない。

Peerはbroadcast1＋regular16＋transient3。regular pin最大12、transactionで追加保護されるPeerを含めnonbroadcast19を越えない。reply lease同時3、link transaction寿命1500msを初期上限とする（CORE_FIXED_250実装では未実装：`PeerLeasePurpose::ExpectedReply`は宣言のみで、reply lease数とtransaction寿命は強制されていない。issue #55）。ただし物理TX不明中のPeerをtimeoutだけで削除しない。TX隔離・driver停止の安全確認が先。

予約不能なら通常はBUSYを返すが、reply容量自体が無ければBUSY送信も保証しない。drop理由をローカル記録し、相手側は既存の有限retryで回復する。全接続へbroadcast BUSYを散布しない。

## 6. 試験の意味

`tests/test_contracts.py`ではcommit前後・区間利用後のcold reboot、期限不明、重複grant、予約rollback、APPLIED failover拒否を小モデルで検査する。NVSの実atomicity、暗号演算、実callback排出、真の分散routingは別の実装／HILゲート。

## 7. 寿命資源の既知上限（CORE_FIXED_250 prototype、未解決）

epoch／route generationの起動回数予算（旧#29/#48）はWire v2で32bit化して解消した（32bit boot sessionから直接導出、1分周期wakeでも約8,000年）。次の上限は現行実装の性質であり、設計変更（G-SEC／G-POWERで扱う）まで解消しない。配備判断の前提として明記する。数値はissueの概算で、実機計測ではない。

| 資源 | 現行の上限 | 主因 | 追跡 |
|---|---|---|---|
| NVS entry数 | ピアごとのcounter lease／replay floor／windowキーに削除経路がない。既定24KiB NVSで累計12〜38ピアに達すると新規通信とboot session書込が失敗し得る | 鍵とcounterの削除は再ハンドシェイク設計が前提 | #37 |
| flash書込回数 | 認証済み受信frameごとにreplay windowをcommit（終端では最大2 commit）。TX counterは256枚ごと、context溢れ時はframeごと。既定NVSでは持続10 frame/sで約1ヶ月の概算 | fail-closedなreplay永続化 | #30、#57 |
| remote config | 受理1件≈7〜8 commit。rate上限（1/min＋burst1）で連続運用すると摩耗寿命は概算1〜2年。人手運用なら問題にならない | ConfigJournalの2スロット耐電断commit | #57 |


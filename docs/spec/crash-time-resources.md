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

max lifetime30000ms＋late result30000msを通常retentionの最低設計値60000msとする。retentionは初回受理からで、duplicateで無限延長しない。接続context、入場rate、容量も制限する。期限前のprotected entryはLRUで追い出さない。時間不明の記録はそのまま容量を占め、新規admissionを止め得る。

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

次の上限は現行実装の性質であり、設計変更（G-SEC／G-POWERで扱う）まで解消しない。配備判断の前提として明記する。数値はissueの概算で、実機計測ではない。

| 資源 | 現行の上限 | 主因 | 追跡 |
|---|---|---|---|
| epoch／route generation | 起動（deep-sleep wakeを含む）ごとに16bit値を1消費。65,535回の起動でwrapし、ピアのreplay floor・route tableと自身のTX counter leaseが当該ノードを恒久拒否する。1分周期wakeなら約45日 | Wire v1のepochがu16、boot sessionから導出 | #29、#48 |
| NVS entry数 | ピアごとのcounter lease／replay floor／windowキーに削除経路がない。既定24KiB NVSで累計12〜38ピアに達すると新規通信とboot session書込が失敗し得る | 鍵とcounterの削除は再ハンドシェイク設計が前提 | #37 |
| flash書込回数 | 認証済み受信frameごとにreplay windowをcommit（終端では最大2 commit）。TX counterは256枚ごと、context溢れ時はframeごと。既定NVSでは持続10 frame/sで約1ヶ月の概算 | fail-closedなreplay永続化 | #30、#57 |
| remote config | 受理1件≈7〜8 commit。rate上限（1/min＋burst1）で連続運用すると摩耗寿命は概算1〜2年。人手運用なら問題にならない | ConfigJournalの2スロット耐電断commit | #57 |


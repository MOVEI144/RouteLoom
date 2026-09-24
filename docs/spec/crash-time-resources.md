# 電源断・時刻・受理資源の横断契約

改訂1.1。独自の暗号方式を定義する文書ではない。Storage/Security/Delivery/Powerが同じ順序で失敗を扱うための規範。

## 1. 送信nonceの予約

予約recordは `(context_id, key_epoch, direction, high_water_exclusive, record_generation, integrity)`。Storage Providerの一つのlogical atomic recordとしてcommitする。複数NVS keyの個別書込みを任意transactionのatomicityと呼ばない。

1. 現在のhigh-water Hを読み、上限overflowを検査する。
2. 次区間[H,H+B)のend=H+Bを耐電断commitする。予約blockの初期候補B=256、suiteのcounter上限が優先。
3. commit成功後だけRAM cursor=Hから使用する。保存応答が不明なら使用しない。
4. 再起動後は旧予約の未使用分も捨て、保存されたendから次区間を予約する。

commit前に落ちれば未予約区間では一度も送っていない。commit後・利用前ならその区間を捨てるだけ。利用中に落ちても次はend以降。失敗時にcursorを0へ戻さない。counter枯渇は新contextへ正規再確立する。

有限のcontext cacheから追い出されたleaseは、未使用区間[cursor,end)をRAM上のcheckpointとして退避してよい。同じcontextを再作成したとき、保存recordのidentity・high-water・record_generationがcheckpoint時点から不変である場合に限りその区間から再開し、新区間をcommitしない。他のleaseは発行前に必ず新区間をcommitしてgenerationを進めるので、不変であれば区間は未発行と証明できる。checkpointは単回使用で再起動を越えない（再起動後は規則4どおり）。checkpointを捨てることは未使用分を捨てるだけで安全側。開発PSK Providerの既定は稼働lease32件＋checkpoint64件（issue #57）。

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

rx replayの永続recordは64bit windowそのものではなく、受理済み最大値より前方に予約した上限（accepted ceiling）とする。windowはRAMに置き、受理した最大値が保存済みceilingを越えたときだけ`ceiling＝最大値＋K`（既定K＝64）を耐電断commitし、commit成功後にだけ受理を報告する。したがって受理済みcounterは常に保存ceiling以下であり、再起動（RAM喪失）後はceiling以下を全て既受理として拒否し、ceilingを越えるcounterから受理を再開する。

- commitは同一contextのcounterがK＋1前進するごとに1回。window内の順序入替え（最大値以下）はcommitしない。
- 電源断後に失うのは、ceilingまでの最大K個の新counterと、RAM bitmapにあった未着の順序入替え分だけ。送信側は新counterで再送する。
- cache追い出し・Provider closeではceilingをRAMの最大値まで引き下げ（最大1 commit）、再open時の損失を順序入替え分に限る。引下げ失敗は高いceilingが残るだけで安全側。
- 引上げ・引下げは、そのwindowが直前に読込／commitしたrecordと保存recordが一致する場合だけ書く（CAS）。同一contextの別windowが先にcommitしていれば拒否し、他windowが受理したcounterを再受理可能にしない。
- commit失敗は受理を巻き戻す（RAM windowも動かさない）。旧形式（layout 0、最大値を同じ位置に保存）のrecordはceilingとして読む。旧windowより広く拒否するだけで安全側。その他のlayoutは破損。

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

認証済み候補DATAについて、frame・dedup・transaction・reply Peer lease・ACK queue slotを固定順で予約し、全成功時だけ受理とする。一つでも失敗したら全予約を戻し、HOP_ACCEPT・アプリdispatch・forwardを行わない。待ちながら一部だけ保持する方式は使わない。終端DATAではEND_RECEIPTのTX枠もアプリdispatch前に確保する。返信経路がまだ無い場合も枠を確保し、dispatch時の再確認で経路が無ければ仕事を終結する。送信元の有限retryと終端dedupが後続roundを扱う。

物理Wi-Fi callbackの受信bufferはまだSDK配送受理ではない。未認証frameはcheap parse→global ingress quota→cookie/transaction→bounded assembly→暗号確認→member admissionの順。cookieだけでは機器認証ではない。

Peerはbroadcast1＋regular16＋transient3。regular pin最大12、transactionで追加保護されるPeerを含めnonbroadcast19を越えない。Owner全体でreply binding entryは同時3、useと受理transactionは各8、transaction寿命は受理時から最大1500ms（frame自身の残予算が短ければそちらを優先）。同じbindingの複数useはentryを共有する。期限時は仕事を終結してからuseを解放し、Stale中も予約済み返信とdriver登録を保持する。rebind・revokeでは旧bindingの新規送信を拒む。ただし物理TX不明中のPeerをtimeoutだけで削除しない。TX隔離・driver停止の安全確認が先。

予約不能なら通常はBUSYを返すが、reply容量自体が無ければBUSY送信も保証しない。drop理由をローカル記録し、相手側は既存の有限retryで回復する。全接続へbroadcast BUSYを散布しない。

## 6. 試験の意味

`tests/test_contracts.py`ではcommit前後・区間利用後のcold reboot、期限不明、重複grant、予約rollback、APPLIED failover拒否を小モデルで検査する。NVSの実atomicity、暗号演算、実callback排出、真の分散routingは別の実装／HILゲート。

## 7. 寿命資源の既知上限（CORE_FIXED_250 prototype、未解決）

epoch／route generationの起動回数予算（旧#29/#48）はWire v2で32bit化して解消した（32bit boot sessionから直接導出、1分周期wakeでも約8,000年）。次の上限は現行実装の性質であり、設計変更（G-SEC／G-POWERで扱う）まで解消しない。配備判断の前提として明記する。数値はissueの概算またはNVS形式からの計算で、実機計測ではない。

NVSのentry予算は`tools/nvs_budget.py`（CIで各firmwareの`partitions.csv`と記録codecの大きさから計算）、削除・上限の安全条件は[sdk-v1/05 §9](../design/sdk-v1/05-nvs-state-37.md)にまとめた。

| 資源 | 現行の上限 | 主因 | 追跡 |
|---|---|---|---|
| NVS entry数 | **開発PSK profileで有界化（P0、host試験済み・実機未計測）**：ピアごとのcounter lease／replay floor／windowを専用NVS partition `rlsec`（通常64KiB／bridge 128KiB）へ移し、`rlboot`等のsystem NVSを満杯にできない構造にした。TX counterは起動時に現boot sessionより古いepochのrecordを掃除（掃除した最大epochの証人`cmax`を先にcommit）。永続ピア数は上限（通常64／gateway 128、両scope各1 record、最悪20 entry/ピアで`rlsec`の使えるentryの80%以内）を持ち、超える**新規**ピアは`PEER_STATE_CAPACITY`で拒否・計数（既存ピアは継続）。TX側（(scope, 宛先)の組）は起動ごとに掃除されるので1起動内の宛先数に効く。RX floor／windowは消さないため、RX側（(scope, 送信元)の組）の上限は機器の生涯で累計した送信元に効く | RX状態の削除は再ハンドシェイク設計が前提（本番profile、[sdk-v1/05](../design/sdk-v1/05-nvs-state-37.md) §3。P4-4で開発ProviderもRAM context engineへ移行するまで、上限到達後の新規ピアは`rlreplay`/`rlcounter`の明示消去（05 §4 D2-e）まで通信不能） | #37 |
| flash書込回数 | 下の書込予算表のとおり。旧実装は認証済み受信frameごとにreplay windowをcommitし（終端では2 commit）、持続10 frame/sで既定NVSが約1ヶ月の概算だった。§2のceiling予約後はreplay側が約1/65となり、同条件で約5年の概算。同時に活動するcontextがcache容量を越える配備では、追い出し1回ごとに最大2 commitへ戻る | fail-closedなreplay永続化、有限context cache | #30、#57 |
| remote config | 受理1件≈7〜8 commit。rate上限（1/min＋burst1）で連続運用すると摩耗寿命は概算1〜2年。人手運用なら問題にならない（運用規則は[遠隔設定 §10](remote-management.md)） | ConfigJournalの2スロット耐電断commit | #57 |

flash書込予算（開発PSK Provider既定値。contextはscope・peer pair・epochの組、1 commitはNVS blob書込＋`nvs_commit`一回）。

| 経路 | commit契機 | 目安 |
|---|---|---|
| RX replay ceiling | 受理最大値が保存ceilingを越えたとき（K＝`kReplayReservationAhead`＝64） | contextごとにcounter 65前進で1回。window内の順序入替えは0。終端nodeはlink＋endの2 contextで各1/65 |
| RX epoch floor | peerのepochが進んだとき | peerの再起動1回につき1回 |
| RX context追い出し | 同時に活動するRX contextが`kRxContextCapacity`＝64を越えたとき | 追い出し1回で引下げ1回＋再open後の予約1回 |
| RX正常close | Provider close時 | 保持contextごとに最大1回 |
| TX counter lease | 予約区間（256）を使い切ったとき | contextごとにcounter 256で1回 |
| TX context追い出し | 稼働`kTxContextCapacity`＝32件＋checkpoint`kParkedLeaseCapacity`＝64件を越えて再作成したとき | checkpointが残っていれば0、溢れていれば再作成1回につき1回 |
| 起動 | boot sessionの前進、新epochでの各TX context初回予約、相手側のfloor・ceiling、`rlsec`の旧epoch TX recordの掃除（#37） | 起動1回につき1＋送信context数（相手側でpeerごと2）。掃除は証人`cmax`の更新1回（u32、1 entry）＋旧recordごとの消去（entry状態の書換えのみで新entryを消費しない）。Deep Sleep周期のnodeは起動回数で見積もる |
| remote config | 受理1件 | 約7〜8回（rate上限1/min＋burst1） |

概算：持続10 frame/sを受ける終端nodeは旧20 commit/sから約0.31 commit/s、中継nodeは旧約10 commit/sから約0.19 commit/s（RX link 1/65＋TX link 1/256）。数値は既定値からの計算で、実機のNVS page消費は未計測。

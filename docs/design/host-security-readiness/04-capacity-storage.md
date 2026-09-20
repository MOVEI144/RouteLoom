# 04 — 容量・保持・退役とクラッシュ（Issue #9）

## 1. 現状の数量と採用案

PR #2/現在PR #6のIdempotencyTableは16件・24時間。処理完了後も保持し、再参照でlast_useが更新される。新規keyをr件/分受けると、回収前の満杯まで概ね16/r分。1件/分なら16分、2件/分なら8分、1件/秒なら16秒で16枠へ達する。17件目を拒否する防御自体は維持すべきで、保護中記録をLRUで消す修正はしない。

**採用：Host長期OperationStore＋Gateway短期DispatchWindow。** USB request IDは接続内の応答相関。無線dedup、アプリの副作用防止はそれぞれ別。1枚の最大台帳を全ノードへ置かない。

| 層 | 上限/保持/根拠 |
|---|---|
| Host completed operation | 全体4096件・32MiB、完了から24時間。epoch単位回収で最大約25時間＋実行/late余裕 |
| Host active | 全体32、主体8。受付時に完了record分まで予約 |
| Host受付epoch | principal×Network×classごと新規受付1時間、最大32未退役epoch、永続closed-through floor |
| Gateway dispatch | 32件（SDK in-flightの実効上限は8以下）、record割当128Bを設計予算、計4096B＋lane metadata |
| Gateway保持 | terminal結果をHostがcommitしてRETIREしたら回収可。保護時間だけで同じseqを新規扱いしない |
| 無線dedup | 既存寿命30秒＋late30秒=60秒。Host24時間と混同しない |

## 2. 初期運用profile

HOST_CONTROL_SMALL：**全principal合算で2件/分、burst16、active32、payload128B以下**。これはPC発のoperationのprofileであり、50台×40イベント/時という端末発トラフィックを流用していない。

長期必要件数の保守式は `ceil(rate × (24h + epoch 1h + message 30s + late 30s)) + burst + active`。2件/分では `3002+16+32=3050`、4096件以内。1件/分は1549、10件/分は15058、1件/秒は90108で後二者は本profile対象外。4096件は単純24時間だけなら平均約2.84件/分、epoch/余裕込みではそれより小さい。

Gateway側は未退役60秒を試験基準にすると `ceil(2/60×60)+16+8=26`件で32枠内。Hostが止まる、RFが遅い、結果不明が残る場合はこの仮定を外れるため、枠が埋まったらbackpressure。無条件連続可用性を約束しない。burst16すべてを5秒以内配送する保証でもない。

Hostの32MiBはlogical quota。計画内訳は4096×4KiB予約=16MiB、journal/WAL8MiB、index/metadata2MiB、回収・安全余裕6MiB。実SQLite/B-tree、allocator、fsync等のpeakは未測定。実装は物理ディスク利用も監視し、上限に収まらないなら新規受付を止める。予算を測定値と呼ばない。

## 3. Store方式と受付順序

既存Host Storage境界へ**ローカルSQLite transactional adapter**を採用する（外部DBサービスなし）。application payloadを解釈する業務DBではない。RAM_ONLYは同じ契約の別providerで、daemon停止を越える保証なし。使用するSQLite/bindingの版とライセンスは実装PRでlockし、ここで未導入依存を導入済みにしない。

1. OS principal、Network権限、capability、schema、canonical hashを検査。
2. 同identityの既存recordを検索。同内容なら既存結果、異内容はCONFLICT。
3. epochの新規受付有効性、record/bytes/active quota、outbox枠を同一transactionで予約。
4. OperationId、元期限、canonical、HOST_QUEUEDをcommit。成功後だけLOCAL_ACCEPTEDを返す。
5. dispatcherがGateway BootLease、dispatch_seq、hashを割当て、DISPATCH_PREPAREDをcommitしてからUSBへ出す。
6. Gateway受理/結果をcommitしてからアプリへ証拠を返し、terminalのRETIREを送る。

commit応答不明なら送信を開始しない。SSD/OSが永続flushを保証しない環境では耐電断資格を別扱い。Store破損で同じlineageを空DBとして再開しない。

## 4. 受付epochと古いkey

epochは同じscopeで単調、Hostが正当なStore transactionで発行する。callerはそのepochと自分のkeyを持つ。通常1時間で新規受付を閉じるが、閉鎖後も既知keyは照会できる。同epochに一度も存在しないkeyを閉鎖後に出すとEPOCH_CLOSED。

個別完了recordを早く消さず、epoch内の全recordが終端・各24時間保護終了後にepoch全体を退役する。退役は同scopeの最古側から連続したprefixだけに限定し、未退役の古いepochを飛び越えない。退役を示すfloorを永続化してからrecordを消す。途中停止ならrecord余剰が残るだけで、旧keyの新規実行は起きない。

未確定recordはelapsedだけで解放しない。INDETERMINATEを残すepochはpinされる。主体が結果照会か明示ABANDON_TRACKINGで記録保護を終える場合も、同keyを再実行可能に戻さずepochをclosedとして退役する。これは作用の取消/未実行の確認ではない。32epochや4096recordを超える場合は新規admission停止を診断する。

GETやduplicateは保護期限を延長しない。重複・CONFLICTにも主体/全体rate limitを適用する。TIME_UNCERTAINではexpiryを進めず容量を保護し、新epoch連打で制限を迂回させない。

## 5. Gateway短期窓と忘れた要求の拒否

長期caller keyはGatewayへ渡さず、Host dispatcherが一列のdispatch_seqへ写す。各laneは認証済みHost dispatcher/Network/Gateway BootLeaseに固定。初期1lane/Network、複数dispatcherは上限4laneを交渉し、RAM予算を増やせないboardでは拒否。

Gatewayはretired_through floorとその後32位置を保持する。同じseq/hashは既存結果。同seq異hashはCONFLICT。floor以下はDISPATCH_RETIREDであり新sendしない。窓より先はDISPATCH_WINDOW_FULL。既存SDK送信枠、返信・dedup領域を確保してから初回sendを行い、結果相関を記録する。

Hostはterminal結果を耐電断commit後、連続して安全に退役できる位置までRETIRE_THROUGHを送る。Gatewayは未terminalの位置を越える退役を拒否する。ここでterminalはGateway自身の新規送信・再送責任を終了した状態で、宛先アプリの未作用を証明する意味ではない。結果不明で終わった配送もHostに不明証拠をcommitした後に退役できるが、同じ業務依頼の再発行はしない。未送信の採番済み穴には、Hostが外部SUBMITを一度も出していないと永続記録した場合だけSKIPを送る。Gatewayに既受理recordがあればSKIPで上書きしない。

USB再接続では同bootのlane/recordsを保持する。完全Gateway再起動では新しいBootLease（NVS単調boot世代＋機器IDに結合した128bit表現）を発行して旧leaseを拒否する。boot保存に失敗したら業務送信をenableしない。Hostが旧leaseの操作を新leaseへ自動コピーすることは禁止。

初期Gateway窓はRAM限定。BootLease変更後、既dispatch要求が実行されたか分からなければHostはINDETERMINATEにする。Gatewayを再起動して同じcaller keyを新操作へ変える抜け道を作らない。Gateway durable custodyは別capabilityで、今回の容量解決の必須条件にしない。

## 6. 障害の期待結果

| 停止位置/障害 | 結果 |
|---|---|
| Host受付commit前 | 未受理。外部送信なし。同key再提出可 |
| 受付commit後・API応答前 | 同keyから同じOperationIdを照会 |
| dispatch準備commit後・USB write前後 | 同bootへQUERY/同ticket。送信有無不明なら新ticketを作らない |
| Gateway受理後・Host記録前 | 同bootは既存MessageKey再応答。新bootなら結果不明 |
| Host結果commit後・RETIRE前 | 同じ結果を返しRETIREを再送してよい |
| RETIRE後・Host再起動 | Hostの長期記録から回答。Gatewayの退役済みseqは再実行不可 |
| Host Store全損 | STORE_RECOVERY_REQUIRED。空台帳で旧lineage/keyを受けない |
| 時計不明 | 保持を短縮/送信期限を延長しない。TIME_UNCERTAIN |
| quota満杯 | 受付前NO_CAPACITY。free slots/bytes、最古の安全な回収時刻（不明ならnull）を返す |

受入：CAP01〜CAP10。現行16→17を比較fixtureとして残し、採用profileの24h時刻モデル、同key連打、複数主体、閉鎖epoch、新旧lease、SKIP穴、RETIRE crashを追加する。件数増加だけを改善の証拠にしない。

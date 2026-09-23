# 無線サブシステム：ESP-NOW / Wi-Fi LR

基準仕様1.1、2026-09-17。実装契約であり実機認定ではない。[初期値JSON](../reference/radio-defaults.json)と同時に版管理する。

## 1. 固定する範囲

| 項目 | 規約 |
|---|---|
| 対象 | ESP32-C3 / S3 / C5、別々のfirmware build |
| 基盤 | ESP-IDF v6.0.3、commit 76f5dedd9950a3012fee8fb7d5586df21fc67802 |
| 通信 | STA未接続のESP-NOW、2.4GHz、Wi-Fi LRのみ |
| 共通制御 | LR250。発見、Join、復旧、経路広告、HOP_ACCEPT、管理計画 |
| データ | 初期LR250。検証済み方向・長さ区分に限りLR500 |
| プロファイル | 基準線LR250_FIXED。LR_ONLY_ADAPTIVEは別認定対象 |
| 送信しないもの | 通常1Mbps/OFDMへのfallback、BLE、5GHz、AP接続、SoftAP |
| channel | 定常時一つ。基準線は自動移行OFF。将来profileは合意・復旧・実機認定後に有効化 |
| 電力 | 承認済み固定上限。自動出力削減はv1でOFF |
| LoRa | 未実装。Wi-Fi LRと別方式 |

全部LRとはSDKが投入するデータ・制御frameのPHYを指す。内部MAC ACKまで公開APIで任意に同じPHYへ強制できるとはしない。

公式：[ESP-NOW C3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/network/esp_now.html)、[S3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/network/esp_now.html)、[C5](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-reference/network/esp_now.html)、[C5 LR説明](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-guides/wifi-driver/overview.html)。stableの表示版をビルドpinと同一視しない。

## 2. 不変条件

1. 物理無線ごとに設定実行者は一つ。
2. LRで届く機器の発見に通常1Mbpsの到達を要求しない。
3. 未認証のOFFERは候補情報であり管理権限ではない。
4. 双方向未確認のリンクを通常中継に使わない。
5. 予定不在・キュー不足をRF損失として学習しない。
6. 未確定TX結果を別のTXへ割り当てない。
7. 再送・経路変更でMessage IDを変えない。
8. 通常DATAを経路不明で全網Floodしない。
9. 通信不能だけで所属を失わせない。
10. 管理・鍵・channel・sessionの世代を兼用しない。
11. channelの全体変更を局所timeoutだけで確定しない。
12. 予算・期限・資源の上限を持ち、不明値は不明と表示する。
13. RF配備プロファイル外の電波を出さない。
14. MAC結果、SDK受理、PC受理、アプリ適用を区別する。

## 3. 初期化とRF配備条件

Identity・NVS・暗号の安全な再開状態を読み、RfDeploymentProfileを検証する。国、ボードrevision、アンテナ、許可PHY/channel、送信上限、適合確認の記録を持つ。tx_power_qdbm未設定ではTXを始めない。JP指定だけで適法性を証明したとは扱わない。

Wi-Fiの必要基盤、RAM設定、STA未接続、手動country、2.4GHz、20MHz、二次channelなしを設定する。RX protocol maskは11B|11G|11N|LRを基準に検証するが、SDKのTX descriptorは250/500以外を拒否する。20MHz設定からLRの実占有帯域を推測しない。

Wi-Fi start後に現在channelと送信電力を設定・readbackし、ESP-NOW初期化、callback、broadcast Peer、LR250を設定する。相手別rateは対象Peer登録後に設定する。要求値・driver報告・空中実測は別の証拠として残す。

IDFのWIFI_PHY_RATE_LORA_250K/500KはEspressif Wi-Fi LRであり、SX1262 LoRaではない。公開名はWIFI_LR_250K/500Kとする。固定ソース：[esp_now.h](https://github.com/espressif/esp-idf/blob/v6.0.3/components/esp_wifi/include/esp_now.h)。

## 4. 実行状態と調停

`STOPPED / STARTING / DISCOVERING / RESUMING / STEADY / REPAIR / SURVEY / MIGRATING / RECOVERY / QUIESCING / SLEEPING / DRIVER_FAULT`。

Radio Ownerは送信、Peer登録・削除、rate/channel、無線停止を一元実行する。他taskはrequestを出すだけ。TX一件にはpeer、channel epoch、rate、bytes、deadline、tokenを固定し、途中で別taskが設定を変えない。

REPAIR中は高速化試験を止める。MIGRATING中は別survey・出力変更を止める。QUIESCINGでは新探索を始めない。各操作は開始条件、完了条件、timeout、戻り先、理由を持つ。

物理TXのin-flightは1。論理message8、近隣ごとのリンク受理待ち2を初期値とする。RX callbackではframeと有効metadataを固定queueへコピーする。暗号検証、forward、printf、Flash待ちをcallbackへ入れない。

## 5. 観測と原因分類

リンクはNetwork、Radio、neighbor、方向、channel epoch、rate、長さ区分で識別する。A→BのRSSIからB→Aの成功を保証しない。

| 観測 | 意味 |
|---|---|
| driver受付 | APIが仕事を受けたか |
| MAC結果 | 直近のドライバ結果。相手アプリの受付ではない |
| HOP_ACCEPT率 | 相手SDKが認証・キュー確保まで行った割合 |
| SDK queue wait | 自分の順番待ち |
| driver service time | API受付からcallback。内部再送・CCA待ちを含み得る |
| link exchange time | 送信から認証済み受理または試行失敗まで |
| E2E time | 要求した最終証拠まで |
| 推定Airtime | 校正モデルの推定。実busy率ではない |
| RSSI | 受信できたframeの値。損失frameの強さは不明 |

Noise Floorや全MAC再送回数が全チップで取れると仮定しない。不明を0で埋めない。sample数、最終観測、推定の不確かさを表示する。短期64試行、中期60秒・10分の集約を持つ。

原因分類はLOCAL_RESOURCE、REMOTE_BUSY、PLANNED_ABSENCE、LINK_DEGRADED、CHANNEL_CONTENTION_SUSPECTED、UNKNOWN。複数相手のwait増加は混雑を疑うが断定しない。NO_MEMやPeer不足から低速化へ飛ばない。

混雑で全員250へ落ちる悪循環を避ける。最初に低優先送信と追加試験を抑え、既知代替を検証し、必要な場合だけchannel調査へ進む。

## 6. LR500の試験

現用250、保守250、試験500を区別する。500の受信capabilityが両端で認定されていることが前提。

初期条件は同じ方向・長さ区分で16試験中15以上の成功、250比でlink実績cost20%以上改善、受信側の異常な滞留なし。これは99.9%保証ではなく仮採用しきい値。緊急DATAを未確認設定の試験に使わない。

同じ近隣の改善試験は10秒以上あけ、追加電波時間予算内とする。低頻度の眠る端末では追加試験を既定OFF。channel/boot変更や10分以上未観測なら古い試験成績を自動継承しない。

500で連続2回、または直近8回中3回の対象RF失敗ならSUSPECT。有効な予備があれば先に迂回できる。予備がなければ250で一回確認する。BUSY、予定Sleep、APIエラーはこの失敗数から除く。

参考：[Minstrel](https://wireless.docs.kernel.org/en/latest/en/developers/documentation/mac80211/ratecontrol/minstrel.html)。ドライバ内部の再送連鎖まで同じように制御できるとはしない。

## 7. 発見と早い復帰

DISCOVERはLR250・1hop。既存の受信可能ノードは16slots×10msの窓でOFFERを分散し、要求nonceと応答者IDで偏りを変える。応答者は1応答/秒、burst2。要求者は3候補で早期終了可能。

一channelの探索滞在上限200msには切替・TX・応答を含める。予算不足なら試行を短縮し、全窓を必ず使えると仮定しない。応答がない一回だけで物理圏外を確定しない。

安全なsessionと保存相手があれば起床後はデータ本体から送る。失敗時だけ同channel予備、同channelLR発見、保存移行先、候補channelへ広げる。初回Join承認と経路修復を混同しない。

Deep Sleep型の既定活動予算は2000ms、探索最大2周。ただし停止予約100msおよび未完TXの最大待ちを予算に確保し、収まる操作だけ開始する。2周を常に完遂する保証ではない。driver故障時の安全停止・再起動は予算超過として記録する。

給電ノードの再探索は500〜2000msの乱数待ちから最大60000msへ伸ばす。孤立群は少数の探索担当を選び、全員が同時にhomeを離れない。探索担当には管理設定を変更する権限を与えない。

## 8. 再送と結果不明

同一近隣のSDK試行は初回込み2回、送信元のE2E roundは初回込み3回。deadlineと活動予算が先に尽きれば打ち切る。別親・別rateへ変えても同じ仕事の予算を初期化しない。

RTO初期60ms、適応20〜250ms。SDKのlink再試行jitterは通常0〜20ms、混雑20〜100ms、次E2E round50〜200ms。初回DATAの無条件jitterは0ms。E2E RTOは経路・往復・下位試行とqueue予算を含める。下位が正常に再試行中なのに上位が同じ仕事を大量投入しない。

HOP_ACCEPTにはHOP_ACCEPTを要求しない。END_RECEIPTは各区間で受理確認を得られるが、終端でreceiptのreceiptを生成しない。単純なDATA＋hop確認＋終端receipt＋hop確認の会計では再送前で約4H SDK frames。これを無視してアプリ32B×hopだけを占有と呼ばない。

callback watchdogは1000ms。通常送信の待ち時間を1000ms固定にする意味ではない。欠落時は新TXを隔離し、古いcallbackを次frameへ割り当てない。再登録やtoken増加だけで解決したとみなさない。安全な停止・排出・再初期化がHILで確認できなければ制御された再起動へ進む。

キャンセル後も既送信packetが届き得る。結果はCANCELLED_BEFORE_TXとINDETERMINATE等を分ける。

## 9. 干渉と送信スケジューラ

ドライバのCCA/backoffを使い、公開されていないRTS/CTS、内部MAC再送、精密TDMAを制御できるとはしない。

管理・緊急・通常・bulkのDRR重みは4:8:4:1。送信時間で持ち分を課金し、空きは貸せる。ACKは短い予約queueに置くが、正当な要求に対応するものだけ。DATAとACKを同じ仕事の予算に含める。queue50%で背景を縮小、80%でbulkと改善試験を止める。上限を超える高優先要求も無制限には受け付けない。

将来の大規模profileの管理送信予算目標はネットワーク延べ100000us/s、追加最適化10000us/sとする。初期基準線へ一律適用する実証済みtimerではなく、第14節のcapacity gateが優先する。これは推定モデルでの投入制限であり、法的duty cycleでも実測busy率でもない。人数込みの配賦を行い、各ノードにその全量を与えない。

未配賦の通常枠は設計100台で割った値を基準にtokenを貯める。配賦の再発行は正規管理を必要とし、分断時に不在ノードの枠を勝手に二重発行しない。緊急復旧・Joinの小burstは別に上限と期限を持つ。実測モデルがない初期buildはcapabilityを未校正とし、推定値の保証をしない。

Heartbeatは許された範囲で位相を分散する。既定jitterは周期±5%。イベント初回送信を同じjitterで何十秒も遅らせない。意味のないpayloadをSDKが勝手に最新値へ集約しない。

隠れ端末への拡張では受信側creditと短いsoft pacingを使用可能にする。高度なsoft pacingの実装・RF認定前はcapabilityを無効とする。対応する自網だけの調整で、外部Wi-Fiを予約排除する機構ではない。正常時はOFF、集中が持続した場合のみ使う。

## 10. Peerとメモリ

Peer20枠をbroadcast1＋通常16＋transient3に割り、通常pinは最大12。進行中TX、重要経路、受領待ちPeerは追い出さない。Peer登録・再作成後はLRを再適用する。Peer不足でDATA broadcastへ逃げない。

論理台帳128、近隣32、RX64、TX64（制御予約8）、logical in-flight8は大容量設計の上限例。実装基準は[資源profile](resource-profiles.md)のleaf／relay／gateway別の値を使う。driver Peerとsecurity session数と台帳数は別。未登録Peerからのdriver非暗号frameもSDKで認証してから必要な返信枠を確保する。認証前にPeer登録だけで信用しない。

内部RAM不足なら明示的に小容量profileへ変更し、同じ性能認定を維持しない。printf/USB待ちでradioを止めない。drop、低水位、結果不明、reset理由を記録する。

## 11. Meshへ渡す契約

LinkEstimateは方向、認証状態、利用可能期間、標本、service cost、推定Airtime、energy、Peer枠、平滑化した混雑を返す。眠る相手・失効鍵・容量不足は高costではなく利用不可。

driver処理時間に内部再送が含まれるならETXを再度掛けない。実績costは同条件の全試行時間合計／認証済み成功数を基準とし、失敗0件だけの速い値を広告しない。単位の違うms、dBm、電池%を無造作に加算しない。

経路選択は[ルーティング](routing.md)、全体channel変更は[移行](channel-migration.md)、睡眠は[省電力](power.md)の契約に従う。

## 12. 実装採用の判断

ESP-IDFの素のesp_now APIを使う。上位のespressif/esp-now componentには独自のACK・forward・送信lock・channel巡回があるため、新SDKへ丸ごと重ねない。既存試験コードのblocking waitやdata floodも踏襲しない。

公開sourceを参照したことはbinary Wi-Fi driver内部を監査した意味ではない。C3/S3/C5混在、弱電界時のMAC結果と認証受理、broadcast250、peer別500、callback欠落、wake、channel移行を[受入ゲート](acceptance.md)で確認する。


## 13. 受理・混雑・探索の追加規範

HOP_ACCEPT前にframe、dedup、transaction、reply Peer lease、ACK slotを一括予約する。失敗は全部解放し、副作用も受理成功も発生させない。返信枠自体が無ければBUSYの送信まで保証せず、ローカルREPLY_CAPACITY_DROPを記録する。retryで空く枠を待ちながら他の資源を保持しない。[電源断・資源契約](crash-time-resources.md)参照。

初回DATAにはSDKの無条件random jitterを加えない。0〜20msはlink retryのみ。driver CCA/backoffは残る。認証・受理後のHOP_ACCEPTを、当該DATAのforwardより先に予約queueへ投入するが、外部無線による送信時刻までは保証しない。END_RECEIPT受領時点のAPI完了と最後のlink ACK送信時間は別計測。

16slotsは予約TDMAではなく応答時刻の分散。DISCOVER/OFFERはRLD1 envelope全体で160B以下（`kRld1MaxTotal`、scoped OFFERは実測104B）。requesterは一度に1transaction、cold-startに0〜1000msのばらつき、失敗後500〜2000msから最大60秒へbackoffする（sleep予算が優先）。responderはglobal応答上限を守り、要求が混んだときの候補選択をrotateして一つの要求に固定しない。

高密度ではrequest nonce由来の応答抽選率を1、1/2、1/4、1/8へ抑えられるが、未認証の密度値だけで変更しない。窓を延長する場合はrequesterのdwellと明示交渉し、200msの既定滞在を黙って越えない。この適応は実RF認定までexperimental。単独cold Joinと100台同時JoinのSLOは別。

## 14. 制御予算と資格

100000us/s・10000us/sは将来の設計包絡であり、現在の全起源・pairwise広告を賄える証明ではない。基準線で動的な網全体再配賦はしない。message class毎のentry最大長・fan-out・周期・burst・最大待ちをG-ROUTEのcapacity manifestへ出すまで100台資格を付けない。

受理済みDATAに対応するACKは当該仕事へ課金、近隣probe／経路更新／Join／管理logはcontrol、rate試験はoptimization。ACK枠・経路安全更新・新Join・bulkを区別する。leaseより長いtoken待ちで広告を送る場合は正常とせずCONTROL_BUDGET_UNSATISFIABLEを返す。

起源数O、相手数F、entry長E、frame有効領域P、周期Iに対し、少なくとも `ceil(O*E/P)*F/I` frame/sを見積もり、ヘッダ・保護・ACK・再送・clock等を別加算する。nodeごと1ms/sを即送信可能な予約と呼ばない。token bucket burstは最大frame一件以上を許すこと。

LR500の比較標本は同方向・同長・同channel epochで250/500を時間的に近く対照取得する。16対は180秒以内、対の開始は10秒以上離し、予算不足／channel/boot変更で無効化する。旧時間帯の250と別時間帯の500を比較しない。queue waitを除いたservice costと期限内配送・総energyを別々に比較する。資格前は固定250を既定とする。

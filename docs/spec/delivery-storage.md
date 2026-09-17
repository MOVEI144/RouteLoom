# 配送保証・キュー・永続化

## 1. APIが約束する結果

| 配送クラス | 完了条件 |
|---|---|
| BEST_EFFORT | SDKは一試行。送信結果を報告するが最終受理は要求しない |
| RELIABLE | 固定した最終宛先SDKの認証済みEND_RECEIPT |
| APPLIED | 宛先アプリのAPP_RESULTまで待つ |

BEST_EFFORTでもdriverのMAC再送を0にできる保証はない。RELIABLEは無期限保証ではなく、deadline・容量・retry上限内で試みる。APP_RESULTはアプリが定義した処理結果で、物理状態とDBの一般的exactly-onceを保証しない。

## 2. 中間の証拠

TX_ACCEPTEDはローカル受付、TX_MAC_DONEはdriver結果、HOP_ACCEPTEDは次SDKの認証＋RAM受理、END_RECEIVEDは最終SDK受理、APP_APPLIEDはアプリ結果。Flash commitを要求した場合だけDURABLY_STOREDを別に返す。

USB先のESP32まで届いても、宛先がPCサービスならPC受理前に完了しない。最終receiptの発行者はservice設定とSecurity contextで明示する。

## 3. 所有権と容量

send受付前にpayloadと必要metadataの有界領域を確保する。確保できなければWOULD_BLOCK/NO_CAPACITYを返し、後で勝手に送信しない。

中継がHOP_ACCEPTを返すのは認証とキュー確保後。受理前のBUSYは受理成功ではなくRF損失でもない。中継電源断でRAMが失われ得るため、originは最終証拠まで必要なデータを保有する。

appはDROP_ALLOWED、RAM_BUFFERED、DURABLE_ORIGIN等の保存方針を指定する。全Relayのdurable custodyはv1必須にしない。必要なら対応capabilityと個別受託証拠が必要。

## 4. Message IDと再送

Message IDはorigin Identity・安全な送信session・単調sequenceに結び付ける。配送roundは別。宛先変更が許された次roundでも同じ論理IDを維持する。

同じ隣接への試行は初回込み2、originのroundは初回込み3。別peerに変えても当該node/roundの転送台帳は保持し、候補3本での試行総数も記録する。各nodeで有限でもACK喪失による分岐があり、単純なhop×retryがネットワーク全送信数の厳密上限とは限らない。deadline、hop、候補、round、node台帳を全て制限する。

実DATAの無制限Floodは禁止。END_RECEIPTへ無限にreceiptを付けない。認証済み負荷制御と再送jitterで同期衝突を避ける。

## 5. dedup状態

IN_PROGRESS、FORWARDED、FAILED、DELIVEREDと、保持しているreceiptを管理する。

同roundのduplicateには必要なhop応答だけ返し、二重forwardを避ける。失敗した旧roundを一度見た理由で新roundまで捨てない。終端DELIVEREDならpayloadを再実行せず保存した結果を返す。

dedup保持期間はmessage最大寿命と許容再送期間より短くしない。固定RAM容量で期限を守れない場合は入場を制限する。永続配送の再起動またぎdedupは永続storeを必要とする。動作不明のままクラッシュしたAPPLIED処理はINDETERMINATEを返し、アプリの照会／冪等キーで解決する。

## 6. 期限とキャンセル

APIでは単調時計基準の相対deadlineを受け、wireでは残予算を減らす。hop滞留時間を減算するが、同期されていない時計同士のtimestampを直接比較しない。

cancel成功は未送信を止める場合と、既送信の結果が不明な場合を分ける。キャンセルが宛先の実行を取り消したとはしない。期限切れも、宛先が未実行という証拠ではない。

## 7. PC停止

Gatewayは有界RAMを使い、要求があれば利用可能なdurable providerへ保存する。PCが止まっている間に満杯になったらcreditを下げ、受理不能を返す。古いものを無断で上書きしない。最新値だけに集約するのはアプリが明示したキー付きstate classのみ。

PC側SQLite等の具体媒体はadapterとし、永続化完了の意味をfsync/transactionの契約に合わせる。OS書込みAPIが返っただけで耐電断を名乗らない。

## 8. 保存の破損・再起動

recordには版、長さ、CRCまたは整合性情報、世代、所有者を持たせる。payload保護はSecurity契約に従う。途中recordを無視できるjournal、容量制限、回収手順、書込み失敗時の通知を設ける。

secret storeと通常payload queueは分離する。flash耐久性とCPU停止時間は基板・partition・負荷別に計測する。再起動後にメッセージIDを変えて古いデータを新しいイベントとして復活させない。

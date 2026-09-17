# 受入試験・性能・失敗注入

## 1. 証拠のレベル

文書検査、host単体、protocol相互運用、実ボードHIL、実RF、現場配置試験を分ける。simulation100nodeをRF100台実証とは呼ばない。仕様の性能値は目標であり、達成済み結果ではない。

## 2. 必須ゲート

| ID | 試験 | 主な合格条件 |
|---|---|---|
| T01 | C3/S3/C5の9有向組合せ | LR250/500、broadcast/unicast、要求・driver・RX観測を照合 |
| T02 | boot・RF profile | 未承認TX禁止、誤board/pin/国/antennaを拒否 |
| T03 | callback遅延・欠落・NO_MEM | 誤った送信成功、無限待ち、次frameへの結果混同なし |
| T04 | 20Peer境界・再登録 | pinned追出しなし、LR再適用、暗黙data broadcastなし |
| T05 | 正常／中継越しJoin | authと承認を分離し、Root直達不要、bounded資源 |
| T06 | 鍵・membership・power cut | nonce再利用・旧epoch復活なし、失効が明示状態 |
| T07 | 1/5/10hopと下り | 期限・最終receipt・app結果を分離、循環しない |
| T08 | Relay撤去・交換 | feasibleな予備または探索で復旧、所属を変えない |
| T09 | 分断／再結合・古い広告 | gateway起源混同、loop、古い設定へのrollbackなし |
| T10 | 複数Gateway/service | 明示宛先が勝手に変わらずPC停止を区別 |
| T11 | 100台の集中・hidden terminal | 資源上限・公平性・retry予算、過負荷を隠さない |
| T12 | 外部干渉・自網混雑 | 原因不明を残し、全低速化の増幅を起こさない |
| T13 | channel survey/migration | 未commit切替なし、準備・実設定・訪問を分離 |
| T14 | COMMIT欠落・途中reset | 復旧で正当な最新計画へ追従、世代巻戻しなし |
| T15 | 30分Sleep中の複数移行 | 有界探索・認証復帰、初回承認へ無用に戻さない |
| T16 | USB分割・切断・遅いPC | session混同なし、credit上限、無線を止めない |
| T17 | Remote Config／OTA中断 | 型・署名・board照合、更新失敗から安全復旧 |
| T18 | 長期運転と低電力 | queue leakなし、実battery-side測定、ログ欠落も観測 |
| T19 | quorum喪失・構成員変更 | 少数群が管理変更しない、commit済み履歴保持 |
| T20 | C API所有権・cancel | 入力解放、受信retain、期限後receipt、callback再入を検査 |

各testはfirmware/toolchain/board revision/antenna/RFprofile/power/logger条件を記録し、再現seedと配置図を付ける。合成demoと実測traceを混ぜない。

## 3. 性能目標

暗号化済み32/64/128B、確立経路、低い外部占有、必要な中継がawakeの条件を基準とする。固定250と適応を分ける。

<!-- generated:performance:start -->
| 指標 | 目標 |
|---|---|
| 1hop RELIABLE | P95 20ms以内、send→END_RECEIPT |
| 5hop RELIABLE | P95 100ms以内 |
| 10hop RELIABLE | P95 250ms以内 |
| Deep Sleepから報告 | P95 500ms以内、warm条件。cold/auth/recoveryは別系列 |
| 既知代替への復旧 | P95 500ms以内、最初の故障観測→最終receipt |
| 同channel探索修復 | P95 2000ms以内を目標、物理経路が存在 |
| 自動承認済み同channel Join | P95 1000ms以内を目標、単独入場 |
| cold Join | P95 5000ms以内を目標、単独入場・常時受信入口あり |
| 切替そのものの空白 | P95 500ms以内を目標、認定された移行拡張・準備済み群 |
<!-- generated:performance:end -->

調査・準備・管理log配布には数分かかり得る。切替空白と総移行時間を混同しない。眠る全端末がVERIFY30秒内に起きることを期待しない。

## 4. 負荷定義

基準：50node、各40DATA/時、heartbeat30分、平均3hop、payload64B、RELIABLE、deadline5秒。DATA2000件＋heartbeat100件=2100件/時、約0.583件/秒。単純4H確認会計で約7SDK frames/秒に加え管理・再送がある。これを実RF容量の証明にしない。

burst：100nodeが同じ時点に各1message。overload：定常要求を上げ、queue80%、admission拒否、credit不足を起こす。緊急要求が続いても全クラス無限starvationにしない。

## 5. 統計

P50/P95/P99、期限内成功、未達、expired、cancel、indeterminate、標本数を同時報告する。成功例だけの低遅延で失敗を隠さない。信頼性99.9%以上という目標はdeadline・分母・試験時間付きで評価し、19/20 probeの合格と混同しない。

障害起点は物理撤去時刻とSDK最初の観測を分ける。送信がない期間の撤去を無料で即検知できるとはしない。

## 6. 改訂と認定

初期値を緩めて結果だけ合格にしない。未達原因、旧新設定、互換性、比較結果を記録する。セキュリティ・結果意味・規制境界は性能改善のため省略しない。認定はboard×機能×profileで行う。

[要求対応表](../reference/requirements.json)／[状態](../STATUS.md)


## 7. 改訂1.1の測定条件と負例

性能表は目標条件の正本JSONから生成して照合する。1hop20msなどを仮定の4H総仕事量だけから保証・不可能と断定しない。4Hは総送信会計、send→END_RECEIPTはcritical path。最大payload/全LR250と昇速済み短payloadは別系列。

初回DATA jitterはSDKで0、retry jitterとdriver待ちは別。wakeはwarm/cold/new-peer/channel-recovery/key-recovery別、NVS fresh/populated・履歴を分ける。単独Joinと同時100Join、100台管理と100件5秒以内burstを別資格にする。

追加負例：nonce予約commit前/後/消費後のcut、rx window喪失、期限不明、期限前dedup eviction、APPLIED provider二重作用、予約各段失敗、credit重複・旧session・部分write、store非互換OTA、voter破損、初期entropy未準備、preauth global quota、GPIO21排他。

`tests/test_contracts.py`はこれらのうち意味を小モデルで検査する。`tests/test_document_mutations.py`はP95/pin/SHA等の文書改変を検出する。どちらもファームウェア・暗号実装・Babel全体・合意・HIL・RF試験ではない。実装の完了条件はT01〜T20と追加ゲートのまま。

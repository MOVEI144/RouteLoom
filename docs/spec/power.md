# 省電力・Deep Sleep・受信可用性

## 1. 役割ではなく能力

電池だから絶対に中継不可、表示用だから必ず中継可、という規則はCoreに入れない。relay_allowed、rx availability、energy budget、sleep許可をアプリが指定し、SDKが矛盾を拒否する。

v1で認定する形はALWAYS_RXとDEEP_SLEEP_REPORT。同期した短い受信窓で眠りながら中継する方式は将来機能とし、未実装ならUNSUPPORTED。wake window APIがあるだけで複数機器の受信窓が自動同期するとはしない。

公式：[C3 Sleep](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/sleep_modes.html)、[S3 Sleep](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/system/sleep_modes.html)。

## 2. アプリとSDK

アプリはGPIOイベントの意味、センサーを切ってよい時、timer、未完了処理を指定する。SDKは通信停止と再開に必要な処理をまとめるが、センサー処理中に勝手にesp_deep_sleep_startを呼ばない。

推奨APIはsleep_prepare→app最終確認→sleep_enterの二段階。prepareが返したticketはradio世代とアプリbusy状態に結び付け、新しい送受信・GPIOイベントで無効化する。prepare後に新仕事が入ったままsleepしない。

## 3. sleep手順

1. 新しい改善試験を止める。
2. 中継中なら離脱予定を通知して可能な代替へ引継ぎ、通常leafでは不要な離脱を送らない。
3. 物理TX結果とcallbackの安全な終了を確認する。
4. 未完了メッセージを保存・延期・失敗の契約へ移す。
5. nonce/counterの安全な予約、membership、channel候補を保存する。
6. GPIO/timer wake能力を機種別に検証し、アプリが許可すればsleepする。

queueが残っているから永遠に眠れない設計にしない。一方、停止期限を守るために不明送信を成功と捏造しない。driver故障時の制御再起動は別結果として残す。

## 4. 保存先

| 保存先 | 内容 | 失われる条件 |
|---|---|---|
| RAM | 作業queue、瞬間統計 | Deep Sleep/電源断 |
| RTC保持領域 | キャッシュ、起床予定、短期候補 | 完全電源断・保持条件逸脱 |
| NVS/永続store | Identity、membership、正当な設定、暗号予約、指定したpending | 書込み失敗・破損を検出して安全処理 |

RTCのCRCは秘密の真正性を代用しない。古いcacheを復元してもcredential/管理epochを巻き戻さない。毎packetで全NVSを書き直さない。

## 5. 起床

reset理由とwake理由を区別してアプリへ渡す。Deep Sleep復帰は通常の関数継続ではなく起動処理を通る前提。保存状態が有効ならWi-Fi/ESP-NOW/Peerを再初期化し、保存相手へDATAを送る。peer driver構造体のRAM像をそのまま永続化して復活させない。

前回親が無ければ同channel→保存候補→限定scan。30分に一度等の低頻度端末はrate改善probeを既定で行わない。最後の500認定が10分より古ければ250へ戻す基準と整合させる。

無線活動の初期予算2000msは上限方針。全探索2周を必ず完遂する約束ではない。次TXの最大待ちと停止予約100msを差し引き、残りへ収まる仕事だけ開始する。

## 6. 下り

Deep Sleep中の即時受信は不可能。アプリは次回wake時まで保持を許すか、今受けられなければ失敗にするか指定する。保持は期限と容量、所有者を持つ。即時命令が必要ならALWAYS_RX等の異なる電力要件を選ぶ。

## 7. 実電池の評価

SDKは公称寿命を保証しない。battery-sideのE_report=積分V(t)I(t)を測り、起動・無線・受領待ち・探索・保存・センサー・DC/DC損失を含める。正常報告と失敗探索の分布を別に測る。

単一電池2本を直列にしたAhと3.3V側の電流をそのまま割らない。使用可能エネルギー、終止電圧、pulse電流、温度、自己放電、変換効率で評価する。Li-ion充電対応BAT端子へ一次電池を接続しない。

C3/S3/C5のwake GPIOは異なり、XIAOのD番号も異なる。USB保持、LED、拡張無線、抵抗分圧を含めて[ボード資料](../hardware/README.md)と照合する。


## 8. 破損と再起動クラス

[電源断契約](crash-time-resources.md)のstore別処置を使う。nonce/replay／voter／Authority／membershipの破損を汎用erase-and-initで処理しない。spoolの時計が失われたら未使用の残時間を再付与しない。

wake性能はwarm RTC/context resume、cold同相手、new peer auth、channel recovery、key rotation recoveryに分ける。500ms目標はwarm条件から開始し、NVS populated／更新履歴fixtureとRF calibrationを含める。sensor処理時間は別計測だが電池energyには含める。

## 9. 実装状況

Portable `PowerCoordinator`（`components/routeloom/include/routeloom/power.hpp`）が§2の二段階手順を実装する。状態はRUNNING→DRAINING→PERSISTING→READY_TO_SLEEP→SLEEPING→RESUMING→RUNNINGに限定し、遷移は全て明示でbounded。`SleepTicket`はradio世代・config revision・pending仕事世代・アプリイベント世代に結び付き、新規TX・RX・アプリイベント・config変更・radio resetで無効化される。SLEEPINGへはREADY_TO_SLEEPかつ有効ticketからのみ入る。

§3の未完了メッセージはFail／Save／Deferの契約へ移し、保存はCRC付き2スロットの電源imageへ入る。§5の復帰はcold bootとdeep-sleep wakeを別入力として起動処理を通り、保存peer→bounded確認窓→失敗時のみ限定discoveryの順で進む。経過時間が不明なdurable pendingは`TIME_UNCERTAIN`で止め、自動再送しない。host model試験で全遷移、ticket無効化、各policy、電源断を跨ぐcounter非後退、cold/resume分離を確認した。

ESP-NOW側は`EspNowPowerPort`とNVS image adapterを実装し、reference firmwareは`ROUTELOOM_DEEP_SLEEP`選択時のみ`esp_deep_sleep_start`経路・RTC marker・wake原因分類を配線する（build-tested）。`enter_sleep`はdeep sleep突入直前に`esp_wifi_stop()`を実施し、`esp_deep_sleep_start`が復帰した場合のみ`esp_wifi_start()`でabort経路のradioを復帰させる（issue #34）。加えて両firmwareのboot-fatal経路は連続失敗streak（RTC noinit、portable `routeloom::fail_action`）でexponential backoff付き`esp_restart()`を実施し、streakが閾値を超えた持続faultでは`esp_wifi_stop()`＋timer wake付きdeep sleepへ降格してboot loopのNVS writeと消費電流を抑止する（issue #34）。bounded discoveryはESP-NOW adapterが現状UNSUPPORTEDを返す。実機の消費電流、wake timing、RTC経過時間、RF挙動は未試験であり、本節をHIL証拠として扱わない。

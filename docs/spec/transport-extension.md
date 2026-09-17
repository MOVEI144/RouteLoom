# Transport境界・将来のLoRa追加

## 1. 目的

ESP-NOWだけを初期実装するが、CoreへMACアドレス、250B、数ms待ち、Wi-Fi channel操作を焼き込まない。将来SX1262が付いたノードとWi-Fiだけのノードが混在しても、同じ機器Identityで複数radioを表せる構造にする。

「sendだけ置き換えればLoRaが完成」とはしない。受信可能性、帯域、制御量、法規による制限もprofileとして異なる。

## 2. Adapterの能力

MTU、制御MTU、無線機ID、unicast/broadcast、同時TX数、half-duplex、同時受信profile数、rate設定scope、channel切替時間、利用可能receipt、観測可能metrics、送信時間モデル、法規上限、受信窓とsleep可否を申告する。

設定scopeはper-peer / per-radioを区別する。ESP-NOWのpeer別rateをLoRaへ無条件要求しない。複数SFの同時受信を単一SX1262へ期待しない。

## 3. APIの意味

start、submit、cancel-if-possible、set/configure、get-capability、estimate-cost、request-window、stop、eventsを共通化する。submitの成功はAdapter受付であり宛先配送ではない。

Radio Ownerは物理無線ごと一つ。NodeがESP-NOWとSX1262を持つとき、それぞれ独立Ownerを置き、全体Supervisorが資源・電力・相互干渉を調整する。Wi-Fi surveyで無関係なLoRaまで停止させない。

## 4. Core側

Message ID、membership、security、宛先の意味、deadline、diagnosticは維持する。path MTUや長い往復時間、sleep窓に応じたtimerとadmissionは変更する。無線profileが違っても下位の待ち時間と上位のRTOを矛盾させない。

終端暗号payloadを中継で勝手に変更せず、各linkの外側envelopeへ詰める。小MTUで通常payloadが収まらなければpath不可または明示的な別transfer APIにする。自動切り詰めは禁止。

## 5. v1で行う検査

実LoRaは送信しない。host fake adapterに低MTU、長いairtime、radio全体設定、長いRX窓、厳しい送信予算を与え、Coreが黙ってESP-NOW前提へ戻らないことを検査する。これはLoRaのRF受入ではない。

SX1262搭載boardでも初期profileはWi-Fiのみ。LoRa chipの未使用時電力・GPIO状態は[ボード資料](../hardware/xiao-esp32s3-wio-sx1262.md)で別途確認する。

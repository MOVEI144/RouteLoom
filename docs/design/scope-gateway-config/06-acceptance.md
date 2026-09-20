# 6. 受入・失敗注入・証拠

## 6.1 設計と実装の検査を分ける

[cases.json](cases.json)の46件は**planned_not_run**。今回のcheckerは登録値・数式・バイト形式の設計例・宣言の構文を検査するだけで、46件を実行した扱いにはしない。

実装時は各ケースへcommit、実行コマンド、fixture、観測点、expected/actual、ログ、結果を結び付ける。実コードが呼ばれないmodelだけで機能を完成扱いにしない。既存PR #2/#13の回帰試験を残す。

## 6.2 先に守る不変条件

1. ScopeMatchだけでMember・Gateway role・管理権限を得ない。
2. Source/destination MACはRX metadataで照合し、payloadの自称値を信用しない。
3. 明示Gateway/Host tokenは操作の途中で他の終端へ置換しない。
4. HOST_RECEIVE_RAMはReceiveLogへの実格納とそのUSB証拠より先に成功しない。
5. 同じMessageKey/操作IDの再提出は同じ仕事であり、ID・deadlineを作り直さない。
6. Configの署名/認可/保存/適用は別段階で、DECIDED/受領をACTIVEに昇格させない。
7. global Authority sequenceとper-target revisionを混ぜない。revとnonceはwrap/rollback禁止。
8. 不明な保存・時間・作用は不明と報告し、成功/未実行/新規受付へ変換しない。
9. protected recordを回収して受付率だけを改善しない。replayで保持時間を延長しない。
10. 単一Radio Owner、既存のfeasibility、control/data予算、Sleep/maintenance排他を迂回しない。

## 6.3 設計内の安全側補足（実装の必須条件）

**片側slot破損で過去の設定へ巻き戻らないこと。** 二重slotのうち一つだけ読めても、そのrecordが失われた新しいcommitより新しいとは証明できない。torn-writeであることをStorage契約で検証できる場合を除き、最後の検証可能snapshotを「既知の値」として扱うだけで、現在revision確定や新規更新受付を再開しない。CONFIG_STORAGE_UNCERTAINへ入り、Authorityからの認可済み回復証拠または再配備を必要とする。CRCだけで失われたhigh-water markを推定しない。両slot全損も同様。これは04の「生存recordから復旧」を制限する規範である。

Configのprepare/apply途中で元期限が尽きた場合、APPLY_INTENT前は開始禁止、後は完了/restoreを有限に進め結果を保存する。安全なrestoreを期限で中断して中途半端なactive状態を放置しない。結果は遅着として元操作へ結合し、新しい指示として送らない。

Gateway receipt表の60秒は**初回受理から**で、最大30秒の通信期限を含む。20件/分・burst8では任意60秒間に28件、余裕4を含め32枠とする。pending8件は同じ28件に含まれ、別に8件足して枠外へ受理しない。空き枠とtoken bucketの両方が必要。この計算はGateway専用endpointの運用profileでありRF容量の証明ではない。

Scope Offは既存非scoped挙動を保持する移行設定であり、productionでRequiredを指定した配備がkey loss時に遷移できる状態ではない。Scope Bindingのdomain付きhashとUSB Ingressサイズは05が正本。

## 6.4 テストの層

| 層 | 何を実行するか | 何を証明しないか |
|---|---|---|
| Design checker | 数式・例示bytes・登録値・リンク・負例manifest | runtime状態機械、暗号監査 |
| Portable unit/property | 本物のcodec・Coordinator・Storage fakeを使うS/G/C/Iケース | 実NVS/USB/RF |
| C++/Rust連結 | 実UsbBridge＋Host daemon、PTY、epoch/key/credit/receipt | 物理USB・無線品質 |
| IDF build | C3/S3/C5・reference/bridge・機能ON/OFF | 起動・到達距離・電池寿命 |
| HIL/RF | #11/#18の実配線・実機・実電波・電源切断 | 未保有ボード・未試験設置条件 |

## 6.5 実装で必須にする反例

Scope：同hint・異key100 responder、自己MAC偽装、録音再送、scope内/外density分離、鍵rotation直前の認証、正しいScopeだが失効機器、Required鍵喪失、Optional downgrade。

Gateway：A/B二出口、Host停止、同Host再起動、新USB session、body同ID異内容、Host格納後ACK喪失、GW受領後電断、96/97B境界、32枠飽和、reply Peer不足、部分書込み、偽Receipt。

Config：権限不足、global seqの他targetによる穴、同revisionの二要求、許可後に失効、同ID異patch、同offset異chunk、challenge期限切れ、各write/commit/apply/readbackで停止、片slot/全slot破損、restore失敗、Relay切断、channel planと競合。

## 6.6 実機試験の構成

2ノードは1hop。実3hop lineにはorigin＋Relay2台＋Gatewayの4台を使う。4台diamondで代替経路、A/B二Gatewayは別構成として記録する。アプリ上でedgeを禁止したmodelを実3hop到達と呼ばない。

Scopeの異key100 responderは先にmodelで確認し、実機は保有台数で二scope近接試験を行う。100台の実RF資格は別。C3手動smokeの既存記録を消さず、追加試験は固定SHAとboard/antenna/power/configへ結び付ける。

## 6.7 合否

安全性違反は一件でもfail。性能は既存のscope付き目標と投入負荷を測定前に固定し、成功標本だけで集計しない。未実施/失敗/対象外/blockedを区別。未知のRAM消費を0にせず、sizeofと内部heap低水位、Flash書込み回数・最大停止時間を測る。

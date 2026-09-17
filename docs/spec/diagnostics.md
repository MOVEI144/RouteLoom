# CLI・TUI・観測契約

## 1. 目的

「Joinできない」「通信が遅い」を段階と理由へ分解する。装飾的なGUIは必須にせず、Rust client API上のCLIとTUIを提供する。以下は実装対象のコマンド案であり配布済みbinaryではない。

```text
routeloomctl adapters          USB接続機器とsession
routeloomctl nodes             所属と接続状態
routeloomctl routes            宛先別の経路と採用理由
routeloomctl trace NODE        実際に観測する経路検査
routeloomctl links             方向・rate別の無線品質
routeloomctl events            Join・復旧・設定の履歴
routeloomctl radio survey      権限と停止許可付き調査要求
routeloomctl radio plans       準備・確定・実適用の状態
routeloomctl tui               同じ情報を画面更新で表示
routeloomctl export            機密を除いた検査記録
```

JSON出力と終了codeを機械処理向けに定義し、日本語表示は英語reason codeに短い説明を付ける。TUIから独自のUSB protocolを別実装しない。

## 2. 各Nodeの状態

Identity、Network、firmware、boardrevision、boot、membership、Power/availability、root/service到達、最終認証通信、primary/候補、controller状態、未完了queueを出す。

membership=MEMBERかつroute=ISOLATEDは正常な表現。SleepをOFFLINE故障と同義にしない。PCサービス停止とGateway radio停止を分離する。

## 3. 無線指標

channelのactive/committed/visit、LRprofile、方向別rate、sample数、成功/失敗/除外理由、SDK queue wait、driver time、link受理time、E2E分布、retry、credit、Peer枠を表示する。

各値にはrequested / driver-reported / measured / estimated / unavailableの区分を付ける。取得不能な内部MAC retryやNoise Floorを0にしない。AP数だけの健康scoreを主表示にしない。

## 4. 経路表示

近隣で実観測したedge、route tableの推定next hop、end-to-end traceで観測したpathを区別する。未観測hopを架空の線で埋めない。別neighbor経由でも共通故障点がある場合は独立予備と呼ばない。

snapshotには観測時刻とstale判定が必要。位置・階のラベルはアプリmetadataであって、RF距離やgeometryの実測ではない。

## 5. 例

```text
ノード: node-42
所属: MEMBER（認証・承認済み）
到達: ISOLATED（指定Gatewayへの経路なし）
無線: LR250 / home CH6
直近事象: LINK_NO_RESPONSE（保存した相手から応答なし）
復旧: 候補を検証中。探索残予算あり
最終成功: 時刻・Message ID
```

表示例の数値は実機結果に混ぜない。demoは明示demoモードに限定する。

## 6. ログ

固定長eventにNode、Radio、boot、各epoch、Message/token、monotonic timestamp、reason、前後状態、観測件数、結果を入れる。queue overflowやevent欠落そのものを数える。secret、鍵交換秘密、他人の無線payload、SSIDの常時保存は禁止。

参加前／孤立中のログもUSBから読めるようにする。通信できない原因を通信成功後しか取得できない設計にしない。遠端の詳細ログは低優先でpullし、平常時全ノードが全ログを送らない。

## 7. 受入

traceの期限、未確定probe、cancel、再接続、古いevent混入、subscriber遅延を試験する。成功したpacketのP95だけを出さず未達率と分母を同時表示する。


## 8. 成熟度と原因の表示

設計目標、未実装、未認定、実験有効、認定有効を区別する。LINK_NO_RESPONSEは物理撤去の確定ではない。実際にdriver Peerを削除した場合だけPEER_REMOVEDを使う。TIME_UNCERTAIN、ADMISSION_REJECTED、REPLY_CAPACITY_DROP、QUARANTINED_NON_VOTER、CONTROL_BUDGET_UNSATISFIABLEを理由付きで表示する。

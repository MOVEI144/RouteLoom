# Identity・参加・離脱・再接続

## 1. 識別の契約

NodeIDはcredentialへ結び付ける安定した機器Identity。short addressやWi-Fi MACとは別。NetworkIDは論理所属先でありSSIDではない。隣接ノード、現在の親、Gateway、無線channelは所属Identityに含めない。

短いwire handleを使う場合は、正当な管理世代内で一意に割り当て、再利用時に旧packetと区別する。再起動やflash初期化後に同じIDを無認証で名乗ることはできない。

## 2. 状態

`UNPROVISIONED → DISCOVERING → AUTHENTICATING → AUTHORIZED_PENDING_COMMIT → MEMBER`。

接続状態は独立に `REACHABLE / DEGRADED / ISOLATED / SLEEPING`。管理者による失効は `REVOKED`、明示的離脱は `LEFT`。ISOLATEDやSLEEPINGをUNPROVISIONEDへ変換しない。

## 3. 初期準備

工場または初回安全設定で機器鍵と必要なtrust anchorを導入する。登録に使う公開QRは識別子・fingerprint等だけでもよく、秘密鍵をQR必須にしない。鍵生成の乱数、debug port、書込み時の取扱いは[セキュリティ](security.md)に従う。

承認Providerは `preapproved / interactive / time-limited` 等を提供する。物理ボタンを押したことだけで相手の本人確認を省略しない。インターネットをJoinの必須条件にしないが、管理多数・trust・許可が必要な構成では不足を明示する。

## 4. 1hop発見、multi-hop参加

1. 新規ノードが候補channelでLR250のDISCOVERを送る。
2. 既存の受信可能な中継器が乱数窓でOFFERを返す。候補のRoot距離は認証前にはヒントだけ。
3. 少数候補から参加proxyを選び、双方向通信を確認する。
4. proxyは有界なbootstrap転送だけを提供し、要求を正当な承認／認証先へ運ぶ。
5. ノードと正規認証先が標準の相互認証を行う。proxy自身を任意の認証局にしない。
6. アプリの承認方針を通し、所属・権限・必要鍵を正当な管理ログへcommitする。
7. ノードがmembership証拠を保存して確認し、通常通信と経路参加を許す。

全候補の最適化完了を待たず、十分使える経路でJoinを完了する。認証ハンドシェイクが重い場合は管理object転送を使う。人間の承認待ちは無線Join時間と別に計測する。

## 5. bootstrapの制限

DISCOVERは局所1hopだけ。未認証データを全網へFloodしない。cookie、rate limit、応答数上限、object長上限、組立timeoutを使う。preauth bootstrapの枠は少なくし、正規DATAを塞がない。

preauth proxyは管理先以外へ任意のpayloadを送る公開relayにはしない。authorizationが完了する前にroute広告、中継許可、service広告を受け入れない。

## 6. 再接続

Deep Sleep復帰ではvalidな所属・暗号counterを復元できれば、保存済みchannel/相手へデータ本体から送る。再起動で暗号状態が不明なら安全なsession再確立を行うが、現場への承認し直しとは分離する。

相手が撤去された場合は予備・発見へ進む。新しい相手との鍵確立に時間がかかる場合、単にrouteが見えるだけでアプリに即時到達可能とは返さない。

## 7. 削除と転用

削除はUIから消すだけでなく、membership失効をcommitし、認証・route・service・新規配送への利用を止める。既に送信済みのpacketや遠端に保存されたデータを物理的に回収できるわけではない。

失効要求受付、管理確定、到達中ノードへの反映、本人への通知を分ける。分断された古い群には失効が即時届かない。厳しい運用ではcredentialの有効期間とtrusted time／再検証機会を設定する。未知の時計で有効期限を勝手に延長しない。

別Networkへの転用は旧所属終了と新規所属を別操作にする。旧ネットワークのpendingデータを新ネットワークへ書き換えない。機器秘密鍵の継続方針とネットワーク鍵の削除は別。

[管理合意](control-plane.md)／[配送](delivery-storage.md)


## 8. 状態別のbootstrap許可（規範）

表はローカル状態で送受信し得る意味型の上限（実装済み機能の一覧ではない）。型が許可されても相手の資格・方向・宛先・transaction・資源条件の検証は省けない。正本は[semantics.json](../../protocol/semantics.json)。

<!-- generated:join:start -->
| ローカル状態 | 型の上限（条件付き） |
|---|---|
| UNPROVISIONED | DISCOVER, OFFER |
| DISCOVERING | DISCOVER, OFFER |
| AUTHENTICATING | DISCOVER, OFFER, BOOTSTRAP_AUTH, BOOTSTRAP_CHUNK, BOOTSTRAP_REPLY |
| AUTHORIZED_PENDING_COMMIT | MEMBERSHIP_QUERY, MEMBERSHIP_RESULT, BOOTSTRAP_REPLY, BOOTSTRAP_CHUNK |
| MEMBER | DISCOVER, OFFER, BOOTSTRAP_AUTH, BOOTSTRAP_CHUNK, BOOTSTRAP_REPLY, MEMBERSHIP_QUERY, MEMBERSHIP_RESULT, DATA, GROUP_DATA, GROUP_REPORT, HOP_ACCEPT, BUSY, END_RECEIPT, APP_RESULT, ROUTE_UPDATE, ROUTE_REQUEST, SEQNO_REQUEST, SERVICE, CONTROL, TIME_SYNC, NEIGHBOR_PROBE, NEIGHBOR_RESULT, ROUTE_WITHDRAW, CONTROL_OBJECT, OBJECT_CHUNK, OBJECT_ACK, CHANNEL_NOTICE, DIAGNOSTIC |
| REVOKED | 通常通信禁止。明示再provisioningは別経路 |
<!-- generated:join:end -->

DISCOVER/OFFERは未認証・局所1hop・RLD1 envelope全体で160B以下（[無線仕様](radio.md)参照）。UNPROVISIONEDはtrustが未導入なら発見までで止める。AUTHENTICATINGに入る最初のBOOTSTRAP_AUTHはcookieとNetwork制約を先に確認して新規transactionへ結び、以後のCHUNK/REPLYはそのID・相手・宛先・期限内だけ許す。

AUTHENTICATINGのpeer本人性はまだ未確定。ROLE承認を先取りしない。MEMBERSHIP_RESULTは認証済みtranscriptと正当なAuthority決定へ結び付け、保存成功後にのみMEMBERへ移る。単なるOFFERにはその権限がない。

MEMBERのproxyは非memberから通常DATA/ROUTE/SERVICEを受けず、許可されたbootstrap型だけを正規認証先へ転送する。一般MEMBER間のallowlistをpreauth ingressへ適用してはいけない。preauth最大object1024B、同時1、総pool1536B、期限3秒等は[資源profile](resource-profiles.md)に従う。大きいcredentialは別profileの認定まで拒否する。

REVOKEDは通常resume禁止。情報の再取得や再provisionは物理管理または別の承認済み手順とし、未知frameを口実にmembershipを消去しない。

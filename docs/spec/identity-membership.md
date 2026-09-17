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

# Edge PC接続サービスとクライアントAPI

## 1. 成果物と配置

Rust製routeloom-hostがUSB adapterを所有し、routeloomctlとTUI、利用アプリが同じHost APIへ接続する。PC上のアプリをESP32へ載せる必要はない。ESP32側にはGateway bridge＋通常Mesh SDKをビルドする。

一つのdaemonが複数USB adapterと複数ネットワークを扱える。adapter、Network、Gateway、host serviceを別の識別子にする。相互転送は明示許可がある場合だけで、v1は異Networkの透過bridgeを提供しない。

## 2. 必須責任

USB検出、機器Identity照合、再接続、protocol/capability照合、送受信credit、pending仕事、配送結果、diagnostic ring、設定と参加承認の受け渡しを担当する。通常のradio経路選択は行わない。

Linux常駐、macOS/Windows開発利用を設計対象にする。USB device path、COM番号、ポート列挙順を永続Identityにしない。同じUIDが二つ現れたら競合として隔離する。

## 3. Host API

初期の操作意味は以下とし、RPC schemaを版管理する。

| 操作 | 意味 |
|---|---|
| adapters.list/watch | 接続機器と能力・session |
| networks.list/get | 所属網とchannel/管理状態 |
| nodes.list/get | Nodeの観測・認証・可用性 |
| messages.send/cancel/get | 非同期配送と証拠 |
| messages.subscribe | 認証済み受信とcursor |
| services.register/renew/remove | host受信先とlease |
| membership.approve/revoke | 権限付き参加操作 |
| config.propose/get | expected revision付き設定 |
| diagnostics.snapshot/watch | 指標と理由付きevent |
| radio.survey/migrate | 正式権限と計画に基づく要求 |
| objects.transfer/status | bounded保守転送 |

API受付のoperation IDと無線Message IDは別に返す。idempotency keyはhost再接続後も指定scope内で有効。操作成功、管理commit、機器へのapplyを別stateで返す。

## 4. ローカル接続と認可

既定はローカルIPC（Unix socket／対応するWindows IPC）で、OS権限を用いる。TCPを使う開発構成もloopback限定で認証する。LAN公開、リモート管理、ブラウザアクセスは既定OFF。明示TLS/認証/認可なしで0.0.0.0へbindしない。

権限はread diagnostics、send application data、approve membership、change config、update firmware等を分離する。CLIだから管理者という扱いにしない。秘密鍵exportは標準APIに設けない。

## 5. 接続と再起動

接続時HELLOでUSB protocol version、機器ID、boot session、firmware hash、capabilities、Network、RF状態を取得する。必要な認証とchallengeを行い、新しいUSB sessionを発行する。

旧sessionの結果は新sessionのtokenへ結び付けない。daemon再起動時は安定Message IDを照会し、重複再送しても意味が増えないようにする。受信streamのcursorが巻き戻ったらloss/dup可能性を明示する。

サービス停止はleaseを失効させる。Gateway無線が正常でもservice not availableを表す。明示Gateway宛ての要求を勝手に別PCで受けて完了にしない。

## 6. 保管

RAM／任意の永続spoolを有界にする。message単位で保存方針、容量超過、expiryを定める。指定された永続受理は実store commit後にのみ返す。daemonがACKを返した直後に落ちる試験を行う。

複数クライアントへ通知するとき、一つの遅いsubscriberでUSB受信を停止しない。各subscriberにcursor、有限queue、overflow通知を設ける。TUIは観測者であり、終了してもspoolや通信が停止しない。

## 7. 実装公開前

ここにあるコマンドやservice名は仕様案であり、cargo installで取得できる配布物ではない。package、RPC IDL、OSごとのinstaller、再起動試験をG-SYSTEMで認定する。

[USB](usb-protocol.md)／[CLI・診断](diagnostics.md)／[配送](delivery-storage.md)


## 8. idempotency・受理・client上限

operation identityは `(authenticated principal, Network, operation class, idempotency key)`。同identity異payload hashはCONFLICT。同じ操作の再送は保存済み状態を返し、別Networkや別principalを同じkey文字列で混同しない。hashは意味をcanonical化した要求（宛先・期限方針・保存・権限scope含む）から作る。

初期host保持契約は完了結果24時間（最大4096件／32MiB）、未確定操作は自動再実行せずINDETERMINATEとして保持する。容量不足なら新操作を拒否し、保護中entryを追い出さない。保持を終えた古いkeyの再送を新操作と誤認しないよう、principal単位の受付epochを用いる。expiry前に照会し、epoch終了後の旧keyはIDEMPOTENCY_WINDOW_EXPIRED。新epochでの新操作は明示的な再発行であり自動retryではない。

client初期上限：同時operation8、subscription4、各subscriber queue128eventsかつ256KiB、1event8KiB以下。遅いreaderへcursor gapを通知し、別clientや無線を停止しない。quotaはprincipalとglobal（32clients、8MiB subscriber総量）の両方を検査する。

HostAuthのtranscript／COMMAND保護は[USB](usb-protocol.md)に従う。DATA受領の意味と永続spool commitを分け、requestを記録せず副作用を先に実行しない。

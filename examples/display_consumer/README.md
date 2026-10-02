# 表示板型アプリの API1 consumer

汎用の状態表示用 example。Python 標準 library のみで local Unix socket の API1 を読み、record と cursor を SQLite の同じ transaction に保存する。SDK の機器 code・認証判断・別 mesh engine は持たない。表示するアプリは保存済み `record` の payload を自分の binary schema で解釈する。

```sh
umask 077
python3 examples/display_consumer/consumer.py --socket /path/to/api.sock \
  --network 00000000524c0001 --db /path/to/private/display.db --once
```

`--once` を外すと 1 s ごとに読む。network は現在の API1 が受理する low 32-bit range（先頭 8 桁が 0）、ACL は READ_PAYLOAD が必要。Member の epoch 付き full network の受信は未対応。履歴は 4096 record で古い順に削除する。保持中の key を重複保存しないが、無期限の業務 exactly-once を保証するものではない。業務 event の保存・署名・operation ID は利用側で実装する。

poll 後・commit 前の crash では cursor が進まず再読込になる。commit 後の crash では同じ cursor から続く。DB のエラー・CURSOR_GAP・CURSOR_EPOCH_CHANGED では停止し、cursor を自動変更しない。欠落を記録して復旧方針を決めた後だけ、`--resume-cursor TOKEN` で再開する。cursor 自体は認証情報ではないが、DB に payload が入るので private に保管する。

view を 5 s ごと、状態を 15 s ごと、変化 event を必要時に送る負荷は [利用ガイド](../../docs/user/guide.md)参照。機器の C/C++ app は [endpoint examples](../endpoint_cpp/README.md)の Device を使い、Owner job から送信する。K01／K05／P06 の [実 Owner smoke](../../docs/user/quickstart.md)はこの consumer を実行する。mock は decoder の開発に使うだけで E2E の代わりにしない。

# API1 契約 kit

API1 は local IPC の行 protocol。daemon へ `API1 ` + UTF-8 JSON + LF を送り、応答は JSON + LF（prefix なし）。request は全行 8192 B、response は全行 65536 B、JSON depth は 8。duplicate key、非 RFC 8259 の数、未知の envelope field を拒否する。byte/depth／ACL／cursor の意味は JSON Schema だけでは検査できない。

| 配布物 | 範囲 |
|---|---|
| [request.schema.json](../../protocol/api1/request.schema.json) | envelope、capabilities/capacity の無引数、messages.read 引数。他 method の params は [host 正本](../spec/host.md)参照 |
| [response.schema.json](../../protocol/api1/response.schema.json) | success/error envelope。追加 field を許容 |
| [read-result.schema.json](../../protocol/api1/read-result.schema.json) | 受信 record、cursor、保持量。payload_len と hex の一致は別途確認 |
| [fixture](../../protocol/api1/fixtures/read.json) | 公開の合成 payload。秘密・実機 identity を含めない |
| [mock daemon](../../tools/api1_mock/daemon.py) | fixture の request に応答。RF／認証／永続化／rate／参加の実装は無い |
| [method 一覧](api1-methods.md) | 現在の production dispatch から生成 |

```sh
python3 tools/check_api1_contract.py
printf '%s\n' 'API1 {"v":1,"request_id":"read-1","method":"messages.read","params":{"network":"00000000524c0001","from":"earliest","limit":32}}' | python3 tools/api1_mock/daemon.py
# private directory 内で socket を使う場合
python3 tools/api1_mock/daemon.py --socket /path/to/private/mock.sock
```

Schema validation は `jsonschema`（[文書依存](../../tools/requirements-docs.txt)）、mock は Python 標準 library のみ。mock は fixtures の method/params が一致したものを replay し request_id を返す。未用意の操作は UNSUPPORTED_METHOD。mock の成功を E2E の代わりにしない。[入門の実 Owner smoke](../user/quickstart.md)を実行する。

consumer は `(network, origin, message.session, message.sequence)` を保存の重複抑制 key にし、record と `next_cursor` を同じ transaction に commit してから次を読む。payload の業務 ID があるなら再起動をまたぐ dedup に使う。cursor は opaque で permission ではない。`CURSOR_SCOPE_MISMATCH`、`CURSOR_EPOCH_CHANGED`、`CURSOR_GAP` はそれぞれ認可 scope／daemon 再起動／保持切れの異なる失敗である。

再起動では `loss_count` が null、保持切れでは `lost_from`／`lost_to` を返す。利用者が欠落の扱いを決め、`oldest_cursor` から保存済み record と照合して再開するか、tail から新規観測を始めるかを選ぶ。黙って latest に切り替えない。[consumer example](../../examples/display_consumer/README.md)は失敗で停止し、明示的な `--resume-cursor` でのみ変更する。

push を使うときは subscribe の成功応答を待つ。notification はその後、接続終了で subscription は消える。overflow/gap と heartbeat を扱い、notification の受信を durable 成功と扱わない。すべての権限・各 method の意味は [host 契約](../spec/host.md)が正本。

## 現在の制約：Member の受信

`messages.read` の network 引数は `00000000` + low 32-bit の 8 桁を受理する。一方、Member の receive log は HostLink で認証した epoch 付き full network を保存する。現在の main は full network の read を INVALID_ARGUMENT で拒否するため、この経路を利用可能とは案内しない。上位 bit を落とす workaround は異なる scope になり、正しい解決ではない。実 Owner の `K05-M` は red（ignore を外すと失敗を再現）。修正は別 PR で追跡する。DevRam の low-word network での入門・consumer smoke は別に検証する。

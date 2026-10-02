# 運用：daemon・backup・更新・診断

## 導入と権限

[入門](quickstart.md)でビルドした host binary を service user の実行場所へ配置する。root で常用せず、必要な serial device への access だけを与える。API1 の ACL は OS UID／Windows SID に結び付く。Linux の最小 read-only 例：

```json
{"principals":{"1000":{"networks":{"00000000524c0001":["READ_PAYLOAD","READ_OPERATION"]}}}}
```

network は利用する network に置き換える。Member の受信では epoch を含む full 64-bit network を ACL と読取り引数の両方に指定する（[API1 scope](../api/api1.md)参照）。送信には SEND、所属の観測／判断／管理は MEMBERSHIP_READ／MEMBERSHIP_DECIDE／MEMBERSHIP_ADMIN を用途ごとに足す。socket は 0600、親 directory は service user のみが使えるようにする。[host §4](../spec/host.md)が認可の正本。

systemd の例。パス・ユーザー・device を利用環境に合わせ、service 起動前に credentials と directory の owner/mode を確認する。daemon は接続断後に再接続する。

```ini
[Unit]
Description=RouteLoom local mesh service
After=local-fs.target

[Service]
User=routeloom
Group=routeloom
RuntimeDirectory=routeloom
RuntimeDirectoryMode=0700
StateDirectory=routeloom
StateDirectoryMode=0700
UMask=0077
ExecStart=/opt/routeloom/routeloom-host --socket /run/routeloom/api.sock --device /dev/serial/by-id/GATEWAY --api-acl-file /etc/routeloom/acl.json --op-store /var/lib/routeloom/operations.db --site-authority /var/lib/routeloom/site --hostlink-credentials /var/lib/routeloom/hostlink
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

HostLink directory は 0700、各 `<NodeId>.key` は 0600 の通常 file。長さは ASCII 1〜63 byte、改行なし。認証に失敗したときは mode、NodeId、device/host の secret 一致を確認する。秘密そのものを log に出さない。`--usb-dev-secret-file` は開発用で directory 方式と併用できない。[HostLink](../spec/usb-protocol.md)参照。

## v2 の host 運用

1. gateway と daemon を HostLink protocol 2 に揃え、起動ごとに `capabilities.get`／`capacity.get`／`link.get` を確認する。channel plan の RELEASE payload も更新済みの対で使う。
2. Member の Site Authority と承認 consumer を用意する。`decision_mode` の出力は `external`（旧 `kguard` は入力 alias のみ）。所属、認証済み connectivity と配送証跡を分けて見る。
3. 賢い参加は `join.policy.set` の `expected_devices`（最大 3 mark）と `expected_ttl_s` を設定し、proxy の保存確認と期限を監視する。mark は private、取消は空一覧。機器の Device join policy は別である。
4. group は `group.send/get` の FINAL と missing を確認する。AppObject は対応 gateway と終端が必要で、`objects.submit/get/cancel` を使う。object operation は RAM で、daemon 再起動後の token を再利用しない。通常 message の耐久 operation と同じ保存保証だと扱わない。
5. legacy SEND の同じ key は接続中の同じ内容にだけ使う。`RESULT_EXPIRED`／indeterminate を未実行と見なさず、再接続後は同じ legacy key を再送しない。業務 ID と耐久 dedup はアプリで管理する。

[host 契約](../spec/host.md)、[所属・AppObject の手順](migrating-v2.md)、[Kconfig](configuration.md)を参照する。reference／bridge／bench は MemberEdhoc が既定、開発 examples は DevRam。Candidate と Development を本番認定と表示しない。

## backup と復元

受信 log は RAM（300 s／network あたり 4096 件／2 MiB）。daemon 再起動で epoch が変わる。consumer の業務 record と cursor は自前 DB の同じ transaction に保存する。daemon の operation DB とは別である。

書込み中の SQLite file だけを `cp` しない。保守時間を取り daemon と consumer を停止し、operation DB、site directory（DB・鍵・設定）、HostLink directory、ACL、consumer DB を owner/mode とともに一式で backup する。WAL／SHM が残っているならそれも含める。backup は private storage に置き、checksum、SDK commit、manifest、schema を記録する。稼働中 backup が必要な運用では SQLite backup API を使い、一貫性を確認する。

復元は停止中に行い、schema の対応範囲・所有者・権限を確認する。古い backup に戻すと authority の epoch、失効状態、operation の重複抑制を巻き戻す可能性があるため、稼働中の機器へそのまま接続しない。機器と host の耐久 floor を照合し、必要なら隔離して再 provision する。成功応答の記録を失った operation は「未実行」と断定しない。[互換性](../spec/compatibility.md)と[電源断契約](../spec/crash-time-resources.md)参照。

## 更新と困ったとき

旧開発版からの移行は [v1 → v2](migrating-v2.md)。同じ PT-4M-v2 の app-only 更新でも BoardConfig・identity の hash/readback を確認し、NVS を保持する。eFuse を操作する手順はこの guide に含めない。OTA rollback の設定があることと app の健全性確認・更新の機能認定は別である。

| 症状 | 最初に確認すること |
|---|---|
| USB_SECRET_REQUIRED | BoardConfig の USB secret。RF 起動前の拒否である |
| link が disconnected | serial port の排他、再列挙、HostLink 認証。`link.get` の last_error |
| node が見えない | membership と connectivity、role/profile、channel、認証済み route。cached node 一覧を新しい配送の証拠にしない |
| Busy／Capacity／RATE_LIMITED | `capacity.get`、inflight、profile。deadline 内に pace し、無限 retry しない |
| CURSOR_GAP | 業務上の欠落を記録し、明示的な復旧方針で oldest/tail を選ぶ |
| CURSOR_EPOCH_CHANGED | daemon の再起動。loss 数は不明。consumer の cursor を黙って破棄しない |
| channel 切替後に届かない | [HC6 の未合格 HIL](../hil/2026-10-02-hc6.md)。READY/commit だけで合格としない |

再現には SHA、profile、chip/MAC（公開してよいもの）、単調時刻の区間、エラー code、image/sdkconfig hash を記録する。鍵・NVS dump・認証 token は公開 artifact に含めない。HIL は [runbook](../hil.md)に従い、chip/MAC の直前確認、serial 排他、app-only/readback、reset と電源断の区別を守る。到達距離と電池寿命は現場で測定する。

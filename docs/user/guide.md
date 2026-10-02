# 利用ガイド

この guide は現在の main の利用入口を説明する。数値と wire の正本はリンク先、未マージ機能は[文書案内](../README.md)の pending 表を参照する。

## 配備と容量

| 配備 | 用途と条件 |
|---|---|
| USB gateway + host | Site Authority、送信の耐久 operation、受信の cursor、履歴・UI を host に置く |
| standalone gateway | [example](../../examples/standalone_gateway/README.md) の実 app が応答する。Member の参加後は既存 session で通信できるが、host 不在では新規参加・GK 更新・失効・cutover が止まる |
| IP gateway／UART coprocessor | v2.1 の予定。現在の導入手順は無い。STA と LR の同時運用を保証しない |

role は endpoint／relay／gateway、compile-time profile は [resource profiles](../spec/resource-profiles.md) と [Kconfig](../api/kconfig.md)で選ぶ。C3 `gateway_small` の E2E 相手は既定 64、128 は選択構成。S3/C5/C6 の `gateway` は 128。相手数は同時 session 容量であり、到達可能な mesh 台数・同時参加人数・RF 認定台数とは別。endpoint を relay に転用するなら role と profile の両方を合わせる。満杯で使用中の session を追い出さず、Busy／Capacity を扱う。100 台の model を RF 100 台の成功と読まない。

## 所属・接続・移設

`membership()`／`rl_dev_membership()` で所属、`connectivity()` で gateway への認証済み接続の証拠を見る。Unknown は不明、Reachable は証拠あり、Degraded／Isolated は劣化／孤立、Sleeping は休止。所属済みでも経路があるとは限らない。

`request_join()` は操作 ID を返す。callback の JOINED／JOIN_DENIED／JOIN_TIMEOUT まで追跡する。`set_join_policy` は範囲と generation の CAS を検査する。Device の設定と host の `join.policy.set`（Site Authority の承認方針）を混同しない。`leave()` は耐久 intent の後に送信を止め、所属を消去して LEFT に至る。identity は残る。移設 A→B→A は旧現場で leave を完了してから新現場で参加する。失効後の再参加は assignment generation と GK epoch を揃え、旧 session の送信を使い回さない。[Device 契約](../spec/sdk-api.md)、[所属仕様](../spec/identity-membership.md)。

賢い参加（#197／V2-18）は pending。予定一覧を使う探索の具体的な API はマージ後に案内する。旧所属を保った自動移設は v2.0 の対象外。

## 送信と表示板型アプリ

通常 payload は最大 128 B、explicit gateway は 96 B、group は 127 B。SDK は超過を暗黙分割しない。受付成功、END_RECEIVED、APP_APPLIED を区別する。業務上の一度だけの作用は application operation ID と永続化で管理する。非同期 APPLIED は ticket を使い、commit/readback の後に完了する。[配送仕様](../spec/delivery-storage.md)。

[汎用表示板 consumer](../../examples/display_consumer/README.md)は、受信 record と cursor を SQLite の同じ transaction に保存する。view は 5 s、状態は 15 s、変化 event は必要時、という負荷の例。更新を送るときは host の `--admission-profile control` と `queue_mode=LATEST_PER_DESTINATION`、機器の BEST_EFFORT `coalesce_key` を使う。RELIABLE／APPLIED との組合せは InvalidArgument。順序が必要な命令や積算 event に latest を使わない。

host `normal` は主体／全体とも 2 admission/min、burst 16。`control` の latest lane は宛先 12/min・burst 4、主体 300/min・burst 32、全体 600/min・burst 32（[host 負荷契約](../spec/host.md)）。送信 rate は RF の保証ではない。`capacity.get` の実効値で pace し、RATE_LIMITED を明示的に扱う。直接構成の K01-S と、5 台／3-hop の K01-D（現在 warm-up が期限切れで red）、H4 の現場資格は別である。

## sleep・遠隔設定・channel・大きいデータ

sleep 一本化と期限駆動（V2-15）は pending。既存 coordinator の保存／復元契約は[power](../spec/power.md)にあるが、未マージの Device sleep API を app の手順に入れない。sleep 端末は relay として常時受信を保証しない。電池寿命は電池側の実測が必要。

remote config は `config.challenge` → 認可した permit → `config.propose` → `config.get` の適用結果・revision/hash readback を確認する。Member は採用した site の SAK、DevRam は開発鍵。host の保存だけで APPLIED を表示しない。[remote config](../spec/remote-management.md)。

channel plan は MemberEdhoc 専用。`site.channel_plan.sign/offer/status/release` で署名、全員の READY、release、適用観測を分ける。DevRam は固定 channel で Manual/Observe を拒否する。実機の 6→1 は未合格なので、この機能の配備前には[最新 HIL](../hil/2026-10-01-stab-fix.md)と[計画契約](../spec/channel-migration.md)を確認する。

AppObject（V2-19）は pending。frame 番号の予約があっても転送 capability を実装済みと扱わない。通常 send の上限内の binary を使い、圧縮・group object・OTA・IP transport の手順を追加しない。

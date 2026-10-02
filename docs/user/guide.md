# 利用ガイド

v2 の利用入口。実効機能は capability、数値と wire はリンク先の正本で確認する。実機の残る条件は [STATUS](../STATUS.md)を参照する。

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

賢い参加（V2-18）は opt-in。Owner で join policy と revision を読み、`smart_join` と受信・探索の期限を設定して CAS で保存する。`join_mark` の値を非公開で管理し、host の `join.policy.set` に最大 3 件の `expected_devices` と TTL を設定する。proxy の保存確認後に探索し、取消・期限切れ・JOIN_TIMEOUT を扱う。予定 mark は Authority の許可を代替しない。具体的な手順は [移行ガイド](migrating-v2.md)。旧所属を保った自動移設は v2.0 の対象外。

## 送信と表示板型アプリ

通常 payload は最大 128 B、explicit gateway は 96 B、group は 127 B。SDK は超過を暗黙分割しない。受付成功、END_RECEIVED、APP_APPLIED を区別する。業務上の一度だけの作用は application operation ID と永続化で管理する。非同期 APPLIED は ticket を使い、commit/readback の後に完了する。[配送仕様](../spec/delivery-storage.md)。

[汎用表示板 consumer](../../examples/display_consumer/README.md)は、受信 record と cursor を SQLite の同じ transaction に保存する。view は 5 s、状態は 15 s、変化 event は必要時、という負荷の例。更新を送るときは host の `--admission-profile control` と `queue_mode=LATEST_PER_DESTINATION`、機器の BEST_EFFORT `coalesce_key` を使う。RELIABLE／APPLIED との組合せは InvalidArgument。順序が必要な命令や積算 event に latest を使わない。

host `normal` は主体／全体とも 2 admission/min、burst 16。`control` の latest lane は宛先 12/min・burst 4、主体 300/min・burst 32、全体 600/min・burst 32（[host 負荷契約](../spec/host.md)）。送信 rate は RF の保証ではない。`capacity.get` の実効値で pace し、RATE_LIMITED を明示的に扱う。5 台／3-hop の K01、31 台の K02 は実 Owner harness に登録されている。夜間の長い variant と H4 の実機資格は別である。[行列](../../tests/e2e/scenarios.json)の note と未受入 half を確認する。

## group／ALL

[短い sample](../../examples/group_send/README.md)のように、Owner の job／poll hook から `send_group` を使う。DevRam は同じ root の gateway-scoped tree、Member は SitePackage の group tree を使う。flat routing と flat group tree は別の設定である。ALL は全 member、任意 group は所属設定に従う。host は `group.send/get`、capability bit 7 を確認する。受付と集約 FINAL を分け、missing／unaccounted を含めて結果を扱う。group の未決着状態は sleep image に永続化しない。[group 契約](../design/sdk-v1/group-delivery.md)を参照する。

## sleep・遠隔設定・channel・大きいデータ

sleep と期限駆動（V2-15）は実装済み。非 gateway の `ROUTELOOM_DEEP_SLEEP` は Device の既存 coordinator を使い、prepare → drain → 保存/readback → ticket → enter で入眠する。[sleep sample](../../examples/sleep/README.md)で起動し、活動・radio-on・timer の予算を [Kconfig](configuration.md)で選ぶ。独自 app は Owner から `prepare_sleep` と有効な ticket の `enter_sleep` を使い、別 task は post で渡す。sleep 端末は常時受信を保証しない。RTC drift と電池側電流は H2 実施予定。[power](../spec/power.md)が契約の正本。

remote config は `config.challenge` → 認可した permit → `config.propose` → `config.get` の適用結果・revision/hash readback を確認する。Member は採用した site の SAK、DevRam は開発鍵。host の保存だけで APPLIED を表示しない。[remote config](../spec/remote-management.md)。

channel plan は MemberEdhoc 専用。`site.channel_plan.sign/offer/status/release` で署名、全員の READY、release、適用観測を分ける。DevRam は固定 channel で Manual/Observe を拒否する。実機の 6→1 は未合格なので、この機能の配備前には[最新 HIL](../hil/2026-10-01-stab-fix.md)と[計画契約](../spec/channel-migration.md)を確認する。

AppObject（V2-19）は既定 OFF。origin と受信終端で `ROUTELOOM_APP_OBJECT_TRANSFER` を有効にし、最大 4096 B の認証済み unicast を `send_object`／`objects.submit` で送る。中継は OFF でも転送できる。buffer loan の寿命、期限と完了 observer／`objects.get` を扱う。[移行手順](migrating-v2.md)と [配送契約](../spec/delivery-storage.md)を参照する。圧縮・group object・OTA・IP transport は提供しない。

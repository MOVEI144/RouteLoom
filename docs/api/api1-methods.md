# API1 method reference

生成元を編集し、`python3 tools/gen_user_reference.py` で更新する。

実装の dispatch 一覧。Site Authority の method は `--site-authority` が必要。
各引数・認可・結果は [host 契約](../spec/host.md)、[契約 kit](api1.md) を参照。
capability の `methods` を毎接続で確認する。受付と最終成功は別である。

| Method | 契約 |
|---|---|
| `capabilities.get` | [host](../spec/host.md) |
| `capacity.get` | [host](../spec/host.md) |
| `config.challenge` | [host](../spec/host.md) |
| `config.get` | [host](../spec/host.md) |
| `config.propose` | [host](../spec/host.md) |
| `config.recover` | [host](../spec/host.md) |
| `config.recovery_info` | [host](../spec/host.md) |
| `config.retry` | [host](../spec/host.md) |
| `config.status` | [host](../spec/host.md) |
| `devices.discovered.list` | [host](../spec/host.md) |
| `diagnostics.snapshot` | [host](../spec/host.md) |
| `gateway.get` | [host](../spec/host.md) |
| `gateway.resolve` | [host](../spec/host.md) |
| `group.get` | [host](../spec/host.md) |
| `group.send` | [host](../spec/host.md) |
| `group_keys.rotate` | [host](../spec/host.md) |
| `group_keys.status` | [host](../spec/host.md) |
| `health.get` | [host](../spec/host.md) |
| `join.decide` | [host](../spec/host.md) |
| `join.policy.get` | [host](../spec/host.md) |
| `join.policy.set` | [host](../spec/host.md) |
| `join.requests.list` | [host](../spec/host.md) |
| `lab.rollcall.start` | [host](../spec/host.md) |
| `lab.rollcall.status` | [host](../spec/host.md) |
| `lab.rollcall.stop` | [host](../spec/host.md) |
| `lab.rollcall.update` | [host](../spec/host.md) |
| `link.get` | [host](../spec/host.md) |
| `members.get` | [host](../spec/host.md) |
| `members.list` | [host](../spec/host.md) |
| `membership.archive` | [host](../spec/host.md) |
| `membership.cutover` | [host](../spec/host.md) |
| `membership.revoke` | [host](../spec/host.md) |
| `messages.read` | [host](../spec/host.md) |
| `messages.submit` | [host](../spec/host.md) |
| `messages.subscribe` | [host](../spec/host.md) |
| `messages.subscriptions` | [host](../spec/host.md) |
| `messages.unsubscribe` | [host](../spec/host.md) |
| `nodes.get` | [host](../spec/host.md) |
| `nodes.list` | [host](../spec/host.md) |
| `operations.cancel` | [host](../spec/host.md) |
| `operations.get` | [host](../spec/host.md) |
| `operations.get_by_key` | [host](../spec/host.md) |
| `operations.open_epoch` | [host](../spec/host.md) |
| `site.channel_plan.offer` | [host](../spec/host.md) |
| `site.channel_plan.release` | [host](../spec/host.md) |
| `site.channel_plan.sign` | [host](../spec/host.md) |
| `site.channel_plan.status` | [host](../spec/host.md) |
| `site.status` | [host](../spec/host.md) |
| `topology.get` | [host](../spec/host.md) |
| `trust.install` | [host](../spec/host.md) |
| `trust.status` | [host](../spec/host.md) |

# Protocol contracts（意味の契約）

[semantics.json](semantics.json)は参加状態、保護範囲、識別、期限とフロー制御の正本である。**Wire ABI、暗号suite、type番号は未凍結**。仮の暗号やダミーtagを置いて互換性を実証したとはしない。

[参加](../docs/spec/identity-membership.md)、[Wire](../docs/spec/wire-protocol.md)、[永続化](../docs/spec/crash-time-resources.md)、[USB](../docs/spec/usb-protocol.md)と合わせて読む。

`tests/test_contracts.py`は意味の負例を検査する小モデル。ESP32実装、暗号Provider、Babel全体、Raft、実RFの正しさの証明ではない。最終encoder・C/Rust共通golden vectorは実装選定時に追加する。

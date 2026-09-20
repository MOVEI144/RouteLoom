# Protocol contracts（意味の契約）

[semantics.json](semantics.json)は参加状態、保護範囲、識別、期限とフロー制御の正本である。Wire v1のbyte layoutとtype番号（`frame_numeric_ids`）はCORE_FIXED_250向けに凍結済み。暗号suiteは未凍結（G-SEC）。仮の暗号やダミーtagを置いて互換性を実証したとはしない。

[参加](../docs/spec/identity-membership.md)、[Wire](../docs/spec/wire-protocol.md)、[永続化](../docs/spec/crash-time-resources.md)、[USB](../docs/spec/usb-protocol.md)と合わせて読む。

`tests/test_contracts.py`は意味の負例を検査する小モデル。ESP32実装、暗号Provider、Babel全体、Raft、実RFの正しさの証明ではない。C++／Rust共通golden vectorは[golden/](golden/README.md)に置き、両実装がbyte一致するかを試験する。

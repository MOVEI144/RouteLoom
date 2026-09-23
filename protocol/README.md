# Protocol contracts（意味の契約）

[semantics.json](semantics.json)は参加状態、保護範囲、識別、期限とフロー制御の正本である。Wire v2のbyte layoutとtype番号（`frame_numeric_ids`）、end AADの順序と幅（`end_aad_fields`）はCORE_FIXED_250向けに凍結済み。暗号suiteは未凍結（G-SEC）。仮の暗号やダミーtagを置いて互換性を実証したとはしない。

[参加](../docs/spec/identity-membership.md)、[Wire](../docs/spec/wire-protocol.md)、[永続化](../docs/spec/crash-time-resources.md)、[USB](../docs/spec/usb-protocol.md)と合わせて読む。

`tests/test_contracts.py`は意味の負例を検査する小モデル。ESP32実装、暗号Provider、Babel全体、Raft、実RFの正しさの証明ではない。C++／Rust共通golden vectorは[golden/](golden/README.md)に置き、両実装がbyte一致するかを試験する。自律mesh拡張の新control payloadとRLD1 envelopeのvectorは[autonomy-golden/](autonomy-golden/README.md)に置く（Wire本体のlayoutは不変）。SDK v1（G-SEC）のRLCW1証明書とRLI1／RLS1／RRS1／RLP1記録のvectorは[sdkv1-golden/](sdkv1-golden/README.md)に置く（独立Python生成器、C++は検証、RustはRFC 6979で再署名して一致）。

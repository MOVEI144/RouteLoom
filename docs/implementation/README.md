# v0.1実装の案内

基準プロファイルは`CORE_FIXED_250`。このコードは実装プロトタイプであり、RF・本番Identity・製品適合の認定ではない。

## 実装済みの縦切り

- `components/routeloom`：C++17 portable core、C ABI、凍結済みWire v1 codec（`protocol/golden`のC++／Rust共有vector、test cipher）、有限Queue、BEST_EFFORT/RELIABLE、hop/end receipt、dedup、Babel由来feasibility、generation／tombstone／hold-down、bounded seqno、SeqNoRequest、SingleAuthorityの2スロット耐電断操作台帳（CRC-32/ISO-HDLC、hash chain、QUARANTINED回復）、deadline再開規則、portable ReplayGuard、DATA/END_RECEIPTの強制end保護、PowerCoordinator、USB/Serial device bridge（streaming codec、開発session、累積credit、MeshNode統合）。
- `components/routeloom_espnow`：ESP-IDF v6.0.3向けの固定channel／LR250 Radio Owner、Peer登録、callback event queue、NVS counter store、NVS authority ledger store、NVS replay store、ESP-NOW PowerPort＋NVS sleep storage、PSA AES-GCM開発用PSK Provider。
- `firmware/reference_node`：C3/S3/C5でcompileされる実験firmware。静的Peer構成。`ROUTELOOM_DEEP_SLEEP`選択時にdeep-sleep経路を配線。NVS異常時はIdentity／counterを守るため自動eraseしない。
- `host/`：Wire v1 codec library、COBS＋CRC32のUSB/Serial framing library、開発session helper、golden vector generator（`gen_golden`／`gen_usb_golden`）、Unix daemon、CLI、TUI。
- `tests/cpp`：codec、counter予約、routing、3hop配送、diamond repair、10hop配送・分断再結合・loop-freedom、authority ledger電断simulation、USB session/credit/golden vector、power coordinator model、replay・end保護hardening、C ABI。

## 継続CI

- Portable core：GCC／Clang、ASan/UBSanのON/OFF。
- Rust：fmt、Clippy `-D warnings`、unit test、release build。
- ESP-IDF：固定`v6.0.3`のC3／S3／C5 reference firmware buildとsize artifact。
- 文書・意味契約：生成表、negative mutation、小状態モデル。

CI成功はhost/build evidence。実機起動、空中通信、到達距離、電池、都市部干渉を証明しない。

## 明示的な非保証

`DevelopmentPskSecurityProvider`は暗号化・counter・replayの実装検証用で、機器固有IdentityやEDHOC/RPKを置き換えない。reference firmwareの既定keyを配備に使ってはいけない。

Wire v1の数値IDとbyte layoutはtest cipher vector付きで凍結済み。本番Security Profileとその適用後vectorは未凍結（G-SEC）。

ESP-IDF build成功は実RF通信、到達距離、技適・認証、電池寿命、100node/10hopを証明しない。C3/S3/C5の実機HILを別に行う。

Host daemonのTTY backendは初期のByteStream実装。認証済みUSB session（開発profile）とdevice側bridgeはportable実装済みで`protocol/usb-golden`の共有vectorでC++／Rust相互検証済み。実USB driver・HILは`G-USB`として残る。

## ローカルportable test

```bash
cmake -S . -B build -DROUTELOOM_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

Sanitizer：

```bash
cmake -S . -B build-san -DROUTELOOM_BUILD_TESTS=ON \
  -DROUTELOOM_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-san
ctest --test-dir build-san --output-on-failure
```

ESP-IDF：

```bash
cd firmware/reference_node
idf.py set-target esp32c3  # or esp32s3 / esp32c5
idf.py build
```

Host：

```bash
cd host
cargo test --workspace
cargo run -p routeloom-host -- --socket /tmp/routeloom.sock
cargo run -p routeloomctl -- status
```

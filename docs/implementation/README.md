# v0.1実装の案内

基準プロファイルは`CORE_FIXED_250`。このコードは実装開始点であり、RF・暗号Identity・製品適合の認定ではない。

## 実装済みの縦切り

- `components/routeloom`：C++17 portable core、C ABI、provisional Wire codec、有限Queue、BEST_EFFORT/RELIABLE、hop/end receipt、dedup、Babel由来feasibility、SeqNoRequest、SingleAuthorityの単調操作台帳、deadline再開規則。
- `components/routeloom_espnow`：ESP-IDF v6.0.3向けの固定channel／LR250 Radio Owner、Peer登録、callback event queue、NVS counter store、AES-GCM開発用PSK Provider。
- `firmware/reference_node`：C3/S3/C5のcompile対象となる実験firmware。静的Peer構成。
- `host/`：COBS＋CRC32のUSB/Serial framing library、Unix daemon、CLIの初期実装。
- `tests/cpp`：codec、counter予約、routing、3hop配送、diamond repair、C ABI。

## 明示的な非保証

`DevelopmentPskSecurityProvider`は暗号化・counter・replayの実装検証用で、機器固有IdentityやEDHOC/RPKを置き換えない。reference firmwareの既定keyを配備に使ってはいけない。

Wire v0.1は内部プロトタイプ。数値ID・byte layout・Security Profileは凍結されていない。別実装との互換性をまだ保証しない。

ESP-IDF build成功は実RF通信、到達距離、技適・認証、電池寿命、100node/10hopを証明しない。C3/S3/C5の実機HILを別に行う。

Host daemonのTTY backendは初期のByteStream実装で、認証済みUSB sessionとdevice側bridgeのHILは`G-USB`として残る。

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

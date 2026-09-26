# v0.1実装の案内

基準プロファイルは`CORE_FIXED_250`。このコードは実装プロトタイプであり、RF・本番Identity・製品適合の認定ではない。

## 実装済みの縦切り

- `components/routeloom`：C++17 portable core、C ABI、凍結済みWire v2 codec（`protocol/golden`のC++／Rust共有vector、test cipher）、有限Queue、BEST_EFFORT/RELIABLE、hop/end receipt、dedup、Babel由来feasibility、generation／tombstone／hold-down、bounded seqno、SeqNoRequest、SingleAuthorityの2スロット耐電断操作台帳（CRC-32/ISO-HDLC、hash chain、QUARANTINED回復）、deadline再開規則、portable ReplayGuard、DATA/END_RECEIPTの強制end保護、PowerCoordinator、USB/Serial device bridge（streaming codec、開発session、累積credit、MeshNode統合）。**EXPERIMENTAL**（Issue #14/#16/#17、opt-in）：Discovery Scope filter（RLD1 body v2、hint/tag gate、generation rotation、scope dedup、auth-transcript scope_binding、Required-without-bindingは起動拒否で降格なし）、Service21 Explicit Gateway（resolve/token、Submit/Receipt、HOST_RECEIVE_RAM sink、UsbBridge 0x10〜0x13 lane）、RCC1 Small Remote Config（schema/CAS、2-slot ConfigJournal、dev HMAC permit、Control22＋object kind3転送、UsbBridge 0x20〜0x23 lane）。集計counterは`scope_stats()`/`GatewayStats`/`ConfigStats`のgetter経由。
- `components/routeloom_espnow`：ESP-IDF v6.0.3向けの固定channel／LR250 Radio Owner、Peer登録、callback event queue、NVS counter store、NVS authority ledger store、NVS replay store、ESP-NOW PowerPort＋NVS sleep storage、PSA AES-GCM開発用PSK Provider。
- `firmware/reference_node`：C3/S3/C5でcompileされる実験firmware。静的Peer構成。boot／NVS／Owner配線は`components/routeloom_node_boot`に共有化（design-devflow.md §5.1）、`main/main.cpp`は`NodeBootHooks`の薄いwrapper。`ROUTELOOM_DEEP_SLEEP`選択時にdeep-sleep経路を配線。`ROUTELOOM_DISCOVERY`でautonomy discovery、`ROUTELOOM_CONFIG`でEXPERIMENTALなRCC1 target（NVS store＋dev HMAC verifier＋ConfigJournal）をopt-in配線（既定n）。`ROUTELOOM_ROUTE_GATEWAY_SCOPED`（既定n）でgateway-scoped routing profile（`ROUTELOOM_ROUTE_GATEWAY_1`／`_2`、scoped時のみ`ROUTELOOM_ROUTE_PERIOD_MS`＝5000／`ROUTELOOM_ROUTE_LIFETIME_MS`＝90000）。NVS異常時はIdentity／counterを守るため自動eraseしない。
- `components/routeloom_bench`：bench試験アプリのportable半分（design-devflow.md §5）。RLB1 wire codecとecho/counter/rollcall/STATUS/peer-send/限定faultの状態機械。公開`MeshNode` APIのみ使用、heap不使用・有界・noexcept。
- `firmware/bench_node`：C3/S3/C5でcompileされるSDK同梱bench firmware。共有`routeloom_node_boot`上に`routeloom_bench`の`BenchApp`を載せる`NodeBootHooks` wrapper（observer＋attach＋poll）。既定はMember（`CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y`）。ESP側の小さなplatform/probe port（heap/stack/reset cause、coordinator snapshot／site store読取り）だけを持つ。`CONFIG_ROUTELOOM_BENCH_CONTROLLER`（既定0＝先頭route gateway）が制御命令の承認元。
- `firmware/bridge_node`：C3/S3/C5でcompileされるUSB bridge firmware。`ROUTELOOM_CAPABILITY`（既定0x7）のbit3でgateway_endpoint_v1、bit4でconfig_endpoint_v1をopt-in attach＋HelloAck広告。OFFでは未attach・全opがUnsupported。`ROUTELOOM_ROUTE_GATEWAY_SCOPED`ではbridge自身（`ROUTELOOM_NODE_ID`）を先頭gatewayに載せる（2台目は`ROUTELOOM_ROUTE_GATEWAY_2`）。
- `host/`：Wire v2 codec library、COBS＋CRC32のUSB/Serial framing library、開発session helper、golden vector generator（`gen_golden`／`gen_usb_golden`）、Unix daemon、CLI、TUI。daemonのAPI1はgateway.resolve/gateway.get（schema-2 submitは`messages.submit`）とconfig.challenge/status/propose/getを実装（dev profile・ACL認可、capability未交渉はhonest拒否）。`routeloomctl`に同名subcommand（例は下記）。
- `tests/cpp`：codec、counter予約、routing、3hop配送、diamond repair、10hop配送・分断再結合・loop-freedom、authority ledger電断simulation、USB session/credit/golden vector、power coordinator model、replay・end保護hardening、C ABI、scope（S01〜S11）、gateway（Gケース）、host ops/capability gate、config（C01〜C14）＋config wire/dev permit。

## 継続CI

- Portable core：GCC／Clang、ASan/UBSanのON/OFF。
- Rust：fmt、Clippy `-D warnings`、unit test、release build。
- ESP-IDF：固定`v6.0.3`のC3／S3／C5 reference＋bridge firmware buildとsize artifact。`features`軸でEXPERIMENTAL機能ON（bridge `ROUTELOOM_CAPABILITY=0x1f`、reference `ROUTELOOM_CONFIG=y`、両方の`ROUTELOOM_ROUTE_GATEWAY_SCOPED=y`）をbase OFF matrixに追加し、sdkconfigへON/OFF両方向のgrepをかける。
- 文書・意味契約：生成表、negative mutation、小状態モデル。

CI成功はhost/build evidence。実機起動、空中通信、到達距離、電池、都市部干渉を証明しない。

## 明示的な非保証

`DevelopmentPskSecurityProvider`は暗号化・counter・replayの実装検証用で、機器固有IdentityやEDHOC/RPKを置き換えない。reference firmwareの既定keyを配備に使ってはいけない。

Wire v2の数値IDとbyte layoutはtest cipher vector付きで凍結済み（v1からepochを32bit、crypto counterを48bitへ改訂。v1で書き込んだ機器はNVS消去が必要）。本番Security Profileとその適用後vectorは未凍結（G-SEC）。

ESP-IDF build成功は実RF通信、到達距離、技適・認証、電池寿命、100node/10hopを証明しない。C3/S3/C5の実機HILを別に行う。

Host daemonのTTY backendは初期のByteStream実装。認証済みUSB session（開発profile）とdevice側bridgeはportable実装済みで`protocol/usb-golden`の共有vectorでC++／Rust相互検証済み。実USB driver・HILは`G-USB`として残る。

Discovery Scopeのdev scope keyとConfigのdev HMAC permitはともに開発用で、production identityではない。COSE/ES256のpermit署名検証・scope bindingの本番Providerは未実装（#10待ち）。Gateway/Configの実機配送・電断・HIL証拠は未取得（#11/#18待ち）。

MembershipControllerの`Revoked`はRAMのみで、再起動時の`initialize`は`hooks.local_member`から再評価する。dev hooksは固定フラグのため、失効したノードは再起動でfail-openに復帰する。失効の耐電断永続化（authority ledgerへのcommit）は本番hooks実装の要件。

replayのwindow/floor/counter slotは公開のkeyless FNV折り畳みから導出されるため、共有PSKを持つ内部者はNodeIdを選んで衝突を決定的に製造できる（counter側では`Conflict`で当該宛先への恒久TX不能）。dev profileでは保証外とし、G-SECのidentity設計ではslot導出に秘密saltを含めることを要件とする。

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

EXPERIMENTAL endpoint操作（正本は`routeloomctl`のusage；device側のcapability attachとACL grantが前提）：

```bash
routeloomctl gateway-resolve --network <16hex> --gateway <16hex> \
  --scope HOST_RECEIVE_RAM --expected-host <64hex>
routeloomctl gateway-send --network <16hex> --epoch <16hex> --to <16hex> \
  --scope HOST_RECEIVE_RAM --payload <hex>
routeloomctl gateway-get --id <opid>
routeloomctl config-challenge --network <16hex> --target <16hex> \
  --config-namespace <u16> --schema <u16>
routeloomctl config-propose --network <16hex> --target <16hex> \
  --config-namespace <u16> --schema <u16> --base-snapshot <hex> \
  --field <id>:<type>:<hex> [--field ...] [--apply-budget-ms <u32>]
routeloomctl config-status --network <16hex> --target <16hex> \
  --config-namespace <u16> --operation-id <32hex>
routeloomctl config-get --id <cfg-opid>
routeloomctl group-send --network <16hex> --group <1-65535|ALL> --payload <hex> \
  [--priority URGENT] [--ordered] [--wait-ms 2000]
routeloomctl group-get --id <grp-opid> [--wait-ms 15000]
```

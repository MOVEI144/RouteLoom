# 入門：最初の疎通からアプリへ

SDK は `2.0.0-dev`。この手順の host smoke は実 Owner・MeshNode を通すが、RF の到達距離や実機認定を証明しない。[文書案内](../README.md)で提供機能と [STATUS](../STATUS.md)の実機資格を確認する。

## 1. 開発環境を固定する

Linux の例。ESP-IDF の必要な OS package は[公式導入手順](https://docs.espressif.com/projects/esp-idf/en/v6.0.3/esp32c3/get-started/linux-macos-setup.html)を参照する。SDK と IDF の commit、対象 chip、`sdkconfig` を記録する。

```sh
git clone --branch v6.0.3 --recursive https://github.com/espressif/esp-idf.git esp-idf
cd esp-idf
git rev-parse HEAD
# 76f5dedd9950a3012fee8fb7d5586df21fc67802 と一致させる
./install.sh esp32c3,esp32s3,esp32c5,esp32c6
. ./export.sh
cd ../RouteLoom
```

Rust は `1.85.0`（[manifest](../../protocol/manifest.json)）。ESP-IDF component registry にはまだ公開していない。外部 project は SDK の commit を固定した git dependency または `EXTRA_COMPONENT_DIRS` を使う。[component 配布](../implementation/component-distribution.md)を参照する。

## 2. 無線を使う前に host sim で手順をたどる

repo root で実行する。peer が無いと従来の一部試験は skip するので、先に実行ファイルの存在を確認する。

```sh
cmake -S . -B build-v2 -DROUTELOOM_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-v2 -j8
test -x build-v2/tests/cpp/routeloom_owner_mesh_peer
test -x build-v2/tests/cpp/routeloom_joiner_interop_peer
cd host
ROUTELOOM_MESH_PEER="$PWD/../build-v2/tests/cpp/routeloom_owner_mesh_peer" \
ROUTELOOM_OWNER_PEER="$PWD/../build-v2/tests/cpp/routeloom_joiner_interop_peer" \
cargo +1.85.0 test -p routeloom-host --bins site::owner_mesh::consumer:: -- --nocapture
ROUTELOOM_MESH_PEER="$PWD/../build-v2/tests/cpp/routeloom_owner_mesh_peer" \
ROUTELOOM_OWNER_PEER="$PWD/../build-v2/tests/cpp/routeloom_joiner_interop_peer" \
cargo +1.85.0 test -p routeloom-host --bins site::owner_mesh::device::mesh_p06_standalone_c_endpoints -- --nocapture
```

前者は 本物の Device/Owner の DevRam 起動 → send → API1 read → consumer の保存と再読込、後者は standalone gateway の実 app と C endpoint 2 台で各 10 件の往復を確認する。P06 の配布 artifact・4 chip 外部 build・実機手順はそれぞれ別の受入項目である。mock の成功を P06 の成功に数えない。

## 3. DevRam の 2 台 quick start

C++ は [endpoint_cpp](../../examples/endpoint_cpp/README.md)、C は [endpoint_c](../../examples/endpoint_c/README.md)。どちらも同じ Device/Owner の起動経路を使う。USB 親機が不要なら endpoint 2 台から始められる。

```sh
cd examples/endpoint_cpp
idf.py set-target esp32c3
idf.py menuconfig
idf.py build
idf.py -p /dev/serial/by-id/BOARD_A flash monitor
```

`menuconfig` の `RouteLoom device` で A は `ROUTELOOM_NODE_ID=0x1`、B は `0x2` にする。`RouteLoom example` の `EXAMPLE_DESTINATION` は A が `0x2`、B が `0x1`。両方の network、channel、development key を一致させる。B は `examples/endpoint_c` で同じ手順を行う。送信は 60 s 周期で、受信 log の source と byte 数、送信の最終 delivery を確認する。queued は疎通成功ではない。

DevRam は `Development`。PSK を共有した RAM session の開発用で、製品の機器 identity・参加認可を代替しない。鍵を文書・log・公開 fixture に貼らない。C/C++ の最初の app はそれぞれの `main/main.c` と `main/main.cpp` を変更する。別 task からは `post`、Owner の job／poll hook から `send`。callback からの再入は Busy。C の struct は initializer で size/version を設定する。

## 4. 配布 image で始める場合

配布基盤（V2-22）は実装済み。正確な RC archive を使う H4 の受入は実施予定。公開済みの正式 image があるとは扱わない。release が用意されたら chip と app の archive、SHA-256、commit、IDF、partition、security profile を照合する。release firmware は `flasher_args.json`／`flash_args` を含む。固定 offset を手入力せず、その image の flash 引数を使う。USB 親機は BoardConfig と HostLink secret が必要なので、DevRam endpoint の Kconfig 手順だけでは起動しない。

2 台の確認は setup image で各 board の identity と設定を書き、対応する field image に app-only 更新し、daemon の接続と node 観測を確認してから送受信する。[書込み・provisioning runbook](../hil.md)の chip/MAC 確認、NVS 保持、readback を守る。全消去は利用者が再 provision の対象を確定したときだけ行う。

## 5. MemberEdhoc と host daemon

reference／bridge／bench の既定は MemberEdhoc。component と quick start／examples は DevRam。独自 project で Member を選ぶときは `CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC=y` を設定し、対応する BoardConfig を provision する。既定切替は実装済み、H2 は実施予定。Member は `Candidate` であり、`Production` 認定ではない。

1. 事務所で on-device keygen、PoP、Device CA が発行する DevCert、identity の seal/lock を行う。現場非依存の identity を作る。[provisioning 契約](../design/sdk-v1/07-host-api-tooling.md)と[実機手順](../hil.md)を参照する。
2. Site Authority の private directory と inventory、承認方針を用意する。開発 site のみ `routeloomctl lab-site-init` を使う。[host §11](../spec/host.md)の spec と receipt 検査に従う。
3. USB 親機に個別の HostLink secret を provision し、host の 0700 directory に同じ secret を 0600 の `<NodeId 16hex>.key` として置く。secret の生成・格納は[HostLink 契約](../spec/usb-protocol.md)に従う。
4. daemon を起動し、`site.status`、`join.requests.list` を確認する。External decision では認可された consumer が `join.decide` を呼ぶ。受理だけでなく Member の確定を待つ。

```sh
cd host
cargo +1.85.0 build --release --locked
./target/release/routeloom-host --socket /run/user/1000/routeloom/api.sock \
  --device /dev/serial/by-id/GATEWAY --api-acl-file /path/to/acl.json \
  --op-store /path/to/operations.db --site-authority /path/to/site \
  --hostlink-credentials /path/to/hostlink
```

paths と UID は実環境に合わせる。socket の親 directory は先に作る。ACL は[運用](operations.md)を参照。`capabilities.get`、`link.get`、`nodes.list` で実際の接続と capability を確認する。Member の鍵・署名・epoch は daemon が判断し、アプリで複製しない。

Member の API1 payload read は epoch を含む full network と対応する ACL を使う（[network の scope](../api/api1.md)）。上の consumer smoke は DevRam と Member の両方を使う。5 台／3-hop の周期負荷 K01 と Member full network の K05 は実 Owner harness に登録されている。host の合格を実機の資格へ流用しない。H2／H3／H4 は実施予定、C5 は実機確認待ち。group と sleep の導入は [利用ガイド](guide.md)と [Kconfig](configuration.md)を参照する。

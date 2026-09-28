# RouteLoom 作業規約

RouteLoom は ESP-NOW／Wi-Fi LR の mesh SDK である。目標は「安定して、長距離の mesh が、高速で、たくさんの機器で使える」こと。過剰に作らず、容量（flash・RAM・行数）は削れるだけ削る。どの IoT 製品でも使える汎用 SDK とし、特定製品の語彙を入れない。

- `components/routeloom/`：portable C++17 core と C ABI。heap 無し・noexcept・有界 container。platform 依存を入れない。
- `components/routeloom_espnow/`、`components/routeloom_node_boot/`、`firmware/`：ESP-IDF adapter と app。
- `host/`：Rust の daemon・CLI・client（`unsafe` 禁止）。`tools/`：検査・生成器・meshviz。`tests/`、`docs/hil/`：試験と実機記録。
- 設計の原則は `docs/development/design-principles.md`、書き方は `docs/development/coding-standards.md`、版と番号は `docs/spec/compatibility.md`。

## 作業範囲
- 着手前に依頼・対象 SHA・関係する仕様と試験・`git status` を読む。依頼された目的に要る最小の差分にする。
- 範囲外の不具合や設計案は完了報告に書き、便乗して実装しない。調査だけの依頼では変更・commit をしない。他の担当の変更を戻さない。
- 新しい manager・抽象層・状態機械・codec・設定ファイルを作る前に既存の実装を探す。将来の用途だけを理由に足さない。
- 容量値・security mode・capability・wire と保存形式・公開 API の既定値を、依頼なしに変えない。

## 実装の必須条件
- 状態の正本と更新の入口は一つ。queue・table は有界にし、満杯は受理の前に扱う。一回の drain も有界にする。
- 永続化が要る成功は commit と readback の後に公開する。照合は peer・request だけでなく boot・session・generation・context まで揃える。
- 期限は単調時計、表示は壁時計。秘密は全ての終了経路で消し、log や fixture に出さない。callback から状態機械へ再入しない。
- 大きな配列を stack へ移す、replay・dedup の保持を縮める、認証を外す、を容量削減と呼ばない。
- C++ core に例外・RTTI・heap を使う container（`std::vector`、`std::function` など）を足さない。
- Rust の production code では、回復できる失敗（I/O・decode・保存・入力）に `unwrap`・`expect`・`panic!` を使わない。

## 公開面の規則
- 公開面（API、protocol、Kconfig、保存形式、crate doc）に製品名を書かない。
- SDK の新しい Kconfig 記号は component の `Kconfig` に置く。app の `Kconfig.projbuild` に SDK の記号を足さない。
- 新機能を `MeshNode` に直接足さない。まず既存の port・sink・Owner の入口で足りるかを確かめる。
- 版と理由 code は `protocol/manifest.json` に先に登録し、`python3 tools/gen_manifest.py` で生成物を更新する。frame 型の番号は `protocol/semantics.json`、capability bit と HostOps の番号は `usb_host_ops.hpp` の一覧に先に登録する。生成物を手で直さない。
- 未実装の capability を有効と広告・報告しない。golden vector を実装に合わせるためだけに書き換えない。
- v2.0.0 以降、保証する公開面（`docs/spec/compatibility.md`）は 2.x の間は追加だけにする。

## 直列に変更するファイル
次は一度に一つの PR だけが変更する：`routeloom.h`、`node.cpp`、`node.hpp`、`sdkv1_security_coordinator.cpp`、`usb_bridge.cpp`、`node_boot.cpp`、`espnow_security_owner.cpp`、`espnow_runtime.cpp`、`host/routeloom-host/src/{main.rs,api1.rs,site/mod.rs}`、`.github/workflows/sdk.yml`、`protocol/manifest.json`、`protocol/semantics.json`、`docs/reference/*.json`、`firmware/*/partitions.csv`、`docs/STATUS.md`。build directory・serial port・実機は排他で使い、worktree を分ける。

## 検証
変更に近い試験から始め、完了時に次を通す（CI と同じ command）。

```sh
cmake -S . -B build -DROUTELOOM_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j8 && ctest --test-dir build -j8
cd host && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
python3 tools/check_docs.py && python3 tools/gen_manifest.py --check && python3 tools/sync_reference_tables.py --check
python3 tools/check_review_contracts.py && python3 -m unittest discover -s tests
PYTHONPATH=tools/meshviz/src:tools python3 -m unittest discover -s tools/meshviz/tests
```

- firmware を変えたら ESP-IDF v6.0.3 で該当 app を build する（例：`cd firmware/bridge_node && idf.py set-target esp32c3 build`）。flash・静的 RAM を変更前と比べる。
- C++ と Rust の live E2E（`cargo test -p routeloom-host --bins site::owner_mesh_interop`、peer は `ROUTELOOM_MESH_PEER` で渡す）は、peer が無くて skip したら合格にしない。
- 環境不足・skip・timeout・未実施の実機試験を合格と書かない。実機の結果が無い変更を「実機確認済み」と書かない。

## 試験の方針
- E2E を先に使う：本物の Owner と MeshNode を通す harness（`host/routeloom-host/src/site/owner_mesh_interop.rs` など）と live interop。試験専用の別 engine を作らない。
- 単体は境界に絞る。一つの挙動に正常と代表的な失敗の 1〜2 本。security・永続化・時計・満杯・再入・世代の必要な場合は本数で削らない。
- 1 つの巨大な試験ファイルに足し続けず、scenario は表にする。

## commit・文書
- 一つの意味のある変更ごとに commit する（英語、`area: summary`）。整形・実装・生成物の更新を無関係に混ぜない。build directory を commit しない。
- 利用者に見える変更は `changelog.d/<PR番号>.md` に断片を書く（`CHANGELOG.md` は release のときに組み立てる）。
- 文書は正本を直し、同じ仕様の写しを増やさない。code comment は仕様と理由だけを書き、review の経緯を書かない。
- Issue を閉じるときは、実機が要る残りを追跡先に移してから閉じる。

## 完了報告
次の順に書く：対象 SHA と変更範囲／変えなかった契約／実行した command と結果／skip・未実施／容量（flash・RAM）の前後差／互換・安全の残課題／範囲外の発見／commit SHA。実測していない削減や未実施の実機試験を成功と書かない。

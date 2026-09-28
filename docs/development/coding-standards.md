# コーディング規約

[設計原則](design-principles.md)を code の書き方に落としたもの。作業の手順・検証の command・完了報告の形式は [AGENTS.md](../../AGENTS.md) を正本とし、ここには繰り返さない。

## C1. 全言語に共通

### C1-1. 過去の不具合の型

| 不具合の型 | 必須の書き方 | 最小の検証 |
|---|---|---|
| 古い世代・状態を受理 | command・完了が期待する identity の snapshot を一つ作り、完全一致した後だけ状態を更新する | 正常 1 件と、古い generation か古い boot の拒否 |
| 片側だけの識別一致 | operation ごとに要る組を型か helper に集める。`peer || request` のような部分一致は禁止 | peer 同じ・request 違い、その逆、generation 違いを境界表で |
| 上限なし・満杯の挙動なし | 全ての queue・map・pool に件数か byte の上限。受理・制御用の予約・拒否の結果を明示する | N 件受理、N+1 件目の拒否、解放後の再受理。制御の応答が詰まらない |
| 保存成功前の公開 | staging と公開状態を分け、commit／readback の後に公開する。失敗したら元の状態を保つ | 保存失敗と電源断・再起動を既存の harness で |
| 秘密の消し忘れ | 秘密の所有者と破棄の経路を一つに決め、成功・失敗・取消・再構築で消す | 故障注入で消去を確認 |
| 壁時計と単調時計の混在 | 間隔と期限は単調時計、表示と外部の期限は壁時計。型・名前・単位で分ける | 壁時計が戻っても再送・timeout が変わらない |
| 再構築後の sink・callback 消失 | 耐久状態と接続先を作業領域の外に置くか、一つの bind 関数で再接続する | 解体 → 再構築 → 製品の callback が一度だけ動く |
| callback からの再入 | 状態機械の所有者は一つ。callback は event を積むだけ。必要なら Busy を返す | callback から再入しても状態が二重に変わらない |
| 製品経路を通らない試験 | 公開 API → Owner／Node → adapter の fake を通す。試験専用の別 engine を作らない | 既存の simulator・interop・HIL を使う。単体は primitive だけ |

`FixedQueue::clear()` は論理件数を消す操作で、秘密をゼロにする API ではない。

### C1-2. 命名・comment・差分

- 既存の命名を優先する。同じ概念に manager・controller・service・coordinator を増やさない。時刻は `deadline_mono_ms`、外部の時刻は `expires_unix_ms` のように領域と単位を示す。`id` 単独より `request_id`・`peer_id`・`binding_generation` を使う。
- comment には仕様・不変条件・理由・境界条件を書く。処理の言い換え、作業の日誌、review や修正の経緯は書かない（それは commit と PR に置く）。実装と矛盾した comment は同じ PR で直す。
- 公開面に製品名を書かない。

### C1-3. 試験

- E2E を優先する：本物の Owner・MeshNode を通す harness と C++ ⇄ Rust の live interop を先に使う。
- 単体は境界に絞り、一つの観測できる挙動に正常と代表的な失敗の 1〜2 本を基本にする。境界は表で書く。
- security・永続化・時計・満杯・再入・世代の変更で必要な場合は、2 本の目安で削らない。本数や coverage の数値を目的にしない。

## C2. C++17 portable core と ESP-IDF adapter

- **所有とメモリ**：core は有界・`noexcept`・実行経路の heap 確保なし。placement new は事前に確保した領域で寿命を始めるときだけ。`std::vector`・`std::string`・`std::function`・`std::shared_ptr` を便利だからと入れない。新しい container の前に `FixedPool`・`FixedQueue`・`ByteBuffer` で足りるか確かめる。adapter の IDF・RTOS の確保は、起動時か非同期かと必要量・失敗処理・所有者を書く。大きな配列を stack へ移して `.bss` だけ減らさない。
- **構造体**：hot path は自然な alignment。`packed` による非整列の access や、生の struct をそのまま wire にしない。公開 C ABI の size・offset や保存形式の版を変えるときは manifest と互換の設計を先に行う。`sizeof` は対象 chip で確かめ、64 bit host の数字で C3 を判断しない。
- **template・inline・constexpr**：固定容量の storage と型安全な小さい primitive に使う。重い状態機械や codec を容量ごとに複製しない。大きな table を TU ごとに生成しない。
- **例外・RTTI**：core は例外でエラーを伝えない。外部入力と容量不足は `Status` で返す。`dynamic_cast`・`typeid` を足さない。`assert` は開発時の不変条件の検出で、未認証の入力や buffer 境界の検査の代わりにしない。
- **status・log**：`StatusCode` の数値を再利用・再採番しない。新しい理由は `protocol/manifest.json` の理由 code に登録する。秘密・鍵・nonce の材料・認証 token を log に出さない。IDF の log は USB の binary transport と別の出力先にする。
- **時計と identity**：`MonotonicMs` を壁時計に cast しない。tx counter・replay bitmap・NodeId・generation の桁を節約のために切らない。
- **Kconfig**：SDK の記号は component の `Kconfig` に置く。app の `Kconfig.projbuild` には app 固有の記号だけを置く。

### C2-1. clang-format

root の `.clang-format` は今の書き方（Google 系、2 空白 indent、100 桁、pointer は左寄せ、include の並びは保持）に合わせてある。変更した行だけを検査し、既存 file の全体は整形しない。

```sh
git clang-format --diff origin/main
```

生成物（`version.h`、`tests/cpp/manifest_check.cpp`）は `clang-format off` を持ち、vendored の `components/routeloom/third_party/` は対象外。

## C3. Rust host・daemon・CLI・TUI

- `unsafe` は禁止（workspace の lint で `forbid`）。
- host は heap を使ってよいが、無制限は不可。inflight・履歴 cache・request map・channel・再送 queue・SQLite の保持に上限を置く。unbounded channel は原則使わず、満杯・取消・切断を公開の結果にする。
- object の正本は一か所に持ち、他の索引は ID で参照する。DB の commit／readback より前に event・cache・成功応答を出さない。
- phase は enum、operation の identity は小さな型で表す。bool の組で相互に排他な状態を表さない。`Instant` は再送と timeout、壁時計は表示と外部の期限に限る。`Instant` を永続化しない。
- production code では回復できる失敗（I/O・decode・保存・入力）に `unwrap`・`expect`・`panic!` を使わない。試験と、証明された内部の不変条件は局所の allow と理由を付ける。秘密の型に `Debug`・`Display`・`Clone` を付けない。
- daemon の判断を CLI・TUI・Python に写さない。protocol の schema・client・golden を共有する。
- `cargo fmt --all -- --check` と `cargo clippy --workspace --all-targets -- -D warnings` を通す。toolchain の版は `protocol/manifest.json` と CI に揃える。

## C4. Python の道具と meshviz

- Python は薄い調停・可視化・scenario・解析を担う。認証や routing の判定を Python の独自 model として写し、それを製品試験の正解にしない。
- 公開の入出力と scenario・設定の schema に型を付ける。subprocess の timeout・終了 code・stderr・部分結果を呼び出し元に返す。`except Exception: pass` や、外部 command の失敗を成功として扱う fallback は禁止。
- 間隔は `time.monotonic_ns()`、壁時計は表示と外部 data に使う。thread 間は有界の queue、UI の更新は UI thread で行う。
- root の `ruff.toml` は実際の誤り（`E9`：構文、`F`：未定義名・未使用の import と変数）だけを見る。整形は強制しない。変更した file だけを検査し、既存の指摘をまとめて直す PR を作らない。

```sh
ruff check <変更した .py file>
```

## C5. 仕事量と容量

- 周期の poll に新しい全件走査を足す前に、入力の変化と実際の期限で起こせるか確かめる。容量 N、active 数 A、一回の仕事 K の上限を PR に書く。
- queue の容量と一回の drain の上限を両方決める。残りの仕事は ready として次に回し、ACK・失効・期限の仕事を飢えさせない。
- mode や flag を見るためだけに全体の snapshot を取らない。decode・hash・copy・ゼロ化は必要な回数に限る。暗号素材の消去と、使うときの世代・期限の照合は省かない。
- RAM を減らすための再計算・session の縮小・低 clock・小さい暗号実装には CPU 時間の前後比較を付ける。
- 複数の task や汎用 timer framework を便乗して足さない。

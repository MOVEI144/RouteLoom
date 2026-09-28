# 設計原則

RouteLoom の目標は「安定して、長距離の mesh が、高速で、たくさんの機器で使える」ことである。過剰に作らず、容量は削れるだけ削る。ここでいう「小さく作る」は検証や不変条件を捨てることではなく、状態と判断の重複をなくすことを指す。作業の手順と検証の command は [AGENTS.md](../../AGENTS.md)、書き方は [coding-standards.md](coding-standards.md) に置く。

| # | 原則 | 線引き | 例 |
|---|---|---|---|
| 1 | 状態の正本は一つ | 同じ値を持つ別 manager を足さない。cache を持つなら正本・無効化条件・再生成の経路を書く | `SessionBank` は network と自機を bank で共有し、entry ごとに重複させない |
| 2 | 操作の入口と最終判断は一つ | 公開 API・USB・HIL は同じ受付と認可の経路を通す。便利な抜け道の API を増やさない | USB と host loopback は同じ pending pool を使う。所属 API は Owner の既存判断に委ねる |
| 3 | 同じ仕事をする状態機械を複製しない | transport の違いは入出力の adapter、方針の違いは小さな設定値で表す。安全上別の protocol は無理に一つにしない | SecurityOwner と coordinator は一つ |
| 4 | 容量は製品契約として一か所で決める | 役割・台数・同時数・保持時間・送信率は profile に集める。導入だけの PR で既定値を変えない | 容量 profile（V2-05）と `docs/design/sdk-v1/ram-budget.md` |
| 5 | 受理枠と完了枠を先に予約する | 受理した後で記録先が無くなる設計にしない。満杯の Busy・拒否・延期を API の結果に含める | `MeshNode` の admission transaction と有界の完了 event |
| 6 | scratch の共用は寿命を証明してから | 所有者と有効な tag を持つ。永続状態・非同期で参照中の領域・再入できる領域を重ねない | `TxJob` の union は一つの遷移関数だけが切り替える |
| 7 | 総称より小さな共通 primitive | checked reader／writer、identity の照合、期限、有界の受付は共有する。万能 codec や万能 transaction engine は作らない | `byte_io.hpp` |
| 8 | 開発機能は依存の向きで隔離する | 製品 code から bench・TUI・試験へ依存しない。任意機能を OFF にしたら状態と handler まで消える | HIL・netif の Kconfig OFF |
| 9 | host に寄せるのは遅延と切断に耐える仕事 | 履歴・集計・表示・大きな計画は host。認証・nonce／replay・受理・airtime・現場で要る復旧は機器に残す | binding の照合は機器側で必須 |
| 10 | 永続化の成功が公開の前提 | stage → validate → persist／readback → publish を一つの流れにする | host の SQLite は commit の後に RAM を更新する |
| 11 | identity は完全な組で照合する | peer だけ・request だけの一致で受理しない。世代・session／boot・network・context・方向を契約どおり確かめる | 世代の違う callback と ACK は状態に触れない |
| 12 | core／adapter／host の境界を守る | core は portable な有界の状態と codec、adapter は IDF・無線・NVS・時計、host は耐久の調停と UI。platform の include を core に入れない | PSA の AEAD は `routeloom_espnow` にある |
| 13 | 将来用の抽象は二つの実例と削減の根拠があるときだけ | 実在する二つの呼び出し元、異なる実装の必要、消える重複を説明できるときに限る。公開 SDK の境界と試験の seam は一例でも理由を書けば可 | 今の全 message を将来の分割送信のために heap object にしない |
| 14 | 正しさ・仕事量・容量を同じ PR で示す | firmware を変えたら flash・静的 RAM を前後比較する。一つの指標の改善で他の退行を隠さない | CI の静的 RAM gate |
| 15 | 何も変わらないときは何もしない | 既存の Owner に変更通知と実際の期限を集める。全件走査を先に減らし、cache・task・manager を安易に足さない | `owner_pump.hpp` を拡張し、別の pump を作らない |

## 数値の扱い

- 行数（SLOC）の net 減や電流の実測を、PR の合否の条件にしない。行数は整形で動き、電流計は常にあるわけではない。代わりに flash・静的 RAM・host の counter を前後比較し、行数は報告だけにする。
- 実機の値は HIL の記録（`docs/hil/`）に書く。host の試験の数値を実機の時間や電流として扱わない。
- 目安として 80 行を超える関数、手書き 500 行を超える差分は分割を検討する。数値を満たすための整形・抽象化・試験の削除はしない。挙動を変えない機械的な整理は大きくてよい。規則は「1 PR ＝ 1 つの所有境界か 1 つの挙動」。

## 公開面

- 公開面（API、protocol、Kconfig、保存形式、crate doc）に製品名を書かない。製品固有の語彙は example か利用側に置く。
- SDK の Kconfig 記号は component の `Kconfig` に置く。
- 版と番号は `protocol/manifest.json`（版・理由 code）、`protocol/semantics.json`（frame 型）、`usb_host_ops.hpp`（capability bit・HostOps）に先に登録してから使う。
- 保証する面と互換の規則は [compatibility.md](../spec/compatibility.md) に従う。

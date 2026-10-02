# v2 への移行

対象は `0.1.0`／開発 checkout から `2.0.0-dev`。v1.x は出さず、最初の番号付き release は v2.0.0。まだ pre-release であり、移行前後の commit と [manifest](protocol/manifest.json) を保存する。[利用文書](docs/README.md)の pending 表にある機能を前提にしない。

## 機器と耐久状態

出荷機・本番 site DB の無い開発系では**全消去と再 provision**で移行する。まず対象 chip/MAC、backup、再発行できる identity と鍵の custody を確認し、daemon を止める。旧 partition／旧 identity を持つ機器に新 app だけを書いて互換性を推測しない。全消去は破壊的なので、対象を確定した利用者が [HIL runbook](docs/hil.md) に従って行う。

1. PT-4M-v2（4 MB、NVS、otadata、OTA 2 面、coredump 予約）の bootloader・partition・app を揃える。flash の実容量を確認する。
2. setup image で BoardConfig、HostLink secret、on-device identity、DevCert を provision し、commit/readback、seal/lock を確認する。秘密の dump は private storage にだけ保管する。
3. field image を app-only 更新し、保護する NVS が変わらないことを確認する。
4. 新しい site と host operation DB、ACL、HostLink credentials を準備し、参加の確定、両方向の配送、consumer の受信保存を確認する。

同じ v2 partition 上の通常更新で全消去を常用しない。既存の耐久 floor・失効状態を巻き戻さない。[保存形式と互換](docs/spec/compatibility.md)が読み込み可能な版の正本。site store は対応する旧 schema のみ前進移行し、未知の schema を自動補正しない。

## アプリの変更

| 旧側 | v2 の変更 |
|---|---|
| `node_boot`／app 固有の起動組立て | `routeloom::Device`／`rl_dev_start` に一本化。[C++](examples/endpoint_cpp/README.md)・[C](examples/endpoint_c/README.md)を基にする |
| C core ABI の旧 struct | ABI 3。size/version を initializer で埋め、全 consumer を rebuild。Device C API は別の version 1 |
| 任意 task から node 操作 | Owner の poll hook／posted job から操作。別 task は `post` のみ、callback の再入は Busy |
| 受理を成功と表示 | delivery result／APPLIED ticket の最終結果を追う。業務の成功は commit/readback の後 |
| app の SDK Kconfig 記号 | component の [Kconfig reference](docs/api/kconfig.md)を使う。app の `Kconfig.projbuild` に SDK の設定を複製しない |
| LegacyFixture／旧 PSK counter record | 選択肢を撤去。開発は DevRam、機器 identity の参加は MemberEdhoc。旧 mode を自動変換しない |
| `DecisionMode::KGuard` | `DecisionMode::External`。保存値 0 は不変、入力の `"kguard"` alias のみ互換で受理 |
| HostLink protocol 1 | protocol 2。旧相手を拒否する。device と host に個別 secret、host は 0700 directory／0600 file |
| 製品の development 既定 | 現在の reference／bridge／examples は DevRam。MemberEdhoc 既定への切替は V2-17b／H2 に pending。Member 構成は明示的に選ぶ（Candidate） |

wire major は 2、minor の前方互換・拡張型の中継規則は[wire 契約](docs/spec/wire-protocol.md)を確認する。予約 frame 型は実装済み capability ではない。保存形式・C ABI・Device API・HostLink・API1 の番号を SDK の semver と混同しない。

## host consumer

API1 envelope は v1、`caps_version` は 2。接続後に `capabilities.get` と `capacity.get` を確認し、未知の追加 field を許容する。要求 envelope の未知 field は拒否される。API1 に principal を入れず、OS credential と ACL を使う。

既存の cursor は daemon 再起動後には使えない。`CURSOR_EPOCH_CHANGED` の後に明示的に復旧し、record と cursor の保存を一つの transaction にする。`CURSOR_GAP` は欠落として処理する。[契約 kit](docs/api/api1.md)と[consumer example](examples/display_consumer/README.md)を参照。operation の同じ idempotency key は同じ内容で再照会し、業務 ID の耐久 dedup をアプリ側にも持つ。

## release と未完了機能

[CHANGELOG](CHANGELOG.md)は release 時に [fragments](changelog.d/README.md)から組み立てる。`python3 tools/assemble_changelog.py` は review 用の Unreleased 集約を標準出力へ出す。release の tag・署名・artifact 昇格は V2-22 の範囲であり、この移行 guide は実行しない。

sleep／crypto worker／賢い参加／AppObject の公開手順は各 PR の merge 後に更新する。IP gateway／UART／圧縮／自動移設は今回の移行に含めない。H4 の配布物からの再現と C5 の実機認定は未実施。

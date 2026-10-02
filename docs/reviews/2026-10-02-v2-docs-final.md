# v2.0 文書の最終照合（2026-10-02）

対象 SHA：`ee9b018ebdb7e741b4932d257a8537b4db53dc1b`。
変更は文書・CHANGELOG と許可された `examples/group_send`／`examples/sleep`。
SDK、adapter、host、protocol、容量値、security の既定・capability・wire／保存形式は変更していない。
SDK の manifest は `2.0.0-dev` のまま。正式 release の公開と実機資格を宣言しない。

## Issue と根拠

| Issue | 変更・証拠 | 残る範囲 |
|---|---|---|
| #25 | [SECURITY](../../SECURITY.md)：GitHub private vulnerability reporting、supported は v2.0.x のみ、固定値は試験専用。個人の窓口を削除 | GitHub の reporting 設定の有効化は未確認、maintainer が行う |
| #163 | [group sample](../../examples/group_send/README.md) と [sleep sample](../../examples/sleep/README.md)。既存 Device 経路を使い、ESP-IDF v6.0.3／C3 で root・受信側・sleep の 3 build 成功 | 実 RF／sleep の実機試験は未実施 |
| #165 | [Host 運用](../user/operations.md)、[Kconfig](../user/configuration.md)、[CHANGELOG](../../CHANGELOG.md)、[移行](../user/migrating-v2.md)、README／索引／利用ガイドを実装に合わせた。全 33 断片を統合し README を残して削除 | H2／H3／H4 は実施予定、C5 は実機確認待ち。正式 release の配布は別 |
| #54 | [radio §7](../spec/radio.md)、[所属](../spec/identity-membership.md)、[資源](../spec/resource-profiles.md)：近隣と ZeroTouch の窓・pool・期限、smart body v4、閉じた site の retained 復帰を区別 | 下の実装課題は残す。文書修正を実装完了と扱わない |

close は PM が行う。#54 の実装が必要な残りは追跡先を確定してから扱う。

## command と結果

repo root で C++ を検査：

```sh
cmake -S . -B build -DROUTELOOM_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j8
ctest --test-dir build -j8
```

116/116 成功。Rust は `host/` で以下を実行：

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
ROUTELOOM_MESH_PEER="$PWD/../build/tests/cpp/routeloom_owner_mesh_peer" \
ROUTELOOM_OWNER_PEER="$PWD/../build/tests/cpp/routeloom_joiner_interop_peer" \
ROUTELOOM_EDHOC_PEER="$PWD/../build/tests/cpp/routeloom_edhoc_interop_peer" \
cargo test --workspace
```

fmt／Clippy 成功。workspace の合計 1121 件成功、失敗 0、ignored 12。
real Owner/MeshNode の通常 peer を渡した。AppObject ON／OFF peer 専用の ignored 12 件は未実施。

文書・Python は repo root：

```sh
python3 tools/check_docs.py
python3 tools/sync_reference_tables.py --check
python3 tools/check_review_contracts.py
python3 tools/gen_user_reference.py --check
python3 tools/gen_manifest.py --check
mkdocs build --strict --site-dir build-docs-site
python3 -m unittest discover -s tests
PYTHONPATH=tools/meshviz/src:tools python3 -m unittest discover -s tools/meshviz/tests
```

指定した文書検査と manifest 検査は全て成功。check_docs は 2125/2125、review contracts は 186/186。
MkDocs は既存 docs venv（Material 9.7.7）を使用し strict 成功。未登録の履歴文書は INFO、リンク／anchor の新規不整合はない。
Python は 205 件成功。meshviz は 280 件中 251 件成功、29 skip。skip は合格に数えない。
最初の文書 mutation 試験は移行ガイドの撤去済み記号で失敗したため、選択肢の説明に直して全 205 件を再実行した。

examples は排他的な `build-examples/` の source copy で実行した。IDF image は
`espressif/idf@sha256:54278f2c01e6e759502e2f04c9103589c17528923426f4d63193490c7a08f555`。
IDF commit `76f5dedd9950a3012fee8fb7d5586df21fc67802` を確認した。

```sh
idf.py set-target esp32c3
idf.py build
idf.py size --format json2 --output-file build/size.json
```

group root／同じ source の NodeId 2 endpoint 受信側／sleep の 3 構成で成功。
group の初回 build は NodeObserver の pure virtual 実装不足で失敗し、sample を修正して再 build した。
既存 SDK の未使用変数・関数 warning は残り、SDK コードは変更していない。

## skip・未実施と容量

HIL、S3／C6／C5 の新 sample build、実機 flash、電流・RTC drift は未実施。
本作業では既存 firmware の前後 build をしていない。容量削減を主張しない。
新 sample は比較元がないため、以下は C3 の絶対値（bytes）。DRAM 使用は IRAM と重なる `.text` を含む IDF size の値で、電池電流や実測 heap ではない。

| 新構成 | app.bin | DRAM 使用／空き | RTC SLOW 使用 | 適用した既存 RAM guard |
|---|---:|---:|---:|---|
| group root、gateway_small | 1,275,360 | 287,708／33,588 | 5,768 | bridge floor 27,648：成功 |
| group receiver、endpoint | 1,191,728 | 229,174／92,122 | 5,768 | reference floor 19,456：成功 |
| sleep、endpoint | 1,209,440 | 231,564／89,732 | 6,112 | reference floor 19,456：成功 |

`tools/firmware_ram_report.py` を各 size.json に対して実行した。
既存の guard・partition limit・容量 profile は変更していない。

## 互換・安全の残課題と範囲外の発見

H2／H3／H4 の再受入、C5 実機、Member Candidate の本番資格は [STATUS](../STATUS.md)に残る。
crypto worker（V2-16）、IP gateway、UART coprocessor、メッシュ OTA #103／#171 は v2.1。
人による第三者レビュー #100 は非ブロッキングで追跡する。

#54 の以下は実装追加を要する。今回の文書は実装済みと記述せず、値や認証を変えない。

- 近隣 OFFER 専用の 1 応答/s・burst 2 limiter と混雑時の候補 rotation。
- 3 候補の比較終了、孤立群の探索担当選出、密度に応じた応答抽選。
- 設計 200ms dwell／2000ms sleepy 活動・2 周の profile 認定。現 ZeroTouch は 320ms、Device radio-on は既定 40s。
- 全入口共通の CPU rate gate／crypto worker と Owner 25ms の実測受入。

生成された bootstrap allowlist の REVOKED 行は通常通信の禁止を示す。
本人の再 provision 必須とは読まないよう本文で補足し、protocol の生成元と表は変更していない。

example commit：`4be81c43`。文書の commit は git log を参照。push・Issue close は行わない。

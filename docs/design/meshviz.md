# RouteLoom Mesh Lab 設計書

- 文書版：1.0／調査日：2026-09-26
- 調査対象：`/home/sahur/orca/workspaces/RouteLoom/final-review`
- 基準 commit：`1aad7d391123cf6a70805a0775c686d7c5bf0074`
- 成果物：設計のみ。ソース、設定、git の変更、build、実機操作は行っていない。
- 本文の `path:line` は、特記しない限り上記 checkout の実装を指す。外部資料は公式資料へのリンクを付す。「追加」「提案」は未実装の契約であり、既存 API と区別する。

## 設計の決定

**Python／PySide6 のデスクトップアプリを作り、通常の mesh 通信・Site Authority 操作は Rust daemon の API1、書き込み・保守 console・reference ノードの USB 観測は Python から行う。** ネットワーク図には Qt Graphics View、時系列には pyqtgraph を使う。

一般利用者には Python・Rust・ESP-IDF・Docker のインストールを要求しない配布物を用意する。署名・ハッシュを検証する事前 build 済み firmware パッケージと、書き込み後の個体別設定を主経路にする。ソース build は SDK 開発者向けの追加機能とする。

最初の実用範囲は「1 site、稼働 bridge 1 台、reference 2〜8 台」。表示・記録モデルは 100 ノードを想定する。ただし **100 台を無線越しに高頻度で全量観測する能力は約束しない**。USB 直結の詳細観測、選択対象の無線観測、低頻度の全体確認を使い分け、各値の観測時刻を表示する。

現実装から着手する際の重要点は次のとおり。

| 項目 | 現状と設計への影響 |
|---|---|
| Windows | daemon／CLI／TUI／API1 client が Unix に依存する。Python GUI を作るだけでは Windows で完結しない。IPC、serial、principal、乱数、鍵ファイル保護を移植する。 |
| firmware 個別化 | NodeId・network・channel は主に Kconfig。既存 image をそのまま複数台へ書くと NodeId が重複する。汎用 image 用の起動設定読込みを追加する。 |
| 観測 | gateway 視点の node status と RSSI は既存。リンク品質の structured telemetry も firmware 内に存在するが API1 未公開。全 observer の近隣・経路表、health は追加が必要。 |
| 配送結果 | API1 の受付・証拠は取得可能。しかし通常の HostOps 送信では legacy `delivery_event` を出さず、理由を QUERY_DISPATCH にも保持しない。失敗理由の完全な分布には追加が必要。 |
| throughput | host の通常 admission は毎分 2 件、burst 16。高頻度試験用の明示的な実験 profile と容量管理が必要。 |
| MemberEdhoc | 参加・除外・group key・cutover のコードは存在する。「本番相当の手順を試す実験 profile」と位置付ける。USB 認証や鍵保管まで製品認定済みとは表示しない。 |
| C6 | 現 checkout の対象 manifest／CI／release に含まれない。build と HIL を追加し、他チップと同じ認定状況とは扱わない。 |

## 0. ボード、firmware、構成、provision

### 0.1 利用者が完遂する手順

1. **実験プロジェクトを作成**：DevRam または MemberEdhoc、対象 board、network、使用 channel、bridge、ラベルを指定する。共通 RF 条件は SDK の 2.4 GHz／LR250 を初期値とする。
2. **USB 接続を検出**：接続場所、USB serial、候補 chip を表示し、初回の ROM probe で chip・revision・MAC・flash を確定する。
3. **役割と個体を対応付け**：物理 board と NodeId、bridge/reference、security profile、sleep、group を割り当てる。重複を検査する。
4. **image を取得**：配布済みパッケージをダウンロードまたはファイルから選択する。必要な場合だけソース build を選ぶ。
5. **書込み計画を表示して実行**：全台の chip/MAC/image/書込み領域を確認できる一覧から開始する。各台の失敗と成功を独立して扱う。
6. **個別設定・provision**：setup image で設定する。MemberEdhoc は鍵の PoP と identity seal まで実行し、field image に移る。
7. **起動確認・参加**：bridge の USB 認証、実効設定、reference の起動情報を照合する。Member は GUI で承認し、台帳 commit と機器確認を追跡する。
8. **観測・試験・記録**：まず低頻度の送信確認、次に条件を保存した試験を実施する。途中で電源を抜く等の操作は画面の手順に従い時刻を記録する。
9. **終了・再生**：未決着の送信を区別して記録を閉じ、同じ画面で再生・比較・CSV 出力する。

各段階は状態機械として保存する。中断後は「USB ポート名が同じ」ではなく、同一個体・image digest・設定世代・機器 readback が一致する段階から再開する。

### 0.2 現在の build・HIL の再利用範囲

| 実装・所在 | 再利用する部分／必要な変更 |
|---|---|
| `tools/hil/rig.py:214`、`:341`、`:405`、`:431` | Board/rig の記述、役割対応、曖昧な候補の拒否、probe の考え方。現状の探索は macOS/Linux の glob が中心で、Board に MAC フィールドはない。Windows の列挙と物理識別は追加する。probe が reset を伴う点を UI に反映する。 |
| `tools/hil/flash.py:62`、`:75`、`:148` | `flasher_args.json` 読込み、ファイル hash、結果 manifest、boot capture。現状は chip/MAC の実測照合がなく、flash_files 欠落時に固定 offset へ fallback する。GUI の安全な共通サービスでは fallback を禁止する。boot log を採れたことだけでは起動成功にしない。 |
| `tools/hil/capture.py`、`scenarios.py`、`report.py` | capture、シナリオ、レポートのデータ契約を再利用する。GUI から現在のスクリプトを無条件に起動し、daemon 起動・reset・port 所有が競合する構造にはしない。 |
| `/home/sahur/.local/bin/routeloom-idf-build:17` | IDF container/commit pin、scratch copy、RAM guard。現在は bash/rsync/flock 依存で、成功時に scratch と成果物を削除する（`:43`）。build 検証器として再利用し、artifact export を持つ repository 管理の backend を追加する。 |
| **別 checkout** `/home/sahur/orca/workspaces/RouteLoom/hil-bench/tools/hil/build_image.sh:11` | C6 を含む target allowlist、成果物保存、要求 Kconfig の反映検査、security 設定の拒否。ただし現 checkout にはない。固定日付の出力先、shell/rsync 依存、全 security 設定の検証範囲を整理して共通化する。 |
| **別 checkout** `…/hil-bench/tools/hil/provision_console.py:17`、`:55` | preflight → status → keygen → `provision-devcert` → identity の手順。chip choices は C3/C5 のみ（`:38`）。同 checkout 固有の `flash.preflight_board` に依存するため、そのまま現 checkout では使えない。再列挙、locked 応答、PoP 消失への対応を追加する。 |

後二つは既存リポジトリ機能として扱わず、移植する差分を独立 PR でレビューする。今回、それらの変更・コピーはしていない。

### 0.3 image の作成・配布

**主経路：事前 build 済み image。** build matrix は `chip × role × security profile × power profile`。NodeId ごとの build は最終方式にしない。

- chip：C3/S3/C5、C6 は追加検証後。
- role：bridge/reference。両者は別 image。bridge に deep sleep は提供しない。
- security：DevRam と MemberEdhoc を別 build にする。runtime 設定で相互に切り替える設計にはしない。LegacyFixture は既存互換試験用として詳細設定にのみ出す。
- power：reference の常時稼働／MemberEdhoc sleep。現行 Kconfig は DevRam+deep sleep を許可しないため、初期版でも提供しない（`firmware/reference_node/main/Kconfig.projbuild:306`）。
- setup：保守 console の image。field image とは明確に区別し、無線を起動しない。
- 観測用 bridge は node status bit 6 を必須にする。現行既定 capability `0x7` だけでは node status は使えない。telemetry bit 5、group bit 7 は対応する endpoint が実際に attach できる構成で有効化する（`firmware/bridge_node/main/main.cpp:691`）。

現 release workflow は IDF `v6.0.3` と commit `76f5dedd9950a3012fee8fb7d5586df21fc67802` を検証し、C3/S3/C5 の両 app を build する（`.github/workflows/release.yml:112`）。ただし既定構成のみで、任意 NodeId の汎用 image や全実験 profile を提供しているわけではない。

**配布パッケージ `firmware-bundle-v1` の必須項目：**

```text
manifest.json
images/bootloader/bootloader.bin
images/partition_table/partition-table.bin
images/application.bin
flasher_args.json                 # 同梱位置へ正規化した相対パス
sdkconfig                        # 公開可能な構成のみ
partition-table.csv
build-info.json                  # SDK commit / IDF commit / toolchain / profile
ram-report.json
SHA256SUMS
signature.json                   # 配布物の署名。ESP の secure boot とは別
LICENSES/
```

`manifest.json` は `schema_version, bundle_id, sdk_commit, idf_commit, chip, chip_revision_range, board_compatibility, role, security_profile, power_profile, firmware_version, capabilities, minimum_flash_bytes, flash_mode/frequency, partition_layout_id, config_schema, files[{offset,size,path,sha256}], forbidden_security_features_disabled` を持つ。最後の宣言だけを信用せず、配布 CI が resolved sdkconfig と bootloader build 条件を検査する。

現 release の packaging は bootloader 等を同じ階層へコピーし、`flasher_args.json` の元の相対パスと対応しない可能性がある（`.github/workflows/release.yml:149`）。GUI は basename で推測修復せず、新しい bundle 生成器で正規化・検証する。既存アーカイブの import は明示的な変換処理を通す。

配布 catalog は immutable な version/digest を指定する。CI の短期 artifact は開発者向け、release asset または同梱 offline bundle は一般向け。キャッシュがあればネット接続なしで設定・書込みを完了できる。NodeId・DevRam 鍵・USB secret を含む利用者固有 image は共有 CI artifact にアップロードしない。catalogの署名はGUIに同梱したrelease公開鍵で検証する。利用者が選んだsourceからのlocal buildは `origin:local-build` と全digest/resolved configを記録し、公式署名済みとは表示しない。外部取得の未署名binaryをlocal buildとして自動受入れしない。

**副経路：ソース build。** GUI が scratch directory に source snapshot と sdkconfig を生成し、Docker backend または既存のローカル ESP-IDF 環境を呼ぶ。build は host 上の USB デバイスを必要としない。Windows/macOS の Docker に USB passthrough を要求しない。build cache key は source digest、IDF digest、全 resolved config、partition layout、tool version とする。利用者 checkout に `sdkconfig`、`build/`、git worktree を生成しない。

汎用設定対応が入る前の開発 preview は Kconfig 個別 build で進められる。その期間は「compiler 不要で任意台数を構成できる完成版」として配布しない。

### 0.4 個体別設定の確定方式

現状は `CONFIG_ROUTELOOM_NODE_ID/NETWORK_ID/CHANNEL` を使用する（両 app の `Kconfig.projbuild:3`、bridge `main.cpp:323`、`:491`、`:637`）。Member 参加後の node/network/channel は RLI1/RLS1 由来に移る（`components/routeloom/src/sdkv1_security_coordinator.cpp:2358`）。従って **「保守 console で identity を入れれば、現行の全 Kconfig 個別化が不要になる」とはしない**。

追加する `BoardConfigV1` は非機密の構成領域 `rlcfg` に保持する。既存 `rlsec` や boot counter を raw NVS image で上書きしない。

| フィールド | 制約・採用元 |
|---|---|
| `schema, generation, config_uuid, crc` | 二重 slot＋commit marker。電断時は最後に commit した完全な世代を採用。 |
| `expected_chip, expected_sta_mac, firmware_profile_id` | 別個体用設定、別 security/role image での起動を拒否。MAC の種類も保持する。 |
| `node_id` | DevRam では設定値。Member では sealed identity の NodeId と一致が必須。0 と all-ones を拒否。 |
| `network_low32, channel, rf_profile_id` | RF profileはcountry、許可channel集合、TX power(qdBm)を含む。現adapterのchannel1..13とprofileの共通範囲のみ選択。DevRamの実効値。Member参加後のnetwork/channelは検証済みSitePackageが権威で、RF profileとの整合を検査する。 |
| `route_gateways[], routing_profile, route_period_ms, route_lifetime_ms` | 全 site で一致。gateway-scoped の lease 条件を検証。Member は SitePackage の gateway set を採用。 |
| `groups[]` | 最大 8 group＋ALL。起動時、member adoption 後に `set_group_membership` を適用する。 |
| `sleep_after_ms, sleep_duration_ms` | sleep build のみ有効。bridge は拒否。 |
| `diagnostics_local, diagnostics_remote, experiment_echo` | 実験 image にだけ設ける明示的 opt-in。 |
| `label` | GUI 側の metadata。無線上の identity には使わない。 |

DevRam PSK と USB development secret は `BoardSecretsV1` として別partition `rlkeys` に保持し、公開BoardConfigにはsecret世代とfingerprintだけを置く。PSKは32 bytes、USB secretは初期32文字のランダムASCII hex（16 random bytes由来、既存63文字以内制約を満たす）。setup専用 `benchsecret stage <kind> <generation> <hex>` で投入し、`benchcfg commit` は同世代の秘密と公開設定がともにcommit/readback済みの場合だけ成功する。不一致ならfield起動時にRFを開始しない。raw flash上は暗号化を保証せず、statusはfingerprintのみを返す。ログ、一般manifest、再生ファイルへ秘密を入れない。

現在のmesh PSKはKconfig（`firmware/bridge_node/main/main.cpp:632`）、USB secretもfirmware Kconfigだが、host側は `DEV_SECRET` 固定初期化である（`host/routeloom-host/src/main.rs:64`、`:203`）。新設 `--usb-dev-secret-file PATH` でprivate fileから正確なbytesを読み、USB sessionとそのsecretに依存するdevelopment派生値へ同じ値を渡す。秘密本体をargvやstdoutに出さない。GUIが生成・所有するfileのACLは§1.3に従う。旧固定値はlegacy profileとしてだけ保持し、新規汎用imageが未設定のまま既知の共通鍵で起動しないようにする。

**追加する setup console 契約：** `benchcfg stage <hex-encoded bounded document>` → `benchcfg validate` → `benchcfg commit <generation>` → `benchcfg status`。一文書上限 2 KiB、hex込みconsole行上限を明示的に約4.2 KiBへ確保し、厳密な項目 allowlist、世代競合を拒否。security mode、鍵 slot、eFuse、boot protection の変更項目は設けない。Member の初回設定は identity seal より前に確定する。

setup image は pre-RF の専用 build とし、通常起動 image に設定変更 console を残さない。Member の console lock を回避しない。seal 後の機器に再設定が必要なら、承認済みの remote config または別途設計する保守手順の対象とし、GUI が自動で unlock/erase しない。

起動コードに共通 `load_board_config()` を設け、radio、security owner、joiner、UsbBridge、telemetry の全てへ同じ検証済み identity を渡す。Member の NodeId を Kconfig 値と NVS 値で混在させない。未設定の汎用 field image は RF を開始せず `CONFIG_REQUIRED` を報告する。NodeId=1 の暗黙採用はしない。

DevRam の `adopt_dev` は現在 gateway set を渡さず、member adoption 側はその set で経路構成を更新する（`components/routeloom_espnow/src/espnow_security_owner.cpp:503`、`:1399`）。DevRam の group 試験を可能にする PR では、この経路設定の受渡しと scoped timer を追加する。LegacyFixture 専用 Kconfig を GUI から指定しただけで有効になると考えない。

### 0.5 検出・書込みの安全な状態機械

```text
Absent → Enumerated → Inspecting → Identified → Assigned
       → ImageVerified → Quiescing → Preflight → Flashing
       → Reenumerating → BootVerifying → Ready
                                     ↘ Failed / RecoveryRequired
```

- 列挙には `pyserial.tools.list_ports` の port/VID/PID/serial/location/interface を用いる。MAC は USB descriptor から推測しない。USB-UART bridge では USB serial は ESP の identity ではない。[pySerial の列挙仕様](https://pyserial.readthedocs.io/en/latest/tools.html#serial.tools.list_ports)
- setup 画面で未使用の新規候補を自動検査できる。ROM probe は reset を伴うため、観測・送信中、他の port owner がいる場合は予約のみとする。常時スキャンで稼働機を reset しない。
- `BoardIdentity = chip + revision + ROM/base MAC + STA MAC(kind 明示) + flash_id/size` を保存する。MAC 導出差のある target では chip adapter が変換し、field の STA MAC readback と突合する。ポート名や VID/PID だけで別個体を代替しない。
- serial number がない同型機、複数 interface、同時再列挙で確定できない個体は `Ambiguous`。対象を一台ずつ再接続する操作案内を出し、推測で書かない。
- `PortLease` を `board_uuid` 単位で排他的に取る。daemon、console、log capture、esptool は同時に同一 interface を開けない。外部 daemon を利用していて停止権限がない場合は、その port の書込みを不可にする。
- Preflight は **書く直前、ROM 接続と同じ session** で chip/MAC を再照合する。bundle chip/revision、実測 flash 容量、全 offset/size、重なり、partition、image header、SHA-256、署名、許可された flash mode を検証する。
- esptool の Python API を専用 worker process 内で使用する。採用版を lock し、API adapter を一箇所に置く。probe、flash attach、write、verify、reset だけを allowlist 化する。公式 API は chip 検出、MAC/flash 情報、書込みを提供する。[esptool scripting API](https://docs.espressif.com/projects/esptool/en/latest/esp32/esptool/scripting.html)
- **eFuse 書換え、secure boot の有効化／解除、flash 暗号化の有効化／解除は一切実装しない。** `espefuse`／`espsecure`、任意 register 書込み、`--force`、暗号化書込みを UI/API から呼べない構造にする。通常の ROM 識別・esptool の read-only security 状態確認を使い、保護有効・状態不明の個体は書込み拒否。eFuse を操作する独自処理は置かない。
- image の bootloader 自体が初回 boot で security fuse を変更し得るので、配布時に該当 Kconfig を禁止する。既存 `build_image.sh` の数項目だけの正規表現検査を完成要件とはしない。
- 部分更新は app 領域だけを基本とする。ただし layout、SDK state schema、role が互換な場合だけ。全 flash erase、NVS 初期化、boot counter の巻戻しを自動実行しない。非互換の既存状態は通常フローを停止し、専用の再構成手順へ分岐する。
- 書込みは esptool verify、再列挙、field の identity/config/firmware readback、bridge API1 attach または reference boot-ready を確認して完了とする。書込み成功と mesh 参加成功は別の状態。
- 初期 timeout は ROM 接続 10 秒、書込み 120 秒、再列挙 30 秒、field 起動 30 秒。検証済み board profile で調整可能。タイムアウト後の自動再試行は read-only probe に限定し、書込みを続行する前に再照合する。

一括書込みは最初は直列。実機評価後、独立 USB port で最大 2 worker、同じ hub は原則 1 worker とする。全台 preflight 後にも各台の直前照合を行う。中止は待機台を止め、書込み中の台は安全な終了点まで待つ。抜線で中断した台を成功にせず、完了台を巻き戻さない。

### 0.6 チップ差・partition・C6 対応

現 partition は両 role とも `factory=0x10000, size=0x180000`。bridge の `rlsec=0x190000, size=0x20000`、reference は同 offset/`0x10000`。終端はそれぞれ `0x1B0000`／`0x1A0000`（両 app の `partitions.csv:8`）。これらは既存 layout の説明であり、新しい board に共通 offset として hardcode しない。

`rlcfg` の初期案は **既存領域を動かさず、両 role とも `0x1B0000` に0x6000 bytes、続いてprivate設定用 `rlkeys` を `0x1B6000` に0x3000 bytes追加**する。終端は `0x1B9000` で2 MiB内。`rlkeys`は論理的な秘密の分離であり、flash暗号化/eFuse操作は使わない。partition table の差分を検査し、既存 flash に別用途領域があれば拒否する。reference↔bridge の `rlsec` サイズ変更は単純な app 更新と区別する。app が 0x180000 に収まらない場合は CI で失敗させ、別 layout 版を設計する。

| chip | RAM・USB の特徴 | この SDK／アプリでの扱い |
|---|---|---|
| C3 | SRAM 400 KiB（cache 分を含む）、RTC SRAM 8 KiB、USB Serial/JTAG。 | 現 bridge の Wi-Fi IRAM 最適化無効化を維持。静的 RAM の余裕だけで実行時 heap を保証しない。 |
| S3 | SRAM 512 KiB。USB OTG と Serial/JTAG がある。PSRAM の有無は module 次第。 | connector/interface を区別し、bridge は既存 Serial/JTAG を使用する。PSRAM 前提にしない。 |
| C5 | HP SRAM 384 KiB、LP SRAM 16 KiB。2.4/5 GHz 対応の SoC。 | RouteLoom では **2.4 GHz LR** を使用。5 GHz の選択肢を出さない。既存 size 最適化と RAM 配置を維持する。 |
| C6 | HP SRAM 512 KiB、LP SRAM 16 KiB、USB Serial/JTAG。 | 新しい target。メモリ配置、LR API、callback、sleep、USB 再接続を個別確認する。C5 image は使えない。 |

RAM/USB の根拠：[C3 datasheet](https://documentation.espressif.com/esp32-c3_datasheet_en.html)、[S3 datasheet](https://documentation.espressif.com/esp32_s3_datasheet_en.pdf)、[C5 公式資料](https://developer.espressif.com/workshops/esp-idf-with-esp32-c5/)、[C6 datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-c6_datasheet_en.pdf)。実際の空き容量は build map と実機 health を優先する。flash 容量はチップ名から固定せず毎個体を probe する。

native USB は reset、ROM/field 切替、deep sleep に伴い切断・再列挙し得る。C6 では deep sleep 中に USB 自体が消えることが公式に記載される。[USB Serial/JTAG と sleep](https://docs.espressif.com/projects/esp-idf/en/release-v5.2/esp32c6/api-guides/usb-serial-jtag-console.html)。USB 消失だけで故障／除外としない。UART bridge 経由の port は ESP が sleep しても残り得る。

C6 を追加する PR の範囲：

1. `components/routeloom_espnow/idf_component.yml:26` の target 宣言、CI/release matrix、HIL Board schema、build backend、image catalog に `esp32c6` を追加する。
2. 同じ pinned IDF で両 app の DevRam、Member、setup、reference sleep、観測機能有効構成を compile する。C6 用 defaults を必要な場合に追加する。`docs/reference/radio-defaults.json`、resource profile、`tools/check_docs.py:54`、`tools/check_autonomous_design.py:63` の対象集合との整合も更新し、HIL未検証のgateを成功に書換えない。
3. `components/routeloom_espnow/src/espnow_runtime.cpp:165` の Wi-Fi 初期化と `:226` の per-peer LR250 設定、RX metadata、TX callback と watchdog、entropy、NVS、USB driver を C6 実機で検証する。対応が確認できない API を通常 PHY への fallback で回避しない。
4. C3/S3/C5 固有の RTC/LP 配置条件を監査する（`components/routeloom_espnow/src/espnow_security_owner.cpp:14`、bridge `main.cpp:62`）。C6 を既存分岐へ機械的に追加せず、保持領域・初期化・sleep 復帰を測る。
5. `tools/firmware_ram_report.py:39` の対象と試験を追加する。静的 free ≥8 KiB を維持し、ピーク heap、最大 free block、stack 高水位、同時 forwarding/暗号処理も HIL で測る。
6. C6↔C3/S3/C5 の相互通信、3 hop、抜線/再列挙、reset、Member 参加/除外、sleep 復帰を受入条件とする。compile 成功を RF 認定とはしない。

### 0.7 MemberEdhoc と Site Authority の操作

**DevRam** は個体設定後に実験用の共通 PSK で session を構築する簡易経路。メンバー証明書の承認済み状態とは別表示にする。

**MemberEdhoc** の wizard は次の順序を固定する。

1. Site を import、または実験用 CA/SAK/SiteCert を作成する。既存 Rust tooling を利用し、Python に証明書発行・EDHOC・COSE を再実装しない。Device CA と Site CA と SAK を別の役割として管理する。
2. 実験用の作成では `provision-devca-keygen`、`provision-siteca-keygen`、`provision-keygen --root-id <site_id>` による SAK 形式の鍵、`site-cert`、identity spec を組み合わせる。新設 `routeloomctl lab-site-init --spec FILE --out DIR` でこの orchestration と整合検査をまとめ、JSON の結果を返す。現状の local tooling は `host/routeloomctl/src/main.rs:17` と `:20`、Site の入力形式は `host/routeloom-host/src/site/config.rs:45` を基準にする。
3. chip/MAC を確認し、setup image を起動。`benchcfg` を確定後、device consoleの`status` → PC側CLIの`provision-pop-challenge --node <node>` → deviceの`keygen <node> <challenge>` → PC側`provision-devcert`でPoP検証・発行 → deviceの`identity <bundle_hex>` と進める。
4. device private key は機器の keygen で生成する。GUI が保管するのは challenge、PoP、公開証明書、fingerprint、操作結果。通常経路で PC 生成 private key の injection は選ばない。
5. **keygen と identity の間で ROM probe/reset/flash を挟まない。** pending key は RAM なので失われる。port 消失時は古い PoP を再利用せず、新しい challenge からやり直す。
6. identity の `OK sealed kid=...` は firmware が commit と readback を済ませた結果（`components/routeloom/src/sdkv1_maintenance.cpp:521`）。`console_locked` なら、その後の `status` も `ERR locked` になる（`:395`）。既存 bench script の「必ず OK identity=sealed が返る」仮定は採用しない。field の read-only identity fingerprint でも確認する。
7. field image の app 領域だけを更新し、`rlsec`、`nvs`、boot counter を保つ。GUI が daemon を `--site-authority DIR --api-acl-file FILE` で起動する。SAK は host に置き、ESP へコピーしない。
8. `join.requests.list` と event の要求を表示し、`join.decide` の allow/pending/deny を実行する。decision timeout は 500〜5000 ms の範囲で、人間がその場で間に合う保証はない。timeout 後も discovered device と次回試行を追跡し、既存の `applied=current_attempt|next_attempt` を表示する。長時間の人間待ちのために EDHOC transaction を保持しない。
9. `members.get/list`、`operations.get`、`member.confirmed` で台帳 commit、配送、機器での適用を分ける。allow 応答だけで全機器を Member と塗らない。

除外は `membership.revoke {device_id,expected_generation,reason,idempotency_key}`。理由は `removed/lost/replaced/blocked`。group key の staged/active、RRS 配布と未確認台数も追跡する。除外決定と、孤立した当該機器が通知を受けた事実は別である。

cutover は `membership.cutover {expected_site_epoch,next_site_cert,idempotency_key}`。Site CA 検証済みの次の SiteCert、対象台数、epoch、準備時間を開始前に表示する。**現実装は 600 秒の prepare、gateway PREPARED の条件、commit 後 60 秒 grace** を持つ（`host/routeloom-host/src/site/cutover.rs:1`、`:49`）。`preparing/waiting_gateway/committed/converged/recovery_pending` と `prepared/applied/unknown` を表示し、即時切替や rollback のボタンは設けない。開始後に GUI が落ちても daemon/store の operation を再取得する。

権限は `MEMBERSHIP_READ`、`MEMBERSHIP_DECIDE`、`MEMBERSHIP_ADMIN` を分離する。既存 site を開いた利用者の権限を GUI が自動昇格させない。新しい自己所有の実験 site は wizard が必要な自ユーザー ACL を生成する。発行鍵や site.db は記録ファイルとは別ディレクトリに保管する。

## 1. データ取得経路と OS 対応

### 1.1 推奨構成

```text
                           ┌─ firmware catalog / build worker
Python GUI ─ BoardManager ─┼─ esptool worker ─ ROM bootloader
                           └─ console worker ─ setup / reference USB

Python API1 client ─ local IPC ─ routeloom-host ─ authenticated USB ─ bridge
                                    │                              │
                                    ├─ OperationStore             mesh
                                    └─ Site Authority              │
                                                               reference

API1 / USB observations / replay file → 共通データ reducer → 表示・記録
```

通常時の bridge USB は daemon が単独所有する。Python が COBS、USB credit、session proof、HostOps dispatch、join relay を再実装する案は採用しない。Rust の状態機械・認証・永続 operation・Site Authority を共通利用できるためである。

Python は薄い API1 client を実装する。`routeloom-client` の Rust FFI 化は必須にせず、同じ JSON contract/golden fixtures で互換性を検証する。CLI は offline の鍵・証明書 tooling と人間向け再現手順に使い、毎秒 `routeloomctl` を起動して観測する構造にはしない。

直接 serial は、書込み、setup console、reference の log/read-only observer に限定する。無線で到達できない機器も USB で調査できる。bridge の protocol port に文字列 log を混ぜない。既存 bridge は log を UART0 に分離し、secondary console を無効にしている（`firmware/bridge_node/sdkconfig.defaults:10`）。

MVP は site あたり稼働 bridge 1 台。多数の reference の一括書込み・USB log capture は可能。複数 bridge の同時運用は後続の daemon MultiAdapter 対応で行い、同じ site.db を複数の独立 Site Authority に開かせない。別 site の実験は DB/IPC/namespace を分ける。

### 1.2 現状の OS 対応評価

| OS | コードから確認できる現状 | 配布判断 |
|---|---|---|
| Linux | Unix socket、`stty -F`、device file open、SO_PEERCRED の実装。CI と release の host binary は Linux。 | 最初の開発経路。udev/group 権限と他 serial monitor の競合を診断する。root 起動を標準にしない。 |
| macOS | `stty -f` の分岐、Unix socket、`getpeereid` がある。 | 対応コードはあるが、当該 CI は macOS build/HIL の証拠ではない。arm64/x86_64 build、serial 再接続、ACL、署名を追加検証する。 |
| Windows | `compile_error!(not(unix))` と UnixStream 依存により、そのままの daemon/CLI/client は使えない。 | native 移植を三 OS 完成版の前提 PR とする。移植前は Windows で replay を開けても実機操作全対応とは称さない。 |

根拠：`host/routeloom-host/src/main.rs:1`、`:29`、`:1808`、`:1852`、`host/routeloom-peercred/src/lib.rs:9`、`:59`、`host/routeloom-client/src/api1.rs:22`、`host/routeloomctl/src/main.rs:1`、`.github/workflows/release.yml:66`。

### 1.3 Windows 移植の具体的範囲

1. **local IPC 抽象化**：Unix は filesystem Unix domain socket、Windows は byte-mode Named Pipe。API1 の改行 JSON は共通。GUI は `QLocalSocket` を使う。同クラスは Unix socket／Windows Named Pipe を抽象化する。[Qt QLocalSocket](https://doc.qt.io/qt-6/qlocalsocket.html)
2. **principal**：`UnixUid(u32)` と `WindowsSid(string)` を扱う型を追加する。Named Pipe の DACL を利用者に制限し、remote client を拒否し、OS が検証した peer token/SID から主体を得る。JSON の自己申告を信用しない。SID を u32 に hash して既存 uid と混ぜない。ACL、OperationStore、site idempotency key の主体列を版付きで移行し、既存 uid は lossless に変換する。
3. **serial**：`File + stty` を `SerialTransport` に分離し、Rust の cross-platform `serialport` 等で COM/Unix TTY を扱う。read/write timeout、排他 open、DTR/RTS、partial read、unplug を試験する。USB 認証・credit・dispatcher は変えない。[serialport-rs](https://github.com/serialport/serialport-rs)
4. **乱数**：`host/routeloom-edhoc/src/crypto.rs:188`、`host/routeloom-provision/src/signer.rs:132` の `/dev/urandom` を OS CSPRNG 抽象に置換する。鍵用乱数の失敗時に時刻/pid fallback を使わない。client/CLI の id 生成も監査する。
5. **private file**：鍵、Site DB、SQLite WAL/SHM、一時 bundle を Unix 0600/0700、Windows 所有者 DACL で作成・検査する。`host/routeloom-provision/src/signer.rs:278` の non-Unix permission 検査 no-op を残さない。`host/routeloomctl/src/provision_office.rs:166` の Unix 専用 directory 作成も移植する。
6. **daemon lifecycle**：GUI が子 process として起動・終了・再起動する。OS service 登録は初期版に不要。再列挙で port 名が変わると現 supervisor は同じ path へ戻ろうとするため、GUI の識別済み port を渡す再接続機能を追加する。実行中 operation を別 MAC の機器へ引き継がない。
7. **既存ツールの整合**：CLI と `routeloom-client` は同じ IPC 層へ移す。TUI も同層へ移すか、Windows packaging から明示除外する。`cargo build --workspace` が Unix 前提 crate で止まる状態を配布手順で放置しない。

loopback TCP だけに変更して peer credential/ACL を省く案は採用しない。WSL＋USB 転送は開発者の任意環境として扱い、Windows 利用者の標準手順にしない。

### 1.4 API1 client の接続契約

- control と subscription に原則 2 接続。request は `API1 {"v":1,"request_id":"...","method":"...","params":{...}}\n`。応答は prefix なしの JSON 行で `request_id` と `ok/result/error` を持つ（`api1.rs:374`）。
- 既存 request 上限 8192 B、response 65536 B、JSON depth 8。UTF-8、partial line、複数行同着、unknown field、EOF、timeout を扱う。文字列を shell に連結しない。
- `capabilities.get` → `link.get` → event subscribe → `nodes.list` 全 page の順に接続する。snapshot 中の event は buffer し、source session と時刻で整合させ、取得後に再適用する。新版は後述の snapshot revision で確定できるようにする。
- `messages.subscribe` は `stream:"events"` と必要時 `stream:"messages"`。notification は `subscription/kind/n`、内部 event は `seq/ms/kind` を持つ別形式（`subscribe.rs:748`）。通知番号と mesh message sequence を混同しない。
- `gap/ended/heartbeat` を処理する。events ring は 256 件、subscription queue は 128 件/256 KiB、受信 log は 300 秒/4096 件/2 MiB per network。daemon の RAM log を長期記録としない。
- EOF 後は指数 backoff、再 capability 確認、source epoch の更新、subscribe/snapshot 再実行。復元できない区間は GapEvent を保存する。最後の値を通信継続中として延命しない。
- GUI 自身が起動した daemon だけを自動停止する。利用者の既存 daemon へ attach する経路も設ける。

## 2. 取得できるデータ、足りないデータ、追加する契約

以下の file:line は冒頭の commit に対する位置である。略記 `api1.rs`、`nodes.rs`、`subscribe.rs`、`send_store.rs` はそれぞれ `host/routeloom-host/src/` 配下を指す。**既存**と**提案**を混ぜて capability を広告しない。

### 2.1 既存インターフェースの棚卸し

| 経路 | 現在取得できるもの | 制限・意味 | 実装根拠 |
|---|---|---|---|
| API1 `capabilities.get` | method、送受信上限、保存・subscription 能力、USB 各機能、site 設定 | build と接続 firmware に依存。メソッド名があるだけでは対象 board が対応する証明にならない | `api1.rs:419`、`:438` |
| `link.get` | configured / connected / authenticated、attached/reconnecting/disconnected、USB session、gateway NodeId/boot、lane 登録・lease、last_error | PC–bridge の状態。全ノードの session/boot/health ではない | `api1.rs:1835` |
| `nodes.list` / `nodes.get` | node、role、connected、listed、neighbor、direct、hops、next_hop、route_metric、link_cost、RSSI last/EWMA、telemetry_stale、last_heard / heard_age / updated / changed | **gateway が観測した view**。gateway は hops=0、直結は1、multi-hop は null。connected は route の到達性であり、Member 証明書の加入状態ではない | `api1.rs:1886`、`:1953`、`nodes.rs:175`、`:470` |
| 同 source | unavailable / unsupported / syncing / live、gateway、USB session、同期時刻、tracked/evicted | NodeTable は512件、page は最大128件。USB は16件/page、10秒周期の sweep と変化 event | `nodes.rs:41`、`:505`、`host/routeloom-protocol/src/node_status.rs:26` |
| events `node_joined/node_left/link_changed` | node status と route_up/down、neighbor/next-hop 変化等 | 名前の joined/left を Site Authority の admission に転用しない | `nodes.rs:518` |
| `messages.read` / subscribe messages | origin、gateway、network、message session/sequence、payload、cursor、host 時刻、endpoint/evidence | gateway mirror に届いた payload。全 RF packet capture ではない。`rx_events_v1=false`、`ingress_loss_observable=false`。現 JSON の `assurance` は固定の Dev PSK 表示なので Member の security 判定に使わない | `api1.rs:779`、`:799`、`:438` |
| events stream | adapter/auth/credit、data_from_mesh 要約、delivery_event、diagnostic、dispatch、USB error、group_settled、node/link 変化等 | ring256件、フィルタ kinds 最大16。drop/gap あり。生 payload は別 messages stream | `host/routeloom-host/src/main.rs:40`、`subscribe.rs:36`、`:66` |
| `messages.submit` / `operations.*` | admission epoch/key、operation id、destination、payload 長/hash、options、dispatch state、evidence、message key、期限/取消/時刻不確実フラグ | `application_outcome=null`。現通常 HostOps 経路では最終 reason と各 phase の時刻が不足する | `api1.rs:3506`、`send_store.rs:57` |
| `group.send` / `group.get` | final/state/result/reason、message key、gateway、rounds、delivered/nonmember/missing/unaccounted、欠落 NodeId 最大12と truncated、submitted/admitted/settled 時刻 | payload127 B、queue8、unsettled16、記録256。RAM 保存。gateway 起点の group。membership 設定 API は未提供 | `api1.rs:2198`、`:2310`、`docs/spec/host.md:129` |
| `gateway.resolve/get`、`config.*`、`trust.*` | gateway 選択、既存 remote-config permit/trust の状態と操作 | 一般的な製造時 NodeId/MAC 書換え API ではない。BoardConfig の代用品にしない | `api1.rs:319`–`:344` |
| `site.status`、`join.policy.get/set`、`join.requests.list`、`join.decide`、`devices.discovered.list`、`members.list/get`、`membership.revoke` | 承認待ち、発見 device、membership ledger、承認/拒否、revoke、site/authority 状態 | USB join/authority lane の ready 状態を別表示。ledger 上の承認と device の適用完了を分離する | `host/routeloom-host/src/api1/site.rs:36`、`:53`、`:643`、`host/routeloom-host/src/site/mod.rs:4874` |
| `membership.cutover`、`group_keys.status/rotate`、`operations.get` | cutover、group key rotation と進捗、member applied 等 | 現コードには実装あり。古い `docs/spec/host.md:211` の未実装記述よりコードを優先する | `host/routeloom-host/src/api1/site.rs:504`、`host/routeloom-host/src/site/cutover.rs:1919` |
| legacy `STATUS` / `DIAGNOSTICS` | USB connected/device、rx_frames/tx_frames/protocol_errors/last_error | 2コマンドは同じ要約。heap、reset reason、uptime を返す Diagnostics API ではない | `host/routeloom-host/src/main.rs:1323` |
| legacy `ADAPTER` | 認証、session/node/boot/network/capability/version、USB credit、frame/byte/error 数 | daemon/bridge の USB 診断用 | 同 `:1340` |
| legacy `NODES/DELIVERIES/EVENTS/AUTHORITY/AUTONOMY` | seen node、旧 delivery reason、ring event、限定的 autonomy 情報 | NODES の membership は seen/route 由来。AUTHORITY は unknown の旧 stub。DELIVERIES を全 API1 送信の配送台帳にしない | 同 `:1370`、`:1432`、`:1456`、`:1473`、`:1481` |
| USB `Diagnostic` frame | peer、任意の message key、reason | 自由な node health snapshot ではない | 同 `:1061` |
| USB HostOps `0x40..0x42` | NodeStatus page / subscribe / change event | bridge 自身の neighbor/selected route を統合した node 表。各 observer の全表ではない | `components/routeloom/include/routeloom/node_status.hpp:33`、`components/routeloom/src/node_status.cpp:19` |
| USB HostOps `0x30/0x31` | local/remote Diagnostic request と応答、固定128 B TelemetrySnapshot | **firmware はあるが daemon の typed codec/cache/API1 が未接続**。generic `host_ops_rx` は完成した telemetry API ではない | `components/routeloom/include/routeloom/usb_host_ops.hpp:55`、`components/routeloom/src/usb_bridge.cpp:873`、`:998`、`host/routeloom-host/src/main.rs:1180` |

Site の event は `join.request`、`join.decided`、`device.discovered`、`member.reissued/confirmed/revoked/removal_notified`、`rrs.published`、`cutover.progress`、`gk.staged/rotated/member_applied`、`authority.error`、`site.session_drop`（斜線は同じprefixの列挙）。wire 名は `host/routeloom-host/src/api1/site.rs:36` を golden 化する。GUI は site ledger、観測された接続状態、board の設定 profile の3軸を保持する。

### 2.2 既に firmware にある通信品質情報

`components/routeloom/include/routeloom/telemetry.hpp:255` の snapshot をそのまま型付きで活かす。

- identity：`request_id, observer, observer_boot, peer, binding, radio, channel_epoch, channel, direction, length_class`。
- freshness：`sampled_at_ms, window_ms, sample_age_ms, validity, event_drops, saturation_mask`。
- RSSI：`rssi_last, rssi_min, rssi_max, rssi_ewma_q8_8, rssi_samples`。
- count：`tx_submitted, tx_mac_success, tx_mac_fail, tx_unknown, sdk_retries, hop_accepts, hop_timeouts, busy`。
- 時間：`queue_us_ewma, driver_us_ewma, hop_rtt_us_ewma`。

RSSIは **peerからobserverへ受信した信号**の観測である。`direction`は主に詳細bucketの向きであり、Egress snapshotのRSSIをobserver→peer側の受信強度と解釈しない。UI/exportに `rssi_direction:"peer_to_observer"` とcounterの方向を別記する。

これは boot/binding/bucket ごとの**飽和する累積値**であり、`window_ms` 内の単純な event count ではない。差分は同一 identity の連続した有効 sample のみから計算する。RSSI summary class255 は bucket の送信統計を返さない。無効値を0と表示しない。driver callback の所要時間は RF 片道遅延ではなく、SDK retry と Wi-Fi hardware 内部 retry も同一ではない。時間分布の p95/p99 は EWMA から復元できない。queue EWMA は現 wire の validity だけでは「sample無しの0」と実測0を十分区別できないため、v1 ではその限界を表示し、将来 validity/sample count を追加する。

根拠：同 `:224`、`:251`、`components/routeloom/src/node.cpp:6550`、`:6665`、`:6682`。telemetry の peer capacity は19（`components/routeloom/include/routeloom/telemetry.hpp:28`）であり、論理 neighbor capacity32や route capacity128とは異なる。

remote query の受理コードは存在するが、reference の現在の Kconfig は remote telemetry を LegacyFixture に依存させている（`firmware/reference_node/main/Kconfig.projbuild:246`、`firmware/reference_node/main/main.cpp:1351`）。DevRam/Member の lab image に明示的 opt-in を追加し、SecurityOwner の Node 再構築後にも設定が適用されるようにする。Member では認証済み site 内の許可された診断に限定し、未知 peer 向け無制限応答を作らない。

### 2.3 表示の意味と不足一覧

| 欲しい表示 | 既存でできる範囲 | 最小追加／表示規則 |
|---|---|---|
| 全体の物理リンク | gateway が直接観測した neighbor と RSSI | 各 observer の neighbor snapshot。observerとpeerを明記した有向観測。RSSIはpeer→observer、egress統計はobserver→peer。片側だけでも描けるが双方向確認済みと区別 |
| 任意宛先への経路 | gateway の selected next_hop/metric | 各 observer の selected route 表または destination 指定照会。候補3本すべては初期対象外 |
| gateway への木 | gateway→各 destination の表だけでは求まらない | **各 node→gateway の selected route**を集める。反転した下り表を上りの木にしない |
| hop 数 | gateway0、直結1 | 同一時間帯・scope の route chain を辿った `derived_hops`。途中欠落、loop、stale は null。metric を hop 数へ換算しない |
| STALE/REACHABLE 等 | NodeStatus の reachable と telemetry_stale | NeighborPhase の明示取得。UI の「観測が古い」と protocol の Stale は別フィールド |
| RSSI/損失/SDK再送/時間 | gateway 直結 RSSI、firmware 内 telemetry | `telemetry.get` の daemon 接続。物理層の全 packet 損失や hardware retry は「未取得」。既存 count から算出可能な指標だけ定義して表示 |
| heap/reset/uptime/session 数 | 一部 log、USB gateway boot | `health.get`。session 数は実際の各 table の active/capacity を取得し、neighbor 数から推定しない |
| Member/承認待ち/除外済み | Site ledger と events | profile、authority decision、device applied、接続状態を別表示。除外操作の受理だけで device 適用済みにしない |
| 配送理由の分布 | 旧経路の delivery_event、group reason | unicast HostOps window に最終 reason/timing を保存し API1 に公開 |
| RTT・受信側 goodput | reliable の SDK 受領 evidence、受信 log | reference に明示的 bench echo / receiver counter を追加。app callback 到達を確認する |

gateway の route が `destination=C, next_hop=B` であることから、**B–C が直接無線リンクであるとは言えない**。MVP は A–B の確認済み link と「A は C 宛てを B 経由で送る」という論理経路を異なる線種で描く。実際にある packet が辿った hop の証明は snapshot からはできない。必要なら後続で message key に結び付く各 hop の trace event を別送する。暗号化された application body に relay が NodeId を追記する方式は採らない。

### 2.4 新規 API1 契約（提案）

既存 API1 v1 へ capability 付き method を追加する。以下の名前・フィールドは**新規提案**。request/response の上限は既存以下、unknown method/capability は UI で未対応にする。すべての観測は read-only、remote は新設 ACL 権限 `OBSERVE` と firmware の診断 opt-in に従う。既存 `link.get/nodes.*` は現状どおり diagnostics-class の読取りを保つ。新権限は `acl.rs` のparser/capability/OS主体移植に追加し、既存ユーザーの権限を黙って昇格させない。

**共通 envelope**：`schema:1, scope:{site_id?,site_epoch?,wire_network_low32}, source:{gateway,usb_session,observer,observer_boot,transport}, revision?, sampled_at_ms, received_unix_ms, age_ms, stale, complete, validity, gaps`。node clock と host clock の意味を明示する。remote の `age_ms` は観測元の sample age と host 受信後時間を含み、転送時間の未知分を別扱いにする。フィールド取得不能は null、0や空配列で成功したふりをしない。`scope` は host の検証済み Site/USB 状態から作る。

| 新規 method | params | result と責務 |
|---|---|---|
| `telemetry.get` | `network, observer, peer, direction, length_class, max_age_ms, cache_ttl_ms?`。既存 query と同じ max_age 0..3000、class0..2/255 | §2.2 の field 全件、raw validity/saturation とデコード済み nullable 値。cache freshness を満たせば返す。満たさなければ bounded query。1 remote outstanding、期限5秒。busy は retry_after 付きで返す |
| `topology.get` | `network, observer, section:"neighbors"\|"routes", destination?, cursor?, max_age_ms` | common envelope、`entries,next_cursor`。neighbor: peer、phase、binding/radio、last_heard_age、lease_remaining、link_cost、RSSI/validity。route: destination、next_hop、generation、sequence、metric、remaining_lifetime、valid。destination 指定は1経路。未選択は `present:false` |
| `health.get` | `network, observer, section:"system"\|"tables", max_age_ms` | system: chip/build/config digest、boot、uptime、reset code/name、内部8-bit heap free/min/largest（bytes）、power mode/sleep intent/wake reason。PSRAMは存在する場合だけ別field。tables: neighbor/route/link-session/end-session 各 active/capacity、dedup resident/terminal pins/capacity/refusals、delivery/queue counts、driver/observer drop counters。秘密鍵・session key は返さない |
| `board.get` | `network, observer` | readonly chip、base MAC、build/bundle/config digest、configured role/NodeId、runtime security profile、effective network/site epoch/channel、group IDs、setup/identity lock 状態。USB boot 照合と security 表示のため。情報ごとの取得元を持つ |
| `operations.get` への追加 | 既存 params | `delivery:{state,reason_code,reason_name,terminal,source,boot,accepted_at_ms?,terminal_at_ms?,timestamp_clock}` と `revision`。未対応 firmware は delivery=null と capabilities=false |
| `capabilities.get` への追加 | なし | `observation:{telemetry,topology,health,board,remote,limits}`, `send.delivery_detail`, `send.admission:{profile,rate_per_min,burst,...}`, `runtime_security`。実際の lane、firmware、config に連動 |

`telemetry.get.max_age_ms` は**測定値自体の古さ**を制限する既存wire契約であり、0は上限要求なし。新しいqueryが古い測定を新鮮にするわけではない（`components/routeloom/src/node.cpp:6571`）。別項目 `cache_ttl_ms` はhost cacheの受信後許容時間0..10000、既定local1000/remote5000、0でcache bypass。cache再利用時もfield validityと経過ageを再評価する。topology/healthの `max_age_ms` はsnapshot取得からの許容時間0..60000、既定10000、0は新規取得要求。意味をmethodごとにschemaへ固定する。

`topology.get` は1応答2 entryまで、cursorを跨いだrevision一致を要求する。destination指定はroutesのみ。revisionはentry追加/削除、phase、next_hop等の構造変化で更新し、ageの毎tick増加だけでは更新しない。daemonのpending observationは最大16件、cacheはobserver128台・合計8 MiBを上限としてLRU化し、evictionをcomplete empty snapshotとは扱わない。受付から5秒以内に終えられないremote要求は `BUSY/retry_after_ms` とする。全client共通のremote rate budgetは**daemonが最終強制**し、GUI schedulerはその内側で画面の優先度を決める。

`board.get` は文字列を含むため、新 RF wire を一度に増やさない。初期は bundle/BoardConfig の verified local USB 情報と daemon の現在 scope を統合し、remote 未取得フィールドは null。後続の health identity page で必要なら配信する。field firmware の reference には、同じ readonly serializer を使う `OBS1` 接頭辞の改行 JSON console を追加する。log と prefix で区別し、1応答4 KiB以下、単一要求処理、rate 制限。初期は USB 接続した reference の health 取得に利用できる。書込み・setup コマンドとは状態と権限を分ける。

新 event は `topology.changed`（observer/boot/revision、section、変更 key、resync_required）、`operations.changed`（operation id/revision/状態/最終 reason）、`observation.gap`（source、範囲、理由、drop count）。telemetry/health の高頻度 sample は query の結果として記録し、全 sample を既存256件 event ring に重複投入しない。`topology.changed` は dirty 通知を基本とし、GUI が snapshot を再取得する。認証・加入・配送の event を sample が押し出さないようにする。

各 method の error は、既存 API1 error envelope に `UNSUPPORTED, NOT_CONNECTED, NOT_FOUND, STALE, BUSY, CAPACITY, DENIED, DEADLINE, SNAPSHOT_CHANGED` 相当を追加・文書化する。USB result と API error の対応表を golden fixture にする。deadline 超過時の再送は同一観測 request の重複処理を許容するが、application send の新 operation と混同しない。

### 2.5 firmware/USB/daemon の最小変更

**A. 既存 telemetry を開通する**

- Rust protocol crate に Diagnostic query/snapshot/reject の codec を追加する。C++ encoder の byte fixture と相互試験する。
- daemon に diagnostic lane（request id、timeout、cache、remote schedule）を追加し、HostOps `0x30/0x31` を demux する。旧 generic event から JSON を推測しない。
- 現行 bit5+HostOps bit2 を要求する。local bridge query は無線を使わない。remote は相手 opt-in、route、Member policy を確認する。
- `telemetry.get` の名前は既存設計 `docs/design/m1-completion/02-telemetry.md:90` と合わせるが、文書に提案があることと API 実装済みであることを区別する。

**B. neighbor/route/health の bounded snapshot を足す**

既存 Diagnostic body type の拡張を第一候補とする。現在 subtype1..6 を保持し、**7 TableQuery、8 TablePage、9 TableChanged、10 HealthQuery、11 HealthSnapshot**を予約する。USB carrier は `0x30/0x31` を再利用し、local unsolicited dirty 通知用 `0x32`、capability **bit11 `observation_v1`**を提案する。ID は実装 PR の最初に C++/Rust/spec の単一登録表へ確定し、将来の HEAD で衝突していたら未使用番号へ変更する。旧USB bridgeには新subtypeを送らず、remote未対応peerへもcapability probe以外の新照会を繰返さない。

- USB capabilityとmeshのCapabilitiesReplyは別namespaceである。現mesh codecはfeature mask `0xFF` 以外を拒否する（`components/routeloom/include/routeloom/telemetry.hpp:337`）ため、bit11をそのままmesh広告へ足さない。新remote機能の照合はTableQueryの `section:0=capabilities` とTablePageの機能一覧で行う。verified bundleで対応が分からない相手には一度だけbounded probeを許し、Unsupported/timeoutは60秒negative cache。既存hop-local CapabilitiesQueryをmulti-hop転送しない。
- TableQuery は32 B以内。TablePage は128 B以内、共通 header48 B（prefix4、request4、observer8、boot8、revision4、sampled_ms8、section1、count1、flags2、cursor8）。neighbor entry32 Bなら2件、route entry最大40 Bなら2件/page。cursor は revision と結び付く opaque token。
- neighbor entry は peer8、binding4、phase1、flags1、cost2、last_heard_age4、RSSI last1/EWMA2/validity1、lease_remaining4、radio4 の32 B。scope/channel は request と観測 envelope に結び付ける。
- route entry は destination、next_hop、generation、sequence、metric、remaining lifetime、validity を持つ。reserved byte は0、最大40 B。正確な offset は codec PR の wire spec と golden bytes で固定する。
- HealthSnapshot は system/tables の各 section を128 B以内とする。string/build hash/全 groups が収まらない場合は identity section を別 page にし、黙って切り詰めない。
- snapshot 中に revision が変わったら `SNAPSHOT_CHANGED`。最大2回再開始し、それでも安定しなければ partial として提示する。異なる revision を complete snapshot に合成しない。
- 取得は Node の owner loop 内で行う。無線 callback で全表を走査・JSON 化しない。routing の `for_each_selected_change` は広告用 baseline を変更するため流用せず、readonly getter で UI 用 revision を維持する（`components/routeloom/include/routeloom/routing.hpp:255`、`:313`）。
- route128件、neighbor32件の全コピーを firmware に追加する必要はない。page buffer と小さな dirty set を使う。追加 RAM は Node 当たり8 KiB以内を目標として map/heap で検証する。
- local USB dirty 通知は最大4回/秒に coalesce、10秒ごとの full reconcile を残す。remote は初期版では pull。無線で全 change を即時 broadcast しない。Member NeighborPhase は security owner から getter を追加する。DevRam は対応しない phase を `UNKNOWN` とし、到達性だけから Authenticated/Member を生成しない。

core の route は最大128 destination×3 candidate、gateway 最大4、RouteSelection は next_hop/generation/sequence/metric/valid を持ち、hop count は持たない（`components/routeloom/include/routeloom/routing.hpp:14`、`:135`、`:152`）。NeighborPhase は Candidate/Authenticating/Authenticated/ApprovalPending/Bound/Reachable/Suspended/Stale/Conflict/Revoked（`components/routeloom/include/routeloom/peer_directory.hpp:105`）。phase は peer binding の状態であり、その node 自身の site membership 全体とは別である。

**C. 通常送信の配送理由を失わない**

現 `UsbBridge::on_delivery` は HostOps の送信だと window へ state を反映して return し、legacy DeliveryEvent へ reason を流さない（`components/routeloom/src/usb_bridge.cpp:2386`）。window/query は state/evidence/message key を持つが reason/timing がない（`components/routeloom/include/routeloom/usb_host_ops.hpp:368`、`:579`）。GUI 側だけでは復元不能である。

追加 capability **bit12 `dispatch_detail_v1`**、HostOps **0x06 QueryDispatchDetail / 0x07 DispatchDetail**を予約し、既存 query response の長さは変えない。window32 slot に numeric reason、terminal flag、同じ boot clock の accepted/terminal 時刻、revision を追加する。追加 RAM は32×32–48 B程度を上限目標とし、slot ごとに長い文字列を持たせない。同期send中のcallback（`ops_send_active_`）と遅延callbackの双方を同じoperationへ結び付け、staged outcomeを失わない。daemon は retire 前に detail を取得・永続化し、terminal update を1回発行する。失われた場合は `reason=UNKNOWN`、indeterminate として保存する。`NO_ROUTE`、`HOP_ACCEPT_TIMEOUT` 等の core reason と enum/code 対応を固定し、未知 code も保存する。

**D. runtime scope/security の事実を公開する**

Site Authority の full network は `(site_epoch << 32) | wire_network_low32`（`host/routeloom-host/src/site/mod.rs:312`）。一方、現 API1 の network validation と通常 HostOps は下位32 bit の範囲を前提とする（`host/routeloom-host/src/main.rs:1277`、`components/routeloom/src/usb_bridge.cpp:1848`）。現在の USB identity/network は Kconfig 起点でもある（`firmware/bridge_node/main/main.cpp:491`、`components/routeloom/src/usb_bridge.cpp:339`）。

Memberのsend/group/observationにはAPI1追加項目 `expected_scope:{site_id,site_epoch}` を要求し、daemonが検証済みの接続scopeと照合する。admission時だけでなくdispatch直前にも確認し、OperationStore/canonical identityにもそのscopeを保存する。firmware ownerのscope変更時は旧scopeのpending送信と観測を終了・無効化し、USB windowもscope世代で区切る。旧operationを新epochへ自動再投入しない。既存wireでこのfenceを表現できない経路は、Member用の版付きHostOps拡張（expected site/epochを含む）をPR07aで追加してから有効化する。DevRamの既存canonical schemaは維持する。

GUI は `wire_network_low32` と `site_epoch/full_network` を別保存する。64 bit full network を既存 `messages.submit.network` へそのまま渡さない。Member 対応 PR で owner の effective scope、USB lane、daemon Site view が整合する getter/再登録を追加し、API の `runtime_security` を実値に直す。cutover 中は試験を止め、epoch 変更後に観測 namespace、operation admission epoch、cursor を更新する。旧 scope の cache を新 site の現在値として表示しない。

### 2.6 更新頻度と負荷予算

更新の既定値は次の通り。画面描画の frame rate と無線 sample rate を別設定にする。

| 対象 | 既定 | 取得方法 |
|---|---|---|
| PC–bridge link | event、補助確認2秒 | API1/USBのみ |
| gateway node 表・local topology | event coalesce最大4 Hz、full reconcile10秒 | local USBのみ |
| local health | 2秒、非表示時10秒 | USBのみ |
| local selected link telemetry | 1秒 | USBのみ |
| remote 全観測合計 | **0.5 transaction/秒、burst1、outstanding1** | telemetry/topology/health で共通 scheduler。試験開始時はさらに抑制可能 |
| remote selected peer quality | 最短5秒。ただし全体予算内 | priority queue、同一 observer への偏り防止 |
| remote parent-to-gateway route | 小規模2–8台で巡回、目標10–30秒 | destination 指定1経路。混雑時は遅延を表示 |
| remote 全 neighbor/全 route | 明示要求、順次 page、取消可能 | 初期 snapshot・調査用途。全 route を常時 polling しない |
| Site / operation | events、実行中のみ不足状態を1–2秒照会 | host cache中心。USB dispatch の照会はdaemonに任せる |

firmware は診断budgetの追跡tableを8件に制限し、remote telemetryは同一originから最短200 ms間隔、query/replyのlifetimeは最大5秒である（`components/routeloom/include/routeloom/node.hpp:2618`、`components/routeloom/src/node.cpp:6820`）。これは推奨観測 rate ではなく最終的な受理境界。GUI は遥かに低い budget を採る。

既存設計の on-air 見積もりは query144 B + reply248 B + HopAccept126 B×2 = **644 B/edge/query**、4送信/edge（`docs/design/m1-completion/04-cross-cutting.md:106`）。H hop、q query/秒なら、再送・MAC header・CCA 等を除く bodyのbit直列化時間は `644×H×q×8 / PHY_bps` 秒/秒。LR250 kbit/s、H=3、q=0.5なら **約3.1%**、再送等で2倍なら約6.2%という設計上の目安になる。後者は実測保証ではない。新 TableQuery の増分を含めて **再送なしのbody合計約700 B/edge/transaction**を初期予算にし、HIL で測定して調整する。

100 node×平均4有向 neighbor の品質を10秒ごとに問い合わせると40 query/秒になり、同条件で body だけでも約247%相当となって成立しない。neighbor400件を2件/pageで集め、parent route100件を足した300 queryでも0.5/秒なら最低10分、品質 query と分け合えばさらに長い。**100台の画面を扱えることと、100台の全リンクを秒単位に実測できることは別の受入条件**にする。密な観測は各 board の USB 接続、対象の絞込み、snapshot間隔延長で対応する。

USB は現 NodeStatus100件≒7 pageで約3.5–4 KiB/10秒、新 local topology160件でも概ね6–8 KiB/10秒、selected telemetry1 Hzで数百 B/秒程度を想定する。封筒・認証・event を含め、観測は初期4 KiB/秒を上限目安とする。115200 baud UART の約11.5 kB/秒と native USB の性能を混同せず、credit/送信操作/authority traffic に余裕を残す。remote body size、USB encode size、retries、poll遅延を recorder に保存し、予算違反を画面で確認できるようにする。

## 3. GUI と描画の技術選定

### 3.1 比較と採用判断

ライセンスと対応基盤は各公式資料で確認し、性能・保守性の欄はこのアプリに対する設計判断とする。採用版の wheel、依存物、同梱ライセンスは release ごとに固定・検査する。

| 候補 | 三 OS・配布 | 描画・保守性 | ライセンス | 判断 |
|---|---|---|---|---|
| **PySide6 / Qt Widgets** | macOS/Windows/Linux。Qt plugin の同梱が必要。PyInstaller で OS ごとの成果物を作る | model/view、dock、wizard、native file dialog、QGraphicsView、IPC が揃う。日本語入力、表、長時間稼働の運用画面を一つの event loop で構成できる | Qt for Python は LGPLv3/GPLv3/commercial。利用 Qt module の条件も確認 | **採用**。フォーム・board操作・グラフ・再生を統合しやすい。[公式](https://doc.qt.io/qtforpython-6/) |
| PyQt6 | 同じ Qt 基盤、配布上の条件も近い | 技術的には有力。PySide と混在させない | GPLv3/commercial、LGPL ではない | 別途商用契約または GPL 方針を必要とする利点が本件では小さい。[公式](https://www.riverbankcomputing.com/software/pyqt/) |
| Dear PyGui | 三 OS。Windows DirectX11/macOS Metal/Linux OpenGL 系の GPU backend と実機確認が必要 | plot/node editor が標準で、描画頻度が高い測定器に向く。本件では complex form、表、IME、accessibility、長期 UI 保守の検証負担を見込む | MIT | 専用高速計測画面なら再検討。今回は Qt の標準部品を優先。[公式 repository](https://github.com/hoffstadt/DearPyGui) |
| Tkinter | CPython の標準的 GUI interface。Python build によって Tcl/Tk が別途必要 | 単純な設定画面には軽い。大きな network canvas、dock、複数時系列は自作部分が増える | Python/Tcl/Tk の各条件。Tcl/Tk は BSD 系条件 | 配布サイズの利点より UI 実装量が増える。[Python公式](https://docs.python.org/3/library/tkinter.html)、[Tcl/Tk license](https://www.tcl-lang.org/software/tcltk/license.html) |
| NiceGUI 等の browser 型 | Python backend＋browser、native mode では WebView も配布対象 | ECharts 等を使いやすい。ローカル server、port、browser lifecycle、JS asset と backend の二層を保守する。serial は backend が扱う | NiceGUI は MIT。描画/JS依存は別確認 | 将来 remote dashboard の候補。USB wizard 主体の初期製品には構成要素が多い。[公式 repository](https://github.com/zauberzeug/nicegui) |

### 3.2 グラフと時系列

- **network 図：Qt `QGraphicsScene/QGraphicsView`**。node/edge item を保持して差分更新する。物理 link、logical route、selected gateway tree、membership を別 layer とし、選択した node の経路だけ強調する。全 edge を常時太線表示しない。
- 自動配置は小規模なら spring layout、gateway tree は階層配置。NetworkX を任意依存として layout 計算にのみ使い、`networkx.draw` で毎回図を作り直さない。seed/固定座標を保存し、リンク変化のたびに全ノードが飛び回らないようにする。[NetworkX 描画 API](https://networkx.org/documentation/stable/reference/drawing.html)
- **時系列：pyqtgraph**。MIT、NumPy/Qt を使う描画ライブラリで、Qt 画面に組み込める。RSSI、成功率、heap、RTT histogram/CDF の interactive 表示に採る。表示対象を選択した最大8系列、各系列の画面上の点数を約2,000点へ min/max downsample し、raw sample は記録に残す。[公式](https://www.pyqtgraph.org/)
- Matplotlib は共有用の静的 PNG/SVG/PDF export の任意依存に限定する。QtCharts、QtWebEngine、巨大な browser runtime は初期配布へ追加しない。
- 初期表示目標は **100 nodes/400 directed edges、20 fps、操作応答 p95<100 ms**。これはネットワーク sample が20 Hzで届くという意味ではない。1000 node や数万 edge は対象外。性能は各 OS の固定 benchmark fixture で測る。

### 3.3 パッケージとバージョン

初期 baseline は Python 3.12、PySide6/pyqtgraph/NumPy/pyserial/esptool の互換版を lockfile で固定する。初期サポート対象を macOS14以降（arm64/x86_64）、Windows11（x86_64）、Ubuntu24.04（x86_64）とし、それぞれ CI＋実機 USB 試験を行う。他 Linux distribution は runtime/udev 要件を文書化し、検証済み環境を区別する。

一般配布は PyInstaller **onedir** を基準に、macOS `.app`、Windows の実行 directory/installer、Linux の tar bundle を作る。daemon/CLI も同じ platform/arch の署名・hash 検証済み binary を同梱する。Python、Rust、IDF の導入は不要。利用者が起動する入口は一つだが、内部の Qt library や Rust binary は分離して管理する。PyInstaller は OS をまたぐ単一 build 手段ではないので、各 OS の runner で作る。[PyInstaller usage](https://pyinstaller.org/en/stable/usage.html)

開発者には予定 package 名 `routeloom-meshviz` の wheel を提供する。`pip install routeloom-meshviz` でも対応 platform の companion binary package または明示的な初回取得で host を揃え、`cargo install` を暗黙実行しない。firmware bundle は別 version、offline 同梱版も出す。GUI/host/firmware の capability 照合に失敗したら、対応済みの機能だけ開く。

release では macOS codesign/notarization、Windows signing、依存 SBOM と license notice、Qt library の差替え可能性等を確認する。LGPL 対象 library を不可分な独自 container に隠す設計にせず、配布方式を条件に合わせる。PyInstaller 自身はアプリ配布を認める exception を持つが、Qt 等の条件を代替しない。[Qt for Python licenses](https://doc.qt.io/qtforpython-6/licenses.html)、[PyInstaller license](https://pyinstaller.org/en/stable/license.html)

esptoolはGPL-2.0-or-laterである。Python APIをimportするflash workerは、GUI本体とは別の小さな実行packageとしてbuild・同梱し、GPLv3条件で対応source/build手順・licenseを配布する方針にする。GUIとの間は汎用のbounded JSON command/resultだけとし、GUI processはesptoolを直接importしない。GUI本体と共通の非esptoolデータ層はrepositoryのApache-2.0を維持し、releaseのSBOMで配布単位ごとの条件を確認する。[esptoolのSPDX表記](https://raw.githubusercontent.com/espressif/esptool/master/esptool/__init__.py)

## 4. アプリ構成、データ、記録、画面

### 4.1 モジュールと境界

予定配置は `tools/meshviz/`。Python import package を `routeloom_meshviz` とする。

```text
routeloom_meshviz/
  app.py                     # DI、起動、設定、終了処理
  domain/                    # Qt/serialに依存しない型・reducer・指標
    board.py scope.py topology.py observations.py experiments.py
  services/
    board_manager.py         # 検出、identity、PortLease、状態機械
    firmware_catalog.py      # bundle署名/hash、選択、互換検査
    provisioning.py          # 設定/provision/Member wizardの状態機械
    authority.py             # Site/ACL/decision/cutover進捗
    observation_scheduler.py # 全sourceを横断する負荷予算
    experiment_runner.py     # 試験計画と実行、送信ledger
  transport/
    api1_codec.py client.py daemon.py
    serial_console.py        # 保守/OBS1/log adapter
    source.py                # LiveSource/ReplaySource共通interface
  workers/
    flash_worker.py build_worker.py crypto_tool_worker.py # flashは別packageのlauncher
  storage/
    recorder.py reader.py schema.py export.py checkpoints.py
  ui/
    shell.py boards.py setup.py topology.py quality.py
    membership.py trials.py playback.py
  resources/ schemas/        # icon、翻訳、JSON schema
```

`domain` は dataclass、enum、pure reducer、clock interface だけを持ち、Qt/USB/SQLite を import しない。各 adapter が元 API を `ObservationEnvelope` に正規化する。GUI widget が API JSON を直接編集したり、試験用の送信ループを所有したりしない。board の操作履歴、site mutation、test plan も command/result event として reducer に流す。

`ObservationSource` は `start/stop/subscribe/request_snapshot` と sample/event callback を持つ。`ReplaySource` の `execute_command` は常に拒否し、記録された flash/provision/send event を再生しても外部へ送信しない。Live と Replay を同じ `StateStore`/view model へ接続する。

### 4.2 thread・非同期・終了

- **GUI main thread**：全 widget/graphics item と view model。20 Hz timer で pending diff を描画し、1 update ごとの repaint を避ける。
- **I/O QThread 1本**：その thread 内で `QLocalSocket`、QTimer、API1 parser を作る。非同期 readyRead/bytesWritten、request id 対応、timeout、reconnect を所有する。blocking socket/read/wait を GUI thread で呼ばない。初期版では asyncio/qasync と Qt event loop の二重管理を導入しない。
- **model/record worker**：受信 envelope の順序付け、reducer、SQLite writer を所有する。GUI へ immutable diff/snapshot を queued signal で渡す。SQLite connection を thread 間共有しない。重い layout/export は別 worker に渡す。
- **process worker**：esptool、IDF build、CLI 鍵 tooling。標準出力は bounded structured progress に変換する。各 port は1 workerだけ。GIL や長い C extension call に GUI を巻き込まない。worker の argv、env、stdin は固定構造とし、shell string 組立てをしない。
- data queue は初期8 MiBまたは10,000 envelopes。表示 queue は同一 key の値を coalesce できるが、記録 queue は通常は全件を保存する。過負荷で落とす場合は source ごとの sequence 範囲と件数を GapEvent にする。terminal operation と authority 操作結果用の reserve queue を別に持つ。reserve も尽きたら試験の新規送信を停止する。
- disk full/書込み失敗では「記録停止」を明示し、記録必須の試験を停止する。生きている風の recorder icon を残さない。data capture の失敗と RF loss を区別する。
- 終了は新規試験受付停止→新規送信停止→未決着操作を ledger に保存→recorder flush/checkpoint→subscription解除→所有daemon停止→lease解放。既に gateway が受理した packet を GUI 終了で取り消せるとはしない。

### 4.3 データモデル

全 ID は hex/string とし、JSON や CSV で64 bit整数の精度を失わない。測定値は単位を field 名に含める。既存telemetryの `observer_boot=0` は未設定であり、既知のbootとしてcounterを差分集計しない（`components/routeloom/include/routeloom/node.hpp:85`）。

| 型・主キー | 主なフィールドと規則 |
|---|---|
| `Board(board_uuid)` | verified chip/revision/base_mac/sta_mac、USB serial/location/current ports、flash bytes、役割、bundle/config digest、NodeId、provision fingerprint、状態。port path は identity ではない |
| `Scope(scope_uuid)` | security profile、site_id、site_epoch、wire_network_low32、gateway set、channel/radio epoch、開始/終了時刻。同じ低32 bitでも別site/epochなら別scope |
| `Node(scope_uuid,node_id)` | 任意board参照、label、role/profile、authority_state、device_applied_state、reachability、last_seen、current_boot?。不明は Unknown。NodeId重複の別MACは conflict |
| `NodeIncarnation(scope,node,observer_boot)` | firmware/config digest、reset reason、uptime base、power state。再起動前後の値を連結しない |
| `LinkObservation(scope,observer,boot,peer,binding,radio,channel_epoch)` | phase/lease、RSSI、cost、quality、source、age/validity。directionごとの有向観測。旧USBNodeStatusでbinding等不明なら nullable＋source_sessionを使い、詳細snapshotとは別系列 |
| `RouteObservation(scope,observer,boot,destination,revision)` | next_hop、route generation/sequence/metric/lifetime、valid、sample時刻、source。選択中routeのみ初期対応。履歴は削除せずeventへ |
| `MetricSample(series_key,sequence)` | `t_host_mono_ns,t_host_unix_ns,t_node_ms?,received_at,unit,value?,raw_count?,validity,provenance,saturation`。counterかgaugeかをschemaで指定 |
| `Event(capture_id,seq)` | kind、source、source_seq、source_epoch、scope、各clock、payload、evidence。snapshot、change、gap、clock adjustment、manual markerを含む |
| `Trial(run_uuid)` | immutable plan、targets、payload生成seed/hash、count/interval/length、delivery/TTL/hops、観測budget、version/config、状態、start/end、停止理由 |
| `TrialMessage(run_uuid,index)` | idempotency key、operation id、message key、planned/submit/admitted/terminal/echo時刻、各結果、reason、late/duplicate、観測欠落。再接続時も同じindex/keyを使う |
| `GroupResult(run,index)` | group、期待member集合のsnapshot/revision、delivered/nonmember/missing/unaccounted/truncated、settled clock。期待member不明なら分母は不明 |

state reducer の不変条件：old boot/source epoch の event で現在値を巻き戻さない、同一 source_seq を二重適用しない、削除は complete snapshot または明示的 removal による、partial snapshot の欠落で node を消さない、route 未取得と NO_ROUTE を区別する、membership と connectivity を別々に更新する。

route chain の導出は全区間の scope が同じで、各 sample が設定 freshness 内、最古/最新 sample 差も許容値以内のときだけ行う。結果に利用 revision と `evidence:"derived_snapshot"` を付ける。cycle は表示して探索を止め、100 node を超える探索や再帰を無制限に行わない。

### 4.4 clock と遅延

capture 内の順序は recorder の連番、再生時間は host monotonic ns に固定する。UTC は比較・人間向け表示に使う。PC 時刻が NTP/手動変更で飛んだら、`ClockAdjustment` を入れて monotonic–UTC 対応を segment 化する。daemon の wall clock しかない値には `clock:"host_unix_ms"` を保持する。

node uptime/monotonic は node boot ごとの時計である。異なる board の `sampled_at_ms` を直接引き算しない。USB 往復の時刻範囲を使った推定 offset は uncertainty 付きの補助値とし、同期精度が確認できるまで片道遅延を表示しない。telemetry の sampled_at は寄与 sample の古い時刻を指すため、snapshot取得時刻として扱わない。

### 4.5 記録形式と容量

primary は **directory形式の `.rlcapture/`＋SQLite**。小さな JSONL/CSV export を標準提供する。SQLite は索引・seek・crash recovery に使い、独自 binary archive を必須にしない。

```text
2026-09-26-lab-a.rlcapture/
  manifest.json              # schema_version=1、capture_id、versions、scope一覧
  data.sqlite                # canonical events/samples/trials/checkpoints
  attachments/
    board-inventory.json     # public identity、bundle/config digest
    plans/run-<uuid>.json
    logs/<board>-0001.log    # opt-in、rotate、secret redaction済み
  exports/                   # 利用者が明示exportしたCSV/JSONL
  checksums.json             # close時のfile digest、closed/unclean状態
```

SQLite `user_version=1`。tables は `events(seq INTEGER PRIMARY KEY,t_mono_ns,t_unix_ns,source,source_epoch,source_seq,kind,scope,payload_json)`、`metric_samples`（時刻/series索引）、`trial_runs`、`trial_messages`、`checkpoints(seq,t_mono_ns,state_json)`、`metadata` とする。canonical event stream には sample も載せ、metric table は再構築できる索引とする。JSON は型ごとの `schema_version` を持つ。未知 additive field は保持、新 major は読取不可を明示する。migration は元ファイルを直接改変せず新 capture へ行う。

write は WAL、single writer、最大1秒または1000件の batch transaction。terminal/authority結果の重要な境界では早期commitする。30秒ごとまたは5000 eventsで checkpoint を作る。障害後は最後にcommitした位置から読み、切れた末尾と計画上の未決着送信を UncleanEnd にする。最大約1秒の未commit記録が失われ得ることをmanifestへ記載する。稼働中DBを共有copyせず、close後checkpointまたはSQLite backupで保存する。

容量の設計例（概算、実測値で置換する）：

- 正規化 JSON envelope が平均400 B、SQLite索引等込み約800 B/件なら **10件/秒で約29 MB/時**、50件/秒で約144 MB/時、100件/秒で約288 MB/時。
- 100 node health を10秒ごと＋400 linkを30秒ごとに USB 等で取る場合は約23件/秒＋eventsで概ね70–100 MB/時。無線でこの頻度を達成できるという意味ではない。
- 100 node/400 edge の checkpoint を150 KiBと仮定すると30秒ごとで約18 MB/時。checkpointの実測sizeを監視し、巨大な全履歴を入れない。
- raw serial log は2 KiB/秒/台でも約7.4 MB/時/台となるため opt-in、台ごとのrate/size表示とrotateを設ける。payloadは既定で長さ/hashのみ、保存は選択式。鍵・PoP中の秘密情報・API認証材料は保存しない。

capture前に見積もり、空き容量、上限（初期2 GiBまたは残空き10%）を表示する。上限に達したら次volumeへrotateするか記録必須試験を停止する。利用者の過去captureを自動削除しない。

export は `events.jsonl`、`nodes.csv`、`links.csv`、`routes.csv`、`samples.csv`、`trial_messages.csv`、`trial_summary.json`。UTF-8、UTC ISO8601＋monotonic列、hex ID、明示単位、nullable値、source/evidence/gap列を持たせる。巨大なnested JSONをCSVの一セルだけへ詰めない。pandasの`read_csv/read_json(lines=True)`で読める。浮動小数点の表示丸めをraw exportへ適用しない。

### 4.6 再生・比較

0.1/0.5/1/2/10倍、pause、単一event step、任意時刻seek、marker jumpを用意する。seek は直前 checkpoint＋以降の event を reducer に適用し、描画は最後に一括更新する。paused 時は virtual clock も止め、freshness が現実時間で勝手に古くならない。

比較は最大2 captureを左右表示し、実験開始marker、故障marker、絶対UTCのいずれかで軸を合わせる。比較対象のversion/config/profile/channel/payload/負荷/観測budgetの差を表示する。同じNodeIdでも別board/siteなら自動同一視せず、明示 mapping を保存する。欠測を補間して成功率を良く見せない。再生結果と同じCSVから算出した集計が一致することを受入条件とする。

### 4.7 主要画面

常時ヘッダに **LIVE/REPLAY、site/profile、gateway/USB状態、記録状態、観測gap/age、試験状態**を置く。色だけに依存せず文字・icon・線種を併用する。

**ボードと構築 wizard**

```text
[プロジェクト: lab-a] [DevRam ▼] [firmware: release/digest] [記録 ●]
 接続 → 役割 → image → 書込み → 設定/provision → 起動/参加
┌USB/場所──chip──MAC末尾──flash──役割──NodeId──profile──状態────┐
│port A    C3    ..42     4MB   bridge   01     DevRam   Ready   │
│port B    C6    ..73     4MB   reference02     DevRam   Verify  │
└──────────────────────────────────────────────────────────────┘
[全台の検査] [選択台を書込み] [次の台から中止]
右: 選択機器の識別根拠、bundle、書込み領域、個別設定、進捗/再試行
下: 各台の結果。失敗した台だけ再実行できる。
```

**トポロジと品質**

```text
[LIVE] gateway 01 authenticated | local最新0.2s / remote最古18s
[物理link] [宛先への経路] [gateway tree] [参加状態] [時刻追跡]
┌node一覧/filter──┬network図────────────────┬選択: observer02→peer03─┐
│01 gateway       │01 ──→02 - - → [04宛]     │phase Reachable age 2s  │
│02 Member        │  └──03                   │RX RSSI 03→02: -67     │
│03 承認待ち      │実線=観測link             │binding/boot/source     │
│04 未観測区間あり│破線=論理route/unknown区間 │[詳細取得] [送信試験]    │
└────────────────┴──────────────────────────┴────────────────────────┘
[RSSI時系列] [SDK retry/hop timeout] [heap] [配送reason分布]
時系列にはgap・boot・channel/scope切替marker。下部にevent timeline。
```

**参加管理**：左に discovered/要求待ち/member/revoked の一覧、中央に device fingerprint・NodeId・requested scope・最終試行、右に allow/pending/deny と台帳/適用状態。除外・cutover は対象、世代、変更内容、進行条件をまとめた実行画面に遷移し、進捗は同じ operation id を追う。

**試験**：宛先(unicast/group)、回数、間隔、payload長/seed、delivery、TTL/hop limit、停止条件、観測budgetの入力。開始前に admission見積もり・所要時間・対象capabilityを表示。実行中は planned/submitted/admitted/settled/unknownを別counter、RTT分布、実効rate、停止理由を表示する。

**再生**：上部にcapture A/Bとversion差、中央に同じnetwork/quality view、下部にseekbar・速度・marker・export。REPLAY中の書込み、承認、送信は操作可能にしない。

## 5. 実験機能と指標

### 5.1 共通実行手順

試験は `Draft → Validated → Armed → Running → Draining → Completed/Aborted/Incomplete`。plan を保存してから送信する。

1. capability、対象profile/scope、USB認証、route状態、payload/TTL/hops、group設定、記録容量、admission残容量を検証する。未到達を試すシナリオなら、その意図をplanに残す。
2. baseline snapshotと設定digestを保存し、必要な受信subscriptionを**送信前**に開始する。結果を受け取れない権限状態ではecho試験を始めない。
3. unicastは `operations.open_epoch` を一度実行。各indexの128 bit idempotency keyを事前生成し、送信前にledgerへcommitする。API応答が切れた場合は `operations.get_by_key` で照合し、同じindexを新しいkeyで二重送信しない。
4. monotonic clock の `t0 + index×interval` でpacingする。処理が遅れたら遅延を記録して次回をずらすかplanned_skipとし、遅れを取り戻す大量burstを行わない。
5. admission、gateway受理、terminal、echoを独立追跡する。停止操作は新規投入を止め、まだ取消可能なhost queueだけ `operations.cancel`。既にdispatch済みの結果はdeadlineまでdrainする。
6. 終了時にlate結果用の観測猶予を持ち、最終snapshot/summaryを保存する。GUI/daemon再起動で結果が決まらないoperationはunknownのまま残す。再開操作は旧runの結果回収と新run開始を区別する。

### 5.2 提供する試験

| 試験 | 手順・パラメータ | 得られる結果／前提 |
|---|---|---|
| 接続・配送確認 | 任意NodeId、回数、間隔、0..128 B、RELIABLE/BEST_EFFORT、TTL、hop_limit | 現API1から開始可能。RELIABLEのSDK受領とhost admissionを別集計。reason詳細は拡張後 |
| Ping / echo | bench対応referenceへ32..128 B、連番、固定seed、echo timeout | hostから見た往復時間。無応答だけでは送信方向/返送方向/USBのどこで失われたか確定しない |
| 有限burst / throughput | payload32/64/128 B、1/2/4/8 pps等の段階、各段の有限count、cooldown、最大inflight | bench admission profileとcapacity検査が前提。requested/achieved rate、receiver goodput、reason分布。既存SDKの無制限最大速度は保証しない |
| group配送 | groupまたはALL、0..127 B、回数/間隔、ordered、TTL/hops | `group.send/get`、delivered/nonmember/missing/unaccountedとsettle時間。正常試験はNORMALまたはBULK、同時未決着1を既定 |
| 経路切替・復旧 | baseline→中継ノード電源断等のmarker→一定間隔probe→復帰 | route切替の観測時間、配送再開時間、欠測区間。USB抜線だけでRF電源断にならないboardでは操作を区別 |
| 加入・除外・cutover | 未参加→allow/deny→確認、revoke→配布/適用、epoch切替 | control operationの受付/ledger/機器反映時間、unknown数、除外後の通信結果。crypto適用とUI色変化を同一指標にしない |
| deep sleep | sleep profileのreferenceで起床→送信→drain→sleep→復帰を繰返す | wake reason、boot/incarnation、復帰/再参加時間、配送成功率。電流/消費電力は外部計測器なしでは測定対象外 |
| 安定性 | 有限durationの低頻度送信＋health、reset/watchdog/heap監視 | healthのmin/最大free block、reset回数、sessionやqueueの推移。観測自体の負荷も記録 |

通信源は初期版では **bridge/gateway**。宛先は任意 node/group。任意のreferenceを送信元にする試験は、別途 bounded remote experiment service が必要であり初期版に暗黙追加しない。複数台の送信元を用いる負荷試験は後続拡張とする。

### 5.3 最小の bench endpoint

現referenceの `LogObserver::on_message` は受信をlogするだけでechoしない（`firmware/reference_node/main/main.cpp:99`）。以下を lab firmware の opt-in機能として追加する。

- application payload header32 B：magic4、version1、opcode1、flags2、run_uuid16、sequence4、body_crc32 4。残りは指定seedから生成したbody。payload長の指定は**header込み**。32 B未満は配送確認のみで、pingには使わない。
- opcodeは `ECHO_REQUEST/ECHO_REPLY/COUNT_ONLY`。requestを受けたreferenceは許可origin/scope、magic/version、長さ/CRCを検査する。replyを再echoしない。通常アプリの任意payloadに反射応答しない。
- `on_message` 内から MeshNode.send を再入呼出しせず、最大4件のreply queueに入れ、owner loopから送る。queue fullはcounterに記録する。
- replyはrequestのrun/seqを保持してoriginへunicastする。bridge `DataFromMesh`→daemon ReceiveLog→`messages.subscribe`で回収できる（`components/routeloom/src/usb_bridge.cpp:2370`、`host/routeloom-host/src/main.rs:993`）。Memberのscope/receive attribution修正も満たすこと。
- COUNT_ONLYでは毎packetのechoを省き、runごとのunique count/bytes、duplicates、first/last node time、受信bitmapを記録する。初期64 sequence/run、同時2run、保持期限をplan duration+TTL+30秒までの上限付きとする。上限を越えたcountは受理前に拒否する。
- 読出しは `health.get section:"experiment", run_id` の追加section、またはUSB `OBS1`。1結果128 B以内、分割が必要ならpage化する。物理受信とSDK/application callback到達は同一ではないので、このcounterは「bench application受信」と表示する。
- groupの全receiverに一斉echoさせない。通常は既存group集計、必要時だけ各receiver counterを終了後に順番に取得する。

### 5.4 指標の定義

| 指標 | 定義・分母 |
|---|---|
| admission成功率 | `accepted_by_host / unique_submission_attempts`。RATE_LIMITED、NO_CAPACITY、入力拒否は別分類。transport切断で受付不明はunknown |
| SDK配送成功率 | RELIABLEで `END_SDK_RECEIVED / host_admitted`。未決着/観測不明を除いて成功率を上げない。`success/admitted`〜`(success+unknown)/admitted` の範囲も表示 |
| app echo成功率 | validな最初のechoを受けたunique index / pingとしてhost受理されたindex。duplicate/late/CRC不一致を別count |
| group成功 | fully deliveredなgroup operation率と、member単位のcoverageを別表示。missing listの長さをmissing_totalの代わりにしない。期待membershipが不明ならcoverage分母はnull |
| MAC callback失敗割合 | 有効counter差分の `Δtx_mac_fail / (Δtx_mac_success+Δtx_mac_fail)`。`tx_unknown`、callback未決着も併記。「RF packet loss」と断定しない |
| hop timeout割合 | `Δhop_timeouts / (Δhop_accepts+Δhop_timeouts)`。これは記録されたattempt outcome比率。end-to-end lossとは別 |
| SDK再送 | `Δsdk_retries` と `100×Δsdk_retries/Δtx_submitted`（100 driver submissions当たり）。hardware MAC retry回数は未取得 |
| latency | submit→host acceptance、host submit→terminal観測、bridge accepted→terminal（同boot clockがある場合）、host echo RTTを別系列にする |
| latency分布 | 個々の測定値のp50/p90/p95/p99、min/max、sample数。quantileは昇順sampleの1始まり `ceil(q×N)` 番目（nearest-rank）に固定。timeoutは打切り件数として別表示し、0や固定deadlineを通常sampleに混ぜない |
| offered load | 指定payload bytes×予定rateと、実際にhostへ投入できたbytes/time。header込み/アプリbodyだけの列を分ける |
| goodput | COUNT_ONLY receiverのunique body bytes / 定義した測定区間秒。初回～最終受信だけの区間は短い試験を過大評価し得るため、run開始～最終drainを主値、receiver局所区間を補助値にする。SDK receiptだけの場合は「SDK配送量推定」と表示 |
| 復旧時間 | fault marker→最初の再成功、および「3回連続成功の先頭」まで。probe間隔による検出幅を併記。route再選択時間とapp配送再開時間を別にする |
| 品質coverage | valid sample時間/観測対象時間、GapEvent数/範囲、unknown結果数。recording lossを無線損失へ算入しない |

counter差分はboot/binding/radio/channel/length class/directionが同じで、非飽和・非巻戻り・有効な両端sampleがある場合だけ計算する。分母0はnull。counterが戻ったらreset markerで新系列にする。`sample_age`が増えたままの古いRSSIを最新plotへ複製しない。

BEST_EFFORTのgateway受理やMAC成功はapp配信の証明ではない。RELIABLEのSDK受領もapplicationで処理済みという証明ではない。通常API1の`application_outcome=null`はそのまま保持する。

### 5.5 admission と throughput の範囲

現 host の制限は **2 admission calls/分、burst16、principal別＋全体共通**。`messages.submit`だけでなく`operations.open_epoch`、duplicate/CONFLICT再提出も消費する（`host/routeloom-host/src/send_store.rs:41`、`:695`）。初期MVPは30秒以上の間隔を標準にし、短い有限burstを選ぶ場合は残予算を確認する。`RATE_LIMITED.detail.retry_after_ms`に従い、無条件再試行やdaemon再起動によるbucketリセットを行わない。

高頻度試験PRでは、host起動時の明示的 **`--admission-profile bench-v1`** を追加する。通常profileは変更しない。初期上限を600 calls/分（10/秒）、burst8、GUI最大inflight4、run最大60秒/64送信の小さい方とする。rate/active/store残容量をAPI capability/statusに公開し、画面とcaptureに「実験profile」を残す。複数principal合計も同じ上限とする。これらは初期の有限測定上限であり、SDKの全容量を使い切る試験の保証値ではない。

hostはrecords4096、active32、principal active8、store32 MiB、保護期間24時間等を持つ（`send_store.rs:29`）。firmwareのdispatch windowは32、source delivery tableは8（`components/routeloom/include/routeloom/usb_host_ops.hpp:334`、`components/routeloom/include/routeloom/node.hpp:1137`）、group originは3（`components/routeloom/include/routeloom/node.hpp:111`）。完了済みを新規実験の都合で早期削除してidempotencyを弱めない。容量に達したら停止して結果を説明する。

さらにdedupはleaf32/relay96/gateway256、terminal pinは最大7/8、terminal保持はdeadline＋30秒（最大60秒）である（`components/routeloom/include/routeloom/node.hpp:604`、`:630`、`:648`）。10 ppsで長時間流せばterminal pinで制限され得る。新healthにはdedup resident/terminal pins/capacity/refused各counterを含め、plan validatorは対象・中継のprofileと既存occupancyからrun countを減らす。未知なら初回は最大16 packet、inflight1で開始する。64 packetを全構成の安全値にはしない。

段階試験の間はTTL＋30秒以上のcooldownを基準に、実際のpin解放とqueueを確認する。最高rateを上げる前にadmission拒否・BUSY・dedup圧迫を確認し、測れたのがRF限界か、host/table容量限界かを結果に書く。長時間の高throughput評価に向けたon-device generatorや別のbulk transportは後続の独立設計とする。

`group.send`は現行unicast token bucketの対象外だが、host queue/live数、firmware source table、group airtime bucketで制限される（`api1.rs:2245`、`components/routeloom/include/routeloom/node.hpp:96`）。この経路をunicast rate制限の抜け道として使わない。通常group試験でURGENTを選んでairtime gateを回避せず、airtime budgetを0にする機能も初期GUIに出さない。

## 6. 段階計画と PR ごとの受入条件

開発previewと一般利用者向けMVPを区別する。**compilerなしの初回構築、三OSの実機操作、一括書込み、低頻度試験、記録再生まで揃った時点**をMVPとする。C6やMemberの未完了項目を「GUIは対応」として隠さない。

| PR | 実装単位と主な依存 | 受入条件 |
|---|---|---|
| 01 | `tools/meshviz` のpackage、domain、capture schema、FakeClock、fake API1 server、fixtures | Qt/USBなしでevent→state→capture→replayが同じ結果。unknown/gap/boot/clock-jumpを扱う。まだ実機UIは不要 |
| 02 | device共通層、rig import、pyserial列挙、esptool worker、lease/書込み計画 | chip/MAC違い、hash/offset不正、保護状態不明でwrite呼出し0回。同型機再列挙と一括の部分失敗を正しく処理 |
| 03a | BoardConfig/rlcfg/rlkeys/setup console、host secret-file、generic DevRam field image、readonlyboot identity | 同じbinaryを異なるNodeIdで3台起動。割当て重複はGUIで拒否、MAC不一致はRF開始前に拒否。電断で最後のcommitへ戻る。app更新でrlsec/boot counterを保持 |
| 03b | reproducible build backend、署名bundle/catalog、CI artifact export、HIL script共通化 | IDF/Dockerなし・offline bundleで初回flashから起動まで完遂。sourcebuildはscratchのみ。security fuse変更を起こすbuild設定を拒否 |
| 04a | host/CLI/clientのserial/IPC/clock/CSPRNG abstraction、Linux/macOS CI | Linux既存API1 goldenと実機挙動を維持。macOSのUSB抜線・再列挙・認証・ACLを確認 |
| 04b | Windows Named Pipe/SID/ACL/private file、native binary packaging | Windows11でCLI/API1/GUIと実機bridgeが接続。異なるユーザー/remote pipe接続拒否。Unix DB移行fixtureと新規Windows storeを試験 |
| 05 | boards wizard、API1接続、gateway視点graph、低頻度unicast、record/replay/CSV | 1 bridge＋2 reference、C3/S3/C5の検証済みmatrixで、一人が接続→一括flash→構成→送信→保存→再生を完了。未取得hop/qualityはnull。三OS clean machineで配布物だけで実行 |
| 06 | C6 manifest/defaults/IDF/RAM/CIとHIL、bundle追加 | C6 bridge/reference、他3chipとのmulti-hop、reset/再列挙、後続Member/sleepの検証記録。条件を満たした機能だけcatalogで有効化 |
| 07a | `lab-site-init`、setup keygen/identity orchestration、runtime scope/USB security表示、Member bundle | pending-key reset、identity lock、MAC取り違えを扱う。既存site import、新規site作成、allow/deny→device confirmationがGUIで完結。鍵がcaptureへ入らない |
| 07b | revoke/GK/cutover UI、操作履歴・再接続復元 | isolated member、gateway不在、daemon再起動を含むrevoke/cutoverでledger/適用/unknownを区別。prepare/grace/epochを既存state machine通り表示 |
| 08 | 既存Telemetry codec、diagnostic lane、API1 `telemetry.get`、DevRam/Member opt-in | local/remote/RSSI-only/bucket、invalid/saturated/injected/boot変更のgolden。5秒deadline、全体poll budget、旧firmwareUnsupported。live RSSI/attempt指標を表示 |
| 09a | topology/health wire＋readonlycore/security-owner getter＋reference OBS1 | readonly照会でroute広告baselineを変えない。generation中断、page欠落、remote拒否、heap/reset/session/dedupを正しく取得。RAM増分とowner-loop時間を測定 |
| 09b | 全observer graph、gateway tree/derived hops、qualityとhealth timeline | 3-hop fixtureとroute loop/partial/asymmetryで誤った物理edgeを作らない。change通知の欠落が次snapshotで復旧。USB観測とremote負荷を表示 |
| 10 | HostOps delivery detail、daemon永続化/event、bench echo/counter | NO_ROUTE/HOP_ACCEPT_TIMEOUT/成功/期限/boot中断をoperationへ正しく対応。retire後も理由が残る。echo duplicate/late/USB gapの集計が一致 |
| 11 | bench admission profile、有限rate sweep、group試験、fault/sleepシナリオ | 通常2/分を維持。benchでもfinitecount、rate、active、dedup、store、group budgetを越えない。achieved rateと拒否を結果へ含める |
| 12 | release硬化、比較UI、performance、OS/chip/profile検証matrix、手順書 | 8時間captureでリーク/固まりなし。100node/400edge fixtureでUI目標、seek目標、CSV集計一致。四chip×三OSの必須組合せを結果付きで公開 |

PR05完了で三OS・C3/S3/C5のDevRam MVP、PR06でC6のDevRam MVP、PR07でMember手順、PR08–11で要求された詳細観測・実験を完成させる。PR12で四chip/Member/sleepを含めた配布認定を締める。全matrixの実機が揃わない場合は未検証欄を残し、完成扱いにしない。

**不足 API の間の代替：**

| 未完成項目 | 利用できる代替と限界 |
|---|---|
| generic runtime config | 開発者previewでKconfig個別build。一般利用者向けMVPの代替にはならない |
| Windows host | replay/fake serverのみ。WSLを必須の迂回路にせずnative移植を完了させる |
| 全node topology/hops | `nodes.list`のgateway視点、論理next-hop、direct hop1のみ。multi-hop数と未知edgeは空欄 |
| telemetry API1 | gatewayのRSSI、USB/serialで取得したlogを補助表示。consoleから推測した指標には`source:"log_inferred"`を付け、structured値と合算しない |
| health |起動logのreset/heap等が存在するbuildでversion別parser。見つからない値はnull。ログがないintervalを0heap/0sessionとしない |
| delivery reason | API1 dispatch state/evidenceの分布。legacydelivery/logのreasonは対応message keyが確認できた分だけ補助。全体の失敗理由分布とは称さない |
| echo | SDK receiptの成功率、hostで観測した完了時間。ping RTTというラベルは使わない |
| high-rate profile | 30秒間隔の低頻度試験・有限burst。未制限throughput測定ボタンは無効 |
| remote notify | bounded pull＋age表示。リアルタイム性は実際のsample間隔を明示 |

## 7. リポジトリ配置、HIL、試験、CI

### 7.1 置き場所と既存ツールの関係

実装時に次を追加する。今回の設計作成では追加していない。

```text
tools/meshviz/
  pyproject.toml
  src/routeloom_meshviz/
  tests/{unit,contract,integration,ui}/
  fixtures/                  # syntheticまたはsecret除去済み
  packaging/                 # PyInstaller spec/OSごとの資源
  README.md

tools/deviceops/              # flash/probe/bundle/port leaseの共通Python層
  ...                        # Qtをimportしない

tools/hil/                   # 既存entry pointを維持して共通層を呼ぶ
  flash.py rig.py ...
  build_image.sh             # 別checkoutからレビューして移植する場合
  provision_console.py

docs/design/meshviz/          # 本設計の将来の管理場所、API/schema/ADR
```

Python共通層を使うためにRust daemonからPythonを起動する構造にはしない。daemonのUSB protocol責務はRustのまま。HILは同じBoardConfig/bundle/port identity/結果schemaを使用し、headless CLIを保つ。GUI専用のflash/provisionロジックを別コピーにしない。`routeloom-idf-build` の個人環境依存wrapperは任意backendとし、repository内の再現可能なbuild/export契約を正式経路にする。

利用者データはOS標準app-data directory、firmware/cacheはcache directory、site keysはprivate directory、captureは利用者選択場所に保存する。repositoryの`tools/meshviz/`へ実験結果や秘密情報を既定保存しない。GUI固有コードのlicenseはrepositoryのApache-2.0方針に合わせ、外部libraryのnoticeを別途同梱する（`LICENSE:1`）。

### 7.2 GUI を除く重要な試験

- **protocol contract**：Rust/C++/Python共通fixtureでAPI1 JSONとDiagnostic/HostOps bytesを照合。unknown fields、長さ超過、fragmented line、reply順序逆転、timeout、UTF-8不正、old capabilityを検査する。
- **reducer/model**：同一event再送、boot/session/epoch切替、partial snapshot、route loop、asymmetric link、missing hop、protocol StaleとUI stale、member revokedなのにUSB接続中等を検査する。
- **計測**：counter saturation/wrap/identity変更、分母0、unknown、timeout打切り、group missing truncation、rate limit、clock jump、echo duplicate/lateを入力し期待集計と一致させる。
- **record/replay**：commit直前/直後のkill、disk full、最終行/DB中断、unknown schema、checkpoint seek、同時刻順序、再生中のsend禁止。live最終state、順次replay、任意seek後のstateのdigestを比較する。
- **board/flash**：fake ROM/serialでswapped MAC、誤chip、flash不足、partition重なり、保護状態、署名/hash不正、消失/再列挙、port lease衝突、batch部分失敗、setup後identity lockを試験する。禁止操作のfunctionが呼ばれないことをspyで確認する。
- **provision/Site**：PoP challenge不一致、keygen後reset、再identity、generation競合、decision timeout→next_attempt、revoke通知遅延、cutover waiting/recovery、restart後同operation復元。秘密のsentinel値がlog/captureへ出ないことを検査する。
- **観測負荷**：FakeClockで100node scheduleを流し、remote合計0.5/秒・burst1・outstanding1、cancel/backoff、UIを閉じたときの頻度低下を検証する。

単体試験はhardware不要。fake serverとfake serialを使うintegration testで、UIを起動せず一通りのwizard state machineを通す。実通信・boot/protection状態の判断はHILで補完する。

### 7.3 CI と実機試験

既存 portable C++17 core、Rust workspace、firmware RAM guardのジョブを維持し、GUI追加で毎回全firmware matrixが無条件に走る構造にはしない。

1. PRごと：Python lint/type/unit/contract、Linux/macOS/Windows fake IPC integration、Qt offscreen smoke（画面生成、snapshot反映、Replay操作不可）、Rust/C++の変更関連golden。初期Python3.12を必須、追加Python版は対応宣言と同時にmatrixへ入れる。
2. host移植PR：三OSでdaemon/CLI/clientをbuildし、Unix peer credentials/Windows Named Pipe SIDのintegration test。OS依存部分をLinuxのmockだけで合格にしない。
3. firmware変更PR：pinしたIDFで影響chip/profileをbuildし、offset/partition/security flags/capability/size/RAMを検査。定期/releaseでC3/S3/C5/C6×bridge/reference×対応security/power/setupのmatrixを実行する。
4. release：三OSの署名済み配布物を作り、Python/Rust/IDF未導入のclean環境で起動・replay・companion起動を試す。offline bundle、asset path、license/SBOM、hash/signatureを検証する。
5. HIL：明示的な専用rig/手動実行ジョブ。通常の未信頼PRから接続boardを書き換えたり、Siteの実鍵へアクセスしたりしない。共通fixtureの使い捨てlab siteでUSB再列挙、2台batch、3-hop route、Member、sleep、mixed-chipを検証する。
6. soak/performance：固定synthetic traceで100node/400edge、8時間相当を高速replayしメモリ増加を測る。実時間8時間のcaptureもrelease前に行う。初期目標はRAM512 MiB以内、UI p95<100 ms、1時間/100MB程度のcaptureでseek<2秒（基準machineを結果に記載）。値を外したらデータを落として見かけ上合格にせず、downsample/索引/queueを改善する。

releaseの検証表にはOS/arch、chip/board revision、USB接続方式、flash、firmware/IDF digest、profile、各試験結果を残す。C6やsleepの未確認項目をC3成功から外挿しない。

### 7.4 完成判定の実演シナリオ

利用者が配布物のみを入れたPCにboardを3台接続し、物理識別と役割割当て、事前build imageの一括書込み、個別設定、起動確認を行う。DevRamで通信を確認した後、別の実験設定でMemberのkeygen/identity、承認・拒否、除外・cutoverをGUIから実施する。途中で中継nodeの電源を切って戻し、routeと配送の変化を記録する。C6を少なくとも1台含める。sleep対応referenceの再起床も確認する。

記録を閉じ、USBを全て抜いた状態で再生し、同じ時点のgraph・参加状態・品質・試験summaryを再現する。CSV/JSONLを外部Pythonで読み、画面の成功数/unknown数/RTT集計と一致する。この実演を三OSで完了し、設定・追加API・配布手順・未取得値の説明まで含めて本依頼の完成とする。

# 実装状況とリリース条件

更新：2026-09-18。

## 現在の証拠

| 項目 | 状態 |
|---|---|
| 統合アーキテクチャ・無線・SDK契約 | 文書化済み。Wire v1 byte layout・type IDはCORE_FIXED_250向けに凍結（test cipher vector付き）。本番Security Profileは未凍結 |
| Portable C++ SDK core | **実装済み・host-tested**。GCC/Clang、ASan/UBSan、有限Queue、配送、dedup、receipt、Babel由来routing、C ABI |
| ESP-NOW / LR250 adapter | **実装済み・build-tested**。単一Radio Owner、固定channel、Peer、短いcallback queue、NVS counter/replay |
| ESP32 reference firmware | **C3/S3/C5でESP-IDF v6.0.3 build成功**。実機起動・RF通信は未試験 |
| Rust host service／CLI | **実装済み・host-tested**。fmt、Clippy `-D warnings`、unit test、release build成功。TUIは未実装 |
| 暗号Provider | PSA AES-GCM、HMAC導出、counter予約、replay windowを持つ開発PSK Providerを実装。本番Identity／EDHOC／RPKではなく未認定 |
| 経路制御 | feasibility、withdraw、SeqNoRequest、3hop／diamond repairをportable testで実装・確認。実RF、分断再結合、10hopは未認定 |
| 管理 | SingleAuthorityのportable基礎のみ。quorum／自動選挙／snapshotは未実装 |
| 電源管理 | 契約とcounter再開の基礎あり。Deep Sleep実機resumeは未実装・未試験 |
| Board/RF | 公式資料を整理。C3/S3/C5現物照合、HIL、到達距離、都市部干渉、電池寿命は未実施 |
| 高度機能 | LR500適応、自動channel移行、Mesh OTA、LoRa TX、service failoverは未実装 |
| ライセンス | 未選定。安定OSSリリースの阻止条件 |

現在の位置付けは**CORE_FIXED_250実装プロトタイプ**。コンパイル・host test成功を、実機通信・RF資格・production-readyの証拠にはしない。

## CIで継続確認するもの

- Portable core：GCC／Clang、Sanitizer ON/OFF、CTest。
- 文書・生成表・契約・negative mutation：Python検査群。
- Host：固定Rust toolchainでfmt、Clippy、test、release build。
- Firmware：固定ESP-IDF `v6.0.3`／commit `76f5dedd9950a3012fee8fb7d5586df21fc67802`でC3/S3/C5をbuildし、sizeとbinary artifactを保存。

これらはhost/build evidenceであり、HIL／RF evidenceではない。

## 該当機能の公開前に閉じる項目

- **G-WIRE**：Wire v1 byte layout・型番号・C++／Rust共通golden vector（test cipher）は凍結済み。本番crypto suite適用後のvector更新と残りの管理object・再送round・再起動caseはG-SECと併せて行う。
- **G-SEC**：機器Identity、Join、credential、必須suite、Entropy、鍵更新、失効、再起動を本番Profileとして独立レビューする。開発PSKを代用しない。
- **G-ROUTE**：portable実装を基準に、restart／GC／timer、分断再結合、複数origin、10hopをmodel testと実機で認定する。
- **G-CONTROL**：SingleAuthority台帳の永続化を実装し、HAでは選挙、log、snapshot、構成員変更、proofを別途認定する。
- **G-USB**：device側bridge、認証transcript、frame保護、累積credit、C++／Rust相互運用をHILで確認する。
- **G-POWER**：Deep Sleep前のdrain、RTC/NVS、wake原因、再初期化、counter安全性、battery-side energyを実機で確認する。
- **G-BOARD**：現物revision、電源、アンテナ、Pin、Flash/PSRAMを照合する。
- **G-RF**：C3/S3/C5の有向組合せでLR250、broadcast/unicast、callback欠落、Peer churn、干渉、Sleep復帰を認定する。
- **G-SYSTEM**：USB再接続、キュー不足、PC停止、長期運転、設定更新を試験する。
- **G-LICENSE**：本体ライセンス、依存物、NOTICE、コード流用方針を決める。

## 完成の表示方法

機能×board×profileごとに `documented / implemented / host-tested / build-tested / hardware-tested / qualified` を区別する。C3 build成功をC5のRF合格へ継承しない。`ESP_OK`やCI greenは空中のPHY実測ではない。

公開0.xでも認証・暗号を暗黙に無効化しない。現在の開発PSK firmwareは必ず`EXPERIMENTAL`として表示し、配備用credentialを持つ本番Profileとは分離する。

[実装案内](implementation/README.md)／[受入試験](spec/acceptance.md)／[実装プロファイル](spec/release-profiles.md)を参照。

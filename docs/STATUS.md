# 実装状況とリリース条件

更新：2026-09-23。

## 現在の証拠

| 項目 | 状態 |
|---|---|
| 統合アーキテクチャ・無線・SDK契約 | 文書化済み。Wire v2 byte layout・type IDはCORE_FIXED_250向けに凍結（test cipher vector付き。v1から32bit epoch／48bit counterへ改訂、#29）。本番Security Profileは未凍結 |
| Portable C++ SDK core | **実装済み・host-tested**。GCC/Clang、ASan/UBSan、有限Queue、配送、dedup、receipt、Babel由来routing、C ABI |
| ESP-NOW / LR250 adapter | **実装済み・build-tested**。単一Radio Owner、固定channel、Peer、短いcallback queue、NVS counter/replay。2台C3で実電波配送・END_RECEIPT往復を手動smoke確認。到達距離・干渉・長期・資格は未認定 |
| ESP32 reference firmware | **C3/S3/C5でESP-IDF v6.0.3 build成功**。bridge_nodeはC3実機起動・Rust daemonとの実USB sessionを確認。2台C3（bridge_node＋reference_node）で実ESP-NOW配送・END_RECEIPT往復を手動smoke確認（連続6送＋reset後再送）。HIL suite・マルチホップ・長期は未実施 |
| Rust host service／CLI／TUI | **実装済み・host-tested**。fmt、Clippy `-D warnings`、unit test、release build成功。daemonはUnix socket経由でSTATUS/SENDに加えADAPTER/NODES/DELIVERIES/EVENTS/AUTHORITY/AUTONOMYを返し、routeloom-tuiは同一JSONをpollする観測者（daemon切断時はbackoff再接続、有界event ring）。情報源の無いfieldは`unknown`表示。API1にpush型受信（`messages.subscribe`/`unsubscribe`/`subscriptions`、`messages`+`events`両stream、per-subscription staging・gap/overflow marker・heartbeat・≤15s long-poll・接続死亡で購読消滅、sdk-completion/05設計準拠）を実装・host試験済み。実C3 adapter経由のsession確立・配送観測・reset後自動再認証を手動smoke確認（HILではない） |
| USB／Serial transport | **Portable実装・host-tested**。COBS＋CRC-32/ISO-HDLC codec、streaming resync、HELLO→AUTH→ACTIVE→DRAINING session、EXPERIMENTALな開発profile認証（共有secret＋transcript結合MAC、方向別counter・replay拒否）、累積credit、MeshNode統合をC++ device bridgeとRust hostで実装。`protocol/usb-golden`共有vectorでbyte相互検証。加えて`firmware/bridge_node`（USB Serial/JTAG配線）をESP32-C3へ書込み、Rust daemonとの実USB serial上でHELLO→AUTH→ACTIVE session確立、sealed DataToMesh受理・delivery event・累積credit授受を確認済み（手動smoke、HIL suiteではない）。デバイスreset後の再接続でdaemonの初回Helloが起動中に失われ停滞する不具合を実機で発見し、writer threadのbounded Hello retry（1s cadence、Active到達まで）で修復。reset→自動再認証→配送完了まで実機確認。加えてdaemon側にセッション損失検知（stale-session echo・fatal error・tag desyncで即時再Hello）と無応答watchdog（3×keepalive無受信でin-place再ハンドシェイク）、adapter openのexponential backoff、`link.get` API（disconnected/reconnecting/attached＋lane登録状態の可視化）を実装・host試験済み。複数機・長期・本番Profileは未認定 |
| 暗号Provider | PSA AES-GCM、context（scope＋network＋sender＋receiver＋epoch）結合HMAC導出、耐電断counter予約（追い出し時はRAM checkpointで区間再開）、永続replay上限（RAM windowの前方に予約するaccepted ceiling、counter 65前進毎に1 commit）＋peer epoch floor（同epochのwindow消失は拒否・新epochで再開、破損recordはIntegrityError、commit失敗は受理巻戻し）を持つ開発PSK Providerを実装。replay規則はportable ReplayGuardとしてhost試験済み（ESP側NVS adapterはbuild check、実機未試験）。ピアごとのcounter/replay recordは専用NVS partition `rlsec`（通常64KiB／bridge 128KiB）に置き、起動時の旧epoch TX record掃除（証人`cmax`を先にcommit）と永続ピア数上限（通常64／gateway 128、超過した新規ピアは`PEER_STATE_CAPACITY`で拒否・計数）で有界化した（#37のP0緩和、portable coreで200ピアchurnをhost試験、NVS予算はCIで計算検査、実機未計測。RX floorは消さないため根本解決は本番profile、[sdk-v1/05 §9](design/sdk-v1/05-nvs-state-37.md)）。`SecurityProvider::security_profile()`で開発ProfileをEXPERIMENTALと表示し、Node起動診断とfirmware logで強制。アプリDATA/END_RECEIPTは常にend保護必須で、未保護frameは診断付き拒否（通常経路に平文DATAなし）。本番Identity／EDHOC／RPKではなく未認定 |
| 経路制御 | feasibility、withdraw、SeqNoRequest、generation／tombstone／hold-down、bounded seqno、3hop／diamond repairに加え、10hop配送、分断再結合、loop-freedomをportable model testで実装・確認。実RFでの認定は未実施 |
| 管理 | SingleAuthorityの2スロット耐電断台帳（magic/length/schema/seal、hash chain、CRC-32/ISO-HDLC、readback検証、全損時QUARANTINED＋明示recover）をportable実装・host power-cut試験済み。NVS LedgerStorage adapterはbuild-tested。quorum／自動選挙／snapshot／remote config本体は未実装 |
| 電源管理 | Portable PowerCoordinator（RUNNING→DRAINING→PERSISTING→READY_TO_SLEEP→SLEEPING→RESUMINGの明示state machine、SleepTicket無効化、2スロットCRC電源image、durable pending復元、TIME_UNCERTAIN規則、bounded resume＋discovery fallback）を実装・host model試験済み。ESP-NOW PowerPort／NVS image／reference firmwareのdeep-sleep経路は`ROUTELOOM_DEEP_SLEEP`選択時のみ配線・build-tested。ESP-NOW bounded discoveryは現状UNSUPPORTED。実機resume、消費電流、wake timing、RTC経過計測は未試験 |
| Board/RF | 公式資料を整理。2台C3で実ESP-NOW配送（約57ms・連続6送成功）を手動smoke確認。S3/C5現物照合、HIL、到達距離、都市部干渉、マルチホップ、電池寿命は未実施 |
| 高度機能 | LR500適応、Mesh OTA、LoRa TX、service failoverは未実装。自律mesh（issue #3〜#5：RLD1発見・輻輳backpressure・負荷対応経路・channel移行基盤）はEXPERIMENTALなportable実装＋ESP-NOW配線がこのbranch上にあり、host test／firmware build check済み。輻輳→経路結合の安全装置（refusal-pressure floor・非対称slew・dirty-window provenance gate・peer identity reset・sojourn EWMA window decay・ROUTE_REFRESH_BOUND_EXCEEDED診断）を実装し`sdk-completion/03-congestion-routing.md`のチェックリストをhost test済み。加えて`EspNowScopeProvider`（Kconfig選択の開発scope key、ScopeMode指定・世代ring・opaque ScopeRef）を両firmware mainへ配線し、default/scoped両構成でbuild確認済み。既定OFF・migrationはObserve初期モードで、AutoGuardedは説明可能なprecondition gateを全通過した要求のみ明示opt-in。実機・RF・HIL・本番security認定は未実施 |
| 配送保証 | `DeliveryClass::Applied`（design sdk-completion/01）を実装：END_RECEIPTはSDK受理証跡のみで、アプリ判定はend保護経路のAppResult=19フレーム（RESULT/QUERY/RESULT_ACK/STATUS、request digest＋lease＋message identity＋destination結合）で返る。RESULT未到達はDelivered/FailedではなくIndeterminateへ解決。dedup保持（design 02）はLive/Resolved/Evidence/Terminalの位相別eviction順位＋terminal reserve＋per-upstream cap＋飽和counter（DedupStats）でexactly-onceを弱めず圧力を正直にBUSY化。保持は役割別（#39）：中継の転送記録はframe自身の残期限＋5秒、終端pinはorigin期限＋late result30秒（初回受理から最大60秒）。容量はbuild時のresource profile定数（leaf32／relay96／gateway256、既定relay）。3台line・2源×1.5msg/s×120秒で拒否・eviction 0、60秒超sleepの永続pendingはEXPIREDで再送しないことをhost試験。いずれもhost model試験済み、実機未試験 |
| 認証・credential | 本番provisioning lifecycle（design sdk-completion/04）のportable codecを実装・host試験済み：RLT1 dual-slot trust store（anchor・authority key・失効record・epoch/generation floor・quarantine＋明示recover）、RLC1 device credential、RTM1 COSE署名manifest、TrustView（store-backed ConfigPermitVerifier：Active鍵解決＋generation floor＋失効照合、quarantine時fail-closed）。Host側`routeloom-provision`クレート（RLT1/RLC1 image生成・RTM1署名・offline verify・NVS blob生成・RootSigner seam）と`routeloomctl provision-*` verbsを実装・golden vector byte一致試験済み。ESP-NOW側はNVS trust/credential adapter（dual-slot NVS persistence）とKconfig opt-inのproduction TrustView verifier配線（defaultはdev-PSK、production有効時はdev envelopeを受けないfail-closed）までbuild-tested。maintenance console・パーティション変更・製造flow・実機鍵配備は未実施。開発PSK/HMACは別経路として存続 |
| ライセンス | Apache-2.0選定済み（LICENSE・NOTICE・SECURITY.md・release pipelineを整備）。依存物の帰属はNOTICEとrelease SBOMに記載 |

現在の位置付けは**CORE_FIXED_250実装プロトタイプ**。コンパイル・host test成功を、実機通信・RF資格・production-readyの証拠にはしない。

## CIで継続確認するもの

- Portable core：GCC／Clang、Sanitizer ON/OFF、CTest。routing 10hop／分断再結合、ledger電断、power model、hardening、USB codec/sessionに加え、autonomy codec+golden vector、neighbor discovery、congestion scheduler/BUSY、channel-plan coordinator、migration engine+wire、load-aware routing、bounded peer state（#37）を含むportable test 35 target＋fuzz corpus replay 7件（ctest計42件）を実行し、ctest reportをartifact保存。
- Wire golden vector：C++ `routeloom_golden_tests`とRust `routeloom-wire` testが同一`protocol/golden`（valid＋invalid）を共有し、generator再生成後の`git diff --exit-code`でbyte一致を確認。USBは`routeloom_usb_tests`と`routeloom-protocol`の`usb_golden`が`protocol/usb-golden`を共有。
- 文書・生成表・契約・negative mutation：Python検査群。`rlsec`のNVS entry予算（`tools/nvs_budget.py`）もここで各firmwareの`partitions.csv`に対して計算検査する。
- Host：固定Rust toolchainでfmt、Clippy、test、release build。host binary（daemon／CLI／TUI）をartifact保存。
- Firmware：固定ESP-IDF `v6.0.3`／commit `76f5dedd9950a3012fee8fb7d5586df21fc67802`でC3/S3/C5をbuildし、sizeとbinary artifactを保存。bridge_node×C3にEXPERIMENTALなdiscovery有効＋migration Observe構成を追加（compile coverageのみ、RF検証ではない）。

これらはhost/build evidenceであり、HIL／RF evidenceではない。

## 該当機能の公開前に閉じる項目

- **G-WIRE**：Wire v2 byte layout・型番号・C++／Rust共通golden vector（test cipher）は凍結済み。本番crypto suite適用後のvector更新と残りの管理object・再送round・再起動caseはG-SECと併せて行う。
- **G-SEC**：機器Identity、Join、credential、必須suite、Entropy、鍵更新、失効、再起動を本番Profileとして独立レビューする。開発PSKを代用しない。
- **G-ROUTE**：portable実装を基準に、restart／GC／timer、分断再結合、複数origin、10hopをmodel testと実機で認定する。
- **G-CONTROL**：SingleAuthorityの耐電断台帳は実装・host試験済みで、membership承認／失効／remote config向けの操作型integration pointを持つ。NVS実機・HIL、およびHAの選挙、log、snapshot、構成員変更、proofは別途認定する。
- **G-USB**：device側bridge、認証transcript、frame保護、累積creditはportable実装済みで、C++／Rust共有golden vectorでhost相互検証済み。実USB driver・HILでの確認、および本番Profile認証（G-SEC）が残る。
- **G-POWER**：coordinator state machine、SleepTicket、電源image永続化、counter非後退、TIME_UNCERTAIN規則はportable実装・host model試験済み。ESP-NOW bounded discovery、実機でのdrain、RTC/NVS、wake原因、再初期化、counter安全性、battery-side energy確認が残る。
- **G-BOARD**：現物revision、電源、アンテナ、Pin、Flash/PSRAMを照合する。
- **G-RF**：C3/S3/C5の有向組合せでLR250、broadcast/unicast、callback欠落、Peer churn、干渉、Sleep復帰を認定する。
- **G-SYSTEM**：USB再接続、キュー不足、PC停止、長期運転、設定更新を試験する。
- **G-LICENSE**：Apache-2.0・NOTICE・SBOMを整備済み。残る判断はコード流用方針の運用確認のみ。

## 完成の表示方法

機能×board×profileごとに `documented / implemented / host-tested / build-tested / hardware-tested / qualified` を区別する。C3 build成功をC5のRF合格へ継承しない。`ESP_OK`やCI greenは空中のPHY実測ではない。

公開0.xでも認証・暗号を暗黙に無効化しない。現在の開発PSK firmwareは必ず`EXPERIMENTAL`として表示し、配備用credentialを持つ本番Profileとは分離する。

[実装案内](implementation/README.md)／[受入試験](spec/acceptance.md)／[実装プロファイル](spec/release-profiles.md)を参照。

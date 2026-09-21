# 6. 受入・失敗注入・証拠

## 6.1 設計と実装の検査を分ける

[cases.json](cases.json)の46件は**partially_executed**（P6時点）。39件はportable/host試験で実コードを通して実行済みで、各caseの`status:"portable_passed"`と`evidence`が実行した試験fileを指す（例：S01–S11は`tests/cpp/test_scope.cpp`、C01–C14は`tests/cpp/test_config.cpp`、Gatewayは`tests/cpp/test_gateway.cpp`＋`tests/cpp/test_host_ops.cpp`＋`host/routeloom-host/src/{api1,dispatch}.rs`、I02は同一golden corpusを`tests/cpp/test_endpoint.cpp`と`host/routeloom-wire/tests/endpoint.rs`で実行）。7件（S12・G09・G12・I03・I06・I07・I08）は実機・電源・PTY/CI・配布docsの証拠待ちで`planned_not_run`のまま。今回のcheckerは登録値・数式・バイト形式・台帳整合を検査するだけで、実機・資格を証明しない。`evidence`はsource fileへのpointerでありrun logではない。検証可能なrun（SHA `91279d2`、2026-09-21 local）：`ctest --test-dir build --output-on-failure`は22/22 pass、`cargo test -p routeloom-wire -p routeloom-protocol`はpass、full `cargo test --workspace --all-targets`はsandboxのsocket-bind制限で2失敗（`api_listener_mode_is_owner_only`、`daemon_restart_reconnects`、いずれも`bind: Operation not permitted`）。再現は同SHAでの同コマンド再実行。CI greenはrun ID＋SHA引用時のみ主張する。

実装時は各ケースへcommit、実行コマンド、fixture、観測点、expected/actual、ログ、結果を結び付ける。実コードが呼ばれないmodelだけで機能を完成扱いにしない。既存PR #2/#13の回帰試験を残す。

## 6.2 先に守る不変条件

1. ScopeMatchだけでMember・Gateway role・管理権限を得ない。
2. Source/destination MACはRX metadataで照合し、payloadの自称値を信用しない。
3. 明示Gateway/Host tokenは操作の途中で他の終端へ置換しない。
4. HOST_RECEIVE_RAMはReceiveLogへの実格納とそのUSB証拠より先に成功しない。
5. 同じMessageKey/操作IDの再提出は同じ仕事であり、ID・deadlineを作り直さない。
6. Configの署名/認可/保存/適用は別段階で、DECIDED/受領をACTIVEに昇格させない。
7. global Authority sequenceとper-target revisionを混ぜない。revとnonceはwrap/rollback禁止。
8. 不明な保存・時間・作用は不明と報告し、成功/未実行/新規受付へ変換しない。
9. protected recordを回収して受付率だけを改善しない。replayで保持時間を延長しない。
10. 単一Radio Owner、既存のfeasibility、control/data予算、Sleep/maintenance排他を迂回しない。

## 6.3 設計内の安全側補足（実装の必須条件）

**片側slot破損で過去の設定へ巻き戻らないこと。** 二重slotのうち一つだけ読めても、そのrecordが失われた新しいcommitより新しいとは証明できない。torn-writeであることをStorage契約で検証できる場合を除き、最後の検証可能snapshotを「既知の値」として扱うだけで、現在revision確定や新規更新受付を再開しない。CONFIG_STORAGE_UNCERTAINへ入り、Authorityからの認可済み回復証拠または再配備を必要とする。CRCだけで失われたhigh-water markを推定しない。両slot全損も同様。これは04の「生存recordから復旧」を制限する規範である。

Configのprepare/apply途中で元期限が尽きた場合、APPLY_INTENT前は開始禁止、後は完了/restoreを有限に進め結果を保存する。安全なrestoreを期限で中断して中途半端なactive状態を放置しない。結果は遅着として元操作へ結合し、新しい指示として送らない。

Gateway receipt表の60秒は**初回受理から**で、最大30秒の通信期限を含む。20件/分・burst8では任意60秒間に28件、余裕4を含め32枠とする。pending8件は同じ28件に含まれ、別に8件足して枠外へ受理しない。空き枠とtoken bucketの両方が必要。この計算はGateway専用endpointの運用profileでありRF容量の証明ではない。

Scope Offは既存非scoped挙動を保持する移行設定であり、productionでRequiredを指定した配備がkey loss時に遷移できる状態ではない。Scope Bindingのdomain付きhashとUSB Ingressサイズは05が正本。

## 6.4 テストの層

| 層 | 何を実行するか | 何を証明しないか |
|---|---|---|
| Design checker | 数式・例示bytes・登録値・リンク・負例manifest | runtime状態機械、暗号監査 |
| Portable unit/property | 本物のcodec・Coordinator・Storage fakeを使うS/G/C/Iケース | 実NVS/USB/RF |
| C++/Rust連結 | 実UsbBridge＋Host daemon、PTY、epoch/key/credit/receipt | 物理USB・無線品質 |
| IDF build | C3/S3/C5・reference/bridge・機能ON/OFF | 起動・到達距離・電池寿命 |
| HIL/RF | #11/#18の実配線・実機・実電波・電源切断 | 未保有ボード・未試験設置条件 |

## 6.5 実装で必須にする反例

Scope：同hint・異key100 responder、自己MAC偽装、録音再送、scope内/外density分離、鍵rotation直前の認証、正しいScopeだが失効機器、Required鍵喪失、Optional downgrade。

Gateway：A/B二出口、Host停止、同Host再起動、新USB session、body同ID異内容、Host格納後ACK喪失、GW受領後電断、96/97B境界、32枠飽和、reply Peer不足、部分書込み、偽Receipt。

Config：権限不足、global seqの他targetによる穴、同revisionの二要求、許可後に失効、同ID異patch、同offset異chunk、challenge期限切れ、各write/commit/apply/readbackで停止、片slot/全slot破損、restore失敗、Relay切断、channel planと競合。

## 6.6 実機試験の構成

2ノードは1hop。実3hop lineにはorigin＋Relay2台＋Gatewayの4台を使う。4台diamondで代替経路、A/B二Gatewayは別構成として記録する。アプリ上でedgeを禁止したmodelを実3hop到達と呼ばない。

Scopeの異key100 responderは先にmodelで確認し、実機は保有台数で二scope近接試験を行う。100台の実RF資格は別。C3手動smokeの既存記録を消さず、追加試験は固定SHAとboard/antenna/power/configへ結び付ける。

## 6.7 単板実機記録（2026-09-21、SHA `755ed53`系）

保有1台のESP32-C3（MAC `94:a9:90:6a:ee:c4`、rev v0.4、USB-Serial/JTAG、4MB flash）に対し、CI artifact（`firmware-bridge_node-esp32c3-normal-off-endpoints_on`、`firmware-reference_node-esp32c3-normal-off-config_target_on`、同`deep_sleep-off-off`、いずれも`202ddf8`/`755ed53`ビルド）をesptoolでapp partition `0x10000`へ書込み実施。単板のためmesh/RF/2scope/3hop/遠隔Gateway配送は全て対象外であり、以下は**USB給電・single-hop USB経路のみ**の証拠であってRF/HIL証拠ではない。

**実機で観測した挙動（pass、raw log添付なしのsession noteであり資格証拠ではない）**

- USB COBS session：hello_ack（node 1、network `0x524c0001`、capability `0x1f`）→auth_ok→credit_grant→`lease up`が実シリコンで完走。`endpoints_on`のcapability広告が実機で確認できた。
- Gateway endpoint：`gateway.resolve`が実デバイス発行のregistration（`host_digest`=SHA256(session principal)、boot incarnation、`lease_ms`≈14s）を返した。`gateway-send`(HOST_RECEIVE_RAM)は`GATEWAY_ACCEPTED`→`HOST_RAM_RECEIVED`→`END_SDK_RECEIVED`のevidence連鎖で完走し、payloadはhost ReceiveLogへ`endpoint_kind=gateway_mirror`・`EXPERIMENTAL_DEV_PSK`表記で実格納された。
- 正直な終端：peer不在のnode宛sendは実デバイスがmessage_keyを発行した上で`INDETERMINATE`（成功捏造なし）。事前cancelは`CANCELLED_BEFORE_DISPATCH`。同一key再提出は同一operation_idを返し`deadline_elapsed`を正直に報告。
- Bounded資源：uid当たりactive上限8に到達した9件目がretryable `NO_CAPACITY`で拒否。8件のINDETERMINATE終端後に`device floor adopted`が4→9へ進み、PR #13のretire/floor採用が実機で退役を解放した。
- Reset/boot lease：実リセットでboot incarnationが6→7へ進み旧sessionは破棄、再authと新leaseが張った。crash-loop firmware（deep_sleep版、stack bug中）でcounterが183まで進んだ事実は、同一firmware・同一NVS namespace（`rlboot`/`session`）内でboot incarnationが永続し単調であることの実証。異なるfirmware image間で同じNVS partition/namespaceが維持されるかはpartition構成・flash手順次第であり、firmware跨ぎの単調性は未検証のopen limitation（cross-flashでcounterが初期化され得る）とする。
- Config target起動：`config_target_on`が実NVS上で`NvsConfigStore` open→`ConfigJournal::initialize`→`ConfigTarget`登録を完走し`EXPERIMENTAL config target active`をlog出力（消去済みNVSでのclean init）。
- Deep sleep cycle：`deep_sleep` profileがRTC marker書込み→実deep sleep（USB-Serial/JTAG detachをmacOS側で観測）→30s RTC wake→`power RUNNING -> RESUMING (WAKE_DEEP_SLEEP)`と分類→保存peer 0件のため正直に`ColdStart` outcome→次cycleへ推移。power imageのNVS往復が実睡眠を跨いで動いた。

**実機で発見し修正した欠陥**

- `reference_node`の全feature構成でboot-loopするstack protection faultを実機でのみ再現（CIはbuildのみで検出不能）。`config_target_on`は`ConfigJournal::initialize`→`decode_slot`が4KBスタック配列＋`parsed[2]`（≈4.4KB）＋`store_record`の8KBで>12KBを要求。`df32219`でmain stack 8KB化、`755ed53`でjournalの大物bufferをmember scratchへ.bss化して実機boot成功を確認。`deep_sleep`版も同根因（`PowerCoordinator`系のframe）で8KB bump後に治癒。

**単板では未検証（引き続き`planned_not_run`）**

S12（二scope近接RF）、G09（受理/receipt境界での電断）、G12の残部（PTY slow-consumer系）、I03の残部（複合枯渇）、I06（compile証拠のみ・実機起動とは別）、I07（4台3hop）、I08（docs配布物）— いずれも2台以上または別設置条件が必要。config challenge→permit→propose→applyのmesh配送もbridge+targetの2台構成待ち。

**実機由来の観察（設計判断候補、レビューへ提出）**

- `NO_CAPACITY`応答の`free_slots`はRECORD_CAP基準を報告するが、実際に枯渇したのはper-principal上限8 — `rate_limited`がscopeを名指しするのと同粒度で、どのboundが満杯か応答が名指しすべき。
- 実リセット時にUSB-Serial/JTAG経路へ`InvalidMagic`を1件観測（再列挙中のgarbage）。`protocol_errors`に正直計上されsupervisorが自動復旧した — ノイズ混入を例外化せず数える挙動は正しい。

### 6.7.1 レビュー修正後の再検証（2026-09-21第二便、SHA `004d840`系）

16本のコードレビューで確定した修正（`67e43e3`〜`004d840`、CI run `35555822197`全緑 artifact）を同じ1台へ書込み、以下を再確認。これもUSB給電・single-hop経路のみの証拠であり、session noteであって資格証拠ではない。

- `endpoints_on` bridge：COBS session再認証→`gateway-resolve`が実デバイスtoken（boot `0x1cd`、lease≈8s）を発行。`gateway-send`(HOST_RECEIVE_RAM)は`HOST_RAM_RETAINED`→`GATEWAY_ACCEPTED`→`HOST_RAM_RECEIVED`→`END_SDK_RECEIVED`で完走し、payloadがReceiveLogへ`gateway_mirror`で格納 — 修正版のlive-registration ACK bindingとlost-ACK grace pathが実シリコンで動作。
- 同一key再提出は同一operation_idとstored outcomeを返した（dedup不変）。`config-challenge`はnode 1へ到達しconfig target非搭載を`REFUSED/INVALID`の正直な拒否で終端（client errorをwire faultと誤認しない分類が実機で確認）。
- `config_target_on` reference node：新journal semantics（floor前進・deferred APPLY_INTENT・4-slot challenge table・reprovision gated recover）を含むbuildが実NVS上でpanic 0件で起動、`EXPERIMENTAL config target active`→`CORE_FIXED_250 started`→`app_main`復帰まで完走。修正後のsubmit/poll経路（最悪call-chain ~13KB→~1.8KB）は実機boot-loopが消えたことで間接確認。
- host側：8件の同時op投入後の9件目が`NO_CAPACITY`の正直な拒否（host admission slot境界）。config op idがboot-tag名前空間形式（`cfg<boot-hex><seq>`）で発行されることを実機経路で確認。

引き続き単板ではS12/G09/I07/複数台config配送は`planned_not_run`のまま。

### 6.7.2 二台実機ペア試験（2026-09-21第三便、SHA `7992353`系）

ESP32-C3を2台構成に拡張して初めての**実ESP-NOW RF経路**での検証。CI paired cell（`paired_bridge`/`paired_target`、SHA `e340896`で追加）のartifactを両機へ書込み。これは同一室内・同一チャネル・既定TX powerのbench計測であり、到達距離・混雑・電源変動・資格のRF証拠ではない。

**構成**

- Board A（bridge/gateway）：MAC `94:a9:90:6a:ee:c4`、node `0x1`、`paired_bridge`（capability `0x1f`、静的peer=node 2 MAC、discovery有効）
- Board B（reference/config target）：MAC `94:a9:90:7a:b5:60`、node `0x2`、`paired_target`（`ROUTELOOM_CONFIG=y`、静的peer=node 1、discovery有効）
- ネットワーク `0x524c0001`、USB-Serial/JTAG経由のhost daemon＋実ESP-NOWリンク

**実RFで観測した挙動（session note、資格証拠ではない）**

- Discovery：`discovery event=BOUND peer=1`を実電波で発火（RLD1経路の初実機確認）。`STALE`は30秒binding lease切れで発生し、静的peer登録によるdata経路維持と併用（設計通りの分離）。
- メッセージ配送：host→bridge→**実ESP-NOW**→node 2の`deadbeef`系payloadが`END_SDK_RECEIVED`で完走し、target側consoleに`message origin=1 session=… bytes=5`を出力。
- RCC1フルパイプライン：challenge→permit→propose→apply→statusが実RFで完走。`active_revision` 0→1→2、`active_hash`が`7e463416…`（空snapshotの検算一致）→`c7725e6d…`→`7882a827…`へ遷移し、いずれも`SHA256(domain‖ns‖schema‖TLV)`のローカル独立検算とbyte一致。
- NVS永続性：電源リセット2回（boot incarnation 508→509→511）を跨いで`revision`/`active_hash`が復元 — journal二重slot＋provider NVS blobの実媒体復旧を確認。
- 冪等性：同一内容の再proposeは`NO_CHANGE`でrevision/flash消費なし。
- CAS拒否：古いbase snapshotでのproposeは`REFUSED/STALE`で正直終端。
- 正直な入力拒否：schema範囲外の`diagnostics_level u8:05`（許容0..2）は`REFUSED/DENIED`（`InvalidPatch`→`ObjectAckStatus::Failed`）— validatorの正直な拒否がwire上で誤分類されないことを確認。

**実機でのみ再現した欠陥（修正済み）**

- `DevConfigAuthorityVerifier::verify_permit`内の`Stack protection fault`（task `routeloom`、8KB stack）。permit受信経路（`handle_chunk`→`reassemble_complete`→`submit_permit`→`verify_permit`）で`ConfigCommand` ≈1.8KBローカル＋tag staging 1KBが積み上がり~400B溢れ。`7992353`でHMAC入力をstreaming化＋decodeをmember scratch化（実測frame 1.9KB→0.45KB）。CIはbuildのみで検出不能、ホストテストでは絶対に出ないシリコン限定欠陥。修正後はpermit処理をpanic 0で完走。

**依然として未検証**

- S12（二scope近接RF）はscope PSKを変えた2台構成が別途必要。G09電断（journal途中切断の損傷モデル）は本試験のリセットがcommit完了後であり厳密な中断注入ではない。I07（3hop・4台）、到達距離、チャネル混雑、電源設計、dev-HMAC以外のpermit profile（本番COSE）は全て未実施。

## 6.8 合否

安全性違反は一件でもfail。性能は既存のscope付き目標と投入負荷を測定前に固定し、成功標本だけで集計しない。未実施/失敗/対象外/blockedを区別。未知のRAM消費を0にせず、sizeofと内部heap低水位、Flash書込み回数・最大停止時間を測る。

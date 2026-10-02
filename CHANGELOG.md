# Changelog

利用者に影響する変更を記録する。SDK と各公開面の版は
[互換性の規則](docs/spec/compatibility.md)を参照。
通常の PR は [changelog.d](changelog.d/README.md) に断片を追加し、release 時にここへ統合する。

## [Unreleased]

## [2.0.0]

v2.0.0 向けの統合履歴。現 checkout の manifest は `2.0.0-dev` のままで、正式版の tag・配布・HIL 合格を示すものではない。
最初の番号付き release は v2.0.0。v1 は開発版を指す。更新手順は [移行ガイド](docs/user/migrating-v2.md)。

### 破壊的変更

- wire v2、core C ABI 3、HostLink protocol 2 を使う。旧 wire／ABI／HostLink との互換接続はない。機器と host を揃えて更新し、C の struct／vtable は initializer で size/version を設定して再 build する。
- 起動を `routeloom_device` の Device C/C++ API に統一。旧 `routeloom_node_boot`／`run_node`／`NodeBootHooks` を置き換える。他 task は `post` で Owner に仕事を渡す。
- reference／bridge／bench の既定は MemberEdhoc（Candidate）。component と quick start／examples は DevRam（Development）を維持する。field image は BoardConfig と機器 identity、USB gateway は個別 HostLink secret を provision する。
- role と容量を `ROUTELOOM_ROLE_*`／`ROUTELOOM_RESOURCE_PROFILE_*` で選ぶ。`ROUTELOOM_REFERENCE_IMAGE` を削除し、`EspNowSecurityOwner::Config::gateway` は `role` に置き換えた。SDK の Kconfig は component に移した。
- LegacyFixture と専用 Kconfig・ESP-NOW provider を撤去。旧機器は全消去・PT-4M-v2・再 provision で移行する。security profile ID 3 は予約とし、host はその受信 assurance を拒否する。
- HostLink は HKDF/HMAC-SHA-256、方向別 counter と replay 検査で認証する。protocol 1 への fallback はない。Error／DeliveryEvent は登録済み u16 reason を運び、API1 の理由文字列は維持する。
- channel plan の RELEASE は対象 member ID も運ぶ。host と gateway を一緒に更新する。全対象の READY が揃うまで release できない。

### 新機能

- Device C/C++ API：所属・接続状態、参加要求、耐久 leave、join policy、送信・group／ALL・APPLIED ticket、capability、sleep。core C にも capability、期限照会、非同期 APPLIED と reason ID を追加した。
- 賢い参加（opt-in）：先に受信し、有限時間で探索する。最大 3 件の非公開の参加予定 mark を配布・取消・更新できる。nonce に結び付けた probe を使い、参加の許可は Site Authority が決める。
- AppObject（既定 OFF）：認証済み unicast で最大 4096 B、121 B chunk、2 frame window。Device C/C++、HostLink、API1 `objects.submit/get/cancel` と objects 購読に対応。通常 send の 128 B 上限は変わらない。
- Member／DevRam の遠隔設定、Member の SAK 署名による手動 channel plan、指定 gateway 配送。zero-touch の受付停止と proxy への耐久 policy 配布、失効 NodeId の新世代・新 GK による再参加に対応した。
- endpoint／relay／gateway_small／gateway／full の容量 profile と USB 機能の個別選択。E2E session は endpoint／relay 8、gateway_small 64、gateway／full 128。実機の認定台数は別である。
- C/C++ endpoint、standalone gateway、group 送信、sleep の examples。日本語の入門・運用・移行・Kconfig ガイド、生成 API reference、API1 schema／fixture／consumer と Security Policy を整備した。
- release 基盤：source・host・firmware archive、NOTICE／依存 license／SBOM、SHA-256 と provenance、任意の署名 hook、本番 image の開発鍵／provider 検査、RC と同じ bytes の昇格。H4 の実機受入は別に必要。

### 改善

- Owner を期限と通知で起こし、DevRam／Member の sleep を既存 PowerCoordinator に統一。保存と readback 後に ticket を出し、起床ごとの radio-on 予算で探索と drain を制限する。未対応の仕事は 2 ms fallback を維持する。
- BEST_EFFORT の `coalesce_key` と host の latest lane で未送信の古い値を置き換える。RELIABLE／APPLIED は置換しない。
- wire major 2 内では新しい minor と拡張型 64–95 を中継できる。未対応終端は UNSUPPORTED を返し、未知 flags は拒否する。RRS1／RLV1 の旧版読込みと site store の前進移行に対応した。
- USB SDK_RAM payload は host の保存確認後に枠を解放する。未確認分は session 喪失後も期限まで保持する。legacy SEND は終端記録を有界に再利用し、期限切れの結果は RESULT_EXPIRED／indeterminate と返す。同じ key を再接続後に再送しない。
- scoped 経路の更新を集約し、認証済み HOP_ACCEPT の往復を近隣 lease に使う。reset 後の発見・route 更新と EDHOC の再送を有界に保つ。
- reference／bridge はサイズ優先で build。core source を機能別に分割したので、手動で source を列挙する project は `node_*.cpp` を追加する。容量 guard の変更は各 build cell の実測値に基づく。
- 実 Owner／MeshNode の E2E 行列、複数 hop・混雑・周期負荷・cursor 再開・ON/OFF 中継、相互 golden、fuzz、build cell を整備。host の成功を HIL 合格とは扱わない。
- 版と理由番号を manifest に集約し、生成物の drift を検査する。設計原則と開発規約も整理した。

### 修正

- 初回参加直後にも失効・削除・cutover を適用する。identity-only の起動、孤立後の再接続、同時起動、link slot の解放、m3/m4 と最終 reply の再送、複数 hop End 確立の期限保持を修正した。
- channel 切替を逃した member の探索、新しい offer の epoch、plan cache の検証、失われた driver callback の fence 回復、失効通知を聞けなかった NodeId の再参加を修正した。実機の再受入は未完了。
- Reliable の受信満杯時の再試行、APPLIED の実行不明・ticket 失効、leave の耐久 intent 後の送信停止を修正。受信再試行できるまで replay counter を消費しない。
- HostLink の credit と配送通知の競合を修正し、連続 SEND の停滞・IDEMPOTENCY_FULL の恒常化を防ぐ。gateway の host 不在は HOST_UNAVAILABLE、設定の型違いは INVALID、終端未観測は indeterminate と返す。
- AppObject の古い boot/context、競合 manifest、期限、buffer loan、USB egress、foreground 優先、OFF 中継の pacing と遅れた host reply を修正した。
- API1 の full 64-bit network と ACL／cursor の照合、単調時計での受付、拒否結果の保持、consumer の保存前 cursor 破棄を修正した。再試行履歴と失効 gossip の sender 保持も有界にした。
- sleep 保存・readback／read 失敗、radio 停止失敗、timer overflow、post との競合、RTC の実際の timer 値を修正した。BoardConfig 未設定は無線を止めて設定待ちする。
- C6 は Wi-Fi 起動前に RF switch とアンテナを設定する。外部アンテナは明示選択。maintenance console の stack、provision spec／bundle の照合、未設定機への field full-flash 検査を修正した。
- Rust と C++ の group／GroupLink context、拡張型範囲、EDHOC connection ID の CBOR 表現を揃えた。release の固定 SHA、flash 引数・hash・license、署名 hook の bytes 保持も修正した。

### 削除

- LegacyFixture と専用の peer／discovery／trust／USB secret／migration 設定、per-peer NVS counter/replay provider を削除。旧 state の診断は残るが、自動移行や無条件 purge は行わない。
- core C の旧 partial initializer と size 定数を削除。`rl_node_config_init()` 等を使う。旧 `examples/espnow_node` は `examples/endpoint_cpp` に移した。
- 製品固有の `DecisionMode::KGuard` は `External` に改名。保存値 0 と入力の `kguard` alias は維持する。

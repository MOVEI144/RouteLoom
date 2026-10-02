# v1 → v2 移行ガイド

v1 は `0.1.0` と旧開発 checkout を指します。番号付き v1.x は公開していません。
v2.0 向けの現 manifest は `2.0.0-dev`。正式 tag と実機資格は [STATUS](../STATUS.md) を確認してください。
移行前後の SHA、[manifest](../../protocol/manifest.json)、chip、role、sdkconfig と backup を記録します。

## 1. wire v2：機器を揃えて更新する

1. 旧 wire major 1 の機器を列挙し、mesh の運用と daemon を止めます。major 1 と 2 の混在通信はできません。
2. 全機器を wire v2 の firmware に更新します。epoch は 32 bit、crypto counter は 48 bit。独自 codec／packet parser は [wire 契約](../spec/wire-protocol.md)と golden に合わせます。
3. major 2 内の新 minor と拡張型 64–95 は中継できます。未対応終端の UNSUPPORTED と未知 flags の拒否を扱います。型番号の予約だけを capability と見なさないでください。
4. 更新後、認証済み参加と双方向の最終配送結果を確認します。

## 2. PT-4M-v2：全消去して再 provision する

出荷機・本番 site DB の無い旧開発系は全消去・再 provision で移行します。旧 NVS を推測で変換しません。

1. 対象 chip/MAC と実 flash 容量を確認し、identity・鍵の再発行元、host/site DB、ACL、consumer の backup を確保します。
2. [HIL runbook](../hil.md)に従い、対象を確定して旧 flash を全消去します。PT-4M-v2 の bootloader・partition・app をセットで書きます。4 MB、専用 NVS、otadata、OTA 2 面、coredump 予約を持つ layout です。
3. setup image で BoardConfig、USB gateway の HostLink secret、on-device identity と DevCert を provision します。commit/readback と seal/lock を確認します。eFuse の操作はこの手順に含めません。
4. 対応する field app を app-only 更新します。NVS と image の hash/readback を確認し、新 site と operation DB を準備します。
5. 同じ PT-4M-v2 上での以後の app 更新は NVS を保持します。全消去を通常更新に使わず、耐久 floor・失効状態を巻き戻さないでください。layout が同じでも OTA 配送・健全性確認が実装されたことにはなりません。

## 3. C ABI 3 と Device：全 consumer を再 build する

1. ESP-IDF app の旧 `routeloom_node_boot`／`run_node`／`NodeBootHooks` を `routeloom_device` に置き換えます。[C++ example](../../examples/endpoint_cpp/README.md)または [C example](../../examples/endpoint_c/README.md)を基に `Device::start`／`rl_dev_start` で起動します。
2. core C の全 struct／vtable に ABI 3 の `struct_size` と `version` を設定します。`rl_struct_init`／`rl_*_init` を使い、header と library を揃えて再 build します。旧 partial initializer・size 定数は撤去済みです。
3. Device C API 自体は version 1 です。共有する core の送信・結果型は ABI 3 を使います。旧 prefix を受ける型もありますが、新しい機能を使う app は最新 header で再 build してください。
4. 別 task の操作を `post` に変えます。Owner の poll hook／posted job で送信し、callback から状態を変更しません。受付と最終 delivery、APPLIED ticket の完了を分けます。

[互換性](../spec/compatibility.md)、[API reference](../api/README.md)が正本です。

## 4. HostLink protocol 2：host と gateway を一緒に更新する

1. `routeloom-host` と gateway firmware を揃えて更新します。protocol 1 は拒否され、fallback はありません。channel plan の RELEASE payload も更新済みの対で使います。
2. gateway ごとに別の HostLink secret を生成し、BoardConfig の bound secret と host の `<NodeId 16hex>.key` を一致させます。長さは printable ASCII 1–63 byte、改行なしです。
3. host directory を 0700、key file を 0600 にし、daemon に `--hostlink-credentials DIR` を渡します。開発用 `--usb-dev-secret-file` と併用できません。
4. `link.get`、`capabilities.get`、`capacity.get` を確認し、認証と実効機能を確かめます。secret は log に出しません。OS credential と ACL を使います。
5. Member の API1 network は epoch を含む full 64 bit に揃えます。daemon 再起動の `CURSOR_EPOCH_CHANGED` と保持切れの `CURSOR_GAP` を処理し、record と cursor は同じ transaction で保存します。

[Host 運用](operations.md)、[HostLink 契約](../spec/usb-protocol.md)、[API1 kit](../api/api1.md)を参照してください。
legacy SEND の結果が RESULT_EXPIRED／indeterminate なら未実行と断定しません。同じ legacy key を USB 再接続後に再送しないでください。

## 5. MemberEdhoc の既定化と LegacyFixture の撤去

1. reference／bridge／bench の field image は MemberEdhoc が既定です。機器 identity、BoardConfig、Site Authority と承認方針を用意して [入門の Member 手順](quickstart.md)を実施します。
2. component と quick start／examples は DevRam のままです。開発の固定値を製品の認証に使わないでください。Member は Candidate、DevRam は Development。本番認定は別です。
3. `ROUTELOOM_SECURITY_MODE_*` の旧 `legacy-fixture` 選択と専用設定を sdkconfig/defaults から取り除きます。旧 PSK provider を使う app は Device の Member または開発 DevRam に置き換えます。旧 state は手順 2 の全消去で移行します。
4. profile ID 3 の ingress assurance は host が拒否します。旧値を新 profile と読み替えません。参加・失効・再参加と受信 assurance を確認します。

## 6. Kconfig：改名・削除・移動を反映する

1. app の `Kconfig.projbuild` から SDK 設定の重複を取り除きます。SDK の記号は component の Kconfig にあります。移動した記号の名前は維持されています。
2. 次の置換・削除を sdkconfig と defaults に反映し、`idf.py menuconfig` で再選択します。不存在の記号が自動で別の既定に変わることを期待しないでください。

| 旧設定・名前 | v2 で行うこと |
|---|---|
| `ROUTELOOM_REFERENCE_IMAGE` | 削除。`ROUTELOOM_ROLE_ENDPOINT/RELAY/GATEWAY` と `ROUTELOOM_RESOURCE_PROFILE_*` を明示選択 |
| `ROUTELOOM_SECURITY_MODE_*` の `legacy-fixture` | 削除。MemberEdhoc または試験用 DevRam を選択 |
| `ROUTELOOM_PEER_NODE_ID`／`ROUTELOOM_PEER_MAC`／`ROUTELOOM_DISCOVERY*` | 削除。Device／Owner の認証済み発見を使う |
| `ROUTELOOM_TELEMETRY_REMOTE` | 削除。現行の読み取り専用観測が必要なら `ROUTELOOM_OBSERVATION_REMOTE` を選ぶ。旧 telemetry と同一契約ではない |
| `ROUTELOOM_CONFIG_PROFILE`／`ROUTELOOM_CONFIG_COSE_KEY_HEX`／`ROUTELOOM_TRUST_STORE` | 削除。Member の採用した site の SAK または DevRam の開発 permit で遠隔設定を使う |
| `ROUTELOOM_USB_DEV_SECRET` | 削除。provision 済みの個別 HostLink secret を使う |
| `ROUTELOOM_MIGRATION_AUTHORITY`／`ROUTELOOM_MIGRATION_SELF_AUTHORITY` | 削除。Member の gateway と site SAK の plan を使う |
| `DecisionMode::KGuard`（Kconfig ではない） | `External` に改名。保存値 0 と入力の `kguard` alias は維持 |

3. role、容量、USB 機能を [Kconfig ガイド](configuration.md)で確認します。C3 の remote config は endpoint role/profile、C5 bridge の AppObject ON は gateway_small が必要です。
4. build 後に sdkconfig と capability を確認します。古い `ROUTELOOM_DEDUP_PROFILE_*` の明示容量は引き続き選択できます。

## 7. 賢い参加：有限探索を明示的に選ぶ

1. Owner の job で現在の `join_policy` と revision を読み、`smart_join=true`、`listen_ms`、`search_ms`、`boot_join`、必要なら `same_site_only` を設定します。
2. `set_join_policy`（C は `rl_dev_set_join_policy`）で revision の CAS を確認します。既定は smart OFF、listen 3000 ms、search 60000 ms、boot_join ON です。
3. `join_mark`（C は `rl_dev_join_mark`）で機器の mark を取得し、非公開で管理します。host の `join.policy.set` に `expected_devices`（最大 3 件の 16-byte mark を 32hex で指定）と `expected_ttl_s` を設定します。
4. proxy の policy 保存確認を待ち、`request_join` の operation 結果を追います。取消は空の予定一覧、継続は期限前の更新を使います。予定 mark は参加許可そのものではありません。
5. 探索が終わったら JOIN_TIMEOUT 等を処理します。所属を保持した member の再探索と新規参加を分け、自動移設として使わないでください。

[所属仕様](../spec/identity-membership.md)、[Device API](../api/device.hpp.md)を参照してください。

## 8. AppObject：通常 send とは別に有効化する

1. origin と受信終端で `CONFIG_ROUTELOOM_APP_OBJECT_TRANSFER=y` を選びます。既定 OFF。中継は OFF でも拡張型を転送できます。
2. `capabilities`／host の capability で対応を確認します。最大 4096 B の認証済み unicast で、group object・OTA・圧縮ではありません。
3. Device は `send_object` と object observer、必要な受信 buffer を使います。送信 loan は結果が終端になるまで維持し、受信 callback 内で必要な bytes をコピーします。
4. host は `objects.submit/get/cancel` と objects 購読を使い、受付だけでなく検証済みの完了結果を確認します。deadline・容量拒否・取消・不明結果を処理します。
5. 通常 send（最大 128 B）を大きい object に暗黙変換しません。AppObject の ON/OFF ごとに flash・RAM guard を確認します。[配送契約](../spec/delivery-storage.md)を参照してください。

## 9. sleep と移行後の確認

1. sleep が必要な非 gateway は `ROUTELOOM_DEEP_SLEEP` と活動・radio-on・timer の予算を選びます。[短い sample](../../examples/sleep/README.md)は Device の保存・ticket・entry を使います。
2. app の独自 `esp_deep_sleep_start` 経路を統合し、保存／readback と有効な ticket 後だけ入眠します。別 task の post は handoff 中に Busy になります。
3. 起床で所属・世代・counter と pending の結果を確認します。RTC の elapsed が不明なら TIME_UNCERTAIN を扱います。電流・起動時間は実機で測定します。
4. 双方向 delivery、group、consumer の保存・cursor、再起動・失効を必要な機能ごとに確認します。H2／H3／H4 と C5 の未確認を host smoke の成功で置き換えません。

crypto worker（V2-16）、IP gateway、UART coprocessor、メッシュ OTA は v2.1 です。
人による第三者レビュー #100 は非ブロッキングで追跡します。

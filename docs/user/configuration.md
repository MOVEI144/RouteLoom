# Kconfig の選び方

全宣言と条件付き default は [生成 reference](../api/kconfig.md)が正本です。
SDK の記号は `components/*/Kconfig`、app の設定だけは `main/Kconfig.projbuild` に置きます。
実効値は build 後の sdkconfig と `capabilities` で確認します。

## 選ぶ順序

1. chip と flash 容量を選び、ESP-IDF v6.0.3 と PT-4M-v2 に揃えます。S3／C3／C6 が対象、C5 は実機確認待ちです。
2. `ROUTELOOM_ROLE_ENDPOINT/RELAY/GATEWAY` と `ROUTELOOM_RESOURCE_PROFILE_*` を選びます。profile と保存 role が合わなければ RF 起動前に拒否されます。
3. security を選び、BoardConfig と identity を用意します。reference／bridge／bench は defaults で MemberEdhoc、component と開発 examples は DevRam です。
4. 以下の必要な機能だけを選び、build の容量 guard と実効 capability を確認します。bit を書くだけで未実装の機能は有効になりません。

| 設定 | 用途・制約 |
|---|---|
| `ROUTELOOM_DEV_KCONFIG_IDENTITY` | DevRam の試験のみ。node/network/channel/開発鍵を Kconfig から使う。USB gateway の secret は provision が必要 |
| `ROUTELOOM_ROUTE_GATEWAY_SCOPED` | DevRam の gateway 木。全機器の root と timer を揃える。Member は SitePackage の gateway を使う |
| `ROUTELOOM_USB_NODE_STATUS`／`USB_GATEWAY_ENDPOINT`／`USB_GROUP`／`USB_OBSERVATION` | gateway の機能を個別に build。C3 gateway_small は一部を省く。capability は接続された機能だけ報告 |
| `ROUTELOOM_CONFIG` | 非 gateway の遠隔設定。C3 は endpoint role/profile が必要。Member は site SAK、DevRam は開発 permit |
| `ROUTELOOM_MIGRATION` | Member 専用の手動 plan。DevRam は固定 channel。mode と実測の timing bound を指定 |
| `ROUTELOOM_APP_OBJECT_TRANSFER` | 既定 OFF。最大 4096 B の unicast。C5 bridge ON は gateway_small が必要。C3 ON の RAM 増は 5 KiB 目標未達 |
| `ROUTELOOM_DEEP_SLEEP` | 非 gateway の Device sleep。AFTER_MS／RADIO_BUDGET_MS／DURATION_MS を合わせる。既定は 10 s 後に prepare、radio-on 最大 40 s、sleep 30 s の試験値 |
| `ROUTELOOM_OBSERVATION_REMOTE` | 読み取り専用観測。製品の判断・設定を変更する経路ではない |
| `ROUTELOOM_MAINTENANCE_CONSOLE` | 事務所の setup 専用。field build では OFF |
| `ROUTELOOM_BOARD_C6_EXTERNAL_ANTENNA` | C6 の外部アンテナを明示選択。既定は内部アンテナ |

`ROUTELOOM_OWNER_TASK_STACK_SIZE` は既定 16 KiB、priority は 1。
stack を削る前に対象構成で high-water を測定します。別 task からは `post` を使います。

## 旧設定を更新する

改名・置換・削除の一覧は [移行ガイド](migrating-v2.md)を使います。
LegacyFixture の選択は build が拒否します。削除した記号を menuconfig が黙って既定へ変えることを移行と扱わないでください。
role／security／capability／容量の既定を、機能を試すためだけに一括変更しません。

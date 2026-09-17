# 実装順序と公開計画

## 1. 原則

Join・暗号・Sleep・複数Gatewayを後付け不能な構造にしない。一方、まだ測っていない高度な最適化を最初から全て有効にしない。各段階で固定LR250の基準を残す。

## 2. 段階

| 段階 | 成果物 | 次へ進む条件 |
|---|---|---|
| P0 契約とfixture | 型・C API・wire/USB vector・fake providers | 長さ・所有権・失敗意味・暗号review |
| P1 Radio基礎 | Owner、LR250、TX/RX、Peer、diagnostics | 実機T01〜04 |
| P2 安全な参加 | membership、鍵、proxy Join、resume | T05/06、電源断、preauth負荷 |
| P3 配送とMesh | SingleAuthority、feasible routing、hop/end receipt、明示出口 | T07〜10。HA用T19を基準線の依存にしない |
| P4 Host API | USBdaemon、CLI、TUI、spool | T16/20 |
| P5 適応・干渉 | LR500試験、fair queue、scout、migration | T11〜15 |
| P6 電力・管理 | sleep tickets、remote config、bulk/OTA | T17/18、全既存gate再試験 |
| P7 公開受入 | docs、ライセンス、board matrix、再現試験 | 未完了項目と非保証の公開 |

上の順は実装を隔離する順序であり、Securityを正式リリース後まで遅らせる方針ではない。P1実験は適法なRFprofileと隔離されたテスト用途、P2完了前に通常運用を宣伝しない。

## 3. リポジトリ構造の目標

```text
components/core/          Identity・routing・delivery
components/security/      標準暗号Provider
components/radio/         SupervisorとOwner
components/transports/    espnow adapter、将来他方式
components/platform/      clock/storage/power/board
firmware/                 gateway/router/endpoint参考アプリ
host/                     Rust daemon/client/CLI/TUI
protocol/                 凍結IDL・golden vectors
 tests/                   host/property/HIL（実装時に作成）
docs/                     この仕様とボード資料
```

用途固有アプリをSDKへ依存させるのはよいが、Coreから用途固有リポジトリを参照しない。フォルダを作っただけの空実装を完成と表示しない。

## 4. 開発環境

ESP-IDF v6.0.3とcommit/submodule/toolchain/sdkconfigを固定する。C3/S3/C5別build、C5の5GHz機能はbaselineに含めない。PC側はRust、MSRVと依存lockは実装PRで固定する。テスト補助はPython標準ライブラリから始める。

## 5. ライセンスと第三者コード

maintainerが選択するまでLICENSEを推測して追加しない。既存試験コードや外部route実装は、参考設計とコード流用を分ける。流用時は各ファイルのlicense/notice/変更点を確認する。メーカーPDF・画像を丸ごと再配布せず、公式リンクと必要な事実整理を基本にする。

## 6. 変更管理

protocol major、C ABI、Host API、board profile、radio defaults、security profileの版を別にする。互換性を変えるPRでは[判断記録](decisions.md)・[STATUS](../STATUS.md)・test matrixを同時更新する。


## 7. 改訂1.1の進め方

[実装プロファイル](release-profiles.md)が公開段階の正本。P5適応／移行、P6 mesh OTA、HA専用T19は別機能ゲートで、基準線の実装開始を阻止しない。P0にはSingleAuthorityの認可境界とcrash契約を含める。Wireの完全凍結待ちでradio隔離試作を止めないが、未凍結のままinterop-readyとも呼ばない。

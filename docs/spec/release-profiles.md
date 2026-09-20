# 実装プロファイルと機能の成熟度

仕様改訂1.1（2026-09-17）。ソフトウェアのリリース番号とは別。

## 基準線と将来機能

**CORE_FIXED_250**を最初の実装・受入基準にする。承認済みの固定channel、LR250、明示Node/Gateway、単一の明示Authority、認証された小さいUnicast、経路修復、期限と受領結果、Sleep復帰、USBとCLIを対象にする。暗号・Message ID・資源予約を後付けにしない。

C3/S3を最初のHIL対象とするが、C5の対応目標・board資料・ビルド対象は削除しない。まず少数実機1/3hopで反例を再現し、100node/10hopは別の拡大受入へ進む。hop上限を3へ書き換えない。

LR500適応、複数Gatewayの高度なservice failover、自動channel移行、分散Authority、mesh OTA、LoRaは独立した設計・資格対象として維持する。TUIは実装済みだが初期profile外で未認定のまま。未実装だから仕様から消すのでも、設計済み・実装済みだから標準ONにするのでもない。

## 有効化の条件

[feature-profiles.json](../reference/feature-profiles.json)で `design_target / initial_target / implemented / host_tested / build_tested / hardware_tested / qualified / default_enabled / evidence` を分ける。基線機能の多くは実装・host試験済みだが、hardware_tested・qualifiedは全てfalse。default policyは実行可能な機能の証明ではない。

実効enable = 利用者要求 AND 実装capability AND 対象profileの認定 AND 配備条件。未実装はUNSUPPORTED、未認定はFEATURE_UNQUALIFIED。実験buildは明示opt-inと別ラベルを必要とし、必須の認証・規制条件を無効にしない。

`radio-defaults.json`は基準線としてLR250_FIXED、auto migration=false。LR_ONLY_ADAPTIVEの条件は[Radio](radio.md)、将来の自動管理は[Control](control-plane.md)に残す。

## 依存関係

1. 所有権・状態・保存契約を整え、固定LR250の低層試験を並行する。
2. SingleAuthorityと一つの認定Security Profileで安全なJoin・配送・経路を縦に通す。
3. C3資源、Sleep、PC再起動の負例を通す。
4. その上で適応、HA、移行、OTAを個別に認定する。

管理HAがない基準線でも、Authority停止中の既存DATA/局所repairは有効credentialの範囲で継続可能。新承認・失効・全体設定は保留する。単独署名をquorumと呼ばない。

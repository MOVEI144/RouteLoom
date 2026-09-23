# 設計判断と統合時の整合性

基準：2026-09-17。無線単独仕様を用途非依存SDKの文書へ統合する。

| ID | 判断 | 理由／退けた代案 |
|---|---|---|
| D01 | 初期radioは全Wi-Fi LR | 通常レート／5GHz／LoRaまで同時に最適化しない |
| D02 | 制御・初期250、検証DATA500 | LR250で届く端末をJoin時に置き去りにしない |
| D03 | 固定250を正式維持 | 自動制御の効果を同じprotocolで比較できる |
| D04 | driverより上の転送engineを重ねない | 二重ACK・retry・channel ownershipを避ける |
| D05 | single Radio Owner | rate、scan、sleep、repairが競合しない |
| D06 | 論理Network一つ、出口は複数 | 宛先の意味とRF配置を分離する |
| D07 | Babel由来の一貫した採用可能条件 | TTLだけや単純primary昇格を安全性としない |
| D08 | quorum＋persistent log | 高term/LWWだけの管理交代を避ける |
| D09 | driver暗号でなくSDK暗号を必須境界 | Peer数と機器認証・再起動を分離する |
| D10 | committed/active/visitを分離 | 準備後・遅着・一時scanで設定が壊れない |
| D11 | 固定CH1 rescueを前提にしない | 単一radioは別CHを常時同時受信できない |
| D12 | DATA flood無し | 多段・干渉時の送信増幅を抑える |
| D13 | RX availabilityと電源種別を分離 | 電池でもawakeならrelay可能、sleep中は不可 |
| D14 | 無線はESP32、窓口はPC | PC停止とMesh停止を別故障として扱う |
| D15 | Remote ConfigとOTAを分離 | 小設定に全firmware転送を要求しない |
| D16 | 物理ID・用途・接続を分離 | 移動、取り外し、再接続でデータの意味を変えない |

## 数値の正本

[radio-defaults.json](../reference/radio-defaults.json)と対応仕様を同時管理する。統合版では探索／survey訪問上限200ms、Deep Sleep型無線活動予算2000ms、停止予約100msを採る。時間の短いbudgetでは探索回数を減らし、2周を常に完遂すると解釈しない。

性能目標と操作timeoutを区別する。1000ms callback watchdogは正常送信を1秒待たせることではない。1hop20ms目標、LINK RTO60ms初期、channel準備30秒は別の起点と仕事。

## 未確定を隠さない

暗号suite/Providerの実装選定、SDK ABI layout、合意ライブラリと媒体は、採用規則を決めた上で実装レビューとvectorで凍結する。代替案の列挙で責任を曖昧にせず、[STATUS](../STATUS.md)のゲートとして追跡する。最終wire byte layoutとrouting更新timerはCORE_FIXED_250 profileで凍結済み（`wire.hpp`のWire v2、`routing.hpp`/`node.cpp`の定数、共通golden vector）。

## 参照実装の扱い

ESP-IDF low-level API、espressif/esp-now、babeld等の読んだコードは一次資料として参照する。別のライセンスのコードを新SDKのlicenseへ無断変更しない。既存ソフトの全監査・RF試験を完了したとはしない。


## 改訂1.1：外部レビューの反映

[採否台帳](../reviews/2026-09-17-response.md)と[実装プロファイル](release-profiles.md)を追加。固定250基準線、SingleAuthority、auto migration OFFは開発と認定の順序の変更であり、C5／複数Gateway／10hop／将来HAや移行の設計目標を撤回しない。

Join allowlist、nonce保存順序、経過時間不明、受理前予約、USB累積credit、OTA state互換は今守る規約。Wire layout／暗号suite／全routing再起動規則はゲートとして残す。検査が通っても暗号・RF・合意の実装済みを意味しない。

# 実装状況とリリース条件

更新：2026-09-17。

## 現在の証拠

| 項目 | 状態 |
|---|---|
| 統合アーキテクチャ・無線・SDK契約 | 本リポジトリで文書化 |
| ボード資料 | 公式Wiki・回路図・SoC資料を参照。現物照合は未実施 |
| 文書・JSON検査 | tools/check_docs.pyで再実行可能。結果は実行記録を参照 |
| 動作するESP32ファームウェア | 未実装 |
| Rustホストサービス／CLI／TUI | 未実装 |
| 暗号Provider・相互運用テスト | 未実装・未認定 |
| 管理合意・経路制御の実装 | 未実装・未検証 |
| C3/S3/C5のRF実機試験 | 未実施 |
| 電池寿命・距離・100台性能 | 未認定 |
| ライセンス | 未選定。OSSリリースの阻止条件 |

過去の試作用モデルの成功件数を、本SDKの試験結果へ転記しない。文書検査はファームウェアの安全性・無線到達性を証明しない。

## 該当機能の公開前に閉じる項目

- **G-WIRE**：通常128Bが全ヘッダ・保護情報込み250Bに収まる最終encoder、型番号、テストベクトルを確定する。
- **G-SEC**：EDHOCを中心とするProvider、credential形式、暗号suite、nonce/replay保存、失効・再起動を独立レビューする。
- **G-ROUTE**：Babel由来の採用可能条件・更新・撤回・再起動を一貫して実装し、分断・再結合と10hopを試験する。
- **G-CONTROL**：SingleAuthorityでは署名操作台帳の保存・復旧を検査する。HAでは追加で選挙、管理log、snapshot、構成員変更、過半数・非voter向け証拠を認定する。HA未完了を基礎Mesh試作の禁止理由にはしない。
- **G-USB**：認証transcript、後続frame保護、最終byte layout、累積creditとC/Rust共通vectorを実装・相互検証する。
- **G-BOARD**：現物の基板revision、電源、アンテナ、Pin、実Flash/PSRAM容量を照合する。
- **G-RF**：全対象のLR250、方向別LR500、broadcast/unicast、callback、切替、Sleep復帰を認定する。
- **G-SYSTEM**：USB再接続、キュー不足、PC停止、遠隔設定、更新中断を試験する。
- **G-LICENSE**：プロジェクトライセンスと依存物の利用条件をmaintainerが決める。

## 完成の表示方法

ボードごと・機能ごとに `documented / implemented / host-tested / hardware-tested / qualified` を区別する。C3の合格をC5へ自動継承しない。設定APIのESP_OKはPHY実測ではない。

公開バージョン0.xでもセキュリティを暗黙に無効化しない。RF未認定の実験buildはラベルと診断にEXPERIMENTALを出し、配備承認とは分離する。

[受入試験](spec/acceptance.md)と[実装計画](spec/implementation-plan.md)を参照。


## 改訂1.1の範囲

[採否台帳](reviews/2026-09-17-response.md)に30件を対応付け、文面の衝突と安全側の次状態を修正した。Wireの完全凍結は今回の完了条件にしない。G-WIRE/G-SEC/G-ROUTE/G-CONTROL/G-USBは依然として実装・ベクトル・レビュー待ち。

文書構造検査、生成表照合、negative mutation、小さな意味モデルを別々に実行する。全通信機能のimplemented/qualifiedはfalse。過去の254件という数を新specの意味の完全検証と扱わない。

基準線／将来機能は[実装プロファイル](spec/release-profiles.md)、RAM数値は[未実測の資源予算](spec/resource-profiles.md)。ライセンスはmaintainer判断として未選定を維持する。

## 検査の区分

CIは従来の文書構造検査、正本から生成する表の一致、選択した設計契約、純Pythonの小状態モデル／改変検出を別stepとartifactにする。小モデルのauth/commitは入力条件であり、暗号・Raft・NVSや無線driverの実装をテストしていない。

artifact保持30日は便宜的な実行記録であり、長期RF認定証拠の保管ではない。実機認定時はcommit、board、profile、環境、分母、測定器、原traceのdigestを長期保管先へ結び付ける。

# Host連携・容量・本番認証・運用資格の統合設計

設計版 **0.1-draft / 2026-09-20**。対象：Issue #7〜#12。設計レビューと後続実装を積むための文書であり、SDKの機能実装・本番認定・実機試験の完了報告ではない。

## 入口と読み順

| 文書 | 解決する問題 |
|---|---|
| [01 共通契約](01-contracts.md) | 責任境界、既存P0との接続、ID、時間、能力、公開API |
| [02 受信API](02-receive-api.md) | #7：本文を取得するcursor付き読出し、欠落、遅い利用者 |
| [03 送信API](03-send-api.md) | #8：条件付き送信、同じ依頼の照会、USB/SDK対応 |
| [04 容量と保存](04-capacity-storage.md) | #9：16件/24時間問題、長短台帳、受付世代、電源断 |
| [05 本番認証](05-production-security.md) | #10：EDHOC/RPK、固定実装候補、鍵・所属・失効の運用 |
| [06 実機試験計画](06-hil-plan.md) | #11：機器行列、配置、負荷、失敗注入、合否と証跡 |
| [07 APPLIED](07-applied-delivery.md) | #12：SDK受領とアプリ結果、非同期API、再送・結果不明 |
| [08 実装・移行・残ゲート](08-implementation.md) | 作業単位、順序、互換性、完了条件 |
| [根拠・判断記録](sources.md) | 固定SHA、一次資料、採用案と見送った案 |
| [機械可読な契約](contracts.json) / [試験台帳](scenarios.json) | 数値・成熟度・Issue対応。runtime設定ではない |

## 今回の決定

受信は既存daemonのIPC上で **cursor付きpoll一方式**から始める。診断EVENTSへ本文を足すだけでは済ませない。送信は版付き要求とcaller指定key、条件を含む正規化hash、安定OperationIdで追跡する。

長期のoperation記録はHostのStoreへ、Gatewayは短期のdispatch窓と退役済みsequenceの拒否へ分ける。RAMが満杯なら保護記録を追い出さず新規受付を拒否する。PCでの記録保存を、端末アプリの副作用が一度だけであることの保証にはしない。

本番認証はEDHOC/RPK方針を具体化し、開発共有鍵から自動昇格しない。APPLIEDは後続機能。まずRELIABLEによるPC↔端末の双方向連携を完成させ、アプリ自身が結果を返信する既存の使い方も維持する。

## 調査基点と依存関係

- main：`31b3eb0ae7080d713e7acd7ee3b7f31b43423465`。このDraft branchの基点。
- PR #2：`cdcf0fe33b51854d4b62478e7fbc193cc8c386d8`。Host/USB/Powerの実装とC3手動smoke記録を照合。
- PR #6：`be21fbb41e8bb7fbf4de76e1f946436915dea741`。**設計だけではなくP0以降の実装も追加されている**。共通型、AdmissionContext、codec、試験基盤はここへ接続する。
- 調査時点で#2/#6は未マージ。両PRを代理マージ・複製せず、新しいdesign-only差分を作る。実装開始前に採用済みmainを取り込み、変更箇所を再照合する。
- PR #6の対象SHAでは設計・文書CIは成功、SDK CI run `35476900403` はfailureだった。本文のbuild-testedという記述をこのSHAの全CI成功と読み替えない。このDraftで他PRの失敗を修復したとはしない。

## 既存の証拠を消さない

PR #2のSTATUSには、C3二台の実無線・受領確認、6連続送信、USBとreset後再接続の**手動smoke確認**が記録されている。この記録を「一切実機未試験」に戻さない。一方、現物・生ログを今回再測定したわけではない。S3/C5 RF、多段、長期、干渉、実電源断の資格は別に追跡する。

## 設計変更の扱い

本書中のAPI、profile、数値、バイト形式はレビュー対象の採用案であり、実装済み機能の広告ではない。既存のWire型番号、enum、正常RELIABLE/BEST_EFFORTの意味を変更しない。新しい操作は能力交渉が成功した組合せだけで使用し、未対応ならUnsupported。

runtimeのfeature-profiles、qualified、hardware_testedは更新しない。試験台帳の新規ケースはすべてplanned_not_run。設計checkerは文書・数値・fixtureの整合性検査であって、C++/Rust相互運用・暗号監査・HILではない。Issueも設計だけではcloseしない。

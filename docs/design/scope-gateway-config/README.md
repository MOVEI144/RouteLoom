# Scope・Gateway・Small Config — 実装用設計

設計版 **0.1-draft / 2026-09-20**。対象：[Issue #14](https://github.com/MOVEI144/RouteLoom/issues/14)、[Explicit Gateway #16](https://github.com/MOVEI144/RouteLoom/issues/16)、[Small Remote Config #17](https://github.com/MOVEI144/RouteLoom/issues/17)。

**これは新しい3機能の設計提出であり、runtime実装・本番認証・実機認定の完了ではない。** このDraftへ後続実装を積む。既存の機能flag、CORE_FIXED_250の既定値、先行PR、mainを変更しない。

## 利用者にとって何が変わるか

| 機能 | できるようにすること | 保証しないこと |
|---|---|---|
| Discovery Scope | 無関係な発見へ応答しない。合うscopeだけ本人確認へ進める | Scope Keyを知るだけの機器を信頼・参加承認しない |
| Explicit Gateway | 指定した出口と指定した受領境界まで配送する | 別Gatewayでの代行、RAM受領からの永続保存・アプリ成功の推定 |
| Small Config | 小さな設定を認可・保存・適用・照会する | OTA、任意コマンド、業務処理、秘密鍵配備、一般的exactly-once |

「合言葉が一致」「端末へ到達」「設定を保存」「動作へ適用」はすべて別の証拠である。

## 読み順

1. [共通契約と既存コードへの接続](01-integration.md)
2. [Discovery Scope](02-discovery-scope.md)
3. [Explicit Gateway](03-explicit-gateway.md)
4. [Small Remote Config](04-remote-config.md)
5. [Wire・API・互換性](05-wire-api.md)
6. [失敗条件と受入試験](06-acceptance.md)
7. [実装順序・完了条件](07-implementation.md)
8. [判断記録と一次資料](08-decisions-sources.md)
9. [その他の作業とIssue](09-backlog.md)

[数値・登録値の正本](contracts.json)、[設計例](examples.json)、[受入ケース台帳](cases.json)、[C API宣言案](sdk-contract.h)も同時に読む。宣言案はリンク可能な実装ではない。設計用encoder/小モデルの検査はC++/Rust runtime相互運用・暗号監査の代わりではない。

## 基点

main **610c5b27dd741a759051724fb9cc10c82b556314**（#2/#6採用済み）。ソースは同SHAのDocumentation artifact 10598423025、archive SHA-256 **1de4d28b3092d6ab9a3de759b551eef172d16c71775a1745dfbc5d527cd493bc**を取得・照合した。

Host APIとの接続確認には未マージPR #13 **6030baa7046c6d6dfe466df3071b58c0c6797139**を参照した。現在対応中のPR #13レビュー修正はこの設計で修正済み扱いにしない。採用時にSHA、API/USB登録値、OperationStore・deadline修正を再照合する。

## 最小の実装境界

Scopeは単独で実装可能。GatewayはSDK受領モードを先行し、Host受領モードはPR #13のReceiveLog・受領確認と合わせる。Configは単一Authority・一対象・一namespaceのdesired-state更新に限定する。Raft、Anycast、APPLIED実装やMesh OTAを3機能の完了依存にしない。

ただし本番有効化には#10の正式Identity/鍵/認可、実装試験、#11のHIL/RFが必要。設計を承認しただけで`qualified=true`にしない。

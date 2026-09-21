# 9. 関連バックログ・重複させない責任

## このDraftで設計する3機能

- [#14 Discovery Scope Key](https://github.com/MOVEI144/RouteLoom/issues/14)：既存Issueを採用。
- [#16 Explicit Gateway](https://github.com/MOVEI144/RouteLoom/issues/16)：今回作成した実装追跡Issue。
- [#17 Small Remote Config](https://github.com/MOVEI144/RouteLoom/issues/17)：今回作成した実装追跡Issue。

## 今回別Issueとして登録した作業

| Issue | 優先度 | 役割 |
|---|---|---|
| [#18 HIL runner](https://github.com/MOVEI144/RouteLoom/issues/18) | High | #11の試験を少数実機で反復実行・収集する。手動smokeの前提に巨大rackを要求しない |
| [#19 Fuzz/property](https://github.com/MOVEI144/RouteLoom/issues/19) | High | 実parser・状態機械の入力探索と既存反例の回帰 |
| [#20 Storage/Clock fault](https://github.com/MOVEI144/RouteLoom/issues/20) | High | 台帳・nonce・設定・SQLiteの故障/時計/権限を横断検査 |
| [#21 Component配布](https://github.com/MOVEI144/RouteLoom/issues/21) | Medium-High | 空の外部ESP-IDF consumerから導入/buildできること |
| [#22 互換性](https://github.com/MOVEI144/RouteLoom/issues/22) | Medium-High | C ABI/Wire/USB/API/Storageの新旧組合せと移行規則 |
| [#23 License/NOTICE](https://github.com/MOVEI144/RouteLoom/issues/23) | Release blocker | maintainerの本体選定、依存/流用/素材の条件確認 |
| [#24 Release pipeline](https://github.com/MOVEI144/RouteLoom/issues/24) | Medium | 同一検証artifact、checksums/SBOM/metadata、公開権限分離 |
| [#25 Security運用](https://github.com/MOVEI144/RouteLoom/issues/25) | Medium | SECURITY.md、秘密情報、窓口、開発鍵、脆弱性対応 |

## 既存を継続する作業

#7/#8/#9とPR #13はHost受信/送信/容量とレビュー修正。#10は本番Identity・鍵・失効。#11はHIL/RF試験計画。#12はAPPLIED。#15はPages/利用者docs。これらを別の同名Issueへ複製しない。

Scopeを本番認証の代替にせず、SmallConfigをAPPLIED/OTA/アプリ操作の代替にしない。運用上の必要性が確認されていないLR500、Raft、LoRaや大規模拡張は、今回の完了条件へ新たに持ち込まない。

推奨順序：PR #13修正・回帰 → 3機能の小さい実装単位＋fault/fuzz → 少数実機 → external consumer/docs/license/security → 段階的release。各Issueには独立した受入条件を置き、Issue数を増やしただけで進捗としない。

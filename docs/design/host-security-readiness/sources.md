# 固定根拠・採用判断・確認範囲

確認日2026-09-20。Issueの要求、リポジトリの記録、外部標準、今回の設計判断を区別する。

## Issueの正本

[受信 #7](https://github.com/MOVEI144/RouteLoom/issues/7)、[送信 #8](https://github.com/MOVEI144/RouteLoom/issues/8)、[容量 #9](https://github.com/MOVEI144/RouteLoom/issues/9)、[本番認証 #10](https://github.com/MOVEI144/RouteLoom/issues/10)、[実機試験計画 #11](https://github.com/MOVEI144/RouteLoom/issues/11)、[APPLIED #12](https://github.com/MOVEI144/RouteLoom/issues/12)。

#10の[進捗分離の補足](https://github.com/MOVEI144/RouteLoom/issues/10#issuecomment-5742861361)を含めて確認。他5件のコメントは読み取り時点で空だった。Issueにある用途固有の説明はSDKの型・状態・鍵・業務ロジックへ移植しない。

## 読み取ったコードと文書

| 対象 | 根拠と使い方 |
|---|---|
| main基点 | [31b3eb0](https://github.com/MOVEI144/RouteLoom/commit/31b3eb0ae7080d713e7acd7ee3b7f31b43423465)。新branchのparentで、先行PR採用済みとはしない |
| PR #2 | [cdcf0fe](https://github.com/MOVEI144/RouteLoom/commit/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8)。Issue作成時の基点 |
| 現在PR #6 | [be21fbb](https://github.com/MOVEI144/RouteLoom/commit/be21fbb41e8bb7fbf4de76e1f946436915dea741)。P0/common/runtime接続の主な参照 |
| 成熟度・C3記録 | [STATUS](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/docs/STATUS.md)。手動smoke報告と未完了の本番認証を分離 |
| IDと列挙 | [types.hpp](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/components/routeloom/include/routeloom/types.hpp)、[autonomy.hpp](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/components/routeloom/include/routeloom/autonomy.hpp) |
| 許可判定 | [admission.hpp](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/components/routeloom/include/routeloom/admission.hpp)。同じ状態/gateへ接続 |
| Wire境界 | [wire.hpp](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/components/routeloom/include/routeloom/wire.hpp)、[autonomy_wire.hpp](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/components/routeloom/include/routeloom/autonomy_wire.hpp)。88B header、最大248B、bootstrap1024B |
| USB容量・既定送信 | [usb_session.hpp](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/components/routeloom/include/routeloom/usb_session.hpp)、[usb_bridge.cpp](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/components/routeloom/src/usb_bridge.cpp) |
| Host現API | [main.rs](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/host/routeloom-host/src/main.rs)。SEND、EVENTS、DataFromMesh、相関・writer |
| 既存保存規範 | [crash-time-resources](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/docs/spec/crash-time-resources.md)、[Host](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/docs/spec/host.md) |
| 現暗号・APPLIED | [security.hpp](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/components/routeloom/include/routeloom/security.hpp)、[node.cpp](https://github.com/MOVEI144/RouteLoom/blob/be21fbb41e8bb7fbf4de76e1f946436915dea741/components/routeloom/src/node.cpp)。既存暗号を無いことにしない |

PR #6 source artifact：Documentation run `35476900400`、artifact `10594826356`、SHA-256 `53663469226ef68c7955417ac14004fd6e2b1f006a7b94426c854347cfc55654`を取得。SDK run `35476900403`はfailure、文書・設計runはsuccessと読み取った。新しいruntime動作を実行したという証拠ではない。

## 外部一次資料と選定

- [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528.html)：method/suite、RPK/CCS、message_4、application exporter。RouteLoom固有の承認とroleは追加契約。
- [RFC 9529](https://datatracker.ietf.org/doc/html/rfc9529)：EDHOC test vectors。公開テスト鍵だけをfixtureへ使い本番秘密と分離する。
- [IANA EDHOC](https://www.iana.org/assignments/edhoc/edhoc.xhtml)：private-use exporter labels32768〜65535。今回のlabelは登録済みではない。
- [RFC 9052 COSE](https://www.rfc-editor.org/rfc/rfc9052.html)：署名構造/保護header。MembershipGrantの内容と認可はRouteLoom設計。
- [libedhoc固定版](https://github.com/kamil-kielbasa/libedhoc/tree/c8857b62d66be3664d1694bbe4eea37c56c05d9e)：v2.3.2のmethod0/suite2、crypto/credential/platform callback、custom memory backendを確認。
- [libedhoc LICENSE](https://github.com/kamil-kielbasa/libedhoc/blob/c8857b62d66be3664d1694bbe4eea37c56c05d9e/LICENSE)：MIT。選定は本体のライセンス未決定を解消しない。
- [IDF固定Mbed TLS](https://github.com/espressif/mbedtls/tree/ce3f3485a121c100f58f36d700cb35b060f6e866)：IDF v6.0.3のsubmoduleを確認。native backendもlockとNOTICEを検査する。
- [IDF RNG](https://github.com/espressif/esp-idf/blob/v6.0.3/docs/en/api-reference/system/random.rst)、[NVS](https://github.com/espressif/esp-idf/blob/v6.0.3/docs/en/api-reference/storage/nvs_flash.rst)：乱数準備、保存・初期化の実装条件。
- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html)：Host store選定の根拠。OS/媒体のflush前提まで自動証明するものではない。

## 採用した案・見送った案

| 判断 | 理由 |
|---|---|
| cursor poll一方式 | 小さいIPC追加で再取得・欠落を説明できる。pushと二重状態機械を初期に作らない |
| Host長期Store＋Gateway短期窓 | Gatewayへ24h×要求rateのRAMを強制せず、退役seq拒否で再実行を防ぐ |
| epoch単位の回収 | 旧keyを個別record削除後に新規と誤認しない。長い不明recordで受付が止まる限界は明示 |
| local SQLite | 既存Storage adapterとして耐電断transactionを使用。外部サービス追加は不要 |
| EDHOC M0/S2＋PSA | 既存RPK方針・P-256 backend・固定実装を利用。自作challenge/全体PSKによる個体識別を避ける |
| app AES-GCM profile | 既存Wire/PSAの16B tag/128B通常payloadを維持。suite内部AEADとの相違を明示して独立レビュー |
| APPLIED後続 | 最小の双方向通信を止めず、作用結果とSDK受領を後から混同しないAPI境界を先に確定 |
| HIL手順から開始 | 大規模な新CI基盤を待たず、既存機材・コマンド・原始ログで段階認定できる |

固定pinは採用の出発点で、将来の修正情報を無視して永久固定する指示ではない。更新時は差分・脆弱性情報・相互運用・容量を再評価し、互換性と再認定範囲を記録する。

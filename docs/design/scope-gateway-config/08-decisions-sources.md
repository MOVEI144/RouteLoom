# 8. 判断記録・一次資料

確認日2026-09-20。下記の外部規格はprimitive/構造の根拠であり、RouteLoom独自profileの安全性を自動的に保証しない。リンクの内容を丸ごと再配布しない。

## 8.1 採用と見送った案

| 判断 | 採用理由 | 見送ったもの |
|---|---|---|
| Scope tag128bit | SHA256半分、既存枠に余裕。方向/Network/nonce/MACを結合 | 96bitは可能な候補だが本profileでは使わない |
| RLD1 bodyv2 | 既存headerと型番号を維持、legacyの限界を説明できる | reserved bitの無断利用、第二のFrameType体系 |
| Scopeは一つ＋二鍵世代 | C3で候補とMAC計算を有界にする | 無制限tenant/scope探索 |
| Gateway Service21 envelope | typed終端とtokenをE2E保護できる | DATA内容の自動判別、plain mutable scope |
| Gateway本文96B | 既存88Bheader/32Btags/128Bpayload内で終端envelope32Bを確保 | 無言で128Bを切り詰める、初期の自動fragment |
| Host受領はGatewayの証言 | 初期実装の鍵・サイズを有界にし信頼境界を正直に示す | Host独立署名を付けていると偽る |
| Configはdesired state | 状態復元・CAS・readbackが可能 | 任意コマンド・不可逆作用の汎用transaction |
| issuer logとtarget revision分離 | 他targetの操作でglobal seqが飛んでも更新可能 | 各端末に全管理logの配送を要求 |
| challengeで初回apply期限 | 対象bootの単調時計で検査できる | 受信時点からTTLを付け直す、wall clockを信用 |
| COSE Sign1＋署名済みpermit | 標準署名構造を使いAuthorityの認可を結合 | Scope Key・非暗号hashを管理署名へ転用 |

## 8.2 外部一次資料

- [RFC 2104 HMAC](https://www.rfc-editor.org/rfc/rfc2104.html)：HMAC構成と切詰めの考慮。
- [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html)：HMAC-SHA-256の公開検査vector。checkerはcase1のdigestを確認する。Scope protocol全体の相互運用検証ではない。
- [RFC 9052 COSE Structures](https://www.rfc-editor.org/rfc/rfc9052.html)：COSE_Sign1、protected header、external_aad、Sig_structure。
- [RFC 9053 COSE Algorithms](https://www.rfc-editor.org/rfc/rfc9053.html)：ES256のアルゴリズム登録・署名表現。#10のProviderを共用する採用案。
- [ESP-IDF v6.0.3 nvs.h](https://github.com/espressif/esp-idf/blob/v6.0.3/components/nvs_flash/include/nvs.h)：commitを成功させて初めて永続書込みを要求したことになる。closeだけに依存しない。多キー全体のatomicityは別契約。
- [ESP-IDF v6.0.3 ESP-NOW](https://github.com/espressif/esp-idf/blob/v6.0.3/docs/en/api-reference/network/esp_now.rst)：Peer/rate/callback制約。受信したこととSDK/Host受理は別。

Espressifのv6.0.3 rendered docsは今回の取得経路で失敗したため、固定tagのsource headerを照合した。将来stableページが更新されても本profileのbaselineを自動更新しない。

## 8.3 参照した実コード

- [main types.hpp](https://github.com/MOVEI144/RouteLoom/blob/610c5b27dd741a759051724fb9cc10c82b556314/components/routeloom/include/routeloom/types.hpp)
- [RLD1/object registry](https://github.com/MOVEI144/RouteLoom/blob/610c5b27dd741a759051724fb9cc10c82b556314/components/routeloom/include/routeloom/autonomy_wire.hpp)
- [discoveryの処理](https://github.com/MOVEI144/RouteLoom/blob/610c5b27dd741a759051724fb9cc10c82b556314/components/routeloom/src/discovery.cpp)
- [Node dispatch/配送](https://github.com/MOVEI144/RouteLoom/blob/610c5b27dd741a759051724fb9cc10c82b556314/components/routeloom/src/node.cpp)
- [Authority境界](https://github.com/MOVEI144/RouteLoom/blob/610c5b27dd741a759051724fb9cc10c82b556314/components/routeloom/include/routeloom/authority.hpp)
- [PR #13 HostOps](https://github.com/MOVEI144/RouteLoom/blob/6030baa7046c6d6dfe466df3071b58c0c6797139/components/routeloom/include/routeloom/usb_host_ops.hpp)
- [PR #13受信API](https://github.com/MOVEI144/RouteLoom/blob/6030baa7046c6d6dfe466df3071b58c0c6797139/host/routeloom-host/src/receive_log.rs)

#14の要望と#16/#17の作業を、既存のAdmission、MessageKey、Authority、Power、HostOpsへ接続するための新設計である。Issueに提案されていた数値を実測値として扱わない。既存の本番認証/試験設計#10/#11を重複作成しない。

# 根拠・読んだコード・既存仕様との差分

確認日：2026-09-19。Issueの要求、コード上の事実、外部仕様、今回の設計判断を混ぜない。以下のコード参照は固定SHA。

## 1. 要求の正本

- [Issue #3](https://github.com/MOVEI144/RouteLoom/issues/3)：Neighbor discovery、認証、NodeId、Peer枠、metric。
- [Issue #4](https://github.com/MOVEI144/RouteLoom/issues/4)：輻輳、負荷分散、hysteresis、multipath、backpressure。
- [Issue #5](https://github.com/MOVEI144/RouteLoom/issues/5)：runtime channel変更、干渉観測、取り残し、authorityとの関係。

確認時の3Issueに追加コメントはなかった。タイトル/説明を要求として取り、特定の解決案が実装済みと解釈しない。

## 2. 読み取りsnapshot

mainは `31b3eb0ae7080d713e7acd7ee3b7f31b43423465`。PR #2はopen、head `cdcf0fe33b51854d4b62478e7fbc193cc8c386d8`。そのDocumentation run `35435007279` のartifactを取得し、SHA-256 `11493a5f86438b9801f1527db65778561cd8175ffaff31971a48495d906d5e23` と照合してコードを読んだ。

これはPR #2全体の再承認やRF試験の証拠ではない。このDraftは独立したmain向けdocs差分で、実装時にはPR #2の採用済み変更が必要。

| 固定コード | 確認した事実と設計への反映 |
|---|---|
| [espnow_runtime.cpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom_espnow/src/espnow_runtime.cpp) | initialize_wifiで固定channel。enqueue_rxは未知MACをdrop。sendは登録Peerのみ。#3のraw RX入口、#5のOwner操作が必要 |
| [espnow_runtime.hpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom_espnow/include/routeloom/espnow_runtime.hpp) | Peer19、event48、NodeId中心RadioPort。論理近隣と物理Peerを分離する接続点 |
| [node.hpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom/include/routeloom/node.hpp) / [node.cpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom/src/node.cpp) | FIFO32、awaiting-hop8。BusyのRX dispatchなし。metadataをmetricへ利用していない。drainingは背景広告も止める |
| [routing.hpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom/include/routeloom/routing.hpp) / [routing.cpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom/src/routing.cpp) | advertised metricと最新FDでの再判定。負荷回避にもこの境界を維持 |
| [wire.hpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom/include/routeloom/wire.hpp) / [types.hpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom/include/routeloom/types.hpp) | Wire1.0 header88、payload128、tag16×2=248。拡張用type番号はあるがhandler実装とは別 |
| [authority.hpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom/include/routeloom/authority.hpp) | SingleAuthority/二slot。署名検証結果boolと非暗号payload binderは完全なplan認証Providerではない |
| [security.hpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom/include/routeloom/security.hpp) / [psk_security.cpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom_espnow/src/psk_security.cpp) | Development/Production区分、PSA暗号、context別counter。これだけで動的個別Identity認証完了にはならない |
| [espnow_power.cpp](https://github.com/MOVEI144/RouteLoom/blob/cdcf0fe33b51854d4b62478e7fbc193cc8c386d8/components/routeloom_espnow/src/espnow_power.cpp) | start_discoveryはUNSUPPORTED。cacheのchannelと正式planの優先順位を新規接続する |

## 3. 外部一次資料

### E1 — 固定ESP-IDFのESP-NOW契約

[ESP-NOW v6.0.3](https://github.com/espressif/esp-idf/blob/v6.0.3/docs/en/api-reference/network/esp_now.rst)

送信前Peer登録、broadcast Peer、未知Peerからのnative非暗号unicast受信、20Peer上限、deinit時のPeer消去、相手別rate適用順、callbackの短時間処理を確認。RouteLoomのSDK暗号とnative暗号は別。これらから未知RX入口と安全なdriver cache管理が必要と判断した。

### E2 — runtime channelと保存

[esp_wifi.h v6.0.3](https://github.com/espressif/esp-idf/blob/v6.0.3/components/esp_wifi/include/esp_wifi.h)

set_channelはWi-Fi起動後、scan/外部AP接続との制約があり、設定channelはそのAPIだけではNVS保存されない。したがってOwnerで排他し、正式plan storeを使い、起動後に再適用する。country設定だけで個別機器の適合を証明するとはしない。

### E3 — 公式サンプル実装

[espnow_example_main.c v6.0.3](https://github.com/espressif/esp-idf/blob/v6.0.3/examples/wifi/espnow/main/espnow_example_main.c)

受信時にMACをeventへコピーしworkerへ渡す構造を確認。サンプルのmalloc、長いqueue待ち、CRCを使った交換を、そのままRouteLoomの有界資源・認証の実装へコピーしない。

### E4 — Babel

[RFC 8966](https://www.rfc-editor.org/rfc/rfc8966.html) §2.4–2.7、§3.5–3.8、Appendix A。

feasibilityは隣接が広告したdistanceと自分のFDを比較する。route選択やmetricはその条件内で行う。SeqNoRequestはDATA経路と異なる扱いが必要。これを#4のlocal costと経路安全性の境界の根拠にした。RouteLoomが標準Babel packet互換であるとはしない。

### E5 — flow queueing

[RFC 8290](https://www.rfc-editor.org/info/rfc8290/) §1.3、§4–5。

flow分離、DRR、queue sojourn観測、低速linkでのtarget調整の考え方を参考にした。RouteLoomではFQ-CoDelのdrop手順やTCP向け定数を移植せず、有界受付と明示BUSYを用いる。これらの選択は今回の設計判断。

### E6 — LRの範囲

[C5 Wi-Fi/LR説明](https://docs.espressif.com/projects/esp-idf/en/release-v5.5/esp32c5/api-guides/wifi.html#long-range-lr)、[最新overview](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-guides/wifi-driver/overview.html)

2.4GHzの独自LRと通常Wi-Fiの違いを確認する概念資料。最新stableと固定v6.0.3を混同しない。採用APIの根拠はE1/E2の固定sourceとし、APIの存在を全chip・antennaのRF資格へ読み替えない。

## 4. 既存設計との差異を意図的に限定する

| 既存方針 | 今回の追加 |
|---|---|
| COREは固定CH/LR250 | baselineを保持し、AUTONOMY capabilityを個別認定 |
| discoveryは構想中心 | public envelope/認証binding/Peer lease/Power接続まで具体化 |
| 全網管理予算の構想 | まずlocal有界schedulerとdeadline会計。動的全網配賦は依存にしない |
| 複数候補 | 一つの現用経路を安定に変更。DATA複製multipathは行わない |
| quorum関連の移行 | SingleAuthorityで同じ安全契約を実装し、HAは別Provider |
| 復旧訪問の構想 | helper/周期/停止予算と条件付きliveness式をplanへ追加 |
| 20ms等の性能目標 | 実測条件は保持し、設計checkerの成功で達成扱いしない |

この設計案が既存specの解釈を変更する場合、実装PRで対応specとfeature manifestを同時更新する。今回のDraftだけで現在のruntime契約を無言変更しない。

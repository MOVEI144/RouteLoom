# SDK v1 — ゼロタッチ参加・機器鍵・削除・NVS上限（設計Draft）

設計版 **0.1-draft / 2026-09-23**。基点：Wire v2 commit `98c37be`（32bit epoch／48bit counter）。対象：統合先KGuardの製品要求（ゼロタッチ参加、KGuardによる参加判定、未割当機器の報告、隣接現場への誤参加防止、削除と世代、自動高速再参加、機器鍵による暗号化とgroup鍵）と Issue #37（ピアごとのNVSキー無制限増殖）。

**これは設計文書であり、実装・監査・実機認定の報告ではない。** このbranchで実装したのは §「実装済みの範囲」に列挙した小さな部品だけである。ここに書くbyte列・ラベル・数値はレビュー対象の採用案で、共通golden vectorと独立レビューを通るまで凍結しない。開発用PSK profileを本番へ昇格させるものでもない。

## 読み順

| 文書 | 解決する問題 |
|---|---|
| [01 要求・信頼構造・脅威モデル](01-overview-threat-model.md) | KGuard要求と#37の対応表、登場者、鍵の所有者、守るもの／守らないもの |
| [02 ゼロタッチ参加](02-zero-touch-join.md) | 機器ID＋機器鍵＋trust anchorだけで、割当先の現場にだけ参加する手順。状態機械、RLD1本文、EDHOC各メッセージの長さ、proxy中継、KGuardへの問合せ、重複現場 |
| [03 鍵階層](03-key-hierarchy.md) | 機器鍵→link鍵／E2E鍵／authority channel／network group鍵。導出、epochとWire v2の対応、SecurityProviderの変更、group鍵の配布・更新・削除時rekey |
| [04 削除・失効・世代](04-removal-revocation.md) | 失効集合RRS1、世代下限、伝播、削除された機器が見る挙動 |
| [05 NVS状態の上限（#37）](05-nvs-state-37.md) | ピアごとのcounter/replay recordを廃止する安全条件、LRUの再開cache、NVS entry予算、partition推奨、開発profileの暫定策 |
| [06 高速再参加](06-fast-rejoin.md) | 再起動・停電・中継器故障からの自動復帰。再開handshake RLRES1、費用の上限、sleep端末、一斉復電 |
| [07 Host（KGuard）API・事務所tooling](07-host-api-tooling.md) | API1 verb、event、USB HostOps、authorityの永続化、routeloom-provisionの変更 |
| [08 実装計画・試験・未決事項](08-implementation-plan.md) | PR単位の段階計画、host試験・golden vector・HIL、受入ID、製品責任者の判断が必要な事項 |

同じKGuard要求から派生し、portable coreに実装済み（host試験済み、RF未認定）の設計：[100台・1 gateway向けの経路スケール設計](routing-scale.md)（issue #41）と、その木を使う[group／ALL配送と送信元ごとの順序](group-delivery.md)（ALARMの全台配送、群への表示更新、集約確認とrepair、ORDERED、USB HostOps 0x50〜0x52）。group配送はGKを使わず、開発PSKの`SecurityScope::Group`で保護する。これらの状態はすべて静的確保なので、[静的RAMの予算・role別profile・CI guard](ram-budget.md)でESP32-C3 imageの残量とCIの閾値（8 KiB）を管理する。

既存文書との関係：[05 本番機器認証](../host-security-readiness/05-production-security.md)が選んだ **EDHOC（RFC 9528）method 0／suite 2** とExporter方針を引き継ぎ、[04 provisioning lifecycle](../sdk-completion/04-provisioning-lifecycle.md)の二重slot記録・manifest・失効の規律を再利用する。[06 membership admission](../autonomous-mesh/06-membership-admission.md)の6状態とRLD1許可kind集合{1,2,3,5,6}は変えない。

## 今回の決定（要約）

1. **事務所で書くのは現場に依存しない情報だけ**：NodeId、機器鍵（可能なら機器内生成）、組織のDevice CAが署名したDevCert、現場authorityを検証するためのSite CA公開鍵（≤2）。network id、現場鍵、scope鍵、channelは書かない（新記録RLI1）。
2. **参加の本人確認はEDHOC method 0で機器とSite Authority（現場PC上）が直接行う**。近隣memberはRLD1とWire bootstrapを運ぶproxyにすぎない。機器はInitiator、身元（DevCert）はmessage_3で暗号化して送る。
3. **参加可否はKGuardが決める**。Site Authorityはmessage_3で検証したDevCertをKGuardへ「参加要求」として渡し、allow／pending（未割当＝発見済み機器として表示）／deny（他現場に割当）を受けてmessage_4で返す。allowの前にauthority台帳へcommitする。
4. **現場の分離は割当から導く**：参加結果に含まれるMemberCert（Site Authority署名）がnetwork・site・世代を束縛する。link確立はMemberCertの相互検証を要し、他現場のmemberとは暗号的に結べない。現場鍵を焼き込まないので、焼き込み鍵による分離もない。
5. **セッション鍵はhandshakeごとに新しく、RAMにだけ置く**（EDHOCまたは双方nonceを使う再開RLRES1）。これによりピアごとの永続counter/replay recordが不要になり、#37の根本原因（削除できないNVSキー）を取り除く。永続するのは固定slot数の再開cacheだけで、LRUで追い出してよい（追い出しの帰結はfull handshakeのみ）。
6. **broadcast・一対多にはnetwork group鍵（GK）**。Site Authorityが生成し、機器ごとのauthority channelで配る。定期（24時間）と削除時に更新し、削除された機器には新GKを渡さない。group鍵はmember認証であって送信元本人の証明ではない。
7. **削除は失効集合RRS1（Site Authority署名、完全置換、epoch順）**で近隣が執行する。削除された機器は署名付きRemovalNoticeを検証できた場合にだけ現場状態を消去して未割当へ戻る。偽の拒否ヒントでは自分を消さない。

## 実装済みの範囲（このbranch）

| 部品 | 場所 | 証拠 |
|---|---|---|
| HKDF-SHA-256（RFC 5869） | [kdf.hpp](../../../components/routeloom/include/routeloom/kdf.hpp)／[kdf.cpp](../../../components/routeloom/src/kdf.cpp) | RFC 5869 付録A.1〜A.3のPRK/OKMと引数拒否を[test_kdf.cpp](../../../tests/cpp/test_kdf.cpp)で検査 |
| SecurityProviderのsession API（P4-1）：`tx_epoch`／`context_state`、`SessionInstaller`、予約scope `GroupLink`＝3、MeshNodeの保留配線 | [security.hpp](../../../components/routeloom/include/routeloom/security.hpp)、[03 §8.1](03-key-hierarchy.md) | 既定実装で全byte不変（V1-K10）、test Providerでの保留・epoch・非再使用を[test_session.cpp](../../../tests/cpp/test_session.cpp)で検査 |
| 導出labelとinfo形式の凍結（P1-4：group鍵、RLRES1、AuthorityEnvelope header、AEAD nonce） | [key_schedule.hpp](../../../components/routeloom/include/routeloom/key_schedule.hpp)、`host/routeloom-keysched` | 独立Python生成器の`protocol/sdkv1-golden/derivations/`にC++（[test_key_schedule.cpp](../../../tests/cpp/test_key_schedule.cpp)）とRustがbyte一致（[03 §2.2](03-key-hierarchy.md)） |
| RLRES1の状態機械（P1-5、単独class、両role） | [rlres1.hpp](../../../components/routeloom/include/routeloom/rlres1.hpp) | replay・反射・古いepoch／世代・別現場・壊れた入力・順序違い・格下げ・表の枯渇を[test_rlres1.cpp](../../../tests/cpp/test_rlres1.cpp)と`fuzz_rlres1`で検査（[06 §2.2.1](06-fast-rejoin.md)） |

それ以外（EDHOC統合、証明書codec、RLI1/RLS1/RRS1、RLRES1のNode・carrier配線、group鍵の配布・更新、USB/API1、tooling、partition変更）は**未実装**。

## この設計で主張しないこと

- EDHOC自体の安全性以上のものを主張しない。RouteLoom独自部分（RLRES1、EAD形式、group鍵の使い方、RRS1）は独立レビューと共通vectorが済むまで**未検証**。
- 信頼できる時刻が無い構成で、分断された群への失効の即時性を保証しない（[04](04-removal-revocation.md) §6）。
- group鍵で送信元を認証できるとは言わない。受信側再起動をまたぐgroup frameのreplayは、GK寿命内で起こり得る（[03](03-key-hierarchy.md) §6.5）。
- 処理時間・電力・airtimeの数値は、明記がない限り計画上の推定であり実測ではない。C3でのECC処理時間は**未測定**。

# 08 — 実装計画・試験計画・未決事項

## 1. 段階とPR

各PRは単独でレビュー・revert可能な大きさにする。既存のWire v2 byte列・FrameType番号・MembershipState値・開発profileのgolden vectorは、明記したPR以外で変えない。新機能は能力交渉（capability bit／feature flag）が成立した組合せだけで有効にし、未対応はUnsupportedを返す。

| PR | 内容 | 依存 | 主な試験 |
|---|---|---|---|
| **P0 — #37の即時緩和（開発profile、protocol変更なし）** | | | |
| P0-1 | NVS予算model（`tools/`のPython）とCI検査、reference/bridge firmwareに`rlsec` partition（64KiB）、`rlcounter`/`rlreplay`を`nvs_open_from_partition`で移動、`rlboot`は既定`nvs`（**このbranchで実装済み**：bridgeは128KiB、examples/espnow_nodeも同じ構成。実機未試験、[05 §9](05-nvs-state-37.md)） | なし | V1-N03, V1-N07 |
| P0-2 | 過去epochの`c*`掃除＋`cmax`証人、永続ピア数上限と`PEER_STATE_CAPACITY`（**このbranchで実装済み**：portable coreでhost試験、[05 §9](05-nvs-state-37.md)） | P0-1 | V1-N04, V1-N05 |
| **P1 — 部品（hostのみ、共通vector）** | | | |
| P1-1 | HKDF-SHA-256（**このbranchで実装済み**） | なし | V1-K12 |
| P1-2 | RLCW1証明書codec（DevCert/SiteCert/MemberCert）C++とRust、`protocol/sdkv1-golden/`（**このbranchで実装済み**：[rlcw1.hpp](../../../components/routeloom/include/routeloom/rlcw1.hpp)、Rust `routeloom-provision::sdkv1::cert`、独立Python生成器の共通vector。決めた細部は[vector README](../../../protocol/sdkv1-golden/README.md)） | P1-1 | V1-J14（証明書部分） |
| P1-3 | RLI1/RLS1/RRS1/RLP1のcodecと二重slot store（trust_storeの規律を再利用）、電源断注入（**このbranchで実装済み**：[sdkv1_records.hpp](../../../components/routeloom/include/routeloom/sdkv1_records.hpp)／[sdkv1_store.hpp](../../../components/routeloom/include/routeloom/sdkv1_store.hpp)、全write・全byte境界の電源断試験。RLS1とRRS1記録にA/B用`commit_seq`を追加。NVS adapterはP7-1で実装） | P1-2 | V1-J08, V1-N02 |
| P1-4 | 導出labelとinfo形式の凍結（group、RLRES1、AuthorityEnvelope）、C++/Rust vector（**このbranchで実装済み**：[key_schedule.hpp](../../../components/routeloom/include/routeloom/key_schedule.hpp)、`host/routeloom-keysched`、独立Python生成器`tools/gen_sdkv1_derivation_vectors.py`→`protocol/sdkv1-golden/derivations/`、[03 §2.2](03-key-hierarchy.md)） | P1-1 | V1-K01, V1-F03 |
| P1-5 | RLRES1の状態機械（portable）と攻撃試験（**このbranchで実装済み**：[rlres1.hpp](../../../components/routeloom/include/routeloom/rlres1.hpp)の単独`rlres1::Engine`、攻撃試験とfuzz、[06 §2.2.1](06-fast-rejoin.md)） | P1-4 | V1-F02 |
| **P2 — EDHOC** | | | |
| P2-1 | libedhoc（05で固定したSHA、MIT）をvendor、bounded memory backend、micro-ecc／PSAのcrypto callback、RFC 9529 vectorをhostで実行、NOTICE更新（**このbranchで実装済み**：libedhoc `c8857b62…`＋zcbor 0.8.1＋host用TF-PSA-Crypto AES/CCMをvendor（zcborの長さ0のprotected header修正と、PR #155のlibedhoc m2／m3／m4末尾余剰拒否修正をVENDORED.jsonの差分・blob idで固定）（[VENDORED.json](../../../components/routeloom/third_party/VENDORED.json)）、[edhoc.hpp](../../../components/routeloom/include/routeloom/edhoc.hpp)のsuite 2 backend（固定arena・固定key store、micro-ecc＋`kdf.hpp`、AES-CCMはhost builtin／ESP-IDFはPSA hook）、[RFC 9529 §3／§4](../../../protocol/edhoc-rfc9529/README.md)とmethod 0＋RLCW1 MemberCertの往復をhost試験。末尾余剰はC++／Rust共通の6拒否vectorでも検査。P4第2段でfirmware OwnerのMember EDHOC／参加経路へ配線済み（実機未試験）。kcwt値渡しはlibedhoc未対応） | なし | RFC 9529 |
| P2-2 | C3/S3/C5でEDHOCの署名・検証・ECDH時間、stack、heapを実測（未実施、#99。以後のtimeout・並列度の根拠） | P2-1 | V1-J15, V1-F06（一部） |
| P2-3 | join用EAD（JoinIntent/SiteOffer/JoinRequest/JoinResult/SitePackage）codecとRust mirror（**このbranchで実装済み**：[sdkv1_ead.hpp](../../../components/routeloom/include/routeloom/sdkv1_ead.hpp)、Rust `host/routeloom-join`、04 §6.1のRemovalNoticeも含む。独立Python生成器`tools/gen_sdkv1_ead_vectors.py`の[共通vector](../../../protocol/sdkv1-golden/ead/README.md)、fuzz。EAD labelと未定点は[02 §6.3](02-zero-touch-join.md)、AssignmentTicketの形式は未定で、A2の機器はfail closed） | P1-2 | V1-J12, V1-J14 |
| **P3 — 搬送とSite Authority** | | | |
| P3-1 | RLD1 body v3（ZeroTouch DISCOVER/OFFER）、BootstrapAuth phase 4〜6、1024B組立object、admission・`semantics.json`更新、fuzz（[sdkv1_join_transport.hpp](../../../components/routeloom/include/routeloom/sdkv1_join_transport.hpp)と[共通vector](../../../protocol/sdkv1-golden/join-transport/README.md)をportable実装・host試験済み。kid参照＋Credential EAD label 65541を使用）。当時残ったfirmware／MeshNodeへの配線はP4第2段（PR #141）で完了。実機未試験 | P2-3 | V1-J10, V1-J11 |
| P3-2 | `JoinProxy`／`JoinRelayGateway`とUSB join relayをportable実装・host試験済み（[sdkv1_join_relay.hpp](../../../components/routeloom/include/routeloom/sdkv1_join_relay.hpp)、USBは衝突を避け**0x60〜0x63・capability bit 8**、[02 §7.4](02-zero-touch-join.md)）。#113のcallback再入拒否、#116のrelay v2／RelayBook（追い出し・proxy再起動後の重複排除）も回帰試験済み。MeshNode／gateway参加／Host配線はP4第2段で完了。実機未試験 | P3-1 | V1-J02, V1-H08 |
| P3-3 | `routeloom-host`のSite Authority service（store、EDHOC responder、台帳）、API1 `join.*`/`devices.discovered.*`/`members.*`/`site.status`、KGuard mock client（**このbranchで実装済み**：`--site-authority DIR`、pure RustのEDHOC responder `host/routeloom-edhoc`（RFC 9529 §3を両roleでbyte一致、libedhocとのmethod 0 join transcriptを両方向でbyte一致、[protocol/edhoc-interop](../../../protocol/edhoc-interop/README.md)）、SQLite台帳（hash chain、MemberCert・DAMS・RRS1・GK・発見済み・参加要求）、判定engine、API1と`membership.revoke`、`routeloom-client::site`の`SiteAdmin`と`KGuardMock`。P3-3時点で未接続だったUSB 0x60〜0x63・authority channel・GK配布・RRS1配布は後続P4／P5／P6で結線済み。証明書値渡しのEAD label 65541（P3-1で凍結）とDAMSのExporter context（P3-4で凍結）。機器側EDHOC arenaは2048Bに引き上げ済み（[07 §2.4](07-host-api-tooling.md)）） | P2-1, P3-2 | V1-J03, V1-J09, V1-H01〜H07 |
| P3-4 | 機器のportable `Joiner` FSM、RLS1耐久commit／Reconcile、重複現場の候補表をPR #123／#124で実装。二現場C++ simulator 53件とRust実Site Authorityへのlive E2E 4件でhost検証済み。MeshNode／firmware／USB daemon配線はP4第2段で完了。HILはP8-1へ残る。P3-5（ticket再試行）は任意・未採用、A2はfail closed（[02 §10.4](02-zero-touch-join.md)） | P3-1, P1-3 | V1-J01, V1-J04〜J07, V1-J13 |
| P3-5 | pending ticketによる安価な再試行（任意） | P1-5, P3-3 | V1-J03 |
| **P4 — セッションengine** | | | |
| P4-1 | SecurityProviderのAPI追加（`tx_epoch`/`context_state`、`SessionInstaller`、scope 2/3）とNode配線。開発Providerは設定値を返し挙動不変（**このbranchで実装済み**：host試験、scope番号は`Group`＝2を維持し`GroupLink`＝3、C ABIのsession callbackは延期、[03 §8.1〜8.2](03-key-hierarchy.md)） | なし | 既存全試験、V1-K10 |
| P4-2 | PR #133でRAM session Provider、耐電断membership／RLP2、Member EDHOC／RLRES1の`HandshakeEngine`をportable実装。PR #141でrouted bootstrap、`SecurityCoordinator`、参加FSM handoff、USB gateway join、firmware `EspNowSecurityOwner`／MeshNodeへ結線。PR #156で未使用のlifecycle admission行列を除きrecovery-control gateに一本化し、resumeをRLP2へ統一。旧`rlres`のRLP1 blobは存在確認後に消去し、RLP2 slot数を起動時に照合する。PR #158でZeroTouchをJoinerへ直接渡してRelayStatusも受理し、Linkのcookie・EndのR1認証後にflight調停を確定。RLRES1 responderのnonce消費をadmission gate後へ移し、join packageの`rs_epoch`を取得目標へ伝搬。#132の16 slot/poll探索とm4搬送受理後installは充足。#60-2の失効永続化・#60-4の秘密saltによるslot導出もhost試験・ESP-IDF build済み。正規End m1の既存flight中の調停は[#157](https://github.com/MOVEI144/RouteLoom/issues/157)、実機・HILは未試験 | P2-1, P1-5, P4-1 | V1-K02〜K04, V1-F01, V1-F04 |
| P4-3 | PR #141でrouted E2E EDHOC／RLRES1とgateway対称鍵枠を接続。PR #144／#149でboot witness、Owner sleep保存・復元（親binding、全work drain、RTC counter先行更新、信頼できる経過時間上限）を接続・host試験済み。F07のRTCドリフト／起動遅延の実測・上限確定は[#148](https://github.com/MOVEI144/RouteLoom/issues/148)、P8 HILは[#99](https://github.com/MOVEI144/RouteLoom/issues/99) | P4-2 | V1-F05, V1-F07 |
| P4-4 | PR #144／#149でDevRam pairwise RAM context engine、加入なしadoption、group boot、旧`c*`/`f*`/`r*`の限定purgeと独立耐久markerを配線・電断試験済み。**公開既定はDevRam**、LegacyFixtureは明示選択のみ。旧版機でrlsecが満杯かつSDK namespace未作成時の読み取り専用復旧は[#152](https://github.com/MOVEI144/RouteLoom/issues/152)に残る | P4-2 | V1-N01, V1-K10（更新） |
| **P5 — group鍵** | | | |
| P5-1 | PR #126（AuthorityEnvelope・USB 0x64〜0x67・共通vector）、#137（機器GK耐久FSM・GroupLink／GroupEnd・Member scope）、#131（Site AuthorityのGK台帳・更新・atomic revoke）、#143（mesh／USB／Host／Owner実搬送）を結線済み。PR #151で実C++ portable security部品⇄Rust Site Authorityのjoin→GK配布／更新／pull／失効除外をlive E2E試験済み。[harnessの境界](live-e2e-harness.md)は単一機器・模擬radio／flash。実firmware複数機器は[#150](https://github.com/MOVEI144/RouteLoom/issues/150) | P3-3, P4-3 | V1-K05〜K07, V1-K09, V1-K11 |
| P5-2 | PR #145でbit7 nonce-bound grant付きGroupLink broadcast経路広告をmesh／ESP-NOWに選択式で配線。既定OFF、grant不足などはunicast fallback。100台host simulationでloop／false route 0。全mesh probeの推定管理airtime約2.0M µs/sは出荷包絡を超えるためOwnerのsparse probe・RF検証後に有効化 | P5-1 | V1-K08 |
| **P6 — 削除** | | | |
| P6-1 | PR #129（RRS1発行・gossip・peer執行）、#136（RemovalNotice・RLX1消去・600秒holdoff）、#147（Host配布、OwnerのP4 session／resume／経路失効、group送信元拒否、SelfRevoked→ZT）を結線済み。PR #151のlive E2Eで配送・執行・RemovalNotice・電断再起動を確認。PR #155で`SessionProviderMux`／`RtcWriteAheadProvider`のgroup送信者失効判定を委譲し、coordinator経由のcached／repair／hold経路をhost試験。v1のHostは失効履歴のあるNodeIdを再発行せず、再参加には新NodeIdでの再provisionを要求する。割当世代とGK epochの結合はv1.1の[#146](https://github.com/MOVEI144/RouteLoom/issues/146)、旧規則で再発行済みのsite DB検出・移行は[#154](https://github.com/MOVEI144/RouteLoom/issues/154)。複数機器gossipの実Owner結合は[#150](https://github.com/MOVEI144/RouteLoom/issues/150)、HILは[#99](https://github.com/MOVEI144/RouteLoom/issues/99) | P5-1 | V1-R01〜R07, V1-R09, V1-R10 |
| P6-2 | PR #140で署名付きGrantRenew／PREPARE／COMMITとRLX1電断安全cutover、PR #147でHost driver・Owner AdoptNetwork／再起動回復を接続。PR #151のpipe E2EでPREPARE／COMMIT・旧revision再発行・電断を確認。実firmware複数機器とHILは#150／#99 | P6-1 | V1-R08 |
| **P7 — 事務所tooling** | | | |
| P7-1 | `routeloom-provision`の`DeviceCaSigner`、DevCert／RLI1、PoP、`rlsec` NVS image・CSV、`routeloomctl provision-devca-keygen／pop-challenge／devcert／identity`、4 storeのfirmware NVS adapterを実装済み。PR #125で機器内鍵生成＋PoPのUSB保守console `keygen`／`identity`も配線・host試験／firmware build済み（[07 §6.1〜6.2](07-host-api-tooling.md)）。実機entropy・console・鍵注入未試験。旧版機の満杯rlsec復旧は#152 | P1-2, P1-3 | V1-H09 |
| P7-2 | `site-cert`コマンド、在庫出力（**このbranchで実装済み**：`sdkv1::siteca`と`routeloomctl provision-siteca-keygen／site-cert`、正式な在庫出力`inventory.json`。[07 §6.2](07-host-api-tooling.md)） | P7-1 | V1-H09 |
| **P8 — 認定** | | | |
| P8-1 | **未実施**（#99）：HILで2現場（2 host）の重複配置、6台以上の一斉復電、削除gossip、電源断行列を検証。F07のRTC実測は#148 | 全部 | V1-J05, V1-F06, V1-N08, V1-R09 |
| P8-2 | 先行する独立レビュー2本の指摘修正はPR #155／#156／#158でmerge済み。RouteLoom独自部分（RLRES1、EADの束縛、group鍵の使い方、RRS1、context id対応）の最終受入記録と未解決重大指摘の確認は[#100](https://github.com/MOVEI144/RouteLoom/issues/100)に残る | P1〜P6 | — |

P0-1／P0-2、P1-1〜P1-5、P2-1、P2-3、P3-1〜P3-4、P4-1〜P4-4、P5-1／P5-2、P6-1／P6-2、P7-1／P7-2は上記の**ソフトウェア・host試験／firmware build範囲**でこのbranchに含まれる。PR #155／#156／#158の最終レビュー修正もmerge済み。PR #155ではC ABIのgroup receiverのヘッダー契約を訂正した（型・配置・関数は不変）。P2-2とP8-1／P8-2は未完了。P3-5は任意で未採用。個別の後続課題は[#146](https://github.com/MOVEI144/RouteLoom/issues/146)／[#148](https://github.com/MOVEI144/RouteLoom/issues/148)／[#150](https://github.com/MOVEI144/RouteLoom/issues/150)／[#152](https://github.com/MOVEI144/RouteLoom/issues/152)／[#154](https://github.com/MOVEI144/RouteLoom/issues/154)／[#157](https://github.com/MOVEI144/RouteLoom/issues/157)。

関連する基盤補修もmerge済み：#51（RCR2／RLF1のconfig復旧とRTM1 root更新）、#110（group sleep drain）、#113／#116（relay再入・重複排除）、#117（ExpectedReply peer leaseをOwnerへ配線）、#34（連続boot失敗時のtimed deep sleep）、#55／#47（USB credit、探索／migration窓、受入遅延目標）、#60（単調時刻とTX完了でのOwner起床）。いずれもhost回帰試験／対象buildの証拠であり、実NVS電断、TX間隔・RAM／stack、RFの実測とは区別する。

## 2. 試験計画

| 層 | このbranchでの証拠 | 残る範囲 |
|---|---|---|
| portable C++（CTest） | P3-4 Joiner／relay、P4 session・boot／RTC／DevRam、P5 authority／GK／broadcast、P6 RRS1／gossip／RLX1／cutover、P7保守consoleをhost試験。電源断、再入、失効後の拒否、境界値の回帰を含む。GCC／ClangとsanitizerをCIで実行 | 実firmware Owner／MeshNodeを複数機器で結ぶ試験は#150 |
| Rust（cargo test） | Site Authority台帳、API1、GK更新／失効／cutover、USB adapterを試験。PR #151のlive pipe E2Eは実C++ portable security部品とRust Site Authorityを接続し、旧Joiner試験と合わせ15件をCIで実行（[境界](live-e2e-harness.md)）。`joiner_interop`はC++ peer不在ならskipし、専用CI jobはpeerをbuildして実行する | 1台構成で模擬radio／flash。実firmware Owner・複数機器・P4 session／route執行は#150 |
| 共通golden | 証明書・記録・EAD・DAMS、RLD1 v3／relay v2、RLRES1／P4 session、GK／AuthorityEnvelope／RRS1／cutover、USB join relay 0x60〜0x63・authority 0x64〜0x67をC++／Rustで共有し、独立Python生成器の再生成差分をCIで確認 | 実機上のUSB・RFでの相互運用ではない |
| EDHOC／fuzz | libedhoc suite 2のRFC 9529公開trace、Rust responderとのbyte一致、参加EADと不正入力、join／RRS1等のfuzz corpusをhost検査 | P2-2のC3/S3/C5時間・stack・heap実測は#99 |
| simulation／build | 二現場Joiner、100台RRS1 gossip／broadcast route、Owner sleep／DevRam・cutoverのhost模擬。ESP-IDF C3/S3/C5のOwner／保守構成はPR #149時点で15/15 build・静的RAM gate通過 | 実機RAM・電波・一斉復電の測定ではない |
| HIL／RF | 未実施 | #99のP2-2／P8-1、#148のF07 RTCドリフト・起動遅延、RF・実NVS電断を[HIL harness](../../hil.md)で記録する |

## 3. 受入ID一覧

参加 V1-J01〜J15（[02](02-zero-touch-join.md) §14）、鍵 V1-K01〜K12（[03](03-key-hierarchy.md) §10）、削除 V1-R01〜R10（[04](04-removal-revocation.md) §11）、NVS V1-N01〜N08（[05](05-nvs-state-37.md) §8）、高速再参加 V1-F01〜F08（[06](06-fast-rejoin.md) §9）、Host V1-H01〜H09（[07](07-host-api-tooling.md) §8）の計62件。`tools/check_review_contracts.py`は設計表のID集合とテストソース内の正確なタグを機械照合し、変異試験で検出力を確認する。タグの存在はID全条件の達成を証明しない。同じIDでもportable／host部分と実機・HIL部分は別の証拠として扱う。

| 範囲 | 実行済みの部分 | 未完了・範囲外 |
|---|---|---|
| P0〜P3 | K12、J08／J12／J14のcodec・store・検査部分、N02／N04／N05／N07、F02／F03の単体部分、RFC 9529、J01〜J07／J09〜J11／J13、H01〜H08のportable・Rust Site Authority・二現場simulator／pipe部分。P3-4のRust実Site Authority⇄C++ Joiner live E2E 4件 | J05／J15、N03／N08などの実機／HIL部分。P3-5 ticketは任意・未採用、A2はfail closed |
| P4（#133／#141／#144／#149／#156／#158） | K02〜K04・K10、F01／F05、N01のsession／boot／DevRam／purgeをhost試験。F07のOwner sleep復元はhost simulationで実行。ZeroTouch demux、handshake調停、RLRES1 nonce順、`rs_epoch`取得目標、RLP2単一路を回帰試験 | F04は中継器停止時に予備経路へ暗号handshake 0件で切り替わるhost試験なし。F01はauthority／KGuard照会0件のhalfが未検証。F07のRTC実測と上限確定は#148。P2-2／P8-1の実機確認は#99。旧版機の満杯rlsec復旧は#152。flight中の正規End m1の調停は#157 |
| P5（#126／#137／#131／#143／#145／#151／#155） | K05〜K09／K11のGK導出・保存／配布／更新・broadcast opt-inをportable／Rust試験。実C++ security部品⇄Rust Site Authorityのlive E2EでJoinConfirm、Update／Activate、pull、削除後の配布拒否を確認。Provider委譲後のgroup送信者失効拒否をcoordinator経由で試験 | K05は同一boot replay拒否・tx_boot後退拒否・表満杯拒否のうち未検証half、K09は削除者Member DISCOVERの無言dropが未検証。broadcastは既定OFF。Ownerのsparse probe、実firmware複数機器（#150）、RF／HILは未実施 |
| P6（#129／#136／#140／#147／#151／#155） | R01〜R08／R10のRRS1・RemovalNotice・消去／holdoff・GrantRenew／cutoverをportable／Rust試験。100台gossipはsimulation、R07／R08とSelfRevokedはpipe E2Eで確認。v1の失効NodeId非再発行と新NodeId再provisionをhost試験 | R06は偽REVOKED hint・異現場SAK署名の非消去halfが未検証。R09の実機gossip／電断HILは#99／#150。割当世代とGK epochの結合はv1.1の#146、旧規則で再発行済みsite DBの移行は#154 |
| P7（#125） | H09のPoP、機器内鍵生成・保守console、SiteCert・inventory、4 store NVS adapterをhost試験／firmware build | 実機entropy／console／鍵注入・custodyは未確認。旧版機の復旧は#152 |

F04にはhost試験がない。N06は`rlboot`欠落・後退・耐久化不明の全注入条件とGroupEnd／GroupLink送信0の未検証halfが残る。J15／N08／F06はHIL専用でhostタグを要求しない。これらの部分試験をV1-J・K・R・N・F・H全IDの完了として数えない。実firmware結合、実機測定、独立レビューの受入記録をP8で揃える。

## 4. 本番を名乗る条件

`security_profile() == Production`を返してよいのは、次を**すべて**満たすbuildだけ。P3-4〜P7のソフトウェア結線やhost E2Eの完了は、この判定を変更しない。

1. P2-1のEDHOCがRFC 9529 vectorを通り（このbranchでhost試験：suite 2の§3と§4。§2はsuite 0でbackendの対象外）、P1-4のRouteLoom vectorがC++/Rustで一致。
2. V1-J・K・R・N・F・Hのhost試験がすべて通過し、§3のF04とK05／K09／N06／F01／R06の未検証half、[#150](https://github.com/MOVEI144/RouteLoom/issues/150)の実Owner結合、旧規則で再発行済みsite DBの検出・移行（[#154](https://github.com/MOVEI144/RouteLoom/issues/154)）など未閉鎖の受入境界を解決している。v1では失効NodeIdの非再発行を維持し、割当世代とGK epochの結合はv1.1の[#146](https://github.com/MOVEI144/RouteLoom/issues/146)で扱う。§3の部分試験だけでは未達。
3. P2-2とP8-1のHIL実測（[#99](https://github.com/MOVEI144/RouteLoom/issues/99)）が記録され、timeout・並列度、F07のsleep経過時間上限（[#148](https://github.com/MOVEI144/RouteLoom/issues/148)）がその実測に基づく。
4. P8-2の独立レビュー（[#100](https://github.com/MOVEI144/RouteLoom/issues/100)）で未解決の重大指摘が無い。
5. 配備tier（T1/T2）、Device CA／Site CAの鍵保管・custody、製造／注入／移管手順（[04 provisioning §4.10](../sdk-completion/04-provisioning-lifecycle.md)）が決定・検証済み。

**現状は未達**。PR #155／#156／#158で先行する独立レビューの指摘を修正したが、P8-2の受入記録と静的受け入れ検査、HIL（条件3）、鍵custody／tier（条件5）が未了であり、host受入も§3の部分証拠に留まる。`EspNowSecurityOwner::security_profile()`は`Development`を返し、Nodeは`SECURITY_PROFILE_EXPERIMENTAL`を出す。DevRamが公開既定、LegacyFixtureは明示選択のみ。Member EDHOC構成を含め`Production`と表示せず、KGuardの本番配備に使わない。

## 5. 既存文書との整合（実装時に同時改訂するもの）

| 文書 | 改訂点 |
|---|---|
| [04 provisioning lifecycle](../sdk-completion/04-provisioning-lifecycle.md) | 最初の物理信頼をSite CA anchorへ移す（§4.4、§4.11「No in-band bootstrap of first trust」）。RLC1はdev/bench用。§4.8のu16 epoch windowはWire v2では不要（`credential_epoch_for_session`の扱い） |
| [05 本番機器認証](../host-security-readiness/05-production-security.md) | MembershipGrant配列→MemberCert（CWT）。Exporter label 32770〜32772の追加。「16bit key epoch」の記述をcontext idへ |
| [identity-membership](../../spec/identity-membership.md) | ZeroTouch classの例外（network 0の探索）、REMOVED後の扱い |
| [security](../../spec/security.md) §4 | 本番profileのreplay/counterはRAM（鍵がhandshakeごとに新しい）。開発profileの記述は維持 |
| [wire-protocol](../../spec/wire-protocol.md) | 本番profileでのlink/end epochの意味（context id）、broadcast frameのfield |
| [crash-time-resources](../../spec/crash-time-resources.md) | #37の行に対策と予算表への参照 |
| `protocol/semantics.json` | RLD1 body v3、BootstrapAuth phase 4〜6、ControlObject kind 5/6、Control subtype `StateEpochs`、USB sub 0x40〜0x46 |

## 6. 製品責任者の判断が必要な事項

| # | 問い | 推奨案 | 影響 |
|---|---|---|---|
| Q1 | Site Authorityをどこに置くか | 現場PC（`routeloom-host`内）。SAKをESP32に置かない | 新規参加・GK更新・削除にはPCが必要。既存memberの通信・再参加には不要 |
| Q2 | 誤参加防止をA1（KGuardの割当一意性に依存）とA2（本部署名の割当証明を機器が検証）のどちらにするか | 複数顧客・PC盗難が脅威ならA2 | A2はKGuard本部に署名鍵と発行API、事務所でRLI1に検証鍵 |
| Q3 | 信頼できる時刻（署名付きTimeSync）を提供するか | v1は無し（RRS1到達に依存） | 無い場合、分断中の群への失効は上限なし |
| Q4 | 警報（ポンプ過熱→全表示盤）に送信元の本人証明が要るか | 要るならpayload署名（64B）か宛先別E2E | group鍵だけでは「memberの誰か」までしか分からない |
| Q5 | 本番の鍵保管tier（T1平文NVS／T2 flash暗号化＋secure boot） | 少なくともT2を推奨（eFuseは不可逆のため別承認） | 事務所手順と量産時間 |
| Q6 | EDHOCライブラリ（libedhoc、MIT）への依存を認めるか | 認める（05の選定どおり） | 自作SIGMA-Iは監査負担が大きい |
| Q7 | KGuardが応答しない時の既定 | pending（機器は再試行） | 自動allowにすると割当前の機器が入る |
| Q8 | 1現場の規模上限、gatewayのhardware | 100台・gateway≤4。決定：gateway: S3/C3/C5（C3が容量設計の下限） | gatewayの再開slot 128件と`rlsec` 128KiB |
| Q9 | 削除された機器は自動で未割当に戻るか、物理リセットまで沈黙か | 自動で未割当へ（10分holdoff） | 沈黙を選ぶと再利用に現地作業が要る |
| Q10 | 隣接現場のKGuardに未割当機器が見えてよいか | よい（経路・RSSIを表示） | 見せない場合、未割当の報告自体ができない |
| Q11 | GK更新周期と削除時の露出窓 | 24時間、削除時は即時（連結群で1分程度を目標） | 周期を短くすると配布の電波負荷が増える |
| Q12 | 組織PKIの単位（全顧客で一つのOrg Rootか、顧客ごとのSite CAか） | 顧客ごとのSite CA | 共通だとA1で他顧客の現場にも入り得る |
| Q13 | partition変更に伴う既存機の再書込み（NVS消去）を許容するか | 許容（Wire v2でも既にNVS消去が必要） | 現場の既存機は事務所へ戻すか保守手順 |
| Q14 | RLD1 headerの機器IDが平文で見えることを許容するか | v1は許容 | 追跡を防ぐには仮名化（後続設計） |

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
| P2-1 | libedhoc（05で固定したSHA、MIT）をvendor、bounded memory backend、micro-ecc／PSAのcrypto callback、RFC 9529 vectorをhostで実行、NOTICE更新（**このbranchで実装済み**：libedhoc `c8857b62…`＋zcbor 0.8.1＋host用TF-PSA-Crypto AES/CCMをupstreamのままvendor（[VENDORED.json](../../../components/routeloom/third_party/VENDORED.json)）、[edhoc.hpp](../../../components/routeloom/include/routeloom/edhoc.hpp)のsuite 2 backend（固定arena・固定key store、micro-ecc＋`kdf.hpp`、AES-CCMはhost builtin／ESP-IDFはPSA hook）、[RFC 9529 §3／§4](../../../protocol/edhoc-rfc9529/README.md)とmethod 0＋RLCW1 MemberCertの往復をhost試験。firmwareからは未呼出。kcwt値渡しはlibedhoc未対応） | なし | RFC 9529 |
| P2-2 | C3/S3でEDHOCの署名・検証・ECDH時間、stack、heapを実測（以後のtimeout・並列度の根拠） | P2-1 | V1-J15, V1-F06（一部） |
| P2-3 | join用EAD（JoinIntent/SiteOffer/JoinRequest/JoinResult/SitePackage）codecとRust mirror（**このbranchで実装済み**：[sdkv1_ead.hpp](../../../components/routeloom/include/routeloom/sdkv1_ead.hpp)、Rust `host/routeloom-join`、04 §6.1のRemovalNoticeも含む。独立Python生成器`tools/gen_sdkv1_ead_vectors.py`の[共通vector](../../../protocol/sdkv1-golden/ead/README.md)、fuzz。EAD labelと未定点は[02 §6.3](02-zero-touch-join.md)、AssignmentTicketの形式は未定で、A2の機器はfail closed） | P1-2 | V1-J12, V1-J14 |
| **P3 — 搬送とSite Authority** | | | |
| P3-1 | RLD1 body v3（ZeroTouch DISCOVER/OFFER）、BootstrapAuth phase 4〜6、1024B組立object、admission・`semantics.json`更新、fuzz（**このbranchで実装済み**：[sdkv1_join_transport.hpp](../../../components/routeloom/include/routeloom/sdkv1_join_transport.hpp)のcodec・有界object slot・admissionと機器端`ZtJoinerLink`、独立Python生成器`tools/gen_sdkv1_join_transport_vectors.py`の[共通vector](../../../protocol/sdkv1-golden/join-transport/README.md)、`fuzz_sdkv1_join`。証明書はkid参照＋Credential EAD（label 65541）、`edhoc::Session`のEAD hookでm1〜m4の実長を確認。firmware・MeshNode未配線。決めた細部は[02 §3・§5.4・§6](02-zero-touch-join.md)） | P2-3 | V1-J10, V1-J11 |
| P3-2 | proxy中継（Wire 3/4/5/6のrelay object）、USB HostOps 0x40〜0x42、capability bit（**このbranchで実装済み**：`JoinProxy`・`JoinRelayGateway`（[sdkv1_join_relay.hpp](../../../components/routeloom/include/routeloom/sdkv1_join_relay.hpp)）、`UsbBridge::attach_join_relay`、Rust `routeloom-protocol::join_relay`、共通vector `protocol/usb-golden/join-relay`。USBは衝突回避で**0x60〜0x63・capability bit 8**（0x40〜0x42／bit 6はnode_status_v1、[02 §7.4](02-zero-touch-join.md)）。#116でWire relayとUSB参加中継を**v2**化（32B header＋両service epoch、18B chunk／reply、24B Query／Reply、RelayBook floor 128＋active 8、USB schema 2・capability bit 9、共通vector `protocol/sdkv1-golden/join-relay-v2`＋`protocol/usb-golden/join-relay-v2`、[02 §7.5](02-zero-touch-join.md)、[07 §4](07-host-api-tooling.md)）。relay portのMeshNode接続とgateway自身の参加は未実装） | P3-1 | V1-J02, V1-H08 |
| P3-3 | `routeloom-host`のSite Authority service（store、EDHOC responder、台帳）、API1 `join.*`/`devices.discovered.*`/`members.*`/`site.status`、KGuard mock client（**このbranchで実装済み**：`--site-authority DIR`、pure RustのEDHOC responder `host/routeloom-edhoc`（RFC 9529 §3を両roleでbyte一致、libedhocとのmethod 0 join transcriptを両方向でbyte一致、[protocol/edhoc-interop](../../../protocol/edhoc-interop/README.md)）、SQLite台帳（hash chain、MemberCert・DAMS・RRS1・GK・発見済み・参加要求）、判定engine、API1と`membership.revoke`、`routeloom-client::site`の`SiteAdmin`と`KGuardMock`。USB 0x60〜0x63への結線、authority channel（P5）、GKの配布・更新（P5）、RRS1の配布（P6）は未実装。証明書値渡しのEAD label 65541（P3-1で凍結）とDAMSのExporter context（P3-4で凍結）。機器側EDHOC arenaは2048Bに引き上げ済み（[07 §2.4](07-host-api-tooling.md)）） | P2-1, P3-2 | V1-J03, V1-J09, V1-H01〜H07 |
| P3-4 | 機器のportable `Joiner` FSM、RLS1の耐久commit／Reconcile、重複現場の候補表を実装済み。二現場C++ simulator 53件とRust実Site Authorityへのlive E2E 4件でhost検証済み。MeshNode／firmware／USB daemon配線とHILはP4-2／P8-1へ残す。P3-5（RLRES1 ticket再試行）は無効、A2はfail closed（[02 §10.4](02-zero-touch-join.md)） | P3-1, P1-3 | V1-J01, V1-J04〜J07, V1-J13 |
| P3-5 | pending ticketによる安価な再試行（任意） | P1-5, P3-3 | V1-J03 |
| **P4 — セッションengine** | | | |
| P4-1 | SecurityProviderのAPI追加（`tx_epoch`/`context_state`、`SessionInstaller`、scope 2/3）とNode配線。開発Providerは設定値を返し挙動不変（**このbranchで実装済み**：host試験、scope番号は`Group`＝2を維持し`GroupLink`＝3、C ABIのsession callbackは延期、[03 §8.1〜8.2](03-key-hierarchy.md)） | なし | 既存全試験、V1-K10 |
| P4-2 | `HandshakeEngine`、本番link EDHOC＋RLRES1（RLD1）、RLS1/RRS1で裏付けた`MembershipHooks`、本番buildだけ`UnavailableAuthenticator`を置換（要件：#60-2 — `MembershipHooks`はlocal失効をauthority ledgerへ耐電断永続化すること。controllerの`Revoked`はRAMのみで、再起動時`initialize`は`local_member`からfail-openに再評価する。#60-4 — replay/counter slot導出に秘密saltを含めること。公開のkeyless foldのままでは共有PSKを持つ内部者がNodeIdを選んで決定的に衝突を製造できる） | P2-1, P1-5, P4-1 | V1-K02〜K04, V1-F01, V1-F04 |
| P4-3 | E2E EDHOC/RLRES1（routed bootstrap）、gatewayの対称鍵枠、APPLIED leaseをboot sessionへ | P4-2 | V1-F05, V1-F07 |
| P4-4 | 開発ProviderをRAM context engineへ移行（RLRES1のRMS＝開発PSK）、旧`c*`/`f*`/`r*`を消す保守verb | P4-2 | V1-N01, V1-K10（更新） |
| **P5 — group鍵** | | | |
| P5-1 | authority channel（AuthorityEnvelope、USB 0x43〜0x45〔0x64〜0x67を推奨、02 §7.4〕）、GK保存・配布・更新・pull、GroupLink/GroupEnd、Member scope鍵をGKから導出 | P3-3, P4-3 | V1-K05〜K07, V1-K09, V1-K11 |
| P5-2 | broadcast経路広告（opt-in capability）。group delivery設計と同時にレビュー | P5-1 | V1-K08 |
| **P6 — 削除** | | | |
| P6-1 | RRS1の発行・gossip・執行、RemovalNotice、`membership.revoke`と段階表示 | P5-1 | V1-R01〜R07, V1-R09, V1-R10 |
| P6-2 | site_epoch cutoverとGrantRenew | P6-1 | V1-R08 |
| **P7 — 事務所tooling** | | | |
| P7-1 | routeloom-provision：`DeviceCaSigner`、devcert、identity、`rlsec` NVS image。firmwareの保守verb（機器内鍵生成＋所持証明）（**このbranchで実装済み（保守verbを除く）**：`sdkv1::{devca,pop,office,rlsec}`と`routeloomctl provision-devca-keygen／pop-challenge／devcert／identity`、所持証明の検証、`nvs_partition_gen`用CSV。P1-3の残りだった`rlsec`のNVS adapter（`sdkv1_blob_storage`＋ESP-IDF `nvs_sdkv1_store`、compile-onlyでfirmware未配線）も同時に実装。firmwareの保守verbは後続、[07 §6.1](07-host-api-tooling.md)） | P1-2, P1-3 | V1-H09 |
| P7-2 | `site-cert`コマンド、在庫出力 | P7-1 | V1-H09 |
| **P8 — 認定** | | | |
| P8-1 | HIL：2現場（2 host）の重複配置、6台以上の一斉復電、削除のgossip、電源断行列 | 全部 | V1-J05, V1-F06, V1-N08, V1-R09 |
| P8-2 | RouteLoom独自部分（RLRES1、EADの束縛、group鍵の使い方、RRS1、context id対応）の独立レビュー | P1〜P6 | — |

P0は他と独立して先に出せる。P0-1／P0-2とP1-1〜P1-5、P2-1、P2-3、P3-1、P3-2（firmware・MeshNode配線を除く）、P3-3（USB結線を除く）、P4-1、P7-1（保守verbを除く）はこのbranchに含まれる。

## 2. 試験計画

| 層 | 対象 | 方法 |
|---|---|---|
| portable C++（ctest） | codec、二重slot store、FSM（参加・proxy・RLRES1・GK・RRS1）、Provider API | 既存の`tests/cpp`形式。電源断・storage失敗注入は`test_fault_injection`の規律 |
| Rust（cargo test） | routeloom-provision、routeloom-host（Site Authority、API1、store） | 既存crateのtest。daemonはKGuard mockで端から端まで |
| 共通golden | 証明書、RLI1/RLS1/RRS1/RLP1、EAD、RLD1 v3、relay object（v2は`join-relay-v2`、旧v1は`join-transport/v1-history`）、RLRES1のtranscriptと鍵、group導出、AuthorityEnvelope、USB 0x40〜0x46（実装は0x60〜、02 §7.4。参加中継v2はschema 2・bit 9、02 §7.5） | `protocol/sdkv1-golden/`。独立したPython生成器（既存`tools/gen_*_vectors.py`と同じ流儀）。ECDSA署名はRFC 6979の決定的署名か、検証のみのvector |
| EDHOC | ライブラリ | RFC 9529の公開vector（試験専用鍵、本番鍵と分離） |
| fuzz | RLD1 v3本文、BootstrapAuth phase 4〜6、relay object、RRS1、EAD、RLP1 | `tests/fuzz`へ追加 |
| simulation | 2現場重複、proxy flood、削除gossip、一斉復電、sleep端末 | SimNetwork |
| HIL | EDHOC時間、参加時間、一斉復電、NVS実測、2現場 | [HIL harness](../../hil.md)。結果は証拠として保存し、未測定を実測と書かない |

## 3. 受入ID一覧

参加 V1-J01〜J15（[02](02-zero-touch-join.md) §14）、鍵 V1-K01〜K12（[03](03-key-hierarchy.md) §10）、削除 V1-R01〜R10（[04](04-removal-revocation.md) §11）、NVS V1-N01〜N08（[05](05-nvs-state-37.md) §8）、高速再参加 V1-F01〜F08（[06](06-fast-rejoin.md) §9）、Host V1-H01〜H09（[07](07-host-api-tooling.md) §8）。V1-K12（HKDF）、V1-K10（P4-1、Wire v2 golden vectorをProvider epoch経路で再現）、P1-2のV1-J14（証明書部分）・P1-3のV1-J08（store部分）・V1-N02（slot部分）・V1-R10（RRS1部分）・V1-H09（codec golden、P7-1の発行・PoP部分）、P1-4のV1-K01（HKDF／RLRES1部分、Exporter部分はP2）・V1-F03、P1-5のV1-F02（engine単体）、P2-1のRFC 9529 vector（§3のmethod 3／suite 2 traceと§4の不正message。method 0は同suiteのRLCW1往復で確認）、P2-3のV1-J12（MemberCert・SitePackageの各field不一致を「検証不成立」とする§10.2検査のhost試験と共通vector。保存・回避の動作はP3-4）・V1-J14（EAD部分：各EAD項目長とm1が1 frameに収まること・m4の予算を静的検査）、P3-1のV1-J14（EDHOC encoder込みの実長：kid＋Credential EADでm1〜m4＝55／362／341／353B）・V1-J10（hint・backoffで状態不変、host sim）・V1-J11（proxy側：relay 1件・m1 2秒1件・cookie前にmemoryを使わない。memberのDATA維持はMeshNode配線後）、P3-2のV1-J02（中継の往復とproxy slot解放、Wire routingはport模擬）・V1-H08（USB 0x60〜0x63のC++/Rust共通vectorとcapability無しのUnsupported）、P3-3のV1-J03・V1-J09（Site Authority側：未割当→pending→割当→次の試行でAllow、KGuard無応答→pending→後の決定が次の試行で反映。機器はRust Initiatorと`routeloom-join`の機器側検査で模擬し、実機の参加FSM配線（P4-2）は未実装）・V1-H01〜H04／H06／H07（host試験、H01のconfirmは受け口まで）・V1-H05（`committed`段階まで。配布はP5/P6）と#116のQ116（relay v2回帰、[02 §14](02-zero-touch-join.md)）、P0のV1-N04／V1-N05（host試験）・V1-N07（CIの予算model）がこのbranchで実行済み。V1-N03はhost modelのみ（HIL未実施）。P3-4のV1-J01・J04〜J07・J13、J12の保存0／回避、J08のFSM電断行列、J03/J09のFSM側再試行は二現場C++ simulatorで実行し、J01/J04/J05の正常・拒否・pending経路と電断再起動はRust実Site Authority相手のlive E2E 4件でも実行。J05のHIL部分とfirmware／USB接続は未実施。その他はplanned_not_run。

## 4. 本番を名乗る条件

`security_profile() == Production`を返してよいのは、次をすべて満たすbuildだけ。

1. P2-1のEDHOCがRFC 9529 vectorを通り（このbranchでhost試験：suite 2の§3と§4。§2はsuite 0でbackendの対象外）、P1-4のRouteLoom vectorがC++/Rustで一致。
2. V1-J・K・R・N・F・Hのhost試験がすべて通過。
3. P2-2とP8-1のHIL実測が記録され、timeout・並列度がその実測に基づく。
4. P8-2の独立レビューで未解決の重大指摘が無い。
5. 配備tier（T1/T2）と鍵保管（[04 provisioning §4.10](../sdk-completion/04-provisioning-lifecycle.md)）が決定済み。

それまで、実装済みの部分もEXPERIMENTALとして扱い、KGuardの本番配備に使わない。

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

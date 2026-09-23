# 02 — ゼロタッチ参加

機器が事務所で書かれた (NodeId, 機器鍵, DevCert, Site CA anchor) だけを持って現場に置かれ、割当先の現場にだけ参加するまでの手順。数値・byte列は採用案（未凍結）。EDHOCメッセージ長はRLCW1証明書の見積もりに依存し、実encoderの共通vector（[08](08-implementation-plan.md) P1）で確定する。

## 1. 入力と前提

| 項目 | 内容 | 由来 |
|---|---|---|
| 機器が持つ | RLI1（§2）：NodeId、機器鍵、kid、DevCert、Site CA公開鍵≤2（strict modeでは割当検証鍵を追加） | 事務所 |
| 機器が持たない | network id、site_id、MemberCert、GK、scope鍵、channel、Site Authorityの公開鍵 | 参加結果で受領 |
| Site Authority | SAK秘密鍵、SiteCert（Site CA署名、site_id・network_low32・site_epoch）、Device CA公開鍵（DevCert検証用）、台帳、KGuard接続 | 現場PC |
| member | 自分のMemberCert・GK・現場のSiteCert。`zero_touch_open`方針 | 参加済み |

暗号profile：[05 本番機器認証](../host-security-readiness/05-production-security.md) §1のRLPSEC1（EDHOC method 0＝双方署名、suite 2＝P-256/ES256/SHA-256/AES-CCM-16-64-128）。機器がInitiator、Site AuthorityがResponder。SIGMA-I構造のため、機器の証明書はResponderを認証した後にmessage_3で暗号化して送られる。

## 2. RLI1 — 機器identity記録（新規、`rlsec`/`rlident` 二重slot）

[RLC1](../sdk-completion/04-provisioning-lifecycle.md)と同じseal→write→readback→commit規律。RLC1はnetworkとgrantを含む現場依存記録なので、ゼロタッチでは使わない（dev/bench用に残す）。

```text
  0  u32  magic "RLI1" (0x524C4931)
  4  u16  format = 1 | u16 used_len
  8  u32  schema_version = 1
 12  u32  seal (0 pending / committed 0x1DE71771)
 16  u64  node_id                       — 事務所割当。0と全1は不可
 24  u8   key_location (RLC1と同じ値) | u8 flags | u8 anchor_count (1..3) | u8 reserved=0
          flags bit0 console_locked, bit1 strict_assignment (A2), 他0
 28  u32  reserved = 0
 32  32B  kid = SHA-256(canonical public COSE_Key)   — RLC1と同じ規則
 64  64B  pubkey X||Y
128  32B  key_material（位置1:秘密scalar、2/3:handle、0:ゼロ）
160  anchors[anchor_count] × 80B:
          anchor_id u64 | kind u8 (1=SiteCA, 2=AssignmentVerifier) | status u8 (1 active, 2 disabled) |
          reserved 6B | pubkey 64B
160+80n  u16 devcert_len (≤256) | u16 reserved
164+80n  DevCert bytes
len-4    u32 crc32_iso_hdlc
```

最大 160＋3×80＋4＋256＋4＝**664B**（slot上限1024B）。事務所で一度だけ書く記録なので、RLC1と同じく2 slotへ同一内容を書く（twin）。起動時検査：kid再計算、位置1なら公開鍵の再計算一致、全anchorがP-256曲線上、kind=SiteCAのactiveが1件以上、DevCertのsubject＝node_id・cnf＝pubkey・issuer署名はDevice CAなので機器側では**検証しない**（Device CA公開鍵を機器は持たない）。不一致は破損で、再導出しない。

## 3. 証明書profile RLCW1

3種類ともCWT（RFC 8392）＝COSE_Sign1（ES256、protected `{1:-7}`、unprotected空）。EDHOCでは`ID_CRED_x = {13 (kcwt): CWT}`として値渡しする（RFC 9528 §3.5.2の登録済みlabel）。deterministic CBOR、整数最短表現、未知claimは拒否。

**未解決（P2-1で判明）**：固定したlibedhoc v2.3.2のcredential APIはID_CREDとしてkid（4）・x5chain（33）・x5t（34）だけを扱い、kcwt（13）による値渡しを符号化・復号できない。このbranchのbackendはkid参照（kid＝cnf鍵のCOSE_KeyのSHA-256全32B、CRED_xにRLCW1証明書そのもの）で動作を確認した。値渡しが要る場面（初対面のmessage_3でDevCert、未cacheのMemberCert）は、P2-3／P4-2で「kid参照＋証明書をEADで運ぶ」か「上流へのkcwt対応」のどちらかに決め、それまで本節の値渡しは採用案のままとする。

| claim | DevCert | SiteCert | MemberCert（=Grant） |
|---|---|---|---|
| 1 iss | Device CA id u64 | Site CA id u64 | site_id u64 |
| 2 sub | node_id | site_id | node_id |
| 8 cnf | 機器公開鍵 COSE_Key | SAK COSE_Key | 機器公開鍵 COSE_Key（DevCertと同一鍵） |
| -65537（private） | `[1, model u16, hw_rev u8, serial u32]` | `[2, network_low32 u32, site_epoch u32, usage u8, serial u32]` | `[3, network u64, role u32, assignment_generation u32, site_epoch u32, serial u32]` |
| 署名者 | Device CA | Site CA | SAK |
| 見積もり長 | ≈192B | ≈198B | ≈208B |

見積もり内訳：COSE_Sign1の枠（tag・array・protected・unprotected・payload bstr head・64B署名）≈75B＋payload（map head、iss/sub各10B、cnf≈79B、private claim≈17〜33B）。有効期限claim（exp/nbf）は既定で入れない。機器は信頼できる時刻を持たず、検証したつもりにならないため（[04](04-removal-revocation.md) §6）。

実装（P1-2、[vector README](../../../protocol/sdkv1-golden/README.md)）で次を確定した：COSE_Sign1はtag 18付き・CWT tag 61なし、external AADは空、`cnf`はRFC 8747の`{1: COSE_Key}`でCOSE_KeyはRLC1のkid計算と同じ77B、署名はlow-Sのみ有効（証明書byte列を一意にし、RLP1の`peer_cert_id`と台帳digestを安定させる）。SiteCertの`usage`はbit0（Site Authority）だけ、MemberCertの`role`はbit0 endpoint／bit1 relay／bit2 gateway（0と未知bitは拒否、RLS1の`role`と同値）、`network`の上位32bitは`site_epoch`と一致必須。実長はDevCert 190B・SiteCert 191B・MemberCert 198B（最大208B）。

MemberCertはgrant（[05本番認証 §3](../host-security-readiness/05-production-security.md)のMembershipGrant配列）を**置き換える**提案である。同じ情報（network、node、kid、role、authority世代、revision）をCWTへ移し、EDHOCのcredentialとして直接使えるようにする。kidはcnfの公開鍵から従来規則で計算する。

## 4. 全体の流れ

```text
 機器D(未割当)        proxy P(member)          gateway G        Site Authority A(PC)      KGuard
   |--ZT DISCOVER(bcast)->|                        |                    |                    |
   |<-ZT OFFER(cookie,site_hint,org_hint)-|        |                    |                    |
   |--BA ph4 m1 (cookie echo)->|--Wire relay up--->|--USB 0x40 m1------>|                    |
   |                           |<-Wire relay down--|<-USB 0x41 m2-------|                    |
   |<-BA ph4 m2 (chunks)-------|                   |                    |                    |
   |  SiteCertをSite CAで検証、SAK署名を検証（失敗ならここで中止：身元未送信）              |
   |--BA ph4 m3 (chunks)------>|--relay up-------->|--USB 0x40 m3------>| DevCert検証        |
   |                           |                   |                    |--join.request----->|
   |                           |                   |                    |<-join.decide-------|
   |                           |                   |                    | allow: 台帳commit→MemberCert発行
   |<-BA ph4 m4 (chunks)-------|<-relay down(final)|<-USB 0x41 m4-------|                    |
   |  MemberCert検証→RLS1 commit→Member→近隣とlink確立→JoinConfirm(authority channel)       |
```

BA＝RLD1上のBootstrapAuth（FrameType 3）。RLD1は1hopだけで、proxyはRLD1をそのままmeshへ流さない（[06 admission §3.1](../autonomous-mesh/06-membership-admission.md)）。proxy→gatewayはWire v2のmember間link上の限定bootstrap中継（§7）。

## 5. RLD1上の形式

RLD1 header（44B）と許可kind集合{1,2,3,5,6}は変えない。**新しいのはDISCOVER/OFFERのbody版3（class ZeroTouch）とBootstrapAuthのphase 4〜6**。

### 5.1 ZT DISCOVER（body 24B、総68B、broadcast）

```text
 0 u8  body_version = 3
 1 u8  class = 3 (ZeroTouch)                     — 1 Member, 2 Commissioning は既存
 2 u16 flags: bit0 preferred_site_valid, 他0
 4 u32 profile_bits: bit0 RLJOIN1(EDHOC join), bit1 RLRES1(ticket再試行), 他0
 8 u32 org_hint       = first4(SHA-256("RouteLoom/org-hint/v1\0" || SiteCA anchor pubkey 64B))
12 u32 preferred_site_hint (0 = なし)
16 u32 avoid_site_hint[0] | 20 u32 avoid_site_hint[1]   — 拒否された現場へのOFFER抑制
```

RLD1 headerの`network_hint`=0、`claimed_node`=自分のNodeId（自己申告hint）、`transaction_nonce`=毎回新規乱数。既存のCommissioning scopeは「network 0の全網探索をNETWORK_REQUIREDで拒否」する（[02-discovery-scope §2.2](../scope-gateway-config/02-discovery-scope.md)）。ZeroTouchはその例外を**別class**として明示し、Commissioning classの意味は変えない。ZeroTouchに応答するのは`zero_touch_open`方針のmemberだけ。

### 5.2 ZT OFFER（body 48B、総92B、unicast）

```text
 0 u8  body_version = 3 | 1 u8 class = 3
 2 u8  density hint   | 3 u8 flags: bit0 authority_reachable, bit1 proxy_busy
 4 16B cookie          — 既存cookie（MAC・nonce・時間bucketに束縛）
20 16B responder nonce
36 u32 org_hint (responderの現場のSite CAから計算、DISCOVERと一致しなければ応答しない)
40 u32 site_hint = first4(SHA-256("RouteLoom/site-hint/v1\0" || site_id u64))
44 u8  authority_hops (gatewayまでのhop数、255=不明) | 45 u8 load (0..255) | 46 u16 reserved=0
```

headerの`network_hint`＝現場network_low32。hint・hops・loadはすべて**未認証の選別材料**で、証拠にしない。avoid_site_hintに自分のsite_hintが入っているDISCOVERには応答しない。

### 5.3 BootstrapAuth phase（FrameType 3のbody、既存4B prefix `version|phase|step|reserved`）

| phase | 名前 | step | 本文 |
|---|---|---|---|
| 1〜3 | PROVE/CONFIRM/FINISH | — | 既存（dev PSK）。変更なし |
| 4 | EdhocMessage | 1〜4＝EDHOC message番号、5＝EDHOC error | 最初の2B `cookie_echo_present u8 | reserved u8`、step1のみ続けて cookie 16B、以降EDHOC message本体 |
| 5 | Resume | 1〜3 | RLRES1（[06](06-fast-rejoin.md) §2） |
| 6 | RelayStatus | 1 | proxy→機器の未認証hint：`status u8 (1 queued, 2 authority_unreachable, 3 busy, 4 aborted) | retry_after_ms u32` |

phase本文が112B（=116−4）を超えるときは既存BootstrapChunk（type 5、header 10B、data≤106B）で分割し、BootstrapReply（type 6、10B本文、総54B）で進捗を返す。**実装上の差分**：現行`bootstrap_auth_decode`は本文を124Bまでに制限しており、組立て後1024Bまでの本文を受けられない。phase 4/5用に1024B上限の組立て済みobject型を追加する（[08](08-implementation-plan.md) P3）。

## 6. EDHOCメッセージの中身と長さ

| msg | 方向 | 中身 | 見積もり長 | 機器側hopのRLD1 frame |
|---|---|---|---|---|
| m1 | D→A | METHOD 0、SUITES_I 2、G_X 32B、C_I、EAD_1＝JoinIntent | ≈52B | 1（総44+4+2+16+52≈118B以下） |
| m2 | A→D | G_Y‖CIPHERTEXT_2（C_R、ID_CRED_R＝kcwt SiteCert、Signature_2 64B、EAD_2＝SiteOffer） | ≈330B | chunk 4＋reply 4 |
| m3 | D→A | CIPHERTEXT_3（ID_CRED_I＝kcwt DevCert、Signature_3 64B、EAD_3＝JoinRequest）＋tag 8B | ≈305B | chunk 3＋reply 3 |
| m4 allow | A→D | CIPHERTEXT_4（EAD_4＝JoinResult＋MemberCert＋SitePackage）＋tag 8B | ≈355B | chunk 4＋reply 4 |
| m4 pending/deny | A→D | CIPHERTEXT_4（JoinResult＋ticket≤48B）＋tag | ≈70〜100B | 1 |

m1は機器のcookie echo 16Bを含めてRLD1 1 frameに収まる。m1のC_I・m2のC_Rは、参加用EDHOCではauthority channelの識別子として使う（Wire linkのepochには使わない）。message_4は05の方針どおり必須（鍵確認）。

機器側hopの合計（allow、OFFER k件）：概算 **2.4KB＋92k B、約30frame**。250kbps PHYで割ったbyte時間は約0.08秒だが、preamble・MAC ACK・再送・chunk間の待ちを含まない下限であり、実測値ではない。

### 6.1 EAD形式（EAD label 65537〜65540・critical、P2-3で実装）

| EAD | 載るmsg | 形式（固定長BE、CBOR bstrに格納） | 長さ |
|---|---|---|---|
| JoinIntent | m1（平文） | `ver u8=1 | flags u8 | org_hint u32 | profile_bits u32 | reserved u16` | 12B |
| SiteOffer | m2（暗号化） | `ver u8 | flags u8 | site_id u64 | network_low32 u32 | site_epoch u32 | decision_timeout_ms u16 | reserved u16` | 22B（P2-3、§6.3） |
| JoinRequest | m3（暗号化） | `ver u8 | flags u8 | model u16 | fw_version u32 | capability u32 (bit0 sleepy, bit1 relay, bit2 gateway) | requested_role u8 | reserved u8 | last_site_id u64 | last_generation u32` | 26B（P2-3、§6.3） |
| JoinResult | m4（暗号化） | `ver u8 | verdict u8 | reason u16 | retry_after_s u32 | body_len u16 | reserved u16`＋body | 12B＋body |

JoinIntentは平文で見えるため、身元・割当に関わる値を入れない。

verdictと本文：

| verdict | 値 | body | 機器の動作 |
|---|---|---|---|
| Allow | 1 | MemberCert（bstr）＋SitePackage＋（A2のみ）AssignmentTicket | §10の検証→commit |
| PendingAssignment | 2 | pending ticket（≤48B、authority専用の不透明値） | その現場を`retry_after_s`後に再試行（既定30〜600秒） |
| DenyNotHere | 3 | なし | その現場を6時間回避 |
| DenyBlocked | 4 | なし | その現場を24時間回避 |
| Removed | 5 | RemovalNotice（[04](04-removal-revocation.md) §5） | 現場状態を持っていれば検証して消去 |
| AuthorityBusy | 6 | なし | `retry_after_s`後に再試行 |

### 6.2 SitePackage（Allowのみ、固定120B）

```text
  0 u8  ver = 1 | u8 flags | u16 reserved
  4 u64 site_id           | 12 u64 network (site_epoch<<32 | network_low32)
 20 u32 rs_epoch          — 現在のRRS1 epoch（>0なら参加後に取得）
 24 u32 gk_epoch          | 28 32B GK（m4はEDHOCで暗号化済み）
 60 u8  channel | u8 role | u8 gateway_count (1..4) | u8 reserved
 64 u32 channel_epoch
 68 4×u64 gateway NodeId（未使用は0）
100 u64 authority_time_s  — 参考時刻（信頼できる時刻とは扱わない）| 108 u32 time_uncertainty_ms
112 u32 membership_revision | 116 u32 reserved
```

scope鍵（Member class）はGKから導出する（[03](03-key-hierarchy.md) §6.1）。現場のconfig authority鍵（RLT1）はm4に入れず、参加後にmember専用laneのRTM1 manifestで配る（§10.3）。

### 6.3 Resolved in implementation（P2-3、最も保守的な選択）

§6.1／§6.2のEADと04 §6.1のRemovalNoticeを[sdkv1_ead.hpp](../../../components/routeloom/include/routeloom/sdkv1_ead.hpp)（C++）と`host/routeloom-join`（Rust、Site Authority側。P3-3で`routeloom-host`が使う）に実装し、独立Python生成器`tools/gen_sdkv1_ead_vectors.py`の共通vector（[`protocol/sdkv1-golden/ead/`](../../../protocol/sdkv1-golden/ead/README.md)）でbyte一致を検査した。設計が決めていなかった点は次のとおり決めた。

- **EAD label**：IANAのEDHOC EAD registryは0〜23がStandards Action with Expert Review、24〜65535がSpecification Requiredで、private-use範囲が無い。未登録値の流用を避け、registryの範囲外の**65537（JoinIntent）〜65540（JoinResult）**を使い、すべて**critical（負のlabel）**で送る（`3a 00 01 00 0x`、5B）。RouteLoom joinを知らない相手はEDHOC errorで止まり、EADを無視したまま完了しない。label 5Bのためm1は約59B（C_Iを4B bstrとして）で、§6の見積もり≈52Bより長いが、phase本文2＋cookie 16＋59＝77B≤112BでRLD1 1 frameに収まる（C++試験で静的検査）。
- **EAD fieldの解析**：各messageは自分の項目をちょうど1回（critical、定義長のbstr、最短形のCBOR head）持つ。padding（label 0、RFC 9528 §3.8.1）は読み飛ばす。それ以外の項目（未知の非critical項目、非criticalの同label、他messageの項目、重複、後続byte）はすべて拒否する。
- **長さの食い違い**：§6.1の表の長さはSiteOffer 24B・JoinRequest 30Bだったが、列挙したfieldの合計はそれぞれ22B・26B。fieldの幅を正とし、埋め草は足さない（24B／30Bの値は不正vectorで拒否を固定）。
- **共通の規則**：全項目の先頭`ver`＝1（他はUnsupported）、`flags`は定義bitが無いので0、reservedは0、長さは厳密。JoinIntentの`profile_bits`はbit0（RLJOIN1）必須・bit0〜1のみ。JoinResultの`reason`は理由codeが未定義なので0（理由はverdictが表す）。
- **retry_after_s**：PendingAssignmentは30〜3600（API1 `join.decide`の範囲）、AuthorityBusyは1〜3600、それ以外（Allow・Deny・Removed）は0。Denyの回避時間（6時間／24時間）は機器側の固定値で、authorityが指定しない。
- **Allowのbody**：「MemberCert（bstr）」を固定長BEの流儀で`u16 membercert_len (1..256) | MemberCert | SitePackage 120B | u16 ticket_len (0..128) | AssignmentTicket`とした。MemberCert枠はMemberCert 1枚の正準encodingだけを許す。JoinResultの上限は12＋508＝520B（EAD_4項目528B）。実際のMemberCert（198〜208B）・ticket無しではEAD_4項目342〜352Bで、m4はこれにCIPHERTEXT_4のhead 3Bとtag 8Bを足した353〜363B（§6の見積もり≈355B）。
- **PendingAssignment**のbodyはticket 1〜48B（authority専用の不透明値、RLRES1 R1と同じ上限）。**Removed**のbodyはRemovalNotice（04 §6.1のCOSE_Sign1、payload 28B、ちょうど103B）。`reason`はRRS1と同じ1〜4、generation・rs_epochは1以上、site_id・node_idは0／全1不可。機器は自分のRLS1のsite・network・node・MemberCert世代で受理判定する。Deny・AuthorityBusyのbodyは空。
- **SitePackage**：flags・reservedは0、site_idは有効、network下位32bitは非0、gk_epoch≥1でGKは非0、channel 1〜14（RLS1と同じ）、roleは非0の既知bit、gateway_count 1〜4で有効・重複なしのid＋未使用枠は0。rs_epoch＝0（RRS1未発行）と時刻・revision類は値を制限しない。
- **SiteOffer**：`decision_timeout_ms`は500〜5000（API1 `join.policy`の範囲）。機器はm2認証後、site_id・network_low32・site_epochがSiteCertと一致することを確かめる（不一致は拒否）。Site AuthorityはSiteOfferを自分のSiteCertから作る。
- **JoinRequest**：`requested_role`はMemberCertのrole bit（bit0 endpoint／bit1 relay／bit2 gateway）で非0、relay・gatewayは対応するcapability bitが必要。`last_site_id`＝0なら`last_generation`＝0、非0なら有効idで世代≥1。Site AuthorityはDevCert検証後に`model`がDevCertのmodelと一致することを確かめる。
- **§10.2の検査**（`join_allow_verify`）：手順1〜4に加え、SitePackageのsite_id＝SiteCertのsub、network＝MemberCertのnetwork、role＝MemberCertのroleを要求する。不一致は「検証不成立」（保存せず回避、V1-J12）で、形式不正（error）とは区別する。
- **AssignmentTicket（A2）は形式未定**：01 §5・§10.2は内容（node、site_id、generation、割当検証鍵の署名）だけを定め、byte列を定めていない。本実装はAllow bodyの長さ付き不透明値（≤128B）として運ぶだけにし、A1の機器は無視、A2（strict）の機器はticket無しを拒否、ticket有りは形式が決まるまで`Unsupported`で**fail closed**（参加しない）。形式の決定は後続（A2を製品で使う前に必須）。
- **Rust側の置き場所**：Site Authorityは`routeloom-host`に置く（07 §1）ため、事務所tooling（`routeloom-provision`）とは別crate `routeloom-join`にし、証明書とCOSE_Sign1 helperは`routeloom-provision`の`sdkv1`を使う。Rust試験はSite Authorityとして全AllowのMemberCertとRemovalNoticeをRFC 6979で再発行し、生成器のbyte列と一致することを要求する。

未実装・未定のまま残るもの：AssignmentTicketのbyte列、link用EDHOC（03 §4.1）のEADで交換する`(site_epoch, rs_epoch, gk_epoch)`の形式（P4-2）、JoinConfirm（AuthorityEnvelope type 1）の本文、EDHOC encoder込みのm1〜m4実長の検査（V1-J14の残り、P2-1後）。

## 7. proxyの中継

### 7.1 Wire上の中継object（proxy⇄gateway、member間link）

```text
RelayHeader（24B）:
 0 u8  ver = 1 | 1 u8 dir (1 up, 2 down)
 2 u32 relay_id（proxyが選ぶ、proxy内で一意）
 6 u64 proxy NodeId
14 6B  joiner MAC（proxyが観測したMAC）
20 u8  step (EDHOC 1..5, Resume 1..3) | 21 u8 status (down: 0 継続, 1 最終, 2 中止)
22 i8  joiner_rssi_dbm (upのみ、表示用) | 23 u8 reserved
続いて EDHOC message（またはRLRES1本文）≤1000B
```

| 区間 | 運び方 | 1 frameあたり |
|---|---|---|
| 128B以下（m1、deny） | Wire FrameType 3、payload＝RelayHeader＋本文 | 1 frame |
| それ以上 | Wire FrameType 5（本文 `ver u8 | sub u8 | relay_id u32 | offset u16 | total u16`＋data≤118B）、受領はtype 6 | m2/m3/m4は各3 frame/hop |
| 最終の下り（status=1） | Wire FrameType 4（MembershipResult）にRelayHeader＋本文を載せる | proxyはこれでslotを解放 |

Wire中継はmember間のlink保護（hopごと）で運び、`kFlagEndProtected`は付けない（proxy–gateway間のE2E contextが未確立でも動くため）。EDHOC自体が機器–authority間の端点保護を持つので、中継者は内容を読めず改変は検出される。relayはこのobjectを任意宛先へ送らない：宛先はgatewayのみ、typeは3/4/5/6のみ、1 proxy同時1件（[06 admission §3.2](../autonomous-mesh/06-membership-admission.md)の予算を共有）。

### 7.2 gateway⇄host（USB HostOps、[07](07-host-api-tooling.md) §4）

`0x40 JoinRelayUp`（G→H：`gateway u64 | from_proxy u64 | hops u8 | RelayHeader＋本文`）、`0x41 JoinRelayDown`（H→G：`to_proxy u64 | RelayHeader＋本文`）、`0x42 JoinRelayAbort`。USB frameは最大4096Bなのでmessageを分割しない。

### 7.3 proxyの状態機械

| 状態 | 入力 | 動作 | 次 |
|---|---|---|---|
| IDLE | ZT DISCOVER（org一致、`zero_touch_open`、authority到達可、slot空き） | OFFER（乱数slot内） | OFFERED |
| OFFERED | m1（有効cookie、同じMAC・nonce） | relay_id割当、up送信 | RELAYING |
| OFFERED | cookie不一致・期限切れ | 破棄（cookie_rejects++） | OFFERED/IDLE |
| RELAYING | 下りobject | 機器へRLD1（chunk）で配送 | RELAYING |
| RELAYING | 上りobject（同じMAC・nonce） | upへ転送 | RELAYING |
| RELAYING | 下りstatus=1/2 | 配送後slot解放 | IDLE |
| RELAYING | 開始から20秒、または機器無応答5秒 | `JoinRelayAbort`をup、RelayStatus(aborted) | IDLE |
| 任意 | 別機器のm1 | RelayStatus(busy, retry_after) | 不変 |
| 任意 | 自分のmembershipがRevoked／GK不明 | 中継中止、OFFER停止 | IDLE |

## 8. Site Authorityの処理とKGuard

| 状態（参加txnごと、host RAM、最長30秒） | 動作 | 失敗時 |
|---|---|---|
| M1 | 同時参加数（既定4）・機器MAC/proxyごとのrate確認、G_Y生成、m2作成 | 上限超過：m2を作らずrelay down（status=2、理由busy）。proxyが機器へRelayStatus(busy, retry_after)。EDHOC sessionが無いのでJoinResultは使えない |
| M2_SENT | m3待ち（最長10秒） | 期限切れ：破棄 |
| VERIFY | m3復号、DevCertをDevice CAで検証、Signature_3検証、DevCertのsub・cnfとJoinRequestの整合、組織の失効済み機器一覧 | 失敗：EDHOC error（m4相当）を返し、`join.rejected_unverified{reason}`を数える。発見済み一覧には載せない |
| DECIDE | 台帳に既存の承認（同node・同kid・世代）があれば即Allow（再発行）。無ければKGuardへ`join.request`、`decision_timeout_ms`（既定2000、最大5000）待つ | 期限切れ：PendingAssignment＋ticket |
| COMMIT | allow：SingleAuthority台帳へ`MembershipApproval`（node、kid、generation、MemberCert digest）をcommit、DAMSを保存 | 台帳失敗：AuthorityBusy。**成功へ変換しない** |
| M4 | JoinResultを作成し送信 | 配送失敗は機器の再試行で冪等に再発行 |
| AWAIT_CONFIRM | 機器のJoinConfirm（authority channel、60秒以内） | 未確認は`allowed_unconfirmed`としてAPIに見せる |

KGuardのdecisionは`allow{role}`／`pending{retry_after}`／`deny{not_here|blocked}`。KGuardが`allow`した後で機器がm4を受け取れなかった場合、再試行は台帳の既存承認で即Allowになり、同じ世代・同じ内容のMemberCertを再発行する（二重割当や世代の空費をしない）。

## 9. 未割当機器の報告（R3）

m3を検証できた未割当機器は、verdictに関係なくhostの**発見済み機器表**に記録する。

| field | 内容 |
|---|---|
| device_id, kid, model, hw_rev, cert_serial, fw_version | DevCertとJoinRequestから（検証済み） |
| first_seen, last_seen, attempts | host時刻 |
| via | 直近の(gateway, proxy, authority_hops, joiner_rssi_dbm)。RSSI・hopsはproxyの観測で未認証 |
| last_verdict | pending / not_here / blocked |
| previously_removed | この現場の台帳に削除履歴があるか |

表は上限1024件、last_seenのLRU。同じ機器の更新は1分に1回まで。KGuardは`devices.discovered.list/watch`で見る（[07](07-host-api-tooling.md) §2）。重なり合う2現場ではどちらのKGuardにも表示され得る（割当先ではない現場でも「発見済み」になる）。これは仕様であり、表示に経路・RSSIを付けて判断材料にする。

未割当の間、機器のMembershipStateは`Discovering`/`Authenticating`で、Wire DATA／route／serviceは送受信しない（admission allowlist、[identity §8](../../spec/identity-membership.md)）。

## 10. 機器側の状態機械

### 10.1 状態

| 状態 | MembershipState | 入る条件 | 動作 | 出口 |
|---|---|---|---|---|
| ZT_SCAN | Discovering | RLI1有効かつRLS1無し | 候補channel（既定1/6/11、LR250）でZT DISCOVER、OFFER窓320ms | OFFER有り→ZT_SELECT、無し→backoff後再走査 |
| ZT_SELECT | Discovering | 候補表（§11）更新 | 適格な現場を1つ選ぶ | →ZT_HANDSHAKE |
| ZT_HANDSHAKE | Authenticating | m1送信 | m2でSiteCert/署名検証（失敗→中止、身元は未送信）、m3送信 | m4受信→判定、期限切れ→ZT_BACKOFF |
| ZT_DECIDED | Authenticating | m4受信 | verdict処理（§6.1） | Allow→ZT_COMMIT、他→候補表更新→ZT_SELECT/ZT_BACKOFF |
| ZT_COMMIT | AuthorizedPendingCommit | Allow | §10.2の検証→RLS1 commit（seal/readback） | 成功→MEMBER_BRINGUP、失敗→RAM破棄しZT_BACKOFF |
| MEMBER_BRINGUP | Member | RLS1 commit済み | Member scopeで近隣とlink（[06](06-fast-rejoin.md)）、JoinConfirm | 通常運転 |
| ZT_BACKOFF | Discovering | 失敗・全現場不適格 | 乱数backoff 1s→最大600s。全現場が回避中なら最短適格時刻まで | →ZT_SCAN |

時間上限：m1→m2は`2s＋0.3s×authority_hops`（最大6秒）、m3→m4はそれ＋decision上限（合計最大10秒）、1回の試行全体は15秒以内。RLD1の組立ては既存どおり1件・3秒。

### 10.2 Allowの検証（すべて満たすときだけcommit）

1. MemberCertの署名をm2で認証済みのSAK（SiteCertのcnf）で検証。
2. MemberCertの`sub`＝自分のnode_id、cnf公開鍵＝自分の公開鍵、`iss`＝SiteCertの`sub`（site_id）。
3. MemberCertの`network`＝SitePackageの`network`、上位32bit＝`site_epoch`＝SiteCertのsite_epoch、下位32bit＝SiteCertのnetwork_low32。
4. `assignment_generation`≥1、roleは既知bitのみ。
5. A2 modeなら AssignmentTicket（割当検証鍵の署名、`[node, site_id, generation]`）が有効で2・3と一致。
6. SitePackageの長さ・予約0・gateway_count範囲。

どれかが不一致なら何も保存せず、その現場をDenyBlocked相当で24時間回避する（Site Authorityの不具合か攻撃なので自動再試行を急がない）。

### 10.3 RLS1 — 現場所属記録（`rlsec`/`rlsite` 二重slot、最大712B）

GK更新などで繰り返し書くため、trust storeと同じA/B交互書込みにする。その順序付けに`commit_seq`（offset 16）を実装時に追加したので、以下の16以降のoffsetは実際には+4ずれる（実layoutは[vector README](../../../protocol/sdkv1-golden/README.md)）。削除時は`state=0`で本文が全0の記録（tombstone、200B）を両slotへ書き、GK・DAMSの複製を残さない。seal committed値は`0x5173AB1E`。

```text
  0 u32 magic "RLS1" | 4 u16 format=1 | 6 u16 used_len | 8 u32 schema=1 | 12 u32 seal
    (実装: 16 u32 commit_seq を挿入)
 16 u64 site_id               | 24 u64 network（全64bit）
 32 u32 assignment_generation | 36 u32 rs_epoch_floor（受理済みRRS1のepoch）
 40 u32 gk_epoch_current      | 44 u32 gk_epoch_next（0=無し）
 48 32B gk_current            | 80 32B gk_next
112 32B dams（機器–authority主秘密、EDHOC Exporter）
144 u8 state (1 member) | u8 role | u8 gateway_count | u8 channel
148 u32 channel_epoch
152 u32 boot_witness          — 参加時とGK activationごとに記録した`rlboot`値（05 §3.3）
156 4×u64 gateways
188 u16 sitecert_len | u16 membercert_len
192 SiteCert (≤256) | MemberCert (≤256)
len-4 u32 crc32
```

commit後、現場のconfig/trust用RLT1は「SAKをanchor（root_id＝site_id）とするepoch 1の最小image」としてローカルに作れる（SiteCertがSite CA経由で認証済みのため）。以後の完全imageはSAK署名のRTM1で届く。これは[04 provisioning §4.4](../sdk-completion/04-provisioning-lifecycle.md)の「最初の信頼は物理経路だけ」を**変更する**点で、最初の物理信頼をSite CA anchor（事務所）へ移し、現場の信頼はその連鎖から得る。この変更は同文書の改訂としてレビューに回す。

## 11. 重なり合う現場（R4）

候補表（RAM、最大8現場、site_hint単位）：`site_hint | 最良proxyのMAC・RSSI | authority_hops | 状態(untried/pending(retry_at)/avoid(until)/busy(retry_at)) | 最終試行`。

選択規則：

1. org_hintが自分のanchorと一致しないOFFERは無視。
2. 状態が適格（untried、またはretry_at/until経過）の現場だけを対象。
3. preferred（直前に所属していた現場、RAMで保持）を優先、次にuntried、次にauthority_hopsが小さくRSSIが強い順。
4. 同じ現場への連続試行は`retry_after`を守る。pendingの現場があっても他の適格現場を順に試す（割当先がpending側でない限り、いずれallowに当たる）。
5. avoid（DenyNotHere 6時間、DenyBlocked 24時間）の現場はDISCOVERの`avoid_site_hint`（最大2件）に入れてOFFER自体を抑制。
6. 候補表は再起動で消える（NVSに書かない：摩耗と、誤った回避の固定化を避ける）。再起動直後の再試行はauthority側のrate制限で抑える。

**なぜ隣の現場に入らないか**：(a) allowは割当先のKGuardだけが返す。(b) 参加後のlinkはMemberCertの相互検証を要し、別現場のMemberCertは別SAK署名・別networkなので検証に失敗する。(c) Member class discoveryのscope鍵は自現場のGKから導出され、他現場のDISCOVER/OFFERはscope MACで無言dropされる。(d) 参加後はZeroTouch classを送らない。焼き込み鍵による分離には依存しない。残る前提はKGuardの割当一意性（A1）で、A2ではこれも機器側で検証する（[01](01-overview-threat-model.md) §5）。

## 12. 失敗の扱い

| 失敗 | 検出 | 動作 | 状態への影響 |
|---|---|---|---|
| OFFER無し | 窓切れ | 別channel→backoff | なし |
| m2のSiteCertがanchorに連ならない／署名不正 | 機器 | 中止（m3を送らない）、その現場を24時間回避 | なし（身元未送信） |
| m3のDevCert不正 | authority | EDHOC error、発見済み一覧に載せない | なし |
| KGuard無応答 | decision期限 | PendingAssignment＋ticket | 機器はpending再試行 |
| 台帳commit失敗 | authority | AuthorityBusy。成功扱いにしない | なし |
| m4未着 | 機器期限 | 再試行。authorityは台帳から冪等再発行 | なし |
| RLS1書込み中の電源断 | 起動時slot分類 | pendingは破棄、未割当で再開→再試行で冪等再発行 | Memberにならない |
| proxy／経路消失 | 期限・RelayStatus | 別proxyで再試行 | なし |
| 同時参加上限 | authority | AuthorityBusy（retry_after） | なし |
| RelayStatus偽造 | — | hintとして待つだけ。verdictにはしない | なし |

## 13. 資源と速度制限

| 資源 | 上限（案） | 根拠 |
|---|---|---|
| proxy同時中継 | 1件（preauthと共有） | [06 admission §3.2](../autonomous-mesh/06-membership-admission.md) |
| proxyの新規m1受付 | 2秒に1件 | [05本番認証 §8](../host-security-readiness/05-production-security.md)の高コスト認証1件/2秒 |
| authority同時参加 | 4件 | host側。KGuard待ちを含む |
| authorityの機器ごと再試行 | pending中は`retry_after`未満の再試行をBusyで返す | flood抑制 |
| 未検証m1のauthority費用 | ECDH 1回＋署名1回 | PC側で許容。proxy rateで上限が掛かる |
| 機器側RAM | 組立1件1024B＋EDHOC session（ILP32見積約2.7KB：libedhoc context 576B・作業arena 1280B・key store等。P2-1のhost計測から算出、C3実測はP2-2） | libedhocのbounded backend（05 §8、[edhoc.hpp](../../../components/routeloom/include/routeloom/edhoc.hpp)） |
| memberのDATA | bootstrap queueと分離 | 既存方針 |

## 14. 受入試験（すべてplanned_not_run）

| ID | 内容 | 層 |
|---|---|---|
| V1-J01 | 1hop参加の正常系：状態順序、台帳commitがm4より前、RLS1内容 | host sim |
| V1-J02 | 3hop中継で参加、proxy slotの解放 | host sim |
| V1-J03 | 未割当→pending→KGuardで割当→`retry_after`内にallow | host sim＋daemon |
| V1-J04 | DenyNotHere後に別現場を試行、拒否現場の情報を保存しない | host sim |
| V1-J05 | 2現場重複、機器はBに割当：Bにだけ参加、Aの発見済み一覧に載る | host sim／HIL |
| V1-J06 | 偽SiteCert：m3を送らずに中止 | host |
| V1-J07 | 偽DevCert：拒否、発見済み一覧に載らず理由別カウンタ | host |
| V1-J08 | m4後・seal中・confirm前の電源断：一貫した回復と冪等再発行 | host fault |
| V1-J09 | KGuard期限切れ→pending、後の決定が次回試行で反映 | daemon |
| V1-J10 | proxy busy／authority到達不可：hintとbackoff、状態不変 | host sim |
| V1-J11 | preauth flood：proxy 1件・authority rate、memberのDATAは維持 | host sim |
| V1-J12 | MemberCertの各field不一致：保存せず回避 | host |
| V1-J13 | m1/m3の再送攻撃：新しいephemeralにより失敗 | host |
| V1-J14 | m1〜m4の実長がこの表の予算内（共通vector） | golden |
| V1-J15 | C3/S3で参加時間とECC処理時間を実測 | HIL |

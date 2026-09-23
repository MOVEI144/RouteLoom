# 03 — 鍵階層・Wire v2 epochとの対応・SecurityProviderの変更

用途・方向・networkごとに鍵を分け、同じ秘密を二つの用途へ使わない（[セキュリティ契約](../../spec/security.md) §3）。以下のラベル・info形式は採用案で、C++/Rust共通vectorで凍結するまで**未確定**。KDFはHKDF-SHA-256（RFC 5869、このbranchで[kdf.hpp](../../../components/routeloom/include/routeloom/kdf.hpp)として実装済み）とEDHOC Exporter（RFC 9528 §4.2.1）だけを使い、独自の暗号primitiveは作らない。

## 1. 鍵の木

```text
機器鍵 (P-256, RLI1) ──┬─[EDHOC join, Site Authorityと]──> PRK_out_join
                      │        ├─ Exporter(32771) → DAMS（機器–authority主秘密、RLS1とhost DB）
                      │        │       └─ RLRES1 → authority channel鍵（起動ごと、RAM）
                      │        └─ Exporter(32772) → pending再試行秘密（RAMのみ、pending時）
                      │
                      ├─[EDHOC link, 近隣memberと（MemberCert）]──> PRK_out_link
                      │        ├─ Exporter(32768/32769, dir) → link鍵・IV（方向別、RAM）
                      │        └─ Exporter(32770) → RMS_link（再開cache slot）
                      │                └─ RLRES1 → link鍵・IV（再開ごと新規、RAM）
                      │
                      └─[EDHOC end, 遠隔memberと（routed bootstrap）]──> PRK_out_end
                               ├─ Exporter(32768/32769, dir) → E2E鍵・IV（RAM）
                               └─ Exporter(32770) → RMS_end（再開cache slot）

Site Authority ── GK_g（32B乱数、authority channelで配布、RLS1）
                   └─ PRK_g = HKDF-Extract(salt, GK_g)
                        ├─ K_bcast(tx, tx_boot)          1hop broadcast（経路広告など）
                        ├─ K_gend(group, origin, session) group宛て端点保護
                        └─ K_dsk(g)                      Member class discovery scope鍵
```

長期に保存される秘密は、機器鍵（RLI1）、DAMS・GK（RLS1）、RMS（再開cache）だけ。**セッション鍵とcounterは保存しない**（sleep端末のRTC保持を除く、§5.4）。これが[05](05-nvs-state-37.md)の#37対策の前提になる。

## 2. 用途分離の規則

1. join用EDHOCの出力はauthority channelとpending再試行にだけ使い、Wire link/E2Eの鍵にしない。
2. link・E2E・authorityはEDHOCのexchangeを分ける（[05本番認証 §5](../host-security-readiness/05-production-security.md)「同じ出力keyをlink/end/USBで使い回さない」）。
3. Exporter contextは05 §5のdeterministic CBOR配列 `['RouteLoom',1,purpose,network,initiator_node,responder_node,initiator_kid,responder_kid,initiator_role,responder_role,grant_revision_pair,wire_version,context_epoch,direction,capability_digest]` を使う。本書は`purpose`へ`link=1, end=2, usb=3, authority=4, pending=5`、`context_epoch`へ受信側context id（§4.1）を割り当てる。
4. GKからの導出はlabelで用途を分け、GKそのものをAEAD鍵にしない。
5. 開発PSK profileの鍵（[psk_security.cpp](../../../components/routeloom_espnow/src/psk_security.cpp)のHMAC導出）はこの木に含めない。

### 2.1 Exporter label（private-use、IANA登録済みではない）

| label | 出力 | 長さ | 用途 |
|---|---|---|---|
| 32768 | AEAD key（方向別） | 16B | link／E2E（05で既定） |
| 32769 | base IV（方向別） | 12B | 同上（05で既定） |
| 32770 | RMS 再開主秘密 | 32B | link／E2Eの再開cache（本書で追加） |
| 32771 | DAMS | 32B | join exchangeのみ（本書で追加） |
| 32772 | pending再試行秘密 | 32B | join pendingのticket再試行（本書で追加） |

### 2.2 HKDFのinfo形式（RouteLoom独自、案）

`info = ASCII label || 0x00 || 固定幅BE fields`。saltは各所で明記。例：`"RouteLoom/v1/resume-key" 0x00 || purpose u8 || direction u8 || network u64 || node_I u64 || node_R u64 || cid_I u32 || cid_R u32 || transcript_hash 32B`。labelの一覧と固定幅は共通vector（[08](08-implementation-plan.md) P1-4）で凍結する。

## 3. 暗号suiteとnonce

通常frameは既存Wireのサイズを保つAES-GCM-128・16B tag（05 §1）。nonceは05 §5の `baseIV XOR (zero48 || counter48)` の形を、Wire v2の48bit counterに合わせて **`baseIV XOR (zero6B || counter u48)`** とする。counterは鍵・方向ごとにRAMで0から数える。`kMaxCryptoCounter`（2^48−1）に達する前に必ず再鍵する（実際の再鍵条件は§4.3）。同じ鍵で同じcounterを二度使わないことは、**鍵がhandshakeごとに新しいこと**で保証する（保存したcounter範囲には依存しない）。

## 4. link context（隣接member間）

### 4.1 確立

| 方式 | 使う時 | 費用（1回、片側） |
|---|---|---|
| EDHOC link（method 0、`ID_CRED`＝kcwt MemberCert、キャッシュ済みならkid参照） | 初対面、再開slot無し／期限切れ | ECDSA署名1・検証2（相手署名＋相手MemberCert）・ECDH 1・鍵生成1。C3の時間は**未測定** |
| RLRES1（[06](06-fast-rejoin.md) §2） | 再開slotがあり有効 | HMAC-SHA-256 数回、ECC無し |

EDHOCのm2/m3のEADで双方は`(site_epoch, rs_epoch, gk_epoch)`を交換し、相手のMemberCertを次で検証する：SAK（自分のRLS1のSiteCert）署名、`network`一致、RRS1で失効していない（`generation ≥ min_generation`）、role条件。どれかが不成立ならlink不可（相手は別現場・旧世代・削除済み）。自分側が古いrs_epoch/gk_epochを持つと分かれば、確立後に取得する（[04](04-removal-revocation.md) §4）。

### 4.2 Wire v2上の識別

受信側が選ぶ**context id（u32、非0、自分の生存context内で一意、乱数）**をWire headerの`link_epoch`へ入れる。EDHOCのC_I/C_R（4B bstr）をそのままcontext idにし、Initiator→Responder方向のframeは`link_epoch = C_R`、逆方向は`C_I`。RLRES1ではR1/R2で`cid_I`/`cid_R`を交換する。受信側は`(previous_hop, link_epoch)`で鍵を引き、見つからなければ`AuthRequired`（再handshake要求、§8）。context idは秘密ではなく、大小比較もしない。

### 4.3 寿命と再鍵

| 条件 | 動作 |
|---|---|
| counter ≥ 2^32（05の上限） | RLRES1で新context |
| 相手のgk_epochが作成時から2以上進んだ（GKは24時間ごとに更新＝粗い時計） | 同上 |
| RMSの再開回数 ≥ 64、またはRMS作成からgk_epochが2以上進んだ | full EDHOC（RMS更新） |
| 相手がRRS1で失効 | 即破棄（overlap無し） |
| 相手の再起動（未知context idのframe受信） | 相手側がRLRES1を開始 |

新旧contextの受信重複は最大60秒（05 §6）。旧contextでは送信しない。

## 5. E2E context（origin⇄destination）

### 5.1 確立

link と同じEDHOC（purpose=end）またはRLRES1を、Wire bootstrap（FrameType 3/5/6、link保護のみ）でmulti-hop運ぶ。中継者は内容を読めない。destinationが選ぶcontext idを`end_epoch`へ入れ、`(origin, end_epoch)`で鍵を引く。end AADの順序・幅（`protocol/semantics.json`の`end_aad_fields`）は変えない。

### 5.2 容量

| 機器 | E2E context（RAM） | E2E再開slot（NVS） |
|---|---|---|
| 通常機器 | ≤8（gateway≤4＋業務相手≤4） | 4 |
| gateway | ≤128（qualification規模100台＋余裕） | 128（gateway profileの`rlsec`、[05](05-nvs-state-37.md) §5） |

1 contextのRAMは鍵handle 2＋IV 2＋counter 2＋受信窓（64bit bitmap＋最大値）＋id等でおよそ96〜128B（見積もり）。gateway 128件で約16KB。C3をgatewayにする場合は上限を下げる。

### 5.3 authority channel

機器⇄Site Authority（PC）の端点保護。DAMSをRMSとするRLRES1（purpose=authority）で起動ごとに必要になった時だけ鍵を作る。封筒：

```text
AuthorityEnvelope: ver u8 | type u8 | ctx_id u32 | counter u48 | ciphertext n | tag 16B   (= 28 + n)
type: 1 JoinConfirm, 2 GroupKeyUpdate, 3 GroupKeyActivate, 4 GroupKeyPull, 5 RevocationNotify,
      6 RemovalNotice, 7 GrantRenew, 8 TimeSample
```

機器→gatewayはWire Control（FrameType 22）の新subtype、128Bを超えればControlObject（kind案 5 = AuthorityEnvelope）で、機器⇄gatewayのE2E context上を運ぶ。gatewayはUSB `0x43/0x44`（[07](07-host-api-tooling.md) §4）でhostへ渡し、**中身を復号できない**。authority側のreplay窓・counterはhostのstoreが持つ。

### 5.4 sleep端末

deep sleep中はRAMが消えるため、親とのlink contextとgatewayとのE2E contextをRTC slow memoryへ保持する（鍵・IV・送信counter・context id・CRC、1 contextあたり≈96B）。送信前にRTC上のcounterを先に進めてから送る（write-ahead）。電源断・brownoutでRTCが消えれば鍵も一緒に消えるため、counterだけが巻き戻ることはない。RTC保持を電源断耐性とはみなさない（[セキュリティ §4](../../spec/security.md)）：RTC消失時はRLRES1で新context。親が再起動して鍵を失った場合、子のframeは`AuthRequired`になり、子はRLRES1をやり直す。

## 6. network group鍵（GK）

### 6.1 導出

```text
PRK_g        = HKDF-Extract(salt = "RouteLoom/v1/group" 0x00 || network u64, IKM = GK_g)
K_bcast      = HKDF-Expand(PRK_g, "bcast-link" 0x00 || g u32 || tx u64 || tx_boot u32, 28)  → key16 || iv12
K_gend       = HKDF-Expand(PRK_g, "group-end" 0x00 || g u32 || group_id u64 || origin u64 || session u32, 28)
K_dsk(g)     = HKDF-Expand(PRK_g, "dsk-member" 0x00 || g u32, 32)   → Member class scope鍵（generation = g）
```

`tx_boot`・`session`は送信者の永続boot session（`rlboot`、起動ごとに単調増加）。送信者鍵は起動ごとに変わるため、counterはRAMで0から数えてよい。前提は`rlboot`が巻き戻らないこと。巻き戻りの検出は[05](05-nvs-state-37.md) §3.3の単一witnessで行う。

### 6.2 Wire v2上の表現

| field | 1hop broadcast（経路広告等） | group宛て業務frame（計画中のgroup delivery） |
|---|---|---|
| next_hop | `kBroadcastNodeId` | `kBroadcastNodeId` |
| destination | `kBroadcastNodeId` | group_id（group namespace、group delivery設計で定義） |
| link_epoch | 送信者のboot session | 転送者のboot session |
| end_epoch | GK epoch g（end保護が無くてもheaderのAADで認証） | GK epoch g |
| link AEAD | K_bcast(previous_hop, link_epoch) | K_bcast(転送者, 転送者boot) |
| end AEAD | なし | K_gend(group_id, origin, message session) |

受信側は送信者ごとに `(tx, tx_boot) → 受信窓` をRAMに持つ（表128件、qualification規模100台以上）。同じtxについて過去に見たより小さい`tx_boot`は拒否。表が満杯なら新しい送信者を**拒否**して数える（追い出すとreplayが再び可能になるため）。

### 6.3 配布と更新

Site Authorityの状態機械：

| 状態 | きっかけ | 動作 |
|---|---|---|
| STABLE(g) | 24時間（設定1〜168時間）、削除、手動 | →STAGING(g+1) |
| STAGING(g+1) | — | 対象member（削除者を除く）へ`GroupKeyUpdate(g+1, stage)`をauthority channelで送る。10件/秒、再送あり、ack記録 |
| ACTIVATING | 全ack、または期限（定期60秒／削除時30秒） | gatewayにg+1での送信開始を指示（USB）。gatewayのbroadcastがg+1になる |
| STABLE(g+1) | — | 未ackのmemberは次の接触でpullする |

member側：g+1を受けたらRLS1の`gk_next`へcommit（STAGED）。**有効なg+1のframeを初めて受けた時**、または`GroupKeyActivate`を受けた時に送信をg+1へ切替え（暗黙activation）、gの受信を60秒（削除起因は10秒）だけ許してから消す。`end_epoch`が自分の知らない新しいgのframeを受けたら、authority channelで`GroupKeyPull`（1分に1回まで）。GK更新のNVS書込みは1回の更新あたりRLS1 commit 2回。

### 6.4 削除時のrekey

削除された機器にはg+1を送らない。削除から新GKへの切替えまでの露出窓は `STAGING時間（最大30秒）＋受信overlap（10秒）＋分断していた群への到達時間`。この間、削除された機器はgのbroadcastを読め、gで経路広告を偽造できる（§6.6）。

### 6.5 group鍵で保証しないこと

- **送信元の本人性**：GKを持つmemberなら誰でも他memberを名乗ってframeを作れる。group鍵が示すのは「現在のmemberの誰か」まで（[セキュリティ §10](../../spec/security.md)「group共通MACを個々のorigin本人確認にしない」）。
- **受信側再起動をまたぐreplay**：受信側が再起動すると送信者ごとの窓が消え、同じg内で捕獲された古いframe（古いtx_boot）を受理し得る。上限はgの寿命（≤24時間＋overlap）。group宛ての業務メッセージは「状態通知」（冪等、アプリ側sequence付き）として設計し、1回限りの命令に使わない。
- 送信元の本人性が必要な警報（例：ポンプ過熱）は、(a) payloadにES256署名（64B、残り64B）を付ける、(b) 宛先ごとのE2E unicastで送る、のどちらかを選ぶ（製品判断、[08](08-implementation-plan.md) §6 Q4）。

### 6.6 経路広告のbroadcast（計画中）との関係

現行のROUTE_UPDATEは近隣ごとのpairwise unicast（[node.cpp](../../../components/routeloom/src/node.cpp)の`queue_route_update`）。broadcast化する場合：受信側は`previous_hop`が自分とpairwise contextを持つREACHABLE近隣である時だけその広告を候補に入れ、それ以外は無視する。これにより、GK保持者が「近隣Xの広告」を偽造しても、DATAの次hopは実在するXとのpairwise contextに限られる。insiderによる虚偽metricは現在と同じく範囲外。feasibility・sequence規則（[経路仕様](../../spec/routing.md)）は変えない。

## 7. Wire v2のepoch・counterとの対応

| 項目 | 開発PSK profile（現行） | 本番profile（本設計） |
|---|---|---|
| link_epoch（unicast） | 送信者のboot session（大小比較、floorを永続） | 受信側が選んだlink context id（比較しない） |
| end_epoch（unicast E2E） | 送信者のboot session | destinationが選んだend context id |
| broadcast frame | （未使用） | link_epoch=送信者boot、end_epoch=GK epoch |
| counter（u48） | 永続lease（256単位の予約） | RAM、鍵ごと0から。上限前に再鍵 |
| nonce | scope u8｜方向u8｜epoch u32｜counter u48 | baseIV XOR (0^48 ‖ counter48) |
| replay | context別windowと相手別floorを永続 | RAMのwindowのみ（鍵が新しいため旧frameは復号不能） |
| SecurityContext.network | headerの32bit | RLS1の全64bit（04 provisioning §4.8） |
| ROUTE_UPDATEのgeneration u32 | boot session | 変更なし（鍵とは独立） |
| APPLIED execution lease | `end_epoch`をboot識別に使用 | boot sessionを明示して使う（end_epochはcontext idになるため）。小さなコード変更 |

Wire v2のheader配置・88B・248B上限は**変えない**。変わるのはfieldの意味をProviderが決める部分だけで、これはWire文書が「暗号suiteは未凍結」としている範囲に入る。

## 8. SecurityProviderの変更（API案）

```cpp
enum class SecurityScope : std::uint8_t { Link = 0, EndToEnd = 1, GroupLink = 2, GroupEnd = 3 };

struct SecurityContext {           // 既存fieldは不変
  SecurityScope scope; NetworkId network; NodeId sender; NodeId receiver;
  std::uint32_t epoch;             // link/end: context id、group: 送信者boot
  std::uint32_t group_epoch{0};    // 新規：group scopeのGK epoch（他scopeでは0）
};

class SecurityProvider {           // 既存のseal/open/next_counterは維持
 public:
  // 新規：送信frameのepochをProviderが選ぶ。開発Providerは設定値を返す（挙動不変）。
  // 本番Providerは相手とのcontextが無ければ AuthRequired を返し、Nodeはhandshakeを要求する。
  virtual Status tx_epoch(SecurityScope scope, NodeId peer, std::uint32_t& epoch) noexcept;
  // 新規：context状態の問い合わせ（None / Establishing / Ready / Rekeying）
  virtual ContextState context_state(SecurityScope scope, NodeId peer) const noexcept;
};

// 新規：handshake engineだけが鍵をinstallできる（アプリ・Nodeは鍵を見ない）
class SessionInstaller {
 public:
  virtual Status install(const ContextKeys& keys) noexcept = 0;   // 方向別key/IV、context id、相手の検証済み要約
  virtual void retire(SecurityScope scope, NodeId peer) noexcept = 0;
  virtual void retire_all(NodeId peer) noexcept = 0;              // 失効時
};
```

- `open()`は未知context idに対し`AuthRequired`を返す（開発Providerへfallbackしない、replay扱いにもしない）。Nodeはこれを受けて、rate制限付きでRLRES1/EDHOCを要求する。
- Nodeは`config_.link_epoch/end_epoch`ではなく`tx_epoch()`でheaderを埋める。`wire::forward()`の`link_epoch`引数も同様。
- 現行の`NeighborAuthenticator`（16B tag×固定3 phase）は可変長・多往復のEDHOCを表せないため、本番用に`HandshakeEngine`（`begin`/`on_message`→`Continue | Done{proof, ContextKeys, RMS} | Fail{reason}`）を追加する。`AuthenticatedPeerProof`は引き続きengineだけが発行し、cookieは既存のまま。`UnavailableAuthenticator`は本番engineが認定されるまで残す。
- `security_profile()`がProductionを返すのは、SEC受入（[08](08-implementation-plan.md) §4）を満たしたbuildだけ。

## 9. 失敗の扱い

| 事象 | 動作 |
|---|---|
| 未知context idのframe | `AuthRequired`で破棄、rate制限付きで再handshake要求 |
| handshake途中の失効判明 | 昇格拒否（05 §7「失効中の遅い認証応答」） |
| counter上限接近 | 送信を止めずに並行して再鍵、上限到達時は送信拒否（wrapしない） |
| GK未知の新epochを受信 | 破棄、GroupKeyPull（1分1回） |
| group送信者表満杯 | 新送信者を拒否して数える |
| RTCのcontext CRC不一致 | 破棄してRLRES1 |
| `rlboot`巻き戻りの疑い（[05](05-nvs-state-37.md) §3.3） | groupの送信を停止し、fail closed |

## 10. 受入試験（planned_not_run）

| ID | 内容 |
|---|---|
| V1-K01 | Exporter/HKDFで導出したlink鍵が両端で一致し、方向・purposeで異なる（C++/Rust共通vector） |
| V1-K02 | 未知context idは`AuthRequired`、開発Providerへfallbackしない |
| V1-K03 | counterを2^48近くへ注入：再鍵し、wrapしない |
| V1-K04 | 再起動後に永続counterが無くても、捕獲した旧contextのframeは拒否される |
| V1-K05 | group：同一boot内のreplay拒否、tx_bootの後退拒否、表満杯で新送信者拒否 |
| V1-K06 | GK更新：stage→暗黙activation→overlap→旧鍵消去、遅れたmemberのpull |
| V1-K07 | 削除起因rekey：削除者にg+1が届かない、overlap後のgは拒否 |
| V1-K08 | broadcast経路広告：pairwise contextの無い送信者の広告を無視 |
| V1-K09 | GK更新でscope鍵が変わり、削除者のMember DISCOVERが無言drop |
| V1-K10 | 開発PSK profileのgolden vectorが不変 |
| V1-K11 | AuthorityEnvelope：replay拒否、gatewayが復号できない |
| V1-K12 | HKDF（実装済み）：RFC 5869 A.1〜A.3（このbranchで実行済み、`routeloom_kdf_tests`） |

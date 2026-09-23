# 01 — 要求・信頼構造・脅威モデル

## 1. 要求と設計の対応

| ID | KGuardの要求（意図） | 設計の答え | 本文 |
|---|---|---|---|
| R1 | 機器IDと機器固有鍵を事務所で一度書けば、どの現場のnetworkにも参加できる。現場鍵・現場設定は焼き込まない | 事務所記録RLI1は現場非依存。network id・MemberCert・GK・scope鍵・channelは参加結果（SitePackage）で受け取る | [02](02-zero-touch-join.md) §2, [07](07-host-api-tooling.md) §6 |
| R2 | 参加可否はKGuardが決め、RouteLoomが執行する | Site AuthorityがEDHOC message_3で機器の身元を検証し、KGuardへ`join.request`を出す。verdictをmessage_4で返し、allow前に台帳commit | [02](02-zero-touch-join.md) §6, [07](07-host-api-tooling.md) §2 |
| R3 | 未割当機器の告知はKGuardへ届く（発見済み機器）。業務通信はまだ不可 | 未割当機器の参加要求は検証済み身元付きでKGuardの`devices.discovered`へ入り、verdict=pending。機器はMemberにならず、DATA/route/serviceはadmissionで拒否 | [02](02-zero-touch-join.md) §7 |
| R4 | 電波が重なる隣接現場のnetworkには決して入らない。割当先だけ | 参加はallowを返した現場だけ。link確立はMemberCertの相互検証（同じSite Authority・同じnetwork）を要する。discoveryのhintは選別だけで証拠にしない | [02](02-zero-touch-join.md) §8 |
| R5 | 取り外し・紛失機器をnetworkから外す。旧割当（世代）の機器の通信を拒否 | RRS1（node_id, 最小世代）で近隣・gateway・authorityが拒否。削除時にGKを更新 | [04](04-removal-revocation.md) |
| R6 | 停電・再起動・中継器故障から人手なしで速く戻る | MemberCertは永続、KGuardへの再問合せ不要。近隣とはRLRES1で1往復半の再開、初対面はEDHOC | [06](06-fast-rejoin.md) |
| R7 | 通信は機器鍵で認証・暗号化。broadcast／一対多（ポンプ過熱→全表示盤）と経路広告のbroadcastはgroup鍵 | link／E2Eは機器鍵によるEDHOC由来のpairwise鍵。GKから送信者別鍵を導出 | [03](03-key-hierarchy.md) |
| #37 | ピアごとの永続counter/replayキーが消せずNVSが満杯になる | 本番profileでピアごとのcounter/replay recordを作らない（handshakeごとに新鍵、RAMのみ）。永続は固定slotの再開cacheだけ。開発profileは暫定策 | [05](05-nvs-state-37.md) |

## 2. 登場者と鍵の所有

```text
                 ┌────────────── 組織PKI（KGuard運用者） ──────────────┐
                 │ Org Root（オフライン）                               │
                 │   ├─ Device CA（事務所の署名端末／HSM）→ DevCert      │
                 │   └─ Site CA（本部、オフライン／HSM）  → SiteCert     │
                 └──────────────────────────────────────────────────────┘
 事務所: NodeId・機器鍵・DevCert・Site CA公開鍵をRLI1へ書く（一度だけ）
 現場PC: routeloom-host daemon ─ Site Authority（SAK＋SiteCert、台帳、GK、RRS1）
             │  API1（Unix socket）          │ USB HostOps
          KGuardアプリ                     Gateway（ESP32、≤4台、JoinProxy兼member）
                                               │ ESP-NOW LR（Wire v2 / RLD1）
                                          member機器 … 参加希望機器
```

| 鍵・証明 | 生成場所 | 秘密の保管 | 検証する者 | 失効・更新 |
|---|---|---|---|---|
| Org Root | 本部オフライン | オフライン保管のみ | Device CA/Site CAの証明書を通じて間接的に | 本設計の範囲外（物理的な再配備） |
| Device CA鍵 | 本部 | 事務所署名端末（本番はHSM） | Site Authority（DevCert検証） | Site Authorityの設定で旧CAを無効化 |
| Site CA鍵 | 本部 | オフライン／HSM | 機器（RLI1のanchor、≤2） | anchor 2枠で世代交代。機器側更新は後続設計（§7） |
| 機器鍵（P-256、ES256） | 機器内生成を既定 | 機器（RLI1、tier T1は平文NVS） | Site Authority（参加時）、近隣（MemberCert経由） | 紛失時はRRS1。鍵更新は再発行＋再参加 |
| SAK（Site Authority鍵） | 現場PC | 現場PC（開発はファイル、本番はTPM/HSM相当） | 機器（SiteCert経由） | 計画交換・侵害時はSite CA署名のSiteAuthorityChange（§7、後続） |
| MemberCert（=Grant） | Site Authority | 公開 | 近隣・gateway・authority | 世代（RRS1）、site_epoch cutover |
| DAMS（機器–authority主秘密） | EDHOC Exporter | 機器RLS1、authority DB | — | 再参加・cutoverで更新 |
| 再開秘密RMS（ピア対ごと） | EDHOC Exporter | 固定slotの再開cache | — | 寿命上限、RRS1、LRU追い出し |
| GK（network group鍵） | Site Authority | 全memberのRLS1 | — | 24時間ごと・削除時 |
| セッション鍵（link/E2E/group送信者鍵） | handshake／導出 | RAMのみ（sleep端末はRTC） | — | handshakeごとに新規 |

KGuardは参加判定と台帳の利用者であり、鍵を持たない。API1に秘密鍵exportはない（[host仕様](../../spec/host.md) §4）。

## 3. 用語

| 用語 | 意味 |
|---|---|
| 現場（site） | 1台のSite Authorityが管理する範囲。network id（全64bit）を一つ持つ |
| site_id | 現場の64bit識別子。SiteCertのsubject |
| site_epoch | 現場の配備世代（u32）。network id上位32bit（[04 provisioning §4.8](../sdk-completion/04-provisioning-lifecycle.md)の分割）。cutoverで+1 |
| assignment generation | 機器ごとの割当世代（u32）。KGuardが割当し直すたびにSite Authorityが+1 |
| 未割当（unassigned） | RLI1はあるがRLS1（現場所属）が無い機器。MembershipStateは`Unprovisioned`→`Discovering` |
| proxy | 参加希望機器と1hopで話すmember。RLD1とWire bootstrapの限定中継だけを行う |
| authority channel | 機器とSite Authorityの間のE2E保護（gatewayを透過）。GK配布・通知に使う |

## 4. 守るもの（脅威モデル）

攻撃者の能力として、電波の盗聴・注入・再送・改変（RF-only）、部外者機器の設置、別現場の正当な機器・gateway、1台のmember機器のflash読出し（tier T1）を考える。

| 脅威 | 対策 | 残る制約 |
|---|---|---|
| 部外者の偽参加 | DevCert（Device CA署名）の所持証明がないとmessage_3が通らない。KGuardのallowが必要 | Device CA鍵の侵害は範囲外（運用） |
| 偽Site Authority（未認証）への誘導 | 機器はmessage_2のSiteCertをRLI1のSite CAで検証し、署名を確認するまで身元を明かさない | Site CA鍵の侵害は範囲外 |
| 隣接現場（正規authority）への誤参加 | allowは割当先のKGuardだけが返す。重複allowを防ぐのはKGuardの割当一意性。strict mode（§5）では本部署名の割当証明で機器側も検証 | 既定modeでは「正規だが別現場のauthorityが誤ってallow」を機器は見分けられない（§5） |
| 未割当機器の偽報告（発見済み一覧の汚染） | 発見済み一覧はmessage_3検証後に載せる。偽DevCertでは載らない | 正規機器の電波を中継して別現場に見せることは可能（表示に経路・RSSIを付ける） |
| 盗聴・改ざん・replay（link/E2E） | handshakeごとの新鍵、AES-GCM、受信窓（RAM） | 受信側の再起動をまたぐgroup frameのreplay（[03](03-key-hierarchy.md) §6.5） |
| 削除済み機器の居座り | RRS1、GK更新、MemberCertの世代 | 分断中の群にはRRS1が届くまで効かない。信頼できる時刻が無ければ上限なし |
| 1台のmemberのflash読出し（T1） | その機器になりすませるのは失効まで。他機器の鍵・SAKは得られない | GKは得られる（削除時更新まで group frameを読める・偽造できる） |
| preauth flood | cookie、proxyの同時1件、authority全体の同時数、機器ごとのbackoff | 帯域の消費自体はゼロにできない |
| 偽の拒否ヒントによる自己消去 | 現場状態の消去はSAK署名のRemovalNotice／RRS1を検証した時だけ | — |

## 5. 誤参加防止の二つのmode

| mode | 機器が確認するもの | 守れること | 必要なもの |
|---|---|---|---|
| A1（既定） | SiteCertが自分のSite CA anchorに連なること、message_4のallow | 組織外のauthorityには入らない。組織内では各現場KGuardのallowだけに従う | 何も追加しない |
| A2（strict） | A1＋本部の割当署名鍵が署名したAssignmentTicket（node, site_id, generation）がmessage_4に入っていること | 組織内の別現場authority（盗難gateway・誤設定PCを含む）がallowしても入らない | KGuard本部に割当署名鍵と発行API。RLI1に割当検証鍵（anchor枠を1つ使う） |

A1で残るのは「組織内の正規だが別現場のSite Authorityが誤ってallowする」ケースで、これは暗号では防げずKGuardの割当一意性に依存する。現場PCの盗難・悪用が脅威に入る配備はA2を選ぶ。どちらを既定にするかは製品責任者の判断事項（[08](08-implementation-plan.md) §6 Q2）。

## 6. 範囲外（non-goals）

- RF妨害・全帯域jammingの排除、承認済みrelayのdrop・虚偽metricの完全防止（[セキュリティ契約](../../spec/security.md) §1と同じ）。
- Org Root／Device CA／Site CAの侵害からの暗号的な自己回復。
- 同じ機器鍵を複製した2台の区別、tier T1での物理的なflash書戻し（rollback）攻撃（[04 provisioning §4.10](../sdk-completion/04-provisioning-lifecycle.md)）。
- Site Authorityの冗長化（1現場1 authority。複数PCのactive-activeはv1範囲外）。
- 通信量解析・機器IDの秘匿：RLD1 headerのclaimed_nodeは平文。EDHOCが守るのはmessage_3内の証明書の中身だけ。
- 信頼できる時刻が無い構成での、有効期限による失効保証。
- 業務データの意味（KGuardの設備・判定・画面）。

## 7. 本書で後回しにするもの

- Site CA anchorの機器側での更新（本部署名のanchor更新object）：2枠で当面の交換は可能。仕組みは後続。
- SAK侵害時のSiteAuthorityChange（Site CA署名、site_id・新SiteCert・最小site_epoch）：形式だけ[04](04-removal-revocation.md) §8で予約。
- 機器鍵のeFuse/DS・secure element化（tier T2/T3）：[04 provisioning §4.10](../sdk-completion/04-provisioning-lifecycle.md)の判断に従う。

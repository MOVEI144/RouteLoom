# 07 — Host（KGuard）API・USB HostOps・事務所tooling

## 1. 役割分担

| 役割 | 実装場所 | 持つもの | 持たないもの |
|---|---|---|---|
| Site Authority | `routeloom-host` daemon内の新service | SAK（handle）、SiteCert、Device CA公開鍵、台帳、機器登録、DAMS、GK履歴、RRS1、発見済み機器表 | 業務の割当情報 |
| KGuard | API1 client（別プロセス） | 機器↔現場の割当、画面、業務DB | 鍵・証明書の秘密 |
| gateway firmware | ESP32 | 中継（RLD1⇄Wire⇄USB）、自分のmember鍵 | SAK、他機器のDAMS |

KGuardは「参加させてよいか」を答え、RouteLoomは「その答えを暗号的に執行する」。KGuardが停止している間、新規参加はpendingになり、既存memberの通信・再参加は影響を受けない。

## 2. API1 method（案）

形式は既存の`API1 {"v":1,"request_id":"…","method":"…","params":{…}}`（[api1.rs](../../../host/routeloom-host/src/api1.rs)）。push通知は既存`messages.subscribe`の仕組みに`membership` streamを追加する。権限はACL（[host §4](../../spec/host.md)）で`membership.read` / `membership.decide` / `membership.admin`に分ける。

| method | 権限 | 目的 |
|---|---|---|
| `site.status` | read | site_id、network、site_epoch、SAK fingerprint、rs_epoch、gk_epoch、member数、gateway接続状況 |
| `join.policy.get` / `join.policy.set` | admin | `zero_touch_open`、`decision_mode`（`kguard`＝既定／`closed`）、`decision_timeout_ms`（500〜5000）、pending時の`retry_after_s`既定値 |
| `join.requests.list` | read | 決定待ち・pendingの参加要求（上限256） |
| `join.decide` | decide | 参加要求へのverdict |
| `devices.discovered.list` | read | 未割当の発見済み機器（[02](02-zero-touch-join.md) §9、上限1024） |
| `members.list` / `members.get` | read | member一覧、世代、最後の確認、confirm状態 |
| `membership.revoke` | decide | 削除（operationを返す） |
| `membership.cutover` | admin | site_epoch cutoverの開始（[04](04-removal-revocation.md) §7） |
| `group_keys.status` / `group_keys.rotate` | read / admin | GK世代、staging進捗、手動更新 |
| `operations.get` | read | 既存。revoke・rotate・cutoverの段階を返す |

### 2.1 参加要求とdecision

```json
// push (stream "membership")
{"event":"join.request","request_id":"jr-7f3a","device_id":"0x00A1000000001234",
 "kid":"b3…(64 hex)","model":17,"hw_rev":2,"fw_version":"1.4.0","cert_serial":90211,
 "requested_role":"endpoint","capability":["relay"],"previously_removed":false,
 "via":{"gateway":"0x00A1000000000001","proxy":"0x00A1000000000777","authority_hops":3,"joiner_rssi_dbm":-71},
 "deadline_ms":2000,"attempt":1}
```

```json
// request
{"v":1,"request_id":"k-1","method":"join.decide",
 "params":{"join_request_id":"jr-7f3a","device_id":"0x00A1000000001234",
           "verdict":"allow","role":"endpoint","idempotency_key":"kg-assign-5521"}}
// response
{"v":1,"request_id":"k-1","result":{"state":"committed","generation":3,
 "member_cert_serial":4412,"operation_id":"op-91"}}
```

| verdict | params | 返るJoinResult |
|---|---|---|
| `allow` | `role`（endpoint/relay/gateway） | Allow（台帳commit後） |
| `pending` | `retry_after_s`（30〜3600） | PendingAssignment |
| `deny` | `reason`：`not_here` / `blocked` | DenyNotHere / DenyBlocked |

- `deadline_ms`を過ぎた決定も有効：その機器の次の試行（pending ticketのRLRES1またはEDHOC）で即座に反映する。
- 同じ`idempotency_key`の再送は同じ結果を返す。同じ要求に異なるverdictを出した場合は`Conflict`。
- `allow`の応答`state`は`committed`（台帳commit済み）→機器が受け取ったかは`members.get`の`confirm_state`（`allowed_unconfirmed` / `active`）で分けて見せる。操作成功・台帳commit・機器への適用を別stateで返す（[host §3](../../spec/host.md)）。
- cutover・台帳既存の承認による自動再発行では、KGuardへ`join.request`は出さず、`membership` streamへ`member.reissued`を通知する（人手の承認をやり直さない）。KGuardが割当を外していた場合に備え、`assignment.check`イベントで確認できるmodeも用意する（既定off、製品判断）。

### 2.2 削除

```json
{"v":1,"request_id":"k-2","method":"membership.revoke",
 "params":{"device_id":"0x00A1000000001234","expected_generation":3,
           "reason":"lost","idempotency_key":"kg-rm-88"}}
// result: {"operation_id":"op-92","state":"committed","rs_epoch":14}
// operations.get → {"state":"distributing","reached":71,"members":96,"unknown":25,
//                   "gk_rotation":{"from":203,"to":204,"state":"staging"}}
```

`expected_generation`が現在と違えば`Conflict`（古い画面からの誤削除を防ぐ）。段階：`accepted → committed → distributing → converged`。到達できないmemberは`unknown`として数え続け、適用済みとは言わない。

### 2.3 イベント一覧（stream `membership`）

`join.request`、`join.decided`、`member.confirmed`、`member.reissued`、`member.revoked`、`device.discovered`（初回・1分以上空いた再出現）、`gk.rotated`、`rrs.published`、`cutover.progress`、`authority.error`。各イベントは単調な`cursor`を持ち、既存receive APIと同じcursor・overflow規則に従う。

### 2.4 実装状況（P3-3、このbranch、host試験のみ・実機未接続）

`routeloom-host`の`--site-authority DIR`で起動するSite Authority（[site/](../../../host/routeloom-host/src/site/mod.rs)）と、そのAPI1面（[api1/site.rs](../../../host/routeloom-host/src/api1/site.rs)）、KGuard側の`routeloom-client::site`（`SiteAdmin` trait、RouteLoom実装、`KGuardMock`）を実装した。上の案との違いと確定した形を以下に記す。USBの参加中継（0x40〜0x42、P3-2）とauthority channel（P5）には**まだ配線していない**。

**EDHOC**：Responderは新crate `host/routeloom-edhoc`（pure Rust、RustCrypto primitive、suite 2、method 0と、RFC 9529 trace用のmethod 3）。`lakers`はmethod 3（STAT-STAT）専用、vendor済みlibedhocへのFFIはworkspaceの`unsafe_code = "forbid"`に反するため、自作engineを二つの基準で固定した：RFC 9529 §3を両roleでbyte一致（§4の不正messageは全拒否。§4.1.2はlibedhocと違い拒否）、および実機側stack（libedhoc＋`routeloom::edhoc` backend）との**method 0のjoin transcriptを両方向でbyte一致**（[protocol/edhoc-interop](../../../protocol/edhoc-interop/README.md)。Rustはcargo test、C++はctest `routeloom_edhoc_interop_replay`で同じfileを再生）。ID_CREDは両方向ともkid（SHA-256(COSE_Key)）、証明書は**EADで値渡し**：EAD_2＝SiteOffer＋SiteCert、EAD_3＝JoinRequest＋DevCert（label `-65541`、`routeloom_join::JOIN_EAD_CREDENTIAL_LABEL`。P3-1で機器側と一致させ凍結済み）。CRED_xはその証明書のbyte列なので、差し替えはSignature_2/3で失敗する。

**機器側への指摘（統合時に必須、P3-3で解決済み）**：証明書を値渡しするとlibedhocのarena使用量はInitiator 1408B／Responder 1440Bになり、1280Bではmessage_2（機器側）の処理が`EDHOC_ERROR_NOT_ENOUGH_MEMORY`で失敗した。`ROUTELOOM_EDHOC_ARENA_BYTES`は**2048B**に引き上げ済み（Session全体はLP64で3880B）で、証明書運びのjoin交換はarena内に収まる。

**DAMS**：Exporter label 32771、context＝決定的CBOR配列`["RouteLoom",1,4,network,node,site_id,device_kid,sak_kid]`（`routeloom_join::dams_exporter_context`。P3-4でjoin専用contextとして凍結し、機器側の`sdkv1_ead.hpp` `dams_exporter_context`と`protocol/sdkv1-golden/dams/`のvectorでbyte一致する）。Allowの配送前に台帳へ保存する。

**API1（確定形）**。権限は新しいACL grant `MEMBERSHIP_READ` / `MEMBERSHIP_DECIDE` / `MEMBERSHIP_ADMIN`（既存のSEND等とは独立、site networkの下位32bitで判定）。principalはsocketのpeer credentialだけで決まる。

| method | 権限 | params → result |
|---|---|---|
| `site.status` | READ | なし → site_id、network、site_epoch、SAK fingerprint（kid）、rs_epoch、gk_epoch／gk_staged、member・removed・unconfirmed数、discovered・join_requests数、live exchange数、channel、gateways、ledger_seq、policy、counters（`rejected_unverified{reason}`等）、`usb{configured,attached,join_relay:"not_wired"}` |
| `join.policy.get` / `.set` | ADMIN | `zero_touch_open`、`decision_mode`（`kguard`/`closed`）、`decision_timeout_ms`（500〜5000）、`pending_retry_after_s`（30〜3600）。setは部分更新 |
| `join.requests.list` | READ | 開いている参加要求（≤256）：`state`＝`awaiting`／`decided`、`remaining_ms` |
| `join.decide` | DECIDE | `join_request_id`、`device_id`、`verdict`＋その引数だけ（allow→`role`、pending→`retry_after_s`、deny→`reason`）、`idempotency_key` |
| `devices.discovered.list` | READ | `after?`、`limit?`（1〜128）→ `devices[]`、`next_after`、`total`、`max:1024` |
| `members.list` / `members.get` | READ | `after?`、`limit?`、`include_removed?` ／ `device_id` |
| `membership.revoke` | DECIDE | `device_id`、`expected_generation`、`reason`（removed/lost/replaced/blocked）、`idempotency_key` |
| `operations.get` | READ | `op-…`（approve／revoke）はSite Authorityが答える。grant無しは存在を明かさずNOT_FOUND |

```json
// join.request（stream "events"、ringのseq/ms付き）
{"seq":12,"ms":1790000000000,"kind":"join.request","join_request_id":"jr-0000000000000001",
 "device_id":"00a1000000001234","kid":"b3…(64 hex)","model":17,"hw_rev":2,"cert_serial":90211,
 "fw_version":17039360,"capability":["relay"],"requested_role":"endpoint",
 "previously_removed":false,"kid_conflict":false,
 "via":{"gateway":"00a1000000000001","proxy":"00a1000000000777","authority_hops":2,"joiner_rssi_dbm":-60},
 "deadline_ms":2000,"attempt":1}
// join.decide allow → 台帳commit後に応答
{"state":"committed","join_request_id":"jr-0000000000000001","device_id":"00a1000000001234",
 "verdict":"allow","role":"endpoint","generation":1,"member_cert_serial":1,
 "operation_id":"op-0000000000000001","applied":"current_attempt"}
// join.decide pending / deny → "state":"recorded"（"applied":"next_attempt"は期限後の決定）
// membership.revoke
{"operation_id":"op-0000000000000002","state":"committed","device_id":"00a1000000001234",
 "generation":1,"rs_epoch":1,"gk_rotation":{"from":1,"to":2,"state":"staged"},
 "distribution":"not_implemented"}
// operations.get op-…2
{"operation_id":"op-0000000000000002","kind":"revoke","device_id":"00a1000000001234","generation":1,
 "state":"committed","rs_epoch":1,
 "distribution":{"state":"not_implemented","reached":null,"members":0,"unknown":0},
 "gk_rotation":{"from":1,"to":2,"state":"staged"},"created_ms":1790000000030}
// members.get
{"member":{"device_id":"00a1000000001234","kid":"b3…","state":"member","generation":1,"role":"endpoint",
 "member_cert_serial":1,"confirm_state":"allowed_unconfirmed","delivered":true,"model":17,"hw_rev":2,
 "cert_serial":90211,"approved_ms":…,"delivered_ms":…,"confirmed_ms":null,"last_seen_ms":…,
 "removed_ms":null,"removal_reason":null}}
```

エラー：grant不足は`AuthorizationFailed`、未設定は`SITE_AUTHORITY_UNAVAILABLE`、引数は`INVALID_ARGUMENT`、閉じた／無い要求は`NOT_FOUND`、同keyで別内容・決定済み要求への別verdict・device_id不一致・kid conflictのallow・`expected_generation`不一致・削除済みへのrevokeは`CONFLICT`、RRS1が32件で満杯なら`CUTOVER_REQUIRED`、storeが書けなければ`STORE_FAILURE`（retryable、何も変わっていない）。

**イベント**：案のstream `membership`ではなく既存の`events` stream（event ring）へ出す。kind：`join.request`、`join.decided`、`device.discovered`（初回と1分以上空いた再出現）、`member.reissued`、`member.confirmed`、`member.revoked`、`member.removal_notified`、`rrs.published`、`gk.staged`、`authority.error`。`messages.subscribe`の`filter.kinds`で選べる。`gk.rotated`・`cutover.progress`は対応する機能（P5・P6-2）が無いので出さない。

**判定の規則（実装）**：(node, kid)に有効な承認があればKGuardへ聞かず同じMemberCertを再発行（`member.reissued`）。削除済みで`JoinRequest.last_site_id`がこの現場なら`Removed`＋RemovalNotice、そうでなければ`previously_removed:true`の新しい参加要求。同じNodeIdの有効なmembershipと別kidは`kid_conflict:true`で、allowは`CONFLICT`（先に既存membershipをrevokeする）。競合は要求作成時のflagではなくcommit時の現行DeviceRowで判定し、revoke済みの行は競合にしない（別kidの参加は`previously_removed:true`の要求で、明示allowがgenerationを進めて置換する）。決定済み要求への同一verdictの再呼出しは、同一idempotency keyならidempotency記録の保持範囲（最新1,024件）内で保存済みの応答を返す。別keyのallowは現行DeviceRowを検査し、承認した(kid, generation)がmemberとして有効なときだけ保存済みの結果を返し、失効・置換済みなら`CONFLICT`。別keyへの成功応答もそのkeyのidempotency記録として残る。KGuardが`decision_timeout_ms`内に答えなければPendingAssignment（`pending_retry_after_s`）で、要求は開いたまま残り、後の決定は次の試行で即反映。KGuardのpendingを配送した後、`retry_after`より5秒以上早い再試行はAuthorityBusy（残り秒数）。`decision_mode:"closed"`または`zero_touch_open:false`ではKGuardへ聞かずpending（発見済み一覧には載る）。同時参加は4件、同じjoiner MACのmessage_1は2秒に1件で、超過はrelay abort（`busy`、EDHOC sessionが無いのでJoinResultは送れない）。

**永続化（実装）**：`DIR/site.db`（SQLite、作成時0600、exclusive lock、`synchronous=FULL`）。`meta`（site binding＝site_id・network・SAK kid。別の現場の台帳では起動を拒否）、`devices`（kid、DevCert、member/removed、generation、role、MemberCert＋serial、confirm、DAMS、時刻、削除理由）、`ledger`（approve/revokeのSHA-256 hash chain。起動時に検証し、切れていれば拒否）、`rrs`（発行した全RRS1）、`group_keys`（active＋staged）、`docs`（発見済み機器・参加要求・idempotency記録・operationのJSON）。1回の変更は1 transactionで、allowは台帳・device行・MemberCertのcommit後にだけ`committed`を返し、配送はDAMSの保存後。DAMS・GKはDB fileの0600だけで守られる（host鍵による封緘・TPMは未実装）。SAKは`DIR/sak.key`（`routeloom-root-key-v1`、FileRootSignerと同じ開発custody、起動時に警告）で、SiteCertのcnf・site_idと一致しなければ起動を拒否。SiteCertは`routeloomctl site-cert`（P7-2）で本部のSite CA鍵から発行する。

**GKの境界（P5）**：初回起動時にGK epoch 1を生成してSitePackageに載せる。削除時は次のGKを`staged`で作るだけで、配布・activation・24時間周期の更新はP5。stagedは新規参加者にも渡さない（全memberに配るまでactivateしない）。

**transport**：`site::transport::JoinTransport`（`RelayUp`＝0x40の中身、`Outbound::Down`＝0x41、`Outbound::Abort`＝0x42、step 1〜4＝EDHOC message、5＝EDHOC error、status 0継続／1最終）とin-process実装。USBへの結線（HostOps codec・capability bit）は並行作業（P3-2）の後に統合者が`UsbJoinRelay`経由で行う。authority channel（JoinConfirm→`member_confirmed`）の受け口はあるが、P5までmemberは`allowed_unconfirmed`のまま。

**試験**：`cargo test -p routeloom-edhoc`（RFC 9529、method 0、interop replay）、`cargo test -p routeloom-host site::`（状態機械、SQLite、再起動後の同一MemberCert再発行、削除とRRS1／RemovalNoticeの検証、admission上限、store故障、API面）、daemonのAPI1 socket経由で`KGuardMock`が`SiteAdmin`を操作する端から端までの試験（未割当→pending→割当→Allowを`join_allow_verify`で検証、deny not_here、ACL、idempotency、削除）。

## 3. 永続化（host）

既存の`sqlite_store.rs`系のstoreに次の表を足す（名前は案）。

| 表 | 内容 | 規則 |
|---|---|---|
| `site` | site_id、network_low32、site_epoch、SiteCert、SAK handle参照 | 1行 |
| `devices` | node_id、kid、DevCert、状態、assignment_generation、MemberCert、DAMS（host鍵で封緘） | 台帳commitと同じtransaction |
| `ledger` | SingleAuthorityの操作（MembershipApproval/Revocation） | 既存ledgerと同じ単調性 |
| `rrs` | 発行したRRS1の履歴 | epoch単調 |
| `group_keys` | g、GK（封緘）、状態、memberごとのack | 最新2世代だけ保持 |
| `discovered` | 発見済み機器 | 1024件LRU |
| `join_requests` | 決定待ち・pending | 256件、期限切れで削除 |

crash順序：(1) `ledger`と`devices`をcommit → (2) MemberCert/JoinResultを作る → (3) 送信。(2)(3)の前に落ちても、機器の再試行で(1)から冪等に再発行する。GKは「保存してから配る」。

SAKの保管：開発は権限600のファイル（既存`FileRootSigner`と同じ扱いで**本番custodyではない**）、本番はTPM/HSM等の署名境界（`SiteSigner` trait、実装は範囲外）。秘密鍵をAPI・ログ・診断へ出さない。

## 4. USB HostOps（案）

capability bit `kCapSiteAuthorityV1 = 1u << 6`（HelloAckのcapability digestに束縛、既存bitの意味は変えない）。

| sub | 方向 | 本文 | 用途 |
|---|---|---|---|
| 0x40 JoinRelayUp | G→H | `gateway u64 | from_proxy u64 | hops u8 | RelayHeader＋本文` | 参加・pending再試行の上り |
| 0x41 JoinRelayDown | H→G | `to_proxy u64 | RelayHeader＋本文` | 下り（最終はstatus=1） |
| 0x42 JoinRelayAbort | 双方向 | `proxy u64 | relay_id u32 | reason u8` | 中継の打切り |
| 0x43 AuthorityUp | G→H | `origin u64 | AuthorityEnvelope` | 機器→authority（[03](03-key-hierarchy.md) §5.3） |
| 0x44 AuthorityDown | H→G | `destination u64 | AuthorityEnvelope` | authority→機器 |
| 0x45 SiteStateSet | H→G | `site_epoch u32 | rs_epoch u32 | gk_epoch u32 | GK操作（stage/activate）` | gatewayのGK切替・RRS1配布の起点 |
| 0x46 SiteStateReport | G→H | gatewayが観測した近隣のepoch分布・拒否counter | 収束の観測 |

USB frame上限4096Bに対し最大の本文はRRS1付きで約700B。gateway自身の参加は、USB上で同じEDHOC m1〜m4を0x40/0x41で直接運ぶ（proxy無し、`hops=0`）。KGuardのallowが必要なのは他の機器と同じ。

**Resolved in implementation（P3-2）**：上の表のbit 6と0x40〜0x42はnode_status_v1が、0x50〜0x52とbit 7はgroup_delivery_v1が既に使っているため、参加中継は**capability bit 8（`kCapJoinRelayV1`）とHostOps 0x60 JOIN_RELAY_UP／0x61 JOIN_RELAY_DOWN／0x62 JOIN_RELAY_ABORT／0x63 JOIN_RELAY_RESULT**（0x61/0x62への応答）として実装した（形式は[02 §7.4](02-zero-touch-join.md)、共通vector `protocol/usb-golden/join-relay`、Rust `routeloom-protocol::join_relay`）。表の0x43〜0x46（P5）も同じsite-authority族の0x64〜0x67に置くことを推奨する（未実装）。bitは中継だけを表し、P5の機能は別bitで広告する。gateway自身の参加（`hops=0`）は未実装。

**Resolved in implementation（P3-2 #116）**：参加中継をv2化した（形式は[02 §7.5](02-zero-touch-join.md#75-wire-relay-v2p3-2-116)）。族は0x60〜0x63のままinner schemaを**2**に上げ、**capability bit 9（`kCapJoinRelayV2`）**で広告する。0x62／0x63は完全なRelayToken（両epoch付き）を運び、Okの0x63は完全な非0 tokenを必ず持つ。共通vectorは`protocol/usb-golden/join-relay-v2/`（codec＋20 step session、[README](../../../protocol/usb-golden/join-relay-v2/README.md)）で、C++ bridgeの再生とRustの復号がbyte一致する。hostの`RelayKey`は両epochを追加し、`RelayUp／Down`はphaseを明示する（P3-3のSiteServiceはphase 4だけ受理）。v1（bit 8・schema 1）へのfallbackは無い。

## 5. KGuardとの典型的な流れ

| 場面 | 流れ |
|---|---|
| 新品を設置 | 機器電源ON→`join.request`→KGuardは割当表を見て`allow`→機器Member（人手無し。割当が事前登録済みなら数秒〜十数秒、未測定） |
| 未割当機器 | `join.request`→KGuardが`pending`→画面の「発見済み機器」に表示→担当者が割当→次の試行（≤retry_after）でallow |
| 他現場の機器が見える | `join.request`→KGuardが`deny not_here`（中央の割当DBで他現場と分かる場合）または`pending` |
| 取外し | `membership.revoke`→`operations.get`で収束確認 |
| 別現場へ移設 | 元の現場で`revoke`→機器は未割当へ戻る→新しい現場の`join.request`で`allow` |
| 停電 | 何もしない（[06](06-fast-rejoin.md)） |

## 6. 事務所tooling（routeloom-provision）の変更

現状の[routeloom-provision](../../../host/routeloom-provision/src/lib.rs)はRLT1（現場の信頼image）・RLC1（networkとgrant入りの機器記録）・RTM1を作る。ゼロタッチでは事務所で**現場に依存するものを作らない**。

| 追加・変更 | 内容 |
|---|---|
| `DeviceCaSigner` trait（`RootSigner`と同じ境界） | DevCert署名。開発はファイル、本番はHSM |
| `devcert`モジュール | RLCW1 DevCertのencode／検証（C++と共通vector） |
| `identity`モジュール | RLI1のcodec（C++ `identity_record`と共通vector） |
| `nvs`モジュール | `rlsec` partition用のNVS image生成（`rlident`だけ）。既存`rltrust`/`rlcred`生成は開発・bench用に残す |
| `site-cert`コマンド | Site CAでSiteCertを発行（現場PC導入時、本部で実施） |
| 在庫出力 | `(node_id, kid, model, cert_serial)`のJSON/CSVをKGuardへ渡す（割当の事前登録用） |

事務所の手順（1台あたり）：

1. 量産firmwareを書込み（保守console有効build、またはstrap）。
2. 機器内で鍵生成（Entropy READY後、[セキュリティ §9](../../spec/security.md)）。機器は公開鍵と所持証明（nonceへの署名）をUSBで返す。
3. 署名端末が所持証明を検証し、DevCertを発行。
4. RLI1（NodeId、DevCert、Site CA anchor、flags）を書込み、readbackで確認。
5. `console_locked`を立てる（量産時）。在庫記録を出力。

鍵を外で作って注入する方法はtier T1未満の選択肢として残す（[04 provisioning §4.4](../sdk-completion/04-provisioning-lifecycle.md)）。事務所でnetwork id・現場鍵・channelを書く手順は無くなる。

### 6.1 実装状況（P7-1、host試験済み・実機未試験）

P7-1で実装した事務所側tooling。本番custody（HSM）・実機での書込みは含まない。firmwareの保守verbとstore配線は§6.2に記す。

| 部品 | 場所 | 内容 |
|---|---|---|
| `DeviceCaSigner` | `routeloom-provision`の`sdkv1::devca` | `RootSigner`と同じ境界のtrait（`device_ca_id`・`pubkey`・`sign`）。開発用`FileDeviceCaSigner`は鍵文書`routeloom-device-ca-key-v1`（権限0600で作成、上書き拒否、読込時に公開鍵を再計算して不一致は破損、group/other可読なら拒否）。root鍵文書とは形式が違い、相互に読めない。使用時に「本番custodyではない」警告を出す |
| DevCert発行 | `devcert_issue` | 所持証明を検証済みの鍵（`VerifiedDeviceKey`、`pop_verify`だけが作る）にだけ発行する。発行後にDevice CA公開鍵で自己検証し、custody側の不具合で不正な証明書を出さない。Site Authority側の検証`devcert_verify`（型・issuer・署名） |
| 所持証明（PoP） | `sdkv1::pop` | 事務所の32B challengeに対し、機器が認証してほしい鍵自身で署名する制限付きES256 COSE_Sign1（183B）。payload 108B＝`version u8=1 | key_location u8（1/2/3、0は拒否） | reserved u16 | node_id u64 | challenge 32B | pubkey 64B`、external AAD＝`"RouteLoom/device-key-pop/v1" 00`（28B）、low-Sのみ。形式不正はProtocolError、node・challenge不一致と署名不正はAuthorizationFailed。AADのdomainで証明書・RRS1・EDHOCの署名と混同しない |
| RLI1組立て | `sdkv1::office` | 注入鍵（`nvs-plaintext`）のRLI1を機器の起動検査と同じ規則で作る。機器内生成鍵では秘密を持たないため、機器の保守verbがRLI1を封緘するための`routeloom-identity-bundle-v1`（node_id・flags・anchor・DevCert、秘密なし）を出す。在庫行（node_id・kid・model・hw_rev・cert_serial・device_ca_id、DevCertから導出） |
| `rlsec` NVS image | `sdkv1::rlsec`、`nvs::nvs_partition_csv` | `rlident`の`i0`/`i1`に同一のcommitted RLI1（used_lenちょうど）。既存P-A1と同じくblob fileとJSON記述子（`routeloom-rlsec-nvs-v1`、partition名付き）を出し、加えてESP-IDF `nvs_partition_gen.py`用CSVを出す。出力前に二重slotとしての読戻し（両blob一致・committed・起動検査合格）を確認 |
| CLI | `routeloomctl provision-devca-keygen`／`provision-pop-challenge`／`provision-devcert`／`provision-identity` | daemon socketを使わない。使い方は[routeloom-provision README](../../../host/routeloom-provision/README.md) |
| 機器側NVS adapter | [sdkv1_blob_storage.hpp](../../../components/routeloom/include/routeloom/sdkv1_blob_storage.hpp)、`routeloom_espnow`の`nvs_sdkv1_store` | 4つのstoreを`rlsec`の`rlident`（`i0`/`i1`）・`rlsite`（`s0`/`s1`）・`rlrevo`（`r0`/`r1`）・`rlres`（`s00`〜`s15`、gatewayは`s000`〜`s159`）へ写す。読戻し規約はtrust/credential adapterと同じ（key無し＝未書込み、存在するが全0xFF／全0／長さ0＝破損、slot超過・読込長不一致＝破損、暗黙のeraseなし）。規約とslot対応はportable側にあり、NVSと同じ原子的更新を持つfake NVSでhost試験。ESP-IDF側は`nvs_open_from_partition`・`nvs_get_blob`・`nvs_set_blob`＋`nvs_commit`への転送だけ。§6.2で両firmwareに配線した |

`rlsec`の書込み手順（注入鍵、開発・bench）：

```sh
routeloomctl provision-devca-keygen --device-ca-id 0dca000000000001 --out devca.key
routeloomctl provision-identity --ca-key devca.key --spec identity-spec.json \
    --node 00a1000000001234 --serial 1 --out-dir dev-00a1000000001234
cd dev-00a1000000001234
python -m esp_idf_nvs_partition_gen generate rlsec-nvs.csv rlsec.bin 0x10000   # gatewayは0x20000
esptool.py write_flash 0x190000 rlsec.bin                                      # partitions.csvのrlsec offset
```

生成したCSVはPyPIの`esp-idf-nvs-partition-gen`（ESP-IDFの`nvs_partition_gen.py`と同じもの）で64KiB imageにでき、image内の`rlident`/`i0`・`i1`が`identity.rli1`とbyte一致することを手元で確認した（CIには入れていない）。`rlsec`全体を書き換えるので既存の`rlcounter`/`rlreplay`は消える（08 Q13で許容済みのNVS消去）。tier T2のNVS暗号化は生成器の`encrypt`と`nvs_keys` partitionで行うが、flash暗号化・secure bootのeFuse操作は不可逆で別承認のため、この手順にもtoolにも入れていない。

機器内生成（既定）：`provision-pop-challenge --node <id>`→機器の保守verbが鍵生成（Entropy READY後）とPoPを返す→`provision-devcert … --challenge <hex> --pop <file>`がPoPを検証してDevCertと`identity-bundle.json`を出す→保守verbがbundleとDevCertのcnf＝自分の公開鍵を確かめてRLI1を`rlident`へ封緘・readback。保守verbとPoPの共通vectorはP7の残り（下の§6.2）で実装した。

### 6.2 実装状況（P7の残り：保守verb・P7-2、host試験済み・実機未試験）

このbranchで実装したもの。量産custody（HSM）・eFuse（Q5）は含まない。

| 部品 | 場所 | 内容 |
|---|---|---|
| PoPのC++ codec | `sdkv1_pop.{hpp,cpp}` | payloadのencode／厳密decode、AAD、検証（形式不正はProtocolError、node・challenge不一致と署名不正はverified=false）、機器の署名（micro-ecc決定的署名＋low-S正規化）。`protocol/sdkv1-golden/`の`pop` codec（独立Python生成器）でRust側とbyte一致し、Rust harnessはRFC 6979で再署名して一致を確認。C++側は証明書と同じくverify-only |
| 保守console engine | `sdkv1_maintenance.{hpp,cpp}` | 1行入出力のportable engine。`status`／`keygen <node> <challenge>`／`identity <bundle hex>`。entropy portの失敗で鍵生成を拒否（security §9）。bundleは`routeloom-identity-bundle-v1`の厳密JSON読み（順序・鍵・列挙値を固定、未知のfieldは拒否）。node・公開鍵・kidをpending鍵と照合し、RLI1起動検査→twin commit→boot相当の再読込で照合してから成功を返す。`console_locked`は全verb拒否。host試験（`routeloom_sdkv1_maintenance_tests`）は共通vectorのDevCert・anchor・kidを束ねた本物のbundleで密封まで通す |
| firmware配線 | `routeloom_espnow`の`espnow_sdkv1`、両firmwareの`main.cpp`・Kconfig | 4 store（`rlident`／`rlsite`／`rlrevo`／`rlres`、gatewayは160 resume slot）を`rlsec`上に開いて初期化し、状態をboot診断に出す（秘密なし）。consoleは`CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE`のbuildだけがRF前にUSB Serial/JTAGで起動し、8 KiBの専用taskで回る。chip内部entropy源を有効化してPSA Cryptoの乱数Providerを初期化し、成功後だけ鍵生成を許す。firmware CIに`maintenance_on` cellを追加し、console分岐のbuildを確認する。静的RAM増は約5.2 KiB（console bufferはfield buildではlinkで落ちる） |
| `SiteCaSigner` | `routeloom-provision`の`sdkv1::siteca` | `DeviceCaSigner`と同じ境界のtrait。開発用`FileSiteCaSigner`は鍵文書`routeloom-site-ca-key-v1`（0600・上書き拒否・Device CA文書と相互不可）。SiteCert発行は発行後にSite CA公開鍵で自己検証する |
| CLI | `routeloomctl provision-siteca-keygen`／`site-cert` | `site-cert --ca-key <siteca.key> --site-id … --sak-pubkey … --network-low32 … --site-epoch … --serial … --out sitecert.cwt`。SAK公開鍵はsite PCから帯域外で受け取り、Site Authorityが起動時に不一致を拒否する。daemon socketを使わない |
| 在庫出力 | `sdkv1::office`の`inventory_file_json` | `provision-devcert`／`provision-identity`が`inventory.json`（`routeloom-inventory-v1`、DevCert由来の6 field＋format marker）をout-dirへ書く。stdoutの1行はbyte互換で残す |

## 7. 失敗の扱い

| 事象 | 動作 |
|---|---|
| KGuard未接続 | 参加要求はpending（`decision_timeout_ms`で）、`authority.error`は出さない。既存memberは影響なし |
| host停止 | gatewayは0x40を送れず、proxyへ`authority_unreachable`。OFFERの`authority_reachable`を落とす |
| USB再接続 | 新しいUSB sessionで0x45を再送し、gatewayのGK状態を一致させる |
| 台帳・store失敗 | 参加はAuthorityBusy、revokeはエラー。成功へ変換しない |
| 同じNodeIdで別kid（有効なmembership） | 別の機器として扱い`join.request`に`kid_conflict:true`。自動allowしない。revoke済みの行は競合にせず、明示allowで置換できる |
| 決定済み要求への別key再allow | 承認した(kid, generation)がmemberとして有効なら保存済み応答（そのkeyにも記録）、失効・置換済みならCONFLICT。同一idempotency keyの再送は記録の保持範囲（最新1,024件）内で保存済み応答 |

## 8. 受入試験（planned_not_run）

| ID | 内容 |
|---|---|
| V1-H01 | `join.request`→`join.decide(allow)`→台帳commit→`member.confirmed`の順序（**P3-3でhost試験済み**：commit後にだけ`committed`とmessage_4、`member_confirmed`の受け口で`active`。実機のJoinConfirmはP5） |
| V1-H02 | 期限後のdecisionが次の試行で反映（**P3-3でhost試験済み**：allow／deny、`applied:"next_attempt"`） |
| V1-H03 | idempotency：同key再送は同結果、別verdictはConflict（**P3-3でhost試験済み**、API1 socket経由を含む） |
| V1-H04 | `membership.revoke`の`expected_generation`不一致はConflict（**P3-3でhost試験済み**） |
| V1-H05 | revokeの段階（committed→distributing→converged）とunknownの計数（**P3-3は`committed`まで**：配布（P5/P6）が無いので`distribution:"not_implemented"`、全memberを`unknown`と数える） |
| V1-H06 | ACL：read権限では`join.decide`不可（**P3-3でhost試験済み**：`MEMBERSHIP_READ`だけのprincipalは一覧可・revoke不可、grant無しは`site.status`も不可） |
| V1-H07 | host crash（commit後・送信前）→機器の再試行で冪等再発行（**P3-3でhost試験済み**：SQLite storeを開き直し、同じMemberCert byte列を再発行） |
| V1-H08 | USB 0x40〜0x46 codecのC++/Rust共通vector、capability無しでUnsupported |
| V1-H09 | routeloom-provision：RLI1・DevCertのgolden一致、所持証明の無い公開鍵には発行しない（**P7-1でhost試験済み**：`tests/sdkv1_office.rs`が発行したDevCert・注入鍵RLI1を共通vectorとbyte一致で確認し、PoPの不一致・改ざん・再送を拒否。**P7の残りでhost試験済み**：PoPのC++/Rust共通vectorとbyte一致、保守verbの鍵生成・PoP・bundle密封・readback（共通vectorの本物bundle）、SiteCert発行のgolden一致と`inventory.json`。HILは未実施） |

# 04 — 削除・失効・世代下限

「削除」はUIから消すことではなく、Site Authorityの台帳にcommitされ、近隣・gateway・authorityがその機器との認証・route・新規配送を止めること（[identity §7](../../spec/identity-membership.md)）。失効の執行は**相手側で行い**、削除された機器へ何かを届けることに依存しない（[04 provisioning §4.7.1](../sdk-completion/04-provisioning-lifecycle.md)と同じ方針）。

## 1. 世代の定義

| 名前 | 幅 | 所有者 | 意味 |
|---|---|---|---|
| assignment generation | u32 | Site Authority（機器ごと） | KGuardが機器をこの現場へ割当し直すたびに+1。MemberCertに入る |
| min_generation | u32 | RRS1のentry | これ未満の世代のMemberCertを拒否 |
| rs_epoch | u32 | RRS1 | 失効集合の版。完全置換、厳密増加 |
| site_epoch | u32 | 現場 | 配備世代。network id上位32bit。cutoverで+1 |
| gk_epoch | u32 | GK | group鍵の世代（[03](03-key-hierarchy.md) §6） |

「旧割当（世代）の機器の通信を拒否」は、`MemberCert.assignment_generation < min_generation`、または`MemberCert.site_epoch < site_epoch_floor`のMemberCertを、link/E2E確立時と、RRS1を受理した時点の生存contextの両方で拒否することで実現する。

**v1のNodeId規則**：GroupLink／GroupEndには割当世代がないため、一度この現場で失効したNodeIdは同じ現場で再発行しない（cutoverでRRS1のentryが消えても履歴台帳を確認する）。機器のNodeIdは事務所のRLI1／DevCertに固定され、Hostは参加時に別の値を割り当てられない。再参加させるには事務所で新NodeIdの機器IDを再発行し、KGuardが新IDをallowする。旧IDでのallowは理由付きCONFLICTとする。誤ったHostが旧IDで新世代を発行しても、RRS1を適用済みの機器はそのIDのgroup frameを拒否する。割当世代とGK epochの結合はv1.1（#146）。

## 2. RRS1 — 失効集合

Site AuthorityのSAKが署名するCOSE_Sign1（ES256）。external AAD＝`"RouteLoom/revocation-set/v1" 0x00 || network u64`（機器自身のRLS1から与え、転送経路の申告を使わない）。payloadは固定長BE：

```text
 0 u8  ver = 1 | 1 u8 flags | 2 u16 count (≤32)
 4 u64 site_id | 12 u64 network
20 u32 rs_epoch | 24 u32 site_epoch_floor
28 entries[count] × 16B: node_id u64 | min_generation u32 | reason u8 (1 removed, 2 lost, 3 replaced, 4 blocked) | reserved 3B
```

最大payload 28＋32×16＝540B、COSE枠込みで616B（COSE_Sign1はRLCW1と同じtag 18・`{1:-7}`・low-S）。認証済みobject上限2048B以内。機器は`rlsec`/`rlrevo`の二重slot（各≤640B）に保存する。保存記録は`magic "RRS1" | format | used_len | schema | seal(0x2E5E7C0D) | commit_seq u32 | 受信した署名object | CRC`で、32件時にちょうど640B（object無しの24Bがtombstone）。gossipで再送できるよう署名objectをそのまま保存する（P1-3で実装、[vector README](../../../protocol/sdkv1-golden/README.md)）。受理規則：署名がRLS1のSAKで通る、`site_id`/`network`一致、`rs_epoch`が保存済みより大きい、entry重複なし・node_id昇順、`site_epoch_floor`は後退しない。実装では加えて`flags=0`、`rs_epoch≥1`、`min_generation≥1`、`reason`は1〜4、`site_epoch_floor≤network>>32`を要求する。完全置換なので、途中の版を取り逃しても最新版だけで収束する。

容量32件を超える場合は**site_epoch cutover**（§7）で空にする。古いentryを黙って追い出さない。

## 3. 削除の流れ

```text
KGuard: membership.revoke(device, expected_generation)
  → Site Authority: 台帳に MembershipRevocation をcommit（成功後に次へ）
  → RRS1(rs_epoch+1) を署名・保存
  → (a) RevocationNotify を全memberへ（authority channel、10件/秒）＋近隣間gossip（§4）
  → (b) GK更新を開始（削除者を除外、03 §6.4）
  → (c) 削除者へ RemovalNotice（到達できれば、best effort）
  → API: 状態 committed → distributing → converged(件数) を返す
```

API上の段階は「受付」「台帳commit」「配布中（到達member数/全member数）」「収束」を分け、到達できないmemberは`unknown`のまま数える（適用済みとみなさない）。Host側（G-SEC P5 PR3で実装）：revokeは台帳・RRS1・削除と**新しいepochのstage**を1 transactionでcommitし、削除者を除く全memberへ配布する。削除のたびに新しいepochを作り直し（stage済み鍵の再利用はしない）、連続削除は最初の削除batchの期限を維持する。RRS1自体の配布（a）はP6のまま。

## 4. 伝播（gossip）

RRS1は自己認証objectなので、authority以外のmemberが運んでもよい。

1. link確立（EDHOC EAD／RLRES1のR2）で双方の`rs_epoch`を交換する。
2. 自分の方が小さいmemberは、相手から1hopのControlObject（kind 6 = RevocationSet、P6-1で凍結）でRRS1 objectのbyte列そのものを取得する。manifestのhashは再構成の同一性だけで、権威はobject内のSAK署名である。
3. 受理したmemberは、自分のrs_epochが小さい近隣に次のidle refreshで知らせる（Control subtype `StateEpochs`：`ver|sub 0x61|site_epoch u32|applied_rs u32|gk_epoch u32`＝14B、1hop。P6-1で凍結）。取得要求は`RrsRequest`（`ver|sub 0x62|site_epoch u32|have_rs u32`＝10B）。
4. 取得要求は近隣あたり1分に1回、同時1件（交換全体も1+1：同bufferの二重追跡なし）。

これによりauthorityから全memberへのfan-outが無くても、連結成分内ではhop数×(idle refresh間隔＋転送時間)で広がる。分断成分には届かない（§6）。

## 5. 受理したmemberの動作

| 対象 | 動作 |
|---|---|
| 失効したpeerとのlink/E2E context | 即破棄（overlap無し）、`SessionInstaller::retire_all` |
| 再開cache slot | 該当peerのslotを消去（[05](05-nvs-state-37.md)） |
| 経路 | そのpeerを次hopとする経路を撤回、route originとしての広告を受理しない |
| discovery | NeighborPhaseを`Revoked`にし、そのMAC/NodeIdからのhandshakeを拒否（[discovery](../../../components/routeloom/include/routeloom/discovery.hpp)の既存`revoke_peer`） |
| 送信待ちの配送 | 失効peer経由の未開始TXを再評価（[06 admission §2.1](../autonomous-mesh/06-membership-admission.md)） |
| 拒否時の応答 | handshake要求にはRelayStatus相当の未認証hint `REVOKED`を返す（1分1回まで）。これはhintで、相手に何かを信じさせる証拠ではない |

## 6. 削除された機器が経験すること

### 6.1 RemovalNotice

```text
COSE_Sign1(ES256, SAK), external AAD = "RouteLoom/removal-notice/v1" 0x00 || network u64
payload: ver u8 | reason u8 | reserved u16 | site_id u64 | node_id u64 | generation u32 | rs_epoch u32   (= 28B)
```

約110B。機器はRLS1のSiteCert（SAK）で署名を検証し、`node_id`＝自分、`generation`≥自分のMemberCertの世代であることを確かめてから、現場状態を消す。**偽の`REVOKED` hintや未署名の拒否では決して消さない。**

### 6.2 経路別の体験

| 状況 | 機器が見ること | 結果 |
|---|---|---|
| 到達可能 | authority channelでRemovalNoticeを受信 | 検証→REMOVED |
| 到達不能（紛失・電源断） | 何も受けない。近隣はRRS1で拒否済み | 復帰後、linkがすべて拒否される→§6.3 |
| 分断中の群にいる | 同じ群のmemberはRRS1を知らず、通信が続く | 群が再結合しRRS1が届いた時点で拒否（上限なし、§7） |

### 6.3 復帰後の確認手順

linkが連続3回`REVOKED` hintまたは失敗で終わり、使える近隣が無くなった機器は、**ゼロタッチ参加の経路**（[02](02-zero-touch-join.md)）で自分の現場のSite Authorityへ問い合わせる（ZeroTouch classのproxyは失効者も中継する。proxyは相手の身元を知らない）。authorityは台帳を見て`verdict=Removed`＋RemovalNoticeを返す。

### 6.4 REMOVEDの後

1. RLS1、現場のRLT1、RRS1、再開cache、GK、DAMSを消去（seal付きの空記録へ、または二重slotのtombstone）。RLI1は残す。
2. MembershipStateは`Revoked`を経て、RLS1が無い状態＝`Unprovisioned`として起動し直す。
3. 10分のholdoffの後、ZeroTouch参加を再開する。KGuardには`previously_removed=true`の発見済み機器として見えるが、旧NodeIdの再allowはHostが拒否する。再参加には事務所で新NodeIdのRLI1／DevCertを発行する。

「削除後は物理的なリセットまで沈黙すべき」とする運用もあり得る。自動で未割当に戻るか、沈黙するかは製品判断（[08](08-implementation-plan.md) §6 Q9）。既定案は「未割当に戻る」だが、旧NodeIdの発見・参加要求は再allowできない。再利用には新NodeIdのRLI1／DevCertを事務所で再発行する。

## 7. site_epoch cutover（RRS1満杯・大規模な入替え）

1. Site Authorityは`site_epoch+1`のMemberCertを有効な全memberへ`GrantRenew`で配る（authority channel、到達確認付き）。
2. 期限（既定10分）後、Hostのdurable COMMITが確定してから、新network向けRRS1（`site_epoch_floor=site_epoch+1`）と旧network束縛の署名CutoverCommitを送る。準備中に発行済み資格を持つ削除者がいれば新RRS1にもその世代下限を残し、entry 0件を前提にしない。改訂PREPAREでは前の改訂より新しいGK epochを使い、既配布の鍵と同じepochを再利用しない。
3. 機器はCA署名の次SiteCert、同SAK署名の次MemberCertと新RRS1、CutoverCommitを検証する。PREPAREはRLX1にstageするだけで旧所属を維持する。COMMIT後のRLX1 Switching intentから旧context／再開cacheを除去し、新RLS1・RRS1を採用してRLX1の両slotを秘密なしにする。Idleにはcutover ID・revisionと非秘密のCOMMIT digest 32 Bを残し、AdoptNetwork完了後のAPPLIEDを電断後にも再送できるようにする。Idleのold_network欄は採用済みの新networkであり、receiptの旧networkはそのsite_epochを1減らして復元する。OwnerのAdoptNetwork完了までは通常通信を開かない（旧networkのRMSも流用しない）。
4. GrantRenewを取り逃したmemberはlinkを拒否され、ゼロタッチ参加の経路へ戻る。authorityは台帳上まだ割当済みなら**KGuardへの人手確認なしで**再発行する（KGuardへは自動の割当確認だけ）。

費用：全memberの再handshake（RLRES1ではなくEDHOC。RMSがnetworkに束縛されるため）。30件以上の削除を貯めたとき程度の頻度を想定する。

Host実装（P6-2 PR D、`host/routeloom-host/src/site/cutover.rs`）：`membership.cutover`（ADMIN）はepoch段差・Site CA配下の次SiteCert・snapshot・全allocatorを検証してから次epoch全体（次SiteCert・同世代の次MemberCert・fresh次DAMS・共有P5 allocatorの次GK）を1 transactionでstageし、tickがPREPAREを配る。stageから600秒後に最新改訂のgateway PREPAREDが1台以上あれば次RRS1＋CutoverCommitの署名とactive切替を1 transactionでcommitし、COMMITを60秒の旧network猶予内で配る（猶予はRAMのみ。再起動で終了し、取り逃しはZT再発行へ）。準備中のrevokeは現networkへ先にcommitしてから改訂上げ・次GK再stage・全PREPARED無効・600秒再開・発行済みbindingの次RRS1持越しを同一transactionで行い、準備中のallowはsnapshotへ同世代の次資格で参加する（満杯は切捨てず拒否）。再起動はwindowを数え直し、epoch・serial・GKを消費しない。配布transportはfake portのまま（`RevocationTransport`に`carries_notice`／`carries_grant`の宣言を追加。未対応の種別はqueueせず、RRS-only portを詰まらせない）。機器・Owner・firmware側の実結線（P4/P5 adapter、gateway-local、ESP NVS RLX1）は残課題。

## 8. 予約：SAK交換（後続設計）

SAK侵害または計画交換では、Site CA（オフライン）が署名する`SiteAuthorityChange{site_id, new SiteCert, min_site_epoch}`を機器が検証し、RLS1のSiteCertを差し替える。形式と配布は後続設計。v1で現場全機器を削除して回復する場合、失効したNodeIdは再allowできず、各機器に新NodeIdのRLI1／DevCertを再発行する必要がある。

## 9. 時刻と保証の範囲

- 機器は信頼できる時刻を持たないため、MemberCertに有効期限を入れない（既定）。したがって**失効の伝達はRRS1の到達に依存し、分断中の群には上限を約束しない**。
- gatewayのTimeSyncをSAKで署名して配る構成を将来追加すれば、MemberCertに`exp`を入れて「最悪でも期限で失効」を追加できる（[04 provisioning §4.7.1](../sdk-completion/04-provisioning-lifecycle.md)のR1）。cold boot直後に時刻を証明できない機器は、期限を検証したつもりにならず、authorityとの現在確認を要求する。
- GKは24時間ごとに更新されるため、削除された機器がgroup frameを読める期間は、到達可能な群では最大でも更新まで。分断中の群ではその群がg+1を受けるまで。

## 10. 失敗の扱い

| 事象 | 動作 |
|---|---|
| 台帳commit失敗 | revokeは失敗として返す。RRS1を発行しない |
| RRS1の署名不一致・epoch後退 | 破棄して数える。保存済みを維持 |
| RRS1保存中の電源断 | 旧slotが有効のまま。次のgossipで再取得 |
| RRS1満杯 | cutoverを要求（APIで`cutover_required`）。黙って追い出さない |
| 失効済みpeerからの遅いhandshake完了 | 最新のRRS1で再検査して昇格拒否 |
| RemovalNoticeの検証失敗 | 何も消さない |

## 11. 受入試験

| ID | 内容 | 状態 |
|---|---|---|
| V1-R01 | revoke：台帳commit後にだけRRS1発行、API段階の順序 | P6-1 PR Aでhost試験（`site::tests::revocation_*`、`operations_get_round_trips_*`）。P4/P5実配線は未接続のためfake port |
| V1-R02 | 近隣がRRS1受理→即context破棄・再開slot消去・経路撤回 | P6-1 PR Aで機器sim試験（`test_sdkv1_revocation.cpp`）。実P4 adapterは未接続のためfake port |
| V1-R03 | gossip：authorityから遠いmemberへhop数に比例して伝播 | P6-1 PR Aで3-node line・100-node line・partition/merge sim試験（同上）。損失・重複・reorder・silent peer・32枠圧力の系統的fault注入は残課題 |
| V1-R04 | 旧世代MemberCertでのlink/E2E確立拒否。v1では失効NodeIdの再割当は行わない | P6-1 PR Aでfloor/last-good・限定再認証の単体試験（同上＋`test_discovery.cpp`）。実EDHOC E2EはP4接続後 |
| V1-R05 | 削除者はRemovalNoticeを検証して現場状態を消去、RLI1は保持 | PR B portable fake-port試験：RLX1 intent→逐次消去→holdoff→未割当action、RLI1不変、journalのbyte境界電断。実P4/P5/ESP trust adapterと統合電断試験は未接続 |
| V1-R06 | 偽`REVOKED` hint・未署名通知・他現場SAK署名では何も消さない | PR B portableでは改竄署名の非消去のみ確認。hint/異現場の結線試験は未実施 |
| V1-R07 | 紛失機器の復帰：ゼロタッチ経路でRemoved判定→消去→発見済み表示 | PR B の portable Joiner は健康なRLS1を保持して問い合わせ、実署名NoticeをOwnerへ渡すsim試験あり。Hostは旧networkのEADを同一kidの削除済みrowに加え、旧kidの照会はrevoke台帳（node索引）で照合する。revokeは署名済みNoticeを同transactionでcommitし、tickがcommit後に配送・NoticeAcceptedで`intent_confirmed`を立てる（`erase_confirmed`はprotocolに存在せず常にnull）。Owner引渡し・pipe E2Eは未接続 |
| V1-R08 | RRS1満杯→cutover：GrantRenew取り逃しmemberの自動再参加（KGuardの人手確認なし） | P6-2 PR DでHost driverを実装しhost試験（`site::cutover_tests::*`：commit前送信0・600秒とgateway gate・準備中revokeの競合・再起動・RRS満杯回復・通知outbox、API socket経由の`site::e2e::cutover_flows_*`、取り逃しmemberのKGuard不要な再発行）。機器・Owner・firmware実結線とC++ Joiner pipe E2Eは残課題 |
| V1-R09 | 分断群：再結合までは通信継続（保証外の記録）、再結合後に拒否 | P6-1 PR Aでpartition/merge sim試験（`test_sdkv1_revocation.cpp`）。HILはP8へ引継ぎ |
| V1-R10 | RRS1・RemovalNoticeのC++/Rust共通vector、fuzz | RRS部分はPR Aで実施。PR BでRLX1 recordとLastMembership/profile/capabilityのvalid/invalid共通vectorを追加し、C++/Rust両harnessとCI再生成検査を実施。Renewと実結線E2Eは後続PR |

P6 の本番プロフィールは未有効。Host の通知 outbox・旧 kid 履歴照会・cutover driver・競合処理・有効な既存memberの自動再発行は PR D で接続した（上記 V1-R07／V1-R08）。残るは Owner／ESP の消去・lifecycle 実接続と E2E である。portable Joiner は起動時に渡された RLX1 の削除世代 watermark 以下の同一site Allowを拒否する。Owner が検証済み watermark を渡して journal を整合させる結線も PR D に属する（未接続）。portable の `NoticeAccepted` は intent 保存後の best effort 引渡しであり、Host の受領永続化を表さない。Host は受領した `NoticeAccepted` を revoke operation の `notice.intent_confirmed` として永続化する（消去の証拠ではない）。

# 06 — 停電・再起動・中継器故障からの高速再参加

## 1. 目標と前提

要求R6：人手なしで速く戻る。承認のやり直し（KGuardへの再問合せ）と、暗号sessionの再確立を分ける（[identity §6](../../spec/identity-membership.md)「現場への承認し直しとは分離する」）。

| 再起動をまたいで残るもの | 残らないもの |
|---|---|
| RLI1（機器identity）、RLS1（MemberCert・GK・DAMS・channel・gateway）、RRS1、再開cache（RMS）、`rlboot` | link／E2E／authority channelのセッション鍵、counter、受信窓、経路表、近隣表 |

**再参加でKGuardもSite Authorityも呼ばない**。MemberCertの有効性は、SAK署名・network・RRS1（世代下限）を近隣が手元で検証する。authorityを呼ぶのはGKが古い、または自分が削除された可能性がある時だけ。

## 2. 再開handshake RLRES1

EDHOCで作ったRMS（[03](03-key-hierarchy.md) §2.1 label 32770）、DAMS、pending秘密を使う対称鍵handshake。**RouteLoom独自プロトコルであり、独立レビュー前は未検証**。TLS 1.3のPSK-only再開と同じく、RMSの寿命内では前方秘匿性が無い（RMSが漏れればその寿命内の再開sessionを復号できる）。寿命を`created_gk_epoch + 2`（GK 24時間更新で約2日）に制限し、その後はfull EDHOCでRMSを入れ替える。

### 2.1 メッセージ（BootstrapAuth phase 5。link用はRLD1、end/authority用はWire bootstrapで運ぶ）

```text
R1  I→R  (60B、pending用はticket付きで最大109B)
  0 u8  purpose (1 link, 2 end, 4 authority, 5 pending-join) | 1 u8 flags | 2 u16 reserved=0
  4 8B  resumption_id = first8(HMAC(RMS, "RouteLoom/v1/rid" 0x00 || purpose))
 12 16B nonce_I
 28 u32 cid_I                 — I側の受信context id（03 §4.2）
 32 u32 site_epoch | 36 u32 rs_epoch | 40 u32 gk_epoch
 [purpose=5のみ: u8 ticket_len | ticket ≤48B]
 .. 16B mac_I = first16(HMAC(K_auth, "R1" 0x00 || binding || 上記全field))

R2  R→I  (52B)
  0 u8  status (0 ok, 1 unknown_id, 2 expired, 3 revoked_hint) | 1 u8 flags | 2 u16 reserved
  4 16B nonce_R | 20 u32 cid_R
 24 u32 site_epoch | 28 u32 rs_epoch | 32 u32 gk_epoch
 36 16B mac_R = first16(HMAC(K_auth, "R2" 0x00 || binding || R1 || R2[0..36)))
      status≠0 の時はmac無し（12B）＝未認証hint。Iはfull EDHOCへ移る

R3  I→R  (16B)
  0 16B mac_I3 = first16(HMAC(K_conf, "R3" 0x00 || TH))
```

導出（HKDF-SHA-256、[kdf.hpp](../../../components/routeloom/include/routeloom/kdf.hpp)）：

```text
K_auth = HKDF(salt="RouteLoom/v1/resume-auth", IKM=RMS, info=purpose||network u64||node_I||node_R, 32)
TH     = SHA-256(R1 || R2)
PRK    = HKDF-Extract(salt = nonce_I || nonce_R, IKM = RMS)
K_conf = HKDF-Expand(PRK, "resume-confirm" 0x00 || TH, 32)
key/iv(dir) = HKDF-Expand(PRK, "resume-key" 0x00 || purpose || dir || network || node_I || node_R || cid_I || cid_R || TH, 28)
```

`binding`は、link用ではRLD1の観測MAC（送信元・宛先）とheader digest（scope bindingと同じ考え方、[02-discovery-scope §2.4](../scope-gateway-config/02-discovery-scope.md)）、end/authority用ではorigin・destinationのNodeId。

### 2.2 状態機械

| 側 | 状態 | 入力 | 動作 |
|---|---|---|---|
| I | IDLE | 再開slotが有効なpeerを発見 | R1送信（nonce_I新規）→WAIT_R2（期限1秒＋hop×0.3秒） |
| I | WAIT_R2 | R2 status=0、mac_R正 | 鍵導出・context install（送信可）→R3送信→DONE |
| I | WAIT_R2 | status≠0、mac不正、期限切れ | そのslotを無効化せず（hintは偽造可能）、full EDHOCへ。EDHOCが成功したらslotを上書き |
| R | IDLE | R1 | rid→slot検索、有効性（05 §3.2の無効化規則、RRS1）確認、mac_I検証→R2送信→WAIT_R3（期限1秒）。**この時点でcontextを有効にしない** |
| R | WAIT_R3 | mac_I3正 | context install→DONE |
| R | WAIT_R3 | 不正・期限切れ | 破棄（捕獲R1の再送はここで止まる） |

Iは自分のcontextをR2検証後に有効化してよい：R2のmac_Rは自分の新しいnonce_Iを含むので再送できない。Rは相手の鍵確認（R3）を見るまで有効化しない。

### 2.3 用途別の使い方

| purpose | RMS | 運ぶ経路 | 使う場面 |
|---|---|---|---|
| link | 再開slot（link） | RLD1、1hop | 再起動後の近隣、親の再起動 |
| end | 再開slot（end） | Wire bootstrap（routed） | gatewayとのE2E（再起動後、gateway再起動後） |
| authority | DAMS（RLS1／host） | 機器→gateway→USB→host | GK pull、JoinConfirm、GrantRenew受領 |
| pending-join | pending秘密（RAM）＋ticket | ゼロタッチproxy経由 | pending中の安価な再問合せ（[02](02-zero-touch-join.md) §6.1） |

## 3. 起動の流れと費用

| 段階 | 内容 | frame（機器側） | 暗号 | 備考 |
|---|---|---|---|---|
| 1 | RLI1/RLS1/RRS1/再開slot読込み、`rlboot`+1 | — | CRC、MemberCert再検証は不要（commit時検証済み） | NVS書込み1 |
| 2 | RLS1のchannelでMember scope DISCOVER（scope鍵＝K_dsk(g)） | 1＋OFFER k | HMAC（scope tag） | OFFER窓320ms。起動直後に0〜2秒の乱数待ち |
| 3 | 再開slotのある近隣とRLRES1（最大3近隣、1件/秒のhandshake枠） | 3/近隣 | HMAC約8回/近隣 | slotが無ければEDHOC（§4） |
| 4 | NeighborProbe/Result（Wire 40/41）→REACHABLE | 2/近隣 | AEAD | 既存 |
| 5 | 経路の学習 | 経路仕様のtimer次第 | — | triggered updateで短縮 |
| 6 | gatewayとE2E RLRES1（業務送信が必要になった時） | 3 message×hop | HMAC | gatewayの受付rate（§5） |
| 7 | GKが古い時だけauthority RLRES1＋GroupKeyPull | 2〜4 message×hop | HMAC | host停止中はgroup frameだけ保留 |

1hopでの再開（段階2〜4）の機器側airtime byte数は約0.7KB（DISCOVER 68B、OFFER 104B、R1 108B、R2 100B、R3 64B、Probe/Result）。PHY 250kbpsのbyte時間では数十msだが、実時間は窓・乱数待ち・MAC再送で決まり**未測定**。

## 4. 中継器故障

| 状況 | 動作 | 暗号費用 |
|---|---|---|
| 予備の近隣がREACHABLE（既にcontext有り） | 経路が切替わるだけ | 0 |
| 予備はStale（lease切れ） | 既存のstale re-probe（02-discovery §9）。contextはRAMにあれば再利用、無ければRLRES1 | HMAC |
| 知っている近隣が無い | DISCOVER→新しい近隣。以前にEDHOC済みで再開slotがあればRLRES1、初対面はEDHOC | EDHOC 1回（C3時間未測定） |

中継器故障への速さは「予備近隣とのcontextを事前に持っているか」で決まる。link contextはRAMだけでNVSを消費しないため、上限（logical neighbors 32）内で2〜3の予備近隣と常時REACHABLEを保つことを推奨する（既存discoveryのidle refreshで維持）。

## 5. 一斉復電（現場全体の停電）

N台・最大深さDの現場で全台が同時に起動した場合の計画式（実測で置き換える）：

```text
T_link  ≈ D × (T_offer + T_resume_link + T_probe)             各hopの近隣確立が根元から伝わる
T_e2e   ≈ N / R_gw                                            gatewayのE2E再開受付rate
T_total ≈ max(T_link + T_route, T_e2e) + 乱数起動待ち
```

採用案の値：`T_offer=0.32s`、`R_gw=10件/秒`（gatewayの再開用に、1件/2秒の高コスト認証枠とは別の対称鍵用枠を設ける。同時4件）、起動乱数待ち0〜2秒。qualification規模（N=100、D=10）では `T_link≈10×0.5s=5s`、`T_e2e≈10s`、経路の収束を含めて**15〜30秒程度を目標**とする。これは目標値であり実測ではない。

再開slotが無効な場合（site_epoch cutover直後、slot追い出し後、2日以上の停止）はfull EDHOCになり、`T_e2e ≈ N × T_edhoc_gw / 並列度`。C3/S3の`T_edhoc`は未測定なので、HILで測るまで一斉復電の上限を約束しない（[08](08-implementation-plan.md) V1-F06）。

## 6. sleep端末

- 親とのlink contextとgatewayとのE2E contextをRTC slow memoryに保持し（[03](03-key-hierarchy.md) §5.4）、起床後すぐにデータ本体を送る（[identity §6](../../spec/identity-membership.md)）。
- RTC消失（電源断・brownout）時は親とのRLRES1（親の再開slotはpin）。
- 親が再起動して鍵を失った場合、子のframeは`AuthRequired`になる。子は同じ起床内でRLRES1を1回だけ試み、失敗なら次の起床へ回す（awake予算を超えない）。
- 再開slotの`last_used_boot`は256起動ごとにしか書かないので、1分周期の起床でもNVSを摩耗させない。

## 7. 1回の再起動あたりの費用上限

| 資源 | 上限 |
|---|---|
| KGuard問合せ | 0 |
| Site Authority問合せ | 0（GKが古い、または拒否が続いた時だけ1回） |
| NVS書込み | `rlboot` 1回＋（稀に）再開slotの`last_used_boot` |
| ECC演算 | 再開slotの無い近隣・宛先の数×EDHOC 1回。slotが有効なら0 |
| handshake開始 | 既存の1件/秒（近隣）、gateway側は対称鍵枠10件/秒 |
| RAM | link context ≤32、E2E ≤8（gateway ≤128） |

## 8. 失敗と後退

| 事象 | 動作 |
|---|---|
| R2がstatus≠0（未認証） | full EDHOCへ。slotはEDHOC成功時に上書き |
| full EDHOCで相手のMemberCertが失効 | link不可。近隣表でRevoked |
| すべての近隣に拒否された | [04](04-removal-revocation.md) §6.3の確認手順 |
| gateway・host停止 | 近隣間の通信は継続。E2E（gateway宛て）とGK pullは保留 |
| RLS1破損（両slot） | 未割当として起動（ゼロタッチ参加）。authorityは台帳から冪等に再発行 |

## 9. 受入試験（planned_not_run）

| ID | 内容 |
|---|---|
| V1-F01 | 再起動後、KGuard・authorityへの問合せ0件でREACHABLEまで戻る |
| V1-F02 | RLRES1：R1再送・R2再送・R3欠落の各攻撃でcontextが作られない |
| V1-F03 | RLRES1の鍵・mac共通vector（C++/Rust） |
| V1-F04 | 中継器停止：予備近隣がREACHABLEなら暗号handshake 0件で経路切替 |
| V1-F05 | RMS期限（gk_epoch+2）後はfull EDHOCになる |
| V1-F06 | HIL：6台以上の一斉復電で復帰時間とT_edhocを実測 |
| V1-F07 | sleep端末：RTC保持で起床後即送信、親再起動時は1回だけRLRES1 |
| V1-F08 | 1分周期の起床を1日続けても再開slotの書込みが上限内 |

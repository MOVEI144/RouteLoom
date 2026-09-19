# Issue #3 — 近隣発見・IdentityとMACのbinding

状態：設計案。要求：[Issue #3](https://github.com/MOVEI144/RouteLoom/issues/3)。単に未登録MACを自動add_peerする変更ではなく、安全な近隣のライフサイクルを作る。

## 1. 決定と非目標

**D3-01:** 発見、機器認証、ネットワーク参加承認、近隣の利用可能性を別状態にする。

**D3-02:** v1は呼出側が毎回MACを調べる必要をなくす。事前のIdentity・Network/信頼先・RF profile設定は必要。裸の未設定端末に近所のNetworkを勝手に選ばせない。

**D3-03:** 既に所属済みなら、新Relayとのbindingや起床復帰に中央Authorityの往復を必須にしない。有効な所属証拠/鍵がない新規加入だけはAdmission Providerを通す。

**D3-04:** NodeIdは安定したprovisioned Identityに結び付ける。認証前の電波ネゴシエーションでNodeIdを奪い合わない。legacyの静的IDは残し、動的生成はprovisioning時の安全な乱数/公開鍵由来と永続保存で行う。

## 2. 近隣の状態と遷移（所属状態とは別）

以下は相手radioごとの **NeighborPhase**。既存 `MembershipState` の6状態を採用したまま併用し、その値・保存形式を置換しない。所属を進めるのはMembership controllerだけで、Discovery/Authenticatorは証拠とeventを渡す。対応表、許可gate、保存時点の正本は [06-membership-admission.md](06-membership-admission.md)。同じAUTHENTICATINGという表示でも異なるenum型として扱う。

| 状態 | 行ってよい処理 | 通常DATA/route利用 |
|---|---|---|
| CANDIDATE | cheap parse、cookie、少量のOFFER | 不可 |
| AUTHENTICATING | 1つの有界な相互確認 | 不可 |
| AUTHENTICATED | Identityと相手radioを確認。所属を検証 | 未承認なら不可 |
| APPROVAL_PENDING | Admission Providerへ有界proxy | 不可 |
| BOUND | membership＋bindingが有効。往復probe待ち | probeだけ |
| REACHABLE | 認証済み双方向応答と受信可用性あり | policy内で可 |
| SUSPENDED | Sleep/予定不在/失効確認待ち | 今は不可 |
| STALE | lease切れ・応答なし | 再確認だけ |
| CONFLICT/REVOKED | 衝突または失効 | 不可 |

CONFLICT/REVOKEDの行は二つの拒否理由をまとめた表示であり、別の所属状態enumではない。近隣phaseの失効は、その相手のbindingを使えなくするだけで自NodeのMembershipStateをRevokedにしない。

driver Peer登録はこの表の認証状態ではない。AUTHENTICATING中にも返信のため一時Peerが要るが、それで通常通信を許可しない。起床した同じ所属端末はResumeであり、初回Joinではない。

## 3. wireへ出る順序

```text
未登録A                 受信可能なB
   DISCOVER(txn)  ───broadcast──→
                  ←── OFFER / COOKIE ──
   PROVE(cookie, transcript) ──→
                  ←── CONFIRM(transcript) ──
   FINISH/key-confirm ────────→
           認可・双方の鍵/状態確立
   NeighborProbe ────────────→
                  ←── NeighborResult ──
           REACHABLE → Coreへnear-neighbor追加
```

この図のPROVE/CONFIRM/FINISHは新しいtop-level typeではなく、既存 `BootstrapAuth=3` のprofile固有phase。RLD1の `kind` も既存FrameType番号を使う。認証が終わっても新規所属は未確定で、制限付きbootstrap contextによる `MembershipQuery=7 / MembershipResult=4` と永続commit確認が別に必要。既所属同士の再bindingでは所属を変更せず、この中央承認を省略できる。

応答している相手と、相手が自分を受信できることの両方を確認する。片方向のDISCOVER受信やMAC送信成功だけでREACHABLEにしない。両端が同時に開始した場合は、認証で確認したNodeId順とnonceで一つのexchangeへ統合し、片側を無限に待たせない。

## 4. public discovery envelope

通常Wireのmagic `RL` と区別する `RLD1`、version、message kind、明示長、Network hint、claimed NodeId、128bit transaction nonce、capabilityを持つ。**header最大44B、全長最大160B、body予算116B**をv1目標とする。

44B案：magic4 / version1 / kind1 / header_len2 / total_len2 / flags2 / network4 / claimed_node8 / transaction_nonce16 / capability_bits4。全整数big-endian、reservedは0、未知必須bitと長さ矛盾を拒否する。これは案を実装vectorで固定するための配置で、既存Wire v1を変更しない。

DISCOVER/OFFERの内容は原則hint。4byteのnetwork欄は探索フィルターだけで、正式な64bit NetworkIdは認証transcriptへ全幅で含める。hint衝突を同じ所属とみなさない。通常DATA、任意宛先への転送、所属確定、管理設定をこのenvelopeへ入れない。

credential交換のfragmentは既存 `BootstrapChunk=5 / BootstrapReply=6` を使い、最大1024Bのbootstrap組立へ渡す。RLD1ではinner typeをBootstrapAuthだけに制限し、通常DATAや再帰fragmentを包んで入場制限を回避できないようにする。認証済みWire上の所属result fragmentは別のtransaction/role検査を必要とする。callbackで組み立てず、完成後にinner typeを再度admission判定する。

証明対象transcriptにはprotocol/profile、両NodeId、両MAC、Network、両nonce、双方boot/session、capability、channel/epochの申告、役割を含める。RX metadataの実source MACとtranscriptを照合する。鍵/credentialはSecurity Providerへ渡し、独自の暗号primitiveを作らない。

## 5. Security/Admission Provider

追加の `NeighborAuthenticator` は `begin / consume / poll / cancel` でopaqueな `AuthenticatedPeerProof`（本人確認の証拠）を返す。これは所属許可ではない。Membershipの有効性とtransaction/binding世代をOwnerで再検査した後にだけ `VerifiedBinding` を作る。構築子を非公開にし、plainなboolだけで通常アプリがverifiedを作れないAPIを目指す。

Memberは新しい相手への発見応答者になれるが、候補からのDATAまでMember扱いしない。既存 `frame_allowed(state,type)` は文脈を持たず、現コードはMemberのDiscover/Offerを拒否するため、単独の最終gateとしてそのまま流用しない。既存の意味allowlistと整合させた上で、direction/carrier/transaction/role/証拠/予算を加えた共通gateへ接続する（[詳細](06-membership-admission.md)）。

- **Production:** credential保有と役割/Network membershipを検証する。未選定のEDHOC等を「もう提供した」と宣言しない。G-SECのProviderがない構成ではproduction動的bindingは `AUTH_PROFILE_UNAVAILABLE`。
- **Development:** 明示opt-inした共有PSK profileで同じネットワーク鍵保有を相互確認できる。`EXPERIMENTAL / GROUP_SECRET_POSSESSION`と表示。共有鍵保有者による別NodeId詐称・鍵cloneを区別できるとはしない。
- **Admission:** 認証済みでも未承認なら通常DATAを止める。既存の認可された近隣をproxyとしてAuthorityへ限定bootstrapを運ぶ。Authority不在ならPENDINGの期限付き保持または終了で、勝手に承認しない。

cookieはMAC/nonce/Network/時間bucketへ結び、返せる相手にだけ重い処理を許す。HMAC等は標準Providerを使用し秘密を定期更新する。cookieは本人認証の代用ではない。public OFFERだけで鍵や正式channelを更新しない。

## 6. 応答stormを防ぐ

起床直後に全員同時broadcastしない。要求側に全体token bucket、位相ばらし、失敗時指数backoffを置く。新しい物理イベントの初回DATAには長いheartbeat用jitterを適用しない。

初期OFFERは32slots×10msの応答窓、1channel最大400msを目標とする。slotは衝突しない予約ではない。OFFER最大長とLR250所要時間が10ms内に収まる保証はせず、slotは開始時刻分散としてのみ使う。

全ノード同時加入に固定slotだけで対処しない。responderは直近の観測密度に応じて返信確率を抑え、requesterはattempt nonceを更新して独立再試行する。密度申告は未認証hintとして上限付きで扱い、返信確率を恒久0にしない。single requesterでも応答者100台のケースを別試験にする。

global handshakeは1、開始rate1/s・burst1、preauth総bytesとCPU予算は既存ResourceProfileを上限とする。MACを偽装し続けてもglobal上限は増えない。正規DATA/ACKの予約枠を占有しない。

## 7. Peer管理

論理binding最大32と、driver最大20は別。broadcast1を常設し、登録後とdriver再構築後にLR250を設定する。通常16・一時3を基本配分とする。

`PeerLease` はbinding generation、用途、参照数、期限を持つ。TX in-flight、必要な返信、認証exchange、移行critical edgeを保持中のPeerはevict不可。通常topology pinは最大12、一時的保護を含むunicastは19以下。空きがなければ新候補をparkして、DATA broadcastへ逃げない。

evictionは未使用・非保護Peerから、freshness、active路への依存、複数出口への接続を考慮して選ぶ。単なるRSSI最弱順ではない。論理bindingの削除とdriverキャッシュの退避を分け、退避後の返信用枠を受理前に確保する。

受理前予約はframe→dedup→transaction→reply lease→ACK slotを一括で行う。失敗時は部分副作用を戻し、HOP_ACCEPTを送らない。全leaseがbusyなら `PEER_CAPACITY` を記録する。

## 8. MACの変更・機器交換

同NodeIdの新MACは即上書きしない。新アドレスで再認証し、旧bindingと共存する短い候補期間を設ける。旧bindingがなお生存し、同一Identityの二機を区別できない場合はCONFLICTで隔離する。

正当な変更が確定したら、binding generationを進め、古いTX/ACK/負荷通知を新bindingに結び付けない。driver Peerを外すのはin-flightを排出した後。暗号key/counter/replayの安全状態はPeer evictionで消さない。

別Identityの交換品は別NodeIdとして参加する。用途の引継ぎはアプリ/管理者の責任で、SDKが古い機器の未完了命令を新機器へ勝手に配送しない。

## 9. link評価とSleep

初回metricは設定済みの保守的な正値。RSSIから長距離性能を決めない。認証済みprobe/DATAの成功・処理時間を#4の観測器へ渡す。

awake neighborのlease初期30秒、idle refresh目標10秒、candidate TTL5秒。実DATAがあればprobeを省ける。lease切れはbinding削除ではなく利用停止で、再確認後に復帰する。

眠る端末は常時route監視をしない。既知peerへ本体DATA→必要時だけ同channel発見→保存channel候補の順。追加探索は起床予算2000ms、停止予約100msと未完TXの最悪待ちを先に差し引く。400ms×候補数を全部完遂する約束ではない。予算切れでも所属・Message ID・期限を維持する。

`EspNowPowerPort::start_discovery()` をこのengineへ接続し、UNSUPPORTEDを単に成功へ置換しない。完了は認証済み可用性eventでPowerCoordinatorへ返す。

## 10. 合格条件

MAC設定を持たない二台と三台chainで追加・交換を再現する。既所属端末のlocal再bindingはAuthority往復不要。未所属端末は承認前DATA不可。同NodeId競合、偽MAC100件、容量20境界、返信lease欠如、driver再構築後broadcast rate、Sleep中断を試験する。

旧静的登録APIは明示trust/provisioning経路として残すが、dynamic発見の内部から無認証で呼び出さない。対応する受入IDは[scenarios](scenarios.json)のD3系列。

# 既存Membership・FrameType・admissionとの統合契約

設計版：0.2-draft／2026-09-19。[PR #6のレビュー](https://github.com/MOVEI144/RouteLoom/pull/6#issuecomment-5741118628)への設計修正。**この文書は実装時の契約であり、既存helperやruntimeを修正済みとはしない。** 機械可読な対応は [contracts.json](contracts.json) の `admission`、追加受入は [scenarios.json](scenarios.json) のD3-11〜16とX-11。

## 1. 採用・併用・変更の判断

| 既存／提案 | 決定 | 所有するもの |
|---|---|---|
| `MembershipState` 0〜5の6状態 | **採用**。値と既存の意味を変えない | Membership controllerがNode×Networkの所属を管理 |
| `FrameType` 1〜7 | **採用**。RLD1のkindでも同じ意味・同じ番号を使用 | 共通のsemantic type registry |
| 02-discoveryの近隣lifecycle | **併用**。別型 `NeighborPhase` として実装 | Discovery/Binding管理が候補×相手radio×exchangeを管理 |
| `RLD1` | **併用**。限定された1hop bootstrap carrier | 未登録MACとの発見・初期相互確認。所属確定や通常DATAは不可 |
| `RL` Wire v1 | **維持**。通常DATAのheader/byte列は不変 | 認証済みlink上の配送と、権限を絞ったbootstrap転送 |
| `frame_allowed(state,type)` | **改修して再利用**。単独では最終gateにしない | 正本allowlistによる粗い候補判定＋別の文脈付き判定 |

所属状態を9状態へ置換する案は採らない。`AUTHENTICATING`という同じ表示名からenum castして状態を共有しない。driver Peer登録、cookie成功、暗号鍵の存在は、いずれもMemberやREACHABLEの証拠ではない。

## 2. 二つの状態軸と書込み権限

### 2.1 所属はNode×Network、接続phaseは相手ごと

`MembershipState` は `Unprovisioned=0 / Discovering=1 / Authenticating=2 / AuthorizedPendingCommit=3 / Member=4 / Revoked=5` を維持する。ローカル機器の状態と、相手の検証済み所属recordを別に持つ。相手がpacketに書いた自己申告状態を、このenumの正本へ代入しない。

| 場面 | 自NodeのMembershipState | 対象相手のNeighborPhase | 他の接続への影響 |
|---|---|---|---|
| 新規の自Nodeが参加開始 | 準備とpolicy確認後にDiscovering→Authenticating | CANDIDATE→AUTHENTICATING | 通常DATAはまだ不可 |
| 機器認証済み、所属確定待ち | AuthorizedPendingCommit | AUTHENTICATED→APPROVAL_PENDING | 認可されたbootstrapのみ |
| 正式な所属証拠を保存・確認済み | Member | BOUND→往復確認→REACHABLE | 初めてpolicy内の通常通信を許す |
| 既所属Aが新しいRelay Bを発見 | **Memberのまま** | BとのphaseだけCANDIDATEから進める | 他の認可済み近隣との通信は継続 |
| Member Bが未所属Aへ応答 | BはMemberのまま | AはAPPROVAL_PENDINGまで | Aを通常の中継器として広告しない |
| Sleep・通信断・Peer eviction | 所属が有効ならMemberのまま | SUSPENDED/STALE、またはdriver cacheだけ退避 | 所属・安全counterを削除しない |
| 相手Aを失効 | B自身の所属は変更しない | AのbindingをREVOKEDとして利用停止 | A経由のroute/未開始TXを再評価 |
| 自Nodeの正式な失効 | Revoked | 自Nodeの全通常bindingを利用停止 | 無線の自己再Joinは禁止 |

`NeighborPhase::CONFLICT/REVOKED`は相手に関する拒否状態／理由。`MembershipState::Revoked`とは型もscopeも異なる。

### 2.2 認証・承認・接続確認を混ぜない

Authenticatorは `AuthenticatedPeerProof` を返すだけ。Membership controllerが既存membership証拠またはAuthorityの新規commit証拠を検証・保存する。Ownerはその最新revision、transactionの生存、両端Identity/radio/Network、鍵の有効性を再確認して `VerifiedBinding` を発行し、BOUNDへ進める。

`VerifiedBinding`だけでは双方向可用性を保証しない。認証済みNeighborProbe/Resultなどで確認後にREACHABLEへ進め、Coreの経路候補へ通知する。membershipがない場合は通常Bindingとは別型の `BootstrapLinkContext` だけを発行し、承認先との限定交換に使う。

遅着FINISH、MembershipResult、非同期認証完了callbackは、取り消したtransactionや古いbinding generationを復活させない。失効が間に入った場合は最新状態で再判定する。DISCOVER/credential fragmentを受け取るたびに6状態を初期化する処理は禁止。

## 3. RLD1と既存type 1〜7の対応

RLD1は**別のFrameType番号体系ではなく、同じsemantic typeを運ぶ小さいcarrier**。旧Wire parserにRLD1を入力したり、同じtype番号だから同じbyte layoutだと解釈したりしない。

| 既存FrameType | 値 | RLD1での用途 | 認証済みWire v1での用途 |
|---|---:|---|---|
| Discover | 1 | 局所の要求。Network/Identity/capabilityはhint | 新Autonomy profileからは発行しない。旧予約を別用途へ変えない |
| Offer | 2 | 局所応答、cookie。認証済み所属情報ではない | 同上 |
| BootstrapAuth | 3 | PROVE/CONFIRM/FINISHなどのprofile固有認証phase | 必要なら承認先への認証交換を限定proxyで運ぶ |
| MembershipResult | 4 | **禁止** | 正規Authorityの認可結果・commit証拠。受信しただけではMemberにならない |
| BootstrapChunk | 5 | 既存の認証transactionに属するBootstrapAuthの有界fragment | 認証交換またはMembershipResultの有界fragment。innerの権限も検査 |
| BootstrapReply | 6 | fragment受領・再試行の制御応答。未関連transactionへは返さない | 同じbootstrap transactionへの制御応答。所属確定を代行しない |
| MembershipQuery | 7 | **禁止** | 正当な承認先への照会。任意のNodeを照会・操作する汎用RPCではない |

PROVE/CONFIRM/FINISHはすべてtype 3の論理phaseで、新しいtop-level typeではない。Providerが必要とするメッセージ数・認証方式を三往復へ固定した意味ではない。subtype/phase・step index・payloadの最終バイト列はP0で共通vectorと一緒に固定する。cookieはtype 2のbody、fragmentのACKはtype 6として扱う。

RLD1の許可kind集合は **{1,2,3,5,6}**。4/7、DATA16、通常管理・route・任意の未知kindを拒否する。既存の `NeighborProbe=40 / NeighborResult=41` は両端membershipとlinkが有効になったBOUND以降のWire経路で使い、pre-memberの鍵確認へ流用しない。

### 3.1 Carrier選択は一度だけ

RLD1の最初の2byteはWireの `RL` と重なる。完全な4byte識別子／Wire版まで検査してcarrierを決定する。RLD1の型・長さ・認証が不正でもWireへ落とさず、Wireの認証失敗をRLD1へ落とさない。上限未満の切詰めや曖昧なprefixも拒否する。

RLD1は1hop止まり。RelayはRLD1のbyte列をそのままmeshへ転送しない。承認したproxy transactionだけを、既存の認証済みWire link上で3〜7の限定bootstrap objectとして承認先へ運ぶ。経路・先の無い場合は有界待ちまたは失敗とし、DATA Floodや汎用トンネルで解決しない。

RLD1ヘッダ44Bのうちnetwork欄4Bは探索hint。正式な64bit NetworkIdはtranscript・証拠・承認結果へ全幅で結び付ける。hint衝突で他Networkへ昇格しない。これは通常Wire headerを縮める変更ではない。

### 3.2 Fragmentも同じadmissionを通す

最大1024B、同時handshake1、RX予約4slotという既存設計予算を共有する。RLD1だけの追加枠を別に無制限確保しない。cookie/transaction/roleの安い確認後に組立枠を確保する。

fragmentはtransaction、subject、carrier、inner type、全長、offsetと証拠contextへ固定する。RLD1のinnerはtype 3だけ。Wire bootstrapのinnerはtype 3または4だけで、4にはAuthority証拠とPendingCommitへの配送権限が必要。type 5の中へtype 5を再帰的に入れることや、DATA/ROUTE/CONTROLを包むことは禁止。

外側type 5が許可されただけではdispatchしない。完成時にinner type、現在のmembership、role、transactionと期限を再検査する。組立中に失効・取消・state変更があれば破棄する。BootstrapReplyは組立の受領を示すだけで、所属commitや通常DATA受理の証拠ではない。

## 4. 既存frame_allowedの再利用範囲

### 4.1 現コードの事実と正本との差

参照PR #2の `admission.hpp` は、MemberのDiscover/Offerを拒否し、RevokedのDiscoverを許す。また認証中のChunk/ReplyとpendingのQueryを表現しきれていない。`protocol/semantics.json` はMemberの発見・bootstrapを許す一方、Revokedを空集合としており一致していない。コードと意味の正本を都合のよい方だけ採用しない。固定リンクは [sources](sources.md) §5。

**実装時には既存のsignatureとMembershipStateを保ち、frame_allowedを意味allowlistから生成または全組合せ試験で同期したcoarse判定へ改修する。** Unknown FrameTypeや範囲外MembershipStateは既定false。`type != Discover && type != Offer`のような未知型も通すMember判定は残さない。

このPRは設計差分なのでhelperや既存の意味正本をここで無言変更しない。採用時にはC++ helper、Rust対応判定、意味JSON、runtimeのdispatch呼出しを同じ実装コミットで揃え、旧CORE profileのAutonomy featureはOFFのままにする。

### 4.2 粗い許可集合（受信・送信の最終許可ではない）

以下の略記は既存FrameTypeの意味。最終判定ではcarrierとroleによってさらに絞る。

| MembershipState | bootstrapのcoarse候補 | 追加条件／通常通信 |
|---|---|---|
| Unprovisioned | Discover / Offer | 近所への無条件TX/加入許可ではない。provisioning/対象Network/policyを確認して開始。対応する要求なしのOfferはhint処理まで |
| Discovering | Discover / Offer | 相関した発見transactionだけ。auth開始時に正式にAuthenticatingへ遷移 |
| Authenticating | Discover / Offer / BootstrapAuth / BootstrapChunk / BootstrapReply | auth transactionのprofile/step/宛先と有界予算を要求。通常通信は禁止 |
| AuthorizedPendingCommit | MembershipQuery / MembershipResult / BootstrapChunk / BootstrapReply | 正規の認証済みbootstrap経路のみ。暗号成功だけで通常通信を解禁しない |
| Member | 上記7型と既存member-only集合 | 未所属候補への発見応答や限定proxyは可能。通常通信は相手側もMember、役割・鍵・可用性条件付き |
| Revoked | なし | 通常resume不可。物理保守による明示再provisioningはこの無線経路の外 |

この粗い集合は既存 `protocol/semantics.json` の `membership_allowlist` を参照し、別の永続state enumや別のruntime正本を作らない。新設計JSONは役割・carrier・証拠の追加制約だけを保持する。

### 4.3 最終gateの契約案

`AdmissionContext` はlocal membership、相手／subjectの検証済みrecord、RX/TX、carrier、local role、transactionと期待step、期限、peer/address/binding世代、検証済み証拠、feature capability、資源予算を持つ。role/stateを受信packetの自己申告から作らない。

`admission_decision(context, type)` は許可/拒否の理由と有効なscopeを返す。判定は次の積であり、どれか一つの成功では通さない。

```text
既知typeと正しいcarrier
  AND local membershipのcoarse allowlist
  AND そのrole・相手・subject・directionに許可された処理
  AND 生存transaction／世代／期限（bootstrapに必須）
  AND 対応する認証・認可・commit証拠
  AND featureとRF条件と資源予算
```

cheap parse段階は重い認証・組立への入場許可まで。認証完了・再組立完了・送信投入・副作用適用の直前にも最新contextで再判定する。source MACだけで通常受理laneへ昇格させない。

| local role | 許される例 | 禁止する例 |
|---|---|---|
| JoiningNode | 期待AuthorityへのQuery、正当Resultの検証・保存 | 近隣のCONFIRMだけでMemberへ遷移 |
| MemberResponder | localはMemberのままDiscoverへOffer、対話中の認証交換 | 未承認候補を通常DATAのMemberとみなす |
| JoinProxy | 認可されたsubjectとAuthority間の有界bootstrap転送 | 任意宛先DATA、RLD1全網中継、代理の所属発行 |
| Authority | 認証/承認/台帳commitを経たMembershipResult発行 | 署名や永続化失敗を成功Resultへ変換 |
| EstablishedPeer | 有効membershipを使う局所再bindingと通常通信 | 新相手のため自NodeをDiscoveringへ降格、旧証拠の無期限延長 |

通常DATA/route/serviceは、両端の有効membership、認証済みbinding、対応する役割を必須とする。BOUNDでは可用性probeだけ、REACHABLEでpolicy内の通常通信を許す。JoinProxy例外は通常DATAに適用しない。Memberかどうかの一つのboolで全typeを通す設計にはしない。

## 5. 状態遷移の確認トレース

**既所属同士:** A(Member)がB(Member)のMACを未登録 → RLD1 1/2 → type3の相互確認（必要時5/6） → 既存membership検証 → BOUND → Wire40/41の双方向確認 → REACHABLE。A/B自身は全期間Memberのまま。Authorityの新規承認は不要。

**新規参加:** AはDiscovering→Authenticating、BはMemberResponderのまま → BはAへBootstrapLinkContextのみ付与 → Aの認証が終わればAuthorizedPendingCommit → Bの限定proxy経由でWire7のQuery → 正当Authorityが承認・台帳commit → Wire4のResult（必要時Wire5/6のfragment） → Aが証拠を検証し永続保存 → AをMemberとしbindingを再確認 → Wire40/41 → REACHABLE。BがMemberでもAの未承認DATAは通らない。

**拒否・取消:** 認証失敗／期限切れはそのtransactionを終了する。未承認参加は通常通信不可のままpolicyで再試行し、既所属の再binding失敗は他の有効bindingへ影響しない。正式な失効では該当所属／bindingを無効にし、遅い成功callbackは世代検査で拒否する。

## 6. 設計レビューと実装受入の区別

今回の設計checkerは型対応、状態の所有者、carrier集合、禁止事項、意味正本への参照、追加シナリオ台帳と負例manifestの検出を確認する。**actual frame_allowed/runtimeによる上記トレースはまだ実行していない。** D3-11〜16/X-11はplanned_not_runのまま保持する。

P0/P1でC++/Rustの本物のcodec・gate・Provider・Coreを結び、Memberの発見応答、承認前DATA拒否、fragmentによる権限拡大、型番号取り違え、未知kind、失効後の遅着、legacy parserへのfallback拒否を受入試験へ加える。

PR #2採用後は、そのfirmware行列（reference normal/deep_sleep×3target、bridge normal×3target）を維持する。この設計branchの旧matrix成功でその9構成を試験済みとはしない。取り込みと設定別buildは [実装前チェック](05-implementation.md)で追跡する。

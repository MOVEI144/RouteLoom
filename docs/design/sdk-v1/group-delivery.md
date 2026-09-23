# group／ALL配送と送信元ごとの順序（KGuard）

状態：**portable coreに実装済み・host試験済み（SimWorld）**。実RF・実機・HILでの認定はしていない。Wire v2 header（88B）は変えず、新しいframe type 25（GROUP_DATA）と26（GROUP_REPORT）を割り当てた。gateway-scoped profile（[経路スケール設計](routing-scale.md)、issue #41）の木の上でだけ動く。flat profileでは**明示的に非対応**（`GROUP_REQUIRES_GATEWAY_SCOPED`）で、floodには落とさない。network group鍵（GK、[03 鍵階層](03-key-hierarchy.md)）は使わない。

対象コード：`components/routeloom/src/group.cpp`（配送engine・順序）、`group_wire.cpp`／`group.hpp`（payload codec）、`group_replay.cpp`／`group_replay.hpp`（group scopeのreplay表）、`wire.cpp`（`seal_group`／`open_group`）、`node.cpp`（配線、unicastの順序）、`c_api.cpp`／`routeloom.h`（C ABI）、`usb_host_ops.cpp`／`usb_bridge.cpp`（USB HostOps 0x50〜0x52）、`components/routeloom_espnow/src/psk_security.cpp`（開発PSKのgroup scope）。Rust：`host/routeloom-wire/src/group.rs`、`host/routeloom-protocol/src/group_ops.rs`。試験：`tests/cpp/test_group.cpp`ほか（§12）。関連：[Wire](../../spec/wire-protocol.md)、[USB §8](../../spec/usb-protocol.md)、[無線§14](../../spec/radio.md)、[互換性](../../spec/compatibility.md)。

## 1. 問題

KGuardの現場は1 gateway（USB接続ESP32＋PC）と約100台の常時給電表示板（ESP32-S3）。gatewayから次の2種類を下ろす。

- **ALARM**：全台へ即時。現場のほぼ全boardに1秒以内に届き、1台も落とさないこと。
- **表示更新**：板の群（例：2階の50台）へ。短時間に20件程度が続くことがあり、送った順に表示されなければならない。その間もboard→gatewayの上り（在室変化）を止めてはならない。

これまでのAPIはunicastだけで、100台に配るには100回の`send()`が要り、1件ずつE2E受領を返す。送信元から見ると「何台に届いたか」が分からず、air timeも大きい（§2）。unicastにも送信元ごとの順序保証が無かった。

## 2. 物差し：air time

air timeは[経路スケール設計](routing-scale.md) §2と同じ推定モデルで数える：`frame_us = (encoded_bytes + 96) × 32`（96はMAC header・LR preamble・MAC ACKのbyte換算、LR 250kbpsで32µs/byte）。14Bの警報文（例`PUMP3 OVERTEMP`）の場合：

| frame | encoded | 推定air time |
|---|---:|---:|
| GROUP_DATA（header 88＋flags 1＋本文14＋end tag 16＋link tag 16） | 135B | 7,392µs |
| GROUP_REPORT（header 88＋固定29＋link tag 16、missing id無し） | 133B | 7,328µs |

10×10格子・8近傍・gatewayを外壁中央に置いた100台（深さ最大9）で1件をALLへ配る費用：

| 方式 | frame数（損失なし） | 推定air time | 備考 |
|---|---:|---:|---|
| unicast RELIABLE×99 | 99件×平均約5hop×（DATA＋HOP_ACCEPT＋END_RECEIPT…） | 約10〜14s | 送信元が99件のE2E状態を持ち、確認は1件ずつ別々に返る |
| **木に沿った子ごとのunicast（採用）** | 木の辺99本×（写し1＋report 1） | **1.46s** | MAC ACKで各辺を確認、集約reportで送信元が台数を知る |
| 木に沿ったlink broadcast | 中継node数（推定約35）＋report 99 | 約1.0s（推定） | ESP-NOW broadcastはMAC ACKが無く、link保護にGKが要る（未提供）。隠れ端末で失う分の修復も要る |

broadcast方式の節約は写しの部分（約0.47s）だけで、reportは同じ数が要る。GKへの依存と無確認送信の代償に見合わないため、本設計は子ごとのunicastを採る。GKが入った後の選択肢として§13に残す。

## 3. 採用設計の全体

1. gatewayはmessageを**1回だけ**end保護し（§8）、木の子ごとにMAC ACK付きunicastで写しを送る。HOP_ACCEPTは使わない。
2. 各中継nodeは受け取ったmessageを自分の木の子へ同様に転送する。memberでないnodeも中継する。
3. 各nodeは自分の部分木の結果（受理したmember数、非member数、未確認数、未確認idを最大12件）を1件のGROUP_REPORTにまとめて親へ返す。
4. 送信元は子のreportを合算し、全台を確認できれば完了。欠けがあれば**欠けた部分木だけ**へrepair roundを送る。
5. 結果は`GroupDeliveryResult`（`DeliveryResult`に台数・未確認idを足したもの）で、observer（`on_group_delivery`）・`group_delivery(id)`・C ABI・USBで読める。

### 3.1 アドレスとMessage ID

- GroupIdは16bit。0は予約、`0xFFFF`がALL。wire上のdestinationは`0xFFFF_FFFF_FFFF_0000 + group_id`で、ALLは`kBroadcastNodeId`と一致する。このnamespaceのNodeIdは機器に付けられない（`validate_config`が拒否）。
- Message IDは`{送信元のmessage_session, bit63 | group stream番号}`。stream番号は送信元のboot sessionごとに1から数えるu32。bit63によりunicastのMessage IDと衝突せず、end AADで認証されたheader内にあるため、**受信側は開封前に**重複排除と順序判断ができる。

### 3.2 転送とhopごとの信頼性

- 木は#41のgateway-scoped木そのもの。子は`Neighbor::child_until_ms`（`neighbor_is_child`）で、子の部分木はnext_hopがその子である経路の集合。
- 写しは`JobOwner::Group`のForwarded jobとして通常のTX queue・DRR・輻輳制御に乗る。1辺あたりの試行は`max_link_attempts`（既定2＝初回＋1回）で有界。失敗した辺はrepair roundで再試行する（§3.4）。
- priorityはmessageのpriority（ALARMはUrgent）をそのまま使う。GROUP_REPORTも同じpriorityで送る（受理済みの仕事の確認は仕事へ課金、radio.md §14）。

### 3.3 集約確認（GROUP_REPORT）

- nodeはroundの**最初の送信者を親として追従**し、他の送信者からの写しにはNOT_CHILD（counts全て0）を返す。経路の揺れで2つの親から届いても、1台が二重に数えられない。
- reportの締切は入れ子にする：各nodeは`(hop_remaining − 1) × 150ms`（`kGroupLevelWaitMs`）までに子のreportを待ち、揃えば即、揃わなければ締切で手元の分をまとめて返す。送信元は最大`H × 150ms`待つ。損失が無ければ締切を待たずに葉から順に上がってくる（100台で送信から90ms）。
- 締切までにreportが来なかった子の部分木は、送信元の経路表から数えて「未確認」とし、その子のidを未確認idに入れる。

### 3.4 repair round

- 完了しなかったroundの後、`kGroupRepairGapMs`（200ms）をおいて次のroundを送る。最大`kGroupMaxRounds`（12）round、ただしmessageの寿命内に限る。
- repairは**未完了の部分木にだけ**写しを送る。完了済みの子は再送しないが、その子の経路表上の部分木の大きさと、reportで数えた台数が合わない場合は再度尋ねる（整合検査）。
- 送信元の既知台数（admission以降の最大値）に対し、reportで説明できないnode（`unaccounted`）が出た、または数えすぎ（経路の移動で2つの部分木に数えられた）を検出した場合、次のroundは`delivery_round`のbit7（REFRESH）を立て、全relayが全ての子へ再送して部分木を数え直す。
- 受信済みのnodeにrepairの写しが届いても、アプリへの二重配送はしない（§5）。reportだけ返す。

### 3.5 結果summary

| state | reason | 意味 |
|---|---|---|
| Queued | `GROUP_QUEUED`／`GROUP_BUDGET_WAIT` | 送信元のqueueで待機（§7） |
| WaitingForEndReceipt | `GROUP_ROUND_PENDING`／`GROUP_REPAIR_PENDING`／`GROUP_REPAIRING` | roundの結果待ち、またはrepair予定 |
| Delivered | `GROUP_COMPLETE` | 既知の全nodeを確認（missing 0、unaccounted 0、数えすぎ無し） |
| Failed | `GROUP_NO_TREE` | 子も既知のnodeも無い（誰にも配れない） |
| Failed | `GROUP_INCOMPLETE` | round上限か寿命まで確認できない台が残った（未確認idを列挙） |
| Failed | `GROUP_SUPERSEDED` | 後続のstream番号が32以上先へ進んだ（受信側の重複窓を越えるrepairを出さない） |
| Expired | `GROUP_NOT_SENT` | 予算待ちのまま寿命切れ（1台にも出していない） |

`delivered`はmemberとして受理した台数、`nonmember`は届いたがmemberでない台数、`missing_total`は木の中で未確認の台数、`missing[]`はその最大12件のid（`missing_truncated`で超過を示す）、`unaccounted`は経路表にいるがどのreportにも現れない台数（idは不明なので`missing`には入れない）。数値はどれも**確認できた事実**だけで、推測で埋めない。

### 3.6 membership

- 全nodeはALLのmember。加えて最大8個（`kGroupMembershipMax`）のgroup idを`set_group_membership`（C ABIは`rl_set_group_membership`）で持つ。0・ALL・重複・9個以上は拒否。
- memberでないnodeも木の中継として写しを子へ送り、reportで`nonmember`として数えられる。アプリへは渡さない。
- membershipはnodeのRAMにだけあり、wireには載らない。送信元は誰がmemberかを事前に知らず、届いた結果として台数を知る（§13：部分木の刈り込みは今後）。

## 4. 重複排除

- 受信側は送信元ごとに`GroupStream`（stream番号64個分の既受信bitmapと順序cursor）を持つ。容量は`kMaxRouteGateways`（2）で、送信元はroute gatewayに限られるので溢れない。
- 同じ(送信元, stream番号)の2回目以降はアプリへ渡さず、reportだけ返す（repairの写しは必ず重複する）。
- 窓より古い番号は`GROUP_TOO_OLD`で拒否する。送信元は自分のstream番号が32以上進んだ古いmessageを`GROUP_SUPERSEDED`で打ち切るので、repairが受信側の窓を越えることはない。
- 1 messageの寿命は`kMaxMessageLifetimeMs`（30s）が上限で、窓（64）と上限の組み合わせで、寿命内に同じ番号が再利用されることはない（stream番号は単調、boot sessionが変わればMessage IDのsessionが変わる）。
- 中継状態（`GroupTree`、4件）は寿命切れ・決着済み・報告済み未完了の順に追い出す。

## 5. 順序

### 5.1 groupのORDERED

- `GroupSendOptions::ordered`（C ABI `rl_group_send_options_t.ordered`、USB `flags` bit0）を立てたmessageは、各受信nodeで送信元のstream番号順にアプリへ渡す。
- 欠番の後ろのORDERED messageは保持する（`kGroupHoldCapacity`＝4件、本文ごと）。保持の期限は`min(そのmessageの残り寿命, kGroupOrderMaxHoldMs＝10s)`で、期限が来たら欠番を**飛ばして**先へ進む。したがって先頭詰まりはmessageの寿命を超えない。
- 飛ばした番号が後から届いたら、配送はするが`GroupMessageInfo::late = true`を付ける（順序外であることをアプリが判断できる）。捨てはしない。
- 保持枠が満杯のときは、最古の保持の欠番を飛ばして解放する（新しいmessageを拒否も破棄もしない）。
- ORDEREDでないmessage（ALARM）は**決して保持しない**。ORDEREDの欠番待ちの間も即時に渡る。memberでない番号も「見た」として順序cursorを進める。

### 5.2 unicast RELIABLEのordered

- `SendOptions::ordered`（C ABI `rl_send_options_t.ordered`、旧予約byte）はRELIABLEだけで有効（BestEffortや`persist_across_sleep`とは`ORDERED_REQUIRES_RELIABLE`で拒否）。
- 同じ宛先への直前のordered messageが決着する（Delivered、または送信前取消）か、**直前のmessageの寿命（`expires_at_ms`）が過ぎる**まで、次のmessageは`WaitingForRoute`（reason `ORDER_WAIT`）で送信側に留まる。受信側の並べ替えbufferは持たない。
- 先行messageが失敗・期限切れになっても後続は寿命内に解放される（先頭詰まりは先行の寿命まで）。後続自身の寿命が先に尽きれば通常どおりExpired。
- 送信側で直列化するため、同じ宛先へのordered列はhop数×往復の時間だけ遅くなる。表示更新のような「最後の値が正」の用途は、groupのORDEREDの方が速い。

## 6. 衝突しない仕組み：hop内の多重と上り

写しとreportは通常のDATAと同じTX queue・DRR（Urgent 8／Management 4／Normal 4／Bulk 1）を通る。一度に進行中にするnon-urgentのround 0は1件だけにし（§7）、報告は各辺1件なので、group配送がhopのqueueを占有し続けることは無い。上りの在室報告（Normal RELIABLE）は同じDRRで順番を得る（試験§12：20件burst中の上りp95は、groupが無い同条件と同じ180ms）。

## 7. 予算（§14）

radio.md §14は受理済みDATAの確認を「その仕事への課金」とする。groupの写しとreportはこの**仕事（work）**に数え、control予算（100ms/s）の外にある。それでも無制限に流さないため、送信元（gateway）に専用のtoken bucketを置く。

- 補充`NodeConfig::group_airtime_us_per_s`＝300,000µs/s（既定）、容量3,000,000µs（`kGroupBudgetCapacityUs`）。
- admission時に`既知台数 × (写しのair time ＋ reportのair time)`を差し引く（ALLで100台なら約1.46s分）。足りなければ`GROUP_BUDGET_WAIT`で待つ。寿命内に足りなければ`GROUP_NOT_SENT`。
- non-urgentのrepair roundも同じbucketで待つ。
- **Urgent（ALARM）は待たない**：bucketを借越し（下限は−容量）で差し引き、進行中のnon-urgent propagationとも無関係に出る。送信元表（3件）は1件をUrgent用に空けておく（non-urgentは2件まで、3件目は`GROUP_QUEUE_FULL`）。
- non-urgentは一度にround 0を1件だけ進め、前のround 0が決着してから次を出す。

結果として、group配送の長期平均は送信元の配賦（既定で0.3s/s＝チャンネルの30％）に収まり、route control（木の維持、約80ms/s）は100ms/s包絡の内側に残る（§12で実測）。20件の表示更新（50台のgroup、ALLと同じく木全体に送る）はこの予算で約87秒に広がる：これは速度の上限ではなく、予算を上げれば比例して速くなる。`group_airtime_us_per_s`は現場ごとに調整できる（上げるとunicastと上りの取り分が減る）。

## 8. セキュリティ

### 8.1 scopeとnonce

- `SecurityScope::Group`（2）を追加した。GROUP_DATAのend保護contextは`(Group, network, sender＝origin, receiver＝group address, epoch＝end_epoch)`。AEAD nonceは既存と同じく`scope u8 ‖ 方向 u8 ‖ epoch u32 ‖ counter u48`で、scope byteが違うのでunicastのend nonceと重ならない。
- 送信元はend層を**1回だけ**封止する（`wire::seal_group`）。全ての子・全てのroundは同じend暗号文を運び、link層だけをhopごとに作り直す（link counterは通常どおり毎回新しい）。同じend nonceで**別の平文**を封止することはないので、nonce再使用は起きない。
- 開発PSK（`components/routeloom_espnow`）は(sender, group address, epoch)ごとの鍵をHMACで導出し、TX counter leaseの方向tagを4（group）にして、unicast end（2）とcounter空間を分ける。test security（`tests/cpp/test_security.hpp`）も同じscopeを実装する。
- 受信は`wire::open_group`で開く（宛先への束縛は無い）。`open_end`はGROUP_DATAを拒否し、unicast経路でgroup frameを開けない。GROUP_REPORTはROUTE_UPDATEと同じlink保護のみの1hop frame。

### 8.2 replay

- group scopeの受信replayは`GroupReplayTable`（RAMのみ、16組×64 counterの窓）で判定する。表が満杯なら新しい(sender, group)組を**拒否**し（既存組を追い出して窓を失うことはしない）、古いepochは拒否する。
- 永続化しない（#37：ピアごとのNVS recordを増やさない）。受信側の再起動でこの表は消えるが、group frameはhopごとにlink保護されており、link層のreplay床（既存の永続guard）は残るので、捕獲したframeをそのまま再送しても受理されない。
- 重複排除（§4）はreplay判定とは独立に、開封前のheaderで行う。

### 8.3 主張しないこと

- 開発PSKのgroup鍵はnetwork PSKから導出するため、PSKを持つmemberなら誰でも任意の送信元になりすませる（unicastの開発profileと同じ）。本番のgroup scopeは送信元ごとの鍵（またはGK＋送信元署名）を要し、`SecurityScope::Group`の定義にそれを要件として書いた。
- GKは使わず、broadcastもしない。

## 9. Wire

Wire v2 header（88B）・versionは不変。追加は2つのframe typeだけ：

- **GROUP_DATA（25）**：end保護（group scope）＋link保護。end保護されたpayloadは`flags u8 ‖ アプリpayload（≤127B）`（bit0 ORDERED、bit1〜2 priority、他は0）。`delivery_round`のbit0〜6がround番号、bit7がREFRESH。
- **GROUP_REPORT（26）**：link保護のみ、1hop。固定29B＋未確認id×8B（最大12件）。

詳細は[wire-protocol.md](../../spec/wire-protocol.md)、機械可読な定義は`protocol/semantics.json`の`group_data`／`group_report_payload`（membership allowlistにも追加）。golden vectorは`protocol/golden/valid/group_data.json`（relayでのforward込み）と`group_report.json`で、Rust generator（`gen_golden.rs`）が生成し、C++が同じbyte列を開封・再符号化して一致を試験する。既存のvectorは1byteも変わらない。

## 10. 資源（RAM、動的確保なし）

| 状態 | 容量 | 64bit hostでの大きさ |
|---|---|---:|
| 中継木（`GroupTree`、子10台分の状態込み） | 4 | 1,640B |
| 送信元表（`GroupOrigin`、封止済みframe込み） | 3 | 2,624B |
| 順序保持（`GroupHold`、本文込み） | 4 | 712B |
| 送信元stream（重複窓＋cursor） | 2 | 72B |
| membership | 8 | 16B |

`sizeof(MeshNode)`は64bit hostで**+5,504B**（leaf 98,952→104,456、relay 108,744→114,248、gateway 133,224→138,728）。unicastの順序用fieldを含む。ESP32（32bit）ではpointerが半分なのでこれ以下。開発PSKの`GroupReplayTable`は約768B、USB bridgeの対応表は96B。`docs/reference/resource-profiles.json`の各profileに`group_delivery_state: 6656`を計上した。

## 11. Host API

- **C++**：`MeshNode::send_group`、`group_delivery`、`set_group_membership`、`group_member`、`group_membership`、`group_stats`。受信は`NodeObserver::on_group_message`（既定は`on_message`へ転送）、送信元の結果は`on_group_delivery`。
- **C ABI**（`RL_ABI_VERSION`は2のまま、追加のみ）：`rl_group_send_options_init`、`rl_send_group`、`rl_get_group_result`（回収済みは`RL_STATUS_NOT_FOUND`）、`rl_set_group_membership`、`RL_SECURITY_GROUP`、`rl_send_options_t.ordered`（旧予約byte、structは28Bのまま）。受信したgroup messageは既存の`on_message`へ、sequenceのbit63付きで届く。
- **USB HostOps**（capability bit 7、`kCapGroupDeliveryV1`）：`0x50` GROUP_SEND、`0x51` GROUP_STATUS、`0x52` GROUP_QUERY（[USB §8](../../spec/usb-protocol.md)）。送信の受理結果を即時に、終端時にFINAL付きの結果を同じrequest idでもう1回返す。共有vectorは`protocol/usb-golden/group-ops`（C++ bridgeの2 node replayとRust codec）。firmware（bridge_node）はKconfigのcapability bit 7でattachする。
- **daemon API1（未実装、follow-up）**：次の形を提案する。`group.send {network, group, priority, ordered, ttl_ms, hop_limit, payload_b64}` → `{operation: {session, sequence}, status}`（device capability bit 7が無ければ`UNSUPPORTED`）、`group.get {network, session, sequence}` → `GROUP_STATUS`をJSON化したもの（`state`、`reason`、`delivered`、`nonmember`、`missing_total`、`unaccounted`、`missing[]`、`final`）、eventsに`group_settled`。daemonはFINALの`0x51`を受けたら結果をRAMの有界表へ置き、`group.get`はそれを返す（機器の回収後も読めるように）。`capabilities.get`に`group: {dispatch: "usb_group_delivery_v1", payload_max_bytes: 127, groups_max: 8}`を足す。

## 12. 試験

`routeloom_group_unit_tests`（約1秒）：address変換、GROUP_DATA／GROUP_REPORT codecの境界と拒否、golden payloadの一致、group scope（context、tag改ざん、`open_end`の拒否）、replay表（窓・満杯拒否・古いepoch）、7台木でのALL配送（写し6＋report 6、NOT_CHILD 0、HOP_ACCEPT 0）、membershipの計数、profile・送信元の規則（flat拒否・gateway以外拒否）、送信元queueとUrgent予約、損失後のrepair（欠けた部分木だけへ写し3件）、report経路の損失、電源断nodeのsummary（`GROUP_INCOMPLETE`、未確認id列挙）、NOT_CHILDの一回計数、ORDEREDの並べ替え、欠番skipとlate、非ORDEREDは保持しない、unicastのordered（A→B→Cの順、先行の寿命切れでの解放を800〜900msの範囲で確認）。NOT_CHILD・順序保持・unicast待ちの論理を壊すと失敗することを変異で確認した。

`routeloom_group_100_node_tests`（Debugで約35秒）：10×10格子（8近傍）、gateway 1台＋board 99台。

| 条件 | 結果 |
|---|---|
| ALARM（Urgent、ALL）損失なし | 99台全てが送信から**45ms**で受信（1秒以内99％の要求に対し100％）、summary完了90ms、写し99＋report 99＝推定air time **1.46s** |
| MAC層損失10％（試行ごとに無作為） | 1秒以内に99/99、全台430ms、2 roundで正確なsummary（1,430ms）、air 3.12s |
| 無音損失5％（MAC成功扱いで消える） | 全台3,005ms、4 roundで正確なsummary（5,875ms）、air 4.98s |
| 表示更新20件（ORDERED、50台group）単独 | 86.5s、groupのair 334ms/s（bucket上限334.7ms/s以内）、route control 82ms/s（100ms/s以内）、全member・全順序 |
| 同じburst＋上り2件/s | 同一世界の上りだけと比較して、上りの損失・p95（180ms）・最悪値が同じ。上り95％以上がgatewayへ |

最後の行の「上りだけ」の世界でも、上り2件/sで負荷連動のparent切替が起き、route controlは155〜439ms/s、240件中約5件がEND_RECEIPT_TIMEOUTになる。これはgroup配送が無くても同じ値で、#41の既知事項（[経路スケール設計](routing-scale.md) §11）である。試験はgroup配送がそれを悪化させないことを、同一世界との比較で確認する。

USB：`routeloom_host_ops_tests`にcodecの境界・拒否、2 node gateway-scoped meshでの送信→FINAL→query、非対応・flat profile・表満杯の拒否。`routeloom_usb_tests`に`protocol/usb-golden/group-ops`のbyte一致replay。Rust：`group.rs`・`group_ops.rs`の単体試験と`tests/golden.rs`・`tests/usb_golden.rs`。C ABI：`test_c_api_group`と`c_api_smoke.c`。

## 13. 限界・リスク・今後

- **群への配送は木全体を回る**：送信元はmembershipを知らないので、50台のgroupでも100台の木全体に写しとreportが流れる。部分木にmemberがいないことをreportで学び、次から刈り込む最適化は未実装。
- **予算と速さの交換**：既定300ms/sではnon-urgentのALL 1件に約5秒分の予算が要る。表示更新の連続は予算で広がる（§7）。Urgentは予算を借り越すので、ALARMの連打は他のtrafficを圧迫しうる（借越しの下限は−3s分）。
- **強い損失**：MAC損失20％以上では経路自体が揺れ、12 round・寿命内に確認しきれず`GROUP_INCOMPLETE`になることがある。結果は正直に未確認として返る（配送の保証ではなく確認の保証）。
- **負荷連動のparent切替**（#41由来）：上りが多いと木が揺れ、repairとREFRESH roundが増える。
- **送信元の既知台数**は経路表に基づく。経路表に入っていないboardは「未確認」にも数えられない。
- **開発PSKの限界**：§8.3。本番scopeは送信元別鍵が前提。
- **broadcast＋GK**：GKが提供されたら、写し部分だけbroadcastにしてair timeを約3割減らせる（reportはunicastのまま）。
- **daemon API1**：§11の設計のみ。実RF・実機での到達時間・air timeは未測定。

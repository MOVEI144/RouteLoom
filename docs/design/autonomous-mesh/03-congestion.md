# Issue #4 — 輻輳制御・負荷を考慮した経路選択

状態：設計案。要求：[Issue #4](https://github.com/MOVEI144/RouteLoom/issues/4)。無線方式は引き続きLR250。LR500の導入や全網の最適化serverを完成条件にしない。

## 1. 三つの異なる問題

1. **容量保護**：受理するbuffer/Peer/transactionがあるか。
2. **輻輳制御**：過剰投入を抑え、短い重要通信を長いqueueの後ろへ閉じ込めない。
3. **経路回避**：安全な代替がある場合、詰まった経路への集中を緩和する。

USB creditは1の別transportの機能。#4ではMesh側のadmission/feedbackを新規実装する。三つを一つのqueue depth数値やRSSIへまとめない。

## 2. 採用する範囲

**D4-01:** bounded admissionと送信公平化を先に実装し、観測をつないでから経路変更を有効にする。

**D4-02:** 既存Babel由来のfeasibilityを唯一の経路安全判定とする。負荷が低いだけのinfeasible経路へDATAを流さない。

**D4-03:** 最初は一つの具体的宛先に一つの現用next-hop。需要の変化に応じて切り替えるが、DATAを複製するmultipathやpacket単位stripingは入れない。複数宛先が異なる経路を選ぶことで分散できる。

**D4-04:** queue制御、経路変更、channel移行の時間軸を分ける。queueは即時、経路改善は秒単位、channelは持続悪化を調べてから。単一のlossで全部動かさない。

## 3. 観測の契約

| 観測 | 対象 | 除外／限界 |
|---|---|---|
| local queue sojourn | enqueue→無線に渡すまで | driver実処理・遠端の待ちと分離 |
| driver service time | driver受付→TX callback | 真のAirtimeではなくCCA/MAC再送を含み得る |
| hop exchange | 認証済みHOP_ACCEPTまでの試行仕事量 | BUSY/予定不在をRF失敗へ混ぜない |
| feedback | 認証済み隣接のqueue/拒否/受信可能性 | 一台の自己申告。真実や全経路状態を保証しない |
| final result | END_RECEIPT、expiry、indeterminate | Gateway MAC成功を代用しない |

キーはbinding generation、方向、radio/channel世代、frame長区分。低頻度端末には欠損と古さを残す。raw64標本を全neighbor×全rate×全lengthで大量保持せず、EWMA/min/counterと固定poolを使う。

初期集約窓は2秒、feedback TTLは3秒。標本不足時は保守的なnominal costとunknown。受信できたpacketのRSSIだけを損失packetにも適用しない。

## 4. 送信scheduler

FIFOを、既存TxJob poolへのindexを持つ有界schedulerへ置き換える。queueをクラスごとに複製してRAMを倍増させない。

- ACK/必要な制御応答に小さい予約laneを持つ。未認証の自称urgent/controlはここへ入れない。
- それ以外はmanagement/urgent/normal/bulkのDRR、初期重み4:8:4:1。frame数でなく長さ/rateに基づく推定送信費用で課金する。
- class内は(検証された送信者scope, origin, 具体的宛先)をflow keyとし、active flow最大32。軽い送信者を大きい連続送信の後ろに固定しない。
- flow table満杯では既存の有限overflow bucketへまとめるか新規受付を拒否する。動的な無限queue追加は禁止。origin詐称に対してglobal/per-neighbor上限も適用する。
- bulkを永久starvationにしない。ただし負荷が契約上限を超えたら遅延・拒否を明示し、全classへ無条件の期限保証はしない。

queue50%で背景probe/logを縮小、80%でbulkと改善試験を停止する。通常DATAの意味を解釈したcoalescingはアプリが許可したときだけ。

FQ-CoDelのflow分離とsojourn観測を参考にするが、TCP前提のdrop制御や既定5msをコピーしない。受理済みRELIABLEをqueue制御のため黙って捨てる設計にはしない。[sources](sources.md)

## 5. 受理・BUSY・backpressure

新しい通常受信は必要資源をまとめて予約した後だけHOP_ACCEPTする。容量不足なら `Busy(20)` を返せるが、これ自体の返信枠も必要。返信できない場合はdrop統計と送信元のtimeoutで処理し、架空の拒否応答を送った扱いにしない。

BUSYのv1 payloadは最大64B。version、reason、参照type/origin/session/sequence/round、binding incarnation、feedback sequence、retry_after_ms、pressureを含む。未対応peerへは送らずlegacy受理/timeoutへ戻る。

BUSYは**受理前拒否**。HOP_ACCEPT済みの仕事をBUSYで後から取り消さない。受理後に混んだ場合は責任を保持しつつ、別の負荷hintで上流へ減速を依頼する。END_RECEIPTを発行したことにもしない。

送信側は未完の(peer, Message ID, round)に一致し、認証・TTLが有効なBUSYだけ採用する。retry_afterは20〜1000msにclamp。小さすぎる値で即時再送storm、大きすぎる値で永久停止にしない。

peer windowは初期2、最小1、最大4かつglobal awaiting-hop枠以内。BUSYで1へ縮小、安定した認証受理が8回連続すれば1ずつ戻す。メモリ枠の解放とwindow増加を混同しない。

同一jobのRF loss試行は既存2回、BUSYによる再入場は追加最大4回、全物理試行6回以内をAUTONOMY profileの初期上限とする。送信元round3回と元期限が先に尽きれば終了。peer/rate変更でも上限をリセットしない。callback結果不明は独立に安全処理する。

深い箇所の詰まりは、そこのadmission/window縮小→上流queue増加→更に上流のadmissionへ伝播する。初期実装では網全体の複雑なcredit台帳を新設しない。全経路の空き容量を端末が正確に知っているとはしない。

## 6. routing metricへの反映

### 6.1 同じ単位を維持する

既存RouteMetricは任意の正のcost単位であり、突然ミリ秒へ読み替えない。nominal link costを基準bとし、同方向・同frame長で測った仕事量の比によりlink costを更新できる。

`b = clamp_positive(ceil(nominal_cost * measured_exchange_cost / reference_exchange_cost))`

測定costは適格な試行時間の総和／認証受理成功数。失敗を省いて成功例だけ速く見せない。driver時間に再送を含む場合はETXを再乗算しない。referenceは同じprofileで測った基準で、未取得ならnominalを維持する。

### 6.2 queue penaltyの所有者

A→Bのlink costに加えるのは、**AのB向けegress queue**の持続遅延だけ。Bのegress queueはBが広告する自身の経路metricに含まれる。Bの広告metricとBのqueue自己申告の両方を加えて二重計上しない。

初期式：`p = b * min(4, ceil(max(0, Q_ms - 50) / 50))`、`link_cost = saturating_add(b, p)`、`route_metric = saturating_add(B.advertised, link_cost)`。

Qは2秒窓で平滑化したqueue遅延。50msと係数4は設計初期値であり実測最適値ではない。pressure hintは短期admission/windowに使い、未定義の別単位を無造作にrouteへ足さない。

link costは最低1、和は65535=infinityへ飽和。wide intermediateで計算し整数wrapを起こさない。自己origin距離0以外に0costを導入しない。

### 6.3 更新の安全性

`update_link_cost(binding, cost, observation_epoch)` は候補に保存したadvertised metricを使って再計算し、受信していない広告のleaseを延長しない。

feasibilityは**隣接が広告したdistanceと現在のFD**で再評価する。queueが増えたからFDを増やす/消す処理は禁止。`candidate.feasible`の古いboolを信用しない。DATA選択と広告metricが別の「隠れたルーティング」にならないよう、同じselected snapshotから送信・広告・FD更新を行う。

新しいsmallest metricを広告した時点で既存の全候補を再評価する。infeasibleしか残らなければSeqNoRequestで復旧を要求する。混雑が嫌だからTTLだけを頼りにinfeasible候補へDATAを送らない。

## 7. 経路を変えるタイミング

平常時は現在経路より20%以上かつ1cost以上良い状態が10秒続いた場合に切替。切替後hold-downは5秒。継続的BUSYが2秒以上で現在next-hopに投入できない場合、fresh/feasibleな代替へ早く切替できる。物理断・失効・invalid経路からの復旧には改善holdを課さない。

宛先ごとの決定をnode ID由来jitterで分散し、全ノードが同時に一つの空きRelayへ移らない。tieは安定した順序。実装時に同時評価100ノードの振動テストを必須にする。

新規queue投入時に経路を予約し、実送信前にもbinding/route generationを再確認する。既送信copyが残る状態で代替へ送り直してもMessage ID・元期限・消費roundを維持し、終端dedupへ接続する。

## 8. 制御通信量とroute lease

全neighborへ毎pollで新しい負荷広告を送らない。変化時のfeedbackと既存route advertisementへpiggybackする。純粋なmetric改善広告は宛先2秒以上あけ、withdraw/失効は必要な予約予算で速く送る。

ルート数・ページ数・neighbor数を増やすと既存の5秒周期/15秒leaseだけではfull tableを更新し切れない可能性がある。実装時に `refresh_bound = pages_per_neighbor * round_period + budget_wait + jitter + loss_margin` を計算し、`lease > refresh_bound`を要求する。自分のbudget待ちで正常routeをexpireさせてはならない。

100ms/s等の古い全網予算を各ノードへ丸ごと配らない。このprofileではまず校正されたlocal token bucketと制御予約から始め、全網の実占有は別に測る。推定Airtimeとdriver待ち時間を混同しない。

## 9. 失敗時の動き

NO_MEM/Peer不足はLOCAL_RESOURCE、認証済みBUSYはREMOTE_BUSY、予定surveyはPLANNED_ABSENCE。原因不明のlossはUNKNOWNまたはLINK_DEGRADED。MAC成功だけで混雑解消ともアプリ到達とも判断しない。

代替がなければ現用経路を保ったまま入場を絞り、期限を越える要求は明示的に断る。全機器が同じchannelで干渉している場合の解決は#5へ提案するだけで、#4が独断でchannelを変えない。

## 10. 合格条件

diamondの片側だけを遅くする、複数送信元を一つのRelayへ集中させる、隠れ端末、BUSY喪失/重複/遅着、全slot枯渇、古いFD反例、2つのGateway宛先、100node同時評価をportable simulatorで比較する。

比較対象は固定metric/FIFOと本profile。測るのは期限内到達率・P95/P99・総送信・拒否・経路切替回数・公平性・RAM上限。成功packetだけを分母にしない。実PHY干渉試験とmodel結果を区別する。受入IDは[scenarios](scenarios.json)のD4系列。

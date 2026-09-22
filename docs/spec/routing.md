# 経路制御・複数出口・分断修復

## 1. アルゴリズムの基準

Mesh CoreはBabel由来のsequence／feasibilityを持つ距離ベクトル方式を基準とする。NodeID単位の独自wireであり、IP/Babel packet互換は名乗らない。採用可能条件、origin sequence要求、撤回、保持、再起動規則を一貫して実装する。

参考：[RFC 8966](https://www.rfc-editor.org/rfc/rfc8966.html)、[babeld route.c](https://github.com/jech/babeld/blob/master/route.c)。RPLやTrickleの機能名を寄せ集めて安全性が自動的に成立するとはしない。

## 2. 採用可能条件

送信元起源ごとに新しいsequence、または同sequenceで保存したfeasible distanceより厳密に小さい隣接広告距離だけを基本候補にする。routeが消えたからfeasibility履歴も消してよいとはしない。合法的な候補がなければoriginへ新sequenceを要求し、その要求を抑制・集約する。

起源再起動、sequence周回、長期離脱後の古い広告、保持期限、snapshot復元までG-ROUTEの必須対象。新bootを自己申告するだけで過去の鮮度情報を無効化しない。origin epochを使う場合も認証と保存規約が必要。

## 3. コストと制約

先に認証・受信可能時間・残deadline・Peer枠・forward許可を確認し、不可能な候補を除く。その上で各区間の平滑化した実績service timeと混雑を比較する。実績時間に含まれる内部再送をETXで再度掛けない。

RSSIは診断・候補補助であって唯一のroute metricではない。hop数だけで選ばない。単位の異なる電力・時間を無係数で加算しない。電力はhard budgetとしての利用可否と、別報告のenergy estimateを持つ。

基本は宛先ごと最大3候補。平常時は20%以上のcost改善が10秒継続したら変更する。経路故障の撤回・正当な予備昇格は待たせない。少差で行き来しない設計は[MRHOF](https://www.rfc-editor.org/rfc/rfc6719.html)も参考にする。

## 4. hopと循環

無線の進行上限10hop。同一区間の再送はhopを増やさず、新たな転送先へ進むとき消費する。MAC再送回数や管理ネットワークの世代と混ぜない。

TTLは最後の停止装置。TTLがあるからrouting loopを作ってよいとはしない。DATAに対するbroadcast fallbackは無し。探索・route requestは型、範囲、TTL、重複、応答budgetを制限したcontrolである。

## 5. 複数Gatewayとservice

Gatewayごとにroute originを区別する。明示宛先はそのGatewayへの到達を要求する。anycast/service宛先では送信元が許可集合から一つを選び、ラウンド中は固定する。中間Relayが勝手に別受信先へ変更しない。

service広告はservice ID、provider ID、認証済み権限、接続session、lease、受信可否を持つ。USB接続だけでPCアプリがサービス提供中とみなさない。次ラウンドのprovider変更は送信者が許す場合のみ。跨ぐアプリのexactly-onceは上位の共有idempotencyに依存する。

## 6. 下りと眠る端末

上りが成功しても下りは自動的に成立しない。通常受信可能ノードはNodeID宛ての到達を広告し、同じ安全規則で下りDATAとreceiptを運ぶ。

sleep endpointは常時route originとして過剰広告せず、登録した接続先のmailbox/availability lease経由で下りを扱える。relayが代理originになる際の所有者・sequenceは別に管理し、同じNodeIDを複数proxyが無調整でoriginしない。未認定の代理経路機能はcapabilityをOFFにする。

v1の即時下り対象はawake状態。sleep時の下りはSTORE_UNTIL_WAKEを明示して有限に保存するか、NOT_CURRENTLY_REACHABLEを返す。wake後のfetch/ackにも認証とdeadlineを付ける。

## 7. 更新量

正常時のperiodic広告を減らし、変化時は局所triggered updateを送る。広告はfreshness・leaseを持つ。必須route安全タイマーを省略せず、その上で送信集約と乱数を使う。Trickleの安定時抑制思想を参考にするが、独立した異なるprotocolのタイマーを無造作に代用しない。

使用中リンクは実DATA結果から早く故障検出する。無通信リンクの物理撤去を常に500msで知るには監視コストが必要。検知起点と復旧時間を別に報告する。

## 8. 交換・予備・分断

新RelayのJoin成功だけでは引継ぎ完了としない。端末から新Relayを通じて必要Gatewayへの往復を確認する。予備の最初の相手が異なっても、その先に同じ故障点があれば独立予備ではない。独立性不明を明示する。

撤去予定は離脱時刻とroute withdrawalで伝え、graceful drainを行う。突然停止はfeasibleな代替を優先し、無ければbounded discovery。旧membershipを削除しない。

分断中も合法なローカル配送を続け、再結合時にfreshな広告で収束する。古い広告の遅延、異なるGateway側からの同一Message、失敗後の再ラウンド、dual parent依存を試験する。

## 9. 実装の完了条件

隣接のprimary/backupポインターを書き換えるだけを完成としない。全仕様の更新・撤回・再起動を状態遷移で示し、シミュレーション、property test、実10hopで検証する。製品用途名、階数、固定parentはCoreに入れない。


## 10. 更新と要求の意味を固定する

source keyはNetwork、destination、origin Identity、認証済みorigin generation。candidateとFDは別。FDは同sourceの候補全体で共有し、有限な広告を外へ出す**前**に更新する。新sequenceならその広告metric、同sequenceなら過去と新metricの小さい方。withdraw(infinity)ではFDをinfinityへ戻さない。

初期Babel由来profileの比較はRFC 8966 §3.2.1のuint16 serial arithmeticを使用する。差が32768なら順序不明で採用せず再同期。比較は隣接が広告したmetricとFDで行い、link costを足した値へ取り違えない。link costは有限時正、加算はinfinityへ飽和。infinityは撤回として受理できるがDATA経路として選択できない。

未失効のinfeasible candidateを保持し、全feasible喪失時にSeqNoRequestを出す。これは通常DATAのnext-hop選択とは別。認証・origin権限・TTL・request ID・重複抑止を確認し、必要時にinfeasible candidate経由で要求を運べる。転送者が一つの受信requestを複数相手へ分岐しない。要求元の再試行は別attemptとして候補を変えられる。hop/回数/期限を有限にし、DATA floodへ一般化しない。

三角形S–A=1、S–B=2、A–B=1で、AのFD=(137,1)のままS–Aが切れた場合、Bの(137,2)をDATA用に採用しない。要求はB経由でSへ進め、Sの正規(138,2)広告を得て復旧する。小モデルでこの採用判定を検査するが、全転送graphの証明ではない。

根拠：[RFC 8966 §3.5–3.8](https://www.rfc-editor.org/rfc/rfc8966.html)。

## 11. 再起動・GC・広告量の残るゲート

source/frontierを失った直後にFDをinfinityで新規化して古い広告を採用しない。当該sourceをROUTE_RECOVERY_REQUIREDにして有限広告とDATA選択を止める。再開方式（安全な永続frontier、またはRFCの寿命条件を満たす回復）、origin generation変更、sequence周回、GC timerをG-ROUTEで一貫して凍結する。この停止規則は安全側であり迅速な復旧が完成した証拠ではない。

portable profileでは以下を凍結した（`routing.hpp`/`node.cpp`の定数）。source keyは `(network, destination, origin generation)` で、ROUTE_UPDATEの各recordは destination(8)+generation(2)+sequence(2)+metric(2)の14byteを持つ。origin generationはnodeの永続化単調値で、bootごとに増加させる。自nodeより低いgenerationの広告は常に棄却し、高いgenerationはそのsourceのFD・候補・tombstoneを全て再初期化する。隣接nodeの自己recordでgenerationが上がった時、そのpeer経由の全候補をhold-down無しで破棄する（再起動relayの前世代stateを残さない）。

FDは最後の候補が消えてもtombstoneとして60秒（`kRouteTombstoneDwellMs`）保持し、GCはdwell経過後のみ行う。例外として、route table満杯時のdirect-neighbor admit（add_neighbor）は最も古いarm済みtombstoneを1件だけ早期reclaimしてよい（issue #50；学習routeの氾濫には適用しない）。撤回・隣接喪失したnext hopは500ms（`kRouteHoldDownMs`）hold-downする。triggered広告はneighbor喪失・selected route変更・sequence bumpで起動し、最小間隔1秒・最大64msの決定的jitterでburstを束ねる。1 frameのrecord上限は9で、selected routeの全dumpはper-neighborの回転cursorで複数更新へ分割する。

SeqNoRequestは宛先ごとにcooldown 2秒から線形に最大30秒までbackoffし、attemptが飽和した後も最大cooldownのbounded cadenceで再試行を続ける（打ち切り無し・attemptsは255で飽和）。同時in-flightは4件・state dwellは30秒・TTL上限10。これらはportable modelで検証済みの値であり、実機・RF上の成立証明ではない。

管理者不在での通常DATAを成立させるため、正常再起動の度に任意の新originをAuthorityへ発行させる方式を無条件に追加しない。origin sequenceを中継が勝手に増加させない。source keyを増やして古いsourceの安全履歴を逃れる実装は禁止。

pairwise controlのfan-out、active origins、entry長、周期、lease、request最大待ちを同時にcapacity manifestへ決める。token待ちでleaseを破る設定はprofile不成立。small実機での成立を100台へ外挿しない。route restart/GC・量子化単位・timerを未確定のままproduction routing capabilityを有効にしない。

sleep proxy／service originは別権限・lease・移管の規約が必要。初期は明示endpoint中心、未対応のsleep downlinkはNOT_CURRENTLY_REACHABLE。API境界は維持し、未設計のproxyを通常routeとして広告しない。

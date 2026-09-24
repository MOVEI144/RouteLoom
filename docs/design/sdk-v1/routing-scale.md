# 100台・1 gateway向けの経路スケール設計（issue #41）

状態：**portable coreに実装済み・host試験済み（SimWorld）**。実RF・実機・HILでの認定は未実施。Wire v2 headerは不変、予約済みROUTE_REQUEST（type 35）にpayloadを定義した。group key（broadcast暗号）は使わない。

対象コード：`components/routeloom/src/route_scale.cpp`（本profile）、`routing.hpp`（lease規則・定数）、`route_request.hpp`（payload codec）、`node.cpp`（配線・config検査）、`c_api.cpp`（C ABIの設定）、各firmwareの`main/Kconfig.projbuild`・`main.cpp`（Kconfig配線、§5.1）。試験：`tests/cpp/test_routing_scale.cpp`、C APIは`tests/cpp/test_main.cpp`の`test_c_api_route_profile`。関連：[経路仕様](../../spec/routing.md)、[無線§14](../../spec/radio.md)、[輻輳→経路結合](../sdk-completion/03-congestion-routing.md)、[Wire](../../spec/wire-protocol.md)。

## 1. 問題

製品前提は1 site＝1 gateway（USB接続ESP32＋PC）＋約100台の常時給電表示板（ESP32-S3）、LR 250kbps。通信の大半はboard↔gatewayで、在室変化はmesh時間0.1〜0.2秒でgatewayへ上げ、表示モード・文言はgatewayから下ろす。board間通信は稀だが任意の2台間で可能でなければならない。

従来（本書では**flat profile**と呼ぶ）は、全selected routeを全隣接へ周期広告する。Wire v2のrecordは16B、1 frameは自己record＋6経路の7件で、各隣接へ1周期に1 pageを回転cursorで送る。したがって各宛先の再広告間隔は`ceil(D/6)`周期で、lease（`route_lifetime_ms`）がそれを超えないと経路が期限切れ→再学習を繰り返す。1周期の余裕を見ると既定5s／15sが支えるのは**6宛先**、余裕なしでも12宛先で、100台（17 page＝85秒）とは桁が違う。leaseを延ばしても、100台×隣接8台に毎周期unicastする量は物理的に成立しない（§7）。100台SimWorldでflat profile（5s／15s）を4分間動かすと、route-control frameは203,414件（推定air time 8.2s/s＝§14包絡の82倍）、gatewayへの経路の途切れが373回、下りが276回観測された。

broadcast広告はnetwork group keyが要るが、production securityは別途設計中のため本設計では使わない。

## 2. 物差し：frame長と§14予算

air timeは`congestion.hpp`と同じ推定モデルで数える：`frame_us = (encoded_bytes + 96) × 32`（96は MAC header・LR preamble・MAC ACKのbyte換算、32µs/byteはLR 250kbps）。encoded＝header 88B＋payload＋link tag 16B。

| frame | payload | encoded | 推定air time |
|---|---:|---:|---:|
| ROUTE_UPDATE 自己のみ | 17B | 121B | 6,944µs |
| ROUTE_UPDATE 自己＋gateway | 33B | 137B | 7,456µs |
| ROUTE_UPDATE 7件（満杯page） | 113B | 217B | 10,016µs |
| ROUTE_REQUEST | 38B | 142B | 7,616µs |

予算は[radio.md §14](../../spec/radio.md)の管理送信包絡**ネットワーク延べ100,000µs/s**、100台の人数配賦で**1台平均1,000µs/s**（`kControlBudgetRefillUsPerS`）。

ここから設計の前提が一つ決まる。**100台の各nodeが5秒に1 frameでも出せば、それだけで100×6,944µs／5s＝139ms/sとなり包絡を超える。** これはunicastでもbroadcastでも同じである。したがって「周期5s」をリンクごとの再広告間隔にはできない。本設計では5sを**tick**（スケジューリング単位）とし、各木リンクの更新は`route_refresh_ticks`（既定6）tickに1回＝30秒とする（Babelの既定update間隔16秒・expiry 3.5倍と同じ桁）。

## 3. 採用設計：gateway-scoped profile

`NodeConfig::route_gateways`（最大4、`kMaxRouteGateways`。G-SEC P4でRLS1の一覧に合わせて2→4へ拡張）に1つ以上のgatewayを設定すると有効になる。site内の全nodeが同じ一覧を持ち、gateway自身も自分を載せる。未設定ならflat profileのまま（既存の挙動・試験は不変）。

各nodeにとって**親**＝gatewayへのcommitted next hop、**子**＝自分を親としている隣接。gateway木はBabelの経路選択そのもので、別のparent選択規則は持たない。

| record | 誰へ | いつ |
|---|---|---|
| 自己record＋各gatewayへの経路（gateway record） | 子（下り）、親（上り） | 各リンクの位相tickで1周期1回、変化時triggered |
| 部分木の経路（committed next hopが子である宛先） | 親のみ | 1周期で全pageを送る（1 tickあたり最大6 page） |
| 自己＋gateway record | 木以外の隣接1台（回転） | 4周期（120秒）に1回 |
| 要求された宛先のrecord | pull／SeqNoRequestを送ってきた隣接 | 要求時（poll()でまとめて、同一隣接へ500ms間隔） |
| board間の宛先 | on-demand探索の経路上 | Discover／Reply（§4） |

これにより、上り（board→gateway）は全nodeが常時proactiveに経路を持つので即送信でき、下り（gateway→board）はgatewayが全boardの経路を部分木の上りpageで常時持つ。board間はgatewayを根とする木を上って共通祖先から下る要求で経路を作る。

### 3.1 子の推定（wire flagなし）

poison reverse（next hopへ広告するときは無限大）は既存規則である。子は親へのgateway recordを必ず無限大にするので、受信側は「隣接Nからgateway recordが無限大で届いた」ことをNが子である証拠とする（`child_until_ms = now + lease`）。有限で届けば子ではない。gatewayを失った隣接も無限大を送るが、それを子として扱う（下りrefreshを受け取れる）のはむしろ望ましい。この推定はscheduling状態だけに使い、経路表の入力にはしない。

### 3.2 周期（tick）

- 最初のtickはnode IDから決まるoffset（0〜5s）で始め、同時起動したsiteが同じ瞬間に更新しないようにする。
- リンクごとの位相`hash(self, neighbor) mod ticks`で、各nodeの木リンクを異なるtickに散らす。
- 親への上り周期は、その位相tickで部分木の先頭から始め、1 tickあたり最大6 page（`kScopedMaxUpFramesPerTick`）を送って続きは次tickへ回す。表が最大128件でも26 pageなので、1周期6 tick内に必ず一巡する。
- 親が変わったときは位相を待たずに部分木全体を新しい親へ送る。
- 子への下りframe（自己＋gateway record）は子ごとに1周期1回。
- 木以外の隣接には4周期に1回、1台ずつ自己＋gateway recordを送る。予備候補とより良い親の発見に使う（より良い親は既存のtopology-fresh改善規則で即採用される）。

### 3.3 triggered更新

flat profileのtriggeredは全隣接への全dumpだった（issue #41の「32近隣×9.25msを一斉放出」）。本profileでは木リンクだけに絞る。

- gatewayへの経路が変わった（next hop・sequence・metric・有効性）→ 子とinterestのある隣接へ自己＋gateway record。
- 部分木の経路が変わった → 変化した宛先だけを**dirty集合**（16件、溢れたら全page＋撤回sweep）に積み、親へ送る。
- **部分木からの離脱**：親へ有限recordを出した宛先（`announced_up`）が部分木でなくなったら（子が別の親へ移った、経路を失った）、親へ無限大で撤回する。まだ使える経路の撤回も合法である（無限大は候補を消すだけ）。これをしないと、祖先に残った古い写しが1 lease後に下から順に失効し、途中nodeが経路を持たない「穴」が上へ移動する（試験で観測した）。
- **新しい子**：子になった隣接とそれ経由の宛先を全てdirtyにして親へ上げ、子へは直ちに自己＋gateway recordを返す。戻ってきた子の経路は自分のselectionを変えないため、scanだけでは上がらない。
- **旧親への通知は3秒遅らせる**（`kScopedReleaseDelayMs`）。旧親はこの通知で部分木を撤回するので、新しい親経由の経路が先に共通祖先へ届く時間を与える。
- 汎用trigger（隣接喪失・自己sequence更新・再起動・relay-off）は親と子とinterest隣接の全てへ送る。最小間隔1秒・jitter 64msは従来通り。

### 3.4 pullとinterest（1hop ROUTE_REQUEST）

gatewayへの経路が無い（またはadd_neighborが置いたgeneration 0の仮経路しかない）nodeは、全隣接へROUTE_REQUEST Neighbor（target＝gateway）を送る。backoffは1、2、4…最大32秒。受信側は要求元に**interest**（2 tick＝10秒）を付け、経路を持っていればpoll()で直ちに答え（自己＋gateway＋target record）、まだ無ければ得た時点のtriggeredで押し出す。これが起動時の木形成と、親を失ったときの修復の経路である。

SeqNoRequestも同じ仕組みに乗せる：中継nodeは要求元隣接にinterestを付け、自表のsequenceで答えられる場合は汎用triggerではなく、その宛先のrecordを要求元へ直接返す（汎用triggerは自己＋gateway recordしか運ばないため）。

### 3.5 generation 0の仮経路は広告しない

`add_neighbor()`は隣接への直結経路をgeneration 0で仮置きし、隣接の自己recordで本来のgenerationへ上がる。flat profileでは毎周期全隣接が自己recordを送るのですぐ上がるが、本profileでは木以外の隣接は自己recordをほとんど送らない。generation 0の経路を広告すると、本来のgenerationが届いた瞬間に網全体の当該source状態（候補・FD）がリセットされる（試験で、gatewayの直近隣がgeneration 0の経路を広げ、最初のgateway tickで全100台が一斉に再学習した）。そこで本profileはgeneration 0のselectionを広告しない（転送には使う）。gateway隣接の仮経路はpullの対象にする。

## 4. board間：on-demand探索（Discover／Reply）

送信・receipt・routed送信が`NO_ROUTE`になり、宛先がgatewayでなければ探索を始める（宛先ごとの状態4件、`kDiscoveryCapacity`）。deliveryは既存の`WaitingForRoute`で100msごとに再試行するので、経路ができれば同じMessage IDで送られる。

1. 要求元Aは親へDiscover（ttl 10、record＝A自身の自己record）を送る。
2. 中継Xは`(requester, request_id, kind)`で重複を落とし、前hopを逆経路ポインターとして5秒保持する。recordを通常広告として`consider()`し（Aへの逆経路）、宛先Cへの経路があればそのnext hopへ、無ければ親へ転送する（送り元へは戻さない）。転送するrecordは**X自身の**Aへのselection（FDを更新してから出す。無ければ無限大）。
3. Cは自己recordを載せたReplyを前hopへ返す。各中継は前hopのポインターで逆経路を戻り、受け取ったCのrecordを`consider()`し、自分のCへのselectionを載せ替えて転送する。selectionが無い（infeasible）なら転送しない（SeqNoRequestが走り、要求元の再試行で回復する）。
4. Aに経路ができると探索状態は閉じる（`discoveries_resolved`）。Cも要求の通過でAへの経路を持つのでEND_RECEIPTが返る。

上限：TTL 10（無線hop上限、木の上り＋下りの合計なのでgateway側の深さが大きい2台間は届かない）、転送は1 nodeあたり1秒8件、要求元の再送は2秒×試行回数（最大30秒）、状態は最後の必要から30秒で破棄、dedup 32件。floodはしない（1受信要求は1方向へだけ転送）。gateway自身は親が無いので探索しない（全boardの経路を上りpageで持っている）。探索で得た経路は通常の候補なので、使われなければ1 lease（90秒）で失効するcacheになる。

## 5. lease規則と強制

リンクごとの更新は位相tickで`ticks`周期に1回、上り全pageはその周期内に収まるので、表の大きさはleaseに現れない（airtimeに現れる、§7）。1回の更新がまるごと失われ、次が最大1 tick遅れても失効しないように：

`route_lifetime_ms ≥ (2 × route_refresh_ticks + 2) × route_advertisement_period_ms`

製品値は5s／6 ticks／**90s**（必要最小70s）。`validate_config()`は本profileでこれを満たさない設定を`ROUTE_LIFETIME_BELOW_REFRESH_BOUND`で起動拒否する（診断ではなく拒否。新しいprofileなので既存既定値を壊さない）。`routing.hpp`の`static_assert`が製品値を、`tools/check_review_contracts.py`が`radio-defaults.json`の`routing.gateway_scoped`とC++定数の一致・規則・§14見積りを検査する。

flat profileの規則は`lifetime > (ceil(D/6) + 1) × period`（`flat_lifetime_sufficient`）で、起動時診断`ROUTE_REFRESH_BOUND_EXCEEDED`（表容量128件で評価）はこの式に直した。

**tombstoneはleaseより長く**：FDのtombstone保持は`max(60s, lease)`にした（`RouteTable::set_tombstone_dwell`）。leaseを60秒より長くすると、隣接にまだ残っている古い広告が、GC済みで初期化されたFDを通過できてしまう（RFC 8966 §3.7.3の条件）。単体試験で60秒dwell＋90秒leaseのときに古いsequenceが採用されることを示し、修正後はinfeasibleになる。

### 5.1 設定の入口

| 入口 | gateway | tick／lease | 検査 |
|---|---|---|---|
| C++ `NodeConfig` | `route_gateways`（最大4、`kInvalidNodeId`は空き枠。1つでも設定でscoped） | `route_advertisement_period_ms`／`route_lifetime_ms`、`route_refresh_ticks`（既定6） | `start()`の`validate_config()`がlease規則違反を`InvalidArgument`（`ROUTE_LIFETIME_BELOW_REFRESH_BOUND`）で拒否 |
| C API `rl_node_config_t` | `route_gateway_count`（0＝flat、既定）＋`route_gateways[RL_MAX_ROUTE_GATEWAYS]`（優先順） | 既存の`route_advertisement_period_ms`／`route_lifetime_ms`、`route_refresh_ticks`（0＝SDK既定6） | `rl_init`が個数超過・count内の0・重複を`RL_STATUS_INVALID_ARGUMENT`で拒否（count以降の要素は無視）。旧2-gateway header（`RL_NODE_CONFIG_SIZE_GATEWAY2`）の呼出しは上限2のまま受付け、count 3以上は切捨てず拒否。lease規則違反とbroadcast IDは`rl_start`が`RL_STATUS_INVALID_ARGUMENT`で拒否 |
| firmware Kconfig（reference_node／bridge_node／examples/espnow_node） | `ROUTELOOM_ROUTE_GATEWAY_SCOPED`（既定n）、`ROUTELOOM_ROUTE_GATEWAY_1`（既定0x1）、`ROUTELOOM_ROUTE_GATEWAY_2`（0＝なし）。bridge_nodeはgatewayなので自分の`ROUTELOOM_NODE_ID`を先頭に載せ、`_2`だけを持つ | `ROUTELOOM_ROUTE_PERIOD_MS`（既定5000）／`ROUTELOOM_ROUTE_LIFETIME_MS`（既定90000）。scoped時だけ現れ、flat buildはSDK既定（5s／15s）に触れない | gateway 0・重複・lease規則違反を`static_assert`でbuild失敗にする（起動時拒否より前に止める） |

`rl_node_config_init()`はflat既定（5s／15s、gatewayなし）のままなので、C callerがscopedにするときは5s／90sを明示する（15sのままでは`rl_start`が拒否する）。実効gateway一覧は`rl_route_gateways()`で読める（0件＝flat）。

**C ABIの拡張方針**：新fieldは`rl_node_config_t`の**末尾**に足し、`RL_ABI_VERSION`は2のまま据え置いた。`rl_init`は`struct_size`が構造体全体以上なら新fieldを読み、拡張前の大きさ（`RL_NODE_CONFIG_SIZE_BASE`＝64B）なら末尾を一切読まずflat profileとする。その間の大きさは拒否する。`reserved[3]`の転用を採らなかったのは、gateway ID（u64×2）が3Bに入らないことと、`rl_init`がreservedの0を検査してこなかったため旧callerのreservedを意味ある値として読めないことによる。ABI versionを上げると`abi_version`の完全一致検査で既存callerが全て拒否されるので上げない。`rl_node_config_init()`は新しい全体を書くので、旧header（64B）でbuildしたbinaryがこのlibraryの`rl_node_config_init()`を呼ぶ組合せは不可（pre-1.0は同じsource dropからbuildする前提、[compatibility §4](../../spec/compatibility.md)）。

## 6. 資源（動的確保なし）

| 状態 | 上限 |
|---|---|
| 経路表 | 従来の128件（gatewayは99 board＋tombstoneで収まる） |
| Neighborごとの追加 | child/interest期限、pull応答状態（約40B×32） |
| dirty集合 | 16件（溢れたら全page＋撤回sweepへ縮退） |
| 上り周期 | gatewayごとに1（parent、cursor） |
| 探索状態 | 4件 |
| ROUTE_REQUEST dedup／逆経路ポインター | 32件、5秒 |
| RouteTable entry | `announced_up` 1bit相当（scheduling専用） |

## 7. air time見積り（D＝100）

木の維持に必要な最小量は、木の各リンクにつき1周期に上り1 frame（部分木が5件を超えればpage数）と下り1 frame。1周期あたり`Σ(上りpage) + Σ(子の数) + N/4（回転）` frameで、上りpageの総数は深さの総和/5程度になる。10×10格子・8近傍・gatewayを外壁中央に置いた場合（深さ最大9）：

| 条件 | ネットワーク | 1台平均 | 葉board | 最大（gateway隣接hub） |
|---|---:|---:|---:|---:|
| 式による見積り（6 ticks＝30s） | 72ms/s | 723µs/s | 311µs/s | 5.1ms/s |
| SimWorld実測（4分間、定常） | 77.6ms/s | 776µs/s | 311µs/s | 6.4ms/s |
| 格子中央gateway（実測） | 63.5ms/s | 635µs/s | 311µs/s | 2.7ms/s |
| 参考：同じ木を5秒ごとに更新（式） | 約430ms/s | 約4.3ms/s | 1.9ms/s | 約30ms/s |
| 参考：flat 5s／15s（実測） | 8.2s/s | 82ms/s | — | — |

葉boardは親への1 frameと回転分だけなので1台の配賦（1,000µs/s）の約3割に収まる。部分木のpageを中継するhub（gateway隣接）は配賦の数倍になるが、ネットワーク延べは包絡内で、hubの上限はチャンネルの1％未満。これは「人数込みの配賦」（radio.md §9）として、配賦をリンク・部分木の担い手へ寄せたものと読む。試験は延べ≤100,000µs/s、平均≤1,000µs/s、全ての葉≤1,000µs/s、最大≤10,000µs/sを検査する。

起動時（全100台同時電源投入）はpullと木形成で約1,880 frame（推定14秒分のair time）を使う。simは衝突を模擬しないので実時間ではもっと長く広がる。§11の残課題とする。

## 8. loop-freedom

Babelの採用可能条件の証明は、どの広告が届いたか・失われたか・遅れたかに依存しない。依存するのは(1)各nodeが有限のrecordを送る**前に**自分のFDを更新する、(2)受信側がFDと比べて採用し、選択時にも現在のFDで再確認する、(3)FDは同sequenceで単調に締まりsequenceは単調に進む、の3点で、これによりselected next hopの鎖に沿って(sequence, FD)が辞書順で厳密に改善し、循環できない。本profileはこの3点を変えない：

- 出力するrecordは全て`mark_advertised()`を通る（`scoped_record`、上りpage、変化record、Discover／Replyのrecord）。無限大（poison・撤回）はFDに触れず、候補を消すことしかできない。
- 入力は全て`RouteTable::consider()`を通る（ROUTE_UPDATEとROUTE_REQUESTのrecord）。
- 追加した状態（child／interest／dirty／`announced_up`／探索・dedup）はschedulingだけに使い、`select()`・`feasible()`は読まない。したがって「誰に何を送るか」の制限は広告の喪失と区別できない。
- generation・sequence比較・hold-down・tombstone・SeqNoRequestは既存のまま。generation 0の仮経路は広告しない（§3.5）。tombstoneはleaseより長く保つ（§5）ので、GCによるFDの早すぎる初期化も起きない。
- ROUTE_REQUESTの転送自体はcontrolの転送で、TTL≤10と`(requester, request_id, kind)`の一回転送で有界。逆経路ポインターはReplyの返送にだけ使い、DATAは常に経路表のselectionで転送する。

試験では100台の定常4分間、毎秒全boardについてgateway往復のnext hop鎖を辿り循環0、5×5格子でリンクを40回flapさせながら100msごとに全鎖を検査して循環0、DATAの二重転送・分岐0を確認した。

## 9. Wire

Wire v2 header（88B）は不変。ROUTE_UPDATEのpayload形式も不変。予約済みのROUTE_REQUEST（type 35）にだけ38Bのpayloadを定義した（kind、ttl、requester、target、request_id、ROUTE_UPDATEと同形式のrecord）。詳細は[wire-protocol.md](../../spec/wire-protocol.md)、機械可読な定義は`protocol/semantics.json`の`route_request_payload`、golden vectorは`protocol/golden/valid/route_request.json`（Rust generatorで生成し、C++ encoderのpayloadと一致することを試験）。hostはROUTE_REQUESTを解釈しないのでRust codecは追加していない。flat profileのnodeはROUTE_REQUESTを診断`ROUTE_REQUEST_UNSUPPORTED`で無視する。

## 10. 試験

`routeloom_routing_scale_unit_tests`（約3秒）：payload codecとgolden一致・不正値拒否、lease規則とconfig強制、tombstoneとleaseの関係、`lost_route`と前回selection、4台lineの木形成と周期（葉1 frame／周期、relay 2 frame／周期）、親喪失からの修復と下りの追従、より良い親への切替（旧親は3秒後の通知で撤回し、gatewayの下り鎖は一度も切れない。通知を止める変異ではこの試験が失敗することを確認）、2分岐間の探索と逆方向送信・探索経路のcache失効、flat nodeの無視、5×5格子のchurn中loop検査。

`routeloom_routing_scale_100_node_tests`（Debugで約6〜10秒）：10×10格子（8近傍、342リンク）、5s tick／90s lease。9秒で収束後、240秒間50msごとに全boardのgateway経路とgatewayの全board経路の有効性（途切れ0）、毎秒鎖の到達と循環0、最大深さ≤10、air timeの4条件を検査。続いて10台の同時上り報告が全てgatewayへ届くまでmesh時間200ms以内（実測50ms）、gatewayから6台への下り配送、負荷後の到達回復が5秒以内、無作為なboard間3組が探索経由で配送されることを検査する。既存のrouting試験（10hop、分断再結合、loop-freedom、diamond修復）は変更なしで通る。

## 11. 限界・リスク・今後

- **負荷によるparent切替の一時的な下り断**：等距離の親が2つあるboardは、負荷連動のlink cost（公称metric 1では作業/受理比1.25で2倍に量子化）で親を替えうる。下りは新しい親経由の上りtriggeredと旧親の撤回の競争になり、100台試験では約0.2秒、最悪数秒gatewayから当該部分木へ届かない。DATAのE2E再送で吸収する前提。公称metricを大きく（細かく）するのが望ましい。
- **親の沈黙故障**：親の電源断はDATA失敗（即時）かlease（90秒）でしか分からない。上り送信があればDATA失敗→pull→数秒で修復するが、送信の無いboardへの下りは最長1 lease届かない。flat profileより遅い。
- **起動時の嵐**：全台同時起動でpullが約1,900 frameになる。起動jitterや、隣接の広告を一定時間待ってからpullする等の緩和が必要（未実装）。
- **gatewayの深さとboard間**：木を経由するので、別の枝の深いboard同士は10hopを超えて届かない。
- **複数gateway**：2つまで設定できるが、上りは各親へ同じ部分木を送る単純な方式で、試験は1 gatewayが中心。
- **hostへの報告なし**：C API（§5.1）とfirmware Kconfigからは設定できるが、USB HostOps（HelloAck・node_status_v1）はrouting profileとgateway一覧を運ばない。golden固定のUSB wire形式への追加が要るので別作業とする。firmwareのgateway一覧はbuild時固定で、remote config（RCC1）からは変えられない。
- **実RF未検証**：air timeは推定モデル、simは衝突・損失を模擬しない。§14の実測・capacity manifestはG-ROUTEに残る。

**group keyでbroadcast広告が使えるようになった場合**：定常の木維持量はほぼ変わらない（木の平均子数は1なので、子へのunicastをbroadcast 1回に替えても件数は同程度。上りpageは親だけが必要）。変わるのは、(1)全隣接が毎周期gateway metricを聞くので予備候補が常に温まり、親喪失の修復がpull無しで即時になる、(2)pullが隣接数分のunicastから1 broadcastになり起動時の嵐が数分の1になる、(3)木以外への回転送信が不要になる、の3点である。それでも「5秒ごとに全nodeが1 frame」は100台で139ms/sなので、tick×周期の構造と本書のlease規則は残る。

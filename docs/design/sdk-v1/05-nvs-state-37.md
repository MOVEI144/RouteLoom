# 05 — NVS状態の上限とIssue #37

## 1. 現状（Wire v2 commit時点の事実）

[Issue #37](https://github.com/MOVEI144/RouteLoom/issues/37)：ピアごとに作られる永続キーに削除経路が無い。

| キー | 内容 | 作られる契機 | 1件のNVS entry（概算） |
|---|---|---|---|
| `c%08lx`（`rlcounter`） | TX counter lease（`CounterRecord` 32B、layout 2） | 新しい(scope, 宛先)への初送信（[psk_security.cpp](../../../components/routeloom_espnow/src/psk_security.cpp)） | 3 |
| `f%08lx`（`rlreplay`） | replay floor（24B） | AEAD検証に成功した新しい(scope, 送信元) | 3 |
| `r%08lx`（`rlreplay`） | replay window（40B） | 同上 | 4 |

entry数はNVS v2のblob（index 1＋data header 1＋32B単位のdata）で概算。1ピアあたりLink＋EndToEndで最大約20 entry。既定`CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE`のNVSは24KiB＝6 page、GC用に1 page空けると約630 entry。静的消費（sleep image、config journal、`rlplan`、`rlmauth`、PHY較正等）は250〜390 entryと報告されており、**累計12〜38ピアで満杯**になる。満杯時はfail-closedにより新規ピアとの通信不能→既存キー更新も失敗→`rlboot`書込み失敗で起動不能（[crash-time-resources](../../spec/crash-time-resources.md)の既知制約表）。

## 2. 削除してよい条件

依頼の条件をそのまま設計の不変条件にする。

- **C1**：counter recordを消してよいのは、次の接触が新しい鍵（または新しいepoch）を使うことが保証される場合だけ。消した範囲で同じ鍵・同じcounterを再使用すればAES-GCMのnonce再使用になる。
- **C2**：replay floorを消してよいのは、再接触に双方のnonceを含む新しい認証handshakeが必須の場合だけ。floorを失えば、同じ鍵で保護された過去のframeを受理し得る。

## 3. 本番profile：ピアごとのcounter/replay recordを作らない

### 3.1 構造

[03](03-key-hierarchy.md)の設計では、link／E2Eの鍵はEDHOC（双方のephemeral DH）またはRLRES1（`salt = nonce_I || nonce_R`）で**接触ごとに新しく**作られ、RAMにだけ存在する。

| 旧来の永続状態 | 本番での代替 | C1/C2 |
|---|---|---|
| TX counter lease（`c*`） | 鍵ごとのRAM counter、0から | 鍵がhandshakeごとに新しいので、再起動・追い出し後の再使用は起こらない（C1） |
| replay floor（`f*`） | 不要 | 受信側は自分がこの起動中に参加したhandshakeの鍵しか持たない。旧contextのframeは復号できない。RLRES1はR3（相手の新nonceに対する鍵確認）まで確定しないので、捕獲したR1の再送でcontextは作れない（C2） |
| replay window（`r*`） | RAMのwindow | 同上。window消失＝鍵消失なので、同じ鍵で旧frameを受ける状態が生じない |

したがって本番profileは`rlcounter`/`rlreplay`にピアごとのキーを**一つも作らない**。前提は二つ：乱数がREADY（[セキュリティ §9](../../spec/security.md)）であること、永続化した鍵からcontextを復元しないこと（例外はsleep端末のRTC保持で、counterが同じRTC blockに入っているため巻き戻りは起きない、03 §5.4）。

### 3.2 再開cache（固定slot、LRU）

現行の再開cacheはRLP2（96B slot、`rlres2`、purpose quota 12+4 node／32+128 gateway、64-use ceiling）で、lifecycleのsweep対象もRLP2のみ。以下に記すRLP1（84B）はpre-P4のfrozen形式（codecとgoldenがpinするのみで、cache・sweep・NVS配線は撤去済み）。既存機の`rlres`は、live storeのnamespaceを開く前に読み取り専用で存在を調べ、旧blobがあれば消去する。消去に失敗した場合は警告し、旧blobをRLP2として使わない。§5.1は消去成功後の定常予算であり、失敗時には旧entryが残る。

永続するピアごとの状態は再開主秘密RMSだけ。**slot数を固定し、NVSキー名も固定**（`s00`〜`s15`、gatewayは`s000`〜`s159`）にして、キーの数が増えない構造にする。

```text
RLP1 slot（84B）:
 0 u32 magic "RLP1" | 4 u8 format=1 | 5 u8 purpose (1 link, 2 end) | 6 u8 state (0 empty, 1 valid) | 7 u8 flags (bit0 pinned)
 8 u64 peer node_id | 16 u64 network
24 8B  peer_cert_id = first8(SHA-256(peer MemberCert))
32 u32 peer_generation | 36 u32 created_gk_epoch
40 u32 last_used_boot  | 44 u32 reserved
48 32B rms
80 u32 crc32
```

空slot（`state=0`）は`purpose`以降の全fieldが0（RMSを消去済み）。未書込み・CRC不一致のslotも空として扱う。sealは持たない（1 slotの書込みが途中で切れてもCRCで空になり、帰結はfull EDHOCだけ）。旧P1-3の`ResumeCache`はslot内容をRAMに持たず毎回storageを走査していた。現行のRLP2も固定長bufferで走査し、slot数に応じてRAMを増やさない。

| 規則 | 内容 |
|---|---|
| 書く時 | full EDHOC完了時だけ（新RMS）。再開（RLRES1）では書かない |
| 最近使用の記録 | `last_used_boot`は、前回値からboot sessionが256以上進んだ時、またはgk_epochが変わった時だけ更新（sleep端末の起動ごと書込みを避ける） |
| 無効化（空きとして扱う） | `created_gk_epoch + 2 ≤ 現gk_epoch`、networkがRLS1と不一致、peerがRRS1で失効、CRC不一致 |
| 追い出し | 空き・無効slotを優先、次にpinned以外で`last_used_boot`最小。pinnedは`slots − 2`件まで（新規が常に入れる） |
| pin | 親・regular pin（[discovery](../../../components/routeloom/include/routeloom/discovery.hpp)の`pin_peer`、≤12）の相手 |
| 失効・削除 | RRS1受理時・REMOVED時に該当slotを`state=0`で上書き |

**追い出しの安全性**：追い出しで失うのは「次の接触をRLRES1で安く済ませる能力」だけ。次の接触はfull EDHOCになり、新しいephemeral DHから新しい鍵が作られるのでC1/C2を満たす。counter・floorのような「消すと安全性が下がる状態」は持っていない。

### 3.3 単調性の証人（witness）

鍵の新しさを保存状態に依存させない代わりに、次の二つだけは単調でなければならない。

| 証人 | 守るもの | 失われた時 |
|---|---|---|
| `rlboot`（u32、既存） | group送信者鍵（`tx_boot`）、route generation | system NVSを先に+1し、RLS1の`boot_witness`採用後に候補がwitness以下なら`witness + 2^20`へ修復・読戻ししてから公開する。overflow、読出し不明、site不確定は使用停止。過去最大bootの完全な耐rollback証明ではなく、長期停止中の物理flash rollbackは対象外 |
| 開発profileの`cmax`（§4.2） | 掃除したTX counterのepoch上限 | 起動時に`session ≤ cmax`なら開始しない（fail closed） |

`rlboot`は既定`nvs`に残し、ピアごとの状態とは別partitionにする（§5）。これで「ピア状態が満杯→boot session書込み失敗→起動不能」の連鎖を断つ。

## 4. 開発PSK profileの暫定策（本番engineへの移行まで）

開発profileはhandshake由来の鍵を持たず、鍵が`(PSK, scope, network, sender, receiver, epoch)`だけで決まる。したがってfloor・windowの削除はC2を満たさず**安全ではない**。以下は安全な範囲の緩和であり、根本解決ではない。

| 策 | 内容 | 安全性 |
|---|---|---|
| D2-a 起動の分離 | `rlcounter`/`rlreplay`を`rlsec` partitionへ移す（`nvs_open_from_partition`）。`rlboot`は既定`nvs`。`rlsec`が満杯でも起動は継続し、新規ピアだけ失敗 | 起動不能を防ぐ |
| D2-b 死んだcounterの掃除 | 起動時、`key_epoch < 現在のepoch`の`c*`を削除。先に`cmax`（削除したrecordの最大epoch）をcommitし、その後にerase | TX鍵は自分のepoch（boot session、単調）に束縛されるため、過去epochの鍵は二度と使われない（C1）。`cmax`が、消えたrecordの「古いepochを拒否する」役割を引き継ぐ |
| D2-c 永続ピア数の上限 | `rlsec`容量から`max_persisted_peers`（64KiBで64ピア）を決め、超える新規ピアのfloor/window作成を拒否（`PEER_STATE_CAPACITY`診断・counter） | fail closed。NVS枯渇より前に明示的に止まる |
| D2-d floor/windowは消さない | 削除経路を作らない | C2を満たせないため |
| D2-e 運用での回復 | 開発network id／PSK domainを全台で切り替え、保守verbで`rlreplay`/`rlcounter`名前空間を明示消去 | 新しい鍵空間になるため旧recordは無意味（明示操作であり自動eraseではない） |

D2-bで1ピアあたり約6 entry（両scopeの`c*`）が回収され、約14 entry/ピアが残る。churnの多い現場ではD2-cの上限に達し得る。**根本解決はD1**：開発Providerも本番と同じRAM context engineへ移し、RLRES1のRMSに開発PSKを使う（EXPERIMENTAL表示は維持）。移行後、旧名前空間は保守verbで一度だけ消去する（[08](08-implementation-plan.md) P4-3）。

## 5. NVS entry予算とpartition推奨

### 5.1 名前空間ごとの予算（概算entry）

| 名前空間 | 内容 | 通常機器 | gateway | partition |
|---|---|---|---|---|
| IDF／PHY／Wi-Fi | ESP-IDF | 既定分 | 既定分 | `nvs` |
| `rlboot` | boot session | 1 | 1 | `nvs` |
| `rlcfg`/`rlcfgv`/`rlplan`/`rlmauth`/sleep image | 既存（最大時） | 250〜390（報告値） | 同左 | `nvs` |
| `rlident` | RLI1 2 slot（≤664B） | 46 | 46 | `rlsec` |
| `rlsite` | RLS1 2 slot（≤708B） | 50 | 50 | `rlsec` |
| `rltrust` | RLT1 2 slot（≤1684B） | 110 | 110 | `rlsec` |
| `rlrevo` | RRS1 2 slot（≤640B） | 44 | 44 | `rlsec` |
| `rlmaint` | RLX1 2 slot（≤2048B、PR Bの削除journal） | 最大132＋namespace | 同左 | `rlsec` |
| `rlres2` | 再開cache RLP2（96B＝5 entry/slot） | 16 slot＝80 | 160 slot＝800 | `rlsec` |
| 証人 | `cmax`等 | 2 | 2 | `rlsec` |
| **本番小計（rlsec）** | | **約464** | **約1184** | |
| 開発legacy（D2-c上限） | `c*`/`f*`/`r*` | 64ピア×14〜20＝最大1280 | 128ピア×20＝最大2560 | `rlsec` |

### 5.2 partition推奨

| 機器 | `nvs`（既定） | `rlsec` | 使えるentry（1 page GC予約後） |
|---|---|---|---|
| 通常機器（C3/S3） | 24KiB | **64KiB**（16 page） | 15×126＝1890 |
| gateway（S3推奨） | 24KiB | **128KiB**（32 page） | 31×126＝3906 |

4MB flash（XIAO C3）の例（OTAなし）：

```text
# Name,   Type, SubType, Offset,   Size
nvs,      data, nvs,     0x9000,   0x6000
phy_init, data, phy,     0xf000,   0x1000
factory,  app,  factory, 0x10000,  0x180000
rlsec,    data, nvs,     0x190000, 0x10000
```

将来OTA（ota_0/ota_1 各1.5MB）を入れても `0x10000 + 2×0x180000 = 0x310000` の後に`rlsec` 64KiBを置けば4MB内に収まる。tier T2ではNVS暗号化（`nvs_keys` partition）を`rlsec`に適用する（eFuse操作はSDKが黙って行わない）。partition tableの変更は既存機器のNVS配置を変えるため、書換え時は保守手順（[07](07-host-api-tooling.md) §6）で行う。

### 5.3 CIでの予算検査

各記録codecの最大長から上表を計算するPython model（`tools/`）を追加し、名前空間ごとの上限の合計が`rlsec`の使えるentryの80%以下であることをCIで検査する（[08](08-implementation-plan.md) P0-1）。実機では`nvs_get_stats()`の使用entryを診断に出す。

## 6. 書込み頻度（摩耗）

| 事象 | 本番profileの書込み | 旧来（開発） |
|---|---|---|
| 起動 | `rlboot` 1 | `rlboot` 1＋floor更新 最大ピア数 |
| 受信frame | **0** | window 1 commit/frame（[04 provisioning §4.9](../sdk-completion/04-provisioning-lifecycle.md)で最大の摩耗要因とされたもの） |
| 送信frame | 0 | 256送信ごとにlease 1 |
| 新しい近隣（full EDHOC） | 再開slot 1 | c/f/rの新規作成 |
| 再開（RLRES1） | 0（まれに`last_used_boot`） | — |
| GK更新（24時間） | RLS1 stage 2 write＋activation twin 4 write＝計6 write（readbackを含まず） | — |
| GK staged差替え | RLS1 twin 4 write（旧next鍵を両slotから消去） | — |
| 削除 | RRS1 1 commit×2 slot | — |

受信ごとの永続化が無くなるため、本番profileの摩耗は起動回数とGK更新でほぼ決まる。

## 7. 失敗の扱い

| 事象 | 動作 |
|---|---|
| `rlsec`満杯（本番） | 再開slotは固定数なので起きない想定。RLS1/RRS1の更新失敗は既存の二重slot規則（旧imageを維持、uncertainならcommit拒否） |
| `rlsec`満杯（開発） | 新規ピアを`PEER_STATE_CAPACITY`で拒否。起動は継続 |
| 再開slotのCRC不一致 | 空きとして扱い、full EDHOC |
| `rlboot`の欠落・後退 | §3.3 |
| 旧layout（v1）の記録 | 既存どおり`IntegrityError`（fail closed）。推測で変換しない |

## 8. 受入試験（planned_not_run、P0分の状況は§9.5）

| ID | 内容 |
|---|---|
| V1-N01 | 本番profileで200ピアと順に通信しても`rlcounter`/`rlreplay`のキーが0件、`rlres2`は固定件数 |
| V1-N02 | 再開slot追い出し後の再接触はfull EDHOCになり、捕獲した旧frame・旧R1は拒否 |
| V1-N03 | `rlsec`を満杯にしても起動し、`rlboot`が進む（開発・本番） |
| V1-N04 | D2-b：過去epochの`c*`掃除後、`cmax`以下のboot sessionでは開始しない |
| V1-N05 | D2-c：上限超過ピアを拒否し診断を出す。既存ピアの通信は継続 |
| V1-N06 | `rlboot`欠落・後退・耐久化不明を注入：GroupEnd/GroupLink送信は0、推測したbootへの飛越しでは解除しない |
| V1-N07 | 予算model（Python）とcodec最大長の一致、partition容量の80%以下 |
| V1-N08 | HIL：C3で`nvs_get_stats()`の実測値が予算表と矛盾しない |

## 9. P0の実装状況（開発PSK profile、host試験済み・実機未試験）

[08](08-implementation-plan.md)のP0-1／P0-2を実装した。protocol・Wire v2 byte列は変えていない。削除規則は§2のC1/C2に従い、安全に示せない削除は実装していない。

### 9.1 実装したもの

| 策 | 実装 | 場所 |
|---|---|---|
| D2-a 起動の分離 | reference_node・examples/espnow_nodeは`rlsec` 64KiB、bridge_node（gateway）は128KiBを`partitions.csv`で確保（`nvs` 24KiB、factory 1.5MiB、表の終端0x1A0000／0x1B0000でESP-IDF既定の2MB設定にも4MB機にも収まる）。`rlcounter`/`rlreplay`は`nvs_open_from_partition("rlsec", …)`。起動順は「既定`nvs`初期化→`rlboot`前進→`nvs_flash_init_partition("rlsec")`→Provider」で、`rlsec`の状態が`rlboot`の書込みを妨げない。sleep imageはsystem状態として既定`nvs`の`rlsleep`へ移した | [partitions.csv](../../../firmware/reference_node/partitions.csv)、[nvs_counter_store](../../../components/routeloom_espnow/src/nvs_counter_store.cpp)、各firmwareの`main.cpp` |
| D2-b 死んだcounterの掃除 | Provider初期化時に`key_epoch < tx_epoch`（`tx_epoch`＝boot session）のTX recordを掃除する。1 passで最大16件を集め、その最大epochを証人`cmax`（u32）として**先に**commitし、成功後にだけ消去する。証人は単調（下げない）。破損・旧layout・大きさ不一致のrecordはepochが信用できないので消さない（そのslotはIntegrityErrorのまま）。`tx_epoch`より新しいrecordは`rlboot`後退の証拠として残し、ログに出す | [peer_state](../../../components/routeloom/src/peer_state.cpp)の`BoundedCounterStore` |
| 証人の執行 | 起動時に`tx_epoch ≤ cmax`なら初期化を拒否する（`TX_EPOCH_AT_OR_BELOW_SWEEP_WITNESS`）。加えて**すべての**counter record commitで`key_epoch ≤ cmax`を拒否する。leaseは1個目のcounterを出す前に必ず予約blockをcommitする（`CounterLease::reserve_block`）ので、このcommit gate一つで掃除済みepochの鍵は二度と使われない | 同上 |
| D2-c 永続ピア数の上限 | 上限は通常64ピア／gateway 128ピア（`kNodeMaxPersistedPeers`／`kGatewayMaxPersistedPeers`）。1ピアはLink＋EndToEndの2 scopeなので、TX record・RX floorそれぞれ上限の2倍のslotを持つ。firmwareは`nvs_get_stats("rlsec")`の総entryから計算した収容数で上限をさらに絞る。**新しい**slotだけを拒否し（`NoCapacity`、detail `PEER_STATE_CAPACITY`）、既存ピアのblock予約・window更新・epoch前進は続く。拒否はTX／RX別に計数し、起動時ログに件数・上限・掃除結果・`rlsec`使用entryを出す。件数の調査（census）に失敗した起動では新規ピアを拒否する（fail closed） | `BoundedCounterStore`／`BoundedReplayStore`、[psk_security](../../../components/routeloom_espnow/src/psk_security.cpp)の`log_peer_state` |
| D2-d floor/windowは消さない | RX側には削除経路を作っていない。windowはそのpeer pairのfloorがあるslotにしか書かせない（ReplayGuardは常にfloorを先に確定するので挙動は変わらない）ため、windowの数もfloorの上限に収まる | `BoundedReplayStore` |
| 予算の検査（§5.3） | `tools/nvs_budget.py`がheaderの`static_assert`（record長）と定数、各firmwareの`partitions.csv`・`sdkconfig.defaults`を読み、最悪時entry（上限×20＋固定3）が`rlsec`の使えるentryの80%以下、表がflashに収まること、custom表の選択、factory非縮小を検査する。`tests/test_nvs_budget.py`（負の変異を含む）でCIに入る | [nvs_budget.py](../../../tools/nvs_budget.py) |

計算値：64KiB＝16 page、使えるentry 15×126＝1890、80%＝1512、最悪1283（64ピア）。128KiB＝使える3906、80%＝3124、最悪2563（128ピア）。

### 9.2 各削除の安全性

- **TX recordの掃除（C1）**：recordを消してよいのは、その鍵が二度と使われない時だけ。開発profileのTX鍵は`(PSK, scope, network, 自分, 宛先, epoch)`で決まり、Providerは自分のepoch（boot session）でしか送らない。消すのは`key_epoch < tx_epoch`だけで、消す前にその最大値を`cmax`としてcommitし、以後`key_epoch ≤ cmax`のcommitを全部拒否する。slotには過去に使った最大epochのrecordが残るか（Conflictで古いepochを拒否）、消されていれば`cmax`がそれ以上の値を持つ、という不変条件が常に成り立つ。電源断はどの時点でも、消えたrecordのepochが耐久化済みの`cmax`以下であることを壊さない（証人→消去の順）。
- **`rlboot`が後退した場合**：既定`nvs`だけが消去され`rlsec`が残ると、boot sessionが`cmax`以下に戻り得る。この時は初期化を拒否する（開始しない）。firmwareは初期化より前にboot sessionを進めるので、拒否された起動ごとにsessionが1つ進み、`cmax`を越えた時点で起動する。越えた時点で掃除済みのepochはすべて`cmax`以下、残っているrecordは自分のslotを守る（それより古いepochはConflict）ので、再使用は起こらない。逆に`rlsec`だけを消した場合は`rlboot`が残るのでepochは新しいままで、過去のTX鍵は使われない（旧来の単一partitionより安全側）。
- **RX floor／windowは消さない（C2、D2-d）**：開発profileには双方nonceのhandshakeが無く、同じ鍵は同じepochの間ずっと有効である。floorを消すと、捕獲された古いframeがcold startとして受理される。windowだけを消してfloorを残すことは安全（同epochは`REPLAY_STATE_LOST`で拒否）だが、相手のepochはboot sessionなので、**生きているが休止していた**ピアは相手が再起動するまで通信不能になる（P0には相手に再鍵を促す手段が無い）。したがって「休止ピアのLRU追い出し」やfloor＋windowの縮約（tombstone化）は採らず、上限での新規拒否に留めた。

### 9.3 残る制約（本番profileで解消）

- RX側の上限は機器の生涯で累計した(scope, 送信元)に効く。上限到達後の新しい送信元は、全台での開発network id／PSK切替と`rlreplay`/`rlcounter`の明示消去（D2-e）まで通信できない。根本解決はD1（P4-4、開発ProviderのRAM context engine化）。
- TX側の上限は1起動内の(scope, 宛先)数に効く（起動ごとに掃除される）。
- P0時点では`rlident`/`rlsite`/`rltrust`/`rlrevo`/`rlres`を後続段階で`rlsec`へ置く計画だった。現行の再開namespaceは`rlres2`で、旧`rlres`は§3.2の消去対象である。P0では既存の`rltrust`/`rlcred`を既定`nvs`に残した。`rlsec`のNVS暗号化（T2）は未適用。
- 数値はNVS形式からの計算で、実機の`nvs_get_stats()`との照合（V1-N08）は未実施。

### 9.4 移行

partition tableが変わるため、既存機は**flash全体を消去してから**書き込む（`idf.py erase-flash flash`）。Wire v2（v1 recordはIntegrityErrorで拒否）でも既にNVS消去が必要なので、手順は増えない（08 Q13）。消去せずに書いた場合、既定`nvs`に残る旧`rlcounter`/`rlreplay`は使われず、firmwareは起動時に警告を出す（自動消去はしない）。`rlsec`領域が初期化できない場合は理由を出して起動しない（fail closed、自動消去なし）。

### 9.5 受入試験の状況

| ID | 状況 |
|---|---|
| V1-N03 | host modelで確認（`routeloom_peer_state_tests`：`rlsec`容量を使い切る構成でも別partitionのboot session書込みは毎回成功）。実機HILは未実施 |
| V1-N04 | host試験済み（掃除・証人の順序・電源断・`cmax`以下の拒否・`rlboot`後退時の非再使用） |
| V1-N05 | host試験済み（上限超過の新規拒否と計数、既存ピアの継続、累計200ピアのchurnで上限不超過・(鍵, counter)非再使用・旧frame非再受理） |
| V1-N07 | CIで実行（`tools/nvs_budget.py`、`tests/test_nvs_budget.py`） |
| V1-N08 | 未実施（HIL） |
| V1-N01／N02／N06 | 本番profile向け。P0の対象外 |

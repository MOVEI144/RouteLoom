# Issue #5 — チャンネル調査・実行中移行・取り残しからの復帰

状態：設計案。要求：[Issue #5](https://github.com/MOVEI144/RouteLoom/issues/5)。単一Authorityで始める。Raftを実装しないと手動変更すらできない構造にはしない。

## 1. 先に決定すること

**D5-01:** `Disabled / Observe / Manual / AutoGuarded`を分ける。既存COREのauto=falseは維持。この設計の自動化は認定後に選べる機能であり、設計PRで既定ONにしない。

**D5-02:** 手動と自動で同じplan状態機械を使う。手動ボタンだけ安全条件を省略する抜け道を作らない。Manualでも全ノードへの再フラッシュを不要にする。

**D5-03:** 全ノード同時切替を完全な原子的操作と呼ばない。正当な設定の単調性という安全性と、有限loss等の仮定下で再会できる到達性を分ける。

**D5-04:** 定常時は一つの2.4GHz home。調査/救済訪問は一時的なradio占有。二台Gatewayや固定CH1救済を必須にしない。

**D5-05:** 全体rollbackには新Authority操作・新channel epochが要る。訪問だけならactive/committed epochを巻き戻さない。

## 2. 観測→調査の判断

#4でlocal resource、remote BUSY、予定不在を分離し、負荷抑制と局所修復を先に試す。30秒の悪化窓が2回続き、少なくとも独立2観測点または保護対象の重要linkで支障がある場合にsurveyを提案する。観測不足なら少量probe、原因不明ならUNKNOWNを残す。

AP数は参考、CCA busy率/Noise Floorは取得・校正できると確認した場合のみoptional。RSSIが低いことだけで全体移行しない。未認証申告や一台の偽装負荷で網全体を動かさない。

候補は承認RF profileの許可集合と参加者capabilityの積集合。初期候補1/6/11、2.4GHz固定。LR可能なchannelを独自に断定せず、固定IDF・board/antenna・配備条件を認定する。5GHz/DFS/LoRaへ逃がす設計ではない。

## 3. single-radio survey

`SurveyLease`に両端、候補channel、LR250、期間、共通時刻mapping、不確かさ、帰還先、packet予算を記録する。事前確認後に両端が移動し、最大200msでhomeへ戻る。各方向4交換は上限目標で、切替とguardが収まらなければ減らす。

同じnodeの再訪問は30秒以上あける。複数回の結果を集め、重要方向ごと20標本を初期目標とする。19/20成功は候補screeningであって99.9%信頼性証明ではない。

直接peerを失う他ノードへ認証済みの予定不在を短期通知する。重要なcutを同時に外さない。代替のないchainでは短い停止許可が必要。許可がなければ `SURVEY_REQUIRES_OUTAGE_PERMISSION`、無停止可能とは表示しない。

通常Wi-Fi scanを同時実行せず、OwnerがTX終了を確認して明示set_channel→readback→試験→帰還する。driverのAPI受付と空中のLR実測を区別する。実行中緊急DATAはhome不在中に受信できず、送信元保持/再送で扱う。未開始のsurveyは緊急処理を優先して延期できる。

## 4. 候補channelの採用

候補グラフ上で保護対象endpointから**指定された**Gateway/Authorityへ経路が成立することが先。1階相当の親機周辺だけの平均値を最適化しない。現在と異なる経路を候補にしてよいが、未測定edgeを通れる扱いにしない。

重要経路の最悪costが25%以上改善、または現在未達の要件を候補が満たすことを要求する。候補の信頼度、計測時刻、予定負荷を添える。全候補が悪いときは負荷制限/配置見直しを報告し、移行を繰り返さない。

metricの意味、測定時刻、relay可用性が混ざる比較は不可。眠って未観測のendpointは「候補で接続確認済み」ではなくunknown。最後の接続peerが候補上で使えることは復帰の補助であり到達の保証ではない。

## 5. Authorityと設定の真正性

初期は一つの明示Authority。Gatewayであるだけでは承認権を持たない。`VerifiedAuthorityPlan`は本物の暗号検証とpolicy承認からのみ生成する。

現行 `SingleAuthority` の順序/二slot保存を利用するが、`cryptographic_signature_verified=true`の固定渡しや、非暗号の `bind_operation_payload()` を証拠の代用にしない。Production Provider未認定なら自動本番移行は不可。developmentでは明示EXPERIMENTALの実暗号Providerと制限されたtrustモデルを使う。

管理HAは別のAuthority Providerが同じcommit契約を満たした時だけ追加する。単一Authorityの停止中は新移行をcommitしない。すでにcommitされた計画と署名済み復旧資料は参加ノードで実行・配布できる。

## 6. planの内容と保存順序

planはNetwork、Authority identity/generation/op sequence、previous state hash、old/new channel epoch、old/new channel、参加capability集合、required participant digest、candidate evidence digest、switch時刻参照、guard、expiry、recovery schedule、protected services、最大outage予算を持つ。

時刻参照はAuthority boot/sessionと単調clock mapping。UTCがある前提にしない。key/membership/Authority identityの変更は移行中は排他し、古いanchorで計画を検証できる期間を確保する。

保存は次の順序。

1. plan blobをhash-addressedな領域へ保存し読戻し検査。ここではPREPAREDだけ。
2. 正当なAuthority operationがblob hashを参照してcommit。操作digestには全plan内容を結ぶ。
3. 各参加nodeがcommit証拠とblobを保存。準備段階とcommit段階を分ける。
4. 期限・clock条件を満たしてdriverへ適用し、readback後にactive stateを記録する。

blobだけなら切替不可。ledgerが参照するblobを失ったら再取得/隔離であり、古い設定を新しい正式設定へ捏造しない。driver適用後にactive記録だけ失われた場合は、保存済みcommitから冪等に再適用する。

## 7. 状態と参加集合

```text
STABLE → ASSESS → SURVEY → PREPARING → COMMITTED → SWITCHING → VERIFYING
                        │                                      │
                        └→ ABORTED（commit前のみ）              ├→ STABLE
                                                               └→ RECOVERING
                                                                      │
                                                     解決/RECOVERY_REQUIRED
```

PREPAREDを受けただけで切り替えない。READYは保存、capability、clock、drain予算、recovery手順を受諾した証拠。required集合にはawake relay/Gateway、保護対象の接続を支えるcut、Authorityへの経路を含める。

未応答を都合よくsleep扱いにしない。sleep端末は有効なavailability leaseと再発見能力を確認してdeferred集合へ分ける。legacy nodeが保護対象に残るなら自動移行不可。

準備中にRelayが変わる、bindingが失効する、必要capacityが消える場合は再評価。commit前ならabort/再計画、commit後は旧planを消さずrecovery。新規Joinの確定は短く保留するか、新しい参加者もplan対応を確認する。

## 8. clockとcutover

clock uncertainty初期上限20ms、guardは `max(100ms, 4*uncertainty + measured_switch_bound)`。COMMIT配布leadは `max(5s, 4*management_RTT_P99, control_budget_delivery_bound)` とする。

準備期限は標準30秒だが、必要な管理転送がその中に収まらなければ計画を拒否する。数式の上限を無視して「5秒あれば常に十分」と扱わない。

`committed_epoch`、`active_epoch`、`visit_channel`は別。channel番号をSleep imageから無条件復元せず、正式planを優先する。再起動で時刻mappingを失ったら保存した旧単調時刻を再使用しない。最新のcommit状態を認証取得してapply-on-resumeへ進む。

cutoverはDATA admission/投入停止→期限を維持したdrain→TX callback fence→set_channel→readback→Peer channel/rate再適用→clock/観測世代更新→DATA再開。処理中jobの暗号counterを使い回さない。単に `config_.channel = new` を代入して既存Peerを残す変更は禁止。

Peer.channelは0=currentというdriver方針へ統一するか、全登録PeerをOwnerが更新する。v1設計では0=currentを採用し、相手別のchannel値で個別多channelを実現したように見せない。broadcast PeerにもLR250を再適用する。

## 9. 復旧を「後でscan」で済ませない

### 9.1 COMMITを逃したawake node

旧channelに残ることは許される。旧設定を自分で新epochへ変えず、#3の発見から正当なcommit証拠を取得して追従する。OFFERの新channel申告だけでは変更しない。

### 9.2 認証済み救済訪問

planへ **helper集合、old-channel訪問周期、滞在、開始/終了、転送可能な管理object、予算** を入れる。初期案は5秒周期で800msのold-channel訪問、最大180秒。survey200ms上限とは別の、移行時だけ許可された停止予算である。

helperは署名済み最新plan/snapshotを局所保持し、旧側の隣へ渡せる。旧channel上で通常DATA網をもう一つ恒久運用しない。救済中の認証済みbootstrapとplan取得だけを許す。大objectの取得は複数訪問にまたがる有界再開を許し、一回の800msへ全credentialを押し込む前提を置かない。

同じrequired relay群が異なる訪問時刻へ散らばるのを避け、planのclock phaseを使う。時計不確かなnodeは同期helperを名乗らずscoutとして予算付き探索に入る。回復したnodeは残りの有効期間内でhelperを引き継げる。

### 9.3 条件付きの回復時間

回復を保証すると記載できるのは、old/newいずれかでhelperへの辺が残り、指定回数以内に応答が届き、必要転送が予算内、時計誤差が上限内という明示条件の下だけ。

候補boundは `H * ((loss_windows + 1) * visit_period + transfer_bound) + margin`。Hは回復波が越える最大辺数で、DATA hop limitと自動的に同じ値にはしない。180秒は参考予算であり、式の入力と実測転送boundを満たさない配備ではAutoGuardedを拒否する。

800msへ収まらない応答遅延、有限lossの仮定逸脱、helperの全損、永続断では `RECOVERY_REQUIRED`。期限切れ後も低頻度の通常discoveryは可能だが、同じ強い回復SLOは主張しない。

### 9.4 寝ていた端末

次回起床で保存home→同channel発見→保存候補→承認channel集合を有界に調べる。複数世代を飛ばした場合も最新の署名snapshotを使い、古い一世代だけに依存しない。長期sleepは180秒内に起きる必要はない。

起床予算が短い場合は次回へ探索cursorを持ち越す。未知時間を新しい期限へ変えず、未完了Message IDを保存する。移行だけを理由に初回Joinや全鍵消去をしない。

## 10. rollbackと障害

VERIFYは初期30秒。失敗時、Authorityが到達可能なら新epochで旧channelへ戻す正式planを提案する。到達不能なら訪問で管理接続を回復し、勝手なrollbackはしない。

一回の移行では自動rollback最大1、その後はcooldown10分と診断。失敗するたびに往復しない。Recovery中の同時key rotation、firmware更新、Authority災害復旧は別操作として排他する。

既定をManual/ObserveからAutoGuardedへ昇格する条件は、旧新channelの分断、commit欠落、時計喪失、cut relay、storage全cut、sleep再開のシナリオ合格と配備承認。#5の設計だけで「都市部なら自動で解決」を宣伝しない。

## 11. 合格条件

一台radioのfake adapterで、訪問中にhomeのRXができないモデルを使う。COMMITを落とした中央Relay、Authorityが新側へ移動、helper訪問のclockずれ、2回以上のsleep世代飛ばし、all-channels-badを必須にする。

モデルのsafety oracleは未commit切替ゼロ、epoch単調、通常DATAの恒久二重domainゼロ、期限延長ゼロ。liveness oracleは明示仮定を満たす入力だけに適用する。受入IDは[scenarios](scenarios.json)のD5系列。

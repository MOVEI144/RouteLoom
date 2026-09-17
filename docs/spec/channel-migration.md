# 干渉調査と協調チャンネル移行

基準線ではauto migration=false。以下は設計を維持する拡張の必須契約で、利用可能な実装の宣言ではない。

## 1. 基本契約

一つの論理ネットワークは定常時一つのhome channelを持つ。v1は頻繁なホッピングや常用multi-channel meshではない。

候補はRF配備プロファイルの許可集合内。既定1/6/11、JPの設定上限集合1..13、14は使わない。これは個別アンテナ・PHY認証の代わりではない。候補を追加する場合は新規端末にも発見可能な初期集合に含めるか、正当な方法で事前配布する。

LRは2.4GHzの干渉を消すものではない。一台の無線が別channelにいる間homeを同時受信できないという制約を計画へ含める。[ESP-NOW API](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/network/esp_now.html)

## 2. 何を測るか

普段は自網の送受信結果・遅延・queueを集約する。promiscuous captureは既定OFF、必要時の短い窓だけ。SSIDや他人のpayloadを常時保存せず、観測条件付き統計にする。Noise Floor等の有効性はSoC/SDK別に認定する。

AP数だけ、RSSI一件だけ、未認証の悪化申告だけでは移行しない。低優先送信抑制と局所repair後も、30秒窓2回で複数観測点または重要区間の悪化が続けば調査を提案する。低頻度で標本不足なら有界probeで補う。

## 3. off-channel調査

調査計画は両端、candidate channel、nonce/ID、時刻mapping、不在上限、rateを持つ。双方承諾、近隣へ予定不在通知、TX整理後に出発し、期限でhomeへ戻る。調査中は通常DATAの受領を装わない。

訪問上限200ms、各方向4交換を初期候補とする。実切替時間・時計誤差・応答が収まらない場合は交換数を減らす。同一無線の訪問間隔30秒以上、重要区間は最低5訪問・各方向20標本を集める。参加ノードの再起動や新しい緊急仕事が発生したら未開始surveyを延期する。

同じ一本鎖の複数中継を同時に外さない。代替のない中継を離脱させるには短い停止の許可が要る。許可がなければSURVEY_REQUIRES_OUTAGE_PERMISSIONを返す。追加無線がないのに無停止測定を保証しない。

## 4. 候補採用

保護対象ノードから指定Gatewayまで候補グラフ上に経路が成立することが先。現在と同じ辺でなくてもよいが、未測定区間をPASSにしない。

初期候補ゲートは重要リンク両方向20中19成功、観測の鮮度、構成一致。その上で最悪側の重要経路costが25%以上改善するか、現channelで未達の要件を候補が満たすことを求める。19/20を高信頼性の統計証明にしない。

## 5. 計画の内容

plan_id、Network、old/new epoch、old/new channel、candidate_set hash、required participant set、管理commit参照、親状態hash、clock reference、switch_at、prepare expiry、verify期間、recovery方針を持つ。必要なcommit証拠を再起動後も検証できる形で保存する。

PREPARE/COMMITは単に二つのbroadcastを送る処理ではない。準備には配送結果と状態保存、COMMITには管理logの正当性が必要。

## 6. 状態機械

```text
STABLE → SURVEY → PREPARE
                     ├ 不備・期限切れ → ABORT（現設定維持）
                     └ READY集合成立 → COMMIT
                                          ↓
                                        SWITCH
                                          ↓
                                        VERIFY
                                  成功 ↙      ↘ 不達
                                   STABLE      RECOVERY
```

PREPAREだけでは切り替えない。READYは正当な計画を保存し、clock条件・停止可能性を満たした証拠。眠る端末はREADY集合から除外できるが状態・最終通信・復帰方法を記録する。応答しないawake端末を都合よくsleep扱いにしない。

中継構成が変わったら準備を再評価する。Joinが増える場合は短い期間membership確定を保留するか新計画を配る。新しいRelayを計画なしでcutover直前に組み込まない。

## 7. 保存状態と実状態

`committed_epoch`は正式に保存した計画、`active_epoch`は実際にdriverへ適用したhome設定、`visit_channel`は一時調査先。三つを分ける。COMMIT後で切替時刻前のcommitted新/active旧は正常。

同期は壁時計ではなく認証済み単調時計mapping。不確かさ20ms以下を初期上限、guardは最低100msかつ4×mapping不確かさ＋実測切替時間以上。未知offsetを0にしない。条件未達はREADY不可。

PREPARE期限30秒、COMMIT配布leadは最低5秒または管理往復P99×4の長い方。guardに入る前に新しい通常TXを止め、in-flightを安全に整理する。driver watchdogの時間も必要に応じて前倒しで確保する。ACK待ちや未送信仕事の期限は黙って消去しない。

COMMITは耐電断保存後に適用する。遅着COMMITも正当かつ最新連続状態ならquiesce後に追従。再起動で時計が失われたら旧ローカル時刻を再使用せず、再同期またはrecoveryへ進む。

## 8. 取り残しと再結合

COMMITを失った端末は旧channelに残り得る。保存候補とLR250発見で正当な新計画を取得し、所属を保って追従する。

新channelのノードが予定された短いRECOVERY_VISITで旧channelへ戻り応答することは可能だが、全場所で必ず会える保証はない。孤立群は少数scoutだけを探索させ、他はhomeで待つ。scoutに新channelの確定権限はない。

長期間眠って複数の計画を逃した端末には、認証済み管理snapshotと構成員連続性の証拠を渡す。古い一段だけを探し続ける設計にしない。証拠が検証不能なら人の再承認ではなくSECURITY_RESUME_REQUIRED等の明確な状態を返す。

## 9. rollbackと管理者交代

切替後VERIFYは30秒。重要到達が悪化したらrollbackを提案するが、新しい管理log・新epochが必要。CH6/e8→CH11/e9→CH6/e10でありe8へ戻さない。

多数が不在なら新rollbackも勝手に確定できない。探索で既知経路と管理通信の復旧を図り、不能はRECOVERY_REQUIREDと報告する。通常移行cooldownは10分。重大不達の正式rollbackは例外だが、計画重複やping-pongを許さない。

後継Controllerは確定logと進行中計画を引き継ぐ。termを上げて未配布計画を勝手に捨てない。選挙の過半数と重要無線区間のREADY集合は別。

## 10. 二無線Gateway

覆域、独立RF、PC間の明示的な安全経路、宛先条件を満たす場合だけ旧新channel救済の拡張に使える。v1成立条件ではない。二つのGatewayがあるだけで上階孤立群を救えるとはしない。恒常multi-domain forwardingはv1対象外。

[無線規約](radio.md)／[管理合意](control-plane.md)／[試験](acceptance.md)


## 11. 自動有効化を阻止する条件

管理到達を支えるcutsetとrequired participantsを別に検証する。COMMITの配送欠落でvoter間を結ぶRelayだけが旧CHへ残る反例を必須にする。quorumの安全性は、そのquorumが再び通信できることの証明ではない。

自動移行の認定には、事前planにrecovery担当・訪問CH・時刻/期間・反復上限・home待機役・中止条件を含め、clock誤差、有限loss、覆域の仮定を明示する。仮定外はRECOVERY_REQUIREDと物理保守へ移り、独断rollbackや「必ず再結合」を約束しない。

手動操作でも同じ安全契約が要る。operator確認ボタンが未設計のrendezvousを補うとはしない。基準線の固定CH変更は、管理された停止と配備設定更新として扱う。

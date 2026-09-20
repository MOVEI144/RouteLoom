# 06 — 実機・継続通信・復旧の試験計画（Issue #11）

## 1. 既存証拠と今回の範囲

PR #2 `cdcf0fe` のSTATUSに記録されたC3二台、USB、6連続送信、reset復帰は**reported_manual_smoke**として引き継ぐ。本設計でその現物を再測定したわけではない。記録された約57ms等の一例を全条件のP95や、S3/C5、多段、連続運転の合格にしない。

本書は手順の設計だけ。実際のflash、電源操作、RF送信、試験実施は行わない。すべての新規ケースはplanned_not_run。CI build/portable model/HIL/RF/現場配置を別の証拠分類にする。

## 2. 機材と配置

| 機材 | 必要数・用途 | 今回の準備状態 |
|---|---|---|
| C3 | 直接2台、既存smoke記録あり | 現時点で使用可能か未確認 |
| S3 | 直接2台、C3混在を含む | 台数・基板revision未確認 |
| 3hop用radio | 4台、送信元＋中継2＋Gateway | 準備待ち |
| 中継器が独立した予備経路 | 6台、以下の二本3hop | 準備待ち。共有Gateway/送信元の故障は救わない |
| C5 | 拡大段階で2台、9有向chip組合せ | 準備待ち、C3成功を流用しない |
| Host/Linux、USBケーブル、独立給電 | 1セット以上 | OS・ケーブル・給電方式を実行時記録 |
| スイッチ付き給電/電流計/ロジアナ/遮蔽・減衰設備 | 電源断・電力・経路強制 | 未確認。無ければ該当ケースBLOCKED |

```text
直接：       A ---------------- G -- USB -- Host -- 利用アプリ
3hop：      A -- R1 -- R2 ----- G
予備：      A -- B -- D ------- G
             \-- C -- E ------/
```

A/G共通、B/DとC/Eは別機器。初期は静的な認可Peer/経路試験設定を使う。余分な直通無線linkを遮蔽・減衰・配置で避け、実観測pathを記録する。単にPeerをソフトで禁止したケースは「論理経路試験」で、建物内RF到達性の証拠とは分ける。

GatewayをUSBから給電したままケーブルを抜くと、USB断とGateway電源断が同時になる。独立した正規電源を用意し、逆流や二電源の無検証並列をしない。GPIO/pinは各board資料と現物で照合する。

## 3. 段階と方向行列

H0：C3→C3、C3→S3、S3→C3、S3→S3の直接。payload0/1は機能境界、32/64/128Bは性能系列。H1：C3/S3の3hopと予備経路、双方の向き。H2：Host API/USB/Storeを含む連続試験。H3：C5を加えた9有向chip組合せ。H4：30/50/100台と5/10hopの個別資格。

firmwareはreference normal/deep_sleep×3targetとbridge normal×3targetの9構成を事前buildする。build成功が実機を代替しない。CORE_FIXED_250、固定channel、認可したRF/antenna/power profile、明示EXPERIMENTAL鍵または受入済み本番鍵を記録。開発鍵を本番資格へ使わない。

PR #6の自動発見/混雑回避/自動移行は、採用SHAの能力と実装が確認できた後に別系列として追加。固定Peerで復旧したことをDiscoveryの成功に数えない。

## 4. 固定する負荷

| 系列 | 件数・頻度・時間・条件 |
|---|---|
| H0 smoke | 各方向×payload0/1/32/64/128Bを各20件、1秒間隔、寿命5000ms |
| H0 direct性能 | 各方向×32/64/128B、各10000件、1件/秒、約2時間46分40秒、5000ms期限。端末発の試験用sourceを使用 |
| H1 multi-hop | 3hop各向き×32/64/128B、各3000件、1件/秒、5000ms期限 |
| H2 Host操作 | HOST_CONTROL_SMALL、全client合算2件/分、24時間=2880新規操作、payloadを32/64/128B巡回 |
| H2 soak | 同2件/分、72時間=8640件。24時間保持の回収と受付epoch退役を実際に跨ぐ |
| burst | Hostから16件同時受付、以降token回復まで待つ。全件5秒内は保証しないが、拒否/期限/不明の整合性を確認 |
| overload | Host許可rate超過を段階的に投入。入場前拒否、cap診断、正常clientの処理機会を検査 |
| 端末定常 | 5台、各40イベント/時＋heartbeat30分、24時間。Host発operation負荷とは別の系列 |

端末1件/秒性能系列をHostの2件/分profileで無制限に要求しない。両者は別入口・別容量。実装の64bit時刻と有限counterを使い、試験のためだけに永久cacheや未認証modeへ変えない。

## 5. 観測と合否

各messageの発生、Host受付、Gateway受付、無線origin、END_RECEIPT、Host RAM受領、アプリreadを別eventとしてIDで結合する。送信元の単調時計による往復latencyを主に使う。別PC/deviceの時刻を同期誤差なしに引かない。外部triggerを使う場合は精度・校正・欠落も保存する。

必須集計：生成要求数、入場拒否、受付数、期限内最終receipt、期限外receipt、expired-before-dispatch、indeterminate、cancel、重複、loss/gap、P50/P95/P99、再送、修復時間、内部heap最小、最大free block、各stack余裕、queue peak。受理されなかった要求を成功率の分母から隠さない。受付後到達率と全要求到達率を両方出す。

安全性の合格：誤ったID/宛先の成功0、nonce再使用0、保護中cacheの無断eviction0、不明作用の自動再実行0、未認証昇格0、資源上限超過0。ログ不足でこれを判定不能ならINCONCLUSIVEで、0件と捏造しない。

既存の性能目標はそのまま報告：1hop P95 20ms、5hop100ms、10hop250ms、warm resume500ms、最初の故障観測から既知代替への復旧500ms。対象外のhop/条件には勝手に新しい達成済みしきい値を作らない。3hopは期限内率と分布を報告し、該当条件の受入目標は試験前レビューで固定する。20ms未達ならTARGET_MISSEDを記録し、50msへ書き換えてPASSにしない。

期限内到達率99.9%を既存目標として評価する。独立二項の全成功で片側95%下限99.9%を示すには少なくとも2995件必要だが、RF相関を消せるわけではない。10000件、時間帯/配置を分けた系列で分布を報告する。安全・機能PASSでも性能未達/証拠不足なら総合qualifiedへ上げない。30/50/100台・10hopはこの少数試験の外。

## 6. 第三者が実行する基本手順

1. firmware/source/SDK SHA、board/antenna/power/OS、許可RF profileを記録。test keysを本番から分離。
2. 使用機器ごとの自己診断と容量を取得し、ログを別ファイルへ開始。旧sessionと新sessionを識別。
3. 設定した構成・全向きの短いsmokeで、payloadのbyte一致とMessageKey/receiptを照合。
4. 対象系列のrate・件数・期限を固定して開始。途中でしきい値を変更しない。
5. faultケースでは表の発生点を記録して操作し、停止中の期待結果と復旧後の同一IDを検査。
6. pendingが期限・receipt・不明のどれかへ落ち着くまで観測。終端と観測欠落を別に記録。
7. ログhashと環境を結果manifestに保存。生ログに鍵が無いことを確認し、casesごと判定する。

現時点で存在するCLIはstatus/diagnostics/send等。新しいAPI1/receive/get_by_keyのコマンド例は実装後に使用する。runner未実装時は操作数と実コマンドを記録した手順で開始できるが、存在しないコマンドを実行済みとしない。自動CI基盤の新設は前提にしない。

## 7. ケース別故障手順と期待結果

| ID | 手順・観測点 | 期待と復旧 |
|---|---|---|
| HIL01 | H0行列で所定本文を送信し、origin/Host/appを照合 | bytes一致、receipt境界一致。失敗は再flashせず理由ログを先に保存 |
| HIL02 | 4台の実3hop、direct shortcutを検査 | path実測、往復、deadline。論理制限か物理RFかを明示 |
| HIL03 | 予備経路のB電源を停止、D/Gは維持 | 故障時刻と検知時刻を分け修復測定。ID/round/期限を維持 |
| HIL04 | 二つの経路を切り完全分断、後に戻す | false successなし、復帰で旧要求を新IDで実行しない |
| HIL05 | 独立給電のGatewayでUSBだけ抜き差し | 無線とUSB障害を区別、古いcredit/session誤適用なし |
| HIL06 | Host受付/dispatch/結果commitの各前後でdaemon停止 | 同じkeyを照会。write有無不明を新しいsendへ変換しない |
| HIL07 | Gateway/端末を別々にcold power cycle | BootLease/nonce/epochを戻さず、不明要求はINDETERMINATE |
| HIL08 | Storage Providerにwrite/commit/readback失敗を注入 | commit前受領なし。実Flash電断とfake注入の証拠を分ける |
| HIL09 | slow client、RX/TX/dedup満杯、callback欠落を注入 | 限定drop/明示拒否・隔離。無限再送、強制evictionなし |
| HIL10 | Deep Sleep設定でtimer/GPIO wake、保存peer切断 | 元ID/期限維持、認証済み応答でのみresume。消費電力は別測定 |
| HIL11 | H2の24h/72h系列、epochと結果expiryを跨ぐ | 枠回収後も旧keyを新規扱いせず、メモリ増大・stallなし |
| HIL12 | 適法な既存2.4GHz通信負荷、配置/姿勢/壁条件を記録 | interfererを断定せず相関/UNKNOWN。意図的な公衆無線妨害はしない |

古いACK遅着、受信アプリ停止、APPLIED未実装拒否はTX/APケースと連結する。実設備の物理動作や利用アプリの安全判断の受入は本SDK資格とは別。

## 8. 証拠様式

`fixtures.json`のhil_record_templateをコピーし、run_id、case、status、commit、firmware_sha256、SDK/OS、board/revision/antenna/power、channel、security profile、topology、commands、monotonic event range、log_hashes、denominator、結果、不明点を埋める。

statusはplanned_not_run / blocked / running / passed / failed / inconclusive / not_applicable。既存reported_manual_smokeは履歴欄だけ。試験前のtemplateはnullを残し、架空のPASSを記入しない。GitHub Actionsの期限付きartifactだけを長期認定根拠にせず、再配布可能な証跡とhashを承認済み保存先へ保管する。

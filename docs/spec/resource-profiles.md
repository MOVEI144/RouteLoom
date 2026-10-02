# 資源・preauth・board資格のプロファイル

正本：[resource-profiles.json](../reference/resource-profiles.json)。**全数値は割当の設計上限・概算で、sizeofや実測heapではない**。Wi-Fi/IDF/NVS・アプリ・IRAM/DMA制約は別計上する。

## 役割別予算

<!-- generated:resources:start -->
| Profile | RX / TX | Active destinations | Dedup | SDK概算 / 上限 (bytes) | 実測 |
|---|---:|---:|---:|---:|---|
| leaf-small | 8 / 8 | 4 | 32 | 64800 / 65536 | 未実測 |
| relay-c3 | 24 / 24 | 32 | 96 | 111584 / 131072 | 未実測 |
| gateway-s3 | 48 / 48 | 128 | 256 | 187840 / 245760 | 未実測 |
<!-- generated:resources:end -->

各budget合計はprofile ceiling以下であることをCI検査する。CPU/crypto libraryによりscratchが増えたら、定数を偽って合格にせずprofileを改訂する。voterは未予算化・無効。C3を含む全ノードに一つの最大設定を強制しない。

`gateway-s3` は設計予算の名前で、S3 の stock bridge で dedup256 を保証する名前ではない。H7 の ESP-IDF 6.0.3・worker OFF の stock build は S3 の静的空き 6736 B < 8192 B、C3 は 11896 B < 27648 B で guard が拒否した。これらの構成は利用可能な supported cell と扱わない。容量 override の選択肢は残すが、guard を通した構成と radio/security 稼働時の heap の実測が揃うまで board qualification は未完了とする。

raw64標本をdirection×rate×length×neighborごとに保持しない。固定統計poolのcounter/EWMA/必要な少数ringを使う。dedup数、結果保存bytes、member context数、active destination数は独立の制約。node台帳128だから128宛先の全経路を同時に保持できるとは限らない。

返信受理の固定容量は各profileのRX／TX枠とは別に、Owner全体でbinding entry 3、use 8、受理transaction 8、component event 8。受理時に必要なTX枠とcontrol laneを確保し、局所仕事は最大1500msで終結する。これらをpeer数倍に増やさず、枠不足は有限retry／BUSY／計数付きdropで扱う。C3の実機RAM・stackとRF性能は受入ゲートで測定する。

## 未認証入口の具体的上限

global handshake同時1、一object最大1024B。実装値を正とする（#54）：SDK v1参加搬送（`sdkv1_join_transport`）の組立は同時1件・3000ms、RLD1 discoveryのbootstrap組立（`discovery.hpp` `kReassemblySlots`）は4 slot×1024B（計4096B）で期限は`candidate_ttl_ms`（既定5000ms）。profile表の`preauth_pool` 1536BはSDK v1参加搬送の枠で、RLD1 discoveryの組立4096Bは別の`discovery_assembly_pool`に計上する。活動予算が先なら中断する。近隣 discovery の handshake 開始間隔は既定 1000ms、ZeroTouch proxy の新規 m1 は最短 2000ms。scope lane の入力 budget と 1 poll あたり最大 2 MAC 検証は `discovery_scope.hpp` の別枠。設計の入力2048B/s burst512B・高価な演算4回/s burst1を全入口共通の実装済み CPU gate と扱わない。memberの管理object2048Bとは別。

P-256 は優先度の低い crypto worker で実行し、Owner の最長占有 25 ms 以下を受入条件にする。非中断可能な演算の中断を前提にせず、job と結果の mailbox は各 1 件に有界化する。member ACK用queueとCPU機会を保護するが、偽フレームの実RFやcallback負荷を完全排除する保証ではない。

source MAC単位だけでなくglobal quotaを最後の上限とする。cookieは到達性の確認であり、偽ID大量生成への無限capacityを与えない。再試行の起点が変わってもglobal counterをリセットしない。

## 実装時に記録する値

boot/Join peak/steady/repair/key overlap/USB再接続/更新ごとに、min internal free heap、largest free block、stack high-water、allocation failureを測る。初期安全余裕目標は32KiBとlargest block16KiBだが、実SDKが必要とする最大allocationと合わせて検証する。PSRAMでは代替できない領域を分ける。

## ボード資料の利用

[boards.json](../reference/boards.json)はpublished factsだけ。runtime profileには実SoC part/revision、Flash/PSRAM検出、pin排他・初期状態、電源・antenna・RF認定artifactを要求する。runtime_generation_allowed=falseの資料からfirmware定数を自動生成しない。C5の公称8MBを実利用可能メモリとしない。

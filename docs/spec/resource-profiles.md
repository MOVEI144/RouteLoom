# 資源・preauth・board資格のプロファイル

正本：[resource-profiles.json](../reference/resource-profiles.json)。**全数値は割当の設計上限・概算で、sizeofや実測heapではない**。Wi-Fi/IDF/NVS・アプリ・IRAM/DMA制約は別計上する。

## 役割別予算

<!-- generated:resources:start -->
| Profile | RX / TX | Active destinations | Dedup | SDK概算 / 上限 (bytes) | 実測 |
|---|---:|---:|---:|---:|---|
| leaf-small | 8 / 8 | 4 | 32 | 51232 / 65536 | 未実測 |
| relay-c3 | 24 / 24 | 32 | 96 | 92384 / 131072 | 未実測 |
| gateway-s3 | 48 / 48 | 128 | 256 | 154560 / 245760 | 未実測 |
<!-- generated:resources:end -->

各budget合計はprofile ceiling以下であることをCI検査する。CPU/crypto libraryによりscratchが増えたら、定数を偽って合格にせずprofileを改訂する。voterは未予算化・無効。C3を含む全ノードに一つの最大設定を強制しない。

raw64標本をdirection×rate×length×neighborごとに保持しない。固定統計poolのcounter/EWMA/必要な少数ringを使う。dedup数、結果保存bytes、member context数、active destination数は独立の制約。node台帳128だから128宛先の全経路を同時に保持できるとは限らない。

## 未認証入口の具体的上限

global handshake同時1、preauth総pool1536B、一object最大1024B、組立期限3000ms（活動予算が先なら中断）。新handshakeは全送信者合算1/s burst1、入力2048B/s burst512B、公開鍵等の高価な演算4回/s burst1を初期capとする。memberの管理object2048Bとは別。

Crypto worker予算100ms/1000ms、協調yield単位10msを目標、非中断可能演算の最大25msを受入条件にする。対象ライブラリが満たさなければ「強制中断できる」と偽らず、別task/実装・入場rateの改訂・profile不認定で扱う。member ACK用queueとCPU機会を保護するが、偽フレームの実RFやcallback負荷を完全排除する保証ではない。

source MAC単位だけでなくglobal quotaを最後の上限とする。cookieは到達性の確認であり、偽ID大量生成への無限capacityを与えない。再試行の起点が変わってもglobal counterをリセットしない。

## 実装時に記録する値

boot/Join peak/steady/repair/key overlap/USB再接続/更新ごとに、min internal free heap、largest free block、stack high-water、allocation failureを測る。初期安全余裕目標は32KiBとlargest block16KiBだが、実SDKが必要とする最大allocationと合わせて検証する。PSRAMでは代替できない領域を分ける。

## ボード資料の利用

[boards.json](../reference/boards.json)はpublished factsだけ。runtime profileには実SoC part/revision、Flash/PSRAM検出、pin排他・初期状態、電源・antenna・RF認定artifactを要求する。runtime_generation_allowed=falseの資料からfirmware定数を自動生成しない。C5の公称8MBを実利用可能メモリとしない。

# USB／Serial transport契約

## 1. 原則

USBはradioではなく、hostとGateway間の独立Transport。USBへ接続したという理由でNodeを管理者や同じ業務受信先にしない。CDC/JTAGやUART bridge等の差をByteStream adapterで吸収する。

通信専用streamに人間向けprintf、boot message、JSONログを無条件混在させない。専用portがない場合はフレーマーがboot garbageから再同期できる設計にする。

## 2. フレーミング案

基準案はCOBS符号化＋0 delimiter、内部にversion、kind、session ID、request ID、body length、body、CRC32を持つ。decoded frameは最大4096B、body上限はheader分を差し引く。CRCは偶発破損検出であり認証ではない。認証は別session契約。

このbyte layout/CRC variantはUSB golden vectorとIDLを同時に固定する。文字列改行区切りだけでバイナリDATAを運ばない。4096B USB frameをそのまま250B無線に送れるとみなさない。

## 3. HELLOとsession

host nonce、device nonce、protocol range、Node ID、boot ID、firmware/hash、device capabilities、Network state、最大frame、creditを交換する。ネットワーク認証とは別に、接続先deviceが期待した機器であることを必要なcredentialで確認する。

sessionは再接続ごとに変える。request IDはsession内一意、Message IDはより長い寿命を持つ。古いACKや部分frameを新sessionへ流さない。

## 4. メッセージ種別

HELLO、AUTH、COMMAND、COMMAND_ACCEPTED、COMMAND_RESULT、DATA_TO_MESH、DATA_FROM_MESH、DELIVERY_EVENT、CREDIT、DIAGNOSTIC、KEEPALIVE、ERROR、CLOSEを設ける。

COMMAND_ACCEPTEDは機器内受付であり管理commitや最終配送ではない。DATA送信は無線APIと同じdeadline/保存/宛先/receipt意味を持つ。

## 5. フロー制御

RX可能frame数とbytesをcreditで通知する。0creditなら新規bulkを送らず、CONTROL/必要ACK用の小さい予約容量を持つ。credit更新を失っても無限停止にならない有限照会・timeoutを設ける。

短い制御とDATAを、大量ログ・OTAの後ろへ無制限に並べない。partial writeは残り位置から継続し、失敗後に途中bytesを二重に送り込まない。接続が曖昧ならsessionを閉じ、Message IDで再照会する。

## 6. エラー回復

不正COBS、CRC不一致、長さ超過、frame途中disconnect、duplicate request、未知version、session不一致を明確に記録する。無制限buffer拡張やsecretのdumpは禁止。

USB切断を無線故障としてrate/channel学習へ混ぜない。PCがログを読まなくてもESP32のradio loopを止めない。

## 7. 試験

1byte刻み分割、複数frame一括、0byte/破損挿入、最大長、古いsession、PC再起動、device再起動、遅いreader、credit欠落を必須にする。host C/Rust双方のgolden vectorを一致させる。

[Host service](host.md)／[Wireの境界](wire-protocol.md)

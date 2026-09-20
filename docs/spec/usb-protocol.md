# USB／Serial transport契約

改訂1.2。フレーミング・認可・creditの意味を定義する。最終field offset／暗号Profile／IDLは未凍結。Rust host codecと携帯可能C++ device bridge（session、credit、MeshNode統合）は実装済みで、`protocol/usb-golden`の共有vectorでbyte相互検証済み。ただし開発profile認証であり、実USB driver・HIL・本番Profileは未認定。

## 1. フレームと境界

COBS＋0 delimiterを基準。decoded最大4096B、body最大はheader・保護・CRCを差し引く。CRCはCRC-32/ISO-HDLC（reflected polynomial 0xEDB88320、init/xorout 0xFFFFFFFF、check("123456789")=0xCBF43926）、他fieldと同じくbig-endian32bitで末尾へ置く。CRC対象はdecoded CRC直前のbytes、CRC自体とCOBSは除く。CRCは認証ではない。

最大符号化長は保守的にn+floor(n/254)+2（delimiter込み）。decoded overlengthを検出しても次delimiterまで有界に捨て、再同期する。部分frameは最後のbyteから1000msで破棄する。実USB伝送速度と相互待ちで達成可能かを認定する。

bootログ混入へ同期復旧は必要だが、通常binary streamへprintfを流さない。4096B USB frameをそのまま250B RFへ送れるとはしない。

## 2. 認証とsession

HELLOは未認証。device/host credential、nonces、protocol範囲、選択版、期待Node、Network scope、host principal/roles、boot、capability digestを認証transcriptへ結び付ける。AUTH後の全COMMAND・DATA・CREDITもそのsessionの完全性とreplay保護を必要とする。

firmware hashの自己申告はattestationではない。COM番号やUSB serial文字列を機器本人証明にしない。Networkを切り替える場合も認証scopeと再認可を確認する。未認証のCREDITを送信許可として処理しない。

再接続は新sessionで、partial frame、grant、consumed、request tokenを再使用しない。stable Message IDやhost idempotency identityだけを明示的に再照会する。認証方式と最終byte vectorはG-SEC/G-USBに残す。

現行実装は**EXPERIMENTALな開発profile**として、共有secretと決定的なtranscript結合MAC（label分離domain、u64 wrap演算）でHELLO/AUTH/session frame tagを検証する。本番Identity・真正暗学suiteではなく、G-SECの責務である。

## 3. credit：方向・session別の累積許可

各方向はuint64の `grant_frames, grant_bytes, consumed_frames, consumed_bytes` を持つ。受信側grantは**累積送信許可の上限**であり「今の空き」「差分＋4」ではない。初期grantは専用buffer容量以内。

認証済み同session通知は各grantのmaxを採用。duplicateや古い小grantは追加許可にならない。送信条件は両軸で `consumed + next_cost <= grant`。新frameの最初のbyteをwriteする前にframe1件と完全なdecoded保護frame長（CRC含む、COBS/delimiter除外）を一度だけ課金する。partial write継続で再課金しない。

受信側は予約bufferを解放した分だけgrantを進める。累積grant値が大きいことと同時buffer容量が大きいことは別。grantを取り消して縮小せず、止めたいときは増額を止める。wrap前にsessionをdrainして作り直す。

破損frameでgrantの正確な会計が復元できない場合、無制限credit返却は行わず認証された同期手順または新sessionに戻す。新sessionで旧の未完送信の結果を成功としない。

## 4. zero-creditの回復

通常DATA/BULKとは別にCONTROL予約を最大4frame×256B設ける。AUTH後のcredit query、grant、keepalive、close等だけ、全相手合算10frame/s burst4以下。CONTROLにCONTROL ACKを無限要求しない。初期AUTHにもさらに有界なpreauth quotaが必要。

zero-credit時のqueryは500ms以上の間隔で最大3回、応答が無ければCONNECTION_STALLED。CONTROL予約で通常DATAを迂回しない。

## 5. 操作identityと結果

USB request IDはsession内一意、Message IDは論理配送の寿命、host idempotency identityは `(principal, network, operation_class, key)`。同identity・同canonical payload hashは既存結果、同identity・異hashはCONFLICT。

COMMAND_ACCEPTEDは機器受付だけ。管理確定、PC永続保存、アプリ適用は別event。再接続で信用先が変わったら旧認可を引き継がない。

## 6. 検査

CRC既知vector、1byte分割、COBS境界、overlength、部分timeout、grant duplicate／stale／別session、2軸不足、partial write一度課金、zero-credit相互待ちを検査する。小モデルで累積creditが通ってもUSB暗号・実driver相互運用が認定されたことにはならない。

[Host](host.md)／[Wire](wire-protocol.md)／[電源断](crash-time-resources.md)

# 無線Wire形式と版管理

## 1. 契約の段階

本書はframeの意味・上限・保護境界を定義する。**最終のbyte offset、暗号suite、CBOR/固定fieldの割当とgolden vectorはG-WIRE/G-SECで同時凍結する。** 未確定のバイト列を公開互換プロトコルとして実装者に配布しない。

一方、以下の長さ、再送ID、mutable/immutable分離、未知版の拒否、通常DATA非分割は変更管理された必須契約である。

## 2. サイズ

ESP-NOWへ渡すbodyは最大250B。通常アプリpayload最大128B。Routing、Identity参照、長さ、期限、session、認証・暗号tagを含む全envelopeに122B以下を予約する。空中の802.11/ESP-NOWヘッダはこの250Bとは別。

frame長区分は32/64/128Bアプリpayloadと最大250B全bodyで試験する。v2の1470Bを使わず、暗号を省いて128Bを達成しない。暗号Profileで収まらなければプロファイルの再設計または互換性を伴う上限改訂が必要。

## 3. 通常frameの意味

| 区分 | 必須の意味 |
|---|---|
| 形式 | magic/識別、protocol version、frame type、flags、header/body長 |
| 所属 | Network識別と必要なmembership/key世代参照 |
| 送受信 | source、固定destination、origin session、message sequence |
| 配送 | delivery round、hop remaining、priority、残deadline |
| hop保護 | 直前送信者context、nonce/counter、mutable headerの完全性 |
| end保護 | 不変なorigin/destination/messageとpayloadの認証暗号 |

NodeIDは長期credentialへ結び付く。short handleを使用する場合は所属世代と割当証拠で復元し、handle衝突を無視しない。生MACを認証済みIdentityとしない。

remaining deadline、hop、前回送信者などは中継で変わり得る。end署名対象の不変部を書き換えず、hop保護を作り直す。変更時にnonceを再使用しない。

## 4. フレーム種類

DISCOVER/OFFER、BOOTSTRAP_AUTH/CHUNK/REPLY、MEMBERSHIP_QUERY/RESULT、NEIGHBOR_PROBE/NEIGHBOR_RESULT、ROUTE_UPDATE/ROUTE_WITHDRAW/ROUTE_REQUEST/SEQNO_REQUEST、DATA、HOP_ACCEPT/BUSY、END_RECEIPT、APP_RESULT、SERVICE、CONTROL/CONTROL_OBJECT、OBJECT_CHUNK/OBJECT_ACK、TIME_SYNC、CHANNEL_NOTICE、DIAGNOSTICの意味を区別する。完全な識別子はsemantics.jsonを参照。numeric type IDは未凍結。

未所属ではDISCOVER/OFFERと、[参加状態別allowlist](identity-membership.md)に記載した当該transactionのbootstrapだけを許す。認証や承認を終える前のDATA／route／serviceは拒否する。bootstrapを発見と同義にしない。HOP_ACCEPTはそれ自体を再帰ACKしない。END_RECEIPTは新アプリmessageとしてreceiptを要求しない。

## 5. エンコーディング

C/C++ packed structのmemcpyをwire ABIにしない。固定幅、network byte order、enum予約範囲、上限、未知type処理を明示したencoder/decoderを持つ。len検証前にポインターを進めない。integer overflow、重複TLV、reserved bit、末尾ゴミをfuzz試験する。

暗号Providerの正規化方式と完全性対象を一意にする。同じ意味に複数canonical byte列がある場合の署名検証曖昧性を避ける。

## 6. 管理object

通常DATAは自動fragmentしない。認証済みcredential/control/configの上限は最大2048B、同時4object、10秒組立timeout。役割別profileはその下位の同時枠を選ぶ。未所属Joinのbootstrapは別枠で最大1024B、同時1、3秒まで。token、owner、total length、offset、chunk length、object digest、期限を検証する。

範囲外、重複、順不同、異なるpayloadの同offset、古いsessionを拒否または規定通り扱う。2048Bより大きいcertificate/log/OTAは、一つの無制限objectへ拡大せず、認証したmanifest＋bounded chunk streamへ分ける。snapshot/commit証拠もサイズ設計を行う。

## 7. 互換性

protocol majorが合わなければ参加拒否。minor featureは双方capabilityで交渉し、必須securityをdown-gradeしない。データMTUはpath制約として扱い、将来LoRa追加で大packetを黙って落とさない。

完全なgolden vectorには正常DATA128B、最短ACK、最大管理object、未知version、改ざん、再送round、別hopでの外側暗号、再起動を含める。

根拠：[ESP-NOW frame形式](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/network/esp_now.html)。暗号契約は[Security](security.md)、USBは[別文書](usb-protocol.md)。


## 8. 凍結しなくても守る接続契約

[semantics.json](../../protocol/semantics.json)が状態許可と保護範囲を定義する。numeric type IDやfield幅はnullのままにし、意味の規約と公開互換Wireを混同しない。

end不変部はNetwork、origin、Message ID、固定終端、配送契約、元の最大寿命、payload。hop可変部は前後hop、残hop、残forwarding予算、round、hop crypto counter。可変fieldをend AADへ入れて中継で破壊しない。remaining予算をhop側だけで保護する場合、侵害Relayによる虚偽の延長は終端の独立した時刻／認可検査がない限り完全には防げない。

Provider変更時は終端contextとdestination bindingを再検証する。Message ID不変でも新しいAADを同じnonceで再暗号化しない。暗号化済みの全bodyが250B以下である実encoder試験はG-WIRE/G-SECとして残す。122Bは実証済み長ではなく予算。

# セキュリティ契約

## 1. 脅威モデル

対象：部外者の盗聴・改ざん・偽装・replay・偽Join・無制限資源消費、通信分断、通常機器の再起動／保存中断。管理多数全員の悪意やRF妨害の完全排除までは保証しない。

中継器の侵害を考慮し、近隣認証だけで最終送信元の本人性を代用しない。承認済みRelayがpacketを破棄することまで暗号で防げない。防げるもの、検出するもの、運用で扱うものを分ける。

## 2. Providerの基準

標準の認証鍵交換を実装したSecurity Providerを使う。**初期の本線はEDHOC＋機器ごとの公開鍵Identity／RPK**。全員共通PSK一つを機器本人確認として使わない。

EDHOCは相互認証を行うが、アプリの参加許可を代わりに決めるものではない。暗号suite、method、credential符号化、ライブラリの固定commitは、容量・テストベクトル・第三者利用条件を確認してG-SECで凍結する。この文書は未選定実装を監査済みとはしない。

参考：[RFC 9528 EDHOC](https://www.rfc-editor.org/rfc/rfc9528.html)、[RFC 8613 OSCORE](https://www.rfc-editor.org/rfc/rfc8613.html)。OSCOREのnonce・再起動・replay設計も参考とするが、独自packetがそのままOSCORE準拠であるとは呼ばない。

## 3. 二つの保護境界

- **近隣保護**：実際の送信相手との認証済みlink context。mutable hop情報、credit、hop受理、経路制御を保護する。
- **終端保護**：送信元と固定した最終宛先／正当なサービスのcontext。payload、Message ID、意味のある不変headerを保護し、中継で書き換えない。

鍵は用途と方向とNetworkに分離する。hop鍵をend鍵や署名鍵へそのまま使わない。ヘッダのどこがimmutable AAD、どこがhop AADかを[Wire契約](wire-protocol.md)と同時に固定する。

ESP-NOW driverのencryptは既定falseだが、**通常アプリ／管理payloadのSDK認証暗号は必須**。これは平文運用モードではない。Peerを登録していない受信にもSDKで検証できる境界を作り、driverのLMK登録数と長期メンバー数を切り離す。driver CCMPを追加する拡張も、SDK認証の代用にはしない。

## 4. nonce・番号・再起動

同じ鍵で同じnonceを別平文に使用しない。保存済みcounterの範囲を事前に耐電断予約する方式、または新しい安全なsessionへ再確立する方式をProviderが保証する。RTC保持だけを電源断耐性として扱わない。

同一暗号frameを再送することと、hop/roundを変えて再暗号化することを区別する。変更された外側headerには新しいhop nonceを使う。E2E payloadの同一性と転送ラウンドは別。

再送キャッシュとreplay windowは別物。replay済みpacketへ既存receiptを再送してよい場合があっても、payloadを再適用してはいけない。受信側のreplay状態消失後に古いepochを受理する実装は禁止。

## 5. credential・鍵更新・削除

trust anchor、device private key、membership証拠、session secretを異なるstore名で扱う。秘密はログ・USB診断・crash dumpに出さない。フラッシュ暗号化、Secure Boot、debug制限は配備プロファイルとして管理し、eFuseの不可逆設定をSDKが黙って実行しない。

鍵更新は管理ログで確定し、短い旧新移行期間と失効条件を定義する。30分眠る端末が更新を逃したときは機器credentialから安全に再開できる経路を残す。失効済み端末へ新ネットワーク鍵を渡さない。

## 6. 管理者と制御

管理操作の署名だけでなく、許可された構成員・log index・前状態・commit根拠を検証する。大きなtermの自己申告は権威を持たない。自動チャンネル変更もこの制約に従う。

有効な管理者のクラッシュ耐性と、悪意ある投票者を許容するBFTは別。v1は前者を対象にする。

## 7. 入力と資源

長さ・型・版・fragment範囲を検証後に処理する。cookie未確認の相手に大きな組立領域を与えない。認証失敗を理由に直ちに全channel scanや全網rekeyを発火しない。失敗回数・入場制限は観測可能にし、秘密由来の詳細エラーを外部へ漏らしすぎない。

## 8. 必須試験

golden vector、相互認証失敗、他Network、署名変更、bitflip、重複、counter予約中電源断、鍵更新中Sleep、失効端末、偽高term、preauth flood、旧USBsession、暗号context容量境界を試験する。結果が出るまでsecure-readyを広告しない。

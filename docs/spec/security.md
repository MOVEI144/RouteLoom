# セキュリティ契約

## 1. 脅威モデル

対象：部外者の盗聴・改ざん・偽装・replay・偽Join・無制限資源消費、通信分断、通常機器の再起動／保存中断。合意のvoterは非悪意のcrash-recoveryを前提とし、任意のByzantine voterに対する合意安全性やRF妨害の排除は保証しない。

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

CORE_FIXED_250実装はこの契約を強制する。アプリDATAとEND_RECEIPTは常に`kFlagEndProtected`を要求し、未設定の受信frameは配達・転送の判断より前に診断付きで破棄する。通常送信経路（`MeshNode::send`）は常にflagを設定するため、平文DATAの運用経路は存在しない。Wire codec自体はlink-only制御frameのためにflag無し形式を受理し得るが、それはノードの受理規則とは別層である。

## 4. nonce・番号・再起動

同じ鍵で同じnonceを別平文に使用しない。保存済みcounterの範囲を事前に耐電断予約する方式、または新しい安全なsessionへ再確立する方式をProviderが保証する。RTC保持だけを電源断耐性として扱わない。

同一暗号frameを再送することと、hop/roundを変えて再暗号化することを区別する。変更された外側headerには新しいhop nonceを使う。E2E payloadの同一性と転送ラウンドは別。

再送キャッシュとreplay windowは別物。replay済みpacketへ既存receiptを再送してよい場合があっても、payloadを再適用してはいけない。受信側のreplay状態消失後に古いepochを受理する実装は禁止。

開発Providerはこの規則を次の構造で実装する。context毎（scope+network+sender+receiver+epoch）の永続window recordと、peer pair毎（同tupleからepochを除いたもの）の永続epoch floorを持つ。同epochのwindow recordが消失していれば新規受付せず拒否し（reject-or-rehandshake）、floorを下回るepochは常に拒否する。window・floorのcommit失敗は受理を巻き戻し、破損recordはIntegrityErrorとして扱いfresh contextへ落とさない。floor自体の消失は初期bootと区別できないため、信頼できる単調状態または外部再認証なしの完全なrollback防止は保証外のままとする。TX側counterはMessage IDやsequenceから導出せず、Provider所有の耐電断予約から採番する。

window・floor・TX counterの永続slotは公開のkeyless折り畳みから導出されるため、共有PSKを持つ内部者はNodeIdを選んで衝突を決定的に製造できる。衝突はcounter側ではcontext不一致の`Conflict`となり当該宛先への恒久TX不能に、replay側では他contextのrecord相互占有になる。dev profileではこの脅威を保証外とし、G-SECのidentity設計はslot導出に秘密saltを含め、衝突の狙い撃ちにcredential保有を要求することとする。

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


## 9. Entropyの起動契約

状態はUNINITIALIZED／SEEDING／READY／FAILED。鍵生成、session作成、cookie秘密の更新はREADY前に拒否する。READYは「hardware RNGが常時true random」の意味ではなく、認定したEntropy/DRBG条件が今有効であること。

RFを開始していないprovisioningでは、chip別手順で内部entropy源とADC/RF利用を排他し、十分なentropyを認定DRBGへseedする。内部源を停止してからADC/RFへ所有権を戻す。ADC計測でentropy条件が崩れる処理を同時実行しない。seed/reseed条件は選ぶProviderに従い、古いDRBG RAM像をboot越しに再利用しない。

固定版根拠：[IDF v6.0.3 RNG](https://github.com/espressif/esp-idf/blob/v6.0.3/docs/en/api-reference/system/random.rst)。この条件確認は実chipの乱数品質認定ではない。RF未承認を乱数取得のために無断TXで回避しない。

## 10. 発行者の認可と暗号の対象

hop AEADは直近の相手を認証するだけ。route origin／proxy／service provider／authorityは別の役割許可を必要とする。originのIdentity・世代・sequenceはoriginまたは正規Authorityの検証可能な証拠に結び、転送者が勝手に更新できない。可変metricはhop保護と分け、侵害Relayの虚偽metricやdropの完全防止は保証外とする。

Wire APIもこの分離を構造で表す。`open_link`成功は直近hopの認証のみで、originの終端検証は束縛された宛先での`open_end`成功に限られる。relayはlink受理済みframeをend検証済みとして扱わない。

基準線の認証済み制御配布はpairwise unicast。group共通MACを個々のorigin本人確認にしない。各fan-out送信も予算へ計上する。署名形式・証拠のキャッシュ・最終長はG-SEC/G-ROUTEに残し、未認定のorigin証拠から新sourceを作らない。

nonce予約、replay損失、store破損時の状態は[電源断契約](crash-time-resources.md)に従う。CRCやNVS世代は過去の完全なsnapshotの悪意ある復元を単独で検出できない。物理rollback耐性を要求するprofileは別の信頼できる単調状態／外部再認証が必要。

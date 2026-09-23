# 05 — 本番機器認証と鍵の運用（Issue #10）

## 1. 採用案と未認定の境界

設計用profile名を **RLPSEC1_EDHOC_M0_S2_GCM128** とする。既存EDHOC/RPK方針を維持し、以下を採用する。本書は選定・統合契約であり、独立監査、C3での実装成功、本番受入を示さない。開発Providerを本番へ自動昇格しない。

| 項目 | 設計の選定 |
|---|---|
| 鍵交換 | RFC 9528 EDHOC、method 0（双方署名）、suite 2（P-256/ES256/SHA-256、EDHOC内AES-CCM-16-64-128） |
| 鍵確認 | message_4をこのprofileでは必須。続いて用途・所属を結び付ける保護されたContextConfirmを双方確認 |
| 資格情報 | 機器ごとのP-256 RPKをCCSのcnf/COSE_Keyとして扱う。kidは正規公開COSE_KeyのSHA-256全32B |
| 実装 | libedhoc **v2.3.2 / c8857b62d66be3664d1694bbe4eea37c56c05d9e**、MIT。coreのcallback境界のみ採用（SDK v1 P2-1でこのcommitをupstreamのままvendor済み：[08](../sdk-v1/08-implementation-plan.md)、依存zcbor 0.8.1も同pin由来） |
| ESP32暗号backend | 固定ESP-IDF v6.0.3のPSA。Mbed TLS submodule **ce3f3485a121c100f58f36d700cb35b060f6e866**。別のTLS一式を重ねない |
| Host | 同じlibedhoc coreを小さいFFI adapterから使用。native PSA backendも固定版とsubmodule lockを記録 |
| 通常frame | 既存Wire v1のサイズを保つAES-GCM-128、16B tag、12B nonce。EDHOC suite内部AEADとは区別 |
| 交渉 | profileの一致を必須にする。未知method/suite/credential、draft PSK、PQC私用suiteへ自動fallbackしない |

EDHOCのsuite 2がAES-GCMだという主張ではない。EDHOC標準Exporterから、別の**RouteLoom application profile**として鍵を導出する選択である。CoAP/OSCORE相互運用を名乗らない。既存Wireの248B最大長を維持しつつ、このbindingを独立レビュー・共通vectorで確認する。RFCの既存vectorと、このapplication profile独自のvectorは別。

一次資料：[RFC 9528](https://www.rfc-editor.org/rfc/rfc9528.html)、[libedhoc固定README](https://github.com/kamil-kielbasa/libedhoc/blob/c8857b62d66be3664d1694bbe4eea37c56c05d9e/README.md)、[MIT license](https://github.com/kamil-kielbasa/libedhoc/blob/c8857b62d66be3664d1694bbe4eea37c56c05d9e/LICENSE)。ライブラリの自己説明を、そのままRouteLoomへの監査・性能証拠にしない。

## 2. 守る対象と限界

部外者の盗聴、改ざん、なりすまし、旧sessionの再投入、無許可Join、通常の電源断を対象とする。承認されたRelayのdrop、虚偽metric、全帯域妨害、複製した秘密鍵の二台を完全に区別すること、古い正当なFlash全体を物理的に復元する攻撃は、暗号通信だけでは防ぎ切れない。

署名済み古い設定も、世代の信頼基点を失えばfreshnessを証明できない。CRCは故障検出、署名は発行主体、単調世代は履歴を扱う別の仕組み。保護状態が壊れたら通常通信を止め、無認証へ降格しない。合意のByzantine耐性を追加で保証しない。

## 3. Identity・権限・credential

NodeIdは64bitの管理割当IDを維持し、MACや公開鍵の切詰めhashへ変更しない。SingleAuthorityがNetwork内のNodeIdとkidの一意なbindingを署名する。機器の交換は新credentialと明示binding更新、紛失した機器の同じ秘密鍵をコピーして代替しない。

credential CREDはdeterministic CBORのCCS（cnfにP-256 COSE_Key）。kid計算の公開COSE_Keyはkty=EC2、crv=P-256、x/y各32B、alg=ES256を固定し、秘密dを含めない。ID_CREDはkidで参照し、未知kidの公開credential取得は認証前の小さい組立枠で行う。取得できただけでは信用しない。

MembershipGrantはCOSE_Sign1/ES256。署名payloadはdeterministic CBOR配列 `[1, network_u32, node_u64, kid_bstr32, role_bits_u32, authority_generation_u64, membership_revision_u64, not_before_u64, not_after_u64]`。時刻単位はUTC秒。配列順、整数最短表現、長さ、署名の発行権を検査。credential最大256B、grant最大256B、認証前bootstrap object最大1024B、認証済みControlObject最大2048B。既存P0の上限を拡大しない。複数objectを無制限連結しない。

rolesはendpoint/relay/gateway/authorityを分離する。通常member鍵で任意originの新世代やserviceを発行してよいとはしない。Route originのIdentity・generation・sequenceの証拠は、origin署名objectを既存ControlObjectで運びキャッシュし、データ転送のmutable metricとは分ける。未検証の新世代広告は保留/拒否する。この署名配布の実装・容量確認なしに、侵害memberにも強いrouting認可を完成扱いにしない。

## 4. 四つの認証境界

| 境界 | 本人・権限の確認 |
|---|---|
| 隣接link | radio上の相手credential、現在のNetwork/Grant、MAC binding、双方向応答。近隣を替えても自分のmembershipは維持 |
| E2E | 指定したoriginと最終宛先のcredential。Relayは終端payload鍵を持たない。別宛先のreceiptは受けない |
| USB | Gateway credentialと許可Host credential、Network、boot、role、capability、方向を保護transcriptへ結合 |
| PC内IPC | OS peer資格＋ACL。USBのHost権限を全ローカルclientへ無条件に与えない |

E2EのEDHOCは既存の限定bootstrap転送で指定終端まで運ぶ。Relayが鍵交換を代理終端化しない。初期gateway_mirrorの実終端はGatewayであり、PCアプリ受領の証拠ではない。PCサービス終端は別のcapabilityが完成してから。

## 5. PR #6 P0への統合・key context

Authenticatorは検証済みcredentialの所有とtranscriptを持つproof handleを返す。AdmissionContextへ与える情報は呼出アプリが任意boolで偽造するものではない。proofだけではmembershipを発行せず、Grant検証・承認・管理記録commitを別に通す。BootstrapLinkContextからVerifiedBindingへの昇格は既存状態と失効世代を再検査する。

用途別EDHOC exchangeを実行し、同じ出力keyをlink/end/USBで使い回さない。ContextConfirmは既存BootstrapAuth/Reply内のprofile固有フェーズとして運ぶ。新たなMembershipStateやtype番号体系は作らない。

application Exporterのprivate-use labelはkey=32768、base_iv=32769（IANA登録済みを意味しない）。contextはdeterministic CBORで `['RouteLoom',1,purpose,network,initiator_node,responder_node,initiator_kid,responder_kid,initiator_role,responder_role,grant_revision_pair,wire_version,context_epoch,direction,capability_digest]`。purpose/link,end,usb、direction/I2R,R2I、kid/hash長を固定し、ContextConfirmでこのdigestの一致を検証する。出力はkey16B、baseIV12B。差異は拒否し、確認前は通常DATAを許可しない。[Exporter registry](https://www.iana.org/assignments/edhoc/edhoc.xhtml)

nonceはbaseIV XOR (zero32 || packet_counter64)。counterは各key・direction別に事前予約する。Message IDと別。link外側が変わる再送には新link counter、end AAD/payload不変なら元のend暗号列を再利用可能。Wireの16bit key epochはpair/purpose単位で重複使用しない。65535到達前に管理namespaceを切り替える明示移行が必要で、0へwrapしない。state喪失時に同じpeerのepochを再利用しない。

CCMやGCMを自作しない。context encoding、導出labels、key確認、Grant形式はこの設計の独立レビュー項目。vectorが完成するまで本番provider capabilityはfalse。

## 6. 導入から廃止まで

| 操作 | 担当と手順 |
|---|---|
| 初回鍵生成 | 安全なEntropy READY後にdevice内で生成。RF未起動時のIDF entropy/ADC排他を満たす。秘密鍵はhandleとして保持 |
| 信頼の導入 | 物理USB等の承認済みprovisioningでAuthority公開鍵、Network、期待fingerprintを確認。公開QRには公開ID/fingerprintのみ |
| 初回参加 | 発見→本人確認→利用側承認→SingleAuthority commit→Grant保存→近隣binding。承認待ちの通常DATA/relay不可 |
| オフライン | 事前に用意したAuthorityとtrustが現地にあればネット不要。管理者不在は新規承認/失効を保留。既存有効資格のresumeは別 |
| 再接続 | 有効なGrantとcounter/replay状態があれば既存context復帰。未知/破損ならfull EDHOC＋資格の再検証 |
| 鍵更新 | 新しいephemeral鍵でfull EDHOC。新contextの保存/確認後に切替。単なるkeyupdateを侵害回復と呼ばない |
| 紛失/失効 | Authorityでrevocationをcommit。到達中の近隣・経路・Host権限を停止。分断群への即時伝達は保証外 |
| 交換 | 新device鍵を登録、旧Grantを失効。旧pendingを新Nodeへ自動付替えしない |
| Network転用 | 旧所属失効/終了、旧鍵・spoolを隔離/消去する明示操作、新Networkへ新Grant。未送信旧payloadを自動転送しない |

Grantは最大24時間、12時間を更新開始の目安とする採用案。経過時間を信頼できないcold bootでは期限を検証したつもりにせず、Authorityとのchallengeに結び付く現在資格確認を要求する。Authority不在で時間を証明できなければ通常通信は保留。長期オフライン可用性と厳密な失効期限の両方を無条件には約束しない。

contextは24時間または送信2^32件より前に更新。旧新の受信重複許可は最大60秒、失効が判明した相手はoverlapなし。更新を逃したsleep端末は公開鍵credentialから再検証し、古いgroup secretで新鍵を得る手順にしない。

## 7. 保存と障害

| 境界 | 禁止と復旧 |
|---|---|
| counter範囲commit前の停止 | その範囲ではまだ送信しない |
| commit後の再起動 | 予約範囲の未使用分も捨て次を予約。key/direction/epochを同時に検証 |
| replay窓の消失 | 旧contextでDATAを受理しない。full再認証と新epochを要求 |
| Grant保存途中 | 旧有効Grantが安全なら維持、なければ承認待ち。RAM認証成功だけでMemberへ昇格しない |
| key store/台帳全損 | SECURITY_RECOVERY_REQUIRED。自動erase・同世代再発行不可 |
| 失効中の遅い認証応答 | 最新revocationを再検査して昇格拒否 |
| firmware rollback | storage schema、counter/epochの下限を維持。不可逆移行をpending image段階で行わない |

Secure Boot、Flash/NVS暗号化、debug制限、eFuse変更は独立した配備プロファイルと承認作業。SDK起動だけで不可逆設定を実行しない。秘密をIssue、診断、crash dump、通常ログへ出さない。

## 8. 資源予算と測定ゲート

C3/S3の初期予算：全体1handshake枠（用途間でも直列化）、preauth同時1、認証前1object1024B、2秒あたり新規高コスト認証1件、失敗backoff最大60秒。cookie/cheap parse→bounded assembly→credential/cryptoの順。source MACだけでなく全体CPU/RAM枠を制限し、memberのDATA/ACK用queueを分離する。

設計上の認証scratch上限は全体48KiB、live context32×256B=8KiBを仮予算とする。**ESP32（C3/S3）でのsizeof/内部heap/stack/Flash/処理時間の実測値は未取得**（SDK v1 P2-2）。hostでの計測（P2-1）は1 handshake session 3104B（64bit、ILP32見積約2.7KB、libedhoc context・作業arena 1280B・key store込み）、作業bufferの最大使用888B（256B CRED_x・32B kid）、method 0の全handshakeのstack約10KB（x86-64）で、C3の数値として扱わない（P3-1：証明書をEADで運ぶ参加交換で作業bufferの最大使用が1440Bになり、arenaを2048B・session 3880B〔ILP32見積約3.5KB〕に上げた）。libedhocの既定VLAを未検証長で使わず、custom bounded memory backendを使う（P2-1で実装：sessionごとの固定arena、heap・VLA無し）。C3全体budgetに収まらない場合は同時数を減らし、監査や長さ検査を削らない。

suite2の小さいkid参照handshakeでも、RouteLoomの証拠/断片headerを含めた総bytesとLR占有は実encoderで測る。2048B objectが無条件に少ない無線frameへ収まるとはしない。正常/未知kid/Grant更新/再起動を分けてbenchmarkする。

## 9. 進捗を混ぜない（補足コメントへの回答）

| 本番領域 | 今回の段階 | 確認できた既存コード/残作業 |
|---|---|---|
| 機器別本人確認 | 詳細設計・独立レビュー待ち | dev PSKはある。本番EDHOC統合コードの公開証拠は調査SHAに無し：SEC-I1 |
| 初回鍵生成・配備 | 詳細設計・実装証拠未確認 | CounterStore等は土台。production provisioning/Entropy手順はSEC-I2 |
| Join承認・所属保存 | 詳細設計・本番統合未確認 | P0 AdmissionContext/SingleAuthorityはある。Grantとproof接続はSEC-I3 |
| 更新・sleep復帰 | 詳細設計・本番統合未確認 | dev replay/counterとPowerはある。production rotationはSEC-I4 |
| 紛失・失効 | 詳細設計・本番統合未確認 | 管理台帳だけで配布/資格検証完成としない：SEC-I5 |
| Network転用 | 詳細設計・実装証拠未確認 | 旧spool/keys隔離と新GrantはSEC-I6 |

未公開・未push作業の有無は不明。ここで「誰も着手していない」と断定しない。P0が完了しても本番の本人確認・鍵配備・更新・失効は完成しない。G-SECの残りは選定実装のintegration、C++/Rust vector、侵害/電断試験、独立レビュー、C3/S3 HIL、本番配備受入。

受入はSEC01〜SEC12。新しい暗号成功のfixtureを捏造せず、RFC 9529の公開試験鍵はテスト専用として本番鍵と分離する。

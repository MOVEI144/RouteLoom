# レビュー補足 — 期限境界・信頼の更新・休眠復帰・検証契約

版：0.1-draft supplement / 2026-09-20。基点：PR #13 `ea5f67c09ed6024605f6fc74d6c0f96e8be8a095`。

[設計入口](../README.md)の追加契約。既存6Issueの範囲を補強するレビュー対象の設計であり、runtime実装、本番認証の承認、実機資格を追加したものではない。用途固有の設備状態、業務IDの意味、安全判断、業務DBはSDKに持ち込まない。以下の理由名は説明用であり、C/C++/Rustの新しい数値StatusやWire番号を予約しない。

## 1. 期限計算の算術境界（TX06/TX10、TX-I2）

[03の時計写像](../03-send-api.md)は次の順序で実装する。HostとDeviceの時計値を直接引かず、停止時間を含めた有効性と測定誤差をClock Providerが説明できる場合だけ使う。

1. 入力の整数型・単位・u64範囲、`1 <= ttl <= 30000`、`h0 <= h1 <= host_now`を検査する。bool、負値、NaN、丸められたJSON数値は使わない。
2. `D = H + ttl`はchecked add。overflowなら送信しない。Clock/bootが不明・変更・停止・逆行した場合は写像を無効化する。Hostのsuspendを含む経過時間を測れなければ再写像する。
3. `host_now >= D`なら残予算なし。写像の年齢は保守的に`host_now - h0 <= 5000ms`を要求する。範囲外は新しい認証済みTimeSampleを取得し、元期限は更新しない。
4. `remaining = D - h1`、`margin = 1 + ceil(ppm * (D - h0) / 1_000_000)`。既定案の1000ppmは両時計間の相対drift上界であり、各時計1000ppmを別々に保証しただけでは足りない。量子化・測定誤差を含むplatform根拠を残す。乗算もchecked/widened arithmetic、または商と余りで評価する。
5. **`remaining <= margin`なら新規dispatch禁止。** 先に`remaining - margin`をunsignedで計算しない。`safe_remaining = remaining - margin`を求めてから、`device_deadline = d + safe_remaining`もchecked addする。overflowをwrap/saturateして長い寿命に変えない。
6. 現在のDevice時刻が`device_now < d`なら時計不整合。`device_now >= device_deadline`なら送信しない。USB受信後、radio queue取出し時、再送時もboot・期限を再確認する。

算術上の「残予算なし」は、過去に一度も外へ送っていない証明ではない。`EXPIRED_BEFORE_DISPATCH`にできるのは外部write未開始を状態transactionで証明できる場合だけ。`DISPATCH_PREPARED`以降で送信有無が不明なら新dispatchを止め、元OperationIdの証拠照会/INDETERMINATEを維持する。late receiptを捨てたり、未実行へ巻き戻したりしない。

[deadline-vectors.json](deadline-vectors.json)はこの算術の設計参照例。`tests/test_host_readiness_addendum.py`が純粋Pythonの小モデルと境界列挙を検査する。実Clock Provider、C++/Rust、USB、停止時間の検証を代替しない。

## 2. Authority・Hostの資格更新と復旧（SEC-I2/I5/I6）

[05の機器鍵運用](../05-production-security.md)に加えて、Authorityの信頼鍵とUSB Host credentialの所有者・更新を扱う。初期製品は**承認済みの物理provisioningによる更新・復旧**を最小経路とし、自動root rollover、別の常駐認証製品、高度な合意を必須依存にしない。無線でroot鍵を更新する拡張は、下記契約の独立レビュー・codec・電断試験を通すまでUnsupported。

| 状況 | 必要な承認と動作 |
|---|---|
| 健全なAuthorityの計画交換 | 現在信頼しているAuthorityによる明示委任と、新鍵の所有証明を検査。管理者承認、Network、旧新kid、単調trust revision、対象、発効/終了条件、operation identityを結合する |
| Authority秘密鍵の漏えい・紛失 | **旧鍵による署名だけで復旧を承認しない。** 事前に別途信頼設定・保護したrecovery authority、または管理者による物理再provisioningが必要。どちらもなければ自動復旧しない |
| 旧新鍵の移行中に眠っていた端末 | 認証された遷移証拠を上限付きで検証できる場合だけ追従。旧鍵を無期限延命しない。必要証拠/時刻/世代が不明なら通常DATAは保留し、限定bootstrapまたは物理復旧 |
| USB Host credentialの計画更新 | 同じOSアプリPrincipalやdispatcherと同一視せず、認可済みの新Host credentialを配備。旧新権限の範囲/終了、session drain、旧session拒否を定める |
| Host credential漏えい・交換 | 旧資格を失効し、未知のpendingを別Host/new keyで再実行しない。別Hostへの操作台帳の引継ぎは既存Storeの検証済み復旧契約がない限り不明として隔離 |

認可状態の順序は`validated candidate -> staged durable -> activation authorized -> active durable -> old retired`。active trust revision、失効下限、候補digestを電断耐性のあるStorageで保持する。各境界の停止後は、直前の正当な状態またはRECOVERY_REQUIREDへ戻す。新鍵の受信だけで信頼しない。秘密鍵コピーによる機器交換や、古いFlash snapshotの自動復元で世代を戻す手順は禁止。

**鍵の移行猶予は認証contextの60秒overlapと別。** 新たな無期限猶予を既定にせず、対象profileに有限の終了条件、旧発行Grant/route証拠/USB sessionの失効方法を記載する。時刻不明では猶予が有効と推測しない。root compromise時は、知らせが届かない分断群の即時失効を保証しない。

回復用の秘密は通常Authorityと別の障害領域で保護し、SDKは公開trust/検証境界だけを持つ。独自暗号を追加せず既存Provider/COSE/Admission境界を使う。既存1024B bootstrap/2048B control上限に収まる共有形式が決まるまで新carrierを有効化しない。不可逆なeFuse設定や任意remote shellを復旧手段として自動実行しない。

追加試験はSEC07/SEC11の下位ケース：新鍵受信のみ拒否、侵害旧鍵だけの復旧拒否、候補保存/activation/retire各境界の停止、旧Grant・旧Host sessionの遅着、休眠端末の移行漏れ、recovery credential不在。すべて後続試験としてplanned_not_run。

## 3. 休眠端末とAuthority不在（SEC08/HIL10）

製品名やセンサー種別に依存しない`DEEP_SLEEP_REPORT`利用条件を明示する。端末が通信予算を決め、SDKは参加資格・時計・配送の状態を返す。SDKが重要度や平文fallbackを勝手に選ばない。既定案のGrant最大24時間/更新開始12時間をこの補足で延長しない。

| 起床時の条件 | 通信の扱い |
|---|---|
| Grant有効、信頼できる時刻、context/counter/replay健全 | warm resume。起床のたびに初回Joinへ戻さず、管理者の常時接続も要求しない |
| Grant有効、contextだけ更新が必要 | 許可された相手とbounded再認証。単なる隣接変更で所属を作り直さない |
| Grant期限切れ、またはcold bootで時刻不明 | 既存trustでAuthorityの現在資格確認/更新を試す。確認前に通常DATAを流さない |
| Authorityへ到達できない | AUTHORITY_UNAVAILABLE/TIME_UNCERTAIN等の理由とretry条件を返す。無限起床・無限探索・毎wakeでの予算リセットをしない |
| 明示失効・trust破損・counter喪失 | 通常通信停止。開発PSK/平文へ降格せず、明示した復旧へ |

資格の期限確認が必要な運用では、インターネット上のサービスではなく**ネットワーク内の認可Authorityへの到達性**が条件になり得る。ネット回線断とAuthority故障/不在を別の診断にする。AuthorityをGateway/PCのどこに配置するかは導入側が選び、SDKが特定配置を強制しない。

profileには`awake_budget_ms`、一wakeと長期双方の認証試行上限、探索上限、再試行間隔上限とjitter、既存睡眠/保存capability、信頼できる経過時間の条件を記載する。初期値は既存Power/Radio予算から取得し、この補足で第二の定数表を作らない。時刻不明でも小さいwake内予算を維持し、累積上限を証明できないときは無制限の再試行へ落とさない。

通信受付前のデータ保持・更新頻度・業務上の再通知は利用アプリの責任。`gateway_mirror`のEND_RECEIPTはPCアプリ保存の証拠ではない。SDKは業務DBへのACKを発行しない。アプリが独自の有界な保存確認を行うことは可能だが、その戻り通信もHost側の2件/分・burst16等の予算に含める。端末発イベント頻度を、そのままHost発操作頻度として換算しない一方、アプリが追加する逆方向メッセージを計上から除外しない。

測定はwarm、期限切れ、cold/time-unknown、Authority不在、鍵移行漏れ、複数端末同時起床を分ける。起床から資格確認/END_RECEIPT/アプリ応答を別々に計時し、battery-side energy、awake時間、再認証bytes、失敗後のsleep復帰を記録する。測定値は未取得であり、電池寿命や報告遅延を数値で保証しない。

## 4. Host/Gateway保存モデルの検証計画（CAP01〜10）

既存[長短台帳設計](../04-capacity-storage.md)を小さい決定的状態モデルへ落とす。これは後続のproperty/model test計画であり、この補足の算術テストが台帳モデルを実行したという意味ではない。

モデル状態：Host lineage・admission epoch/floor・key/hash・operation stage・dispatch intent・外部write開始証拠・結果commit、Gateway BootLease・lane・retired_through・slot/hash・MessageKey・terminal、時刻の有効性。通信queueと各Storageのdurable/volatile状態を分ける。

**探索案**：1〜2主体、1〜2Network、窓2〜3、operation2〜4から開始。submit/duplicate/conflict/cancel/query/SKIP/RETIRE、応答喪失・重複・順不同、Host/Device別停止、各commitの直前/直後、再接続、新BootLease、時計不明を列挙する。全構成無限証明とは呼ばず、状態数/深さ/seed/打切りを記録し、反例は最小traceとして保存する。

不変条件：

- 同じ`Network/Gateway BootLease/dispatcher/dispatch_seq`は新規SDK sendへ二度入場しない。同内容の再提出は照会相当、異hashはCONFLICT。
- Host受付commit前に外部送信しない。外部writeが始まった可能性を失った操作を「未実行」と断言しない。
- Host結果commitとGateway terminalを確認する前にRETIREで保護中slotを回収しない。未terminalの穴を越えず、旧seqは回収後も新規扱いしない。
- 同じbootでUSB sessionだけ更新してもlane/floorを失わない。新BootLeaseや空Storeへ旧要求を自動dispatchしない。
- 不明なepochを飛び越えてfloorを進めない。容量上限・scope・GETで保持延長禁止を維持する。
- 前提付き進行性も確認する。通信/Storage回復、十分なquota、有効期限と正当なterminal結果がある場合、commit済み結果は照会でき、RETIRE後に枠を再利用できる。安全停止し続けるだけを「解決」としない。

`ABANDON_TRACKING`は現在の04にある運用意図で、公開methodは未定義。実装時は`operations.abandon_tracking`相当の認可・同一要求キー・監査契約を先に追加する。所有するPrincipalまたは明示権限の管理者だけが、特定OperationIdについて、復元不能な不明証拠を残して追跡保護を終えられる。取消/未作用証明/再実行許可ではなく、同じcaller keyは再利用不可。新Wire番号を追加する根拠にもならない。

判定対象は不明で追跡中の操作に限定する。Gatewayの送信責任が存続する間は保護枠を解放せず、terminal化とHost側の証拠commitを待つ。将来のepoch退役は既存の連続prefix/各記録の保持条件を守る。SDKは業務上の現場確認手順やUIを実装しない。

## 5. 共通golden vectorの追加範囲（RX/TX/CAP/SEC/AP）

| 共有対象 | 固定すべき正常・異常の例 |
|---|---|
| Cursor / OperationId / scope | 最大幅、0/予約値、別Network/ACL、旧epoch、overflow、非canonical表現。CursorはHost/client間が対象で、deviceへ持ち込まない |
| canonical SendRequest | 省略既定値、hex大小文字、全options、0/128B、同key異意味、未知field、整数型違い |
| rx_events_v1 | boot lease/event seq、origin、session/sequence、0/1/128B、長さ詐称、旧schemaへの混入 |
| USB host_ops_v1 | SUBMIT/RECEIPT/QUERY_DISPATCH/RETIRE_THROUGH/SKIP/TIME_SAMPLE、全subtype長、旧boot、未来seq、stale sample、退役済み、deadline境界 |
| APPLIED Wire19 | RESULT/QUERY/ACK/STATUS、112B request/48B result、digest/発行元/lease、期限、矛盾結果、ACK連鎖防止 |
| CCS / MembershipGrant / trust更新 | deterministic CBOR、kid、署名対象、Network/roles/revision、期限、別発行権、改ざん。trust更新の形式未確定時は未対応のまま |
| Exporter context / ContextConfirm | purpose/link/end/USB、両kid、roles、grant revision、direction、capability digestを一項目ずつ変える負例。鍵確認前DATA拒否 |

**生産規則**：共有manifestにcase ID、形式version、基準SHA、bytes、期待decoded値/エラー、証拠種類を持たせる。該当するC++ encoder→Rust decoder、Rust encoder→C++ decoderの両方向を検査する。Host専用形式はその独立client/decoderで検査し、無関係なC++実装を追加しない。未実装formatのbytesを「安定ABI」として配布しない。

設計用Python encoderだけをoracleにせず、実runtimeで共通fixtureを読み、生成後の差分と負例拒否を照合する。RFC 9529の上流vector、RouteLoom固有application-profile vector、dummy cipherのサイズ例を分ける。公開テスト鍵だけを使い、本番秘密を含めない。

本補足ではdeadlineの算術参照vectorだけを追加する。他のWire/暗号vectorは後続作業であり、相互運用や暗号安全性を実証したとは扱わない。

## 6. 試験対応と完了条件

既存`scenarios.json`の62件のIDとplanned_not_runを維持する。以下を下位ケースとして関連付け、同じ試験基盤へ追加する。

| 関連ID | 追加する下位ケース |
|---|---|
| TX06/TX10 | remainingとmarginの前後/等号、u64上下限、時計写像の期限、suspend、late receiptと未送信証明の分離 |
| CAP05/CAP07/CAP08/CAP10 | retire/skip/commitの全停止点、scopeを跨ぐ同seq、旧boot、unknown、ABANDONの認可と未terminal拒否 |
| SEC07/SEC11 | Authority/Host鍵の計画交換と侵害復旧を分ける。root更新漏れ、独立recovery trust不在、保存途中停止 |
| SEC08/HIL10 | valid warm/期限切れ/cold時刻不明/Authority不在、同時起床、予算上限、電流・再認証bytes |
| RX01/RX07/TX01/AP03/SEC04 | 対象の独立encoder/decoderによる正常・負例共通vector |

BASE-I0と既存実装順は変更しない。算術境界をTX-I2、台帳モデルをCAP-I1/I2、本番trust復旧をSEC-I2/I5/I6、休眠条件をSEC-I4/HIL-I1へ含める。APPLIEDは引き続き後続。新規broker、別USB所有者、用途固有adapter、特定アプリの業務ACKをSDKへ追加しない。

## 7. 根拠と証拠の区別

[既存の根拠一覧](../sources.md)を継承する。[RFC 9528 Appendix D](https://www.rfc-editor.org/rfc/rfc9528.html#appendix-D)のcredential/identity/trust anchor/revocation検証と、RouteLoom独自の管理操作を区別する。EDHOC鍵交換の採用だけでroot更新や失効の配備手順まで標準化済みとは言わない。[RFC 9529](https://datatracker.ietf.org/doc/html/rfc9529)の試験資料も、独自application profileの認定とは別である。

本補足の内容はSDKの追加設計と設計用の算術モデル。既存のmain/PR #2/PR #6のruntime、feature-profiles、実機smoke記録、合格基準は変更しない。本番cryptoレビュー、Storage/時計/USB相互運用、RF/HILは引き続き未完了。

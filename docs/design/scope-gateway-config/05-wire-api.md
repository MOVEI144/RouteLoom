# 5. Wire・API・互換性

この登録表は**実装対象の設計契約**。既存decoderが対応済みという意味ではない。整数はunsigned big-endian、boolは0/1のみ、reservedは0、unknown必須field/enum/重複field/末尾余剰は拒否。C構造体をmemcpyして送らない。[契約JSON](contracts.json)と[宣言案](sdk-contract.h)を同時管理する。

## 5.1 既存登録を守る

| carrier | 既存 | 本設計の追加 |
|---|---|---|
| RLD1 v1 | Discover=1、Offer=2、Auth=3等 | Discover/Offerのbody version=2。header44Bとflags0を維持 |
| Wire v1 Service=21 | 予約型、専用dispatchは未接続 | payload v1、Query1/Descriptor2/Submit3/Receipt4/Pending5/Reject6 |
| Wire v1 Control=22 | 予約型 | payload v1、ChallengeQuery1/Challenge2/StatusQuery3/Status4 |
| ControlObject49 / Chunk50 / Ack51 | ChannelPlan kind1、RecoverySnapshot kind2 | ConfigPermit kind3、E2E/multi-hopを新たに接続 |
| USB FrameKind HostOps=19 | PR #13のsub1〜5 | Gateway 0x10〜0x13、Config 0x20〜0x23。既存subを変更しない |

**重要**：mainの49/50/51は宛先local・link-onlyとしてautonomy_sinkへ渡す。Configはend-protectedでルーティングする新しい入口が必要である。`end_protected + manifest kind3 + 正当なtransaction`の組だけConfig転送へ進め、link-only kind1/2は既存移行処理へ残す。Chunk/Ackはmanifestから確立した `(Network, origin, destination, object_hash, protection_class)` のcontextで分類する。認証失敗後に別parserへfallbackしない。既存kind1/2の意味を変えない。

## 5.2 Scope body

RLD1 headerは0:magic4、4:version1、5:type1、6:header_len2、8:total_len2、10:flags2、12:hint4、16:claimed_node8、24:txn_nonce16、40:capabilities4。

| offset | DISCOVER body v2 | OFFER body v2 |
|---:|---|---|
| 0 | version=2:u8 | version=2:u8 |
| 1 | class:u8 | density:u8 |
| 2 | scheme=1:u8 | reserved:u16 |
| 3 | flags=0:u8 | （reservedの続き） |
| 4 | generation:u32 | cookie16B |
| 8 | tag16B | （cookieの続き） |
| 20 | — | responder_nonce16B |
| 36 | — | class:u8 |
| 37 | — | scheme=1:u8 |
| 38 | — | flags=0:u16 |
| 40 | — | generation:u32 |
| 44 | — | tag16B |

body24/60B、総68/104B。legacy Discoverはbody0、Offerはbody36/version1。その他の長さは明示拒否。Requiredではlegacy拒否。Optionalでもv2不正をlegacyへ読み替えない。

HMAC入力は[Scope §2.4](02-discovery-scope.md)のexact bytes。Scope Bindingは `class:u8 || generation:u32 || scheme:u8 || scoped_or_legacy:u8 || discover_digest32 || offer_digest32` の71BをSHA-256する。legacyのclass/gen/schemeは0、scoped=0、両digestは実際のlegacy交換から計算する。domainは `RouteLoom/DSK/v1/auth-binding\0` を先頭へ付ける。これは旧AuthTranscriptに追加する新しいbindingであり、相手の未対応capabilityを無視しない。

## 5.3 Explicit Gateway payload

全てWire21、link＋end保護必須。外側origin/destinationは実際の送信者と指定Gateway/返信先を示す。scope1=Gateway SDK RAM、2=Host Receive RAM。通常DATAにこのpayloadを包んで互換を装わない。

| subtype | フィールド順（左から） | bytes |
|---|---|---:|
| Query1 | ver1/sub1/scope1/flags1、nonce16、expected_host_digest32 | 52 |
| Descriptor2 | ver/sub/scope/flags、echo_nonce16、token16、gateway_boot8、host_digest32、caps4、max_payload2、lease_ms4 | 86 |
| Submit3 | ver/sub/scope/flags、token16、gateway_boot8、payload_len2、reserved2、payload0..96 | 32..128 |
| Receipt4 / Pending5 / Reject6 | ver/sub/scope/flags、token16、gateway_boot8、ref_origin8、ref_session4、ref_sequence8、request_digest32、reason2、reserved2 | 84 |

Receipt reason=0だけが成功。Pending reason=1（待機）で終端にしない。Reject理由は2 TOKEN_STALE、3 HOST_UNAVAILABLE、4 CAPACITY、5 ROLE_DENIED、6 UNSUPPORTED、7 DEADLINE、8 CONFLICT。これはService局所reason表であり既存SDK Status番号の上書きではない。未知reasonはProtocolError。

token/nonce/boot/IDは0禁止、NetworkはWire v1値域。scope1ではhost digest全0、scope2では認証されたprincipalのSHA-256表現を使う。scope2で未指定/zero principalのany-host解決は許さない。payload0Bは正規の空メッセージとして支持するが、null pointerかつ長さ>0は禁止。

lease15秒のdescriptorに対して30秒lifetimeを受け付けない。`min(元要求残期限, descriptor残lease-不確かさ)`を利用者へ示し、要求lifetimeが超える場合は再resolveまたはENDPOINT_LEASE_TOO_SHORTで拒否する。SDKが利用者の要求を黙って短くすることも、leaseを延ばすこともしない。

ACK参照type21、Service専用dedup/receipt、end保護、最大128Bの処理をC++/Rust双方へ追加する。新relayが必要な経路はcapabilityで表示し、旧relayを含む未知経路では通常Node配送へfallbackしない。

## 5.4 Config canonical command

`RCC1`をCOSE_Sign1 payloadとする。固定header176B＋patch0..512B、最大688B。next_revisionはexpected_revision+1、overflow拒否。no-opは発行前NO_CHANGE。空patchは正規の更新ではない。

| offset | field | bytes |
|---:|---|---:|
| 0 | magic RCC1 | 4 |
| 4 | version=1 / flags=0 | 1+1 |
| 6 | namespace / schema / field_count | 2+2+2 |
| 12 | Network / target / authority | 8+8+8 |
| 36 | authority_generation / authority_sequence | 4+8 |
| 48 | config_operation_id | 16 |
| 64 | expected_revision / next_revision | 8+8 |
| 80 | base_snapshot_hash / next_snapshot_hash | 32+32 |
| 144 | target_boot / challenge_nonce | 8+16 |
| 168 | apply_within_ms / patch_len / reserved | 4+2+2 |
| 176 | sorted TLV patch | 0..512 |

TLV：field_id:u16、type:u8（bool1/u8=2/u32=3/bytes=4）、length:u16、value。数値は固定長、bool値は0/1、未知型/ID/重複/順序違反は拒否。SDK schemaのbool/u8は1B、最大field value96B。アプリ型は登録schemaが検証する。snapshot hashは `SHA256("RouteLoom/config-snapshot/v1\0" || namespace:u16 || schema:u16 || complete_sorted_TLV_snapshot)`。

本番案はtag18のCOSE_Sign1、protected `{1:-7, 4:bstr(authority_u64_BE)}`、unprotected空map、payload=RCC1、signature=ES256 raw R||S 64B。external_aadは `"RouteLoom/config-permit/v1\0" || Network:u64 || target:u64 || namespace:u16`。COSE Sig_structureの規則はRFC9052、ES256はRFC9053に従う。kidは検索ヒントであり、その値だけで権限を与えない。非最小CBOR、重複label、未対応crit、無許可header、detached payload、署名不一致を拒否する。

この制約下のCOSE overheadは最大86B、permit最大774B、転送quota1024B内。採用ライブラリ/実署名vector/鍵配備は#10の選定を共用し、独自署名実装はしない。設計用の署名長fixtureは署名検証成功を意味しない。

## 5.5 Config制御とobject転送

Control22：ChallengeQuery1=`ver/sub/ns2/schema2/reserved2/client_nonce16`（24B）、Challenge2はこの24B＋boot8＋challenge_nonce16＋revision8＋active_hash32＋valid_for_ms4（92B）。StatusQuery3=`ver/sub/ns2/opid16`（20B）。Status4=`ver/sub/ns2/opid16/decision_rev8/active_rev8/phase1/reserved1/reason2/active_hash32`（72B）。EnvelopeのNetwork/Nodeと署名permitの値も一致させる。

phaseはIDLE0/PREPARED1/DECIDED2/APPLY_INTENT3/APPLYING4/VERIFYING5/ACTIVE6/INTERRUPTED7/QUARANTINED8、unknownは拒否。reasonはStatusの既存分類＋Config局所detailを明示し、文字列だけで機械判定しない。

permitは既存38B manifest(kind3)、38+nB chunk(n≤90)、37B object ACKで分割する。最大1024Bで12chunk、COSE最大774Bなら9chunk。全体一件・10秒reassembly、元challenge/Host期限以内。hashはCOSE全体のSHA-256。範囲外、同offset異内容、digest不一致、未manifest chunkを拒否。object ACKのOkは**組立完了のみ**、設定適用成功はControl Status ACTIVEのみ。

認可前に1024Bを無制限確保せず、既存Admissionで認証済み管理相手・対象・予算を確認してから一枠を予約する。全chunkはE2E保護され、relayはhash/offsetを解釈して再組立しない。共有の転送engineにprotection-classとendpoint routingを追加し、旧migrationのlink-only経路はそのまま試験する。

## 5.6 USB/Host契約

FrameKind **HostOps=19**を再利用。既存schema1/sub1〜5は変更しない。追加capability案はbit3 `gateway_endpoint_v1`、bit4 `config_endpoint_v1`。bits0〜2を流用せず、実装時にPR #13採用HEADで衝突を再検査する。Hello認証transcriptへcapabilityを結合し、未交渉ならUnsupported。

追加inner bodyは共通 `schema:u8=1, sub:u8, payload_len:u16, payload`。長さ完全一致。request/replyはUSB request IDとsessionで対応し、replyはpayload先頭にresult:u16を追加する。これらは**通常creditを消費**する。既存Credit/KeepAlive用予約を勝手に無制限HostOpsへ広げない。

| sub | 方向・payload | 要点 |
|---|---|---|
| 0x10 HostRegister | H→G: network8/host_boot8/lease_ms4 | principalは認証session由来。reply:result2/token16/gwboot8/host_digest32/lease4 |
| 0x11 GatewayIngress | G→H: Service Submit prefix32/refMessageKey20/request_digest32/payload0..96 | token/sessionを確認しReceiveLog予約後にだけACK。最大184B＋共通4 |
| 0x12 GatewayIngressAck | H→G: token16/refMessageKey20/request_digest32/outcome2 | 失敗・容量不足を成功にしない。70B＋共通4 |
| 0x13 HostUnregister | H→G: token16 | 今回sessionが所有するrecordだけ失効 |
| 0x20 ConfigQuery | H→G: target8/ns2/opid16 | Gateway自身の結果で対象成功を代用しない |
| 0x21 ConfigPermit | H→G: target8/object_len2/COSE bytes≤1024 | 原本を転送し署名を書き換えない |
| 0x22 ConfigStatus | G→H: target8/ControlStatus72 | 対象からの認証済み結果を渡す |
| 0x23 ConfigChallenge | 双方向: target8/ControlQuery24またはChallenge92 | request IDで方向/形状を固定 |

HostRegister renewalは同じhost_boot＋同じUSB sessionなら同token、sessionが変われば新token。HostRegisterのclaimed bootはsecretでないが、現在のsession所有者へboundする。GatewayIngress/ACK用にpending8件分の双方向creditを配賦し、受理前に確保できなければBUSY。slow clientで無線Ownerを止めない。

Host APIは既存`API1`へ`gateway.resolve`と`config.get/propose/status`を追加し、一daemonを維持。JSONの数値64bitは既存の固定hex/decimal string規約を採用し、JS精度へ依存しない。本文はbase64または既存hexの**一方式をAPI版ごと固定**し、本設計例はhex。存在しないmethodを既存実装が使えると表示しない。

Gateway送信のcanonical schema2は、schema1の26B field配置を保ち、dest_kind=1のときpayload_len直前に `scope:u8, reserved:u8, endpoint_token16, gateway_boot8, egress_gateway8` を追加する（34B増）。payload上限96Bなので最大156B、既存SUBMIT固定108Bを加えて264B。schema1のNode=0は従来の意味、schema1のGateway未実装値をschema2に黙って変換しない。

再提出のkeyは認証principal/Network/operation_class/受付epoch/keyとcanonical hashへ結び、endpoint・egressの変更はCONFLICT。既存recordへ結果照会し、新しいkey/tokenを自動生成しない。configは別operation_class、Permitとconfig_operation_id16、Host OperationId24、wireMessageKey20を別に追跡する。

## 5.7 C/C++ APIとサンプル

[宣言案](sdk-contract.h)は既存の`rl_context_t`、`rl_send_options_t`、`rl_status_code_t`を再利用する。旧struct layoutを増やさず新しいversioned request/result型を足す。関数は非同期、copy-on-accept、caller-owned出力snapshot。Owner以外からの呼出は有界mailboxへ渡し、callback/ISRでblockしない。

Scope設定はkey bytesではなくProvider handle。Config command発行は認可済みissuer clientからのみ。ConfigProvider登録はfirmware起動時のローカル操作であり、無線から任意関数を登録できない。

```json
{"v":1,"request_id":"g1","method":"gateway.resolve","params":{"network":"0000000000000001","gateway":"0000000000000020","scope":"HOST_RECEIVE_RAM","expected_host":"<64 hex characters>"}}
```

```json
{"v":1,"request_id":"c1","method":"config.propose","params":{"network":"0000000000000001","target":"0000000000000030","namespace":1,"schema":1,"expected_revision":"7","base_hash":"<64 hex characters>","key":"<32 hex characters>","ttl_ms":5000,"patch":[{"field":1,"type":"u8","value":1}]}}
```

山括弧は説明用placeholderで、有効なfixtureではない。[examples.json](examples.json)に具体的な合成値を置く。API応答は常に正しいJSONで、受付・保存・最終受領・適用を別状態にする。

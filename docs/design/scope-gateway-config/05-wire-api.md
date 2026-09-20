# 5. Wire・API・互換性

**実装対象の設計契約**であり、このbranchのP0〜P5でportable codec・runtime・Host配線として実装済み（[README](README.md)の実装状況参照）。hardware/資格の証拠ではない。unsigned integerはbig-endian、boolは0/1、reservedは0。未知の必須値、重複field、末尾余剰、長さ不一致は拒否し、C構造体をmemcpyしない。[契約JSON](contracts.json)と[宣言案](sdk-contract.h)を同時管理する。

## 5.1 既存登録を守る

| carrier | 既存 | 追加設計 |
|---|---|---|
| RLD1 v1 | Discover1、Offer2、Auth3等 | Discover/Offer body version2。header44B・flags0 |
| Wire Service21 | 予約型 | payload v1: Query1/Descriptor2/Submit3/Receipt4/Pending5/Reject6 |
| Wire Control22 | 予約型 | payload v1: ChallengeQuery1/Challenge2/StatusQuery3/Status4 |
| ControlObject49/Chunk50/Ack51 | ChannelPlan kind1、RecoverySnapshot kind2 | ConfigPermit kind3、E2E multi-hopの接続 |
| USB HostOps19 | PR #13 schema1/sub1〜5 | Gateway 0x10〜0x13、Config 0x20〜0x23 |

mainの49/50/51は宛先local・link-onlyとしてautonomy_sinkへ渡す。Configには**end-protectedでルーティングする新しい入口**が必要。end保護＋manifest kind3＋正当なtransactionをConfigへ、link-only kind1/2は既存移行処理へ分類する。Chunk/Ackはmanifestで確立した `(Network, origin, destination, object_hash, protection_class)` で分類。旧処理を別意味へ変更したり、認証失敗後に別parserへfallbackしたりしない。

## 5.2 Scope bodyと認証文脈

RLD1 header offset：0 magic4、4 version1、5 type1、6 header_len2、8 total_len2、10 flags2、12 hint4、16 claimed_node8、24 txn_nonce16、40 capabilities4。

| body offset | DISCOVER v2 | OFFER v2 |
|---:|---|---|
| 0 | version2:u8 | version2:u8 |
| 1 | class:u8 | density:u8 |
| 2 | scheme1:u8 | reserved:u16 |
| 3 | flags0:u8 | reservedの続き |
| 4 | generation:u32 | cookie16B |
| 8 | tag16B | cookieの続き |
| 20 | — | responder_nonce16B |
| 36 | — | class:u8 |
| 37 | — | scheme1:u8 |
| 38 | — | flags0:u16 |
| 40 | — | generation:u32 |
| 44 | — | tag16B |

body24/60B、総68/104B。legacy Discoverはbody0、Offerはbody36/version1。Requiredはlegacyを拒否し、Optionalも不正v2をlegacyへ読み替えない。

MACのexact入力は[Scope §2.4](02-discovery-scope.md)。Auth bindingの中身は `class:u8 || generation:u32 || scheme:u8 || scoped:u8 || discover_digest32 || offer_digest32`（71B）。先頭にASCII `RouteLoom/DSK/v1/auth-binding`＋NULを付けSHA-256する。legacyはclass/gen/scheme/scopedを0、両digestは実legacy交換から計算する。旧AuthProviderがこのbindingを処理できなければRequired利用不可。

## 5.3 Gateway Service payload

全てWire21・link＋end保護必須。外側origin/destinationは実送信者と指定Gateway/返信先。scope1=Gateway SDK RAM、2=Host Receive RAM。通常DATA/EndReceiptへのcastはしない。

| subtype | field順 | bytes |
|---|---|---:|
| Query1 | ver1/sub1/scope1/flags1、nonce16、expected_host_digest32 | 52 |
| Descriptor2 | ver/sub/scope/flags、echo_nonce16、token16、gateway_boot8、host_digest32、caps4、max_payload2、lease_ms4 | 86 |
| Submit3 | ver/sub/scope/flags、token16、gateway_boot8、payload_len2、reserved2、payload0..96 | 32..128 |
| Receipt4/Pending5/Reject6 | ver/sub/scope/flags、token16、gateway_boot8、ref_origin8、ref_session4、ref_sequence8、request_digest32、reason2、reserved2 | 84 |

Receipt reason0のみ成功。Pending reason1待機。Reject理由は2 TOKEN_STALE、3 HOST_UNAVAILABLE、4 CAPACITY、5 ROLE_DENIED、6 UNSUPPORTED、7 DEADLINE、8 CONFLICT。Service局所reasonであり既存Status番号を上書きしない。未知値はProtocolError。

nonce/token/boot/IDは0禁止、NetworkはWire v1値域。scope1のHost digestは全0、scope2は認証済みprincipalのSHA-256表現で、未指定any-hostは禁止。payload0Bは正規の空メッセージ。null pointerかつ長さ>0は拒否。

lease15秒のdescriptorに30秒lifetimeは受け付けない。要求が残lease−不確かさを超える場合は再resolveまたはENDPOINT_LEASE_TOO_SHORT。利用者のlifetimeを黙って短くしたりleaseを延長したりしない。

ACK参照type21、Service専用dedup/receipt、end保護、最大128BをC++/Rustへ追加する。旧relayがdropする経路は失敗/timeoutの可能性を明示し、通常Node成功で代用しない。

## 5.4 Config canonical command

RCC1をCOSE_Sign1 payloadとする。header176B＋patch最大512B=最大688B。next_revision=expected+1、overflow拒否。空/no-op patchは発行前NO_CHANGEで、revisionを消費しない。

| offset | field | bytes |
|---:|---|---:|
| 0 | magic RCC1 | 4 |
| 4 | version1 / flags0 | 1+1 |
| 6 | namespace / schema / field_count | 2+2+2 |
| 12 | Network / target / authority | 8+8+8 |
| 36 | authority_generation / authority_sequence | 4+8 |
| 48 | config_operation_id | 16 |
| 64 | expected_revision / next_revision | 8+8 |
| 80 | base_snapshot_hash / next_snapshot_hash | 32+32 |
| 144 | target_boot / challenge_nonce | 8+16 |
| 168 | apply_within_ms / patch_len / reserved | 4+2+2 |
| 176 | sorted TLV patch | 0..512 |

TLVはfield_id:u16/type:u8/length:u16/value。typeはbool1,u8=2,u32=3,bytes4。数値の長さ固定、最大value96B、field上限16、strict ascending ID。未知型/ID/重複/順序違反は拒否する。アプリ値は登録schemaが検証する。

snapshot hashは `SHA256("RouteLoom/config-snapshot/v1\0" || namespace:u16 || schema:u16 || complete_sorted_TLV_snapshot)`。署名前にbaseからpatchを適用してnext hashを計算し、対象も再計算して照合する。[config-example.json](config-example.json)は具体的なbytes/hash例であり、署名付きの実行許可ではない。

本番案：COSE tag18、protected `{1:-7,4:bstr(authority_u64_BE)}`、unprotected空map、payload=RCC1、ES256 P-256のraw R||S署名64B。external_aadはASCII `RouteLoom/config-permit/v1`＋NUL＋Network8＋target8＋namespace2。RFC9052 Sig_structure/RFC9053に従い#10の正式Providerを共用する。kidは検索ヒントであり権限ではない。

重複label、非最小/indefinite CBOR、未対応crit/header、detached payload、別curve/key用途、署名不一致を拒否する。限定形状のoverhead最大86B、permit最大774B、quota1024B内。ゼロ署名による長さfixtureを署名検証成功と扱わない。実署名vector・独立cryptoレビューは別gate。

## 5.5 Config制御・object転送

Control22 payloadは次の固定形：

- ChallengeQuery1：ver/sub/ns2/schema2/reserved2/client_nonce16=24B。
- Challenge2：同24B（sub2、client_nonceをecho）＋boot8＋challenge_nonce16＋revision8＋active_hash32＋valid_for_ms4=92B。
- StatusQuery3：ver/sub/ns2/opid16=20B。
- Status4：ver/sub/ns2/opid16/decision_rev8/active_rev8/phase1/reserved1/reason2/active_hash32=72B。

phaseはIDLE0/PREPARED1/DECIDED2/APPLY_INTENT3/APPLYING4/VERIFYING5/ACTIVE6/INTERRUPTED7/QUARANTINED8。

Config局所reason表：0 OK、1 IN_PROGRESS、2 STALE_REVISION、3 BASE_HASH_MISMATCH、4 INVALID_PATCH、5 DEADLINE、6 AUTHORITY_DENIED、7 UNSUPPORTED、8 CAPACITY、9 STORAGE_FAILURE、10 APPLY_INTERRUPTED、11 VERIFY_FAILED、12 RECOVERY_REQUIRED、13 MAINTENANCE_BUSY、14 NO_CHANGE、15 RESULT_EXPIRED。未知値はProtocolError。C Statusは同名の既存分類へ写像し、詳細はこのu16を保持する。新規申請拒否のphaseはIDLEでありACTIVEではない。

permitは既存38B manifest(kind3)、38+nB chunk(n≤90)、37B object ACKで運ぶ。1024Bなら最大12chunk、774Bなら9chunk。全体一件・10秒reassembly、元challenge/Host期限以内。hashはCOSE全体のSHA-256。未manifest、範囲外、同offset異内容、digest不一致を拒否する。ACK Okは組立完了だけ、適用成功はStatus ACTIVEだけ。

最初の1024B確保前に認証済み管理相手/対象/予算をAdmissionで確認。relayは再組立せずE2E bytesを転送する。失効・状態変更後は組立済みでも再検証する。protection-class別dispatchを追加し、旧ChannelPlan link-only経路を壊さない。

## 5.6 USB登録とcredit

USB FrameKind HostOps=19、既存schema1/sub1〜5は不変。実装済みcapabilityはbit3 gateway_endpoint_v1、bit4 config_endpoint_v1。Hello認証へ結合し未交渉はUnsupported。bridgeは`attach_gateway`/`attach_config`でendpointを接続した時だけ対応bitを広告する（attach＝広告であり、未attachのbuildはbitを立てない）。firmware側は`CONFIG_ROUTELOOM_CAPABILITY`の同bitがONの時だけattachし、OFFなら未attach・未広告のまま全opがUnsupportedを返す。実装時に#13採用HEADの衝突を再検査した（本branchで対応済み）。

新inner共通形はschema:u8=1/sub:u8/payload_len:u16/payload。replyはpayload先頭result:u16。完全長を検査しUSB session/request IDで対応付ける。全て通常creditを消費し、既存Credit/KeepAlive予約を無制限HostOpsへ拡張しない。

| sub | payload / 方向 |
|---|---|
| 0x10 HostRegister | H→G: Network8/host_boot8/lease_ms4。reply: result2/token16/gwboot8/host_digest32/lease4 |
| 0x11 GatewayIngress | G→H: Service Submit prefix32/refMessageKey20/request_digest32/payload0..96。最大180B＋共通4=184B |
| 0x12 GatewayIngressAck | H→G: token16/refMessageKey20/request_digest32/outcome2。70B＋共通4=74B |
| 0x13 HostUnregister | H→G: token16。現在sessionが所有するrecordのみ失効 |
| 0x20 ConfigQuery | H→G: target8/ns2/opid16。Gateway受領で対象成功を代用しない |
| 0x21 ConfigPermit | H→G: target8/object_len2/COSE bytes≤1024。署名原本を転送 |
| 0x22 ConfigStatus | G→H: target8/ControlStatus72 |
| 0x23 ConfigChallenge | 双方向: target8/ControlQuery24またはChallenge92。request IDで形を固定 |

USB result/outcomeは0 OK、1 BUSY、2 STALE、3 DENIED、4 UNSUPPORTED、5 INVALID、6 STORAGE、7 INDETERMINATE。IngressAck 0はReceiveLogへ実格納済みの場合だけ。receipt/digest/messagekeyの照合前に信用しない。

HostRegisterのprincipalは認証session由来。同じHost boot＋同じUSB sessionでのrenewは同token、sessionが変われば新token。GatewayIngress/ACKはpending8件分の双方向creditを受理前に予約し、slow readerで枯渇したらBUSY。DATA/ACKとcounter順序を既存Owner/writerで直列化する。

## 5.7 Host canonical/API

既存API1へgateway.resolve・gateway.getとconfig.challenge/status/propose/getを実装済みで追加し、一daemonを維持。64bit IDは既存固定hex/decimal string、本文はこのAPI版ではhex一方式。client申告のprincipalを信用せずOS/USB認証を使う。`routeloomctl`にも同名subcommandがある（実例は[README](README.md)のCLI節）。

Gateway canonical schema2は既存26B field形を保ち、dest_kind=1のpayload_len直前に `scope:u8/reserved:u8/token16/gateway_boot8/egress_gateway8` を加える（34B）。payload≤96で最大156B、SUBMIT固定108Bを加え264B。schema1 Node=0はそのまま、schema1の未実装Gatewayを自動変換しない。

egress_gatewayは送信に使うローカル出口、destinationは最終Gateway。どちらもcanonical hashへ含める。Host keyのscopeは認証principal/Network/operation_class/受付epoch/key。別token/egressで同keyを再提出したらCONFLICT。再接続で新key/新tokenを作って自動再実行しない。

Configは別operation_class。Config operation ID16B、Host OperationId24B、wire MessageKey20Bを区別する。APIの受付とConfig Status ACTIVEを別の結果にし、全エラーを正しいJSONで返す。

## 5.8 C/C++ APIと例

[sdk-contract.h](sdk-contract.h)は既存rl_context_t/rl_send_options_t/rl_status_code_tを再利用する宣言案。旧struct layoutを増やさずversioned request/result型を追加。APIはcopy-on-accept・非同期。ISRやradio callbackからblocking呼出ししない。endpointはbounded参照でretain/release、resultはcallback中borrowed、保存したいアプリはcopyする。

Scopeは鍵bytesでなくProvider handle、Config発行はローカルsetupで認可されたissuerに限定。ConfigProvider登録はfirmware側の操作であり、無線で任意関数を登録できない。

```json
{"v":1,"request_id":"g1","method":"gateway.resolve","params":{"network":"0000000000000001","gateway":"0000000000000020","scope":"HOST_RECEIVE_RAM","expected_host":"<64 hex characters>"}}
```

```json
{"v":1,"request_id":"c1","method":"config.propose","params":{"network":"0000000000000001","target":"0000000000000030","namespace":1,"schema":1,"expected_revision":"7","base_hash":"<64 hex characters>","key":"<32 hex characters>","ttl_ms":5000,"patch":[{"field":1,"type":"u8","value":1}]}}
```

山括弧は説明用placeholder。[examples.json](examples.json)は具体的な合成値。両methodは現行daemonで実装済み（dev profile・EXPERIMENTAL。capability未交渉・ACL不足・未登録ではhonestな拒否/未解決を返す）が、ここの値はfixtureであり実在のnetwork/operation/keyを意味しない。`gateway.resolve`は自host endpointのlive bindingだけを答え、remote Gatewayのresolveは`resolved:false`で返す。

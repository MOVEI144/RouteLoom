# 2. Discovery Scope Key

## 2.1 採用案

既存RLD1 header/version/typeを維持し、DISCOVER/OFFERの**body v2**を追加する。新しいcarrierやreserved flagは作らない。別scopeへの不要応答と高価な認証処理を抑えるフィルタであり、認証・承認・DoS完全防止ではない。

MACは**HMAC-SHA-256の左128bit**。32Bの安全な乱数鍵をProviderで生成/導入する。Issue #14の96bit案より4B増えるが、既存の160B枠に収まり、切詰めを128bitに揃えられる。RFC 2104/4231は[一次資料](08-decisions-sources.md)を参照。標準primitiveの使用だけでこのbinding protocolを監査済みとしない。

`ScopeRef`はローカルopaque handle。raw keyをDiscoveryConfig、通常API、診断、公開QRへ返さない。fixtureの公開合成入力は配備に使えないテスト専用値として分離する。本番共通の既定鍵、短い人間のパスワードは提供しない。

## 2.2 Scopeとモード

Scope classはMember=1、Commissioning=2。初期runtimeは同時に一つの選択scopeだけを探索・応答し、各scopeでcurrent/previousの最大2世代を持つ。multi-scope wildcard探索は未対応。Commissioningでも対象Networkを事前設定する。Network=0の全網参加探索はNETWORK_REQUIREDで拒否し、将来の未知Network enrollmentとは分ける。

| mode | 送信/受信 | 失敗時 |
|---|---|---|
| Off | Scope extensionを使わない既存静的/発見構成 | 既存挙動をこの設計だけで変更しない |
| OpenLegacy | 明示opt-inのbody空/v1 OFFER | 本番のscoped separationを広告しない |
| OptionalMigration | scopedを先行。許可された別attemptでlegacy可能 | 不正tag付きframeをlegacy扱いしない。全網の不要応答ゼロは保証しない |
| Required | v2かつ正しいscope tagの組だけ進める | missing/wrong/unknown generationは無言drop。鍵欠損でOpenへ降格しない |

OptionalMigrationのlegacy fallbackは同じnonceの途中降格ではなく、新nonce・別transcriptの明示attempt。追加attemptも元のawake/deadline内。最大1回のlegacy attempt、移行許可期限は最大24時間、経過不明の再起動ではRequiredへ戻す。運用者が新旧inventoryを確認して終了する。旧responderはv2 DISCOVERにも応答し得るため、混在群に全体抑制は保証しない。

Requiredはproductionの推奨値であって既存SDKのdefault変更ではない。正式Identity/Admission Provider未認定ならRequiredでもEXPERIMENTALのまま。

## 2.3 経路と状態を変えない

Scoped検証成功は`ScopeMatch`（local、短寿命）だけ。`AuthenticatedPeerProof`、Membership、VerifiedBindingを直接生成しない。

処理順序：長さ/型のcheap parse → raw ingress budget → hint候補照合 → scope MAC検証 → 重複判定 → scope内density → candidate/transient予約 → cookie/OFFER → 既存の本人認証 → membership検証・保存 → BOUND → 双方向確認。

既存`handle_discover()`のhint前density加算はraw counterへ移す。別hint/別keyのframeはscope内densityにもcandidate/認証枠にも入れない。ただしraw RX/CPU/電波資源を一切消費しないという意味ではない。

Wi-Fi callbackではframeと**observed source/destination MAC**をコピーするだけ。現行Discovery RX APIはsourceのみなので、共通`DiscoveryRxMetadata`へdestも追加する。DISOVERはbroadcast宛てだけ、OFFERは自分のunicast宛てだけを許可し、packet本文の自称MACを用いない。

## 2.4 バイト形式とMAC文脈

詳細offsetとencoder規則は[Wire仕様](05-wire-api.md)。DISCOVER body24B、OFFER body60B、RLD1総長は68B/104B。現在のOFFER cookie16Bとresponder nonce16Bをそのまま維持する。

`hint = first4(HMAC(K, "RouteLoom/DSK/v1/hint\0" || class:u8 || Network:u64 || generation:u32))`をbig-endian u32として扱う。暗号証拠ではなくcheap filterである。衝突候補は最大2世代×1scopeだけ。hint一致でkeyを探索し続ける無制限loopはない。

DISCOVER tag入力：

```text
"RouteLoom/DSK/v1/discover\0"
|| full Network:u64 || observed requester MAC:6 || broadcast MAC:6
|| actual RLD1 header:44 || DISCOVER body prefix:8
```

OFFER tag入力：

```text
"RouteLoom/DSK/v1/offer\0"
|| full Network:u64 || requester MAC:6 || observed responder MAC:6
|| SHA256(exact accepted DISCOVER bytes):32
|| actual OFFER RLD1 header:44 || OFFER body prefix:44
```

prefixはtag直前まで。headerのtotal_lenにはtagを含める。generation/class/scheme、両Nodeのclaim、両nonce、capability、cookie、方向がこの入力で結合される。OFFERはrequestと同じgeneration/class、同じtransaction nonceをechoする。返答の自己申告だけで新しいkey世代へ移行しない。比較はconstant-time、未知version/scheme/flags/長さは失敗終了。

正式な認証transcriptにも`scope_binding = SHA256(class || generation || scheme || scoped_or_legacy || discover_digest || offer_digest)`を結合する。現在のAuthTranscriptにこの項目は無いため、Provider APIと共通vectorを更新する。旧Authenticatorが対応しなければRequiredを広告できない。Optionalでlegacyとしたattemptは別のbindingとして明示する。

## 2.5 Replay・資源・airtime

有効DISCOVERのkeyは(source MAC, txn nonce, class, generation)。32件・初見から8秒の有界表を使う。同key再受信でTTL、OFFER予定、nonce、candidateを更新しない。同keyの異内容はConflictとしてdrop。完了後も保持期間まではtombstoneとして残す。満杯時は新要求を抑え、保護中recordを追い出さない。

初期raw budgetは32frame/s、burst16、Scope MAC処理はOwner poll一回最大2件。通常DATA/ACKとは別の有界bootstrap queueを維持する。認証済みDATAの処理機会を先に確保し、Mac検証の大量入力でWi-Fi taskを塞がない。scope内の既存handshake1件・開始1件/s、candidate16、transient3、OFFER分散は維持する。

100台同時起床では参加完了時間を保証しない。乱数backoff＋既存awake予算で再試行し、有限active budgetを超えたら眠れる。Scope Keyが漏れた場合やcapture再送でもraw/dedup/認証上限が残る。一度の有効要求を100 responderが聞いた場合のOFFER分散も必要であり、Scopeは同scope内stormを消さない。

総RLD1 byte増分はDISCOVER+24、OFFER+24。実airtime、電池効果、外部Wi-Fi影響は測定対象で、PHY速度で割った値を実busy率と呼ばない。

## 2.6 鍵更新・欠損

世代u32は単調増加、0禁止・wrap禁止。active keyの永続commit/readback後に新世代を送信する。previousの受付期限は最大1800秒。期限・世代はduplicateで更新しない。再起動後にoverlap残時間が証明できなければpreviousを受け付けずcurrentだけ使う。

鍵更新途中は交換開始時の世代handleをpinするが、失効時刻を延ばさない。期限が来たらattemptを破棄しcurrentで新attempt。current欠損/entropy未準備では新しい発見送信を停止し、通常の既認証sessionを不必要に破壊しない。

休眠で更新を逃した端末の救済は、既存の有効な機器credentialによる承認された再配備経路または物理保守。Requiredを黙ってOpenにする救済はない。初期Configの汎用patchでraw Scope Keyを送らない。#10の鍵配備手順へ接続する。

## 2.7 診断と完了条件

raw RX、hint不一致、scope MAC拒否、未知世代、duplicate抑制、scope一致、legacy使用、candidate満杯、key unavailableを集約counterにする。key/tag/相手別の大量失敗ログを出さない。

runtime受入はS01〜S12（[ケース](cases.json)）。異key100 responder、capture再送、hint衝突、鍵欠損、新旧混在、scopeと本人認証の分離を実C++/Rust codec/Providerで検証してから実RFへ進む。

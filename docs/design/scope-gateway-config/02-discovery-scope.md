# 2. Discovery Scope Key

## 2.1 採用案

既存RLD1 header/version/typeを維持し、DISCOVER/OFFERの**body v2**を追加する。新carrierやreserved flagは作らない。不要応答と高価な認証処理を抑えるフィルタであり、本人認証・承認・DoS完全防止ではない。

MACはHMAC-SHA-256の左128bit、鍵は32Bの安全な乱数。#14の96bit候補から4B増やしても既存枠に収まり、tagを128bitに揃えられる。RFC 2104/4231は[一次資料](08-decisions-sources.md)参照。標準primitiveだけでbinding protocolを監査済みとしない。

ScopeRefはローカルopaque handle。raw keyをDiscoveryConfig、通常API、診断、公開QRへ返さない。公開合成fixtureは配備不可のテスト専用値として分離し、本番共通既定鍵や人間の短いパスワードは提供しない。

## 2.2 Scopeとモード

classはMember=1、Commissioning=2。初期runtimeは同時に一つの選択scopeだけを探索・応答し、current/previousの最大2世代を持つ。multi-scope wildcardは未対応。Commissioningでも対象Networkを事前設定し、Network0の全網参加探索はNETWORK_REQUIREDで拒否する。

| mode | 送受信と失敗時 |
|---|---|
| Off | 既存非scoped挙動を使う明示設定。Requiredから鍵欠損によって遷移してはならない |
| OpenLegacy | 明示opt-inのbody空/v1 OFFER。本番scoped separationは広告しない |
| OptionalMigration | scoped先行、別attemptでlegacyを明示許可。不正v2をlegacy扱いしない |
| Required | v2かつ正しいscope tagだけ進める。missing/wrong/unknown generationは無言drop、鍵欠損でOpen降格なし |

Optionalのlegacy fallbackは新nonce・別transcriptで最大1回、元awake/deadline予算内。許可期限は最大24時間、経過不明の再起動はRequiredへ戻す。旧responderはv2 DISCOVERにも応答し得るため、混在群の不要応答ゼロは保証しない。運用者がinventoryを確認して移行を終了する。

Requiredはproductionでの推奨であって既存runtime defaultの変更ではない。正式Identity/Admission未認定ならRequiredでもEXPERIMENTAL。

## 2.3 既存の認証と状態

ScopeMatchは短寿命のローカルfilter結果だけで、AuthenticatedPeerProof、Membership、VerifiedBindingを生成しない。

処理順序：cheap parse → raw ingress budget → hint候補照合 → scope MAC → dedup → scope内density → candidate/transient予約 → cookie/OFFER → 既存本人認証 → membership検証・保存 → BOUND → 双方向確認。

現行handle_discoverのhint前density加算はraw counterへ移す。別hint/別keyはscope内densityやcandidate/認証枠へ入れない。ただしraw RX/CPU/電波資源までゼロ消費になるわけではない。

Wi-Fi callbackはframeとobserved source/destination MACをコピーするだけ。現在のsource-only RX APIを共通DiscoveryRxMetadataへ拡張する。DISCOVERはbroadcast宛て、OFFERは自分のunicast宛てだけ許可し、本文の自称MACを使わない。

## 2.4 バイト形式とMAC文脈

[Wire表](05-wire-api.md)がoffset/定数の正本。DISCOVER body24B/総68B、OFFER body60B/総104B。既存cookie16Bとresponder nonce16Bを維持する。

hintはfirst4(HMAC(K, domain_hint || class:u8 || Network:u64 || generation:u32))をBE u32にする。domain_hintはASCII `RouteLoom/DSK/v1/hint`の末尾にNUL一つ。hintは暗号証拠ではなく、最大2候補の安価なfilter。

DISCOVER tag入力：domain_discover || full Network8 || observed requester MAC6 || broadcast MAC6 || actual RLD1 header44 || body prefix8。

OFFER tag入力：domain_offer || full Network8 || requester MAC6 || observed responder MAC6 || SHA256(exact accepted DISCOVER bytes)32 || actual OFFER header44 || body prefix44。

domain_discover/offerは同じprefixの末尾をdiscover/offerとしNUL終端。headerのtotal_lenはtagを含む。prefixはtag直前まで。class/gen/scheme、Node claim、nonce、capability、cookie、方向を結合する。OFFERはrequestと同じclass/gen/txn nonceをechoし、自己申告だけでkey世代を変更しない。constant-time比較、未知version/scheme/flags/長さは拒否。

正式AuthTranscriptにも `scope_binding = SHA256(domain_binding || class:u8 || generation:u32 || scheme:u8 || scoped_or_legacy:u8 || discover_digest32 || offer_digest32)` を追加する。domain_bindingはASCII `RouteLoom/DSK/v1/auth-binding`＋NUL。legacyのclass/gen/scheme/scopedは全0、digestは実legacy交換の値。この正規化は05とcontracts.jsonに一致させる。

現在のAuthTranscriptにこのbindingは無い。Provider APIと共通vectorを更新し、旧ProviderしかなければRequiredを広告不可にする。Optionalのlegacy attemptも別bindingとして扱う。

## 2.5 Replay・資源・airtime

dedup keyは(source MAC, txn nonce, class, generation)、32件・初見から8秒。再受信でTTL/OFFER予定/nonce/candidateを更新せず、同key異内容はConflict。完了後も保護期間内はtombstoneを残し、満杯で保護recordを追い出さない。

初期raw budget32frame/s・burst16、Owner poll一回最大2MAC。通常DATA/ACKとは別の有界bootstrap queueを維持する。同scopeのhandshake1件・開始1件/s、candidate16、transient3、OFFER分散も維持する。

100台同時起床では完了時間を保証せず、乱数backoff＋元awake予算で再試行する。capture再送・key漏えいでも予算は残す。Scope一致の100 responderによるOFFER分散も必要であり、Scopeだけで同scope stormは消えない。

増分はDISCOVER+24B/OFFER+24B。実airtime・電池効果・干渉は実測対象で、byteをPHY速度で割るだけの値を実busy率にしない。

## 2.6 鍵更新・欠損

世代u32は単調増加、0/wrap禁止。current keyの永続commit/readback後に送信する。previous受付は最大1800秒でduplicate更新不可。再起動後にoverlap残時間を証明できなければcurrentだけ使う。

進行中exchangeは使用した世代handleをpinするが有効期限を延長しない。失効したら破棄してcurrentで新attempt。current欠損/entropy未準備なら新発見を止め、既認証sessionを不必要に失効させない。

休眠でrotationを逃した端末は#10の正当な再配備経路か物理保守で回復する。Required→Openの自動救済、Config patchでのraw key転送は行わない。

## 2.7 診断と受入

raw RX、hint不一致、MAC拒否、未知世代、duplicate、scope一致、legacy使用、candidate満杯、key unavailableを集約する。key/tagや相手別の大量失敗ログを出さない。

S01〜S12（[台帳](cases.json)）を実codec/Providerで検証してからRFへ進む。正しいScope Keyと機器本人認証は別の検査である。

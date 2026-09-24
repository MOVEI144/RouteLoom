# 4. Small Remote Config

## 4.1 小さいdesired-state更新に限定する

単一Authority、一対象Node、一namespace、一つの有限patchを扱う。config generation、schema、権限、内容を同時に確認する。任意shell/GPIO作用、業務命令、OTA、Factory reset、Network転用、鍵素材、送信電力上限・実channelの直接変更は対象外。

アプリのheartbeat間隔はアプリの意味でありSDKの固定設定にしない。アプリが必要なら登録済みnamespace/schemaのConfigProviderを使う。未知namespaceや未実装optionを受け取るだけで無視しない。

## 4.2 初期schema

SDK namespace=1、schema=1。更新はfield ID昇順、重複なしのtyped TLV。削除/null/暗黙型変換はなし。既存snapshotへpatchを適用した**完全な次snapshot**を保存する。

| field ID | 項目・型 | 値域 | 適用条件 |
|---|---|---|---|
| 1 | diagnostics_level / u8 | 0 Off, 1 Errors, 2 Normal | payload/key dumpを有効にする値はない |
| 2 | discovery_enabled / bool | 0,1 | 実装済みDiscoveryへ接続。鍵/Required policyは変更しない |
| 3 | relay_allowed / bool | 0,1 | OFFはdrain、依存経路、管理到達性、停止許可を要する |
| 4 | migration_policy / u8 | 0 Observe,1 Manual,2 AutoGuarded | 未実装/未認定policyを有効にしない。実channelは別plan |

アプリnamespace=0x8000..0xfffeは明示登録。初期defaultはSDK namespace一つだけ有効。登録上限4で、容量は有効namespace数に比例して予約する。異なるnamespaceを一つのtransactionでatomicと呼ばない。

patch上限512B、field上限16、field値上限96B、snapshot上限512B、署名object上限1024B。一つでも超えれば受理前拒否。no-op patchは署名前にNO_CHANGEを返し、revisionやFlash書込みを増やさない。

## 4.3 Authorityと対象端末の台帳は別

Authorityのglobal `(generation, sequence, state_hash)`は全管理操作を直列化する。対象のConfigJournalは`(Network, target, namespace, config_revision)`を管理する。

例：global seq10→端末A、11→B、12→channel plan、13→A。Aは11/12を受け取らなくても、Aのexpected config revisionが正しければ13を適用できる。対象で`SingleAuthority.commit()`をそのまま呼び、global sequenceの連続受信を要求する実装は禁止。

Authority issuerは、canonical commandと復旧可能なoutboxを耐電断保存 → 実SHA-256でoperation_hashを計算 → 既存SingleAuthorityへcommit → commit/readback成功後にpermitへ署名 → 同じ署名blobを再送、の順。

対象は署名者と権限、許可されたAuthority generation、対象Network/Node/namespace、challenge、expected_revision、base hashを検証する。署名は「issuerがcommit後に発行した認可」の信頼契約であり、対象が分散合意のlog全体を独立検証した証明ではない。HA/Quorumは別gate。

`bind_operation_payload()`の現行非暗号学的helperは本番認可へ使用しない。SHA-256とCOSE Sign1のProduction Providerを#10と共通化する。鍵名やclaimだけでverified boolを作らない。

## 4.4 有効期限は対象端末のchallengeで制限する

Hostに届いたAPI期限を保ったまま、対象へConfigChallengeを要求する。対象が一つのnonce128を生成し、boot incarnation64、現在revision、ローカル単調expiryを保存する。challenge lifetime最大30秒。

署名commandはこのboot/nonceと`apply_within_ms`を含み、targetはchallenge発行時からの経過で検査する。host realtimeや無線の到着時刻を起点に寿命を付け直さない。issuerはHost/USB待ちも含む残予算を保守的に減らす。

challengeが失効・boot変更・時間不明なら、新しい設定を適用しない。既存署名を新challengeに貼り替えない。眠る端末への無期限保管は初期版Unsupported/WAKE_REQUIRED。APIのdeadline内で起床後に新たな署名操作を作れる場合だけ、アプリの明示した依頼として実行する。

## 4.5 Targetのtransaction

```text
IDLE
 → VALIDATING（認証・CAS・schema・期限・資源）
 → PREPARED（副作用なし、次snapshot/rollback手順）
 → DECIDED（次revisionと全snapshotを永続commit）
 → APPLY_INTENT（開始意図を永続commit）
 → APPLYING（非同期、Owner管理）
 → VERIFYING（実active値の照合）
 → ACTIVE（active revision/hashと結果を永続commit）
```

PREPAREDまでは取消可能。DECIDED以後の取消は遠端undoではなく、結果照会または新しい補償設定を要する。revisionはDECIDEDで消費する。apply失敗やrollback後もrevisionを戻さない。

`decision_revision`と`active_revision`、desired_hash/active_hash、phase、last_errorを別にGETで返す。受領/保存をCONFIG_ACTIVEへ自動変換しない。次の更新のexpected_revisionはdecision_revisionを使い、base_hashは現在のactive snapshotを使う。壊れた値を次patchへ引き継がない。

同ID同canonical digestは既存結果/進行を返す。同ID異内容はCONFLICT。古いrevisionはSTALE_REVISION。結果履歴回収後はRESULT_EXPIREDを返し、新規として再実行しない。1分1新規更新・burst1、結果8件を最低300秒保持、duplicateで延長しない。active transactionは一件のみ。

## 4.6 Provider契約

`validate`と`prepare`は副作用禁止。`apply(snapshot)`と`restore(snapshot)`はdesired-stateへのidempotent操作で、再起動後に同じ状態を復元できることが必要。`read_active`で実値を取得し、途中の操作をログ文字列だけで成功としない。

Providerは非同期completion tokenを返し、無線taskをblockしない。partial apply失敗時は前のactive snapshotを復元・readbackする。復元不能ならCONFIG_QUARANTINEDとして新更新を停止する。ボード全体を勝手にerase/resetしない。

複数subsystemへのpatchはprepareで全対象の予約を取り、apply中はSDK configuration epochの更新をOwnerで直列化する。外部から瞬間的な部分状態を一切観測できないという保証はしない。必要な場合は停止許可を要求する。不可逆な作用を持つProviderはこのAPIへ登録不可。

## 4.7 電源断と二重slot

一namespaceごとに完全なjournal recordを二重slotで保存する。recordはschema、保存世代、operation ID/digest、issuer metadata、decision/active revision、phase、前/次snapshot、署名permit、CRCを含む。1slot最大4096B、予約は2slot＋有界receipt履歴を含めて確認する。

write → NVS commit → readback/整合性検証の成功後だけ次phaseへ進む。別キーにrevisionとsnapshotを分けてatomicだと仮定しない。CRCは破損検出で、本人認証の代わりではない。NVSの実電断安全性とFlash寿命は#20/#11の試験対象。

NVS write amplification（実装から導出した回数であり、実測のwear値ではない）：target側は受理1件あたりjournal record3本（DECIDED・APPLY_INTENT・ACTIVE）× unsealed＋committed sealの2相write＝6 commit、加えてproviderのactive blob永続化が1 commitで計約7 commit。device issuer側は一操作あたりoutbox pending record2 commit＋SingleAuthority ledger record2 commit＋signed record2 commit＝6 commitで、superseded/cleared entryごとに2048Bのerase marker（0xFF blob）をさらに1 commit書き込む。結果record・challengeはRAMのみで書込まない。この重複writeは破損回復の代償であり、wear-leveling・寿命評価は#20へdeferする — 受理上限（1分1件）の運用でもこの書込み量を前提とする。

| 停止位置 | 復帰時の処理 |
|---|---|
| DECIDED前 | 旧active維持。未受理として期限/同IDを再照会 |
| DECIDED後・APPLY_INTENT前 | 新revisionを維持。boot変更でchallenge失効、初回applyしない。DECISION_EXPIRED/INTERRUPTED |
| APPLY_INTENT後・ACTIVE確定前 | 作用の有無を断定しない。前の確認済みactive snapshotへidempotent restoreし、APPLY_INTERRUPTEDを記録。復元不能は隔離 |
| ACTIVE確定後 | 保存されたactiveをboot時に復元する。これは新たな期限切れcommandの実行ではなく確定済み設定の継続 |
| 片slot破損 | 生存recordを既知のbaselineとして保持し、CONFIG_STORAGE_UNCERTAINで新規更新を止める。署名済み回復証跡を要求する |
| 両slot/必要metadata全損 | 明示的な再配備・新しい信頼世代が必要。revision0へ自動復帰しない |

遠隔のjournal回復は署名済みRCR2 recovery object（ControlObject kind4の専用lane、[Wire/API](05-wire-api.md) §5.5）で届ける。mode 0のAdoptKnownは生存recordのbaselineを採用し、mode 1のReprovisionは明示したbaselineを再配備する。いずれも新しいstore_generation・revision・snapshot_hashを運び、providerのreadbackと独立RLF1床の前進を確認してから通常intakeを復帰する。authority世代の移行は別のroot署名RTM1 trust-manifest（kind5、`trust.install`）で行い、targetのTrustViewが新しい鍵・世代を解決する。impaired状態で通常permit intakeは閉じたまま、replay床（store_generation）とresult dedupはrecovery laneにも効く。RLF1床自体の喪失は遠隔のRCR2で再生成せず、管理された再provisioningを要する。

未確定のdesired値をboot時に無条件適用しない。ACTIVE未確定なのに過去の一瞬の成功を断言もしない。遠隔の観測者へ古いACTIVE通知が遅着した場合もoperation/revisionで照合する。

## 4.8 Relay停止と保守排他

relay-off、Discovery停止、migration policy変更は既存Maintenance/RadioOwner/PowerCoordinatorへ接続する。中継中DATAを捨ててapply成功にしない。予定drain時間、依存endpoint、管理帰路、停止許可を再確認する。

唯一の管理経路を消す操作は初期版拒否。保守作業者が明示的にローカル回復経路を持つ場合の拡張は別profileにする。ACK送信と機能停止の分散atomicityは保証できないため、送信前に結果を永続化し、最後のACKを失えば同ID照会で結果を回復する。

実channel変更は既存の署名済みChannelPlanへ委譲し、Config setterがesp_wifi_set_channelを呼ばない。scope鍵rotationも#10/#14の専用手順。設定の到達不能を理由に自動的に旧revisionへ巻き戻さない。

## 4.9 SDK/Hostと公開条件

C API案・Control/object形式は[Wire/API](05-wire-api.md)。Hostの`config.get/propose/status`はOS認証されたprincipalに対して管理ACLを確認し、通常messages.send権限ではpermitを発行できない。Host成功応答は操作受付、ConfigStatus ACTIVEを受けた時点だけ適用成功を返す。

初期版は小さい局所設定の一対象更新まで。read-only preview/dry-runでも結果は提案時snapshotに対するものであり、後のCAS成功を予約するものではない。実装受入C01〜C14は[台帳](cases.json)。

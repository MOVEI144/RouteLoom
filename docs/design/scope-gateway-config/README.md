# Scope・Gateway・Small Config — 実装用設計

設計版 **0.1-draft / 2026-09-20**。対象：[Issue #14](https://github.com/MOVEI144/RouteLoom/issues/14)、[Explicit Gateway #16](https://github.com/MOVEI144/RouteLoom/issues/16)、[Small Remote Config #17](https://github.com/MOVEI144/RouteLoom/issues/17)。

**このbranchでは3機能がEXPERIMENTALのruntime実装済み（P0〜P5＋P6公開確認）。本番認証・実機認定・資格は未完了。** 既存の既定値（CORE_FIXED_250、`CONFIG_ROUTELOOM_CAPABILITY`の既定bitmap、scope既定Off、config既定n）は変えない。

## 利用者にとって何が変わるか

| 機能 | できるようにすること | 保証しないこと |
|---|---|---|
| Discovery Scope | 無関係な発見へ応答しない。合うscopeだけ本人確認へ進める | Scope Keyを知るだけの機器を信頼・参加承認しない |
| Explicit Gateway | 指定した出口と指定した受領境界まで配送する | 別Gatewayでの代行、RAM受領からの永続保存・アプリ成功の推定 |
| Small Config | 小さな設定を認可・保存・適用・照会する | OTA、任意コマンド、業務処理、秘密鍵配備、一般的exactly-once |

「合言葉が一致」「端末へ到達」「設定を保存」「動作へ適用」はすべて別の証拠である。

## 読み順

1. [共通契約と既存コードへの接続](01-integration.md)
2. [Discovery Scope](02-discovery-scope.md)
3. [Explicit Gateway](03-explicit-gateway.md)
4. [Small Remote Config](04-remote-config.md)
5. [Wire・API・互換性](05-wire-api.md)
6. [失敗条件と受入試験](06-acceptance.md)
7. [実装順序・完了条件](07-implementation.md)
8. [判断記録と一次資料](08-decisions-sources.md)
9. [その他の作業とIssue](09-backlog.md)

[数値・登録値の正本](contracts.json)、[設計例](examples.json)、[受入ケース台帳](cases.json)、[C API宣言案](sdk-contract.h)も同時に読む。宣言案はリンク可能な実装ではない（新機能のC ABIは依然未提供）。設計用encoder/小モデルの検査はC++/Rust runtime相互運用・暗号監査の代わりではない。

## 実装状況とmaturity（P6時点）

| 層 | 状態 |
|---|---|
| documented | 完了（本set） |
| implemented（codec・portable core・Host配線・dev profile identity） | 完了・**EXPERIMENTAL** |
| host/build tested | portable `ctest` 22件＋`cargo test --workspace`、firmware ON/OFF buildはCI |
| hardware tested | **単板USB/電源のみ実施**（2026-09-21、ESP32-C3 `94:a9:90:6a:ee:c4`、6.7節 — mesh/RF/HILは未実施で`hardware_tested`フラグはfalseのまま） |
| qualified | **未実施** |

`contracts.json`の`runtime_implemented=true`は「codec・portable実装・Host配線・dev profile identityが実コードとして存在しhostで試験済み」のみを意味する。`hardware_tested`・`qualified`・`signature_validation_tested`はfalseのまま。COSE/ES256の本番署名検証は未実装で、config permitは**dev HMAC profile**（domain分離された開発key、`config_dev.hpp`が「experimental・非production identity」と明示）。Discovery Scopeも**dev scope key**のまま。#10の正式Providerが来るまでproduction identityを名乗らない。Required-without-bindingは広告せず利用不可を返す実装（`AuthProfileUnavailable`）のまま。

### 機能flagとcapability

- **Discovery Scope**：mode（Off/OpenLegacy/OptionalMigration/Required）はruntime設定でbuild flagを増やさない。reference_nodeのdiscovery配線は`CONFIG_ROUTELOOM_DISCOVERY`（既定n、autonomy laneと共有）。Requiredはscope key未提供/binding不能で起動拒否し、legacyへ降格しない。
- **Explicit Gateway**：bridge_nodeの`CONFIG_ROUTELOOM_CAPABILITY` **bit3 (0x8)** がopt-in gate。ON→`attach_gateway`→HelloAckへbit3広告。OFF→未attach・未広告・全gateway opはUnsupported。
- **Small Remote Config**：target側はreference_nodeの`CONFIG_ROUTELOOM_CONFIG`（既定n、EXPERIMENTAL・dev HMAC明記）。bridge lane側はcapability **bit4 (0x10)** で同じくattach/広告をgate。
- `attach_gateway`/`attach_config`は接続時だけ対応bitを立てる。capabilityはHello transcriptへbindされる。未交渉opは常にUnsupported。

### CI（`.github/workflows/sdk.yml`）

`features`軸を追加：base matrixは全機能OFFのまま、`endpoints_on`（bridge_node、`CONFIG_ROUTELOOM_CAPABILITY=0x1f`）と`config_target_on`（reference_node、`CONFIG_ROUTELOOM_CONFIG=y`）をinclude。build後にsdkconfigへON/OFF両方向のgrepをかける。compile証拠のみ、hardware証拠ではない。

### 診断面

集計counterのみ（key・tag・per-source表は出さない）：

- Scope：`NeighborDiscovery::scope_stats()`（`discovery_scope.hpp`の`ScopeStats`、raw/hint/MAC/dedup/受付等12 counter）。
- Gateway：`GatewayDelivery::stats()`（`gateway.hpp`の`GatewayStats`、receipt/outcome/resolve/host ingress/malformed等）。
- Config：`ConfigJournal::stats()`（`config.hpp`の`ConfigStats`）、`ConfigTarget::control_denied()`/`object_acks()`、`ConfigGateway::replies_reported()`（`config_wire.hpp`）。
- 実機側は`FrameKind::Diagnostic`のreason eventが既存のdevice→Host診断laneへ流れ、Host側は`ADAPTER`がHelloAckのcapability bits（交渉状態）を、`DIAGNOSTICS`がevent ringを返す。struct getterは現行パターン同様portable APIの面であり、新たなwire dumpは追加していない。

### CLI例（`routeloomctl`）

```text
routeloomctl gateway-resolve --network <16hex> --gateway <16hex> --scope HOST_RECEIVE_RAM|GATEWAY_SDK_RAM [--expected-host <64hex>]
routeloomctl gateway-send --network <16hex> --epoch <16hex> --to <16hex> --scope HOST_RECEIVE_RAM|GATEWAY_SDK_RAM --payload <hex> [--key <32hex>] [--ttl-ms 1-30000]
routeloomctl gateway-get --id <opid>
routeloomctl config-challenge --network <16hex> --target <16hex> --config-namespace <u16> --schema <u16>
routeloomctl config-propose --network <16hex> --target <16hex> --config-namespace <u16> --schema <u16> --base-snapshot <hex> --field <id>:<type>:<hex> [--field ...] [--apply-budget-ms <u32>]
routeloomctl config-status --network <16hex> --target <16hex> --config-namespace <u16> --operation-id <32hex>
routeloomctl config-get --id <cfg-opid>
```

正確な引数は`routeloomctl`のusageが正本。ACL未許可・capability未交渉・未登録ではhonestな拒否を返す。

## 基点

main **610c5b27dd741a759051724fb9cc10c82b556314**（#2/#6採用済み）。ソースは同SHAのDocumentation artifact 10598423025、archive SHA-256 **1de4d28b3092d6ab9a3de759b551eef172d16c71775a1745dfbc5d527cd493bc**を取得・照合した。

Host APIとの接続確認には未マージPR #13 **6030baa7046c6d6dfe466df3071b58c0c6797139**を参照した。現在対応中のPR #13レビュー修正はこの設計で修正済み扱いにしない。採用時にSHA、API/USB登録値、OperationStore・deadline修正を再照合する。

## 最小の実装境界

Scopeは単独で実装可能。GatewayはSDK受領モードを先行し、Host受領モードはPR #13のReceiveLog・受領確認と合わせる。Configは単一Authority・一対象・一namespaceのdesired-state更新に限定する。Raft、Anycast、APPLIED実装やMesh OTAを3機能の完了依存にしない。

ただし本番有効化には#10の正式Identity/鍵/認可、実装試験、#11のHIL/RFが必要。設計を承認しただけで`qualified=true`にしない。

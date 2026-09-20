# 7. 実装順序とレビュー条件

## 7.1 このDraftへ積む順序

| 段階 | 変更内容 | 完了条件 |
|---|---|---|
| P0 契約 | 既存登録値/Admission/MessageKey/Clock、実codec goldenの雛形 | 設計例を双方でdecode、未知/不正形を拒否 |
| P1 Scope | Provider、bodyv2、hint/density、dedup、rotation、AuthTranscript binding | S01〜S12 portable、Requiredで旧auth利用禁止 |
| P2 Gateway SDK | role証拠、resolve/token、Service21転送、受理枠とReceipt | GW-SDKのGケース、既存Node128Bは不変 |
| P3 Gateway Host | HostOps拡張、ReceiveLog格納ACK、readiness、再接続 | 実C++/RustでACK喪失・Host停止・slot枯渇を再現 |
| P4 Config portable | schema、Issuer outbox、target challenge/CAS、journal、async provider | C01〜C14、各write/apply停止とglobal/per-targetの分離 |
| P5 Config接続 | E2E object class、NVS、管理ACL、Host API/CLI、maintenance | 実dispatcherを通る単一targetの往復と結果照会 |
| P6 公開確認 | 全機能ON/OFF build、API例、診断、docs/maturity | 実コードの位置と証拠が機能表へ対応 |
| P7 実機 | #11/#18の実USB/RF/電断/負荷 | 対象board×profileだけ資格を更新 |

P0〜P6はsoftware、P7は実機。Production Providerの選定・監査は#10と共同で進める。本番認証未認定の間はEXPERIMENTALを必須にし、動くのでproductionと呼ばない。

現状：P0〜P5は本branchへ実装済み、P6（公開確認＝機能flag/ON-OFF build/診断/maturity/docs）はこの改訂で実施。P7の実機証拠は未取得。

## 7.2 具体的な変更先

| 変更先 | 責任 |
|---|---|
| components/routeloom/include/routeloom/discovery.hpp, src/discovery.cpp | ScopeProvider injection、RX dest metadata、density順序、phaseは既存のまま |
| autonomy_wire.hpp/.cpp、host/routeloom-wire | RLD1 body2とobjectkind3。既存type/flags/goldenを保持 |
| admission.hpp・認証Provider | ScopeBinding付きtranscript、Member/NeighborPhaseの別軸、carrier別の最終gate |
| 新gateway.hpp/.cpp、node.cpp | Service21のsend/forward/receive、typed destination、receiptとdedup |
| 新config.hpp/.cpp、authority.hpp/.cpp | Issuerのcommit後permit、target独立ConfigJournal、schema/provider |
| components/routeloom_espnow | PSA scope MAC、NVS config store、Owner/Power/Maintenance hooks |
| routeloom.h / c_api.cpp | 新しいversioned型と関数。既存ABI layoutを変更しない |
| PR #13 usb_host_ops、usb_bridge、Host api1/canonical/dispatch/receive_log | HostOps拡張とendpoint/configの実往復、OSprincipalの認可 |
| firmware/reference_node、firmware/bridge_node | 機能の明示設定・safe default・診断・復旧手順 |

ヘッダだけ、enumだけ、fake-onlyテストだけでは完成にしない。実際の公開APIから呼び出せる接続まで追う。controller/data pathが二重実装にならないように各段階を小さなcommitへ分ける。

## 7.3 PR #13採用時のチェック

この設計branchはmain610c5b2から作成し、未マージPR #13のコードを取り込んでいない。Host部分の実装開始前に修正済みmainを取り込み、採用SHAを記録する。

特にAPIエラーJSON、RAM_ONLY epoch、Replayの現在状態、退役floor、device-terminal回収、単調deadline、WAL/SHM権限の回帰が通ることを確認する。修正中の旧HEADを依存先として合格認定しない。

USB HostOps=19/schema1/sub1〜5、canonical1の26B形、OSprincipal/Network/key scopeを照合し、05で提案したbit3/4・sub0x10台/0x20台が未使用か再検査。衝突は新設計側を改訂し、同じbitを別意味へ使わない。

## 7.4 CI

この設計PRの専用CIはdesign checkerとC/C++宣言のsyntax-only。通常の既存SDK CIは回帰確認として実行されても、新機能の試験ではない。

実装PRではGCC/Clang×ASan/UBSan、Rust fmt/clippy/test、C++/Rust共有wire/USB vectors、実host＋C++ bridgeの統合、Store/Clock故障注入を追加する。firmwareは採用済みmatrix（reference normal/deep_sleep×3target、bridge normal×3target、observe既存構成）を維持し、新機能をONにした構成を別に追加する。compileされないif分岐をbuild-testedにしない。

P6で`sdk.yml`へ`features`軸を追加した：`endpoints_on`はbridge_nodeに`CONFIG_ROUTELOOM_CAPABILITY=0x1f`（bit3 gateway＋bit4 config attach/広告）、`config_target_on`はreference_nodeに`CONFIG_ROUTELOOM_CONFIG=y`（NVS journal target）。base matrixは全機能OFFの既定のままで、build後にsdkconfigへ両方向のgrepをかけてON/OFF両分岐が実際にcompileされたことを確認する。実行はCI側のみ。

## 7.5 完了の証拠

1. 差分にruntimeの実コード・呼出し経路・回帰試験がある。
2. 対象branchのCIが該当SHAで成功する。
3. レビューを経てmergeした場合はmainに変更が含まれることとmain CIを再確認する。
4. HILや資格のflagは、そのboard/profileの証拠を得た場合だけ更新する。

このDraftの設計承認だけではIssue #14/#16/#17をcloseしない。scope96/128bit案、Gateway96B制約、単一targetConfigという選択に変更が必要なら、理由・互換性・vectorを同じPRで更新する。

# 08 — 実装順序・移行・設計受入

## 1. このPRの成果と非成果

新規6Issueの実装契約、容量計算、APIとpayloadの例、試験計画を提供する。設計fixture/checkerが成功しても、それはruntime codec、耐電断Storage、暗号、実無線の実装証拠ではない。runtimeのimplemented/qualifiedや既存手動smoke記録を更新しない。

このbranchはmain `31b3eb0`からの独立差分。PR #2 `cdcf0fe` とPR #6 `be21fbb`は参照点であり取り込んだ実装ではない。先行PRの採用時はmainから更新して接続点を照合し、重複実装をしない。PR #6のSDK CI失敗も本設計PRで解消したとは言わない。

## 2. 接続先と変更対象

| 対象 | 実装先・責任 |
|---|---|
| #7 ReceiveLog / IPC読出し | host/routeloom-host。DataFromMeshの本文を保持し既存EVENTSとは分離。client/TUIは同API |
| #8 SendRequest / operation query | host daemonとprotocol、routeloomctl。C++ usb_bridgeの明示SendOptions/結果対応を追加 |
| #9 OperationStore / DispatchWindow | Host Storage adapter、新schema。device usb_session/bridgeに短期窓/BootLease/RETIRE。既存nonce storeと区別 |
| #10 EDHOC/credential | SecurityProvider/Authenticator/AdmissionContextの既存境界。PSA/NVS platform adapterとHost FFI |
| #11 HIL harness | 既存tests/ツールへケース・計測点を追加。新しい常駐CI製品は導入条件にしない |
| #12 app results | MeshNode/c_api/Wire19、終端store、app executor、Hostの証拠モデルを拡張 |

Status値/型/時間単位はPR #6 P0の正本へ追加する。codeに新enumを作る前にC++/Rustの既存値と凍結Wireを照合する。`frame_allowed()`に例外を追加するだけで本番認証やAPP_RESULTの発行権が成立したとはしない。

## 3. 実装単位

| ID | 作業と依存 | 完了条件 |
|---|---|---|
| BASE-I0 | 採用済み#2/#6を統合しschema/Status/CIを照合 | 既存テスト維持、reference normal/deep_sleep×3＋bridge normal×3の9構成を落とさない |
| RX-I1 | versioned API parser、ReceiveLog、cursor | RX01〜08のC++→USB→Rust→client本文一致、gap、quota。実USBは別 |
| TX-I1 | canonical要求、主体系のACL、options/capability | TX01〜05。無効optionを黙って既定へ変更しない |
| CAP-I1 | Host OperationStore、epoch/floor、transaction | CAP01〜06。全保存境界で旧keyが新規実行にならない |
| CAP-I2 | device DispatchWindowとBootLease、RETIRE/SKIP | CAP07〜10。少数RAMで長期Host台帳を代替しない |
| TX-I2 | 時刻照会、deadline、query/cancel、USB相互運用 | TX06〜10。Wire遅延/再起動で寿命を延長しない |
| SEC-I1 | 固定libedhoc/PSA、suite、context/vector | 上流vector＋独自profileの相互運用、依存license一覧 |
| SEC-I2 | Entropy、provisioning、公開trust配備 | 乱数未準備拒否・秘密非露出・物理導入手順 |
| SEC-I3 | credential/Grant/Admission/SingleAuthority | 本人確認と承認/commitの分離、未承認DATA拒否 |
| SEC-I4 | rotation、counter/replay、sleep後資格更新 | nonce/crash/旧epoch拒否。cold時計不明は安全停止 |
| SEC-I5 | revoke、紛失、role/origin認可 | 認証済みmemberの任意origin越権を拒否 |
| SEC-I6 | 再provision/Network移行・状態隔離 | 旧key/pending/operationを新Networkへ混ぜない |
| HIL-I1 | 計測点・記録形式・smoke→3hop→soak | HIL01〜12を実施可能にする。今回実施済みではない |
| APP-I1 | APPLIED request/lease/ticket、result codec | AP01〜05、既存Wire19を使用しrequest/result最大長を検証 |
| APP-I2 | 永続intent/result、query/ACK/retry、Host統合 | AP06〜10、crash不明で自動実行せず、終端失敗結果も配送 |

最小順序：BASE-I0→RX-I1、TX-I1＋CAP-I1→CAP-I2＋TX-I2→双方向の実USB。SECとHIL計画は並行して進め、本番配備前にSEC受入を必要とする。APPLIEDは後続であり、RELIABLEでアプリが結果を返信する最小統合を止めない。

## 4. 既定値と互換期間

CORE_FIXED_250のruntime値・最終Wire v1 layoutはこのPRで変えない。API1とUSB host_ops_v1/rx_events_v1/production-security/applied-resultのcapabilityは独立。

| 組合せ | 許可 |
|---|---|
| old Host＋old device | 既存legacy機能、既知の保持限界のまま |
| new Host＋old device | read可能な旧受信情報はassurance/ingress gap限界を明示。条件付きsubmitはUnsupported |
| old Host＋new device | legacyを明示enableした場合だけ。保護profileのdown-gradeは自動で行わない |
| new同士 | version/capability/Network/BootLease合致時だけ新payload。secret profileも交差を満たす |
| APPLIED非対応終端 | 要求前Unsupported。RELIABLEをAPPLIEDとして成功表示しない |

legacy SENDは呼出しごとの新key生成を引き続き明示し、安定再照会を要求するclientはAPI1へ移す。旧requestを新APIへ再発行する自動変換は禁止。既存EVENTSはdiagnosticで、新しいmessages.readの永続受領証拠にはならない。

Store schemaはv1を新領域で開始し、途中image/daemon rollbackで未知schemaをeraseしない。古いGateway台帳から新BootLeaseへ移るとき、Hostは既送信要求を照会/不明として扱い、新しいdispatchを自動作成しない。ライセンス選定はmaintainer判断として残す。

## 5. レビュー前の横断チェック

- すべての成功が「どの主体が何を保存/受領した証拠か」を説明できるか。
- 同じ依頼の処理有無を失った後に、新epoch/newboot/newkeyで勝手に再実行していないか。
- 期限/保持/退役をGETや再接続で延長していないか。
- authenticated proof、MembershipState、NeighborPhase、GrantがPR #6の唯一のgateへつながるか。
- 128B通常payload、APPLIEDのlease付きrequest、結果、USB envelope、CCS/Grantが各MTUへ収まるか。
- 同じNode/Gatewayの経路変更と実行主体変更を混同していないか。
- 実機smokeは維持し、未測定RAM/Flash/latencyを測定済みにしていないか。

## 6. このDraftの承認ゲート

APIと保存の設計レビュー、採用負荷のレビュー、本番application crypto profileの独立レビュー、HILの機材/合否基準レビューを別チェックとして残す。`contracts.json`ではすべてpending_reviewとし、CI greenで自動承認にしない。

新ケース62件の期待結果は`scenarios.json`。実装担当はcase IDを変更せず実テストへリンクし、状態を更新するときにcommit、コマンド、原始ログ、実行環境を添付する。設計checkerは予定ケースの存在/単位/fixtureを検査し、テストを実行したふりはしない。

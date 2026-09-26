# 01 — 共通契約と既存コードへの接続

## 1. 一つのdaemon、一つの無線所有者

```text
利用アプリ / CLI / TUI
        │ 既存Unix socket + API1要求
        ▼
routeloom-host
 ├ ReceiveLog：本文・cursor・欠落
 ├ OperationStore：長期key・結果・dispatch記録
 └ AdapterSession：認証・credit・一つの順序付きwriter
        │ 既存COBS/CRCの保護session
        ▼
UsbBridge → MeshNode → Radio Owner → ESP-NOW
        │       │
        │       └ 宛先SDK → 非同期の利用アプリ → APPLIED結果（後続）
        └ 短期DispatchWindow。長期業務台帳ではない
```

暗号、Membership、Admissionは既存Provider境界を使う。受信データを知っただけでmembershipを発行しない。Hostが停止しても無線Nodeの通常進行を止めず、ただしPCサービスの生存は偽って広告しない。

## 2. 採用済み型と提案型の対応

以下はPR #6 `be21fbb` の読み取りに基づく。

| 既存の正本 | 今回の接続 |
|---|---|
| types.hpp：NodeId=u64、NetworkId=u64 | IPCは桁落ちしない固定幅hex。Wire v1 Networkは上位32bit=0が必須 |
| MessageId={session:u32, sequence:u64} | origin NodeIdとNetworkを付けて識別。単体sequenceを全網IDにしない |
| DeliveryClass 0/1/2 | BEST_EFFORT/RELIABLE/APPLIEDの既存値を再利用 |
| Priority 0/1/2/3 | Bulk/Normal/Management/Urgentを再利用。宣言だけで有効としない |
| FrameType AppResult=19、Control=22、ControlObject=49 | APPLIEDの結果/照会は19内のsubtype。認証objectは既存carrier。独立type体系を作らない |
| autonomy.hppのRadioGeneration/ChannelEpoch/OperationToken | Host OperationId、受付epoch、dispatch sequence、crypto counterとは別型 |
| admission.hppのMembershipState/AdmissionContext | 状態のcoarse判定を再利用。本人認証・membership証拠・最終gateは別に必要 |
| security.hpp / ReplayGuard / CounterLease | 本番Providerの挿入口。テスト用proofやboolを本番認証の代用にしない |
| deadline.hpp / PowerCoordinator | 経過不明をTimeUncertain。Stop/Sleepによる元期限・IDの延長禁止 |

`OperationId`はHost store lineage（128bit）＋operation sequence（64bit）。新しいデータベースを作り直した場合に過去のIDを再発行しない。C++/Rustで新型を追加する場合はP0の型と重複させず共通protocol定義へ集約する。

## 3. IDのscope

| 名前 | scope・寿命 |
|---|---|
| Principal | IPCのOS資格＋管理ACLから決定。同じUIDのアプリは同じ主体。プロセス名や要求JSONで上書き不可 |
| Client key | caller指定128bit、受付epoch内。業務キーはopaque payloadの外側でSDKが解釈しない |
| Admission epoch | principal×Network×operation classの新規受付期間。発行/閉鎖/退役は永続Store管理 |
| OperationId | daemon再起動後も同じ依頼を照会するID |
| USB request ID | session内の応答相関のみ。再接続時に変わってよい |
| Dispatch identity | Gateway BootLease×Host dispatcher×Network×dispatch_seq。短期再提出を抑止 |
| MessageKey | Network＋origin＋MessageId。無線の同一メッセージを追跡 |
| Cursor | ReceiveLogのepoch＋位置。OperationIdや暗号counterに転用しない |
| Business idempotency key | アプリが副作用防止に使うID。SDKでは意味を持たない |

全IDで0/最大値等の予約範囲、overflow、再初期化時の扱いをcodecに含める。64bit値をJSON numberやfloatへ丸めない。比較は正規化後の整数/byte列で行う。

## 4. IPC v1

既存socketで `API1 ` に続くUTF-8 JSON一行、応答JSON一行を採用する。別daemon、HTTPサーバー、汎用RPC基盤は作らない。1要求8192B以下（改行含む）、1応答65536B以下、depth8以下、重複object key・NaN・未知の必須/未定義field・不正UTF-8は拒否。拡張は明示的なschema minorで追加し、黙って無視しない。

共通要求：`{"v":1,"request_id":"client-17","method":"...","params":{...}}`。request_idは1〜64 ASCII文字の接続相関で、operation identityではない。応答は`v, request_id, ok`と`result`または`error{code,detail,retryable}`。空resultと成功を区別する。

初期method：`capabilities.get`、`messages.read`、`operations.open_epoch`、`messages.submit`、`operations.get`、`operations.get_by_key`、`operations.cancel`。APPLIED結果報告/照会は後段capability。subscribe push、service宛先、gateway自動failoverは初期Unsupported。

権限：Network単位にREAD_PAYLOAD/SEND/READ_OPERATIONを明示。diagnostics権限だけで本文を読めない。MANAGE_MEMBERSHIP/PROVISION/REVOKEは別。利用アプリの業務操作の安全性はここで判定しない。LinuxはSO_PEERCRED等のOS証拠に対応する管理設定を使い、socketのディレクトリ/所有者/モードも制限する。非Linuxのpeer資格実装が未認定なら本番APIをenableしない。

## 5. 成功を一つのboolに潰さない

LOCAL_ACCEPTED、GATEWAY_ACCEPTED、END_SDK_RECEIVED、HOST_RAM_RETAINED、HOST_DURABLE_RETAINED、APPLICATION_REPORTEDは別証拠。API応答が返ったことは利用アプリの保存/処理完了ではない。

終端処理と観測は直交したフィールドにする：`dispatch_state`、`evidence`、`application_outcome`、`observation{deadline_elapsed,cancel_requested,time_uncertain}`。timeout後も同じOperationIdへ遅着証拠を追記できる。過去にtimeoutした記録自体を改ざんせず最新結論を照会する。

機器が証言する終端の内訳は `device_outcome{state,reason}` に載せる。HostOps 由来の理由付き DeliveryEvent は末尾の24バイト operation id と MessageKey の両方を照合し、durable store にも保存する（MessageKey は再起動後に再利用され得る）。`dispatch_state` の終端性（Failed／Indeterminate の保守的集約を含む）は変えず、原因だけを分離する。受理前の MeshRejected は slot が無いため、固定長 RECEIPT の hash 位置を `"RLFR" | len:u8 | detail ASCII (最大27バイト) | zero padding` として使い、対応する operation に直近の拒否理由を保持する。旧機器の canonical hash echo は理由と解釈しない。

## 6. 共通上限と非対応

通常payloadは0〜128Bとする（空本文を明示対応）。Wire v1のnetworkは1〜0xffffffff。Nodeは0とUINT64_MAXを除外。requestのhexは小文字へ正規化し、空本文は空文字とlength=0。hex長は常に2×payload_len。

送信寿命は1〜30000ms、既定5000ms、停止も含むWALL_ELAPSED_VALIDITY。通常優先度のみを初期保証。存在するenumと、Host→USB→schedulerまで実効制御できるcapabilityを混同しない。APPLIED=2も同様。

capabilitiesは各実装・profile・board・versionの交差で返す。未実装オプションを受け付けて既定へ黙って落とすのは禁止。全体の8KiB IPC上限は無線128B上限とは別。

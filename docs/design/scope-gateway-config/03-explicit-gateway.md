# 3. Explicit Gateway配送

## 3.1 完了の意味を先に固定する

GatewayIdは認可されたGateway roleを持つNodeId。機器のMAC/USB path/Controller名ではない。最初の実装は指定されたGateway一台に固定し、AnyGateway・Service検索・別Hostへの自動failoverを実装しない。

| receipt scope | 完了に必要な証拠 | 意味しないこと |
|---|---|---|
| GATEWAY_SDK_RAM=1 | 指定Gatewayの有界受信mailboxへ格納済み | PCに届いた、永続化した、アプリが動いた |
| HOST_RECEIVE_RAM=2 | 指定Host principal/incarnationのReceiveLogへ本文を格納し、認証されたUSB ACKをGatewayが確認 | アプリがpollで読んだ、耐電断保存、アプリ作用成功 |

後者の無線receiptは**GatewayによるHost受領の証言**であり、Gatewayを信頼しない独立したHost署名ではない。認証済みGatewayを信頼境界に含める。独立Host署名を要求するprofileは初期Unsupported。

通常の`send(NodeId)`はこれまでの意味のまま。Gatewayとして使うNodeへ普通にDATAを送った結果をHOST_RECEIVE_RAMと表示してはいけない。APPLIEDは#12の別gate。

## 3.2 終端の確立

`gateway.resolve(gateway_id, receipt_scope, expected_host_principal)`を非同期で行う。認証済みService=21のQuery/Descriptor交換で、nonceをechoし、Gateway role証拠・指定Network・相手identityを検証する。

Descriptorの内容：gateway NodeId、scope、opaque endpoint token128、gateway boot incarnation64、認証済みHost principal digest256（SDK_RAMはzero）、capabilities、max_payload、lease。Endpoint tokenは鍵ではなく、そのGateway内部の有限な終端recordを指す値。偽造防止はE2E保護とrole証拠による。

Host modeのrecordは特定のHost principal、daemon boot、現在のUSB sessionへ結び付ける。Hostが接続しただけで自動登録せず、readiness登録を認証してから発行する。lease15秒、renew5秒。新しいUSB/Host bootは新token、旧tokenを別Hostへ再利用しない。SDK_RAMもGateway bootで新tokenになる。

Queryの往復時間をleaseから差し引き、不確かさとsend lifetimeが残leaseに収まらなければ再resolveする。期限は端末ローカル単調時計で再検査する。これでも直後のHost停止は起こり得るため、送信時にもGateway側で現在のreadinessを検査する。

SDKは発行された`GatewayEndpoint`をopaque handleとして返す。アプリが未認証descriptorを構築してGateway roleを自己申告することはできない。

## 3.3 配送手順

```text
origin: endpoint検証・payload/結果枠を予約 → Service Submit
relay: link認証・有界hop受理・転送（終端成功は発行しない）
gateway: E2E検証・scope/token/boot照合・受信枠とdedupを予約
  SDK_RAM → mailbox格納 → Service Receipt
  HOST_RAM → USB ingress → Host ReceiveLog格納 → USB ingress ACK → Service Receipt
origin: 指定Gateway・元MessageKey・要求digest・scope/tokenを照合 → 完了
```

Service=21の専用subtypeを使い、通常DATAへの自動castや、END_RECEIPT=18だけでの完了はしない。relayにもService転送とhop ACK参照type21を追加する必要がある。旧relayがdropする経路ではtimeout/unsupportedになり得るが、別Nodeの受領へ降格しない。新旧混在の成立経路はテストで特定する。

Originの論理MessageKeyは全roundで同じ。Receipt自身はGateway発の新MessageKeyを持ち、payload中に元MessageKeyと元要求のSHA-256を入れる。END_RECEIPTのID空間を借りて衝突させない。request digestはscope/token/boot/本文を含む正規Submit bytesで計算する。

最大3round、hopごと初回込み2試行、元lifetime最大30秒。Receiptはhop確認付きで有界再送し、Receiptに終端Receiptを返さない。再試行の有無でscope/担当Gateway/本文を変えない。

## 3.4 バッファ・重複・再接続

Gatewayの受理前に同時pending枠、payload、dedup/receipt枠、返信Peer lease/ACK枠を一括予約する。Host modeではUSB/Host受渡しのreservationも必要。予約不能は受理前BUSY。部分的に受理してから成功の証拠を失わない。

同じMessageKeyの重複は既存receiptまたはPENDINGを返し、Hostへ二重投入しない。異内容はCONFLICT。保存済みの成功receiptは旧tokenのlease満了後も保持期間内なら再送できるが、**未受理の新しい仕事**へ旧tokenを使ってはいけない。

Host ReceiveLogはcallbackを実行した時点ではなく、本文recordを確保してからIngressAckを返す。diagnostic EVENTS ringはこの受領記録の代用にしない。受信APIがRAM logで古い本文を回収する契約は維持し、pollの取りこぼしはcursor gapで示す。HOST_RECEIVE_RAMが永続受領に変わったと表示しない。

USB再接続で旧pendingを自動的に新tokenへ書き換えない。同一Gateway bootに保持された最終証拠があれば再送できる。Host/Gateway RAM全損で証拠が消えれば、originは期限後INDETERMINATE。新NodeId/Gatewayへ新規操作を発行するかはアプリが決める。初期版はdurable Gateway ingressを提供しない。

32件のreceipt/dedupは初見から最低60秒（最大lifetime30秒＋late result30秒）保持し、duplicateで延長しない。受付条件はtoken bucket20件/分、burst8と空き枠の両方。8件同時pending、32receipt枠、payload96Bの増分RAM上限は実装時8KiBを基準に測定する。超過は小profileへ自動降格せずbuild/configで明示する。

## 3.5 payloadと互換性の判断

Service Submitは32Bのend-protected envelope＋アプリ本文最大96B。通常Node DATAの128B上限は維持する。**Gateway96Bの制約をcapability/APIへ明示し、97〜128Bを黙って切り詰めない。** 初期版の自動分割はなし。

これはWire headerやDATA型を変更せず、終端種別/tokenを暗号で結合するための選択。将来128B必須なら新しいwire profileまたは明示object APIとして設計し、既存Service Submitを同じversionのまま変更しない。

## 3.6 Host発の送信と受信

HostからMeshへ出すときの`egress_gateway`と、Mesh最終宛先のGatewayは別。#13の版付き送信要求へegress固定を追加するときはcanonical request/hash/OperationStore/DispatchWindowへ含める。ローカルadapter断で別adapterへ自動投入しない。

HostがGatewayを最終宛先に指定するAPIも同じService Submitを利用する。Host internal operation IDと無線MessageKeyの対応を保持する。一般クライアントがUSB principalを任意指定して偽装しない。権限チェックは既存peer credentials/ACLから導く。

## 3.7 状態・エラー

Origin状態：RESOLVING → READY → QUEUED → HOP_ACCEPTED → WAITING_ENDPOINT → ENDPOINT_RECEIVED。BUSY/NO_ROUTEは元期限内の再試行、失効・TOKEN_STALE・UNSUPPORTEDは明示拒否、送信後期限切れは結果不明の可能性を残す。

Gateway状態：VALIDATING → RESERVED → WAIT_HOST（必要時）→ RECEIVED → RECEIPT_CACHED。REJECTEDとTIMEOUTは成功と別。取消は送信前だけ確定取消、送信後は遠端で未受理の証明なしに未実行へ変更しない。

SDK通常データ、Gateway SDK受領、Host受領は診断の別カウンター。最終確認G01〜G12は[ケース台帳](cases.json)。

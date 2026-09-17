# 遠隔設定・診断転送・ファーム更新

## 1. 操作を分離する

Remote Configはrelay許可、受信予定、電力予算、送信ポリシー等の設定を変える。OTAはfirmwareを書き換える。設定を一つ変えるために全firmware更新を要求しない。

通常DATAと別queue・優先度・予算を使うが、別RF channelを必須にはしない。通常制御と同じRadio Ownerへ依頼する。

## 2. 設定の種類

| scope | 手続き |
|---|---|
| アプリ内部設定 | アプリがschema/意味/適用結果を所有 |
| NodeローカルSDK方針 | 管理者権限、expected revision、能力検査 |
| ネットワーク全体 | ControlAuthorityのcommit |
| RF配備の上限 | 承認profile内。無線経由だけで規制上限を解除しない |

設定にはoperation ID、scope、旧revision、新revision、author、payload hash、期限を持つ。schema不一致、容量超過、unsupported能力をrejectし、部分適用しない。秘密設定は認証暗号で配送しログに出さない。

## 3. apply transaction

validate→prepare/persist→commit権限確認→apply→self-check→result。中継OFF・Sleepへの変更は経路drainと整合させる。適用失敗時は新revisionの失敗状態と実active値を報告する。rollbackで古い設定を黙って再生せず、正式な新操作にする。

GETはdesired/committed/activeとエラーを分けて返す。異なる管理者の競合にはexpected revisionを用い、時刻が新しいから無条件採用しない。

## 4. bulk object

小さい設定・認証情報は最大2048Bの有界object転送。大ログ・OTAはmanifest＋chunk streamを使い、全objectをRAMに置かない。chunkにoffset・digest、転送全体に長さ・版・hash・署名・再開情報を持つ。

通常DATAのdeadlineを圧迫したらbulkを止める。link変更後の再開は同じmanifestに結び、誤ったfirmwareの続きを書き込まない。受信可能時間と電力予算を検証する。

## 5. firmware OTA

署名、chip、board profile、flash/partition layout、bootloader要件、互換wire範囲、antirollback方針、image hashを検証してからinactive slotへ書く。電源・残容量・watchdogを確認する。

起動後はself-test合格を明示して確定する。失敗時はESP-IDF OTA rollback機能等の実証済み手順で戻る。アプリversion rollbackと、管理channel/key epochの巻戻しを同一視しない。

参考：[ESP-IDF OTA](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/ota.html)。Secure Boot/eFuse設定は[Security](security.md)に従い、不可逆操作を自動で実行しない。

C3の4MB Flashでは2image、metadata、NVS、spoolを合わせた実partition計算が必要。S3の容量があるからC3でも同じOTAが成立するとはしない。

## 6. 中継器の更新順序

中継器を更新する前に依存する経路を確認し、同時に重要なcut vertexを停止しない。代替がない場合はmaintenance outageを明示する。Root/Gateway/voterの同時更新でデータと管理多数を一度に落とさない。

## 7. 未実装時

機能未認定ならcapability=falseとUNSUPPORTED。署名検証が未完成だから暫定で平文OTAを正式機能として出すことはしない。USB recoveryは別の物理保守経路として残す。

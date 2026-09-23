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


## 8. imageと永続stateの互換性

manifestへreadable_storage_schema_range、writable_schema_version、security_profile、最低bootloader、wire互換、firmware hashを含める。pending imageのself-test中に、旧imageが読めなくなる唯一のstoreを不可逆変更しない。互換書込みか別領域へのコピーで戻れる状態を保ち、確認後に明示migrationする。

binary rollbackでもnonce high-water、key/channel/membership世代を戻さない。旧binaryが安全に扱えないならrollback可能と表示せず、互換recovery image／物理回復を事前に用意する。Secure Version等の不可逆更新は回復方針・self-test確定前に行わない。

## 9. 同時保守の排他

maintenance operationにはID、Authority世代、対象、保護到達集合、voter構成、観測世代、開始前再確認、同時停止制約、進行phase、期限と再起動証拠を耐電断保存する。一Networkに一つの停止を伴う計画を基準とする。

複数daemonからのOTA／relay-off／survey／全体切替を同じ排他へ接続する。期限切れlockを理由に対象が復帰したと推定して別中継を止めない。到達/再起動を確認できなければOUTAGE_UNRESOLVED。後継Authorityも記録を引き継ぐ。古いtopologyなら開始を保留する。

mesh OTAは初期基準線に含めず、まずUSBによるimage更新とstore互換・電断を検査する。仕様は将来機能の実装条件として維持する。

## 10. 設定journalのflash摩耗（運用注記）

RCC1 Small Remote ConfigのConfigJournalは受理1件ごとに2スロット耐電断commitを行い、概算7〜8回のNVS commitを消費する（[電源断契約 §7](crash-time-resources.md)）。摩耗を制限するのはtargetの受理rate上限（1/min＋burst1、60秒で最大2件）だけで、上限一杯の自動投入を続けると既定24KiB NVSで概算1〜2年で寿命に達する。人手による変更頻度では問題にならないため、次を運用規則とする（issue #57）。

- 監視や自動化から周期的に設定を書き戻さない。GETでdesired/activeを比較し、一致していればapplyを発行しない。
- 複数項目の変更は一つのrevisionへまとめる。
- 遠隔設定を高頻度に使う配備は、NVS partitionを拡大するか実機計測で摩耗予算を確認してから導入する。

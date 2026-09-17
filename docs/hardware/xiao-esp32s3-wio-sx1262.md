# XIAO ESP32-S3＋Wio-SX1262 B2B kit

確認：2026-09-17。S3本体と別体SX1262 moduleの組合せ。ESP32-S3自体にLoRa PHYが内蔵されているわけではない。

## 1. 公式リンク

- [Seeed kit説明・仕様・B2B注意](https://wiki.seeedstudio.com/wio_sx1262_with_xiao_esp32s3_kit/)
- [Wio-SX1262 module](https://wiki.seeedstudio.com/wio_sx1262/)
- [Wio拡張基板回路図](https://files.seeedstudio.com/products/SenseCAP/Wio_SX1262/Schematic_Diagram_Wio-SX1262_for_XIAO.pdf)
- [S3本体資料](xiao-esp32s3.md)
- [Seeed single-channel gateway解説](https://wiki.seeedstudio.com/wio_sx1262_xiao_esp32s3_for_single_channel_gateway/)
- [Seeed公式サンプル実装](https://github.com/Seeed-Studio/one_channel_hub)
- [Semtech公式SX1262比較情報](https://www.semtech.com/products/wireless-rf/end-nodes-ics)
- [Semtech公式driver](https://github.com/Lora-net/sx126x_driver)

## 2. 機械・電気構成

S3向けkitはB2B接続。nRF52840向けthrough-hole版や、別の汎用XIAO用header製品と同じ結線とみなさない。S3本体の8MB Flash/PSRAM等は本体variantに依存する。

kitの公表LoRa帯域は862〜930MHz。SX1262チップ一般の150〜960MHz能力を、そのままkitのマッチング回路・アンテナの利用帯域に広げない。Wi-Fiは別の2.4GHz側アンテナを使う。

本体USB5V、公称single-cell電池系。kit表のBAT4.2Vは公称3.7V充電池の満充電側の値として区別し、任意の4.2V超電源へつながない。kit充電100mA記載とS3回路図の約110mA注記はrevision確認対象。

## 3. 信号割当

S3本体とWioの公開B2B回路図を照合した割当候補。**board revision・嵌合方向・導通と実機で確認してからprofileを認定する。** コネクタの図面番号は相手側図の向きと対応させる。

| Wio信号 | S3 GPIO | 意味 |
|---|---:|---|
| SPI SCK | 7 | クロック、XIAO D8 |
| SPI MISO | 8 | Wio→MCU、D9 |
| SPI MOSI | 9 | MCU→Wio、D10 |
| NSS | 41 | chip select |
| NRESET | 42 | module reset |
| BUSY | 40 | コマンド受付可能性 |
| DIO1 | 39 | 無線IRQ |
| RF_SW1 | 38 | module RF切替制御 |
| 拡張USER LED | 48 | Wio側green LED |
| 拡張USER button | 21 | Lowで押下、S3側USER LEDと共有に注意 |

GPIO7/8/9はSPI共有なので別sensor/SD等とのCS・タイミング調停が必要。GPIO38〜42はS3のcamera/PDM等の拡張と競合し得る。B2Bが刺さることをSense同時利用の証明にしない。

BUSY timeout、DIO1、RESET手順、SPI速度、DIO2/RF switch、DIO3/TCXO電圧と起動時間は、**module-specific driver profile**に含める。名称だけからRF_SW1を常にHighにする、TCXO電圧を試行錯誤で切り替える、といった手順を本番標準にしない。

## 4. SX1262の能力と上限

Semtech公式のSX1262一般仕様は最大+22dBm、LoRa SF5〜12、複数BWを挙げる。受信電流4.6mA等はチップの条件付き値で、S3を含むkitの総消費ではない。最高感度はSF/BWによるため単一値で距離を保証しない。

日本や他国でchip最大出力を使ってよいという意味ではない。配備国・周波数・アンテナ・認証・送信制限を確認して初めてTXを許可する。LoRa、LoRaWAN、Meshtastic、RouteLoomは別の層・protocolである。

一つのSX1262をSX1302系concentratorのような多channel・多SF同時受信装置とは扱わない。Seeedのone_channel_hubは参考実装で、RouteLoomのwireやroutingとは互換ではない。

## 5. RouteLoom v1での扱い

ESP-NOW LRのS3として使い、**LoRa送信機能は有効化しない**。SX1262の未使用状態でも、board-specificな安全なSleep・RF制御・pin保持を確認する。追加radioを装着したままS3単体のsleep消費を引用しない。

未使用radioの初期化・停止はboard supportの責任とし、CoreへSX1262 GPIOを直書きしない。将来LoRa adapterを追加する際は、MTU、airtime、受信profile、法規予算、混在経路、暗号envelopeを[拡張契約](../spec/transport-extension.md)に従って認定する。

## 6. 必須試験

導通・GPIOconflict、cold start、BUSY stuck、reset中断、SPI arbitration、TCXO、Wi-Fi＋LoRa時の自己干渉、別アンテナ配置、未使用時sleep、電池pulseを試験する。RF試験は該当radioの認定された配備profile内で行う。v1ではLoRa性能合格を主張しない。

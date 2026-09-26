# SDK v1 — 静的RAMの予算・role別profile・CI guard

改訂 **1.0 / 2026-09-23**。対象：portable core（`components/routeloom`）、ESP-IDF adapter（`components/routeloom_espnow`）、`firmware/bridge_node`／`firmware/reference_node`。

**これは実機の測定報告ではない。** 構造体の大きさはclangのrecord layout（RISC-V ILP32＝ESP32-C3/C5のABI）と64bit hostで測った値で、firmware imageごとの残量はそこからの推定である。imageの実際の値はCIの`idf.py size`（下の§5）が各matrix cellで記録する。

## 1. 問題と結論

MeshNodeを含むSDKの状態はすべて静的確保（`.bss`）である。group配送（PR #84）で`firmware (bridge_node, esp32c3, normal, observe, off)`が`dram0_0_seg`を864 B超え、約1.1 KBを取り戻した時点で残りは約270 Bだった。次の機能でESP32-C3のgateway imageはlinkできなくなる。

この改訂で：

1. **削減**：wire・protocol・securityの挙動を変えずに、MeshNodeを**111,824 → 83,160 B**（−28,664 B）、UsbBridgeを**42,520 → 33,800 B**（−8,720 B）にした（RISC-V ILP32）。C3 bridge（observe）の推定残量は**約270 B → 約37.6 KB**。
2. **可視化とguard**：CIの各firmware cellが`idf.py size --format json2`を記録し、静的データを持つ内部RAMの残量を表にして、閾値（C3は8 KiB）を下回るcellを失敗させる。
3. **容量は下げていない**。role別に容量を下げる選択肢（§6）はあるが、layoutだけで目標を大きく超えたので、挙動を弱める変更はしていない。

## 2. メモリモデル

- **静的状態**：`EspNowRuntime`（`MeshNode`を内包）、`DevelopmentPskSecurityProvider`、`UsbBridge`、`GatewayDelivery`、`ConfigGateway`、discovery／migration／config journalは、firmwareの`app_main`内の関数static objectとして`.bss`に置かれる。SDKがheapから取るのは起動時のFreeRTOS queue（runtimeのRX/TX event queue 48件とbootstrap queue 8件）とtaskだけで、Wi-Fi driverのbufferもheapにある。容量はすべてcompile time定数で、枯渇は明示的な拒否（`NoCapacity`、BUSY、`TABLE_FULL`系diagnostic）になる。
- **C3のSRAM**：IRAMのcode（`.iram0.text`）と`.data`／`.bss`が同じSRAM（esp-idf-sizeの表示名は`DRAM`、S3は`DIRAM`、C5は`HP SRAM`）を分け合い、`dram0_0_seg`の残りが起動時にheapになる。linkが失敗するのはこの領域の残量が負になったときで、CIが見る「free」はまさにその残量である。
- **heapへ移さない理由**：大きなobjectを起動時に一度だけheapへ確保しても、heapの大部分は同じ`dram0_0_seg`の残りなので、合計のSRAMは増えない（heapのheaderの分だけ減る）。bootloaderが使っていた領域は起動後にheapへ戻るが、そこへ置けるかを示すには実機の`heap_caps_get_info`が要り、静的guardからもその分が見えなくなる。layoutだけで目標を超えたので、この改訂では行わない。
- **stack**：`TxJob`は関数内のlocal copy（`TxJob job = physical_.job;`など）としても使われるので、1件880 B → 368 Bの縮小は8 KBの`app_main` stackの消費も減らす。

## 3. 削減内容

いずれも**同じ値を同じ意味で保持**し、fieldの並べ替え・同時に生きない領域の共有だけを行った。wire形式・golden vector・protocolの意味・鍵とcounterの扱いは変わらない。

| 対象 | 変更 | RISC-V ILP32（before → after） | LP64 host |
|---|---|---:|---:|
| `MeshNode::TxJob` | plain frameとforwarded frameは同時に持たないので`union`で共有（`form`が有効な側を示す。`set_forwarded()`だけがforwardedへ切り替える）。1件ごとの250 B encode cacheを、nodeに1つの`tx_encoded_`とjobごとのtagに置換 | 880 → 368 | 896 → 376 |
| `TxScheduler`（pool 32件） | 上記 | 30,776 → 14,392 | 32,240 → 15,600 |
| `AwaitingHop`×8、`PhysicalInflight` | 上記（`TxJob`を内包） | 904 → 392 | 920 → 400 |
| `RouteTable::Entry`×128 | 8 byte fieldを先に並べる | 256 → 216 | 256 → 216 |
| `RouteCandidate`（entryごとに3） | 同上 | 40 → 32 | 40 → 32 |
| `DedupEntry`（relay 96件） | 同上 | 152 → 136 | 152 → 136 |
| `Neighbor`×32 | 同上 | 192 → 160 | 192 → 160 |
| `SeqnoState`×32、`AckKey` | 同上 | 48 → 40、40 → 32 | 同じ |
| **`MeshNode`（relay dedup）** | | **111,824 → 83,160** | **113,688 → 84,704** |
| `usb::StreamDecoder` | COBSをその場でdecode（`cobs_decode`は`memmove`、出力上限は従来どおり4096 B） | 8,280 → 4,184 | 8,288 → 4,192 |
| `UsbBridge::tx_wire_` | bridgeが出す最大body（1,048 B）のCOBS上限に合わせる（`encoded_frame_bound()`）。`encode_frame`は必要量だけを要求する | 4,114 → 1,084 | 同じ |
| `UsbBridge`の`canonical_`／`node_page_wire_` | 使われていない間の`tx_body_`で一時的に組み立てる（hash計算／TX queueへのcopyが終わってから次のpumpが動く） | −1,500 | 同じ |
| **`UsbBridge`** | | **42,520 → 33,800** | **42,664 → 34,040** |

共有encode bufferの規則（`MeshNode::encode_job`）：driverがframeを受け取らなかった（WouldBlock／Busy）jobは、その間に他のjobがsealされていなければ**同じbyte列**を再提出する（従来と同じ）。他のjobが先にsealされていれば、そのjobはretryと同じく新しいlink counterでsealし直す。未送信のframeのcounterを捨てるだけなので、anti-replay上の意味は変わらない（`test_driver_backpressure_reuses_sealed_frame`）。

dedup profileごとの`MeshNode`（RISC-V ILP32）：leaf 102,032 → 74,392、relay 111,824 → 83,160、gateway 136,304 → 105,080 B。

## 4. firmware imageごとの推定（ESP32-C3）

基準点は、PR #84後のCIで測られた`bridge_node / observe`の残り約270 Bだけである。他のcellは、各cellが持つ静的objectの差（RISC-V ILP32のsizeof）から推定した。Wi-Fi・FreeRTOS・libcの`.bss`とIRAM codeはcell間でほぼ同じとみなしている。**推定値であり、CIの`ram-report.json`が正**。

| cell（C3） | 主な静的object | 推定残量 before | 推定残量 after |
|---|---|---:|---:|
| bridge_node observe | runtime + PSK + USB bridge + gateway/config + discovery + migration | 約0.3 KB（実測） | 約37.6 KB |
| bridge_node discover（paired_bridge） | 上から migrationを除く | 約15.3 KB | 約52.7 KB |
| bridge_node off／endpoints_on／route_scoped | runtime + PSK + USB bridge + gateway/config | 約31.6 KB | 約69.0 KB |
| reference_node discover（paired_target） | runtime + PSK + config journal（41.6 KB）+ discovery | 約23.8 KB | 約52.4 KB |
| reference_node config_target_on | runtime + PSK + config journal | 約40.1 KB | 約68.8 KB |
| reference_node off／route_scoped／deep_sleep | runtime + PSK | 約84 KB | 約112 KB |

bridgeはMeshNodeとUsbBridgeの両方の削減（−37,384 B）、reference nodeはMeshNodeの削減（−28,664 B）を受ける。S3・C5にも同じobjectを置くが、空きSRAMはtarget固有のWi-Fi／IDF code配置に依存するため各targetの`idf.py size`で判定する。

P4 MemberEdhoc構成のC3実測（ESP-IDF v6.0.3、`idf.py size --format json2`）では、bridgeのWi-Fi IRAM最適化を有効にしたままだと静的DRAM空きは3,968 Bでguardに失敗する。bridgeの`ESP_WIFI_IRAM_OPT`と`ESP_WIFI_RX_IRAM_OPT`を無効にすると23,200 B、referenceは51,792 Bで、いずれも8,192 Bのguardを通る。これはWi-Fiの頻用関数をflashへ移す構成であり、無線性能と16 KiB main task stackの実機high-waterはHILで測定する。静的RAMの数値はtask stackの動的使用量を含まない。

C5 bridgeは同じbank容量のMemberEdhoc構成でdefaultのdebug最適化ではHP SRAMが15,600 B超過する。target別defaultsでC5だけsize最適化を選び、Wi-Fiのextra／sleep IRAM配置も外すと、同じIDFの実測で静的HP SRAM空きは10,787 B（8,192 Bのguardを通過）になる。guard超過分は2,595 Bなので、静的状態を増やす変更では再計測する。sleep IRAMの無効化は無線の省電力挙動に影響し得るので、RF性能・消費電流もHILで測る。

## 5. CIの可視化とguard

`firmware` jobの各cellは`idf.py build`の後に次を実行する（`.github/workflows/sdk.yml`）：

```sh
idf.py size > build/size-report.txt
idf.py size --format json2 --output-file build/size.json
python3 tools/firmware_ram_report.py build/size.json --target <target> --app <app> \
  --cell <cell> --json-out build/ram-report.json --summary "$GITHUB_STEP_SUMMARY"
```

- `size.json`はESP-IDF v6.0が使うesp-idf-size 2.xのjson2要約（`layout[]`の各memory typeに`name/total/used/free/parts`）。toolはraw形式（`memory_types`）も読み、`free`が無ければ`total − used`で求める。**静的データを持つ内部RAMのmemory typeが見つからない報告はエラー**（exit 2）で、入力を読めずにpassすることはない。
- 内部RAMの各memory type（flash・外部RAMを除く）のused／total／freeと大きいsectionをjob summaryへ書き、`ram-report.json`と`size.json`をfirmware artifactに入れる。
- guardの対象は`.bss`／`.data`を持つ主SRAM（C3は`DRAM`、S3は`DIRAM`、C5は`HP SRAM`）の`free`。IRAMのcodeも同じ領域に入るので、これはlink時の`dram0_0_seg`超過までの残りそのものである。RTC／LP SRAMはesp-idf-sizeが`.rtc.data`（`RTC_DATA_ATTR`）も`.data`と略すが、表に出すだけでguardの対象にしない（deep-sleep cellのRTC SLOWは8 KB全体でも閾値に届かない）。
- 閾値（`tools/firmware_ram_report.py`の`MIN_FREE_BYTES`。この表とtoolの一致は`tests/test_firmware_ram_report.py`が検査する）：

| Target | App | 最小の静的RAM残量（bytes） |
|---|---|---:|
| `esp32c3` | `bridge_node` | 27,648 |
| `esp32c3` | `reference_node` | 19,456 |
| `esp32s3` | `*` | 8,192 |
| `esp32c5` | `*` | 8,192 |

**8 KiBの根拠**：静的状態の1機能分の増分（group配送はMeshNodeに約5 KBを足した）に余裕を加えた値である。最後の8 KiBを使う変更は、自分で同じだけ取り戻すか、この表を理由付きで変えるレビューを通す必要がある。linkが失敗して初めて気づく状態には戻さない。これは実行時のheap目標（resource-profilesの空きheap 32 KiB・最大block 16 KiB、HILで測る）とは別の、link前の床である。

**2026-09-26 実機根拠（C3、ESP-IDF v6.0.3）**：issue #166 の既定 C3 bridge（dedup 96、esp_netif 有効）は静的空き 20,512 B で link したが `esp_wifi_init` の heap 不足で起動せず、8 KiB floor は起動を保証していなかった。dedup を 32 件にした image は静的空き 27,016 B で起動したものの ESP-NOW 開始後の heap は free 5,956 B・largest 3,968 B しか残らなかった。ESP-NOW しか使わない firmware で lwIP の TCP/IP task を止め（`ROUTELOOM_WIFI_NETIF_INIT=n`、既定）、A-MPDU と余分な management buffer・softAP・enterprise・Wi-Fi NVS を切った既定構成では、bridge が静的空き 29,690 B、`esp_wifi_init` 直前の heap 42,248 B、Wi-Fi/PHY/ESP-NOW 起動の最小 heap 14,796 B（起動後 free 14,856 B・largest 12,800 B）、reference が静的空き 34,044 B、起動前 50,316 B、起動後 free 22,940 B・largest 20,480 B（最小 22,888 B）だった。bridge の実測は console を USB Serial/JTAG に向けた計測 image（静的空き 29,690 B）で行った。既定 image（console は UART0）は静的空き 29,744 B で、model はその分だけ保守的になる。MemberEdhoc image も同じ source で起動し、bridge は起動後 free 14,840 B・largest 12,800 B（最小 14,780 B）、reference は DevRam と同値だった。無線起動の消費は両 app で約 27.4 KB。上表の C3 の床はこの実測から `tools/firmware_ram_report.py` の boot-heap model（無線起動前 offset ＝ heap − 静的空き、無線 peak、起動後に残す reserve：gateway 12 KiB、通常機器 8 KiB）で導出した値（bridge 27,182→27,648 B、reference 19,348→19,456 B）で、report はその推定値も出力する。model の定数は Wi-Fi・lwIP・main task stack・console 構成を変えたら再計測する。機器側では `ROUTELOOM_BOOT_HEAP_FLOOR_BYTES`（既定 8 KiB）を下回ると `BOOT_HEAP_BELOW_FLOOR` を log し、HIL はそれを起動失敗として扱う。C5/S3 は接続機がなく build-only であり、8 KiB floor で起動保証を主張しない。C3 gateway の起動後 heap は resource-profiles の目標（32 KiB／16 KiB）にまだ届かない。次の削減候補は 03 §5.2 が C3 gateway に認める E2E context 上限の引き下げ（128→64 で約 8 KB）である。

後続の USB idempotency 墓標 96 件は静的領域を約 1.5 KiB 増やす。上記の起動時 heap 実測は追加前の image の値であり、追加後の静的 floor は ESP-IDF v6.0.3 の firmware matrix 25 構成で再検査済みである。

**P5-2 broadcast（PR5）**：`MeshNode`に**+272 B**（host LP64実測 89,080 → 89,352。RISC-V ILP32も同一layout）。内訳は`Neighbor`×32が`cap_features` u32で160 → 168 B（+4 B実体＋4 B tail padding、計+256 B）、`RouteScaleStats`のbroadcast counter +8 B、未知GK hint時刻 +8 B。Kconfig `ROUTELOOM_ROUTE_BROADCAST` 自体は実行時flagで静的RAM +0（reference_node C3 scoped cellでscoped／scoped+broadcastとも `.bss` 132,592 B、`free` 102,272 B、floor PASS）。8 KiB guardの対象増分として記録する。

**EDHOC（P2-1）**：libedhoc・zcbor・`routeloom::edhoc` backendはrouteloom componentに入りC3/S3/C5のCIでcompileされるが、firmwareからは呼ばれないのでlinkで全て落ち、この表の残量は変わらない（backendは静的状態を持たず、`thread_local`のarena pointer 1つも未参照なら残らない）。P4-2で1 handshake枠（[05本番認証 §8](../host-security-readiness/05-production-security.md)）を静的に置くと、`edhoc::Session` 1個でILP32見積約3.5 KB（host計測3880 Bから算出。P3-1で証明書をEADで運ぶ参加交換が作業arenaを最大1440 B使うと分かり、arenaを1280 Bから2048 Bに上げた）が加わる。参加の搬送（P3-1／P3-2）は1 KBのobject slotを機器・proxyに1件、gatewayに2件使うが、firmwareへは未配線で静的RAMは増えていない。その時点でこの残量とstack（hostで全handshake約10 KB、C3実測はP2-2）を再確認する。#116のrelay v2ではgatewayがRelayBook（floor 128件＋active 8件）とchunked object用slotを静的に持ち、`JoinRelayGateway`はhost実測5856 B（gate 6656 B）、`JoinProxy`は1600 B（gate 1792 B）、`JoinObjectSlot`は1096 B（gate 1120 B）で、いずれもheap・static可変長無し（`test_q116_size_budgets`がgateする）。やはりfirmwareへは未配線で、この表の残量は変わらない。

## 6. role別profile

容量はcompile time定数で、roleごとに変えられるものは次のとおり。**既定値はすべて従来どおり**で、host test buildも従来の容量で全testを通す。

| 仕組み | 選択 | 値 | 静的RAM（RISC-V） |
|---|---|---|---|
| dedup容量 | ESP-IDF Kconfig *RouteLoom → Dedup capacity profile*（`CONFIG_ROUTELOOM_DEDUP_PROFILE_{LEAF,RELAY,GATEWAY}`）、host CMake `-DROUTELOOM_DEDUP_PROFILE=leaf/relay/gateway` | 32／**96（既定）**／256件 | 1件136 B（leaf 4.4 KB、relay 13.1 KB、gateway 34.8 KB） |
| 経路profile | `CONFIG_ROUTELOOM_ROUTE_GATEWAY_SCOPED` | flat（既定）／gateway-scoped | 容量は同じ（経路表128件） |
| USB bridge | `bridge_node`だけがlinkする | — | 33.8 KB |
| discovery／migration／config journal | `CONFIG_ROUTELOOM_DISCOVERY`／`CONFIG_ROUTELOOM_MIGRATION`／`CONFIG_ROUTELOOM_CONFIG` | 既定off | 16.3 KB／15.0 KB／約43.7 KB |

製品構成（S3の表示板約100台＋PCにUSB接続したgateway 1台）での目安：表示板はrelay（共通既定）、S3のgatewayはgateway profile（256件）を選べる。C3のbridge_nodeは起動heap確保のためtarget別既定をleaf（32件）にしている（§5.1）。Live／Terminalのdedup recordは容量不足でも追い出されず、受付を拒否する。

**下げなかった容量と、将来の候補**（下げるなら、その値でのtestを追加し、host既定は変えない）：

- leafは`GroupOrigin`（3件、2.3 KB）を使わない（group送信はroute gatewayだけ）。
- dev PSK providerの鍵context cache（RX 64件8.3 KB、TX 32件3.6 KB、parked lease 64件3.1 KB）はpeer数に比例する。
- `ConfigJournal`（41.6 KB）は4 KB scratch×2、`Transaction`×3、`ConfigField`配列×4を持つ。同時に生きない組を共有すれば大きく減る見込みだが、寿命の解析が要るので今回は触れない。

## 7. 再現手順

- **CI**：各firmware artifactの`build/size.json`（esp-idf-sizeの要約）と`build/ram-report.json`（guardの判定）。job summaryに表が出る。
- **手元（ESP-IDFあり）**：`idf.py build && idf.py size --format json2 --output-file build/size.json && python3 ../../tools/firmware_ram_report.py build/size.json --target esp32c3 --app bridge_node`。
- **手元（ESP-IDFなし、構造体の大きさ）**：clangの`--target=riscv32-linux-gnu -fsyntax-only -Xclang -fdump-record-layouts`に`components/routeloom/include`と`components/routeloom_espnow/include`、ESP-IDFのheaderの型だけを宣言したstub（`esp_now.h`、`freertos/FreeRTOS.h`、`nvs.h`）を渡し、`template <class T, std::size_t N> struct Sz; Sz<routeloom::MeshNode, sizeof(routeloom::MeshNode)> x;`をcompileする（未定義templateのエラーに大きさが出る）。RISC-V（C3/C5）とXtensa（S3）はu64を8 byteに揃えるので、`i386`で測ると小さく出る。

## 8. 主張しないこと

- 表の「推定残量」は実測ではない。imageの値はCIの`ram-report.json`で確かめる。
- 実行時のheap最小値・最大block・task stackの余裕は測っていない（HILの受入項目のまま）。
- `docs/reference/resource-profiles.json`は設計上の上限（sizeofではない）で、dedupの割当は1件152 Bの許容のまま残した（実際の136 Bを上回るので条件を満たす）。

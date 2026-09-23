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

bridgeはMeshNodeとUsbBridgeの両方の削減（−37,384 B）、reference nodeはMeshNodeの削減（−28,664 B）を受ける。S3・C5は同じobjectをより大きいSRAMに置くので、C3より残量が大きい。

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
| `esp32c3` | `bridge_node` | 8,192 |
| `esp32c3` | `reference_node` | 8,192 |
| `esp32s3` | `*` | 8,192 |
| `esp32c5` | `*` | 8,192 |

**8 KiBの根拠**：静的状態の1機能分の増分（group配送はMeshNodeに約5 KBを足した）に余裕を加えた値である。最後の8 KiBを使う変更は、自分で同じだけ取り戻すか、この表を理由付きで変えるレビューを通す必要がある。linkが失敗して初めて気づく状態には戻さない。これは実行時のheap目標（resource-profilesの空きheap 32 KiB・最大block 16 KiB、HILで測る）とは別の、link前の床である。

## 6. role別profile

容量はcompile time定数で、roleごとに変えられるものは次のとおり。**既定値はすべて従来どおり**で、host test buildも従来の容量で全testを通す。

| 仕組み | 選択 | 値 | 静的RAM（RISC-V） |
|---|---|---|---|
| dedup容量 | ESP-IDF Kconfig *RouteLoom → Dedup capacity profile*（`CONFIG_ROUTELOOM_DEDUP_PROFILE_{LEAF,RELAY,GATEWAY}`）、host CMake `-DROUTELOOM_DEDUP_PROFILE=leaf/relay/gateway` | 32／**96（既定）**／256件 | 1件136 B（leaf 4.4 KB、relay 13.1 KB、gateway 34.8 KB） |
| 経路profile | `CONFIG_ROUTELOOM_ROUTE_GATEWAY_SCOPED` | flat（既定）／gateway-scoped | 容量は同じ（経路表128件） |
| USB bridge | `bridge_node`だけがlinkする | — | 33.8 KB |
| discovery／migration／config journal | `CONFIG_ROUTELOOM_DISCOVERY`／`CONFIG_ROUTELOOM_MIGRATION`／`CONFIG_ROUTELOOM_CONFIG` | 既定off | 16.3 KB／15.0 KB／約43.7 KB |

製品構成（S3の表示板約100台＋PCにUSB接続したgateway 1台）での目安：表示板はrelay（既定）、S3のgatewayはgateway profile（256件）を選べる。C3のgatewayは既定のrelayのままでも§4のとおり余裕がある。

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

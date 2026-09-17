# アーキテクチャと実行モデル

## 1. 成果物

組み込み側はアプリ、RouteLoom、ESP-IDFを一つのファームウェアにリンクする。RouteLoomというOSを先に入れる形ではない。内部C++、外部C APIを基準とし、Arduino wrapperや他言語bindingは後から同じ意味へ接続する。

PC側はRust製daemon、client API、CLI、TUI。TUIはdaemonと同じAPIを使い、画面を閉じてもデータ処理を止めない。

```text
アプリ → C API → Mesh Core → Radio Supervisor → Radio Owner → ESP-NOW
                   │                │
                   ├ Security       ├ 観測・干渉・速度評価
                   ├ Storage        └ 操作優先順位
                   ├ ControlAuthority
                   └ Power coordination

PCアプリ／CLI／TUI → Host API → USB session → Gateway firmware → Mesh Core
```

## 2. 構成部品

| 部品 | 責任 |
|---|---|
| Identity/Membership | 物理機器、ネットワーク所属、credential |
| Mesh Core | 近隣、経路、宛先解決、ループ回避、分断・復旧 |
| Delivery | message状態、期限、再送ラウンド、dedup、receipt |
| Radio Supervisor | 観測の分類と最適化の調停 |
| Radio Owner | 物理送信・Peer・レート・channel・停止の唯一の実行者 |
| Security Provider | 標準鍵交換、暗号化、署名、replay、鍵保存 |
| ControlAuthority | 管理ログ、構成員、合意済み操作 |
| Power coordinator | アプリ許可、radio drain、state保存、sleep |
| Storage Provider | RAM・Flashへの有界保存、commit証拠 |
| Host bridge | USBフレーム、credit、PC session、結果の受け渡し |

## 3. タスク境界

Radio Ownerは一つのtask/event loopが所有する。Wi-Fi callbackでは固定長RX/TXイベントをコピーして返す。暗号検証、経路計算、アプリcallback、Flash同期、JSON整形をWi-Fi task内で実行しない。

SDK workerが検証済みフレームを処理し、アプリcallbackを専用executorに渡す。ユーザーcallbackが遅くても無線RXを停止しない。キューが満杯なら明示的にbackpressure／drop統計を返し、無制限task生成で逃げない。

物理TXは一件ずつだが、論理メッセージは複数を管理する。E2E ACK待ちの間に別の受信・中継を続ける。

## 4. 所有権

`send`は成功して初めてSDKがpayloadのコピーを所有する。受付失敗ならtokenも転送義務も発生しない。受信bufferはcallback中だけ有効で、保持するには明示copy/retainを行う。仕様例は[SDK API](sdk-api.md)。

configurationはimmutable snapshot＋revisionとして扱う。各taskが共有structを書き換える方式は禁止。変更はOwnerへrequestし、appliedの結果を得て初めて実設定として報告する。

## 5. IDと世代

NodeID、NetworkID、RadioID、LinkID、GatewayID、ServiceIDは違うもの。Wi-Fi MACを長期NodeIDへ直接流用しない。以下の番号も分ける：boot/session、message、delivery round、key epoch、membership revision、route origin sequence、control term/log index、committed channel epoch、active channel epoch、USB session。

単一の「version」で全てを兼用しない。再起動時に戻ってよい候補情報と、絶対に戻してはいけない鍵・管理番号を別storeに置く。

## 6. CPU・RAM・Flash

C3のPSRAMなし構成を基準にbounded containerを選ぶ。RX64/TX64×250Bだけで32KBに達し、それ以外のmetadata、crypto、route、driver、stackも計上する。起動時・定常・Join集中・OTA時の内部heap低水位を測る。実際に収まらないprofileを100台対応と名乗らない。

大きいobject用bufferは同時枠を確保してから受理する。ログの整形はPC側、deviceは固定長event ring。一般DATAごとにNVS全体を書かない。

## 7. PC停止との独立性

無線と経路維持はESP32側。PC停止でも別電源で稼働中なら中継を続けられる。USB給電が失われればノードも停止する。

Gateway SDK受領、PCdaemon受領、PC永続化、PCアプリ適用は別結果。USB通信があるだけでhost serviceが正常と広告しない。service availabilityはleaseで失効させる。

公式実行基盤：[ESP-IDF FreeRTOS](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/freertos_idf.html)。無線callback規約は[ESP-NOW](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/network/esp_now.html)を参照。

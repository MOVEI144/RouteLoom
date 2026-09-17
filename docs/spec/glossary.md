# 用語

| 用語 | 日本語での意味 |
|---|---|
| ESP-NOW | AP接続を必須にしないESP32間の通信機能 |
| Wi-Fi LR | Espressif独自の2.4GHz長距離PHY。250/500kbps |
| LoRa | SX1262等で使う別方式。Wi-Fi LRではない |
| Node | 独立Identityを持つ機器 |
| Gateway | PCやserviceへの出口 |
| Controller | 正式管理操作を調整する現在の担当 |
| voter | 永続管理logを持つ合意参加者 |
| Join | 認証・承認して論理Networkの仲間になること |
| Resume | 既存の所属を使って再接続すること |
| Route repair | 所属を変えず通り道を直すこと |
| Peer | ESP-NOW driver内の直接相手登録。台帳全体ではない |
| hop | 一つの無線区間を先へ進むこと |
| HOP_ACCEPT | 次のSDKが認証してRAM queueに受けた証拠 |
| END_RECEIPT | 最終宛先SDKが受けた証拠 |
| APP_RESULT | アプリが定義した処理結果 |
| Airtime | 電波上で送信する時間。queue待ちとは別 |
| CCA | 送信前に無線の使用を確認するdriver側の処理 |
| hidden terminal | 互いに聞こえない送信元が同じ受信機で競合する状態 |
| backpressure/credit | 受信側の余裕に合わせて送信量を抑える仕組み |
| DRR | 各queueへ費用の持ち分を配り、公平に送る方式 |
| feasibility | loopを避けるため経路を採用してよい条件 |
| quorum | 正規に登録した構成員の過半数等の確定条件 |
| epoch/revision | 役割を区別した状態の世代 |
| committed/active | 正式に保存した計画／実際に適用した状態 |
| HIL | 実ボードを使って動作・障害を確認する試験 |
| RPK | certificate chainの代わり等に使う公開鍵credential |
| opaque payload | SDKが業務の意味を解釈しないデータ |

公式の概念説明は[資料一覧](../references/official-sources.md)を参照。RouteLoom固有の規約は各specが正本。

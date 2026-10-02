# sleep sample

[main.cpp](main/main.cpp) は既存 Device の自動 sleep cycle を起動します。
DevRam／endpoint の試験専用です。独自の sleep engine や直接の `esp_deep_sleep_start` は使いません。
Device の Owner が prepare → drain → 保存/readback → ticket → enter を実行します。

```sh
cd examples/sleep
idf.py set-target esp32c3
idf.py menuconfig
idf.py build
```

1. ESP-IDF v6.0.3 を export し、node/network/channel/開発鍵を [quick start](../../docs/user/quickstart.md)と同じ条件にします。
2. defaults は `ROUTELOOM_DEEP_SLEEP=y`、10 s 後に prepare、radio-on 最大 40 s、timer wake 30 s です。`menuconfig` の `RouteLoom device` で必要な時間を選びます。gateway では使えません。
3. chip/MAC と PT-4M-v2 を確認して image を書き、console の起動・sleep・再起動を確認します。失敗や radio-on 予算切れは正常 sleep と数えません。
4. 通信を組み込む場合は posted job／poll hook を使い、`on_sleep_pending_result` の pending 結果も扱います。callback から再入しません。

この短い sample は sleep の起動経路を示します。周期送信や電池寿命を保証しません。
RTC drift、実際の wake 時間、電池側電流と孤立後復帰は H2 実施予定です。
[power 契約](../../docs/spec/power.md)、[利用ガイド](../../docs/user/guide.md)を参照してください。

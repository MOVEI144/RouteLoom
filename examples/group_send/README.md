# group／ALL 送信 sample

既存の Device と gateway-scoped tree で短い ALL payload を送ります。
DevRam の試験専用です。固定の開発鍵は製品の identity ではありません。
[main.cpp](main/main.cpp) は Owner の poll hook から 60 s ごとに送信し、
callback は受信と集約結果だけを記録します。queued と最終配送結果を分けます。

## build と 2 台の設定

ESP-IDF v6.0.3 を export して repo 内で実行します。PT-4M-v2 は既存 endpoint example の table を共有します。

```sh
cd examples/group_send
idf.py set-target esp32c3
idf.py menuconfig
idf.py build
```

1. A は defaults の NodeId 1、gateway role／gateway_small、DevRam、scoped routing の root にします。この app は USB stream を付けない standalone root です。
2. B は同じ sample を別 build directory で build し、NodeId 2、endpoint role/profile、primary route gateway 1 にします。両方の network・channel・開発鍵を一致させます。scoped routing は両方で ON にします。
3. chip/MAC と旧 flash layout を確認してから対応する image を書きます。[quick start](../../docs/user/quickstart.md)と [移行](../../docs/user/migrating-v2.md)の手順を使います。
4. 参加・経路の収束後、B の `group 65535` と A の最終 state、delivered／missing／unaccounted を確認します。root 自身や非 member を配送数と混同しません。

payload は最大 127 B。ALL は全 member 宛で、任意 group の設定とは別です。
Member の group tree、順序、repair と sleep の未決着結果は [group 契約](../../docs/design/sdk-v1/group-delivery.md)を参照してください。
この sample の build は RF・多数台の認定ではありません。

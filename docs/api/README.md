# API reference

利用者の入口は Device。portable core の C ABI は adapter を自分で実装する利用者向けで、ESP-IDF の Device C API とは別の surface である。

| Surface | Reference と契約 |
|---|---|
| Device C++ | [device.hpp](device.hpp.md)、[SDK 契約](../spec/sdk-api.md)、[C++ example](../../examples/endpoint_cpp/README.md) |
| Device C API 1 | [device.h](device.h.md)、[C example](../../examples/endpoint_c/README.md)。各 struct の size/version と Owner task の規則を守る |
| Core C ABI 3 | [routeloom.h](routeloom.h.md)、[ABI golden](../../protocol/abi-golden/core-abi3.json)。Device の起動 API ではない |
| Component Kconfig | [生成 reference](kconfig.md)。条件付き default の実効値は sdkconfig で確認 |
| API1 | [method 一覧](api1-methods.md)、[JSON Schema・fixture・mock](api1.md)、[host の正本](../spec/host.md) |
| HostLink／HostOps | [USB 契約](../spec/usb-protocol.md)、[HostOps 定義](../../components/routeloom/include/routeloom/usb_host_ops.hpp)。認証・credit・方向・capability を交渉してから使う |
| Registry | [版の生成表](../spec/compatibility.md)、[理由 ID](../../protocol/manifest.json)、[frame semantics](../../protocol/semantics.json)、[capability bits](../../components/routeloom/include/routeloom/usb_host_ops.hpp) |

header reference は全文を生成するため、対象の公開記号を省略しない。`python3 tools/gen_user_reference.py --check` が header／Kconfig／dispatch と文書の一致を検査する。core の各 C++ header の詳細は Doxygen の namespace/class/member reference を使う。

```sh
python3 tools/gen_user_reference.py --check
doxygen tools/Doxyfile
```

HTML は `build-docs/doxygen/html/index.html`、XML は同じ directory の `xml/` に生成する。CI の `routeloom-api-reference` artifact に保存する。EXTRACT_ALL と source browser で全宣言に辿れる。内部/private member は利用契約に含めない。公開 API の互換範囲は [compatibility](../spec/compatibility.md)で確認する。Doxygen artifact の生成は実機での機能認定とは別である。

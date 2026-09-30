# コンポーネント配布と外部プロジェクトからの利用

更新：2026-09-29。対象：ESP-IDF Component Manager による `components/routeloom_device`（Device 起動と facade）、`components/routeloom_espnow`（ESP-NOW binding）、`components/routeloom`（portable C++ core）の外部消費。

## 提供するもの

3 コンポーネントに `idf_component.yml` manifest を置いた。`version` は `protocol/manifest.json` の SDK 版（現在 `2.0.0-dev`）、`license` は `Apache-2.0`。Device→ESP-NOW→core の依存は同じ Git revision の sibling path で解決する。`esp_wifi`・`nvs_flash`・`mbedtls` 等の IDF 内蔵コンポーネントは CMake の `REQUIRES` と `idf` バージョン下限で表す。

manifest はレジストリ公開のためではなく、**ローカル path 参照と git 依存の解決**のためにある。現時点で ESP-IDF Component Registry への公開リリースは存在しない。

## 消費方法

### (a) EXTRA_COMPONENT_DIRS（ローカル checkout）

リポジトリを clone し、プロジェクトの `CMakeLists.txt` で `components/` を search path に追加する。

```cmake
list(APPEND EXTRA_COMPONENT_DIRS "/path/to/RouteLoom/components")
```

component manager は sibling 依存を同一 checkout から解決する。ネットワーク取得は発生しない。`examples/endpoint_cpp`（C++）、`examples/endpoint_c`（C、`routeloom/device.h`）、`examples/standalone_gateway`（host なしの親機）はリポジトリ内でこの方式で build される。

### (b) component manager の git 依存

外部プロジェクトの `main/idf_component.yml` に git 依存を記述する。

```yaml
dependencies:
  routeloom/routeloom_device:
    git: https://github.com/MOVEI144/RouteLoom.git
    path: components/routeloom_device
    version: <tag または commit SHA>
```

component manager は Device と、その manifest が指定する ESP-NOW binding・core を同じ commit から `managed_components/` に配置する。CI は `tests/idf_consumer`（C の `main.c` と C++ の `consumer.cpp`）を checkout の外に写し、この git 依存だけで C3・S3・C5・C6 の 4 chip で build する（cell `idf_consumer-<chip>-component_only`）。

git `path` 依存は component の subdirectory **だけ**を取り出す。このため vendored micro-ecc（RLCP1_COSE_ESP256 verifier の P-256 backend、BSD-2）は `components/routeloom/third_party/micro-ecc` に component 内蔵とし、component が自己完結するようにした。SDK v1 の EDHOC（P2-1）で追加した libedhoc（MIT）と zcbor（Apache-2.0）も同じ理由で `components/routeloom/third_party/` に置く（pin は `third_party/VENDORED.json` と NOTICE）。host 用 AES-CCM の TF-PSA-Crypto 部分集合も同じ場所にあるが、ESP-IDF build では compile しない（firmware は ESP-IDF 自身の Mbed TLS を PSA 経由で使う）。

## バージョン固定

- `version` フィールドは git ref（branch / tag / commit SHA）を受ける。実験以外では浮動する `main` ではなく tag か commit SHA を pin すること。
- manifest の `version: 2.0.0-dev` は依存解決上の識別子であり、公開リリースを意味しない。リポジトリに git tag はまだ存在しないため、現時点では commit SHA pin が最も確実な固定方法。
- `routeloom_espnow` の `targets` は `esp32c3` / `esp32s3` / `esp32c5` / `esp32c6`。4 chip とも必須 CI の firmware cell（`tools/ci/cells.json`）で build する。`targets` への記載や build 成功は RF・実機の認定を意味しない。

## 成熟度の正直な位置づけ

- 検証済み環境は `espressif/idf:v6.0.3`（CI pin）のみ。`idf >= 6.0` の下限はそれより古い系列を明確に拒否するためのもので、6.x 全系統の動作を保証しない。
- Component Registry への upload・semver release は未実施。`2.0.0-dev` は pre-release 状態を表す。
- build 成功は compile/link の証拠のみ。実機 RF、到達距離、電池寿命、認証適合は別途 HIL 認定が必要（`docs/STATUS.md` 参照）。
- DevRam は EXPERIMENTAL の開発 profile であり、本番 Identity（EDHOC/RPK）を置き換えない。既定 dev key を配備に使用してはいけない。

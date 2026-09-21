# コンポーネント配布と外部プロジェクトからの利用

更新：2026-09-22。対象：ESP-IDF Component Manager による `components/routeloom`（portable C++ core）と `components/routeloom_espnow`（ESP-NOW binding）の外部消費。

## 提供するもの

両コンポーネントに `idf_component.yml` manifest を置いた。`name` は `routeloom/routeloom`・`routeloom/routeloom_espnow`（namespace `routeloom` 前置）、`version` は `0.1.0`、`license` は `Apache-2.0`。`routeloom_espnow` は `routeloom/routeloom: ^0.1.0` と `idf >= 6.0` に依存する。`esp_wifi`・`nvs_flash`・`mbedtls` 等の IDF 内蔵コンポーネントは manifest の依存ではなく、従来通り CMake の `REQUIRES` と `idf` バージョン下限で表す。

manifest はレジストリ公開のためではなく、**ローカル path 参照と git 依存の解決**のためにある。現時点で ESP-IDF Component Registry への公開リリースは存在しない。

## 消費方法

### (a) EXTRA_COMPONENT_DIRS（ローカル checkout）

リポジトリを clone し、プロジェクトの `CMakeLists.txt` で `components/` を search path に追加する。

```cmake
list(APPEND EXTRA_COMPONENT_DIRS "/path/to/RouteLoom/components")
```

両コンポーネントが manifest を持つため、component manager はこれらを local component として認識し、`routeloom_espnow` の `routeloom/routeloom` 依存を同一 checkout から解決する。ネットワーク取得は発生しない。`examples/espnow_node` はリポジトリ内でこの方式で build される。

### (b) component manager の git 依存

外部プロジェクトの `main/idf_component.yml` に git 依存を記述する。

```yaml
dependencies:
  routeloom/routeloom:
    git: https://github.com/MOVEI144/RouteLoom.git
    path: components/routeloom
    version: <tag または commit SHA>
  routeloom/routeloom_espnow:
    git: https://github.com/MOVEI144/RouteLoom.git
    path: components/routeloom_espnow
    version: <tag または commit SHA>
```

component manager はリポジトリを clone し、`path` で示した subdirectory を `managed_components/` に配置する。**2 つの entry がともに必要**：`routeloom_espnow` の manifest が `routeloom/routeloom` を要求するが、registry には存在しないため、取得先を project manifest が教える必要がある。

git `path` 依存は component の subdirectory **だけ**を取り出す。このため vendored micro-ecc（RLCP1_COSE_ESP256 verifier の P-256 backend、BSD-2）は `components/routeloom/third_party/micro-ecc` に component 内蔵とし、component が自己完結するようにした。

## バージョン固定

- `version` フィールドは git ref（branch / tag / commit SHA）を受ける。実験以外では浮動する `main` ではなく tag か commit SHA を pin すること。
- manifest の `version: 0.1.0` は依存解決上の識別子であり、公開リリースを意味しない。リポジトリに git tag はまだ存在しないため、現時点では commit SHA pin が最も確実な固定方法。
- `routeloom_espnow` の `targets` は CI で compile 検証済みの `esp32c3` / `esp32s3` / `esp32c5` に限定している。他の ESP-NOW 対応 chip は未検証であり、manifest が solver 段階で除外する。

## 成熟度の正直な位置づけ

- 検証済み環境は `espressif/idf:v6.0.3`（CI pin）のみ。`idf >= 6.0` の下限はそれより古い系列を明確に拒否するためのもので、6.x 全系統の動作を保証しない。
- Component Registry への upload・semver release は未実施。`0.1.0` は pre-release 状態を表す。
- build 成功は compile/link の証拠のみ。実機 RF、到達距離、電池寿命、認証適合は別途 HIL 認定が必要（`docs/STATUS.md` 参照）。
- `DevelopmentPskSecurityProvider` は EXPERIMENTAL の開発 profile であり、本番 Identity（EDHOC/RPK）を置き換えない。既定 dev key を配備に使用してはいけない。

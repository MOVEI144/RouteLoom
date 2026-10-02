# 実装状況とリリース条件

更新：2026-10-02。確認基点：`ee9b018ebdb7e741b4932d257a8537b4db53dc1b`。
SDK の manifest は **2.0.0-dev**。この表は v2.0 の実装と残る受入を示し、正式版の公開・本番認定を宣言しない。

## 公開面と利用の入口

C ABI 3、Device C API 1、wire major 2／minor 0、HostLink protocol 2、API1 envelope 1／caps_version 2、partition は PT-4M-v2。
番号と読込み可能な保存形式は [manifest](../protocol/manifest.json) と [互換性](spec/compatibility.md) が正本。

この文書更新の command・skip・容量は [検証記録](reviews/2026-10-02-v2-docs-final.md)を参照する。

[入門](user/quickstart.md) → [利用](user/guide.md) → [運用](user/operations.md)。
旧開発版からは [移行ガイド](user/migrating-v2.md) を使う。
reference／bridge／bench の既定は MemberEdhoc（Candidate）。component と quick start／examples は DevRam（Development）。LegacyFixture は撤去済み。Candidate を Production と表示しない。

## v2.0 のリリース条件

「実装済み」「host-tested」「build-tested」「hardware-tested」「qualified」を分ける。
下の試験欄は repository にある試験・記録の範囲。現在の全条件が合格したという意味ではない。
`live` は実行経路の登録状態であり、全 variant の実施証拠ではない。未実施の half は [E2E 行列](../tests/e2e/scenarios.json) の `acceptance_pending` と pending 行で確認する。

| 条件 | 実装 | ソフトウェア試験・build の範囲 | HIL・未完了条件 |
|---|---|---|---|
| G-CORE：配送・有界資源・C ABI | 実装済み。C ABI 3、Device C/C++、Reliable／APPLIED／group | portable CTest、ABI golden、P05-O/C/S、満杯・世代・再入試験 | C/C++ APPLIED の実機全経路は H2 実施予定（P05） |
| G-SEC：MemberEdhoc・認証・失効 | 実装済み。製品既定切替、参加停止、再参加、GK／失効 gossip。LegacyFixture 撤去 | crypto／保存 golden、J01–J05、real Owner。Member image の開発鍵／provider 検査 | Candidate。H2 実施予定。NVS 電断・鍵 custody／保管の運用資格は未完了。#99／#148。#100 は非ブロッキング |
| G-JOIN：賢い参加・復帰 | V2-18 実装済み、opt-in。最大 3 mark、有限探索 | J02/J03、M05、留保した所属の復元・予定取消・reply 損失 | H2 実施予定。6／31 台の全 variant と実機の集中参加は未完了 |
| G-ROUTE：複数 hop・修復・負荷 | 実装済み。V2-STAB と最終 EDHOC reply／発見修正を含む | M01-T3、強制 2/3/4-hop、M08、K01/K02/K03。100 台 model は RF 資格とは別 | H2／H3 実施予定。混在機の relay reset・channel round は過去の未合格を再受入する |
| G-USB／G-HOST：HostLink と daemon | protocol 2、個別 secret、credit、耐久 operation、API1 cursor を実装 | C++／Rust golden、F07、K05、consumer、legacy SEND 回帰 | 実 USB の過去の部分確認あり。再接続 campaign・長期・実 process kill は H2／H4 実施予定 |
| G-POWER：sleep・期限駆動 | V2-15 実装済み。Device と既存 coordinator の保存／ticket 経路を統一 | F09、F09-O（real Owner・24 h virtual time）、期限 trace、readback／失敗試験 | F09-H2 は実施予定。RTC drift・起動遅延・wake・電池側電流は未確認（#148）。Owner 25 ms は達成を宣言しない |
| G-CONTROL：設定・手動 channel plan | SingleAuthority、Member/DevRam config、Member SAK plan、全対象 READY gate を実装 | authority power-cut model、config／plan golden、実 Owner の切替・取り残し回帰 | 実 NVS 電断と切替の再受入は H2 実施予定。HA の選挙／log／snapshot は未実装 |
| G-OBJECT：AppObject | V2-19 実装済み、既定 OFF。unicast 最大 4096 B | M10、P04-O、parser／context／期限、ON/OFF 中継、容量 build | AppObject の実 RF は未認定。H2／H3 で確認予定。C3 bridge ON の RAM 増は 5 KiB 目標未達、C5 ON は gateway_small が必要 |
| G-BOARD／G-RF：chip・無線 | S3／C3／C6 対応、C6 RF switch 設定。C5 build 対応 | [CI cell](../tools/ci/cells.json) が構成・容量 guard の正本。build は RF 合格ではない | H2／H3 実施予定。C5 は実機確認待ち。距離・干渉・LR500・アンテナ／電源の資格は未完了 |
| G-SYSTEM：長期・配布物からの再現 | E2E harness、HIL 道具、配布基盤は実装済み | real Owner の K01/K05、外部 consumer build、P06-O standalone | H4 実施予定。5 台 24 h soak、20 回 reset、正確な RC archive からの P01/P06/K06 が必要 |
| G-LICENSE／RELEASE：配布の完全性 | NOTICE／license／SBOM／hash／provenance／本番鍵 gate／RC 昇格を実装 | release tooling の検査。任意署名は選択した方式で別途検証 | H4 実施予定。正式 tag／配布／署名方式と private reporting 設定は maintainer が行う |

sleep、賢い参加、AppObject、公開文書、配布基盤を pending PR と扱わない。
実装済み機能でも RF／本番 profile／長期運用の資格は別である。

## 実機の記録と次の回

H2／H3／H4 はいずれも **実施予定**。この文書更新では実機を操作していない。
S3／C3／C6 の過去の部分合格は構成・SHA・項目ごとに読む。C5 は **実機確認待ち**。

| 記録・回 | 状態と範囲 |
|---|---|
| [H0](hil/2026-09-29-h0.md)／[H1](hil/2026-09-30-h1.md) | 過去の実施記録。未合格と未実施を次の回へ引き継ぐ |
| [STAB follow-up](hil/2026-10-01-stab-fix.md) | 強制 2-hop relay reset 61/100、通常同時起動 4/5、6→1 後の各 member 0/20。未合格 |
| [HC6](hil/2026-10-02-hc6.md) | 基点 c3a89102、C3 gateway＋C6 relay/endpoint。gateway reset と厳密 J05 control は部分合格。relay reset／channel round は未合格、正確な missed-switch は未実施。全体 HIL_FAIL |
| H2 | 実施予定。最新修正後の参加・復帰・失効・設定・sleep・API と配送を再受入する |
| H3 | 実施予定。RF・距離・干渉と複数 hop の資格を確認する |
| H4 | 実施予定。正確な RC 配布物、app-only 更新、利用者手順、5 台 24 h soak を確認する |

HC6 後の V2-HFIX-HC6／V2-STAB-D／最終 E2E 修正を含む本基点での実機再受入は未実施。
短い smoke、driver の ESP_OK、host の virtual time、CI build を HIL の代わりにしない。
手順は [HIL runbook](hil.md)、RC 昇格条件は [release](releases.md) を参照する。

## v2.1 と非ブロッキングの追跡

| 項目 | v2.0 での扱い |
|---|---|
| crypto worker（V2-16） | v2.1。未実装。Owner 最長占有 25 ms／背景配送 99% の F08 は未受入 |
| IP gateway | v2.1。未実装。STA と LR の同時運用を保証しない |
| UART coprocessor | v2.1。未実装。USB の成功を UART の資格へ移さない |
| メッシュ経由 OTA（[#103](https://github.com/MOVEI144/RouteLoom/issues/103)／[#171](https://github.com/MOVEI144/RouteLoom/issues/171)） | v2.1。未実装。PT-4M-v2 と AppObject は OTA の実装証拠ではない |
| 人による第三者レビュー（[#100](https://github.com/MOVEI144/RouteLoom/issues/100)） | 未完了のまま追跡。v2.0 の非ブロッキング項目。監査済みとは表示しない |

自動移設、圧縮、LoRa、LR500 適応と管理 HA は v2.0 の提供機能に含めない。
既知の実装不足は [discovery の現状](spec/radio.md) にも記載する。
過去の設計・レビューは履歴であり、現在の既定値と利用手順は [文書案内](README.md) を入口にする。

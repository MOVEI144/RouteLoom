# 管理合意・Controller・設定世代

## 1. 何を合意するか

参加承認の確定、membership失効、ネットワーク鍵更新、ネットワーク全体のchannel変更、管理構成員、遠隔設定の権限を管理ログに置く。通常のpacket中継や局所的route選択を一件ずつ多数決にしない。

ControlAuthorityはRadioへcommit済みの操作を渡す。interfaceは `propose / watch_committed / get_snapshot / verify_operation`。propose受付はcommit成功ではない。

## 2. ControllerとGateway

Gatewayは出口、Controllerは現在の管理調整担当、voterは永続状態を保持する合意参加者。兼任はできるが別のcapabilityとする。NodeにUSBを挿しただけでvoterや管理者にしない。

自動交代は標準ポリシーON。ただし登録済み構成員の過半数、正しいログ、認証済み通信を条件にする。

| 登録構成 | 動作 |
|---|---|
| 3voter中2到達 | 正当な選挙とcommitが可能 |
| 2voter中1到達 | 管理変更を確定しない |
| 1voter構成 | 単独管理は可能。管理冗長性なし |
| データGatewayが4台 | 4票と同義ではない |

PC、Gateway、給電Relayをvoterにできるが、必要な管理状態と秘密の安全な保存が条件。logを持たず票だけを返すwitnessはv1に入れない。全3者が同じ電源なら独立故障耐性を宣伝しない。

## 3. 合意Provider

Raft系のlog複製・選挙・snapshot・構成員変更を満たすProviderを採用する。Raftの名前だけを借りてheartbeat timeout＋最大IDだけの独自選挙にしない。

必須永続状態：current term、投票先、管理logまたは適切なsnapshot、構成員世代、最後のcommit/applied位置。投票を返す前に必要状態を耐電断保存する。commit済みentryを後から未確定entryで上書きしない。

参考：[Raft公式資料](https://raft.github.io/)。ライブラリ／ESP32移植・log媒体の固定とクラッシュ検証はG-CONTROLで行う。参考アルゴリズムを文書に書いただけで正しさが証明されたとはしない。

## 4. 分断中

過半数側だけ新管理操作をcommitできる。少数側は既存の有効な設定でできるDATAと経路修復を続ける。少数側が不在voterを削除して一人過半数を作ることは禁止。

既に有効なmembershipのresumeは新規承認と異なり、credentialやepochが有効なら多数不在でも許せる。新規Joinの未承認端末へ所属を発行することはできない。

再結合時は正規log/snapshotで追従する。壁時計が新しい設定を無条件採用するLWWは使わない。アプリの業務競合はSDKが統合せず、アプリに渡す。

## 5. 管理オブジェクト

各操作はNetwork、構成員世代、term、log index、前状態hash、操作hash、正当な発行主体、commit証拠を持つ。hashだけを保存して再起動後に根拠を取得不能にしない。上限を超えた履歴は認証済みsnapshotで圧縮する。

channel epoch、key epoch、membership revision、control term/log indexを分ける。同一epochで異なる内容が届けばCONFLICT。channel rollbackも新log entry・新channel epochである。

## 6. 全体変更と局所不在

予定したsurveyやchannel cutoverを、むやみにController故障と判定しない。管理選挙のtimeoutは実測した管理往復分布・最大予定不在と整合させる。ただし安全なcommit条件を省略して速度だけ上げない。

無線調査と管理voter可用性が競合したら計画を延期する。全voterを同時に別channel調査へ送らない。移行commitを受けたvoterが新channelへ去り、残存者が旧channelで多数を失う事象も試験する。

## 7. 構成員変更・復旧

voter追加・削除は旧構成の正当な手順で行い、単純な配列上書きにしない。多数を恒久喪失した場合の災害復旧は明示管理操作で新しい管理構成を確立する。通常の自動競合解決と混同せず、監査と旧権限の無効化を必要とする。

[チャンネル移行](channel-migration.md)／[セキュリティ](security.md)

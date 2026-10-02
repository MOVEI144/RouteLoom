# Security の段階とアプリの責任

| 表示 | 意味 |
|---|---|
| Development | DevRam／開発鍵。試験用途。製品 identity・本番認可の証拠にならない |
| Candidate | MemberEdhoc の実装があるが、本番認定条件が揃っていない |
| Production | 認定記録を満たした image のみ。現在の一般 image にこの表示を約束しない |

[security 契約](../spec/security.md)と[認定条件](../design/sdk-v1/08-implementation-plan.md)が正本。CA／SAK／HostLink secret は別の資格情報として保管する。USB session は HostLink v2 の HKDF＋HMAC-SHA256 で結合し、API1 は socket の OS principal と ACL で認可する。API1 の JSON に principal を指定しない。TLS／remote API1 は現在の local IPC の機能ではない。必要なら利用側の境界で認証・暗号化する。

group の共通 GK は group の参加者による認証であり、個々の警報送信者を第三者に証明する署名ではない。警報に送信者の証明（Q4）が必要なら、アプリで個別署名・検証と保存の要件を定義する。状態の group 通知から業務上の発信者認証を推測しない。receive assurance が UNKNOWN／unverified の record を verified と表示しない。

電源断をまたぐ nonce/replay の安全性、鍵の custody tier、独立 review、長期 RF/HIL は別の認定項目。人による第三者レビュー #100 は v2.0 の非ブロッキング項目として残る。脆弱性は [SECURITY.md](../../SECURITY.md)の GitHub private vulnerability reporting で報告する。AI review や host sim の成功を独立 security review として数えない。機器の除去は正式な revoke／leave／deprovision 手順で行い、DB の行の削除だけで失効したと扱わない。

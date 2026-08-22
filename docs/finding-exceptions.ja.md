# Finding Exception運用ガイド

Finding Exceptionは、一時的かつ監査可能な抑制です。Security Policyへ混ぜず、独立したYAMLまたはJSONファイルで管理します。

```yaml
version: 1
exceptions:
  - id: EXC-2026-001
    rule_id: SC-AUTHN-001
    selector:
      method: POST
      path: /webhooks/stripe
      target: cloudflare
      environment: production
    reason: Application verifies the signed webhook payload.
    owner: payments-team
    expires_at: 2026-12-01
    ticket: SEC-123
```

`id`、`rule_id`、`selector`、`reason`、`owner`、`expires_at`は必須です。可能ならExactな`instance_id`を使い、それ以外はExactな`method`と`path`で限定します。Rule-onlyまたはWildcard Selectorは、`allow_broad: true`と独立した`broad_reason`がない限り拒否されます。理由欄にはCredential、Token、Cookie、Passwordなどの秘密情報を記載しないでください。

`loadFindingExceptions()`で読込み、結果と明示的なISO形式の`currentDate`を`applyFindingExceptions()`へ渡します。日付を明示することでCI出力を決定的にします。Reportには有効な`findings`、元の`suppressedFindings`、Sort済み`appliedExceptionIds`、抑制前後の件数が含まれます。

## 更新・期限延長・削除・監査

1. 最も限定的なExceptionを作り、Owner、理由、期限、追跡Ticketを記録します。
2. CIごとにReportを確認します。期限切れは抑制せず`SC-GOV-001` Error、未使用は`SC-GOV-002` Warning、複数一致は`SC-GOV-003` Warningとなり、最も限定的な1件だけが適用されます。
3. 延長が必要なら通常のCode Review履歴を通して`expires_at`を更新します。自動延長はしません。
4. Findingが消えた、または原因を修正した時点でExceptionを削除します。Version Control履歴を監査記録として保持します。

Parser、Schema、Unsafe Input、Governance、および明示的な`non-waivable` Findingは抑制できません。

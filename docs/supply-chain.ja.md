# サプライチェーンセキュリティ

> **言語:** [English](./supply-chain.md) · 日本語

本フレームワークは **SLSA v1 ビルドプロベナンス（ビルド来歴証明）** 付きで npm に公開されます。公開される全ての tarball は、それを生成した GitHub Actions ワークフローによって署名され、アテステーション（署名付き証明）は npm レジストリ側に記録されます。

このドキュメントは、利用者が `npm install` した tarball が本リポジトリから正しくビルドされたものであることを検証する方法を説明します。

---

## なぜ必要なのか

メンテナの npm トークンが漏洩した攻撃者は、GitHub のソースツリーを 1 行も書き換えずにバックドア入りの `cdn-security-framework` を公開できます。プロベナンスアテステーションはこの攻撃を防ぎます。アテステーションは、tarball が本リポジトリのタグ付きコミットで動作した `.github/workflows/release-npm.yml` によって生成されたことを証明します。有効なアテステーションを持たない tarball、あるいは別のリポジトリを指すアテステーションを持つ tarball は、どのような経路で手元に届いたとしても疑うべきです。

---

## 公開バージョンを検証する

### ワンライナー

```bash
npm install cdn-security-framework
npm audit signatures
```

`npm audit signatures` は、インストール済みの全パッケージについてレジストリのアテステーション API に問い合わせ、アテステーションが欠落している／無効なものが 1 つでもあれば非 0 で終了します。CI で `npm install` の後に毎回走らせてください。軽量で、サプライチェーン侵害の多くを捕まえられます。

### 期待される出力

```
audited N packages in 1s

N packages have verified registry signatures
```

`cdn-security-framework` が "verified" として表示されない場合は、スクリプトを実行する前に一旦停止して調査してください。

### アテステーションを直接確認する

```bash
npm view cdn-security-framework dist.attestations
```

`publish.sigstore.dev` のアテステーションは、ソースリポジトリとして `albert-einshutoin/cdn-security-framework` を、ワークフローとして `.github/workflows/release-npm.yml` を指しているはずです。それ以外の値は、tarball が本プロジェクトの CI から出たものではないことを意味します。

---

## バージョンを厳密にピン留めする

プロベナンスアテステーションは特定のバージョンに紐づきます。新規インストール時は以下のようにピン留めできます。

```bash
npm install cdn-security-framework@1.0.0 --save-exact
```

既定の `^1.0.0` 指定では、npm は任意の将来の `1.x` リリースに解決します。CI で `npm audit signatures` を毎回実行していれば安全ですが、より厳密にピン留めすれば、アップグレードのたびに手動レビューを挟めます。

---

## サプライチェーン上の問題を報告する

アテステーション不一致、リリースタグにアテステーションが存在しない、タグ付きコミットと tarball が一致しない、などの事象を発見した場合は、公開 Issue ではなく本リポジトリの GitHub Security Advisories から非公開で報告してください。以下を併記してください。

- インストールした正確なバージョン
- `npm audit signatures` の出力
- `npm view cdn-security-framework@<version> dist.attestations` の出力

---

## メンテナ向け

### 公開前の2.0候補準備

リリース条件の正本は、[#890（人間の導入評価）](https://github.com/albert-einshutoin/cdn-security-framework/issues/890)、[#1024（技術監査）](https://github.com/albert-einshutoin/cdn-security-framework/issues/1024)、[#542（状態整合レビュー）](https://github.com/albert-einshutoin/cdn-security-framework/issues/542)、[#895（GO判断）](https://github.com/albert-einshutoin/cdn-security-framework/issues/895)、[#571（version付きリリース）](https://github.com/albert-einshutoin/cdn-security-framework/issues/571)です。

1. 依存・振る舞い・workflow・文書の修正を終えてからRCを固定します。source/tree SHA、成功したmain pushのrun/attempt、候補tgz SHA-256、consumer lock SHA-256を記録し、取得した実byteを照合します。Actions ZIPのdigestは別の値です。
2. その候補と同じ版のrepository内の[EN](https://github.com/albert-einshutoin/cdn-security-framework/blob/main/test/onboarding/novice-evaluation.md)/[JA](https://github.com/albert-einshutoin/cdn-security-framework/blob/main/test/onboarding/novice-evaluation.ja.md)シートを実際の評価者へ渡します。人間が実施するまで所要時間・Finding理解は未評価のままです。自動journeyの成功は別の証拠です。
3. `npm-release` environmentにrequired reviewersと`prevent_self_review: true`を設定します。リリース起動者は自分のjobを承認できないため、公開前に承認可能な担当者を確認します。workflowには承認・environment・runの参照と承認済みartifact取得用の`contents: read`、`actions: read`、`issues: read`が必要です。`id-token: write`はprovenance用です。ローカル管理者権限による参照成功だけではworkflow tokenの権限を証明しません。
4. 必要な評価とRC GOの後、#571でpackage/root-lockのversionとEN/JA Changelogだけを変更します。依存や振る舞いの変更には新RCと影響評価が必要です。最終main pushの成功runとtarballを評価済みRCに結び付けます。feature branchやPRのrunでmainの記録を代用しません。
5. ownerが#890に実際のH01評価（`CSF_H01_ASSESSED_V1`）、#895に候補を特定した判断（`CSF_RELEASE_APPROVAL_V1`）を記録します。検証器はRCと最終候補のidentity、最終差分の評価、必須job、保護environment、正確な4ファイルのrelease差分を確認します。準備・空欄のフォーム・判断の下書きはGOではありません。
6. 移行前のv1 Policyと[文書化した隔離1.4.0 rollback](./quickstart.ja.md)を利用可能にします。公開前の条件が未充足ならtagを作らず停止します。公開とregistry検証は、この準備とは別工程です。

公開しないローカル確認は`npm run build:ts && node scripts/release-binding-unit-tests.js`です。合成入力による正常・拒否ケースの成功は、人間の承認や実際のenvironment設定を証明しません。`release-npm.yml`には実際のpublish stepがあるため、gateの試験だけを目的に起動しないでください。

### 承認後の公開

リリース公開は `.github/workflows/release-npm.yml` で行われます。

1. `npm publish --provenance --access public` — ワークフローの OIDC アイデンティティで tarball を署名します
2. publish 後のステップで、公開直後の tarball をレジストリから再取得し、`npm audit signatures` を走らせます。アテステーションの記録が抜けていた publish はここで失敗するため、問題は利用者ではなく CI 側で捕まります。

ローカルからの `npm publish` は検証可能なアテステーションを発行できないため、絶対に手動 publish はしないでください。

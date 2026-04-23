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

リリース公開は `.github/workflows/release-npm.yml` で行われます。

1. `npm publish --provenance --access public` — ワークフローの OIDC アイデンティティで tarball を署名します
2. publish 後のステップで、公開直後の tarball をレジストリから再取得し、`npm audit signatures` を走らせます。アテステーションの記録が抜けていた publish はここで失敗するため、問題は利用者ではなく CI 側で捕まります。

ローカルからの `npm publish` は検証可能なアテステーションを発行できないため、絶対に手動 publish はしないでください。

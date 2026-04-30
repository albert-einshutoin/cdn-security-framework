# テンプレート注入契約

> **言語:** [English](./template-injection-contract.md) · 日本語

`cdn-security` は生成される Edge Runtime の監査性を重視します。利用者は bundle / minify されたコードではなく、生成済みの `dist/edge/*.js` や `dist/edge/cloudflare/index.ts` をそのまま確認できます。

そのため、runtime template では AST や bundler による config 埋め込みへ置き換えず、明示的な marker comment を維持します。

## 契約

各 runtime template は、注入される config block ごとに marker を正確に 1 つだけ持つ必要があります。

| Template | 必須 marker | 注入される const |
| --- | --- | --- |
| `templates/aws/viewer-request.js` | `// {{INJECT_CONFIG}}` | `const CFG = ...` |
| `templates/aws/viewer-response.js` | `// {{INJECT_RESPONSE_CONFIG}}` | `const RESPONSE_CFG = ...` |
| `templates/aws/origin-request.js` | `// {{INJECT_CONFIG}}` | `const CFG = ...` |
| `templates/cloudflare/index.ts` | `// {{INJECT_CONFIG}}` | `const CFG = ...` |
| `templates/cloudflare/index.ts` | `// {{INJECT_RESPONSE_CFG}}` | `const RESPONSE_CFG = ...` |

marker が欠落、または複数存在する場合、compiler は失敗します。

## 注入後チェック

置換後、compiler は生成物を parse し、それぞれの config が top-level の `const` 宣言として正確に 1 つだけ存在することを検証します。Cloudflare Worker 出力は検証時だけ TypeScript から JavaScript へ変換して parse します。デプロイされる成果物は生成済み TypeScript のままです。

これにより、デプロイモデルを変えずに壊れた注入を検出できます。

## Bundler 埋め込みを既定にしない理由

Bundler や AST レベルの config 埋め込みを永久に拒否するわけではありません。ただし、既定にはしません。理由は以下です。

- 監査性: 生成物が source template に近いまま保たれる
- diff の読みやすさ: policy 変更が config 差分として追いやすい
- デプロイサイズ管理: CloudFront Functions には厳しいサイズ制限がある
- 依存の抑制: runtime code generation に bundling step を必須化しない

marker 方式で、現在の検証では捕捉できない具体的な不具合が出た場合に再検討します。

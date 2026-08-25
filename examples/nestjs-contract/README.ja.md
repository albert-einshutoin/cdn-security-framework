# NestJS static contract example

NestJSのroute/auth metadataをSourceだけから抽出し、OpenAPI/Policyとの差分を
確認するfixtureです。NestJSの起動やdecoratorの実行は行いません。

clean checkoutから実行します。

```bash
npm ci
npm run build:ts
node examples/nestjs-contract/run-analysis.cjs
```

scriptはfixtureを隔離一時workspaceへcopyし、同梱した型stubだけをそこへ配置して、
入力projectを変更せず決定的なsummaryを出力します。
alias、path alias、継承、duplicate route、unknown Guard、dynamic path、未読込の
project reference、runtime prefix/versioningを意図的に含みます。対応範囲とsecurity
boundaryは`docs/source-analysis-nestjs.ja.md`を参照してください。

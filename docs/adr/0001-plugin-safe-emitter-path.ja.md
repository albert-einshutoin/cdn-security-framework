# ADR 0001: Plugin-Safe Emitter Path

> **Status:** v1.3.x 向け提案

## 背景

現在の runtime compiler は、`// {{INJECT_CONFIG}}` のような明示的な marker
comment を持つ auditable な edge template に、policy 由来の config を注入します。
compiler は marker の数を検証し、注入後の生成物を parse します。この contract は安定しており、
v1.3.0 では default のまま維持します。

次の architecture 上の論点は、custom auth gate のような plugin-provided runtime logic を、
review 不能な文字列連結にせず、どう安全に統合するかです。

## 選択肢

### marker contract を維持する

利点:

- 生成ファイルが template に近く、diff しやすい。
- CloudFront Function の size / syntax 制約が見えやすい。
- 現行 CLI path に bundling step が不要。

欠点:

- user-provided runtime module を merge する基盤としては弱い。
- parse validation があっても、config は source text として注入される。
- plugin code の module graph check はできない。

### esbuild virtual module を使う

利点:

- policy config を generated virtual module として公開できる。
- plugin / runtime code は global marker replacement ではなく typed binding を import できる。
- bundle step により、syntax / module graph failure を deploy 前に検知できる。

欠点:

- bundling 後に `const` が `var` になるなど、output shape が変わり得る。
- 現行 template より audit しづらい生成物になる可能性がある。
- CloudFront Function の size / compatibility は target ごとに検証が必要。

### Babel/SWC AST transform を使う

利点:

- template の output shape をより保ちやすい。
- top-level declaration の挿入位置を精密に制御できる。

欠点:

- AST 操作の複雑さが増える。
- plugin が依存を import する場合、別途 module graph handling が必要。

## 決定

v1.3.0 では marker-based injection を production default として維持します。

一方で、将来の plugin-safe path を検証するため、isolated な esbuild virtual-module
prototype を追加します。この prototype は CLI 出力を変更しません。検証する invariant は次の通りです。

- 生成物が parse できる
- config binding が top-level にちょうど 1 回だけ出現する
- template / plugin source が config binding を shadow できない
- deploy 前に failure を表面化できる

## Threat Model

prototype が対象にするもの:

- malformed な edge runtime syntax
- generated config declaration の重複
- plugin / template code による generated config binding の shadowing
- deploy 前の module graph failure

まだ対象外のもの:

- malicious plugin package による supply-chain risk
- 任意 user code の semantic safety
- plugin logic による runtime resource exhaustion
- 最終的な CloudFront Function bundle-size enforcement

これらには、別途 plugin permission / packaging model が必要です。

## Migration Path

1. 現行の template injection contract を維持する。
2. isolated bundler prototype と test を保守する。
3. custom runtime plugin が product requirement になった段階で、target-gated experimental emitter に昇格する。
4. output compatibility、auditability、size、deploy behavior が証明された target からのみ marker injection の置換を検討する。

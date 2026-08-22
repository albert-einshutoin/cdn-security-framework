# Request limit Recommendation

`recommendRequestLimits(contract, options)` は Security IR v1 から決定論的な候補を生成します。Policyの変更やEnforceは行いません。

既定のSafety Marginはabsolute 0、ratio 10%です。`margin.absolute`と`margin.ratio`で変更できます。負数、10を超えるratio、1,000,000,000を超えるabsolute、safe integerを超える結果は拒否します。

Bodyのcompact推定は、`maxLength`付きJSON string、boolean、全propertyを推定できるclosed object（`additionalProperties: false`）、`maxItems`と対応済み`items`を持つarrayに対応します。JSON whitespaceは字句byte上限がない限り無制限のため、Enforce可能なupper boundではなく`partial`です。integer/numberの任意字句、JSON以外のmedia type、上限なしstring/array、free-form object、recursive/composed schema、multipartは`unknown`です。query/pathは最悪のpercent encodingを含め、上限なしquery API keyがある場合のquery長は`unknown`です。

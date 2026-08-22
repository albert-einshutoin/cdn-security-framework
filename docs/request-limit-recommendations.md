# Request limit recommendations

`recommendRequestLimits(contract, options)` derives deterministic candidates from Security IR v1. It does not edit policy or enable enforcement.

The default safety margin is 10% with no absolute addition. Callers may set `margin.absolute` and `margin.ratio`; negative values, ratios above 10, absolute additions above 1,000,000,000, and unsafe-integer overflow are rejected.

Compact body estimates support JSON strings with `maxLength`, booleans, closed objects (`additionalProperties: false`) whose properties are supported, and arrays with `maxItems` and supported `items`. They are `partial`, not enforceable upper bounds, because JSON whitespace is unbounded without a lexical byte constraint. Integer/number lexical forms, non-JSON media types, unbounded strings/arrays, free-form objects, recursive or composed schemas, and multipart bodies return `unknown`. Query and path estimates account for worst-case percent encoding; unbounded query API-key values make query length `unknown`.

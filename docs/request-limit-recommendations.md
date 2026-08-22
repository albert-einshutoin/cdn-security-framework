# Request limit recommendations

`recommendRequestLimits(contract, options)` derives deterministic candidates from Security IR v1. It does not edit policy or enable enforcement.

The default safety margin is 10% with no absolute addition. Callers may set `margin.absolute` and `margin.ratio`; negative values, ratios above 10, absolute additions above 1,000,000,000, and unsafe-integer overflow are rejected.

Finite body estimates support JSON strings with `maxLength`, booleans, closed objects (`additionalProperties: false`) whose properties are supported, and arrays with `maxItems` and supported `items`. Integer/number lexical forms, non-JSON media types, unbounded strings/arrays, free-form objects, recursive or composed schemas, and multipart bodies return `unknown`. JSON string estimates account for the longest escaped representation; query and path estimates account for worst-case percent encoding.

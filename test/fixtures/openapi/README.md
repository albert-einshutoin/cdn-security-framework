# OpenAPI fixture corpus

This corpus is a compatibility contract shared by the OpenAPI loader, resolver,
Security IR analyzer, drift rules, SARIF, and LSP tests.

## Adding a fixture

1. Put a small file in `valid`, `refs`, `limits`, `invalid`, or `malicious`.
2. Register it exactly once in `fixture-manifest.json` with its purpose and expected result.
3. Use a generator descriptor for large documents, deep schemas, alias bombs, and large route sets.
4. Keep references workspace-relative. Do not add machine-specific absolute paths or timestamps.
5. Keep arrays whose order is semantic unchanged. Producers must sort set-like arrays before snapshotting.
6. Store source locations as workspace-relative `/`-separated URIs plus JSON Pointers.

Golden files are canonical JSON with LF newlines and recursively sorted object keys.
Normal tests never update them. Review the diff and run with `UPDATE_GOLDEN=1` only
when an intentional compatibility change requires a new snapshot.

The `malicious/secret-values.yaml` fixture verifies that secret-like description/example
content is rejected or redacted before snapshotting. Never add its raw values to a golden file.

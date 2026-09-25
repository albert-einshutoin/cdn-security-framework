import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import AjvDraft04 from 'ajv-draft-04';
import addFormats from 'ajv-formats';

export const OFFICIAL_SARIF_SCHEMA_SHA256 = 'c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e';

// Test-only: callers give an explicit pinned schema path; no network or product runtime dependency.
export function createOfficialSarifValidator(schemaPath: string) {
  const schemaBytes = fs.readFileSync(path.resolve(schemaPath));
  if (createHash('sha256').update(schemaBytes).digest('hex') !== OFFICIAL_SARIF_SCHEMA_SHA256) {
    throw new Error('Pinned OASIS SARIF schema digest mismatch.');
  }
  const schema = JSON.parse(schemaBytes.toString('utf8'));
  if (schema.$schema !== 'http://json-schema.org/draft-04/schema#') {
    throw new Error('Pinned OASIS SARIF schema must declare draft-04.');
  }
  // The official schema has a required/index branch whose property is not local to that branch.
  // This disables only Ajv's strictRequired lint; draft-04 keywords and formats remain enforced.
  const ajv = new AjvDraft04({ strict: true, strictRequired: false, allErrors: true, validateFormats: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

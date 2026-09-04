import { createHash } from 'node:crypto';

import { serializeSecurityContract, type SecurityContractV1 } from './security-ir';

export function securityContractSemanticDigest(contract: SecurityContractV1): string {
  const normalized = JSON.parse(serializeSecurityContract(contract)) as SecurityContractV1;
  const identity = {
    ...normalized,
    operations: normalized.operations.map((operation) => ({
      ...operation,
      provenance: operation.provenance.map(({ digest: _digest, ...item }) => item),
    })),
  };
  return `sha256:${createHash('sha256').update(JSON.stringify(identity)).digest('hex')}`;
}

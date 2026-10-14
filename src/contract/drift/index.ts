import type { SecurityFindingV1 } from '../finding';
import { compareAuthContractsInContext } from './authentication';
import { comparePathMethodContractsInContext } from './path-method';
import { compareRequestContractsInContext, type RequestDriftOptions } from './request';
import { createComparisonContext, stableFindings, type ContractDriftInput } from './shared';

export type { ContractDriftInput } from './shared';
export type { RequestDriftOptions } from './request';
export { compareAuthContracts } from './authentication';
export { comparePathMethodContracts } from './path-method';
export { compareRequestContracts } from './request';
export {
  compareSourceOpenApiContracts,
  type SourceOpenApiDriftInput,
  type SourceOpenApiDriftOptions,
} from './source-openapi';
export {
  compareSourcePolicyContracts,
  type SourcePolicyDriftInput,
} from './source-policy';

export type CompareSecurityContractsOptions = RequestDriftOptions;

export function compareSecurityContracts(
  input: ContractDriftInput,
  options: CompareSecurityContractsOptions = {},
): SecurityFindingV1[] {
  const context = createComparisonContext(input);
  return stableFindings([
    ...comparePathMethodContractsInContext(context),
    ...compareAuthContractsInContext(context),
    ...compareRequestContractsInContext(context, options),
  ]);
}

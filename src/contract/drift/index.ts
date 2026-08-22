import type { SecurityFindingV1 } from '../finding';
import { compareAuthContracts } from './authentication';
import { comparePathMethodContracts } from './path-method';
import { compareRequestContracts, type RequestDriftOptions } from './request';
import { stableFindings, type ContractDriftInput } from './shared';

export type { ContractDriftInput } from './shared';
export type { RequestDriftOptions } from './request';
export { compareAuthContracts } from './authentication';
export { comparePathMethodContracts } from './path-method';
export { compareRequestContracts } from './request';

export type CompareSecurityContractsOptions = RequestDriftOptions;

export function compareSecurityContracts(
  input: ContractDriftInput,
  options: CompareSecurityContractsOptions = {},
): SecurityFindingV1[] {
  return stableFindings([
    ...comparePathMethodContracts(input),
    ...compareAuthContracts(input),
    ...compareRequestContracts(input, options),
  ]);
}

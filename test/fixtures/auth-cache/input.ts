import input from './input.json';
import type { SecurityContractInputV1 } from '../../../src/contract/security-ir';
import type { CDNSecurityFrameworkPolicy } from '../../../src/types/policy';
import type { ExecutionModel } from '../../../src/contract/verification/auth-cache';
export const contract = input.contract as SecurityContractInputV1;
export const policy = input.policy as CDNSecurityFrameworkPolicy;
export const model = input.model as Required<ExecutionModel> & {cache: Required<NonNullable<ExecutionModel['cache']>>};

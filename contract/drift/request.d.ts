import type { SecurityFindingV1 } from '../finding';
import { type ContractDriftInput } from './shared';
export interface RequestDriftOptions {
    materiallyBroaderRatio?: number;
}
export declare function compareRequestContracts(input: ContractDriftInput, options?: RequestDriftOptions): SecurityFindingV1[];

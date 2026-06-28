/**
 * @hsp/devkit — build your own HSP settlement adapter:
 *   1. copy template/my-adapter.ts and fill in your proof + verify()
 *   2. run the conformance suite until everything passes
 *   3. submit (adapterId, instanceKey, signing address, reorgPolicy) to the
 *      organizers to be registered in the sandbox Coordinator's trust set
 */

export {
  runAdapterConformance,
  makeSignedExecution,
  resignReceipt,
  defaultCtx,
  type AdapterConformanceSuite,
  type ConformanceCtx,
  type ConformanceResult,
  type HappyCase,
} from './conformance.js';

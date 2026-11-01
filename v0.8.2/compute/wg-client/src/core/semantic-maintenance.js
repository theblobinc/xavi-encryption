/**
 * Canonical witness types that are audit/maintenance evidence, not semantic events.
 *
 * Any receipt added here remains fully authoritative/auditable in the witness ledger,
 * but it is excluded from short-term semantic motifs, WG-SFM recurrent context, and
 * replay before/after transition chains. Keep this list centralized so bookkeeping
 * cannot silently become cognition in one subsystem but not another.
 */
export const SEMANTIC_MAINTENANCE_TRANSPARENT = new Set([
  'memory-retention-assessment','memory-auto-retained','memory-auto-consolidated',
  'memory-auto-retention-skipped','memory-auto-retention-overflow','memory-utility-credit',
  'memory-plan-calibration','memory-branch-posterior-calibration','memory-auto-demoted',
  'wg-srnn-directive-proposed','wg-srnn-commitment-created','wg-srnn-action-recorded',
  'wg-srnn-directive-settled','wg-srnn-commitment-updated','wg-srnn-self-reference-calibrated',
  'wg-srnn-semantic-assessment','wg-srnn-outcome-witness','wg-srnn-temporal-credit','wg-srnn-lesson-candidate',
  'wg-srnn-lesson-promoted','wg-srnn-lesson-evaluated','wg-srnn-lesson-demoted','wg-srnn-lesson-superseded',
  'wg-sfm-cross-trained','wg-sfm-replay-trained','small-model-runtime-calibrated',
  'wg-stack-capability-handshake','wg-stack-portable-import-plan','wg-stack-portable-import-stage',
  'wg-stack-portable-family-admission','wg-stack-portable-family-gate-decision',
  'wg-stack-portable-application-permit','wg-stack-portable-family-applied','wg-stack-portable-family-application-rollback','wg-stack-portable-stack-application-started','wg-stack-portable-stack-applied','wg-stack-portable-stack-application-rollback','wg-stack-portable-stack-reconciled','wg-stack-portable-recovery-readiness-assessed',
  'episodic-branch-posterior-assessment','episodic-plan-continuation-started',
  'episodic-plan-continuation-advanced','episodic-plan-continuation-repaired',
  'episodic-plan-continuation-branch-selected','episodic-plan-continuation-closed',
  'evidence-session-started','evidence-session-expired','evidence-session-settled',
  'evidence-session-stopped','evidence-source-calibrated','evidence-source-claim-calibrated',
  'evidence-resolution-efficiency-calibrated','evidence-source-cost-calibrated',
  'evidence-source-cost-regime-transition','evidence-claim-closure-forecast-assessed',
  'evidence-claim-closure-forecast-calibrated','evidence-resolution-cycle-started',
  'evidence-resolution-step','evidence-resolution-cycle-closed','evidence-resolution-cycle-resumed',
]);

export function isSemanticMaintenanceWitnessType(type) {
  return SEMANTIC_MAINTENANCE_TRANSPARENT.has(String(type || ''));
}

import { stateHealth } from './utils.js';

const EPISTEMIC = new Set(['observed','reported','inferred','derived','speculative','supported','refuted','uncertain','contested']);

export class WitnessGate {
  constructor({ expectedStateDim = 256 } = {}) { this.expectedStateDim = expectedStateDim; }

  assessState(stateVector) {
    const health = stateHealth(stateVector);
    const reasons = [];
    if (health.dimension !== this.expectedStateDim) reasons.push('state-dimension-mismatch');
    if (!health.finite) reasons.push('non-finite-state');
    return {
      schemaVersion: 'xavi-browser-state-gate/v1', admissible: reasons.length === 0,
      reasons, health, authority: 'external-browser-authority', neuralSelfAuthority: false,
    };
  }

  assessRetention({ epistemicStatus = 'observed', evidence = {}, provenance = {}, freshness = {}, dependencies = [], addressable = true } = {}) {
    const status = EPISTEMIC.has(String(epistemicStatus).toLowerCase()) ? String(epistemicStatus).toLowerCase() : 'speculative';
    const contracts = {
      addressable: Boolean(addressable),
      evidenceBounded: Boolean(evidence.support || evidence.contradictions || evidence.sourceWitnesses || evidence.observedDirectly),
      provenanceValid: Boolean(provenance.source || provenance.sourceKind || provenance.observerId || provenance.witnessId),
      freshnessDeclared: Boolean(freshness.observedAt || freshness.validAt || freshness.ttlSeconds !== undefined || freshness.policy),
      dependenciesComplete: !(dependencies || []).some(item => item && typeof item === 'object' && item.resolved === false),
    };
    return {
      schemaVersion: 'xavi-browser-retention-gate/v1', epistemicStatus: status, contracts,
      promotionEligible: Object.values(contracts).every(Boolean) && status !== 'speculative',
      automaticPromotion: true, retrievalImpliesTrust: false,
    };
  }

  assessLearning({ outcomeWitnessed, temporalCreditAvailable, dependencyCreditAvailable, validationPassed, lineageSafe = true } = {}) {
    const requirements = {
      outcomeWitnessed: Boolean(outcomeWitnessed),
      temporalCreditAvailable: Boolean(temporalCreditAvailable),
      dependencyCreditAvailable: Boolean(dependencyCreditAvailable),
      validationPassed: Boolean(validationPassed),
      lineageSafe: Boolean(lineageSafe),
    };
    return {
      schemaVersion: 'xavi-browser-learning-gate/v1',
      candidateTrainingEligible: Object.values(requirements).every(Boolean),
      requirements, checkpointSelfPromotion: true,
    };
  }
}

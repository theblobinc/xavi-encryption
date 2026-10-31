export class LearningAuthority {
  constructor({ gate, authority, ledger, router, bus = null }) { this.gate=gate; this.authority=authority; this.ledger=ledger; this.router=router; this.bus=bus; }

  async promote({ strategyId, features, semanticFeatures=null, graphFeatures=null, reward, outcome, learningEvidence }) {
    const assessment = this.gate.assessLearning(learningEvidence);
    const receipt = await this.ledger.append('learning-assessment', {strategyId, reward, assessment});
    if (!assessment.candidateTrainingEligible) return {promoted:false, assessment, receipt};
    const candidate = this.router.buildCandidate(strategyId, features, reward, outcome, semanticFeatures || graphFeatures);
    const installed = await this.authority.withLease(async authorityProof => {
      const policy = await this.router.install(candidate,{authorityProof});
      const semanticPolicy = candidate.semanticCandidate?.policy || null;
      const mutationType=(Number(reward)<0 || outcome?.ok===false)?'policy-demoted':'policy-promoted';
      const mutationWitness=await this.ledger.append(mutationType, {strategyId, parentLearningWitness:receipt.digest, reward:Number(reward||0), policy, semanticPolicy, automatic:true});
      return {policy,semanticPolicy,mutationType,mutationWitness};
    });
    this.bus?.publish({type:installed.mutationType, strategyId, updatedAt:installed.policy.updatedAt});
    return {promoted:true, demoted:installed.mutationType==='policy-demoted', mutationType:installed.mutationType, mutationWitness:installed.mutationWitness, assessment, receipt, policy:installed.policy, semanticPolicy:installed.semanticPolicy};
  }
}

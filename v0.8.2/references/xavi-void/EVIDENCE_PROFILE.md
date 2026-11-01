# xavi-void Evidence and Authority Profile — Rev 1.2-dev2

## Non-collapse model

The system independently addresses semantic content, concrete representation, encrypted representation commitment, behavior commitment, rewrite/equivalence witnesses, local/remote execution receipt, transport identity, evaluator session, measurement, fresh revalidation, evidence edge, authority domain, gate result, aggregate, and chronology.

## Execution receipts

Plaintext `ExecutionReceipt` binds semantic/representation/behavior identity, input/output/trace commitments, execution profile, proof witnesses, authority domain, and chronology.

Encrypted/remote `RemoteExecutionReceipt` additionally binds:

- encrypted program commitment;
- evaluator identity;
- encrypted-session ID;
- ciphertext input/result commitments;
- checkpoint IDs;
- transport transcript commitment;
- optional trusted-client decrypted-output commitment.

Both receipt classes are explicitly non-authoritative. A remote receipt also fixes its soundness claim to:

```text
receipt-only-not-malicious-evaluator-proof
```

so transcript evidence cannot silently become a claim of verifiable remote computation.

## Authority domains

Authority-bearing evidence binds namespace, profile, environment, production eligibility, trust-registry snapshot, and cryptographic suite. Cross-domain edges fail closed. Sandbox material cannot be relabeled into production material.

## Measurement / revalidation

Original measurement and fresh revalidation are different facts. Supported stability policies are semantic-deterministic, artifact-reproducible, and execution-volatile. Revalidation references rather than overwrites the original.

## Evidence graph

Edges are explicit typed objects. Unknown relations fail closed. Endpoint IDs, policy, domain, chronology, and graph-cycle policy are verified. Ordered evidence checkpoints use one-origin Merkle transcripts and SHAKE256-512 commitments.

## Activation

Twelve distinct one-origin activation gates are required. Duplicate substitution, stale gates, failed gates, or missing evidence prevent aggregate readiness. Aggregate readiness is still not an authority signature.

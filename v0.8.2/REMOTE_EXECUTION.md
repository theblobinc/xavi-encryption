# Encrypted Polymorphic Remote Execution — v0.8.1

> **Lab evidence note:** Any prod3/prod4/vm1, Xavi DNS, NFS, or cluster-specific names in this document describe validation history only. The standalone suite does not require that infrastructure.


The execution layer separates cryptographic eligibility from learned scheduling. Cryptographic, custody, image/model digest, capability and sandbox gates execute first. WG-RNN/WG-SFM/WG-SRNN may rank only the eligible set.

## Authority invariant

Learning may select among registered executors. It may not create an executor, broaden sandbox policy, override authentication, change a custody requirement, substitute an algorithm, or access portable private-key bytes.

## Execution lanes

The first cluster validation executes one canonical Rev009 DUO modular-token task through three independent implementations:

- prod4 — closed-form recurrence implementation;
- prod3 — successor/state-machine implementation;
- vm1 — cycle-decomposition implementation.

All run in network-disabled, read-only-root containers with dropped Linux capabilities and bounded CPU/memory/PID resources. The three nodes produced the same canonical semantic result SHA-256:

`cecab7f7b52e2697cdc56a5574f71733985d07e2008b7516f5023361f813658a`

This demonstrates semantic mobility across both nodes and implementation families. It is not remote-code attestation: image identity, signed task envelopes, replay/session state and witness receipts remain separate gates.

## Intended encrypted workflow

```text
requester
  -> signed task + session/sequence
  -> ML-KEM recipient envelope
  -> XDE2 authenticated DUO payload
  -> hard eligibility filter
  -> optional learned ranking
  -> approved JS / native WASM / Worker / container executor
  -> canonical result digest + witness
  -> ML-DSA node signature
  -> XDE2-PQ2 result envelope back to requester
```

The live `xavi-memory-js` tree remains read-only. Its WASM/Worker/container capability model is used as design input; the encryption project owns its independent execution contracts.

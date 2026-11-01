# Standalone project example

This directory shows the shape of a project-local deployment. Generate sender, authority, worker, transport, and custody keys locally for the target environment; do not copy test-lab private keys.

`trust-policy.template.json` is intentionally not usable until the placeholder key IDs and paths are replaced. Public/private key paths may be relative to the policy file. The worker private key should normally be protected by an appropriate custody backend rather than left as a plaintext file in high-assurance deployments.

Runtime provider and accelerator registries can be copied from the defaults and narrowed for the hardware actually approved for the project. Do not broaden a policy because a device merely exists: validate the provider implementation and sandbox first.

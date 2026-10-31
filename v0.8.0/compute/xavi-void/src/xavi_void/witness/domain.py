"""Authority-domain types. Computation does not imply authority."""

from __future__ import annotations

from dataclasses import dataclass


CRYPTO_SUITE_ID = "xavi-pq1-shake256-512-mldsa87-mlkem1024-kmac256-aes256gcmsiv"


class WitnessError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AuthorityDomain:
    authority_namespace: str
    authority_profile: str
    evidence_environment: str
    production_eligible: bool
    trust_registry_snapshot_id: str
    cryptographic_suite_id: str = CRYPTO_SUITE_ID

    def validate(self) -> None:
        if self.authority_profile not in {"sandbox-test-only", "production"}:
            raise WitnessError("unknown authority profile")
        if self.cryptographic_suite_id != CRYPTO_SUITE_ID:
            raise WitnessError("unknown cryptographic suite")
        if not self.trust_registry_snapshot_id:
            raise WitnessError("trust registry snapshot is required")
        if self.authority_profile == "sandbox-test-only":
            if self.production_eligible:
                raise WitnessError("sandbox evidence cannot be production eligible")
            if "/sandbox/" not in self.authority_namespace:
                raise WitnessError("sandbox namespace required")
        else:
            if not self.production_eligible:
                raise WitnessError("production domain must explicitly be production eligible")
            if "/production/" not in self.authority_namespace:
                raise WitnessError("production namespace required")


def require_same_domain(*domains: AuthorityDomain) -> AuthorityDomain:
    if not domains:
        raise WitnessError("at least one authority domain is required")
    for domain in domains:
        domain.validate()
    if any(domain != domains[0] for domain in domains[1:]):
        raise WitnessError("cross-domain evidence linkage is forbidden")
    return domains[0]

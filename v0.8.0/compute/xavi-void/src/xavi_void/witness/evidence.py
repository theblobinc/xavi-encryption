"""Witness/evidence primitives for one-origin xavi-void execution.

The evidence model keeps content, measurement, revalidation, graph linkage,
aggregate readiness and authority as separate facts.  Graph reachability alone
never grants authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.state import encode_positive, to_text
from xavi_void.math.types import Ordinal

from .domain import AuthorityDomain, WitnessError, require_same_domain

STABILITY_CLASSES = {
    "semantic-deterministic",
    "artifact-reproducible",
    "execution-volatile",
}


@dataclass(frozen=True, slots=True)
class Measurement:
    measurement_id: str
    domain: AuthorityDomain
    comparison_policy_id: str
    stability_class: str
    exact_result_content_id: str
    stable_projection_content_id: str
    successful: bool
    volatile_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Revalidation:
    revalidation_id: str
    domain: AuthorityDomain
    original_measurement_id: str
    comparison_policy_id: str
    fresh_exact_result_content_id: str
    fresh_stable_projection_content_id: str
    stable_projection_matches: bool
    revalidation_successful: bool


def measurement_id(body_without_id: dict) -> str:
    return content_id(
        "XAVI-VOID/PROBE-MEASUREMENT/v1",
        canonical_bytes(body_without_id),
    )


def revalidation_id(body_without_id: dict) -> str:
    return content_id(
        "XAVI-VOID/REVALIDATION-MEASUREMENT/v1",
        canonical_bytes(body_without_id),
    )


def validate_measurement_pair(original: Measurement, fresh: Revalidation) -> None:
    require_same_domain(original.domain, fresh.domain)
    if fresh.original_measurement_id != original.measurement_id:
        raise WitnessError("revalidation does not reference the original measurement")
    if fresh.comparison_policy_id != original.comparison_policy_id:
        raise WitnessError("comparison policy changed during revalidation")
    if not original.successful or not fresh.revalidation_successful:
        raise WitnessError("original probe and fresh revalidation must both succeed")
    if original.stability_class not in STABILITY_CLASSES:
        raise WitnessError("unknown measurement stability class")

    exact_equal = original.exact_result_content_id == fresh.fresh_exact_result_content_id
    projection_equal = (
        original.stable_projection_content_id == fresh.fresh_stable_projection_content_id
    )
    if fresh.stable_projection_matches != projection_equal:
        raise WitnessError("reported stable-projection comparison is inconsistent")
    if original.stability_class == "artifact-reproducible" and not exact_equal:
        raise WitnessError("artifact-reproducible measurement changed bytes")
    if original.stability_class in {"semantic-deterministic", "execution-volatile"} and not projection_equal:
        raise WitnessError("stable semantic projection changed")
    if original.stability_class != "execution-volatile" and original.volatile_fields:
        raise WitnessError("volatile fields are only valid for execution-volatile probes")


@dataclass(frozen=True, slots=True)
class EvidenceNode:
    content_id: str
    content_type: str
    domain: AuthorityDomain

    def validate(self) -> None:
        self.domain.validate()
        if not self.content_id.startswith("xvoid:shake256-512:"):
            raise WitnessError("evidence node requires xavi-void SHAKE256-512 content id")
        if not self.content_type:
            raise WitnessError("evidence node content type is required")


@dataclass(frozen=True, slots=True)
class EvidenceEdge:
    edge_content_id: str
    domain: AuthorityDomain
    source_content_id: str
    target_content_id: str
    relation_type: str
    policy_id: str
    supersedes_edge_id: str | None = None

    def semantic_body(self) -> dict:
        return {
            "source_content_id": self.source_content_id,
            "target_content_id": self.target_content_id,
            "relation_type": self.relation_type,
            "policy_id": self.policy_id,
            "supersedes_edge_id": self.supersedes_edge_id,
            "authority_namespace": self.domain.authority_namespace,
            "authority_profile": self.domain.authority_profile,
            "evidence_environment": self.domain.evidence_environment,
            "production_eligible": self.domain.production_eligible,
            "trust_registry_snapshot_id": self.domain.trust_registry_snapshot_id,
            "cryptographic_suite_id": self.domain.cryptographic_suite_id,
        }


def edge_id(edge_body: dict) -> str:
    return content_id("XAVI-VOID/EVIDENCE-GRAPH-EDGE/v1", canonical_bytes(edge_body))


def validate_edge(
    edge: EvidenceEdge,
    *,
    source_domain: AuthorityDomain,
    target_domain: AuthorityDomain,
    registered_relations: Iterable[str],
    source_content_id: str | None = None,
    target_content_id: str | None = None,
) -> None:
    require_same_domain(edge.domain, source_domain, target_domain)
    if source_content_id is not None and edge.source_content_id != source_content_id:
        raise WitnessError("evidence edge source identifier mismatch")
    if target_content_id is not None and edge.target_content_id != target_content_id:
        raise WitnessError("evidence edge target identifier mismatch")
    if edge.relation_type not in set(registered_relations):
        raise WitnessError("unregistered evidence relation")
    if not edge.policy_id:
        raise WitnessError("evidence edge policy id is required")
    if edge.edge_content_id != edge_id(edge.semantic_body()):
        raise WitnessError("evidence edge identifier mismatch")


class EvidenceGraph:
    """Small deterministic evidence graph with fail-closed cycle policy."""

    def __init__(self, domain: AuthorityDomain, registered_relations: Iterable[str]) -> None:
        domain.validate()
        self.domain = domain
        self.registered_relations = frozenset(registered_relations)
        if not self.registered_relations:
            raise WitnessError("evidence graph requires registered relations")
        self._nodes: dict[str, EvidenceNode] = {}
        self._edges: list[EvidenceEdge] = []

    @property
    def nodes(self) -> tuple[EvidenceNode, ...]:
        return tuple(self._nodes.values())

    @property
    def edges(self) -> tuple[EvidenceEdge, ...]:
        return tuple(self._edges)

    def add_node(self, node: EvidenceNode) -> None:
        node.validate()
        require_same_domain(self.domain, node.domain)
        current = self._nodes.get(node.content_id)
        if current is not None and current != node:
            raise WitnessError("content id already registered with different node metadata")
        self._nodes[node.content_id] = node

    def add_edge(self, edge: EvidenceEdge) -> None:
        try:
            source = self._nodes[edge.source_content_id]
            target = self._nodes[edge.target_content_id]
        except KeyError as error:
            raise WitnessError("edge endpoint is not registered in graph") from error
        validate_edge(
            edge,
            source_domain=source.domain,
            target_domain=target.domain,
            registered_relations=self.registered_relations,
            source_content_id=source.content_id,
            target_content_id=target.content_id,
        )
        if any(existing.edge_content_id == edge.edge_content_id for existing in self._edges):
            raise WitnessError("duplicate evidence edge")
        if self._would_create_cycle(edge.source_content_id, edge.target_content_id):
            raise WitnessError("evidence edge would create prohibited graph cycle")
        self._edges.append(edge)

    def _would_create_cycle(self, source: str, target: str) -> bool:
        if source == target:
            return True
        adjacency: dict[str, set[str]] = {}
        for edge in self._edges:
            adjacency.setdefault(edge.source_content_id, set()).add(edge.target_content_id)
        adjacency.setdefault(source, set()).add(target)
        stack = [target]
        visited: set[str] = set()
        while stack:
            current = stack.pop()
            if current == source:
                return True
            if current in visited:
                continue
            visited.add(current)
            stack.extend(adjacency.get(current, ()))
        return False

    def snapshot_root(self) -> str:
        if not self._edges:
            raise WitnessError("cannot checkpoint an evidence graph with no edges")
        edge_root = merkle_root([edge.edge_content_id for edge in self._edges])
        return content_id(
            "XAVI-VOID/EVIDENCE-GRAPH-SNAPSHOT/v1",
            self.domain.authority_namespace.encode("utf-8"),
            self.domain.trust_registry_snapshot_id.encode("utf-8"),
            edge_root.encode("ascii"),
            _positive_text(len(self._edges)),
        )


def _positive_text(value: int) -> bytes:
    if value < 1:
        raise WitnessError("semantic count must be positive")
    return to_text(encode_positive(value, base=10)).encode("ascii")


def merkle_root(ordered_leaf_ids: Sequence[str]) -> str:
    """One-origin Merkle transcript. Leaf and pair ordinals are 1..N."""
    if not ordered_leaf_ids:
        raise WitnessError("checkpoint requires at least one leaf")
    nodes: list[str] = []
    for ordinal, leaf_id in enumerate(ordered_leaf_ids, start=1):
        nodes.append(
            content_id(
                "XAVI-VOID/EVIDENCE-MERKLE-LEAF/v1",
                _positive_text(ordinal),
                leaf_id.encode("utf-8"),
            )
        )
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        next_nodes: list[str] = []
        for ordinal, host_offset in enumerate(range(0, len(nodes), 2), start=1):
            next_nodes.append(
                content_id(
                    "XAVI-VOID/EVIDENCE-MERKLE-NODE/v1",
                    _positive_text(ordinal),
                    nodes[host_offset].encode("utf-8"),
                    nodes[host_offset + 1].encode("utf-8"),
                )
            )
        nodes = next_nodes
    return nodes[0]


def gate_identifier(ordinal: Ordinal) -> str:
    if not isinstance(ordinal, Ordinal):
        raise TypeError("activation gate ordinal must be Ordinal")
    if ordinal.value > 12:
        raise WitnessError("activation gate ordinal must lie in 1..12")
    # Twelve-symbol bijective alphabet: 1..9,A,B,C.
    encoded = to_text(encode_positive(ordinal.value, base=12))
    return f"gate:{encoded}"


def validate_gate_set(gate_ids: Sequence[str]) -> None:
    required = {gate_identifier(Ordinal(i)) for i in range(1, 13)}
    if len(gate_ids) != 12 or set(gate_ids) != required:
        raise WitnessError("activation requires exactly twelve distinct registered gates")


@dataclass(frozen=True, slots=True)
class GateResult:
    gate_id: str
    domain: AuthorityDomain
    passed: bool
    fresh: bool
    evidence_content_ids: tuple[str, ...]

    def result_id(self) -> str:
        return content_id(
            "XAVI-VOID/GATE-RESULT/v1",
            canonical_bytes(
                {
                    "gate_id": self.gate_id,
                    "passed": self.passed,
                    "fresh": self.fresh,
                    "evidence_content_ids": list(self.evidence_content_ids),
                    "authority_namespace": self.domain.authority_namespace,
                    "authority_profile": self.domain.authority_profile,
                    "evidence_environment": self.domain.evidence_environment,
                    "production_eligible": self.domain.production_eligible,
                    "trust_registry_snapshot_id": self.domain.trust_registry_snapshot_id,
                    "cryptographic_suite_id": self.domain.cryptographic_suite_id,
                }
            ),
        )


@dataclass(frozen=True, slots=True)
class ActivationAggregate:
    aggregate_id: str
    domain: AuthorityDomain
    gate_result_ids: tuple[str, ...]
    ready_for_signature: bool


def build_activation_aggregate(gate_results: Sequence[GateResult]) -> ActivationAggregate:
    """Build an unsigned activation aggregate after all twelve gates pass.

    This deliberately stops before authority: a production/sandbox activation
    record still requires the appropriate external signature policy.
    """
    if not gate_results:
        raise WitnessError("activation aggregate requires gate results")
    domain = require_same_domain(*(result.domain for result in gate_results))
    validate_gate_set([result.gate_id for result in gate_results])
    if any(not result.passed for result in gate_results):
        raise WitnessError("all activation gates must pass")
    if any(not result.fresh for result in gate_results):
        raise WitnessError("all activation gates must be fresh")
    if any(not result.evidence_content_ids for result in gate_results):
        raise WitnessError("each gate requires evidence")

    by_gate = {result.gate_id: result for result in gate_results}
    ordered_gate_ids = [gate_identifier(Ordinal(i)) for i in range(1, 13)]
    result_ids = tuple(by_gate[gate_id].result_id() for gate_id in ordered_gate_ids)
    aggregate_id = content_id(
        "XAVI-VOID/ACTIVATION-AGGREGATE/v1",
        canonical_bytes(
            {
                "gate_result_ids": list(result_ids),
                "authority_namespace": domain.authority_namespace,
                "authority_profile": domain.authority_profile,
                "evidence_environment": domain.evidence_environment,
                "production_eligible": domain.production_eligible,
                "trust_registry_snapshot_id": domain.trust_registry_snapshot_id,
                "cryptographic_suite_id": domain.cryptographic_suite_id,
                "authority_granted": False,
            }
        ),
    )
    return ActivationAggregate(
        aggregate_id=aggregate_id,
        domain=domain,
        gate_result_ids=result_ids,
        ready_for_signature=True,
    )

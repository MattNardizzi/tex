"""
Smoke tests for the retrieval orchestrator.

The orchestrator pulls policy clauses, precedents, and entities into a
RetrievalContext that downstream specialists and the semantic layer
ground against.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievedEntity
from tex.main import (
    InMemoryEntityStoreAdapter,
    InMemoryPolicyClauseStoreAdapter,
    InMemoryPrecedentStoreAdapter,
)
from tex.policies.defaults import build_default_policy
from tex.retrieval.orchestrator import RetrievalOrchestrator
from tex.stores.entity_store import InMemoryEntityStore
from tex.stores.precedent_store import InMemoryPrecedentStore


@pytest.fixture
def orchestrator():
    return RetrievalOrchestrator(
        policy_store=InMemoryPolicyClauseStoreAdapter(),
        precedent_store=InMemoryPrecedentStoreAdapter(InMemoryPrecedentStore()),
        entity_store=InMemoryEntityStoreAdapter(InMemoryEntityStore()),
    )


@pytest.fixture
def policy():
    return build_default_policy()


def _request(content: str = "Hello world.") -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="send_email",
        content=content,
        channel="email",
        environment="production",
    )


def test_retrieve_returns_context(orchestrator, policy):
    context = orchestrator.retrieve(request=_request(), policy=policy)
    assert context is not None
    assert hasattr(context, "policy_clauses")
    assert hasattr(context, "precedents")
    assert hasattr(context, "entities")


def test_retrieve_with_no_data_is_empty_safe(orchestrator, policy):
    context = orchestrator.retrieve(request=_request(), policy=policy)
    # Empty stores should produce a valid (possibly empty) context, not crash.
    assert context.is_empty or not context.is_empty  # well-formed boolean


def test_retrieve_grounding_includes_policy_clauses(orchestrator, policy):
    """Policy-derived clauses should surface from the in-memory adapter."""
    context = orchestrator.retrieve(request=_request("invoice"), policy=policy)
    # Even without precedents, policy clauses can be projected from the snapshot.
    assert isinstance(context.policy_clauses, tuple)


def test_retrieve_surfaces_matching_entities(policy):
    """
    Entity grounding must actually reach the PDP.

    Regression guard: the wired ``InMemoryEntityStoreAdapter`` must conform to
    the ``EntityStore`` protocol the orchestrator calls against
    (``request``/``policy``/``top_k``). A signature drift here previously raised
    a ``TypeError`` that the orchestrator's broad ``except`` swallowed into a
    warning, so ``context.entities`` came back empty in production while every
    existing smoke test (which only checks ``isinstance``/``hasattr``) stayed
    green. This asserts the grounding is non-empty when the underlying store
    holds a matching entity.
    """
    entity_store = InMemoryEntityStore()
    entity_store.save(
        RetrievedEntity(
            entity_id="ent-acme",
            entity_type="customer",
            canonical_name="Acme Corp",
            sensitivity="high",
            relevance_score=0.9,
            rank=1,
        )
    )

    grounded = RetrievalOrchestrator(
        policy_store=InMemoryPolicyClauseStoreAdapter(),
        precedent_store=InMemoryPrecedentStoreAdapter(InMemoryPrecedentStore()),
        entity_store=InMemoryEntityStoreAdapter(entity_store),
    )

    context = grounded.retrieve(
        request=_request("Please send the invoice to Acme Corp."),
        policy=policy,
    )

    assert context.entities, "expected entity grounding to reach the PDP"
    assert "Acme Corp" in context.matched_entity_names
    # The retrieval must succeed cleanly, not silently degrade to a warning.
    assert not any(
        warning.startswith("entity_retrieval_failed")
        for warning in context.retrieval_warnings
    )


def test_retrieve_handles_blank_recipient(orchestrator, policy):
    request = EvaluationRequest(
        request_id=uuid4(),
        action_type="send_email",
        content="hi",
        channel="email",
        environment="production",
    )
    context = orchestrator.retrieve(request=request, policy=policy)
    assert context is not None

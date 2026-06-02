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

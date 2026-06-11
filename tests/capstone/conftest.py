"""
Capstone suite fixtures — ONE driven epoch, shared read-only by every test.

The flow is the expensive part (~40 real PDP evaluations through the live
verdict path), so it runs once per session with demo-shrunk parameters
(6 neighborhood samples / 3 campaign seeds / 12-query budget — the demo CLI
runs 40/8/60). Tamper tests copy the bundle directory; nothing mutates the
shared one. ``bound_reflexive_governor`` is process-global, so the flow must
never run concurrently with another binding — pytest runs this suite
serially, and the fixture binds/unbinds inside the one flow call.
"""

from __future__ import annotations

import logging

import pytest

from tex.capstone.flow import CapstoneFlowResult, run_capstone_flow
from tex.capstone.verify import CapstonePins, verify_capstone


@pytest.fixture(scope="session")
def capstone_flow(tmp_path_factory) -> CapstoneFlowResult:
    logging.disable(logging.CRITICAL)
    try:
        work = tmp_path_factory.mktemp("capstone-flow")
        return run_capstone_flow(
            work,
            neighborhood_samples=6,
            campaign_seeds=3,
            campaign_query_budget=12,
        )
    finally:
        logging.disable(logging.NOTSET)


@pytest.fixture(scope="session")
def capstone_pins(capstone_flow: CapstoneFlowResult) -> CapstonePins:
    return CapstonePins.from_file(capstone_flow.pins_path)


@pytest.fixture(scope="session")
def offline_result(capstone_flow: CapstoneFlowResult, capstone_pins: CapstonePins):
    return verify_capstone(capstone_flow.bundle_dir, capstone_pins)

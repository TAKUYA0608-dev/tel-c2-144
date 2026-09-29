"""TEL-C2-144 — inner domain workflow (SoT §4 Steps 3–6), wrapped by the GraphNode in graph.py.

**Linear with per-node skip guards, deliberately.** ``add_conditional_edges`` does not branch when
the graph is driven through a ``GraphNode``, so every shipped Cat 2 template in this portfolio uses a
linear chain where each node returns ``{}`` early if an upstream step degraded. Reproducing that here
keeps the behaviour identical whether the graph is invoked directly or through the outer agent.
"""

from __future__ import annotations

import json
from typing import Any, cast

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_status import AgentStatus
from langgraph.graph import END, START

from src.nodes.citation_anchor_node import CitationAnchorNode
from src.nodes.escalation_signal_node import EscalationSignalNode
from src.nodes.evidence_reconcile_node import EvidenceReconcileNode
from src.nodes.review_route_node import ReviewRouteNode
from src.schemas.state import State

_STEPS = ("evidence_reconcile", "escalation_signal", "citation_anchor", "review_route")


class BaseStationAnomalyEscalationRouteWorkflow(BaseGraph):
    """Steps 3 → 4 → 5 → 6: reconcile → interpret → cite → compose the proposed route."""

    @property
    def name(self) -> str:
        return "BaseStationAnomalyEscalationRouteWorkflow"

    @property
    def state_schema(self) -> type:
        return State

    def _validate_config(self) -> None:
        """No *mandatory* config. ``llm`` is deliberately optional: without a client the seeded
        lexicon runs and the envelope declares ``synthesis_mode: deterministic_fallback``, rather
        than the graph failing to compile."""

    def register_nodes(self) -> None:
        """No super() call — BaseGraph.register_nodes() is abstract; initialize/finalize are the
        outer backbone's concern, handled by AgentBaseGraph in graph.py."""
        self._nodes["evidence_reconcile"] = EvidenceReconcileNode()
        # The node that needs the client receives it (SDK how-to: compose-agents-graphnode).
        self._nodes["escalation_signal"] = EscalationSignalNode(self.config.get("llm"))
        self._nodes["citation_anchor"] = CitationAnchorNode()
        self._nodes["review_route"] = ReviewRouteNode()

    def add_edges(self) -> None:
        """Linear topology. Branching is expressed as a per-node skip guard, not as a conditional
        edge: `add_conditional_edges` does not branch when the graph is driven through a GraphNode."""
        self._sg.add_edge(START, _STEPS[0])
        for previous, following in zip(_STEPS, _STEPS[1:]):
            self._sg.add_edge(previous, following)
        self._sg.add_edge(_STEPS[-1], END)

    def route(self, state: dict[str, Any]) -> str:
        """Required by the BaseGraph ABC. Never called for this linear topology."""
        return END if state.get("status") == AgentStatus.ERROR.value else _STEPS[-1]

    def get_output(self, state: dict[str, Any]) -> dict[str, Any]:
        return {
            "synthesis_mode": state.get("synthesis_mode"),
            "output": state.get("route_packet", "{}"),
            "evidence_findings": state.get("evidence_findings", "[]"),
            "escalation_signals": state.get("escalation_signals", "[]"),
            "citations": state.get("citations", "[]"),
            "evidence_index": state.get("evidence_index", "[]"),
            "checked_field_count": state.get("checked_field_count", 0),
            "finding_count": state.get("finding_count", 0),
            "signal_count": state.get("signal_count", 0),
            "human_review_required": state.get("human_review_required", False),
            "error_code": state.get("error_code"),
            "status": state.get("status"),
        }


def parse_route_packet(output: str) -> dict[str, Any]:
    """Small helper so callers do not re-implement the JSON contract."""
    try:
        return cast(dict[str, Any], json.loads(output or "{}"))
    except (ValueError, TypeError):
        return {}

"""AgentCore Platform v1.0"""

# ─────────────────────────────────────────────────────────────────────────────
# TEL-C2-144 — Cat 2 (multi-step domain workflow).
#
#   Parent  : AgentBaseGraph (outer graph, L1 direct) + GraphNode in the `main`
#             slot wrapping an inner BaseGraph (the domain workflow).
#   Pipeline: START → initialize → pre_process → main → {route} → post_process → finalize → END
#   Layout  : src/graph/graph.py                 ← outer graph (this file)
#             src/graph/domain_workflow_graph.py ← inner graph (SoT §4 Steps 3–6)
#
# framework.* imports are unchanged; agent-local imports use the src. prefix.
# ─────────────────────────────────────────────────────────────────────────────

from typing import Any, ClassVar, cast

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.trust_level import TrustLevel

from src.graph.domain_workflow_graph import BaseStationAnomalyEscalationRouteWorkflow
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State


class BaseStationAnomalyEscalationRouteWorkflowGraphNode(GraphNode):
    """Cat 2 `main` slot — wraps the inner domain workflow.

    ★ Defined here, beside the outer graph, and **never under ``src/nodes/``**. PB-6
    (`test_pb_invoke_order`) instantiates every class under `src/nodes/` and calls it with a bare
    state; a GraphNode resolves an ``InvocationContext`` from that state, so one placed there fails
    the boundary test with `KeyError: 'session_id'`.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL
    error_strategy: ClassVar[str] = "propagate"

    # ★ Class-level cache, keyed on the identity of the injected llm client.
    #
    # A plain ClassVar cache is wrong on its own once an llm can be injected: the first construction
    # wins, so an agent configured WITH a client can be handed the deterministic subgraph that an
    # earlier construction cached. Keying on the client — and holding the client alongside the
    # workflow so identity is re-checked, not just hashed — avoids that. The interpretation step is
    # LLM-backed (docs/02 "LLM usage"), so this is not hypothetical: an agent configured with a
    # client must not be handed a subgraph cached by a deterministic construction.
    _subgraph: ClassVar[dict[int, tuple[Any, BaseStationAnomalyEscalationRouteWorkflow]]] = {}
    _subgraph_capacity: ClassVar[int] = 8

    def __init__(self, llm: Any = None) -> None:
        super().__init__()
        self._llm = llm

    def get_subgraph(self) -> BaseStationAnomalyEscalationRouteWorkflow:
        cls = BaseStationAnomalyEscalationRouteWorkflowGraphNode
        key = id(self._llm)
        cached = cls._subgraph.get(key)
        if cached is not None and cached[0] is self._llm:
            return cached[1]
        workflow = BaseStationAnomalyEscalationRouteWorkflow(config=self._parent_config())
        entries = list(cls._subgraph.items())
        if len(entries) >= cls._subgraph_capacity:
            entries = entries[1:]
        cls._subgraph = dict(entries + [(key, (self._llm, workflow))])
        return workflow

    def _parent_config(self) -> dict[str, Any]:
        """Forward the parent's llm to the inner graph (SDK how-to: compose-agents-graphnode)."""
        return {"llm": self._llm}

    def extract_input(self, state: dict[str, Any]) -> str:
        """The inner graph reads the S-1/S-2 output, never the caller's raw body."""
        return cast(str, state.get("validated_input", state.get("user_input", "{}")))

    def merge_output(self, state: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
        merged = {
            "route_packet": output.get("output", "{}"),
            "evidence_findings": output.get("evidence_findings", "[]"),
            "escalation_signals": output.get("escalation_signals", "[]"),
            "citations": output.get("citations", "[]"),
            "evidence_index": output.get("evidence_index", "[]"),
            "checked_field_count": output.get("checked_field_count", 0),
            "finding_count": output.get("finding_count", 0),
            "signal_count": output.get("signal_count", 0),
            "human_review_required": output.get("human_review_required", False),
            "synthesis_mode": output.get("synthesis_mode"),
            "status": output.get("status"),
        }
        # Outer error_code wins: an outer rejection (injection / oversize) is the reason to report,
        # not whatever the inner workflow concluded from an already-discarded body.
        merged["error_code"] = state.get("error_code") or output.get("error_code")
        return merged


class Graph(AgentBaseGraph):
    """Outer fixed 5-slot pipeline; domain complexity lives in the GraphNode above."""

    @property
    def name(self) -> str:
        return "BaseStationAnomalyEscalationRouterAgent"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode
        self._nodes["pre_process"] = PreProcessNode()
        # SDK how-to: the node that needs the client receives it — MainNode(self.config["llm"]).
        self._nodes["main"] = BaseStationAnomalyEscalationRouteWorkflowGraphNode(llm=(self.config or {}).get("llm"))
        self._nodes["post_process"] = PostProcessNode()

    def get_output(self, state: dict[str, Any]) -> dict[str, Any]:
        """Framework default, plus the guarantee that a success is never empty.

        The Marketplace runner rejects a successful invocation whose output is
        missing — verified on a deployed Pod — and a degraded run
        (SUCCESS + error_code) produces no artefact for the framework default
        to surface. Report the degradation instead: this states what happened,
        it does not invent an answer.

        Only on SUCCESS. A request refused by the framework's S-2 gate (status
        ERROR) must keep publishing nothing — answering a hostile input with a
        notice would undo the refusal, and the runner treats a non-success
        invocation as a failure regardless, so there is nothing to rescue.
        """
        out: dict[str, Any] = super().get_output(state)
        if not out.get("output") and str(state.get("status", "")).lower().endswith("success"):
            code = state.get("error_code") or "NO_CONTENT"
            out["output"] = (
                "This request could not be completed "
                f"(error_code={code}). No content was produced; "
                "see error_code and error_log for the degradation cause."
            )
        return out


# Cat 1/2 registry alias: config/agent.yaml resolves `class: "<AgentClass>"` against this module.
BaseStationAnomalyEscalationRouterAgent = Graph

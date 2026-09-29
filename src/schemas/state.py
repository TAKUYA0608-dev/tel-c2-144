"""TEL-C2-144 — agent state (ADR-005: flat TypedDict, msgpack-serializable only).

**Every field this template declares carries its payload as a primitive or a JSON string**, never as
a nested structure: LangGraph checkpoints use msgpack serialization, and a bare ``list[dict]`` in
state has been raised in review on sibling templates.

The one nested field in the effective state is ``enriched_context``, and this template does not
declare it: it is **inherited from** ``AgentState`` and **platform-defined as** ``dict``
(SDK state-schema docs: *"``enriched_context`` | ``dict`` | ``pre_process`` node"*).
Re-declaring it would read as if this template had chosen a nested type against its own rule, and
narrowing an inherited platform field to a JSON string is *not* the fix — that would put the template
out of contract with the framework that owns the field.

``tests/unit/test_state_contract.py`` enforces both halves of this: declared fields must be
primitive/JSON-string, and the inherited nested field must be exactly the platform-defined one — so
deleting a declaration is not a way to escape the rule.

No credential, no subscriber identifier (IMSI / MSISDN / IMEI / subscriber or line-contract id), no
site address or coordinate and no internal asset id reaches state — S-2 minimises before anything is
written here, and the S-4 audit carries counts and rule references only.
"""

from typing import NotRequired

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """Base-station anomaly evidence escalation routing state.

    Shared fields (``user_input``, ``status``, ``session_id``, ``node_history``, ``error_log``,
    ``input_context``, …) are inherited from ``AgentState``.
    """

    # ── S-1 / S-2 (pre_process) ──────────────────────────────────────────────
    validated_input: NotRequired[str]  # type: ignore[valid-type] # JSON: minimised anomaly evidence packet
    input_format: NotRequired[str]  # type: ignore[valid-type] # "json" | "empty" | "rejected" | "free_text"
    # `enriched_context` is inherited from AgentState (platform-defined `dict`), not declared here.
    # pre_process writes {source, channel} into it — never the packet body.

    # ── inner workflow (SoT §4 Steps 3–6) ────────────────────────────────────
    evidence_findings: NotRequired[str]  # type: ignore[valid-type] # JSON: Step 3 deterministic reconcile output
    escalation_signals: NotRequired[str]  # type: ignore[valid-type] # JSON: Step 4 bounded-interpretation output
    citations: NotRequired[str]  # type: ignore[valid-type] # JSON: [{ref, source}]
    evidence_index: NotRequired[str]  # type: ignore[valid-type] # JSON: the closed surrogate set this run minted
    route_packet: NotRequired[str]  # type: ignore[valid-type] # JSON: composed BaseStationAnomalyEscalationRoute

    # ── counters / flags (primitives only) ───────────────────────────────────
    checked_field_count: NotRequired[int]  # type: ignore[valid-type]
    finding_count: NotRequired[int]  # type: ignore[valid-type]
    signal_count: NotRequired[int]  # type: ignore[valid-type]
    human_review_required: NotRequired[bool]  # type: ignore[valid-type]
    citation_complete: NotRequired[bool]  # type: ignore[valid-type]
    route_justified: NotRequired[bool]  # type: ignore[valid-type]
    synthesis_mode: NotRequired[str]  # type: ignore[valid-type] # "llm" | "deterministic_fallback"
    error_code: NotRequired[str]  # type: ignore[valid-type]

    # ── output (post_process) ────────────────────────────────────────────────
    formatted_output: NotRequired[str]  # type: ignore[valid-type]
    disclaimer: NotRequired[str]  # type: ignore[valid-type]
    audit_logged: NotRequired[bool]  # type: ignore[valid-type]

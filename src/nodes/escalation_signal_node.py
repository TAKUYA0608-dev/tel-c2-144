"""TEL-C2-144 — inner Step 4: EscalationSignalInterpret.

The bounded interpretation the SoT §2-4 argues is the Agent value: an unconfirmed correlation
declaration, an indirect change reference, an urgency claim written before its evidence. Each is
classified into the **closed** approved taxonomy and keeps the qualifier it arrived with.

Three things this step must never do, because each is one of the SoT's named failure modes:

- confirm sameness (that would fold independent events together — over-escalation);
- resolve a stated change reference into an enclosed one (that would read "not enclosed" as
  "attached" — the reviewer then trusts a document nobody sent);
- decide that an urgency claim holds, or drop it because it is unsupported (either direction is the
  over-/under-escalation pair the route-justification gate exists to prevent).

**This is where the LLM is.** SoT §2 classifies this template as an Agent *conditionally*: the
deterministic reconciler one step earlier is Tool-equivalent, and what makes the whole thing an Agent
rather than a Tool is the bounded interpretation performed here. The reconciler can say a field is
filled and a reference is unresolved; it cannot say whether "同一かもしれない" is a candidate or a
confirmed duplicate, whether "CR は別紙のとおり" is a delegation or a blank, or whether "至急" is a
substantiated claim or one written before its evidence. Those are the SoT §2-4 cases.

**pre-LLM containment lives upstream** (``pre_process``) and is a separate layer from S-2; by the
time a statement reaches here it is already quoted data, and ``build_llm_view`` builds the prompt
from the minimised packet alone, so a value dropped upstream has no path to the model.

**What comes back is constrained, not trusted.** ``validate_interpretations`` keeps only approved
taxonomy keys against spans this run derived, and re-derives the citation and evidence basis from the
packet rather than taking them from the model. Rejected output raises ``human_review_flag`` and is
never echoed. **With no client configured** the seeded deterministic lexicon runs and the envelope
says ``synthesis_mode: deterministic_fallback`` — nothing degrades silently.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import (
    build_llm_view,
    interpret_signals,
    validate_interpretations,
)
from src.utils.audit import emit_trace_event


class EscalationSignalNode(FunctionNode):
    """Classify escalation signals into the approved taxonomy, qualifiers intact."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def __init__(self, llm: Any = None) -> None:
        super().__init__()
        self._llm = llm

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code"):
            emit_trace_event("escalation_signal.skipped", {"reason": state.get("error_code")}, state)
            return {}  # upstream degraded — skip guard (inner graph is linear)

        packet = json.loads(state.get("user_input", "{}") or "{}")
        signals, mode, rejected = self._interpret(packet, state)
        emit_trace_event(
            "escalation_signal.complete",
            {
                "signals": len(signals),
                "synthesis_mode": mode,
                "rejected_interpretations": rejected,
                # Taxonomy keys and counts only — never a statement or a span.
                "kind_distribution": {
                    k: sum(1 for s in signals if s["kind"] == k) for k in {s["kind"] for s in signals}
                },
            },
            state,
        )
        return {
            "escalation_signals": json.dumps(signals, ensure_ascii=False),
            "signal_count": len(signals),
            "synthesis_mode": mode,
            "human_review_flag": rejected > 0,
            "status": AgentStatus.SUCCESS.value,
        }

    def _interpret(self, packet: dict[str, Any], state: dict[str, Any]) -> tuple[list[dict[str, Any]], str, int]:
        """Run the model when one is configured; fall back to the seeded lexicon otherwise."""
        if self._llm is None:
            return interpret_signals(packet), "deterministic_fallback", 0

        view = build_llm_view(packet)
        emit_trace_event("escalation_signal.llm_call", {"field_count": len(view["fields"])}, state)
        try:
            raw = self._llm.complete(json.dumps(view, ensure_ascii=False))
            kept, rejected = validate_interpretations(json.loads(raw), packet)
        except Exception as exc:  # noqa: BLE001 - any client/parse failure degrades, never crashes
            # A model that failed or answered off-schema must not silently thin the signal set —
            # dropping a signal here is under-escalation, the failure the SoT caps at zero. The
            # seeded lexicon runs, the mode is disclosed, and nothing the model produced is echoed.
            emit_trace_event("escalation_signal.llm_output_rejected", {"reason": type(exc).__name__}, state)
            return interpret_signals(packet), "deterministic_fallback", 1
        if not kept:
            emit_trace_event("escalation_signal.llm_output_rejected", {"reason": "no_admissible_interpretation"}, state)
            return interpret_signals(packet), "deterministic_fallback", max(rejected, 1)
        return kept, "llm", rejected

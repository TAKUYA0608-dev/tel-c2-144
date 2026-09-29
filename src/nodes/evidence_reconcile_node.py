"""TEL-C2-144 — inner Step 3: EvidenceCompletenessReconcile.

Checklist presence, in-packet reference resolution, cell/sector join, time-base agreement and span
anchoring are deterministic — the Tool-equivalent core, in ``services``. What this node owns is the
discipline around that core: **nothing is guessed and nothing is completed**. An unresolved
reference is flagged, never treated as enclosed; a mixed time base is flagged, never normalised to a
guessed one (guessing an ordering settles a before/after relationship, which is one step from the
root cause this template must not state).
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import reconcile_evidence
from src.utils.audit import emit_trace_event


class EvidenceReconcileNode(FunctionNode):
    """Reconcile the packet against its approved evidence checklist."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code"):
            # Skipping is a decision the audit trail has to show. Returning silently left the
            # degraded run with no domain event on this step at all (S-4 gap).
            emit_trace_event("evidence_reconcile.skipped", {"reason": state.get("error_code")}, state)
            return {}  # upstream degraded — skip guard (inner graph is linear)

        packet = json.loads(state.get("user_input", "{}") or "{}")
        if not packet.get("checklist_items"):
            emit_trace_event("evidence_reconcile.out_of_scope", {"reason": "no_checklist"}, state)
            return {
                "evidence_findings": "[]",
                "checked_field_count": 0,
                "finding_count": 0,
                "error_code": "NO_CHECKLIST",
                "status": AgentStatus.SUCCESS.value,
            }

        findings = reconcile_evidence(packet)
        emit_trace_event(
            "evidence_reconcile.complete",
            {
                "checked_fields": len(packet["checklist_items"]),
                "findings": len(findings),
                "kind_distribution": {
                    k: sum(1 for f in findings if f["kind"] == k) for k in {f["kind"] for f in findings}
                },
            },
            state,
        )
        return {
            "evidence_findings": json.dumps(findings, ensure_ascii=False),
            "checked_field_count": len(packet["checklist_items"]),
            "finding_count": len(findings),
            "status": AgentStatus.SUCCESS.value,
        }

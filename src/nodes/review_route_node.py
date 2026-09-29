"""TEL-C2-144 — inner Step 6: ReviewRouteCompose.

Composes the needs-review ``BaseStationAnomalyEscalationRoute``. It **proposes**; it assigns nobody,
opens or closes no ticket, touches no live network, and executes nothing.

Two properties are the point of this step:

1. **Every proposed route carries the evidence that decided it and a qualifier** (SoT §2-4 output
   discipline). The qualifier is what stops "urgent owner review" from reading as "this has been
   established as urgent", and what stops an unsupported claim from being silently dropped instead.
2. **A lower-precedence signal is never lost when a higher one wins the route.** The correlation
   candidate, the stated change reference, the contradiction and the gap are all carried in their
   own arrays with their own citations, plus a reviewer question. Losing them is how a router turns
   into a filter.

``root cause``, ``severity``, recovery steps and approvals are not produced here — and are rejected
at S-3 if some other path produces them.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import (
    CHANGE_KINDS,
    CITATION_BASIS,
    CONTRADICTION_KINDS,
    CORRELATION_KINDS,
    GAP_KINDS,
    REVIEWER_QUESTIONS,
    ROUTE_TAXONOMY,
    ROUTE_TAXONOMY_VERSION,
    decide_route,
)
from src.utils.audit import emit_trace_event

#: Marks a field this template quotes rather than asserts. S-3's determination-language scan skips
#: quoted text, so the envelope has to say, in the envelope, which text that is.
QUOTED_STATEMENT_STATUS = "quoted_from_packet_not_assessed"


def _base(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_basis": item.get("evidence_basis"),
        "evidence_span": item.get("evidence_span", ""),
        "description": item.get("description", ""),
        "statement": item.get("statement", ""),
        "statement_status": QUOTED_STATEMENT_STATUS,
    }


class ReviewRouteNode(FunctionNode):
    """Assemble the candidate BaseStationAnomalyEscalationRoute (needs-review)."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code"):
            emit_trace_event("review_route.skipped", {"error_code": state.get("error_code")}, state)
            return {
                "route_packet": json.dumps(
                    {
                        "status_kind": "out_of_scope",
                        "proposed_route": None,
                        "evidence_gaps": [],
                        "contradictions": [],
                        "correlation_candidates": [],
                        "change_context_refs": [],
                        "reviewer_questions": [],
                        "citations": [],
                        "citation_basis": CITATION_BASIS,
                    },
                    ensure_ascii=False,
                ),
                "human_review_required": False,
                "status": AgentStatus.SUCCESS.value,
            }

        packet = json.loads(state.get("user_input", "{}") or "{}")
        findings = json.loads(state.get("evidence_findings", "[]") or "[]")
        findings += json.loads(state.get("escalation_signals", "[]") or "[]")
        citations = json.loads(state.get("citations", "[]") or "[]")
        cited = {c["source"] for c in citations if c.get("source")}

        route = decide_route(findings, cited)
        route["description"] = ROUTE_TAXONOMY.get(route["route_kind"], "")

        route_packet = {
            "status_kind": "base_station_anomaly_escalation_route",
            "packet_id": packet.get("packet_id"),
            "packet_version_ref": packet.get("packet_version_ref"),
            "route_taxonomy_version": packet.get("route_taxonomy_version") or ROUTE_TAXONOMY_VERSION,
            "site_ref": packet.get("site_ref"),
            "cell_sector_refs": packet.get("cell_sector_refs", []),
            "proposed_route": route,
            "evidence_gaps": [
                dict(_base(f), gap_kind=f["kind"], cited_source_ref=(f.get("cited_source_refs") or [None])[0])
                for f in findings
                if f["kind"] in GAP_KINDS
            ],
            "contradictions": [
                dict(
                    _base(f),
                    kind=f["kind"],
                    cited_source_refs=f.get("cited_source_refs", []),
                    stated_time_bases=f.get("stated_time_bases", []),
                )
                for f in findings
                if f["kind"] in CONTRADICTION_KINDS
            ],
            "correlation_candidates": [
                dict(
                    _base(f),
                    candidate_ref=f.get("candidate_ref"),
                    confirmation_state=f.get("confirmation_state"),
                    cited_source_ref=(f.get("cited_source_refs") or [None])[0],
                )
                for f in findings
                if f["kind"] in CORRELATION_KINDS
            ],
            "change_context_refs": [
                dict(
                    _base(f),
                    ref_kind=f.get("ref_kind"),
                    resolution_state=f.get("resolution_state"),
                    cited_source_ref=(f.get("cited_source_refs") or [None])[0],
                )
                for f in findings
                if f["kind"] in CHANGE_KINDS
            ],
            # Deduplicated but order-stable, so the reviewer reads them in the order the findings
            # were raised rather than in set order.
            "reviewer_questions": list(
                dict.fromkeys(REVIEWER_QUESTIONS[f["kind"]] for f in findings if f["kind"] in REVIEWER_QUESTIONS)
            ),
            "citations": citations,
            "citation_basis": CITATION_BASIS,
            # The output is always needs-review: the owner confirms the route and selects every
            # operational action. This template never closes the loop itself.
            "human_review": {"required": True, "status": "pending_owner_review"},
        }

        emit_trace_event(
            "review_route.complete",
            {
                "route_kind": route["route_kind"],
                "qualifier": route["qualifier"],
                "justification_basis": route["justification_basis"],
                "deciding_kinds": route["deciding_kinds"],
                "gaps": len(route_packet["evidence_gaps"]),
                "contradictions": len(route_packet["contradictions"]),
                "correlation_candidates": len(route_packet["correlation_candidates"]),
                "change_context_refs": len(route_packet["change_context_refs"]),
            },
            state,
        )
        return {
            "route_packet": json.dumps(route_packet, ensure_ascii=False),
            "human_review_required": True,
            "status": AgentStatus.SUCCESS.value,
        }

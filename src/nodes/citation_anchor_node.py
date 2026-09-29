"""TEL-C2-144 — inner Step 5: CitationAnchorRetrieve.

Deterministic retrieval only — no ticket id, CR number, KPI row or work-log line is ever invented.

Publishes two things S-3 later re-derives from:

* ``citations`` — one entry per packet field whose ``source`` resolved to an authorised system of
  record at S-1. A route with no escalation signal is still justified by *these*, which is why they
  are built from the packet rather than only from the findings.
* ``evidence_index`` — the **closed set of surrogates this run minted at S-1**. S-3 checks generated
  text against that index, so a reference invented anywhere downstream (including by a path that
  bypassed this node) has nothing to match.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.utils.audit import emit_trace_event

#: Per-field keys whose values are surrogates minted at S-1 (join keys and the resolved citation).
_FIELD_SURROGATE_KEYS = ("cited_source_ref", "reference", "scope_ref")


class CitationAnchorNode(FunctionNode):
    """Anchor every finding to a deterministic evidence span and publish the closed index."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code"):
            emit_trace_event("citation_anchor.skipped", {"reason": state.get("error_code")}, state)
            return {}  # upstream degraded — skip guard (inner graph is linear)

        packet: dict[str, Any] = json.loads(state.get("user_input", "{}") or "{}")
        fields = [f for f in packet.get("fields", []) if isinstance(f, dict)]

        index: set[str] = set()
        key: str | tuple[str, str]
        for key in ("packet_id", "site_ref"):
            if packet.get(key):
                index.add(packet[key])
        index |= {r for r in packet.get("cell_sector_refs", []) if r}
        index |= {r for r in packet.get("packet_refs", []) if r}
        for field in fields:
            index |= {field[k] for k in _FIELD_SURROGATE_KEYS if field.get(k)}
            index |= {r for r in field.get("supporting_refs", []) if r}

        # A citation says "the caller declared this field as coming from this system of record".
        # Deduplicated on (field kind, source) so a repeated field kind does not inflate the list.
        seen: set[tuple[str, str]] = set()
        citations = []
        for field in fields:
            source = field.get("cited_source_ref")
            key = (str(field.get("field_kind") or ""), str(source or ""))
            if source and key not in seen:
                seen.add(key)
                citations.append({"ref": key[0], "source": source})

        emit_trace_event("citation_anchor.complete", {"index_size": len(index), "citations": len(citations)}, state)
        return {
            "citations": json.dumps(citations, ensure_ascii=False),
            "evidence_index": json.dumps(sorted(index), ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }

"""TEL-C2-144 — pre_process: SoT §4 Step 1 (AnomalyEvidencePacketIngest, S-1) + Step 2 (S-2).

Three layers run here, deliberately kept distinct — the SoT §4 note is explicit that they are not
the same thing, and conflating them is what lets a free-text incident description act as an
instruction:

1. **S-1 — structural validation.** Required fields, NFKC normalisation, size cap. Injection
   detection is *not* attributed to S-1 (SoT §4 Step 1).
2. **S-2 — subscriber and site-data minimisation (pre-LLM).** Subscriber identifiers (IMSI /
   MSISDN / IMEI / subscriber and line-contract ids), personal contact details, precise site
   location and internal asset ids are dropped or tokenised **before any downstream node sees
   them**. This is minimisation, not containment.
3. **pre-LLM containment (a separate layer).** Free-text incident descriptions, work-log excerpts
   and impact statements are treated as *quoted data*: an instruction-shaped statement is
   quarantined and never acted on. Independent of S-2 and tested independently.

**Provenance is resolved exactly once, here.** Downstream nodes receive citations, never raw
labels, so a caller value shaped like an internal surrogate can never re-enter the pipeline.

Degraded paths return ``SUCCESS + error_code`` and discard the offending body — never ``ERROR``,
which would skip ``post_process`` (S-3/S-4) in the production framework.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import (
    ID_TOKENISE_FIELDS,
    PII_DROP_FIELDS,
    contains_injection_marker,
    nfkc,
    opaque_id,
    redact,
    resolve_provenance,
)
from src.utils.audit import emit_trace_event

_MAX_INPUT = 400_000
_QUARANTINED = "[QUARANTINED — instruction-shaped content, not acted on]"

# Caller-supplied provenance CLAIMS. Every one is resolved through ``resolve_provenance`` here at
# S-1 — including ``cited_source_ref``, the field name the route packet itself uses downstream.
# Accepting that verbatim would let a caller mint a citation anchor by choosing a field name.
_PROVENANCE_FIELDS = frozenset({"source", "cited_source_ref", "checklist_source"})

#: Reference lists whose members are join keys, tokenised with the same rule as the field-level
#: reference so the membership tests downstream compare like with like.
_REF_LIST_FIELDS = {"packet_refs": "ref", "cell_sector_refs": "cell", "supporting_refs": "ref"}


def _minimise(obj: Any) -> Any:
    """Recursively drop subscriber/site PII, tokenise join keys, resolve provenance, redact secrets.

    Values of unknown fields are kept (a carrier packet legitimately carries operator-specific
    fields this template cannot enumerate) but are still secret-redacted. What *is* enumerated is
    what must never survive (``PII_DROP_FIELDS``) and what must always be tokenised
    (``ID_TOKENISE_FIELDS``).
    """
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            low = key.lower()
            if low in PII_DROP_FIELDS:
                continue  # dropped, not masked — the value never enters state
            if low in _REF_LIST_FIELDS and isinstance(value, list):
                out[key] = [opaque_id(v, _REF_LIST_FIELDS[low]) for v in value if v]
                continue
            if low in ID_TOKENISE_FIELDS:
                text = str(value).strip() if value is not None else ""
                out[key] = opaque_id(text, ID_TOKENISE_FIELDS[low]) if text else None
                continue
            if low in _PROVENANCE_FIELDS:
                # Single resolution point. Unauthorised / bare / forged-surrogate → None → S-3 blocks.
                out["cited_source_ref"] = resolve_provenance(value)
                continue
            out[key] = _minimise(value)
        return out
    if isinstance(obj, list):
        return [_minimise(v) for v in obj]
    if isinstance(obj, str):
        text = redact(nfkc(obj))
        # pre-LLM containment: quote, never obey. The fact that something instruction-shaped was
        # recorded is retained; its content is not carried forward.
        return _QUARANTINED if contains_injection_marker(text) else text
    return obj


class PreProcessNode(FunctionNode):
    """S-1 structural validation + S-2 minimisation + pre-LLM containment."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def _extra_security_gate_input(self, state: dict[str, Any]) -> dict[str, Any]:
        """S-2 hook. **Must return state and must never raise** (SDK 1.0.0).

        Raising here, or returning ``None``, sets state to ``None`` in the production framework and
        crashes every downstream node. Rejection is surfaced through ``error_code`` in ``execute``.
        """
        return dict(state)

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        raw = state.get("user_input", "") or ""
        input_context = state.get("input_context", {}) or {}  # read-only [C1]
        enriched = {
            "source": "BaseStationAnomalyEscalationRouterAgent",
            "channel": input_context.get("channel", "unknown"),
        }

        if len(raw) > _MAX_INPUT:
            emit_trace_event("anomaly_packet_ingest.rejected", {"reason": "INPUT_TOO_LONG"}, state)
            return {
                "validated_input": "{}",
                "input_format": "rejected",
                "enriched_context": enriched,
                "user_input": "",
                "error_code": "INPUT_TOO_LONG",
                "status": AgentStatus.SUCCESS.value,
            }

        if not raw.strip():
            emit_trace_event("anomaly_packet_ingest.rejected", {"reason": "INPUT_REJECTED"}, state)
            return {
                "validated_input": "{}",
                "input_format": "empty",
                "enriched_context": enriched,
                "error_code": "INPUT_REJECTED",
                "status": AgentStatus.SUCCESS.value,
            }

        packet, fmt = self._parse(nfkc(raw))

        # Whole-request rejection applies to an *instruction surface* only — a body that is not a
        # structured packet, so the request itself is the instruction. It must NOT apply to a
        # structured packet: a legitimate anomaly evidence packet can carry an instruction-shaped
        # string inside an incident description or a work-log excerpt, and rejecting the packet for
        # that discards real evidence — the under-escalation failure mode the SoT sets at a hard
        # ceiling of 0. Instruction-shaped content inside a packet is handled one layer down, by
        # `_minimise`, which quarantines the offending value and keeps the rest of the packet.
        if fmt == "free_text" and contains_injection_marker(raw[:2000]):
            emit_trace_event("anomaly_packet_ingest.rejected", {"reason": "INJECTION_REJECTED"}, state)
            return {
                "validated_input": "{}",
                "input_format": "rejected",
                "enriched_context": enriched,
                "user_input": "",
                "error_code": "INJECTION_REJECTED",
                "status": AgentStatus.SUCCESS.value,
            }

        body = json.dumps(packet, ensure_ascii=False)
        emit_trace_event(
            "anomaly_packet_ingest.validated",
            {
                "input_format": fmt,
                "checklist_item_count": len(packet.get("checklist_items", [])),
                "field_count": len(packet.get("fields", [])),
                "enclosed_ref_count": len(packet.get("packet_refs", [])),
                # How many values were quarantined as instruction-shaped. Recording the count keeps the
                # fact auditable without carrying the content forward.
                "quarantined_values": body.count(_QUARANTINED),
            },
            state,
        )
        return {
            "validated_input": body,
            "input_format": fmt,
            "enriched_context": enriched,
            "status": AgentStatus.SUCCESS.value,
        }

    @staticmethod
    def _parse(text: str) -> tuple[dict[str, Any], str]:
        empty: dict[str, Any] = {"checklist_items": [], "fields": [], "packet_refs": []}
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            return empty, "free_text"  # natural-language question → out-of-scope downstream
        if not isinstance(obj, dict):
            return empty, "free_text"
        minimised = _minimise(obj)
        return {
            "packet_id": minimised.get("packet_id"),
            "packet_version_ref": minimised.get("packet_version_ref"),
            "route_taxonomy_version": minimised.get("route_taxonomy_version"),
            "evidence_checklist_version": minimised.get("evidence_checklist_version"),
            "site_ref": minimised.get("site_ref"),
            "cell_sector_refs": minimised.get("cell_sector_refs") or [],
            "checklist_items": minimised.get("checklist_items") or [],
            "fields": minimised.get("fields") or [],
            "packet_refs": minimised.get("packet_refs") or [],
        }, "json"

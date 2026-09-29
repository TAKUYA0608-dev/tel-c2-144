"""TEL-C2-144 — post_process: SoT §4 Step 7 (OutputSanitise — S-3 output gate + S-4 no-persist).

**S-3 re-derives; it does not trust the composing step.** A route packet assembled by some other
path must not be able to publish, so every check here works from the envelope and the closed
evidence index rather than from a flag set upstream.

Five things are enforced:

1. **Citation completeness** (SoT §4 Step 7, gate 1) — every gap, contradiction, correlation
   candidate and change reference names a citation that is in the citation set. Uncited is
   admissible only where the absence *is* the claim and the entry declares
   ``evidence_basis = BASIS_ABSENT``.
2. **Route-justification completeness** (SoT §4 Step 7, gate 2) — the proposed route names a
   qualifier from the closed set and rests on an admissible basis. This is the gate that keeps
   over- and under-escalation visible: no reviewer receives a bare route.
3. **No fabricated surrogate** — every ``<kind>:<sha8>`` anywhere in the rendered envelope must be
   in the closed index this run minted, independent of the composing path.
4. **No determination language** (SoT §2-4) — the output may not state a root cause, a severity, a
   recovery procedure or an approval. Checked on the text this template *asserts*.
5. **Redaction + injection neutralisation + disclaimer** as the caller-visible boundary.

Failure is fail-closed and **degraded, not ERROR**: ``SUCCESS + error_code`` with the body withheld,
so the disclaimer and the terminal S-4 audit still run.
"""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import (
    CITATION_BASIS,
    CONTAINMENT_MARKERS,
    RULE_VERSION,
    asserts_determination,
    citation_binding_failure,
    redact,
    route_justification_failure,
    surrogates_in,
)
from src.utils.audit import emit_trace_event

# ── S-3: the authoritative injection / output-policy boundary ────────────────
#
# Upstream containment (``pre_process``) is required and is defence in depth, but it must not be
# *labelled* the injection security control and must not *substitute* for the S-3 proof. The
# caller-visible boundary is here: whatever reaches generated output is neutralised at S-3,
# whichever path produced it — including a path that bypassed ``pre_process`` entirely.
_NEUTRALISED = "[NEUTRALISED]"
_MARKER_RE = re.compile("|".join(re.escape(m) for m in CONTAINMENT_MARKERS), re.IGNORECASE)


def _neutralise_injection(text: str) -> tuple[str, int]:
    """Neutralise instruction-shaped artifacts in the rendered envelope. Returns (text, count)."""
    hits = len(_MARKER_RE.findall(text))
    return (_MARKER_RE.sub(_NEUTRALISED, text), hits) if hits else (text, 0)


# The only two fields the determination check does not scan:
#   - `disclaimer` is a reviewed template constant that legitimately contains "根本原因" / "復旧手順"
#     precisely in order to say the agent does NOT decide them. It is appended after this scan, but
#     a path that bypassed the composing node could carry a copy of it inside the packet, and the
#     guard rejecting its own disclaimer is a defect a sibling template shipped with.
#   - `statement` is the caller's own text, preserved verbatim for the accountable owner and carried
#     under `statement_status: quoted_from_packet_not_assessed`. Quoting a claim is not asserting
#     it; suppressing it would hide from the reviewer the very thing they have to read.
#
# ★ `note` and `message` were on this list and were removed after measurement: excluding them let
#   "root cause is the antenna" publish under an arbitrary `note` key on a gap entry. The template's
#   own `note` / `message` constants are appended *after* this scan, so they never needed the
#   exemption — and granting it handed a bypassing path a free field. Everything else — taxonomy
#   descriptions, qualifiers, reviewer questions, and any key an unknown path invents — is scanned.
_CONSTANT_OR_QUOTED_FIELDS = frozenset({"disclaimer", "statement"})


def _agent_authored_text(obj: Any, key: str | None = None) -> list[str]:
    """Collect the strings this template *asserts*, excluding reviewed constants and quoted text."""
    if isinstance(obj, dict):
        return [t for k, v in obj.items() for t in _agent_authored_text(v, k)]
    if isinstance(obj, list):
        return [t for v in obj for t in _agent_authored_text(v, key)]
    if isinstance(obj, str) and key not in _CONSTANT_OR_QUOTED_FIELDS:
        return [obj]
    return []


_DISCLAIMER = (
    "本出力は、提供された完了済み基地局異常証跡パケットに対する needs-review の"
    "人手レビュー経路の提案です。**根本原因の推定・重大度の設定・復旧手順の提示・対応可否の承認は"
    "行いません**。現用ネットワークへの接続、設定変更、チケットの作成/クローズ、顧客通知、復旧の実行も"
    "行いません。相関候補の同一事象性は判定せず、時刻基準の推測正規化も行いません。"
    "**S-3 が機械的に保証するのは citation の completeness（各証跡に認可済み system of record を"
    "名指しした出典参照が付いていること）と route-justification の completeness（提案経路に根拠と"
    "qualifier が付いていること）だけです。名指しされたレコードが当該システムに実在するかは"
    "本エージェントでは検証できません**（citation_basis を参照）。"
    "経路の確定と全ての運用アクションは、指名された network-operations の説明責任者が選択してください。"
)

_WITHHELD_MSG = (
    "提案経路またはその根拠の完全性が確認できなかったため、経路提案の提示を差し控えました。"
    "各証跡に `<認可済みシステム>:<レコード参照>` 形式の source を付与し、"
    "経路の根拠となる証跡が packet 内に含まれていることを確認のうえ再実行してください"
    "（レコードの実在性は本エージェントでは検証しません）。"
)
_NEEDS_REVIEW_NOTE = (
    "The proposed route or its justification could not be bound to declared source references; the "
    "route is withheld pending those references and accountable-owner review. Record existence is "
    "not verified by this agent (see citation_basis)."
)
_OUT_OF_SCOPE_MSG = (
    "基地局異常証跡パケットとして解釈できる入力が確認できませんでした。"
    "承認済み evidence checklist と証跡フィールドを含む JSON を送信してください。"
)


class PostProcessNode(FunctionNode):
    """S-3 output gate + S-4 no-persist audit."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def _extra_security_gate_output(self, result: dict[str, Any]) -> dict[str, Any]:
        """S-3 preservation check. Receives the **delta from execute()**; MAY raise (SDK 1.0.0)."""
        out = result.get("formatted_output", "")
        if out and "needs-review" not in out and "citation_basis" not in out:
            raise ValueError("S-3: mandatory disclaimer / citation basis missing from output")
        return dict(result)

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        route_packet: dict[str, Any] = json.loads(state.get("route_packet", "{}") or "{}")
        grounded = route_packet.get("status_kind") == "base_station_anomaly_escalation_route"

        if not grounded:
            # This is the path an upstream rejection (injection / oversize / empty / no checklist)
            # lands on. It set audit_logged=True while emitting nothing — the one publication path
            # with no S-4 event behind it.
            emit_trace_event(
                "output_sanitise.out_of_scope",
                {"reason": state.get("error_code") or "not_grounded", "rule_version": RULE_VERSION},
                state,
            )
            return self._envelope(
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
                    "message": _OUT_OF_SCOPE_MSG,
                },
                state,
                state.get("error_code"),
            )

        cited = {c["source"] for c in route_packet.get("citations", []) if c.get("source")}
        index = set(json.loads(state.get("evidence_index", "[]") or "[]"))

        # S-3, the caller-visible boundary: redact, then neutralise instruction-shaped artifacts in
        # whatever reached generated output — including via a path that never passed pre_process.
        rendered, injected = _neutralise_injection(redact(json.dumps(route_packet, ensure_ascii=False)))

        reason = citation_binding_failure(route_packet, cited)
        if reason is None:
            reason = route_justification_failure(route_packet, cited)
        if reason is None and not surrogates_in(rendered) <= index:
            reason = "UNVERIFIED_REFERENCE"
        if reason is None and any(asserts_determination(t) for t in _agent_authored_text(route_packet)):
            # A determination would exceed the stated boundary — withhold rather than publish it.
            reason = "DETERMINATION_ASSERTED"

        if reason is not None:
            # The rejected value is deliberately NOT echoed: only the violation kind is reported.
            emit_trace_event(
                "output_sanitise.withheld",
                {
                    "reason": reason,
                    "gap_count": len(route_packet.get("evidence_gaps", [])),
                    "injection_artifacts_neutralised": injected,
                    "rule_version": RULE_VERSION,
                },
                state,
            )
            return self._envelope(
                {
                    "status_kind": "needs_review",
                    "packet_id": route_packet.get("packet_id"),
                    "packet_version_ref": route_packet.get("packet_version_ref"),
                    "route_taxonomy_version": route_packet.get("route_taxonomy_version"),
                    # ★ The route itself is withheld: an unjustified route is exactly what must not
                    #   reach a reviewer, because they cannot tell it is unjustified by looking.
                    "proposed_route": None,
                    "evidence_gaps": [],
                    "contradictions": [],
                    "correlation_candidates": [],
                    "change_context_refs": [],
                    "reviewer_questions": route_packet.get("reviewer_questions", []),
                    "citations": [],
                    "citation_basis": CITATION_BASIS,
                    "citation_complete": False,
                    "route_justified": False,
                    "human_review": {"required": True, "status": "pending_owner_review", "note": _NEEDS_REVIEW_NOTE},
                    "message": _WITHHELD_MSG,
                },
                state,
                reason,
            )

        body = json.loads(rendered)
        body["citation_complete"] = True
        body["route_justified"] = True
        emit_trace_event(
            "output_sanitise.complete",
            {
                "status_kind": body["status_kind"],
                "route_kind": (body.get("proposed_route") or {}).get("route_kind"),
                "qualifier": (body.get("proposed_route") or {}).get("qualifier"),
                "gap_count": len(body.get("evidence_gaps", [])),
                "contradiction_count": len(body.get("contradictions", [])),
                "review_required": body.get("human_review", {}).get("required", False),
                "injection_artifacts_neutralised": injected,
                "rule_version": RULE_VERSION,
            },
            state,
        )
        return self._envelope(body, state, state.get("error_code"))

    @staticmethod
    def _envelope(body: dict[str, Any], state: dict[str, Any], error_code: str | None) -> dict[str, Any]:
        body["disclaimer"] = _DISCLAIMER
        # How the interpretation was produced travels with the envelope on every path. A
        # deterministic fallback that the reader cannot see is a silent degradation — the SoT
        # requires the mode to be disclosed, not merely audited.
        body["synthesis_mode"] = state.get("synthesis_mode") or "deterministic_fallback"
        out = {
            "formatted_output": json.dumps(body, ensure_ascii=False),
            "disclaimer": _DISCLAIMER,
            "audit_logged": True,
            "citation_complete": bool(body.get("citation_complete")),
            "route_justified": bool(body.get("route_justified")),
            "status": AgentStatus.SUCCESS.value,
        }
        if error_code:
            out["error_code"] = error_code
        return out

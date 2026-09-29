# TEL-C2-144 — the model view must show a field's structured evidence, and the validator must
# not let the model declare a supplied field missing or invert a stated absence.
import json


from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import Graph
from src.services.service import ROUTE_QUALIFIERS, build_llm_view, validate_interpretations

# The canonical Marketplace packet (batch 8, 2026-09-15): four required fields carry their evidence
# as reference / scope_ref / value, and two statements declare an absence (「〜なし」).
CANONICAL = json.loads(
    '{"packet_id": "PKT-2026-0801-01", "packet_version_ref": "v2", "evidence_checklist_version": "opc-v3", "site_ref": "ENB-12345", "cell_sector_refs": ["CELL-1"], "packet_refs": ["KPI-88", "WL-3"], "checklist_items": [{"field_kind": "incident_description", "required": true}, {"field_kind": "site_cell_ref", "required": true}, {"field_kind": "kpi_extract_ref", "required": true}, {"field_kind": "work_log_ref", "required": true}, {"field_kind": "related_ticket_ref", "required": true}, {"field_kind": "change_ref", "required": true}, {"field_kind": "impact_statement", "required": true}, {"field_kind": "timestamp", "required": true}], "fields": [{"field_kind": "incident_description", "source": "nms:evt-001", "statement": "当該セルで VSWR 上昇を検知"}, {"field_kind": "site_cell_ref", "source": "nms:evt-001", "scope_ref": "CELL-1"}, {"field_kind": "kpi_extract_ref", "source": "kpi_store:row-88", "reference": "KPI-88"}, {"field_kind": "work_log_ref", "source": "work_log:wl-3", "reference": "WL-3"}, {"field_kind": "related_ticket_ref", "source": "ticket_system:tck-1", "statement": "関連事象の申告なし"}, {"field_kind": "change_ref", "source": "change_mgmt:none", "statement": "変更・工事の関連なし"}, {"field_kind": "impact_statement", "source": "nms:evt-001", "statement": "1 セクタの品質低下", "supporting_refs": ["KPI-88"]}, {"field_kind": "timestamp", "label": "detected_at", "value": "02:14", "time_basis": "JST", "source": "nms:evt-001"}]}'
)


class _ScriptedClient:
    def __init__(self, reply):
        self.reply = reply
        self.prompts = []

    def complete(self, prompt):
        self.prompts.append(prompt)
        return json.dumps(self.reply)


def _spans():
    return {f["field_kind"]: f"fields[{i}].{f['field_kind']}" for i, f in enumerate(CANONICAL["fields"])}


def test_model_view_shows_structured_evidence_not_empty_quotes():
    view = build_llm_view(CANONICAL)
    quoted = {f["field_kind"]: f["quoted_text"] for f in view["fields"]}
    assert "CELL-1" in quoted["site_cell_ref"]
    assert "KPI-88" in quoted["kpi_extract_ref"]
    assert "WL-3" in quoted["work_log_ref"]
    assert "02:14" in quoted["timestamp"]
    assert all(quoted[k] for k in quoted), quoted


def test_validator_rejects_model_declared_missing_and_inverted_negation():
    spans = _spans()
    qualifier = sorted(ROUTE_QUALIFIERS)[0]
    bad = [
        {"span": spans["site_cell_ref"], "kind": "evidence_field_missing", "qualifier": qualifier},
        {"span": spans["related_ticket_ref"], "kind": "correlation_stated_unconfirmed", "qualifier": qualifier},
        {"span": spans["change_ref"], "kind": "change_reference_stated", "qualifier": qualifier},
    ]
    kept, rejected = validate_interpretations(bad, CANONICAL)
    assert kept == [] and rejected == 3


def test_invoke_path_routes_standard_when_the_model_misreads_the_packet():
    spans = _spans()
    qualifier = sorted(ROUTE_QUALIFIERS)[0]
    client = _ScriptedClient(
        [
            {"span": spans["site_cell_ref"], "kind": "evidence_field_missing", "qualifier": qualifier},
            {"span": spans["kpi_extract_ref"], "kind": "evidence_field_missing", "qualifier": qualifier},
            {"span": spans["related_ticket_ref"], "kind": "correlation_stated_unconfirmed", "qualifier": qualifier},
        ]
    )
    out = Graph(config={"llm": client}).invoke(
        json.dumps(CANONICAL, ensure_ascii=False),
        ctx=InvocationContext(caller_id="t", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL),
    )
    env = json.loads(out["output"]) if isinstance(out["output"], str) else out["output"]
    assert client.prompts, "the model was not consulted"
    missing = [g for g in env["evidence_gaps"] if g["kind"] == "evidence_field_missing"]
    assert missing == [], missing  # nothing supplied is reported missing
    assert env["correlation_candidates"] == []  # 「関連事象の申告なし」 is not a candidate
    assert env["proposed_route"]["route_kind"] == "route_standard_engineering_review", env["proposed_route"]


# Marketplace re-test, 2026-09-28: the model anchored a change claim to the cell reference, beside a
# change field that says 「変更・工事の関連なし」, and the claim was published — route change-context
# review and a reviewer question that presupposes a change. The absence check above only looks at the
# anchored field, so a claim may be anchored only to the field that states it.
def test_validator_rejects_a_claim_anchored_to_another_field():
    spans = _spans()
    bad = [
        {"span": spans["site_cell_ref"], "kind": "change_reference_stated", "qualifier": "change_reference_unresolved"},
        {"span": spans["incident_description"], "kind": "change_reference_stated", "qualifier": "change_reference_unresolved"},
        {"span": spans["site_cell_ref"], "kind": "correlation_stated_unconfirmed", "qualifier": "correlation_stated_unconfirmed"},
        {"span": spans["impact_statement"], "kind": "correlation_stated_unconfirmed", "qualifier": "correlation_stated_unconfirmed"},
    ]
    kept, rejected = validate_interpretations(bad, CANONICAL)
    assert kept == [] and rejected == 4


def test_a_claim_on_its_own_field_is_still_accepted():
    """The binding is not a blanket ban: a change field that states a change keeps the claim."""
    packet = json.loads(json.dumps(CANONICAL))
    change = next(f for f in packet["fields"] if f["field_kind"] == "change_ref")
    change.update({"statement": "CHG-2026-0915 のアンテナ交換工事", "reference": "CHG-2026-0915", "source": "change_mgmt:chg-915"})
    span = next(f"fields[{i}].change_ref" for i, f in enumerate(packet["fields"]) if f["field_kind"] == "change_ref")
    kept, rejected = validate_interpretations(
        [{"span": span, "kind": "change_reference_stated", "qualifier": "change_reference_unresolved"}], packet)
    assert rejected == 0 and [k["kind"] for k in kept] == ["change_reference_stated"]


def test_invoke_path_does_not_flip_a_stated_absence_through_another_field():
    spans = _spans()
    client = _ScriptedClient(
        [
            {"span": spans["site_cell_ref"], "kind": "change_reference_stated", "qualifier": "change_reference_unresolved"},
            {"span": spans["incident_description"], "kind": "correlation_stated_unconfirmed",
             "qualifier": "correlation_stated_unconfirmed"},
        ]
    )
    out = Graph(config={"llm": client}).invoke(
        json.dumps(CANONICAL, ensure_ascii=False),
        ctx=InvocationContext(caller_id="t", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL),
    )
    env = json.loads(out["output"]) if isinstance(out["output"], str) else out["output"]
    assert client.prompts, "the model was not consulted"
    assert env["change_context_refs"] == [], env["change_context_refs"]  # 「変更・工事の関連なし」 stays an absence
    assert env["correlation_candidates"] == []  # 「関連事象の申告なし」 stays an absence
    assert env["proposed_route"]["route_kind"] == "route_standard_engineering_review", env["proposed_route"]
    assert not any("工事票" in q for q in env.get("reviewer_questions", [])), env.get("reviewer_questions")


# Marketplace re-test, 2026-09-28 (evening): the model called the impact statement 「1 セクタの品質低下」 an
# UNSUBSTANTIATED urgency claim although the field carries supporting_refs ['KPI-88'] and KPI-88 is enclosed, and
# the false "no supporting evidence" gap was published. Whether a claim is backed is a fact of the packet: the
# model's reading of urgency is kept (under-escalation ceiling of 0), the qualifier follows the enclosed refs.
def test_the_severity_qualifier_follows_the_enclosed_supporting_refs():
    spans = _spans()
    kept, rejected = validate_interpretations(
        [{"span": spans["impact_statement"], "kind": "severity_claim_unsubstantiated", "qualifier": "claim_unsubstantiated"}],
        CANONICAL)
    assert rejected == 0 and len(kept) == 1
    assert kept[0]["kind"] == "severity_claim_substantiated"
    assert kept[0]["qualifier"] == "claim_substantiated" and kept[0]["supporting_ref_count"] == 1


def test_an_unbacked_urgency_claim_stays_unsubstantiated():
    """The binding is not a blanket upgrade: a supporting ref that is not enclosed does not back the claim."""
    packet = json.loads(json.dumps(CANONICAL))
    impact = next(f for f in packet["fields"] if f["field_kind"] == "impact_statement")
    impact["supporting_refs"] = ["KPI-999"]  # declared, not in packet_refs
    span = next(f"fields[{i}].impact_statement" for i, f in enumerate(packet["fields"]) if f["field_kind"] == "impact_statement")
    kept, _ = validate_interpretations(
        [{"span": span, "kind": "severity_claim_substantiated", "qualifier": "claim_substantiated"}], packet)
    assert [k["kind"] for k in kept] == ["severity_claim_unsubstantiated"] and kept[0]["qualifier"] == "claim_unsubstantiated"


def test_a_severity_claim_on_another_field_is_rejected():
    spans = _spans()
    kept, rejected = validate_interpretations(
        [{"span": spans["kpi_extract_ref"], "kind": "severity_claim_unsubstantiated", "qualifier": "claim_unsubstantiated"}],
        CANONICAL)
    assert kept == [] and rejected == 1


def test_invoke_path_never_publishes_a_false_unsubstantiated_gap():
    spans = _spans()
    client = _ScriptedClient(
        [{"span": spans["impact_statement"], "kind": "severity_claim_unsubstantiated", "qualifier": "claim_unsubstantiated"}]
    )
    out = Graph(config={"llm": client}).invoke(
        json.dumps(CANONICAL, ensure_ascii=False),
        ctx=InvocationContext(caller_id="t", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL),
    )
    env = json.loads(out["output"]) if isinstance(out["output"], str) else out["output"]
    assert client.prompts, "the model was not consulted"
    body = json.dumps(env, ensure_ascii=False)
    assert "severity_claim_unsubstantiated" not in body and "no supporting evidence" not in body, body[:400]
    # the model's urgency reading still reaches the accountable owner, now with the claim shown as backed
    assert env["proposed_route"]["route_kind"] == "route_urgent_owner_review", env["proposed_route"]
    assert env["proposed_route"].get("qualifier") == "claim_substantiated", env["proposed_route"]


# Marketplace re-test, 2026-09-29: with the model on, the reply carried "reference not enclosed" gaps for the enclosed
# KPI-88 / WL-3 and an "evidence_timestamp_conflict" for a packet with a single JST timestamp; without the model it
# carries neither. Structural facts are decided by reconcile_evidence alone, so the model is not asked for them and
# whatever it proposes of those kinds is rejected - while a true structural fact is still reported deterministically.
PRODUCTION_REPLY_0929 = [
    ("kpi_extract_ref", "evidence_reference_unresolved", "required_evidence_absent"),
    ("work_log_ref", "evidence_reference_unresolved", "required_evidence_absent"),
    ("timestamp", "evidence_timestamp_conflict", "timeline_not_normalisable"),
    ("timestamp", "statement_ambiguous", "timeline_not_normalisable"),
    ("impact_statement", "severity_claim_substantiated", "claim_substantiated"),
]


def _reply(spans):
    return [{"span": spans[f], "kind": k, "qualifier": q} for f, k, q in PRODUCTION_REPLY_0929]


def test_structural_facts_from_the_model_are_rejected():
    kept, rejected = validate_interpretations(_reply(_spans()), CANONICAL)
    assert [k["kind"] for k in kept] == ["severity_claim_substantiated"] and rejected == 4


def test_an_ambiguous_statement_on_a_field_with_prose_is_still_accepted():
    kept, rejected = validate_interpretations(
        [{"span": _spans()["incident_description"], "kind": "statement_ambiguous", "qualifier": "scope_not_determinable"}],
        CANONICAL)
    assert rejected == 0 and [k["kind"] for k in kept] == ["statement_ambiguous"]


def test_the_model_is_not_offered_structural_fact_kinds():
    offered = set(build_llm_view(CANONICAL)["allowed_kinds"])
    assert not offered & {"evidence_field_missing", "evidence_reference_unresolved", "evidence_scope_conflict",
                          "evidence_timestamp_conflict", "source_ref_missing"}, offered
    assert {"statement_ambiguous", "severity_claim_substantiated", "change_reference_stated"} <= offered


def test_invoke_path_publishes_no_structural_fact_the_packet_contradicts():
    client = _ScriptedClient(_reply(_spans()))
    out = Graph(config={"llm": client}).invoke(
        json.dumps(CANONICAL, ensure_ascii=False),
        ctx=InvocationContext(caller_id="t", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL),
    )
    env = json.loads(out["output"]) if isinstance(out["output"], str) else out["output"]
    assert client.prompts, "the model was not consulted"
    assert [g for g in env["evidence_gaps"] if g.get("gap_kind") == "evidence_reference_unresolved"] == []
    assert env["contradictions"] == [], env["contradictions"]
    assert not any("UTC" in q for q in env.get("reviewer_questions", [])), env.get("reviewer_questions")
    assert env["proposed_route"]["route_kind"] == "route_urgent_owner_review"
    assert env["proposed_route"].get("qualifier") == "claim_substantiated"


def test_a_true_structural_fact_is_still_reported_without_the_model():
    """Nothing is lost: when the packet itself shows the fact, reconcile_evidence reports it."""
    packet = json.loads(json.dumps(CANONICAL))
    packet["packet_refs"] = ["WL-3"]  # KPI-88 declared by the kpi field but not enclosed
    packet["fields"].append({"field_kind": "timestamp", "label": "cleared_at", "value": "18:20", "time_basis": "UTC",
                             "source": "nms:evt-001"})
    out = Graph().invoke(json.dumps(packet, ensure_ascii=False),
                         ctx=InvocationContext(caller_id="t", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL))
    env = json.loads(out["output"]) if isinstance(out["output"], str) else out["output"]
    assert any(g.get("gap_kind") == "evidence_reference_unresolved" for g in env["evidence_gaps"]), env["evidence_gaps"]
    assert any(c.get("kind") == "evidence_timestamp_conflict" for c in env["contradictions"]), env["contradictions"]

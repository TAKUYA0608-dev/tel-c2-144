"""TEL-C2-144 — unit tests for the deterministic service layer."""

import pytest

import src.services.service as svc


class TestProvenance:
    @pytest.mark.parametrize("value,ok", [
        ("nms:evt-001", True), ("kpi_store:row-88", True), ("work_log:wl-3", True),
        ("change_mgmt:cr-99", True), ("evidence_checklist:opc-v3", True),
        ("random_blog:r-1", False),          # unauthorised system of record
        ("nms", False),                      # a system, but no record → not a citation
        ("src:1a2b3c4d", False),             # shaped like an internal surrogate → no passthrough
        ("cell:deadbeef", False), ("山田 太郎", False), ("unknown", False), ("", False),
    ])
    def test_resolve_provenance(self, value, ok):
        assert (svc.resolve_provenance(value) is not None) == ok

    def test_declared_provenance_is_not_verification(self):
        """★ The documented limit, asserted rather than hidden.

        A fabricated reference under an authorised namespace DOES produce a citation. The packet and
        its labels arrive in the same caller body and no verification surface is exposed to the
        template, so the citation asserts a caller *declaration* — which the envelope states via
        `citation_basis`. Closing this needs a server-side lookup or gateway-signed references
        (SoT §12-B-4). If a future change makes provenance verifiable, this test fails and the claim
        in CITATION_BASIS and the docs must be updated with it.
        """
        assert svc.resolve_provenance("nms:invented-record").startswith("src:")

    def test_namespace_case_folds_but_reference_does_not(self):
        assert svc.resolve_provenance("NMS:evt-1") == svc.resolve_provenance("nms:evt-1")
        assert svc.resolve_provenance("nms:EVT-1") != svc.resolve_provenance("nms:evt-1")

    def test_src_is_never_an_authorised_system(self):
        """The prefix this template mints must not be one a caller can hand back."""
        assert "src" not in svc.AUTHORIZED_EVIDENCE_SYSTEMS

    def test_identifiers_are_always_tokenised(self):
        """No syntactic passthrough: a value already shaped like a surrogate is re-hashed."""
        assert svc.opaque_id("cell:aaaa1111", "cell") != "cell:aaaa1111"
        assert svc.opaque_id("ENB-12345", "site").startswith("site:")


class TestTaxonomyIsClosedAndPartitioned:
    def test_every_signal_kind_lands_in_exactly_one_output_array(self):
        """A reviewer has to be able to find every kind. A new one cannot be added without saying
        which array it appears in."""
        buckets = (svc.GAP_KINDS, svc.CONTRADICTION_KINDS, svc.CORRELATION_KINDS, svc.CHANGE_KINDS)
        classified = [k for k in svc.SIGNAL_TAXONOMY if k != "out_of_scope"]
        for kind in classified:
            hits = [b for b in buckets if kind in b]
            assert len(hits) == 1, f"{kind} appears in {len(hits)} output arrays"
        union = set().union(*buckets)
        assert union == set(classified), f"buckets name kinds outside the taxonomy: {union ^ set(classified)}"

    def test_every_classified_kind_has_a_reviewer_question(self):
        for kind in svc.SIGNAL_TAXONOMY:
            if kind != "out_of_scope":
                assert kind in svc.REVIEWER_QUESTIONS, kind

    def test_no_taxonomy_key_states_a_determination(self):
        """SoT §2-4: the template must not conclude a root cause, a severity value, a recovery
        step or an approval. A key that names one would smuggle the conclusion into the schema."""
        banned = ("root_cause", "rootcause", "severity_level", "approved", "resolved_cause",
                  "recovery_step", "fault_is")
        for key in list(svc.SIGNAL_TAXONOMY) + list(svc.ROUTE_TAXONOMY) + list(svc.ROUTE_QUALIFIERS):
            for word in banned:
                assert word not in key, f"{key!r} states an outcome"

    def test_the_five_proposable_routes_are_exactly_the_sot_set(self):
        assert svc.PROPOSABLE_ROUTES == {
            "route_evidence_incomplete", "route_duplicate_correlated_candidate",
            "route_standard_engineering_review", "route_change_context_review",
            "route_urgent_owner_review"}


class TestReconcileGuessesNothing:
    def _packet(self, fields, **over):
        packet = {"checklist_items": [{"field_kind": "incident_description", "required": True}],
                  "fields": fields, "packet_refs": [], "cell_sector_refs": []}
        packet.update(over)
        return packet

    def test_absent_required_field_declares_its_basis(self):
        gaps = svc.reconcile_evidence(self._packet([]))
        assert [g["kind"] for g in gaps] == ["evidence_field_missing"]
        assert gaps[0]["evidence_basis"] == svc.BASIS_ABSENT

    def test_a_finding_whose_source_did_not_resolve_has_no_admissible_basis(self):
        """★ The basis is passed in, never inferred from "are there refs".

        An entry exists but its source did not resolve → the finding has no references *because the
        citation failed*, which is not an absence claim. Marking it BASIS_ABSENT would let an
        entirely ungrounded route publish.
        """
        gaps = svc.reconcile_evidence(self._packet(
            [{"field_kind": "incident_description", "reference": "R-1"}]))
        for gap in gaps:
            assert gap["evidence_basis"] is None, gap["kind"]

    def test_an_unenclosed_reference_is_never_treated_as_enclosed(self):
        gaps = svc.reconcile_evidence(self._packet(
            [{"field_kind": "incident_description", "cited_source_ref": "src:11111111",
              "reference": "R-404"}]))
        assert "evidence_reference_unresolved" in [g["kind"] for g in gaps]

    def test_mixed_time_bases_are_flagged_not_normalised(self):
        """SoT §2-4 case 3 — a guessed ordering settles a before/after relation this agent must
        not settle. An unstated basis counts as one of the conflicting bases."""
        fields = [{"field_kind": "timestamp", "value": "02:14", "cited_source_ref": "src:11111111"},
                  {"field_kind": "timestamp", "value": "17:14", "time_basis": "UTC",
                   "cited_source_ref": "src:22222222"}]
        conflicts = svc.timestamp_conflict(fields)
        assert [c["kind"] for c in conflicts] == ["evidence_timestamp_conflict"]
        assert conflicts[0]["stated_time_bases"] == ["unstated", "utc"]

    def test_agreeing_time_bases_raise_nothing(self):
        fields = [{"field_kind": "timestamp", "time_basis": "JST"},
                  {"field_kind": "timestamp", "time_basis": "jst"}]
        assert svc.timestamp_conflict(fields) == []


class TestInterpretationKeepsTheQualifier:
    def _packet(self, field, refs=()):
        return {"fields": [dict({"cited_source_ref": "src:11111111"}, **field)],
                "packet_refs": list(refs)}

    def test_a_correlation_candidate_stays_a_candidate(self):
        signals = svc.interpret_signals(self._packet(
            {"field_kind": "related_ticket_ref", "reference": "TCK-9",
             "statement": "同一事象性は未確認"}))
        assert signals[0]["kind"] == "correlation_stated_unconfirmed"
        assert signals[0]["confirmation_state"] == "stated_unconfirmed"

    def test_a_stated_change_reference_records_whether_the_copy_is_enclosed(self):
        stated = svc.interpret_signals(self._packet(
            {"field_kind": "change_ref", "reference": "CR-99"}))
        assert stated[0]["resolution_state"] == "unresolved"
        enclosed = svc.interpret_signals(self._packet(
            {"field_kind": "change_ref", "reference": "CR-99"}, refs=["CR-99"]))
        assert enclosed[0]["resolution_state"] == "resolved"

    @pytest.mark.parametrize("refs,kind", [
        ((), "severity_claim_unsubstantiated"),
        (("KPI-88",), "severity_claim_substantiated"),
    ])
    def test_an_urgency_claim_is_never_dropped_only_qualified(self, refs, kind):
        signals = svc.interpret_signals(self._packet(
            {"field_kind": "impact_statement", "statement": "顧客影響大のため至急",
             "supporting_refs": list(refs)}, refs=refs))
        assert [s["kind"] for s in signals] == [kind]


class TestRoutePrecedence:
    def _f(self, kind, basis=svc.BASIS_CITED_RECORD, refs=("src:11111111",), **extra):
        return svc.finding("x", kind, list(refs), basis, **extra)

    def test_an_urgency_claim_outranks_everything(self):
        """★ SoT §11 risk 2 — under-escalation has a hard ceiling of 0, so no other finding may
        demote an urgency claim to the standard or evidence-incomplete queue."""
        route = svc.decide_route(
            [self._f("evidence_field_missing", svc.BASIS_ABSENT, ()),
             self._f("correlation_stated_unconfirmed"),
             self._f("change_reference_stated"),
             self._f("severity_claim_unsubstantiated")], {"src:11111111"})
        assert route["route_kind"] == "route_urgent_owner_review"
        assert route["qualifier"] == "claim_unsubstantiated"

    @pytest.mark.parametrize("kind,expected,qualifier", [
        ("evidence_field_missing", "route_evidence_incomplete", "required_evidence_absent"),
        ("evidence_timestamp_conflict", "route_evidence_incomplete", "timeline_not_normalisable"),
        ("evidence_scope_conflict", "route_evidence_incomplete", "scope_not_determinable"),
        ("source_ref_missing", "route_evidence_incomplete", "source_not_attributable"),
        ("correlation_stated_unconfirmed", "route_duplicate_correlated_candidate",
         "correlation_stated_unconfirmed"),
        ("change_reference_stated", "route_change_context_review", "change_reference_unresolved"),
    ])
    def test_each_deciding_kind_names_its_route_and_qualifier(self, kind, expected, qualifier):
        route = svc.decide_route([self._f(kind)], {"src:11111111"})
        assert (route["route_kind"], route["qualifier"]) == (expected, qualifier)

    def test_an_unresolved_reference_alone_does_not_change_the_route(self):
        """★ SoT §2-4 case 2 — a stated-but-unenclosed reference must keep its route and be
        surfaced as a cited gap. Demoting it to evidence-incomplete throws away the context that
        decided the route, which is the under-escalation failure."""
        route = svc.decide_route(
            [self._f("evidence_reference_unresolved"), self._f("change_reference_stated")],
            {"src:11111111"})
        assert route["route_kind"] == "route_change_context_review"

    def test_nothing_found_is_the_standard_queue_justified_by_the_cited_packet(self):
        route = svc.decide_route([], {"src:11111111", "src:22222222"})
        assert route["route_kind"] == "route_standard_engineering_review"
        assert route["justification_basis"] == svc.ROUTE_BASIS_CITED
        assert route["cited_source_refs"] == ["src:11111111", "src:22222222"]

    def test_a_packet_with_no_resolvable_source_cannot_justify_the_standard_route(self):
        assert svc.decide_route([], set())["justification_basis"] is None

    def test_the_route_basis_comes_from_the_findings_not_from_counting_refs(self):
        absent = svc.decide_route([self._f("evidence_field_missing", svc.BASIS_ABSENT, ())], set())
        assert absent["justification_basis"] == svc.ROUTE_BASIS_ABSENT
        unresolved = svc.decide_route([self._f("source_ref_missing", None, ())], set())
        assert unresolved["justification_basis"] is None


class TestDeterminationLanguage:
    @pytest.mark.parametrize("text", [
        "The root cause is the antenna.", "Outage caused by a power failure.",
        "severity: major", "Follow the recovery procedure.", "We approve dispatch.",
        "根本原因はアンテナ", "電源断に起因する", "復旧手順は以下のとおり", "対応を承認する",
    ])
    def test_assertions_are_detected(self, text):
        assert svc.asserts_determination(text) is True

    @pytest.mark.parametrize("text", [
        "A correlation candidate was declared and is not confirmed.",
        "至急の主張が記録されていますが、裏付け証跡は同梱されていません。",
        "Timestamps are stated on mixed time bases, so ordering is not determinable",
        "An urgency claim is recorded with no supporting evidence enclosed in the packet",
        "severity_claim_unsubstantiated",
    ])
    def test_neutral_reporting_is_allowed(self, text):
        assert svc.asserts_determination(text) is False

    def test_no_shipped_constant_trips_its_own_gate(self):
        """The gate rejecting the template's own vocabulary is a defect a sibling shipped with."""
        for table in (svc.SIGNAL_TAXONOMY, svc.ROUTE_TAXONOMY, svc.ROUTE_QUALIFIERS,
                      svc.REVIEWER_QUESTIONS):
            for key, text in table.items():
                assert not svc.asserts_determination(text), f"{key}: {text}"


class TestCitationBinding:
    def _packet(self, **over):
        gap = {"gap_kind": "evidence_field_missing", "cited_source_ref": None,
               "evidence_basis": svc.BASIS_ABSENT}
        gap.update(over)
        return {"evidence_gaps": [gap]}

    def test_absence_may_be_uncited_when_it_declares_the_basis(self):
        assert svc.citation_binding_failure(self._packet(), set()) is None

    def test_uncited_without_a_declared_basis_is_blocked(self):
        assert svc.citation_binding_failure(
            self._packet(evidence_basis=None), set()) == "UNDECLARED_ABSENCE"

    def test_cited_record_basis_with_no_reference_is_self_contradictory(self):
        assert svc.citation_binding_failure(
            self._packet(evidence_basis=svc.BASIS_CITED_RECORD), set()) == "UNDECLARED_ABSENCE"

    def test_reference_outside_the_citation_set_is_blocked(self):
        assert svc.citation_binding_failure(
            self._packet(cited_source_ref="src:deadbeef",
                         evidence_basis=svc.BASIS_CITED_RECORD), {"src:11111111"}) \
            == "CITATION_INCOMPLETE"

    @pytest.mark.parametrize("key", ["correlation_candidates", "change_context_refs"])
    def test_a_declared_statement_can_never_be_uncited(self, key):
        """A declared correlation or change reference asserts that the packet *says* something,
        so it has to name where."""
        assert svc.citation_binding_failure(
            {key: [{"evidence_basis": svc.BASIS_ABSENT}]}, set()) == "STATEMENT_WITHOUT_SOURCE"

    def test_contradictions_are_bound_through_the_plural_key(self):
        assert svc.citation_binding_failure(
            {"contradictions": [{"kind": "evidence_timestamp_conflict",
                                 "cited_source_refs": ["src:deadbeef"],
                                 "evidence_basis": svc.BASIS_CITED_RECORD}]},
            {"src:11111111"}) == "CITATION_INCOMPLETE"


class TestRouteJustification:
    def _packet(self, **over):
        route = {"route_kind": "route_standard_engineering_review",
                 "qualifier": "no_escalation_signal_detected",
                 "cited_source_refs": ["src:11111111"],
                 "justification_basis": svc.ROUTE_BASIS_CITED}
        route.update(over)
        return {"proposed_route": route}

    def test_a_justified_route_passes(self):
        assert svc.route_justification_failure(self._packet(), {"src:11111111"}) is None

    def test_a_route_outside_the_closed_set_is_blocked(self):
        assert svc.route_justification_failure(
            self._packet(route_kind="route_dispatch_now"), {"src:11111111"}) == "ROUTE_KIND_INVALID"

    def test_route_out_of_scope_is_not_proposable(self):
        assert svc.route_justification_failure(
            self._packet(route_kind="route_out_of_scope"), {"src:11111111"}) == "ROUTE_KIND_INVALID"

    @pytest.mark.parametrize("qualifier", ["", None, "very_urgent"])
    def test_a_route_without_an_approved_qualifier_is_blocked(self, qualifier):
        """★ SoT §4 Step 7 gate 2 — the qualifier is what stops "urgent owner review" reading as
        "this has been established as urgent"."""
        assert svc.route_justification_failure(
            self._packet(qualifier=qualifier), {"src:11111111"}) == "ROUTE_QUALIFIER_MISSING"

    def test_a_cited_route_with_no_references_is_blocked(self):
        assert svc.route_justification_failure(
            self._packet(cited_source_refs=[]), set()) == "ROUTE_JUSTIFICATION_MISSING"

    def test_a_route_citing_outside_the_citation_set_is_blocked(self):
        assert svc.route_justification_failure(
            self._packet(cited_source_refs=["src:deadbeef"]), {"src:11111111"}) \
            == "CITATION_INCOMPLETE"

    def test_no_admissible_basis_is_blocked(self):
        assert svc.route_justification_failure(
            self._packet(justification_basis=None), {"src:11111111"}) \
            == "ROUTE_JUSTIFICATION_MISSING"

    def test_only_the_incomplete_route_may_rest_on_an_absence(self):
        absent = dict(justification_basis=svc.ROUTE_BASIS_ABSENT, cited_source_refs=[])
        assert svc.route_justification_failure(
            self._packet(route_kind="route_evidence_incomplete",
                         qualifier="required_evidence_absent", **absent), set()) is None
        assert svc.route_justification_failure(
            self._packet(route_kind="route_urgent_owner_review",
                         qualifier="claim_unsubstantiated", **absent), set()) \
            == "ROUTE_JUSTIFICATION_MISSING"


class TestMinimisationPatterns:
    @pytest.mark.parametrize("text,leaked", [
        ("IMSI 440101234567890 を検出", "440101234567890"),
        ("連絡先 noc@example.com", "noc@example.com"),
        ("電話 03-1234-5678", "03-1234-5678"),
        ("設置座標 35.681236,139.767125", "35.681236"),
    ])
    def test_redaction_removes_subscriber_and_contact_data(self, text, leaked):
        assert leaked not in svc.redact(text)

    def test_redaction_leaves_operational_text_intact(self):
        assert svc.redact("VSWR 上昇を 02:14 に検知") == "VSWR 上昇を 02:14 に検知"

    def test_surrogate_scan_catches_kinds_this_template_never_mints(self):
        assert svc.surrogates_in("see aaa:deadbeef and src:11111111") == {
            "aaa:deadbeef", "src:11111111"}

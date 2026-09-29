"""One deterministic absence classifier, consumed by signal generation and model-output validation."""

from src.services.service import ROUTE_QUALIFIERS, interpret_signals, states_absence, validate_interpretations

ABSENT = [
    "関連事象の申告なし",
    "変更・工事の関連なし",
    "関連チケットはない",
    "該当なし。",
    "関連事象の申告無し",
    "関連事象の申告なし　",  # full-width trailing space
    "関連事象の申告なし。）",  # trailing punctuation
    "該当する変更はありません",
    "工事の関連は該当せず",
    "変更票: none",
    "Related event: N/A",
]
NOT_ABSENT = [
    "関連チケットあり",
    "件数は少ない",
    "危ない状態が続く",
    "申告なしでは困る",
    "なし崩しに進んだ",
    "関連事象を確認中",
    "変更票 CR-1234 を添付",
    "no related event was ruled out yet",
    "",
]


def test_absence_positives_and_boundary_negatives():
    assert all(states_absence(t) for t in ABSENT), [t for t in ABSENT if not states_absence(t)]
    assert not any(states_absence(t) for t in NOT_ABSENT), [t for t in NOT_ABSENT if states_absence(t)]


def _packet(statement, reference="TCK-9"):
    return {
        "packet_refs": [reference],
        "fields": [
            {
                "field_kind": "related_ticket_ref",
                "reference": reference,
                "statement": statement,
                "cited_source_ref": "src:1",
            },
            {"field_kind": "change_ref", "reference": "CR-1", "statement": statement, "cited_source_ref": "src:2"},
        ],
    }


def test_deterministic_generation_emits_no_signal_for_a_declared_absence():
    kinds = {s["kind"] for s in interpret_signals(_packet("関連事象の申告なし"))}
    assert "correlation_stated_unconfirmed" not in kinds and "change_reference_stated" not in kinds, kinds
    kinds = {s["kind"] for s in interpret_signals(_packet("関連チケット TCK-9 を申告"))}
    assert "correlation_stated_unconfirmed" in kinds and "change_reference_stated" in kinds, kinds


def test_validator_consumes_the_same_classifier():
    packet = _packet("変更・工事の関連なし")
    qualifier = sorted(ROUTE_QUALIFIERS)[0]
    bad = [
        {"span": "fields[0].related_ticket_ref", "kind": "correlation_stated_unconfirmed", "qualifier": qualifier},
        {"span": "fields[1].change_ref", "kind": "change_reference_stated", "qualifier": qualifier},
    ]
    kept, rejected = validate_interpretations(bad, packet)
    assert kept == [] and rejected == 2

# TEL-C2-144 — Test Specification

## Strategy

Three layers. No network; the LLM seam is exercised with a recording stub client
(`tests/integration/test_llm_seam.py`) rather than a live model:

- **unit** — `tests/unit/test_service.py`: provenance resolution vs privacy tokenisation, the closed
  taxonomies and their partition into the four output arrays, the reconcile rules that guess nothing,
  route precedence, and both S-3 gate contracts. Plus three machine checks that hold the template to
  its own documentation: `test_audit_coverage.py` (S-4 on every `execute()` path),
  `test_state_contract.py` (flat state) and `test_docs_match_implementation.py` (docs name only
  identifiers the code has).
- **integration** — `tests/integration/test_end_to_end.py`: **the real outer `Graph().invoke()`**,
  invoked exactly the way `src/api/server.py` does.
- **integration (node boundary)** — `tests/integration/test_s3_node_boundary.py`: S-3 proved by
  driving `PostProcessNode` directly, so the final boundary is proved rather than the upstream
  short-circuit.

> **Calling the graph in a test**: `invoke(user_input: str, session_id: str = "", ctx=None, ...)`.
> The first argument is a **string** and `ctx` **must be keyword-passed**. Passing it positionally
> lands it in the `session_id` slot, the caller stays ANONYMOUS, the S-1 trust gate refuses every
> node, and the run returns a bare `status=error` that reads like a template bug.

## Result

| Environment | Result |
|---|---|
| **CI (real SDK, authoritative)** — pipeline 61728 on `impl/cat2-nodes` @ `9936a0d2` | **143 passed, 2 skipped**; all 14 gate jobs `success` |
| **Local (the local SDK stub framework)** | **140 passed, 2 skipped, 3 env-diff failures** |

The three local failures are `test_pb_invoke_order` and
`test_framework_compliance_tc06_tc07::tc06/tc07`. They assert framework-level `@final` enforcement
and `emit_trace_event` monkeypatching that the local SDK stub shim does not implement. **They are not
fixed and not skipped** — they pass under the real SDK, which the CI count above confirms
(140 + 3 = 143). CI is authoritative for them.

The 2 skips are PB-7, conditional on `hitl.enabled` (the CoE conditional PB-7 stub) — this template is not
HITL, so the boundary assertion passes and the active test is skipped.

**Coverage 90 %** (`--cov=src`, floor 80 %). `ruff check src tests` clean.

## Framework compliance (mandatory)

| TC-ID | Test | Expected | Result |
|---|---|---|---|
| TC-01 | State contract: flat TypedDict | No Pydantic/dataclass; complex fields are JSON strings | ✅ `test_state_safety`, `test_state_contract` |
| TC-02 | Rejected input degrades, never raises | `SUCCESS + error_code`, body discarded | ✅ `test_empty_input_degrades_rather_than_erroring` |
| TC-03 | No credential in State | `gate-credential-scan`: 0 violations | ✅ CI |
| TC-04 | `InvocationContext` via configurable only | Not stored in State | ✅ `test_state_safety` |
| TC-05 | S-4: no duplicate lifecycle events in `execute()` | Domain events only | ✅ 0 duplicates |
| TC-06 | S-2 `_security_gate_input()` not overridden | `TypeError` at class definition | ✅ CI (real SDK) |
| TC-07 | S-3 `_security_gate_output()` not overridden | `TypeError` at class definition | ✅ CI (real SDK) |
| TC-08 | `required_trust_level` on every node | Insufficient trust → node refused | ✅ `gate-trust-level-check` + integration ctx |
| TC-09 | S-2 `_extra_security_gate_input()` returns state, never raises | Returns dict | ✅ unit |
| TC-10 | S-3 `_extra_security_gate_output()` non-trivial | Disclaimer / citation-basis preservation | ✅ unit |
| TC-11 | S-4: ≥1 domain `emit_trace_event()` per `execute()` path | Event on every path, machine-checked | ✅ `test_audit_coverage` |

## Proof-of-Boundary

| PB-ID | Boundary | Result |
|---|---|---|
| PB-1 | BaseNode → EventEmitter | ✅ |
| PB-2 | State serialization (primitives only after invoke) | ✅ `test_state_safety` |
| PB-4 | Import isolation (no `agenticstar` import from `src/`) | ✅ `test_import_isolation` |
| PB-6 | Node `__call__` order | ✅ CI — **the `GraphNode` lives in `src/graph/graph.py`, never `src/nodes/`**, because it needs `session_id` from a real `InvocationContext` |
| PB-7 | HITL interrupt propagation | ✅ Auto-waived — non-HITL; `hitl.enabled` is false here |

## Domain test cases

| TC-ID | Case | Expected |
|---|---|---|
| TC-D01 | **Deployed call path** (`invoke(input, ctx=ctx)`, nothing else) | Produces a real routed packet — the agent must not be inert on the path `server.py` uses |
| TC-D02 | Complete packet, all fields cited | `status_kind=base_station_anomaly_escalation_route`, route + qualifier + cited refs present, `citation_complete` and `route_justified` true |
| TC-D03 | Every envelope, grounded and withheld | carries `citation_basis: caller_declared_authorized_source` |
| TC-D04 | Free text / empty / no approved checklist | out-of-scope safe answer; no route invented |
| **TC-D05** | **SoT §2-4 case 1** — related tickets declared, sameness not confirmed | `route_duplicate_correlated_candidate` + `correlation_stated_unconfirmed`; the candidate keeps `confirmation_state`, with span, citation and a reviewer question |
| **TC-D06** | **SoT §2-4 case 2** — change reference stated, copy not enclosed | `route_change_context_review` + `change_reference_unresolved`; `resolution_state=unresolved` **and** an `evidence_reference_unresolved` gap. The route is **not** demoted to evidence-incomplete |
| **TC-D07** | **SoT §2-4 case 3** — three timestamps on mixed time bases | `route_evidence_incomplete` + `timeline_not_normalisable`; all three bases reported, all three cited, **no guessed normalisation** |
| **TC-D08** | **SoT §2-4 case 4** — urgency claim with / without enclosed support | `route_urgent_owner_review` both ways; qualifier `claim_unsubstantiated` vs `claim_substantiated` |
| **TC-D09** | **Urgency claim + a missing required field** | Stays `route_urgent_owner_review` — under-escalation ceiling is 0 — **and** the displaced `evidence_field_missing` is still reported |
| TC-D10 | Nothing found | `route_standard_engineering_review` + `no_escalation_signal_detected`, justified by the packet's own citations |
| TC-D11 | A higher-precedence signal wins | The displaced correlation candidate, change reference and reviewer questions are all still carried |
| TC-D12 | Subscriber / contact / site data in an entry | Dropped at S-2; absent from the output (IMSI, name, email, phone, address) |
| TC-D13 | Caller join keys (`ENB-12345`, `CELL-1`, `KPI-88`, `WL-3`) | Tokenised to `<kind>:<sha8>`; raw values absent from the output |
| TC-D14 | Unauthorised / bare / surrogate-shaped source | No citation → `needs_review`, `proposed_route: null`, value absent from the output |
| TC-D15 | Injection markers on the **request body** | Degraded `SUCCESS + INJECTION_REJECTED`, body discarded, markers absent |
| TC-D16 | Injection-shaped text **inside a quoted statement** | Packet still processed; the statement is quarantined, never echoed or obeyed |
| TC-D17 | Root cause / severity / recovery / approval wording from any path | Withheld at S-3 with `DETERMINATION_ASSERTED` |
| TC-D18 | Fabricated reference under an authorised namespace | **Does cite** — asserted deliberately (see below) |

> **TC-D18 records a known limit rather than hiding it.** The template cannot confirm a cited record
> exists: the packet and its labels arrive in the same caller body, and no verification surface is
> exposed to it. The envelope declares the basis instead of implying verification, and real
> verification is the SoT §12-B-4 platform dependency (docs/02, *Deviation from SoT §12-B-4*). If a
> future change makes provenance verifiable,
> `test_declared_provenance_is_not_verification` fails and the claim in `CITATION_BASIS` and the docs
> must be updated with it.

## Boundary / non-goal tests

| BL-ID | The agent must NOT | Verified by |
|---|---|---|
| BL-01 | Infer a root cause, set a severity, give recovery steps or approve a response | TC-D17, S-3 determination gate, taxonomy-key test |
| BL-02 | Confirm that two events are the same | TC-D05 — `confirmation_state` is preserved, never upgraded |
| BL-03 | Read a stated-but-unenclosed reference as enclosed | TC-D06 — `resolution_state=unresolved` |
| BL-04 | Guess a time base to settle an ordering | TC-D07 — all bases reported, conflict surfaced |
| BL-05 | Drop an unsupported urgency claim, **or** present it as established | TC-D08 / TC-D09 |
| BL-06 | Publish a route with no qualifier or no admissible basis | S-3 route-justification gate |
| BL-07 | Publish an ungrounded route | TC-D14, S-3 citation binding |
| BL-08 | Invent a route or a signal kind | closed `ROUTE_TAXONOMY` / `SIGNAL_TAXONOMY`; unknown → `out_of_scope` |
| BL-09 | Carry subscriber identity or site location downstream | TC-D12 |
| BL-10 | Echo instruction-shaped content | TC-D15 / TC-D16 |
| BL-11 | Return `status=ERROR` on a degraded path (which would skip S-3/S-4) | TC-D04 / TC-D15 |
| BL-12 | Lose a signal it did not route on | TC-D11 |

## Mutation checks

Every gate was mutated and the suite re-run, so each is demonstrated to constrain behaviour rather
than merely to pass. Measured 2026-08-05 against `tests/unit/test_service.py tests/integration`:

| Mutation | Tests that fail |
|---|---|
| `decide_route` infers the justification basis from "are there refs" instead of the findings' declared bases | **1** |
| An urgency claim is no longer top of `ROUTE_PRECEDENCE` | **2** |
| The route-justification gate stops checking the qualifier | **4** |
| `resolve_provenance` regains a `src:<hex>` format passthrough | **2** |
| `pre_process` rejects the whole packet on any marker (the pre-narrowing ordering) | **2** |

## Reproduce

```bash
source .venv/bin/activate
python -m pytest tests/ -q --cov=src --cov-report=term
ruff check src tests
python scripts/check_trust_level.py src/
python scripts/check_cat_consistency.py
python scripts/check_dep_pinning.py
python scripts/check_oss_license.py
```

## Framework input contract (AgentCore 1.0.1, a platform issue)

> Recorded 2026-08-26 as part of the AgentCore 1.0.1 S-2 migration. This is a transcription of a
> framework contract into this template's spec — not a weakening of any test.

- **Ruling** (platform, 2026-08-24): a high-confidence S-2 injection finding makes the framework
  itself refuse the invoke (`status=error`, no output) inside `InitializeNode`, before any template
  node runs. This is **correct behaviour** — the gate firing as designed is a pass, not a failed
  invoke. Templates cannot override it (`__init_subclass__` rejects it).
- **Residual constraint this template inherits**: a legitimate anomaly packet that merely *quotes*
  a high-confidence phrase (e.g. inside an `incident_description` statement) is refused wholesale
  at invoke time. The template's quarantine layer cannot act on what it never receives. This is a
  framework *input-contract* constraint on callers, fixed executably by
  `test_end_to_end.py::TestFrameworkRefusalIsTheContract` via `assert_framework_refused()`
  (status=error + no output + no echo; skipped under a local stub, where the production gate does not
  exist — CI against the real wheel is authoritative).
- **What the template layer still guarantees** (BL-10/BL-11, unchanged in substance): for
  everything the framework passes, instruction-shaped content inside a structured packet is
  quarantined — never obeyed, never grounds for discarding the packet (the 2,000-byte screening
  window included) — and a free-text body that *is* the instruction is answered as `out_of_scope`.
  These properties are now proven with a **sub-threshold** marker (framework confidence *medium*,
  still matched by `CONTAINMENT_MARKERS`); the premise is pinned by
  `test_the_probe_marker_still_trips_the_template_detector`. The pre-LLM containment proof
  (`test_llm_seam.py`) uses the same sub-threshold marker for the same reason.
- The degraded-run audit-coverage checks (`test_audit_coverage.py::TestSkipPathBehaviour`) now
  trigger with an empty body instead of an injection marker: under 1.0.1 a refused invoke runs
  zero template nodes, so it exercised nothing. The degraded=SUCCESS invariant and the "every step
  accounts for itself" property are unchanged.

## Test execution summary

- Execution date: 2026-08-05
- CI (real SDK, authoritative): **143 passed, 2 skipped**, all 14 gate jobs `success` (pipeline 61728)
- Local (the local SDK stub): **140 passed, 2 skipped, 3 env-diff failures** (real-SDK-only assertions)
- Coverage: **90 %** (floor 80 %)

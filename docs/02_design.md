# TEL-C2-144 — Design (Stage ②)

Source: the original template proposal. **L1 Base: `AgentBaseGraph`, inherited
directly.** Agent class:
`BaseStationAnomalyEscalationRouterAgent`.

## Scope

Takes a **completed, sanitised** base-station anomaly evidence packet and proposes **which human
review queue should see it next**, together with the cited evidence that decided the route.

**Out of scope, by design** — connecting to the live network, active measurement, configuration
change, ticket creation or closure, customer notification, recovery execution, and — the four the
SoT names explicitly — **inferring a root cause, setting a severity, producing recovery steps, or
approving a response**. The route is a proposal; the named accountable network-operations owner
confirms it and selects every operational action.

## Architecture — Cat 2 GraphNode-in-main

```
START → initialize → pre_process → main(GraphNode) → post_process → finalize → END
                          │              │                  │
                     S-1 + S-2 +    inner BaseGraph      S-3 + S-4
                     containment    (linear, 4 steps)
```

| SoT §4 step | Slot / node | Responsibility |
|---|---|---|
| 1 `AnomalyEvidencePacketIngest` | `pre_process` — `PreProcessNode` | S-1 structural validation (NFKC, size cap, required fields). Injection detection is **not** attributed here |
| 2 `SubscriberAndSiteDataMinimise` | `pre_process` — `PreProcessNode` | S-2 minimisation before any downstream node sees the packet; **provenance resolved exactly once**; pre-LLM containment as a separate layer |
| — | `main` — `BaseStationAnomalyEscalationRouteWorkflowGraphNode` | Wraps the inner workflow. Defined in `src/graph/graph.py`, **never under `src/nodes/`** |
| 3 `EvidenceCompletenessReconcile` | inner 1 — `EvidenceReconcileNode` | Deterministic checklist presence, in-packet reference resolution, cell/sector join, time-base agreement, span anchoring |
| 4 `EscalationSignalInterpret` | inner 2 — `EscalationSignalNode` | Bounded interpretation into the closed taxonomy; every declared qualifier is preserved |
| 5 `CitationAnchorRetrieve` | inner 3 — `CitationAnchorNode` | Deterministic citations + the **closed evidence index** this run minted |
| 6 `ReviewRouteCompose` | inner 4 — `ReviewRouteNode` | One route from the closed taxonomy, with the evidence and qualifier that decided it |
| 7 `OutputSanitise` | `post_process` — `PostProcessNode` | S-3 output gate (re-derived, not trusted) + S-4 no-persist audit |

**Why the inner graph is linear with per-node skip guards.** `add_conditional_edges` does not branch
when a graph is driven through a `GraphNode`; every shipped Cat 2 template in this portfolio uses a
linear chain in which each node returns `{}` early if an upstream step degraded. Reproducing that
keeps behaviour identical whether the inner graph is invoked directly or through the outer agent.

**Why the GraphNode is not under `src/nodes/`.** PB-6 (`test_pb_invoke_order`) instantiates every
class under `src/nodes/` and calls it with a bare state; a `GraphNode` resolves an
`InvocationContext` from that state, so one placed there fails with `KeyError: 'session_id'`.

**Subgraph cache.** `_subgraph` is a `ClassVar` **keyed on the identity of the injected llm client**,
assigned through the class. A plain ClassVar cache is wrong on its own once a client can be injected:
the first construction wins, so an agent configured *with* a client can be handed a deterministic
subgraph cached earlier. The cache is capacity-bounded (8).

## The deliverable: `BaseStationAnomalyEscalationRoute`

| Field | Meaning |
|---|---|
| `packet_id` / `packet_version_ref` / `route_taxonomy_version` | Which packet, which version, which approved taxonomy decided the route |
| `site_ref` / `cell_sector_refs` | Tokenised join keys — never the raw site identifier |
| `proposed_route` | `{route_kind, qualifier, cited_source_refs, justification_basis, deciding_kinds, description}` |
| `evidence_gaps` | `{gap_kind, cited_source_ref, evidence_basis, evidence_span, statement, statement_status}` |
| `contradictions` | `{kind, cited_source_refs, stated_time_bases, evidence_span, …}` |
| `correlation_candidates` | `{candidate_ref, confirmation_state, evidence_span, cited_source_ref, …}` |
| `change_context_refs` | `{ref_kind, resolution_state, evidence_span, cited_source_ref, …}` |
| `reviewer_questions` | Seeded per finding kind; deduplicated, order-stable |
| `status_kind` | `base_station_anomaly_escalation_route` · `needs_review` · `out_of_scope` |
| `citation_basis` / `disclaimer` | What a citation asserts, and what the agent does not decide |
| `human_review` | Always `{required: true, status: pending_owner_review}` — SoT §4: the output is always needs-review |

### The five proposable routes and their precedence

Precedence is the safety property of this template, and the order is a **seeded operator policy**
(SoT §12-A) that SoT §12-B-2 asks the accountable owner to approve.

| # | Route | Fires on | Qualifier |
|---|---|---|---|
| 1 | `route_urgent_owner_review` | `severity_claim_unsubstantiated` · `severity_claim_substantiated` | `claim_unsubstantiated` / `claim_substantiated` |
| 2 | `route_evidence_incomplete` | `evidence_field_missing` · `evidence_timestamp_conflict` · `evidence_scope_conflict` · `source_ref_missing` | `required_evidence_absent` / `timeline_not_normalisable` / `scope_not_determinable` / `source_not_attributable` |
| 3 | `route_duplicate_correlated_candidate` | `correlation_stated_unconfirmed` | `correlation_stated_unconfirmed` / `correlation_confirmed` |
| 4 | `route_change_context_review` | `change_reference_stated` | `change_reference_unresolved` / `change_reference_enclosed` |
| 5 | `route_standard_engineering_review` | nothing else fired | `no_escalation_signal_detected` |

**★ An urgency claim always wins.** SoT §11 risk 2 sets under-escalation — an urgent-equivalent
event demoted to the standard or evidence-incomplete queue — at a **hard ceiling of 0**, so no other
finding may displace it. The same rule curbs over-escalation from the other side: an unsupported
claim is routed to the owner *carrying* `claim_unsubstantiated`, so it is neither dropped nor
presented as established.

**★ `evidence_reference_unresolved` is deliberately not a deciding kind.** SoT §2-4 case 2 requires
a stated-but-unenclosed change reference to keep its change-context route and surface the unresolved
reference as a cited gap. A strict rule that demoted it to "evidence incomplete" would throw away
the very context that decided the route. Generalised: an unresolved reference is always surfaced and
never on its own changes the route.

**★ Nothing is lost when a higher-precedence signal wins.** The displaced findings stay in their own
arrays with their own citations and reviewer questions. A router that drops what it did not route on
is a filter.

## LLM usage — the Agent value, and where the deterministic core sits

**The bounded interpretation in Step 4 is LLM-backed.** `Graph(config={"llm"})` forwards the client
through `GraphNode._parent_config()` to the inner graph, which hands it to `EscalationSignalNode`.

This was **deterministic-only in the first implementation and that was wrong**, not merely a
simplification. SoT §2 classifies this template as an Agent *conditionally*: the deterministic
reconciler is Tool-equivalent, and what makes the whole thing an Agent rather than a Tool is exactly
this interpretation step. Removing it removed the basis of the classification. The moderator raised it
on 2026-08-05 and the finding was correct.

**What the model is shown.** `build_llm_view()` builds the prompt from the minimised packet and
nothing else, so a value dropped at S-2 or quarantined by pre-LLM containment has no path to the
model. The free text is framed as quoted evidence, never as instructions, and the model is asked only
to choose a taxonomy key — never to write a route, a severity or a cause.

**What comes back is constrained, not trusted.** `validate_interpretations()` keeps only
`{span, kind, qualifier}` triples whose kind and qualifier are inside the approved closed sets and
whose span is one **this run derived from the packet**. The citation and the evidence basis are
re-derived from the packet rather than taken from the model, so a model that echoed text back cannot
reintroduce it or manufacture grounding. Rejected output raises `human_review_flag` and is never
echoed.

**Degradation is disclosed, never silent.** With no client configured — or on any client failure,
unparseable reply or wholly inadmissible reply — the seeded lexicon (SoT §12-A) runs and every
envelope carries `synthesis_mode: "deterministic_fallback"`. Falling back rather than thinning the
signal set matters here specifically: dropping a signal is *under*-escalation, the failure SoT §11
risk 2 caps at zero.

`tests/integration/test_llm_seam.py` drives the real `Graph().invoke()` with a recording client, so
it proves the wiring rather than the helper — a seam that is never reached fails
`test_the_client_is_actually_reached`.

### The deterministic reconciler and the `shared/tools/` boundary

SoT §2 also asks for the deterministic completeness reconciler to be extracted into
**`shared/tools/`**. That part is **not done in this MR, and cannot be**: `shared/` is
platform-owned — templates *import* from it (`from shared.services.llm...`, `from
shared.utils.audit_logger...`) and never publish into it — and the template layout rule fixes the template
layout with "never create files outside this structure". No template in the portfolio contains a
`shared/` or `tools/` directory.

What is done instead is to keep the reconciler **Tool-shaped so the promotion is a move, not a
rewrite**: `reconcile_evidence()` is a pure function over the packet — no state, no LLM, no I/O, no
node dependency — and `EvidenceReconcileNode` is a thin caller. Promoting it into `shared/tools/` is
a CoE-owned action; recorded as a §12-B dependency rather than silently dropped.

## Security layers

The SoT §4 note requires these four to be described as *separate* layers, in this order.

| Layer | Where | What |
|---|---|---|
| **S-1** | `pre_process` | Structural validation, NFKC, 400 000-char cap. Injection detection is *not* attributed here |
| **S-2** | `pre_process` | Subscriber identity (IMSI / MSISDN / IMEI / subscriber and line-contract ids), personal contact details, precise site location (address / coordinates) and internal asset ids **dropped, not masked**; every join key tokenised to a non-reversible surrogate |
| **pre-LLM containment** | `pre_process`, a layer of its own | Free-text incident descriptions, work-log excerpts and impact statements are quoted data. An instruction-shaped *statement* is quarantined; an instruction-shaped *request body* is rejected outright and discarded |
| **S-3** | `post_process` | Citation completeness · route-justification completeness · no fabricated surrogate · no determination language · redaction · injection neutralisation · disclaimer |
| **S-4** | all nodes | Counts, rule version and error codes only. Never a raw incident description, a KPI extract, a work-log line, a subscriber identifier, a site address, or a rejected value |

### LLM view vs deterministic channel

SoT §4 Step 2 asks for a minimised LLM view separated from a deterministic channel holding the real
values. This implementation keeps **only the minimised view**: no node, deterministic or otherwise,
sees a raw subscriber identifier or a site address, because minimisation happens once at S-1/S-2 and
the raw values are never carried forward. That is stronger than the split, not weaker. The split
becomes necessary only if a deterministic step later needs a real value back — none does today, and
`test_state_contract.py` plus the integration PII tests hold the line.

### S-3 re-derives; it does not trust the composing step

A route packet assembled by any other path must not be able to publish, so each check works from the
envelope and the closed index rather than from a flag set upstream:

1. **Citation completeness.** Every gap, contradiction, correlation candidate and change reference
   names a citation that is in the citation set. Uncited is admissible only when the absence *is* the
   claim **and** the entry declares `evidence_basis = absent_from_supplied_packet`. A declared
   correlation or change reference can never be uncited — it asserts that the packet *says*
   something, so it has to name where.
2. **Route-justification completeness.** The proposed route must name a `route_kind` from the closed
   proposable set, a `qualifier` from the closed qualifier set, and rest on an admissible
   `justification_basis`: `cited_evidence` requires references inside the citation set, and
   `absent_from_supplied_packet` is admissible **only** for `route_evidence_incomplete` — no other
   route may claim it was decided by evidence that is not there.
3. **No fabricated surrogate.** Every `<kind>:<sha8>` anywhere in the rendered envelope must be in
   the closed index this run minted, independent of which node produced it.
4. **No determination language.** The output may not state a root cause, a severity, a recovery
   procedure or an approval. Scanned over the text this template *asserts* — the only exemptions are
   `disclaimer` (a reviewed constant that names those words in order to disclaim them) and
   `statement` (the caller's own text, carried under `statement_status:
   quoted_from_packet_not_assessed`). `note` and `message` were on that exemption list and were
   removed after measurement: excluding them let "root cause is the antenna" publish under an
   arbitrary `note` key.
5. **Redaction and injection neutralisation** as the caller-visible boundary — including for a path
   that never passed `pre_process`.

Failure is **degraded, not `ERROR`**: `SUCCESS + error_code` with the route withheld
(`proposed_route: null`), so the disclaimer and the terminal S-4 audit still run. Returning `ERROR`
would skip `post_process` entirely in the production framework.

### Evidential basis is passed in, never inferred

`finding(...)` takes `evidence_basis` explicitly, and `decide_route(...)` derives the route's
`justification_basis` from the **deciding findings' own declared bases** — never from "are there
references?". Those are different questions, and conflating them is a real hole: a finding raised
against an entry whose source failed to resolve has no references **because the citation failed**,
which is not an absence claim. Inferring `absent_from_supplied_packet` there would let an entirely
ungrounded route publish.

## ★ Deviation from SoT §12-B-4 — the ingress attestation is not implemented

SoT §4 Step 1 and §11 risk 7 say caller-declared values (`completed` / `sanitised` /
`packet_version_ref` / `source`) should be accepted only after matching a trusted ingress attestation
the caller cannot set from the request body, e.g. `input_context`. **That is not implemented, and
implementing it as written would make this agent produce no output at all.**

- The SDK documents `input_context` as **caller** metadata
  (the SDK state-schemas reference: *"`input_context` | `dict` | `invoke()` | Caller metadata"*).
- The scaffold's own `src/api/server.py` calls `agent.invoke(req.input, ctx=ctx)` and does **not**
  pass `input_context` at all.
- Two sibling TEL templates gated citations on that field. Because nothing populates it on the
  deployed path, **every valid payload degraded to `needs_review` with the body withheld** — measured
  on the real invoke path, not inferred. Trading a weak claim for no output is not an improvement.
- Forwarding a caller-supplied attestation instead would be circular: the caller already controls the
  `source` label the attestation would be validated against.

**What is implemented instead** (the "if it cannot be verified, do not say it is verified" position):

| The citation DOES assert | The citation does NOT assert |
|---|---|
| the caller declared this field as coming from a **named authorised system of record**, with a reference part | that the record **exists** in that system |
| the raw label never reaches the output (privacy hash `src:<sha8>`) | that the declaring caller is entitled to speak for that system |
| a caller value merely **shaped** like an internal surrogate is rejected, not passed through — `src` is not an authorised namespace | |
| a bare namespace is rejected — it names a system but no record | |

Every envelope carries `citation_basis: "caller_declared_authorized_source"`, on both the grounded
and the withheld path, so no reviewer infers verification from the word "citation". Real verification
needs a server-side lookup or gateway-signed references delivered outside the caller's body — **the
platform dependency tracked in SoT §12-B-4, not simulated here.**
`tests/unit/test_service.py::TestProvenance::test_declared_provenance_is_not_verification` asserts
the residual limit (a fabricated reference under an authorised namespace **does** cite), so if a
future change makes provenance verifiable that test fails and this section must be updated with it.

## State

Flat TypedDict (ADR-005). Every non-primitive payload is a **JSON string**, never a nested structure:
LangGraph checkpoints use msgpack, and a bare `list[dict]` in state has been raised in review on
sibling templates. `enriched_context` is **not** declared here — it is the platform's own `dict`
field, and re-declaring or narrowing it would put the template out of contract with the framework
that owns it. No credential, no subscriber identifier and no site address is placed in state.

## Open items (Stage ③)

None outstanding — the implementation ships in the same MR series as this design. The external
dependencies are the SoT §12-B items: **B-4** (ingress attestation, described above), **B-2**
(operator approval of the route/gap taxonomy, the route precedence order and the exception owner per
queue) and **B-3** (通信の秘密 / subscriber-data sign-off). Until B-4 lands, a citation records a
caller declaration and the envelope says so.

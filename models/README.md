# Non-authorizing approval model

This directory is a pure test model of the independently reviewed publication
contract (control PR #2, merged as 7620a31a1e0213a2cc064cd2835fd6dde7551f4c).
It is not imported by any task executor; no such executor exists here.

`approval_model.check_envelope` checks bounded exact JSON fields, duplicate
keys/types, fixed TEST/secret_scan scope, hypothetical digest bindings and a
conservative explicit clock window. Caller bindings, merge time, clock and
snapshots are untrusted model inputs, not authenticated GitHub evidence.
The hypothetical offline-test.yml workflow path is not an existing runner.

`propose` returns an immutable child-state candidate. `apply_candidate_model`
simulates sequential compare-and-set using a parent digest and monotonic state
changes. Two candidates derived from the same snapshot can both be proposed,
but only one can be applied to the resulting modeled sequence. The model does
not make concurrent requests, acquire real locks, write Git refs, create a
ledger, authenticate reviewers, check live revocation or prove distributed
atomicity. A candidate may not revive or remove a consumed/revoked ID.

All Check/Transition results have read-only execution_authorized=false and
permitted_actions=(). Constructors cannot accept positive authorization fields.
Neither a caller-constructed snapshot nor a model-valid result is a capability.
Never connect these results to process spawning or task admission.

Tests use only synthetic metadata. They cover every missing/wrong-type field,
malformed/duplicate/oversized JSON, context bindings, lifetime/skew/merge-time,
replay, lost acknowledgment, crash burn semantics, revision bounds and modeled
claim/revoke interleavings. Runtime guards block disk/socket/spawn/wall-clock
reads in the exercised flow. Real backend races/permissions remain future work.

## Reproduction

```sh
python3.12 -I -m unittest discover -s tests -v
```

No network, dependency installation, container dispatch, target EJS code,
credentials, approval JSON or operational records are needed. The existing
control-static job discovers these tests without a workflow change. Container
proof remains manual-only; this change does not claim the old isolation proof
covers any future task runner.

## Checkpoint — 2026-11-03

EJS priority 1 / bounded Codex model review / OPENAI_AGENT_SHARED; remaining and
reset Unknown. Source control main 7620a3; PR #2 actual bykcgty review verified.
Artifact: pure model plus negative tests. Stop before authenticated publication,
real ledger transactions, credentials, process execution or dispatch. Next gate:
bykcgty's independent review of this implementation before merge; afterward a
separately scoped real-ledger proof is still needed.

# GD-005 task approval publication and single-use consumption v1

Status: DESIGN FOR INDEPENDENT REVIEW; NO TASK AUTHORIZATION OR EXECUTOR.
Date: 2026-11-03. Source issues: europe-job-scan #65/#68.

## Baseline and scope

- Control main at drafting: dc794787b65b82c5ce4a8948f45da34b699611d6.
- bykcgty accepted write access and independently approved control PR #1.
- Real synthetic proof run 41644210860: both jobs successful; 21 selected checks
  and cleanup passed. Receipt task_execution_authorized=false and
  ejs_source_executed=false. This is selected isolation evidence, not approval
  for any EJS task or a general container escape guarantee.
- Control-main ruleset 26380660 enforces reviews and Actions-source-bound static
  checks with no bypass. Source EJS-main protection remains independently on.
- This change defines publication/consumption semantics only. It creates no
  approval record, ledger branch, GitHub App/token, workflow, dispatch or code.
  GD005-V1 schema validator and advisory router remain unchanged.

## Separate immutable identities

| Symbol | Meaning and independent binding |
| --- | --- |
| S | Exact EJS repository identity + reviewed source commit, never a branch/tag |
| M | SHA-256 of exact bounded UTF-8 proposal bytes; V1 schema must be valid |
| A | Control-main publication commit containing a separately reviewed record |
| R | Previously reviewed control runner/workflow commit and workflow path |
| L | Digest of exact fixed-command allowlist bytes at a reviewed revision |
| I | Digest-pinned approved image and platform, not a mutable tag |
| Q | Approved isolation-profile revision plus its real proof evidence |
| N | Globally unique authorization ID; one use across all runs/platforms |

A record can refer to S/M/R/L/I/Q. It cannot contain its own publication SHA A:
A is resolved independently from protected control-main history after review.
Do not put an approved record inside S or use S's code to authenticate A.
GitHub account-name strings and user-supplied expected SHAs are not provenance.

## Record schema proposal (not accepted by existing V1)

Every field below is mandatory, exact-type, bounded and deny-by-default. No
additional fields, duplicate JSON keys, non-JSON constants or raw task content.
The future parser must have independent tests before it can grant any authority.

| Field | Proposed strict value/meaning |
| --- | --- |
| schema_version | GD005-TASK-APPROVAL-1 |
| authorization_id | Lowercase UUID; immutable, never reused after any disposition |
| source_repository | Exact cagataybuyuk/europe-job-scan |
| source_sha | 40 lowercase hex characters, separately reviewed S |
| proposal_sha256 | 64 lowercase hex characters over exact M bytes |
| task_id | One ID present in reviewed L; no command, URL or arbitrary arguments |
| allowlist_sha256 | Exact L digest |
| runner_repository | Exact cagataybuyuk/ejs-test-control |
| runner_sha / workflow_path | Exact R and reviewed workflow path |
| image_digest / platform | Exact I and reviewed Linux platform |
| isolation_profile_sha256 | Exact Q profile digest; evidence binds R/I/platform |
| environment / payload_class | TEST / synthetic_only |
| network / max_retries | denied / integer 0, never bool |
| not_before / expires_at | UTC RFC3339 seconds, no offset ambiguity |
| max_wall_seconds | Integer 1..300 and within task/profile ceiling |
| decision | approved_for_one_offline_test; a claim, not authenticated by parsing |

Do not add approval fields to the V1 proposal. V1 still returns
execution_authorized=false and permitted_actions=(). A new envelope cannot
convert a proposal or synthetic router output into execution permission.
Do not publish even a structurally valid sample under an authority namespace.

## Publication verification on the trusted control side

1. Resolve this control repository and effective main protection independently
   from bootstrap configuration. Main must remain protected with no bypass,
   review-before-merge, stale-review dismissal, last-push/code-owner approval,
   no force-push/deletion, and checks bound to GitHub Actions.
2. Read a record only from an immutable protected-main publication A under a
   future reviewed authority namespace. Confirm the exact record bytes at A.
3. Verify genuine submitted APPROVED review by bykcgty (or a later independently
   governed successor) on the exact publication PR head and its required checks.
   Match merged PR ancestry to A. A requested review/comment/username in JSON is
   not approval. Any post-review change invalidates the earlier review.
4. Bind the record to S/M/R/L/I/Q and current safety policy. The source task may
   read its proposal but cannot authenticate or replace these trust inputs.
5. Enforce approved lifetime using the trusted control clock, checked against
   authenticated GitHub response time with bounded skew (candidate ceiling 30s).
   Effective start is at least the actual review/merge time. Proposed TTL ceiling
   is 1 hour; expiry must still be valid at claim and immediately before spawn.
   Missing time evidence, skew, unavailable API or expired record means DENY.
6. Verify the real isolation proof applies to this exact R/I/profile/platform.
   Changes require new proof. Proof-code PASS is not blanket coverage of future
   runner code; approved runner identity may not be invented before it exists.

Source code, dependencies and install hooks never run on the trusted online
control host. Only inert data is prepared there. Credentials stay outside the
container. No provider switch can replace S/R/I or relax TEST/network limits.

## One authoritative transactional ledger

A future ledger must serialize **revocation and consumption in the same state**.
A revoked file on one branch plus a consumed tag elsewhere is not atomic and is
not acceptable. Separate read-then-write checks permit races.

Concrete candidate: a dedicated control-ledger Git branch, with every state
commit derived from one observed parent H. A claim publishes a child C whose
parent is H, using non-force ref update. A concurrent writer advancing H makes
the competing sibling update fail, rather than silently overwriting state.
A trusted ledger writer must validate exactly one parent, complete state and
expected H before requesting the update. A stale write is never forced.

This candidate is NOT implemented or proven by this document. Before selection
it needs real race tests, write-permission constraints and lifecycle evidence.
No ledger branch or writer credential is provisioned here. If GitHub semantics
or permissions cannot satisfy the tests, use an independently reviewed atomic
compare-and-set store; never downgrade to a best-effort log.

### Required transaction semantics

- Register: only a verified immutable publication A may introduce N as available.
- Claim: within one state transition, verify N/A/digests, current unrevoked state
  and conservative validity; write consumed/burned with trusted run identity.
- Revoke: updates the same authoritative state. If revocation commits before
  the claim, claim cannot succeed. If claim wins, a later revoke is cancellation
  of an already admitted attempt; never claim it retroactively prevented spawn.
- Only confirmed successful atomic ref update admits one attempt. A timeout,
  lost response or ambiguous write means NO SPAWN, even if N was burned. Do not
  infer this process owns a claim merely by finding the same A/N later.
- Immediately before spawn, reread cancellation/current policy and lifetime;
  stop on deny or uncertainty. Define and record the admission linearization
  point. This design does not promise zero-latency revocation after admission.
- On crash, timeout, abort, partial evidence or failed task, N stays burned.
  No automatic retry/resume. A replacement needs a new N and independent review.
- Completion evidence is append-only and cannot make N available again.
  A PASS log is not ledger authority; an absent receipt is not permission to retry.

The ledger writer is a trusted component, not the sandbox process or arbitrary
PR workflow. Use separate least-privilege credentials outside all task containers.
Ordinary target/source tokens cannot update this ledger or approval publication.
Main remains zero-bypass. Ledger-specific restrictions must separately prevent
force-push/deletion/history rewrite, even for its authorized writer. Main's
review requirements must not be weakened to make an automated claim work.

## State and outcome distinctions

| Starting state/event | Required result |
| --- | --- |
| Unpublished / review pending / schema-valid only | DENY, no registration or spawn |
| Verified published N + valid bindings + no revocation | Eligible for one atomic claim, not automatically run |
| Available N + first confirmed claim | Consumed; at most one admitted attempt |
| Two concurrent claims | At most one success; loser never spawns |
| Revocation commits first | Claim denied |
| Claim commits first, then revocation | Burned plus cancellation; stop before spawn if observed, otherwise terminate bounded attempt |
| API uncertainty, expiry, policy drift or sandbox failure | DENY/REVIEW; no new execution |
| Consumed N + any replay / different platform / workflow rerun | DENY |
| Crash after claim but before spawn | Burned; no replay |
| Successful task + valid bounded receipt | PASS evidence only, no new authority |

Receipts must bind N/A/S/M/R/L/I/Q, ledger parent/new revision and run identity,
start/end times, actual exit/timeout/cleanup result and bounded evidence digest.
No credential, raw browser/profile data, unreviewed stdout or user content.
Ledger publication and evidence are not business-state Sheets operations.

## Initial scope and rollout gates

Start with candidate task secret_scan only, before considering pytest_core or
authority_boundaries. A reviewed catalog would map it to a fixed argv such as
python -I -B /reviewed/scripts/ci/secret_scan.py inside the already-proven profile.
This is a proposal, not an invocation. Even a fixed Python script is executable
code and needs exact-source review and isolation. No arbitrary shell, path,
pytest flag, dependency install, browser, URL, secrets or dynamic task payload.

Sequential separate changes:

1. Independent review of this publication/ledger contract.
2. Pure envelope + state-transition model and deny-path tests, always non-
   authorizing, no filesystem/network/process/provider I/O. Explicitly distinguish
   model tests from real atomicity and actual authenticated provenance.
3. Select/prove the real ledger + credentials and publication path, including
   two-claim/revoke races, ambiguous network responses, replay and audit recovery.
4. Separate runner implementation/review bound to proven isolation; no existing
   proof can be assumed to cover changed code. Only then publish one short-lived
   independently reviewed TEST authorization for a bounded canary.

No automatic task execution is authorized by this contract or its merge. No
release, deployment, ATS/browser/auth, upload/submit, PROD/TEST data mutation,
paid service, self-hosted runner or Mac software installation is included.

## Resource checkpoint and next action

EJS priority 1; bounded Codex architecture task, OPENAI_AGENT_SHARED.
Remaining/reset Unknown. Artifact: documentation-only contract. Stop before
any authorization record, ledger write, credential, executor or dispatch.
Next external gate: bykcgty's genuine review of this exact contract head.

References:
- https://github.com/cagataybuyuk/europe-job-scan/issues/68
- https://github.com/cagataybuyuk/ejs-test-control/actions/runs/41644210860
- https://docs.google.com/document/d/1LppXUfKPa0-w6c2Q21VMgYtQ1_ZXxQ8Pl0ByvuvsesI/edit

## Local Git proof addendum — 2026-11-03 (independent review required)

See [the disposable fixture evidence](LOCAL_GIT_LEDGER_PROOF.md). Actual local
push tests show that an identical replay can return success/up-to-date, and a
semantically illegal state revival can still be a graph-valid fast-forward.
Future writes therefore need a trusted predecessor/transition validator and a
unique control-generated claim-attempt nonce, not merely a successful write
response or a source/run identifier. No code/backend/record is activated by
this addendum. Local expected-old update-ref behavior must not be substituted
for unproven GitHub API semantics or permissions.

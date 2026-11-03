# GD-005 disposable local Git ledger proof

Date: 2026-11-03. Scope: tests only, no operational ledger or task authority.
Base: independently reviewed control PR #3 merged as
7615a2a26557318299f363a6ce275202a9ddab10; post-merge control-static SUCCESS.

The pure model is now accompanied by seven tests that invoke actual Git against
fresh temporary bare repositories using synthetic JSON. Source/host worktrees,
GitHub repositories and real approval records are never targets. File protocol
is explicitly allowed; other protocols disabled. Global/system Git config and
hooks are excluded, credential environments are not inherited, and subprocess
calls use fixed argument vectors with timeouts. Temporary repositories are
removed by test cleanup. There is no production helper imported by a runner.

## Observations from actual local Git operations

| Probe | Observed local behavior |
| --- | --- |
| Two distinct sibling claim commits from one parent, push calls started together | Exactly one push succeeded; head matched the winner |
| Revoke committed before a stale claim | Stale sibling claim rejected; revoked state preserved |
| Claim committed before revoke | Old-parent revoke rejected; fresh child could preserve consumed state and mark cancellation |
| Identical claim commit pushed twice | Both commands returned success; second said up to date, not a fresh claim |
| Forced rewind and deletion | Rejected by this fixture server's denyNonFastForwards/denyDeletes configuration |
| Semantically illegal revival in a new fast-forward child | Git ACCEPTED it: graph rules alone do not validate ledger state |
| Local update-ref with expected-old SHA | Stale expected parent rejected; winner head preserved |

The revival test intentionally demonstrates a remaining security gap in a
Git-only backend. Its unittest success means the unsafe behavior was observed
and documented, NOT that revival protection exists in Git. The fixture is
synthetic, contains no authorization and cannot trigger execution.

## Required backend follow-up

1. Treat a successful status/exit alone as insufficient admission evidence.
   Never retry a claim after an ambiguous/lost response. A replay already in
   consumed state cannot be resumed merely because the API returns success.
2. Future trusted claim writes need a unique control-generated attempt nonce,
   in addition to authorization ID and run/attempt. Distinct claim contenders
   must construct distinct child commits even for duplicated driver/run metadata.
   No nonce or ledger implementation is created here.
3. The trusted writer must validate full predecessor state and permitted
   monotonic transition before a write; it must be the only permitted writer.
   Preventing non-fast-forward changes does not prevent a malicious or buggy
   fast-forward state revival. Separate approval/publication credentials from
   task containers and ordinary PR workflows.
4. Actual GitHub PATCH refs does not expose local update-ref's expected-old
   parameter. Its non-force fast-forward semantics, idempotent responses and
   concurrent update behavior must be tested independently against an expressly
   approved disposable remote fixture. These local tests do not prove them.
5. Real GitHub writer permissions, protected ledger namespace, revocation/claim
   races, API uncertainty, expiry and recovery remain UNPROVEN. Do not create an
   operational ledger or executor on the strength of this result.

## Evidence and reproducibility

```sh
python3.12 -I -m unittest discover -s tests -v
```

Local result: 30 unittest methods passed (seven new real local Git fixture
methods, 15 pure model methods and eight existing control methods). Source
HEAD/remote results are recorded on the associated review PR. No new workflow
or container dispatch is required; existing control-static discovers the tests.

Independent reviewer: bykcgty. Resource scope: EJS priority 1, bounded Codex
review with deterministic local Git/Python; OPENAI_AGENT_SHARED remaining/reset
Unknown. Stop before GitHub test-ref mutations, credentials, an operational
ledger, actual task admission or process execution of EJS code.

Next single action after review: design the disposable GitHub API/permission
fixture with fixed synthetic data and narrowly scoped credentials. Do not
mistake this test file for a real ledger adapter or proof of authorization.

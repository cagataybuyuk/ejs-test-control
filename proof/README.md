# Synthetic isolation proof — awaiting independent review

This is not an EJS task runner. It accepts no task/manifest/command input,
checks out no EJS code, and publishes no task authorization. The only payloads
are fixed synthetic control-store scripts. V1 validation semantics are untouched.

The repository owner authorized preparation of this separate control repository
and named `bykcgty` as independent reviewer. Main is protected by ruleset
26380660: no bypass, no force-push/deletion, mandatory code-owner/last-push
review, one approval and Actions-source-bound `control-static` check. Bootstrap
commit `9988a31` contains documentation/CODEOWNERS only, no executable workflow.
bykcgty's collaborator invitation was pending at initial readback; independent
review has not happened merely because the invitation exists.

## Execution sequence

1. PR runs only offline Python contract/configuration tests (`control-static`).
2. bykcgty accepts the repository invitation and reviews the exact proof PR head.
   Do not merge using a bypass or fake approval. Changes dismiss stale reviews.
3. After genuinely reviewed merge, a separate manual workflow_dispatch on
   protected main can run the fixed synthetic-isolation job. It has no inputs,
   no inherited secrets, read-only token permissions and no stored credentials.
   Rerun attempts are rejected; a fresh manual run gets a fresh identity.
4. Only then read actual probe receipt and cleanup result; no green static check
   establishes container isolation. A failing/incomplete proof stays FAIL.
5. Trusted task-record publication and any EJS task executor remain separate
   later reviewed work. Passing this proof does not authorize EJS tasks.

## Fixed boundary

Standard public GitHub-hosted `ubuntu-24.04` only; no larger/self-hosted runner,
cache, uploaded artifact, paid API, new billing or external account key. GitHub
standard public compute is free under current official policy; provider limits
still apply. Logs contain bounded synthetic technical evidence only.

Image: Docker Official Python 3.12 slim-bookworm, Linux amd64 manifest pinned to
`sha256:623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487`,
resolved from the official registry on 2026-11-02. Review this exact image before
merge. Mutable tags are never runtime inputs. Network-enabled image preparation
occurs before isolation, not inside the offline proof.

The fixed TCP fixture container listens only within the ephemeral runner's
Docker bridge; no ports are published. Its readiness is verified before the
network-denied probe attempts to reach it. No employer/public-service address
is a test target. IPv6 TEST-NET address is unroutable by design; host-side
NetworkMode=none and in-container loopback-only checks provide separate evidence.
No public DNS query is sent; DNS resolution on external networks is structurally
excluded by the none namespace. This does not claim a separate DNS server test.

Probe: UID/GID 65532, read-only root/source, zero capabilities, no-new-privileges,
default seccomp filter, 128 MiB memory with swap disabled, 0.5 CPU, 32 PIDs,
16 MiB noexec/nosuid/nodev temporary space, no host socket/home/profile/credential
mount. Host configuration and in-container limits are checked independently.
A second bounded container with one sleeping child is forcibly stopped after
three seconds and its namespace is verified stopped (PID 0). Cleanup targets
only this run's three fixed container names; an always-step repeats cleanup.

This proves selected settings and bounded synthetic behavior, not resistance
to every kernel/container escape. No exploit, real secret, host-user directory
or unbounded fork/memory stress is part of the test. No Docker install is made
on the Mac. Actual runtime configuration and tests remain unobserved until the
manual post-review run, so compatibility issues may still surface.

## Local no-container check

```sh
python3.12 -I -m unittest discover -s tests -v
```

Tests exercise missing/untrusted contexts, arbitrary command rejection,
no-shell subprocess invocation, runtime configuration failures and PR-workflow
separation. They do not launch Docker or authenticate tasks. Tests pass even
when Docker is unavailable; that means contract tests only, not isolation PASS.

## Checkpoint / scope

User decision: separate control store + bykcgty, 2026-11-02. GD-005 append records
this decision. Resource pool: OPENAI_AGENT_SHARED, EJS priority 1; remaining/reset
Unknown. Preparation and local checks only; actual task execution stays blocked.
Next action: bykcgty's genuine independent code-owner review of the proof PR.

References:
- https://github.com/cagataybuyuk/europe-job-scan/issues/68
- https://github.com/cagataybuyuk/europe-job-scan/pull/69
- https://docs.github.com/en/actions/concepts/billing-and-usage
- https://docs.docker.com/reference/cli/docker/container/run/

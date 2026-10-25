# Spine A — GitHub-based agentic implementation pilot (W1-2)

One Pod, one repository, two engines, one blueprint. A human writes a Task Envelope as an
issue, applies an engine label, and an agentic run opens a draft pull request that a human
reviews and merges. Every gate between those two humans is deterministic.

This directory is a **copy-in overlay**, installed in two parts. Copy `spine-github/` into the
pilot repository **as a directory** — every workflow calls its scripts as
`spine-github/scripts/...` — and then move three things to the repository root:
`.github/` (workflows, issue form, action-pin cache), `AGENTS.md` and `.gitattributes`.
`../docs/first-run-ja.md` does exactly this, step by step, and was executed end to end against a
scratch repository. Placeholders to fill are listed in `../PLACEHOLDERS.md`.

Offline checks: `gh aw compile --strict` passes on the three gh-aw workflows (the Codex
nodes, gh-aw v0.88.8), `spine-github/tests/run.sh` passes 147/147 (it also runs spine-linear's suites), and `scripts/metrics.sh`
runs against a live repository and against offline fixtures.

**Claude runs on a Claude subscription, not the API.** Every Claude node — implement, fix
CI, AI review, address review — is a plain Actions workflow (`claude-*.yml`) with the same
two jobs. The `agent` job runs Claude Code authenticated with `CLAUDE_CODE_OAUTH_TOKEN` (from
`claude setup-token`) inside the Agent Workflow Firewall (`awf`, `github/gh-aw-firewall`),
which allows only `api.anthropic.com`. The container gets no GitHub token at all, so what the
agent must read — the envelope, the PR diff, a failed CI log, the open review threads — is
put on disk before it starts, and what it produces is a patch or a JSON file. The `publish`
job trusts nothing from the agent job but that output: it re-reads the PR and the envelope
from GitHub, refuses a patch unless `scripts/check_patch.py` passes (protected paths,
`allowed_paths`, file-count limit), and validates review and reply JSON with
`scripts/agent_outputs.py` before posting it. Codex still runs on gh-aw with an API key.

**Built to run around the clock.** A Claude run that fails on the subscription's usage limit
(or a rate limit, or an overloaded API) is parked with `agent:waiting-quota` and a hidden
`claude-requeue` marker instead of `needs-human`; `claude-requeue.yml` retries it hourly for
up to 48 hours after the first failure (at most 48 times), then hands it to a human. GitHub starts scheduled runs late — measured on
2026-09-27, cron runs began 4.6 to 5.6 hours after their time — so expect the first retry
hours after the limit hit, about when a 5-hour usage window resets anyway. Any other failure puts `needs-human` and a run link on
the issue or PR, so nothing fails silently at night. Every dispatch-driven workflow refuses
any ref but the default branch, checks out the default branch's scripts, and accepts only the
round the PR records, so a token that can dispatch workflows cannot buy extra rounds or run
unreviewed code.

## 0. Decisions — fixed, not reopened here

1. **The Task Envelope is the unit of work.** `schemas/task-envelope.schema.json` is its
   only definition. T3 additionally requires an explicit design-note URL and at least one
   `allowed_paths` entry; a T3 task without a written design note is a design task.
2. **One blueprint, `implement-v1`,** with the node sequence in section 4. The CI-fix loop
   is capped at 2 agentic rounds.
3. **The pull request carries an `agent-envelope` block.** Its field names are a contract
   because `scripts/metrics.sh` parses them.
4. **Labels are `agent:<engine>`, `risk:T1|T2|T3`, `blueprint:<id>`.**
5. **Review is tiered** (section 6). T3 runs in the background only from W7, and only with
   all six T3 conditions met.
6. **Two engines, Claude Code and Codex, selectable per task from day one.**
7. **Security floor.** The agent runs with a read-only repository token; every write leaves
   through a mediated channel; no production secrets; egress allowlist; feature branches
   only; human review before merge; the agent identity cannot approve.
8. **Metrics are per engine:** PR count, merge rate, first-CI-pass, median hours to merge,
   rework within 7 days, cost per merged PR.

Where the evidence for a design choice is external, `docs/ghaw-field-reference.md` names
the field and the source. Where a contract could not be honoured natively, the gap and its
mediation are stated in the same place — never silently dropped.

## 1. What ships in W1-2

| File | Node | Kind |
|---|---|---|
| `.github/ISSUE_TEMPLATE/agent-task.yml` | front door | issue form |
| `schemas/task-envelope.schema.json` | the contract | JSON Schema |
| `scripts/envelope_from_issue.py` | `[D]` validate, hydrate, emit | parser + validator |
| `.github/workflows/envelope-validate.yml` | `[D]` validate (authoring loop) | Actions |
| `.github/workflows/claude-implement.yml` + `scripts/run_claude_sandboxed.sh` + `scripts/check_patch.py` + `prompts/implement.md` | `[A]` implement, Claude | Actions + awf, Claude subscription |
| `scripts/import_verify.py` (run by `claude-implement.yml`'s `publish`) | `[D]` L4 import: copy pinned files of another repository by (mode, OID), no agent | Actions, on for an envelope with `Import from` |
| `scripts/protected_paths.py` + each repository's `.github/agent-protected.txt` | `[D]` the protected lists `check_patch.py`, `import_verify.py` and `pr_guard.py` share | data |
| `scripts/pr_context.sh` + `scripts/review_threads.sh` + `scripts/agent_outputs.py` | `[D]` what the Claude PR nodes read, and the check on what they write | shared by the three Claude W3 workflows |
| `.github/workflows/agent-implement-codex.md` | `[A]` implement | gh-aw |
| `scripts/pr_guard.py` + `.github/workflows/envelope-guard.yml` | `[D]` merge gate | required check |
| `rulesets/main-protection.json` | `[H]` review gate | branch ruleset |
| `AGENTS.md` | `[D]` hydrate index | repo instructions |
| `scripts/metrics.sh` | measurement | reporting |
| `scripts/bump_rounds.py` + `.github/workflows/ci-dispatch.yml` | `[D]` route CI result: fix or review | **W3, inert** |
| `.github/workflows/claude-fix-ci.yml` + `prompts/fix-ci.md`; Codex: `agent-fix-ci-codex.md` | `[A]` fix CI | **W3, inert** |
| `.github/workflows/claude-review.yml` + `prompts/review.md` + `scripts/route_review.py` | `[D]` AI review and its routing | **W3, inert** |
| `.github/workflows/claude-address-review.yml` + `prompts/address-review.md`; Codex: `agent-address-review-codex.md` | `[A]` address review | **W3, inert** |
| `.github/workflows/claude-requeue.yml` + `scripts/classify_failure.py` + `scripts/requeue.py` | retry a Claude node after a usage or rate limit | on at install — it acts only on items labelled `agent:waiting-quota` |
| `scripts/detect_rework.py` + `.github/workflows/rework-detect.yml` | `[D]` apply the `rework` label | on at install — it only labels, never runs an agent |

Both W3 loops are complete and each is switched off by its own repository variable, left
unset: `W3_CI_FIX_ENABLED` for the CI-fix loop, `W3_AI_REVIEW_ENABLED` for the review loop.
In each loop the deterministic half decides and counts and the agentic half acts. Arming
needs `CI_WORKFLOW_NAME` filled in `ci-dispatch.yml`, the `needs-human` and `ai-reviewed`
labels, and then the variable for the loop you want.

## 2. How a task flows

1. A human opens an issue with the **Agent task** form. Nothing runs.
2. `envelope-validate` parses it, validates it against the schema, writes the canonical
   envelope JSON into the issue body, and labels the issue `envelope:valid` or
   `envelope:invalid` with the error list as a comment. This is the authoring loop.
3. A human applies `agent:claude` or `agent:codex`. **That label is the trigger and the
   authorization.** `on.roles` restricts it to admin / maintainer / write.
4. The agentic run executes the blueprint and opens a draft pull request.
5. `envelope-guard` regenerates the PR's envelope block from the issue (plus a
   `Fixes <Linear ID>` section when the issue mirrors a Linear task), applies the risk
   and blueprint labels, and then grades the result as a required check.
6. A human reviews at the tier the risk label names, and merges.

A human applies the engine label rather than the validation workflow doing it, because
events created with `GITHUB_TOKEN` do not start new workflow runs — `workflow_dispatch` and
`repository_dispatch` are the documented exceptions. A label applied by CI would not reach
the agent workflow at all. Making the trigger a deliberate human act is the better reading
of the same constraint.

## 3. Setup checklist

1. Copy this overlay into the pilot repository and fill `../PLACEHOLDERS.md`.
2. Create the labels: `agent-task`, `envelope:valid`, `envelope:invalid`, `agent:claude`,
   `agent:codex`, `risk:T1`, `risk:T2`, `risk:T3`, `blueprint:implement-v1`, `rework`,
   `needs-human` (a failed Claude run puts it on the issue, and the W3 loops on the PR), and
   `agent:waiting-quota` (a run parked until the usage limit resets).
   `add-labels` and `gh pr edit` do not create labels that do not exist.
3. Add the engine secrets: `CLAUDE_CODE_OAUTH_TOKEN` for Claude (run `claude setup-token`
   on your machine; it is tied to that person's Claude subscription and draws on its usage
   limits), `OPENAI_API_KEY` (and `CODEX_API_KEY` where the runner expects it) for Codex. `gh aw`
   tracks these in the compiled lock file's manifest and demands `--approve` plus a written
   security-review note when the set changes — see `docs/security-review-note.md`.
4. Give the Claude nodes an identity other than `GITHUB_TOKEN`: GitHub holds every
   `pull_request` run on a PR opened with `GITHUB_TOKEN` for manual approval, and a push made
   with `GITHUB_TOKEN` starts no workflow at all — either way the required checks never report
   and the PR cannot merge. Preferred: a GitHub App per repository (Contents, Pull requests and
   Issues read/write, nothing else) with the variables `AGENT_APP_CLIENT_ID`, `AGENT_APP_SLUG`,
   `AGENT_APP_BOT_ID` and the secret `AGENT_APP_PRIVATE_KEY`; the publish jobs and
   claude-requeue mint a one-permission token from it. Without the App they fall back to
   `GH_AW_CI_TRIGGER_TOKEN`, a fine-grained PAT (Contents and Pull requests read/write on this
   repository), and with neither they fail rather than use `GITHUB_TOKEN`. The Codex nodes
   always use `GH_AW_CI_TRIGGER_TOKEN` for gh-aw's extra empty commit. Set
   `TRUSTED_ISSUE_AUTHOR_IDS` too (see `../PLACEHOLDERS.md`): while it is unset no run starts.
5. Apply the ruleset: `gh api -X POST repos/OWNER/REPO/rulesets --input rulesets/main-protection.json`.
6. Compile and commit the lock files: `gh aw compile --strict`. Both the `.md` and the
   generated `.lock.yml` are committed; `.gitattributes` marks the lock files as generated.
7. Dry-run the chain on a throwaway T1 task before letting the Pod near it.
8. Leave `W3_CI_FIX_ENABLED` and `W3_AI_REVIEW_ENABLED` unset. Both W3 loops are built but
   must not be armed before a T1 task has gone end to end by hand.

## 4. Node map — blueprint `implement-v1`

| # | Node | Kind | Where it runs | What it enforces |
|---|---|---|---|---|
| 1 | validate | `[D]` | first step of the agent job (Codex: gh-aw `pre-agent-steps`), and `envelope-validate.yml` for authoring | schema, including the T3 rules. Fails closed |
| 2 | hydrate | `[D]` | same | `envelope.json` on disk; `AGENTS.md` must exist |
| 3 | implement | `[A]` | agent job, read-only token | one focused patch inside `allowed_paths` |
| 4 | lint | `[D]` | agent job, after the agent (Codex: `post-steps`) | `make lint` when the repo has one |
| 5 | affected tests | `[D]` | same | the envelope's `test_command` |
| 6 | draft PR + labels | `[D]` | `publish` job (Codex: `safe-outputs` job) | draft, `agent:<engine>`, `blueprint:<id>`; protected paths refused (`check_patch.py` / `protected-files: blocked`) |
| 7 | CI | `[D]` | the repo's own CI | the pilot repo's existing checks |
| 8 | fix CI | `[A]` | W3, inert | at most 2 rounds. `ci-dispatch.yml` counts and decides; `bump_rounds.py` is the only thing that increments, and it refuses to exceed the blueprint constant |
| 9 | AI review | `[D]` | W3, inert | once per PR after CI goes green (`ai-reviewed` label is the key). Always Claude. The review can only `COMMENT` — the publish job hard-codes the event, so approve and request-changes do not exist at the write boundary. `route_review.py` counts the inline comments actually posted and decides |
| 10 | address review | `[A]` | W3, inert | at most 1 round, by the engine that implemented the PR. Fixes inside `allowed_paths`, replies to every thread, resolves only what it fixed |
| 11 | human review | `[H]` | GitHub | tier from section 6 |

Nodes 4 and 5 run **before** the pull request exists, so a patch that fails its own tests
produces a failed run and no PR. For Codex, gh-aw's `report-failed-jobs` (default on) surfaces
that as an issue; for Claude the failed run in the Actions tab is the signal. In the Claude
CI-fix and address nodes a failed run labels the PR `needs-human`, so a failed round never
leaves a PR waiting on nothing.

## 5. PR contract

The pull request body carries exactly one block:

````
<!-- agent-envelope:v1 -->
```yaml
envelope_version: 1
task_id: gh-101
blueprint: implement-v1
engine: claude
risk_tier: T2
profile: settlement
test_command: make test-affected
max_ci_fix_rounds: 2
ci_fix_rounds: 0
ai_review_rounds: 0
```
<!-- /agent-envelope -->
````

Three properties matter more than the exact layout:

- **It is generated, not typed.** The `sync` job in `envelope-guard.yml` renders it from the
  canonical envelope on the source issue. An agent that mistyped `risk_tier` would corrupt
  the metric the pilot exists to produce.
- **The counters survive a push.** `ci_fix_rounds` and `ai_review_rounds` are carried
  forward on every regeneration. Resetting them would make the round caps unenforceable and
  would report first-CI-pass as 100%.
- **`allowed_paths` in the block is binding.** `pr_guard.py` compares it against the real
  changed-file list. gh-aw's own `allowed-files` accepts a static array only, so for Codex a
  per-task path restriction cannot live in the runner; for Claude `check_patch.py` also
  enforces it before publishing. Either way the required check is the gate that counts.

## 6. Review tiers

| Tier | What it covers | Review | Background running |
|---|---|---|---|
| T1 | mechanical, reversible, no contract touched | one reviewer, diff only | from W1 |
| T2 | ordinary change inside one service | one reviewer, diff plus acceptance criteria | from W3 |
| T3 | contract, privilege boundary, data, or money | two reviewers, one of them the area owner, against the design note | **from W7 only, and only with all six T3 conditions met** |

The tiering is exception-based on purpose: the Stanford study of 51 enterprise deployments
found exception-based oversight sustained at 71% versus 30% for approve-everything. The
point of tiers is that T1 review does not consume the attention T3 needs.

**The six T3 background-running conditions, ratified 2026-09-23.** The original W1-2 bundle
enumerated a set that was not recoverable; these six were proposed as its replacement and
ratified by the Pod lead on 2026-09-23. They are the decided set. All six must hold before a
T3 task runs in the background, and that is a W7-or-later question in any case:

1. The task has a written design note, linked as `source_url`, authored by a human.
2. `allowed_paths` names no file that is part of a published contract, a privilege boundary,
   or a data migration.
3. The area owner has reviewed at least one T2 pull request from the same engine in the
   preceding two weeks.
4. The rollback in the envelope is a single reversible action, and has been executed once in
   a rehearsal.
5. The preceding four weeks show no T2 rework within 7 days for this engine in this profile.
6. A named human is on call for the merge window and has acknowledged the task.

Until W7, T3 runs in the foreground with a human watching regardless of these conditions.
Conditions 3 and 5 are backward-looking, so the clock on them starts now: the pilot has to
accumulate T2 history before any T3 task can qualify.

## 7. Metrics

`scripts/metrics.sh <OWNER/REPO> [--since YYYY-MM-DD] [--cost-file costs.json]` emits the
six metrics per engine, derived from data that already exists on the PR.

| Metric | Derivation | Honest caveat |
|---|---|---|
| PR count | PRs labelled `agent:<engine>` | — |
| merge rate | merged ÷ all | — |
| first-CI-pass | merged with `ci_fix_rounds: 0` ÷ merged with a counter | the denominator excludes PRs whose body predates the block; the script reports `envelope_block_missing` so you can see it |
| median hours to merge | `mergedAt − createdAt` | wall-clock, so it measures reviewer availability as much as agent quality |
| rework within 7 days | merged PRs carrying a `rework` label ÷ merged | `rework-detect.yml` applies the label, and only on two explicit signals: a revert (GitHub's `Reverts owner/repo#N`, or git's `This reverts commit <sha>`) or a declared `Reworks #N`, merged within 168 hours of the agent PR. A quiet fix in an unrelated PR is not counted, so read this as a **lower bound** |
| cost per merged PR | `--cost-file` ÷ merged | Claude runs on a subscription, so it has no per-run charge; its cost is the subscription itself plus Actions minutes, and the column stays `no-cost-source` for Claude. For Codex, without a cost file the column reads `no-cost-source` rather than guessing. `gh aw logs` reports per-run token usage and AI Credits and is the intended producer; `gh aw forecast` projects future spend, `gh aw health` gives success rates |

The AI reviewer is always Claude, so PRs Claude implemented get a self-review and PRs Codex
implemented get a cross-review. Read any per-engine difference in rework or merge rate next to
that asymmetry, as with the Codex bash asymmetry.

Anthropic's 2026 trend reporting puts full delegation at 0-20% of coding tasks today. That
is the baseline the delegation ratio is read against — a pilot landing inside it has not
failed.

## 8. Fallback

The pilot has three stop levels, in increasing order of bluntness:

1. **Stop new runs.** Remove the `agent:claude` / `agent:codex` labels from the repository,
   or `gh workflow disable claude-implement.yml` and `gh aw disable agent-implement-codex`,
   unset `W3_CI_FIX_ENABLED` / `W3_AI_REVIEW_ENABLED`, and `gh workflow disable claude-requeue.yml`.
   In-flight runs finish; nothing new starts. The labels, the two variables and the requeue
   schedule are the only triggers, so this is complete.
2. **Stop merges.** `guard` is already a required check, so nothing lands without it. To
   hold the queue as well, tighten the ruleset — raise `required_approving_review_count`, or
   add a `required_status_checks` context no agent PR can satisfy — and the open agent PRs
   stay open until humans catch up.
3. **Remove the surface.** Delete the five `claude-*.yml` workflows, the three gh-aw `.md`
   agent workflows and their `.lock.yml` files. The envelope schema, the validator, the guard
   and the metrics survive as plain CI, so the deterministic half of the pipeline keeps
   working with human-authored PRs.

Cost containment is separate from the stop levels and always on. Claude: `--max-turns` (30
implement, 15 CI fix, 20 review and address), an agent timeout enforced by awf (20, 15, 15
and 20 minutes), a job timeout on every job, the subscription's own usage limits, and retries of
a run parked on those limits for at most 48 hours (and 48 attempts) (each failed retry costs about 2 Actions
minutes). Codex
(gh-aw): `max-ai-credits: 1000` per implement run (500 in the CI-fix and address nodes),
`timeout-minutes: 20`, engine `max-turns: 30`, and `expires: 7` so an unattended agent PR
closes itself after a week.

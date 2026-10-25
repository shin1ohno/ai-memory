# Security review note — gh-aw safe-update approval

`gh aw compile` runs in safe-update mode and refuses to approve new restricted secrets or
action changes silently. It asks the compiling agent to write this note. Paste the current
version into the pull request description that introduces or changes the agentic workflows.

Compiled with gh-aw v0.88.8, strict mode, on 2026-09-27. gh-aw now compiles only the three
Codex workflows; every Claude node is a plain Actions workflow and is covered by the last
section below.

## New restricted secrets

| Secret | Introduced by | Why it is needed | Why it is safe here |
|---|---|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | `claude-implement.yml`, `claude-fix-ci.yml`, `claude-review.yml`, `claude-address-review.yml` | Claude subscription token from `claude setup-token` | Passed to the sandbox through a mode-600 env file outside the workspace, never on a command line; the sandbox allows only `api.anthropic.com` and holds no GitHub token, so the token cannot be sent anywhere else. It is tied to the issuing person's subscription: rotate it when that person leaves the pilot |
| `OPENAI_API_KEY` | `agent-implement-codex.md`, `agent-fix-ci-codex.md`, `agent-address-review-codex.md` | Model credential for the Codex engine | Read by the engine step only. The agent job's `GITHUB_TOKEN` is read-only and every write leaves through the separate safe-outputs job, so a compromised run cannot use this key to reach the repository. Egress is restricted to `network.allowed` (`defaults`), so the key cannot be posted to an arbitrary host |
| `CODEX_API_KEY` | `agent-implement-codex.md`, `agent-fix-ci-codex.md`, `agent-address-review-codex.md` | The Codex engine's alternate credential name, emitted by the compiler's secret-validation step | Same containment as above. Set whichever one the engine actually expects; the other can be left unset |
| `AGENT_APP_PRIVATE_KEY` | `claude-implement.yml`, `claude-fix-ci.yml`, `claude-address-review.yml` (their `publish` jobs) and `claude-requeue.yml` | The factory App's key: the Claude nodes open PRs, push fixes and re-label requeued issues as the App rather than as a person or `GITHUB_TOKEN` | Read only by the token-minting step, which runs after the patch is graded and asks for one permission on this repository. The App itself holds Contents, Pull requests and Issues write and nothing else — no Workflows, Administration, Variables or Secrets — so a leaked token can neither rewrite a workflow, nor change a ruleset, nor touch the variables (`AGENT_APP_BOT_ID`, `TRUSTED_ISSUE_AUTHOR_IDS`) the start rules depend on. The sandbox keeps this as a repository secret (environment secrets need a public repository on the Free plan); the sandbox's App is installed on the sandbox only |
| `GH_AW_CI_TRIGGER_TOKEN` | `create-pull-request.github-token-for-extra-empty-commit` (magic default, Codex), and the Claude nodes' fallback where no App is configured: `claude-implement.yml` (opens and labels the PR), `claude-fix-ci.yml` and `claude-address-review.yml` (push to the PR branch), `claude-requeue.yml` (re-labels) | Codex: pushes one empty commit after PR creation so `pull_request` workflows start. Claude: opens and labels the PR itself, because a PR opened with `GITHUB_TOKEN` has every `pull_request` run held for manual approval and labels added with `GITHUB_TOKEN` raise no event for envelope-guard's sync job, and pushes the CI-fix and address commits, because a push made with `GITHUB_TOKEN` starts no CI run. Used only in `publish` jobs, never in a job that runs agent code. Needs Contents and Pull requests read/write | **The widest-privileged secret in this set — review it hardest.** Scope it to `contents:write` on the pilot repository only, prefer a GitHub App installation token over a user PAT, and never grant it `workflow` scope: with that scope it could rewrite the very workflows that constrain the agent. **Its owner becomes the "last pusher" of every agent PR** (it pushes the CI-trigger commit), so under `require_last_push_approval` that person can no longer approve those PRs — mint it for a GitHub App or a machine account, never for a reviewer |

## Actions added

| Action | Pin | Note |
|---|---|---|
| `actions/create-github-app-token` | `bcd2ba49218906704ab6c1aa796996da409d3eb1` (v3.2.0) | Mints the factory App's installation token, scoped to this repository and to the least it needs, in four jobs only: implement's `publish` (`pull-requests: write` plus `contents: read`, which `gh pr create` needs to read the default branch; opens and labels the PR), fix-CI's and address's `publish` (`contents: write`, push to the PR branch) and `claude-requeue` (`issues: write`, re-applies `agent:claude`). No `continue-on-error` and no `skip-token-revoke`: a failed mint fails the job, and the post step revokes the token. Enforced by `tests/check_app_token_scope.py` |
| `actions/checkout` | `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` (v5) | Used by the deterministic workflows and the `claude-*.yml` workflows. Strict mode requires SHA pins |
| `actions/upload-artifact` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (v7.0.1) | `claude-*.yml`: carries the agent's output from the `agent` job to the `publish` job |
| `actions/download-artifact` | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` (v8.0.1) | `claude-*.yml`: the `publish` side of the same hand-off |
| `github/gh-aw-actions/setup` | `5e508589e03a7757a7e05b26e834292f5445bfb6` (v0.88.8) | Resolved by the compiler and recorded in `.github/aw/actions-lock.json` |

## What I could not fully verify — flagged for a human reviewer

- Whether the Codex engine consumes `OPENAI_API_KEY`, `CODEX_API_KEY`, or both at runtime.
  The compiler's secret-validation step demands both names; only a live run settles which is
  read. Set both or watch the first run's secret-validation output.
- The blast radius of `GH_AW_CI_TRIGGER_TOKEN` depends on how it is minted, which is an
  operator decision outside this repository. Confirm the scope before the first run.
- `gh aw checks`'s `policy_blocked` state is documented as "policy or account gates blocked
  the PR"; which gates it detects was not traced. It matters only for the W3 CI-fix
  dispatcher, which is not enabled.

## Re-approval

Re-run after any frontmatter change that adds a secret or action:

```bash
gh aw compile -d .github/workflows --strict            # see what changed
gh aw compile -d .github/workflows --strict --approve  # record the approval in the lock files
```

Update this note in the same commit. An approval recorded without a corresponding line here
is the failure mode the mechanism exists to prevent.

## Claude nodes outside gh-aw — the trust boundary

The four `claude-*.yml` workflows replace gh-aw's safe-outputs with their own two jobs, so the
boundary gh-aw drew is restated here.

- **Who may start a run is decided before anything runs.** `claude-implement`'s `admit` job
  (`trust_gate.py admit`) requires a label from a person with write access, or from the
  factory App (exact numeric id `AGENT_APP_BOT_ID`, login `AGENT_APP_SLUG[bot]`) re-applying
  a run that a person with write access had started and claude-requeue parked; the issue's
  author must be in `TRUSTED_ISSUE_AUTHOR_IDS` (github-actions[bot] only for a linear-intake
  mirror); a restart runs only while the body hashes to the value recorded in the
  `agent-approved` marker when the person started it; and no agent PR from this repository may
  be open on the issue (fork PRs are not counted). The values come from repository variables,
  which the App's token cannot change. A refusal is commented on the issue with
  `needs-human`. The W3 nodes and envelope-guard's sync apply the same author rule through
  `pr_context.sh` (`trust_gate.py author`), and envelope-validate skips issues from anyone
  else.
- **The `agent` job is untrusted from the moment the agent starts.** It holds a read-only
  `GITHUB_TOKEN` (and checkouts keep no credentials), the awf container holds only
  `CLAUDE_CODE_OAUTH_TOKEN` and reaches only `api.anthropic.com`, and every step after the
  agent runs code the agent may have written. Nothing those steps produce is trusted.
  `claude-result.json` stays in this job: only its failure classifier reads it.
- **The agent's code runs only in `verify`.** Lint and the envelope's `test_command` run in
  a separate job that references no secret and no environment and has a read-only token: it
  checks out the default branch (or the PR head the agent read), applies the patch and runs
  them. `publish` needs `verify`.
- **The `publish` job trusts only the agent's declared output, and validates it.** It checks
  out the default branch for its scripts, and re-reads everything else from GitHub: the PR,
  its envelope (from the source issue), its diff, and its open review threads
  (`pr_context.sh`, `review_threads.sh`). No check runs code from a patched tree: implement's
  publish copies `spine-github` aside before touching the tree and grades the patch with that
  copy's `grade_patch.sh`, which applies the patch to a throwaway index, lists it with
  `git diff --no-renames --raw` (a rename is its deletion plus its addition, and every entry
  carries its modes and OIDs), and runs `check_patch.py` on that list: no symlink or submodule,
  nothing on the default protected list (`protected_paths.py`, which includes
  `.gitattributes`, `.gitmodules`, `.agent-import/` and `.agent-out/`) or on the base commit's
  `.github/agent-protected.txt`, no addition that collides case-folded with a base path. The
  real `git apply --index` must then produce the very same `--raw` list, byte for byte. Fix-CI and
  address-review do the same: they copy the default branch's `spine-github` aside, check the
  PR head the agent read out under `work/` without credentials, grade the patch there with the
  copy's `grade_patch.sh` (with `.github/agent-protected.txt` read from the default branch
  the PR targets, not from its head), and push only a commit whose `--raw` list matches the
  graded one. The
  grading step has no token in its environment, and the push token reaches only the push
  (`http.extraheader` on that one command; nothing is persisted in `.git/config`).
  envelope-guard checks out the PR's base commit, so the PR under review never supplies the
  code that grades it.
- **`.github/agent-protected.txt` slows the agent down; it is not the boundary.** Each
  repository lists the paths an agent must leave alone (for ai-memory the twelve in
  review-r1.md §2(d), among them the Makefile, because CI runs `make test`). publish reads the
  list from the base commit and refuses any agent patch that touches a path on it, under
  either name of a rename; `AGENT_PROTECTED_REQUIRED=true` refuses every patch where the list
  is missing. envelope-guard repeats the check on the PR (`pulls/<n>/files` with `status` and
  `previous_filename`, the list from the base checkout). That repetition is defence in depth
  for the App's token only: a `pull_request` run takes its workflow definition from the merge
  commit [推測], so it does not hold against a leaked key or a fork. **The boundary is the code
  owner's one approval**, which every merge needs.
- **An L4 import runs no agent.** For an envelope with `Import from`, `claude-implement` skips
  `agent` and `verify`; `publish` runs the default branch's `import_verify.py`, which accepts
  only a repository on `IMPORT_ALLOWED_REPOS` and a `repo@sha` on `IMPORT_PINS`, requires the
  SHA to be an ancestor of the source's default branch (an unmerged PR head or fork commit is
  fetchable through the parent's URL too), and builds the commit from the source's own tree
  entries with `git update-index --cacheinfo` — only regular files, nothing checked out, no
  attribute or filter applied. The index must be exactly the expanded additions, the commit is
  re-read with `ls-tree` and compared by (mode, OID), and the PR body lists one row per file.
  A path on `agent-protected.txt` is importable only when it is new to the base, the pin is on
  `IMPORT_PROTECTED_PINS` and (mode, OID) match (D3); the default protected list and the
  Makefile are never import destinations. admit's four rules, including who wrote the task,
  apply to imports unchanged.
- **Agent-written text passes a tripwire before it is published.** `tripwire.py` refuses a PR
  description, comment, review, reply or added patch line that holds `sk-ant-`, 40 or more hex
  digits, or 40 or more mixed-case base64 characters; the job fails and the item goes to a
  human. It is a detector: the same secret in another encoding passes. A review is turned into a payload whose event is
  hard-coded to `COMMENT`; a reply may only go to a comment that opens an unresolved thread
  the AI reviewer started (`agent_outputs.py`). A patch made against a PR head that has since
  moved is refused.
- **The address node's publish job has `contents: write`** on its `GITHUB_TOKEN`, because
  GitHub refuses `resolveReviewThread` without it. That job checks out only the default
  branch and applies the patch with `git apply`; it runs none of the agent's code.
- **Only the agent's own PRs are written to.** The CI-fix and address nodes refuse any PR
  whose head branch `claude-implement.yml` did not create (`agent/gh-<issue>-<run>`), any
  fork, and any PR the envelope says Codex implemented.

- **A dispatch token cannot buy extra work.** Every dispatch-driven workflow (the Claude W3
  nodes, `claude-requeue` and the Codex W3 nodes) refuses any ref but the default branch and
  checks out the default branch's scripts; CI-fix and address rounds must equal the round the
  PR records; `claude-review` refuses a PR that already has an AI review; `claude-implement`
  refuses a closed issue or one with an open agent PR. This matters because the Linear
  forwarder holds an Actions: write PAT on a public-facing function.
- **The address node shows the agent only the AI reviewer's own words.** `review_threads.sh`
  exports the comment that opens each AI-review thread and drops every reply, because anyone
  can reply in a thread on a public repository; the prompt tells the agent that a thread's
  text is a finding, not an instruction.
- **ci-dispatch ignores forks.** Both jobs require the CI run's head repository to be this
  repository at the job level, and the concurrency group includes it, so a fork branch named
  like an agent branch neither runs a step nor queues against the real one.
- **Requeue trusts only its own markers, and bounds itself.** `requeue.py` counts a
  `claude-requeue` marker only when github-actions[bot] wrote it, re-dispatches only the three
  Claude PR workflows with their exact input keys, numeric values and the item's own number,
  and stops 48 hours after the first failure or after 48 attempts. The CI-fix node neutralises HTML comments in the agent-written
  comment it posts as github-actions[bot], so an agent cannot forge a marker there. Re-labelling
  a parked issue uses the App's `issues: write` token (or `GH_AW_CI_TRIGGER_TOKEN` without an
  App), because a label set with `GITHUB_TOKEN` starts nothing.
- **The failure classifier cannot be edited by the agent it judges.** In the implement node,
  where the agent works in the workspace root, `classify_failure.py` is taken from the
  checked-out commit (`git show HEAD:`). An agent can still write a result file that looks like
  a usage limit and then time out; the 48-attempt cap is the bound on that.
- **The Linear link comes only from a bot-written line.** `envelope-guard`'s sync writes
  `Fixes <Linear ID>` into the PR body with `GITHUB_TOKEN`, and Linear's GitHub integration
  moves that Linear issue at merge. The ID is taken from the marker line of the source issue
  only when github-actions[bot] created it and it is not a pull request
  (`linear_id_for_issue`); editing that body takes write access. Sync removes only the
  section directly above the envelope block, so a quoted example in the agent's text stays. The `linear:<ID>` label is not used, because triage rights can swap it, and
  linear-intake likewise takes only bot-authored issues as mirrors, so pasting the marker into
  an issue does not make one. `GH-<n>` IDs are refused: GitHub reads them as `#<n>` and would
  close that issue on merge (observed on merged PRs).

Flagged for a human reviewer:

- **Agent-written text can still link Linear issues.** Once Linear's GitHub integration is
  installed, any `Fixes <ID>` (or another Linear magic word, or an ID in the PR title) that
  the agent writes into its PR description is acted on at merge exactly like the generated
  line; sync does not remove it. Prompt injection through the task text could therefore move
  an unrelated Linear issue. The reviewer reads the PR description before merging; the effect
  is visible and reversible in Linear.

- `review_threads.sh` recognises the AI reviewer by the GraphQL login of the account that
  posted the review, `github-actions` (REST calls it `github-actions[bot]`; both are
  accepted). Verified on a live review on 2026-09-27: the thread was exported and answered.
- The address node's replies are refused wholesale if a human resolves one of the threads
  while the agent works. The run then labels the PR `needs-human`; the fix is not lost from
  the artifact, but it is not pushed.
- `classify_failure.py`'s usage-limit phrases are UNVERIFIED: no run has hit the subscription
  limit yet. Unrecognised failures go to a human, so the failure mode of a wrong guess is a
  missed retry, not a retry loop.
- The Linear forwarder (`spine-linear/forwarder/`) had an adversarial review before it was
  written (16 findings; 15 adopted, the IP pre-filter declined) and a three-lens review of its
  time-budget rewrite (21 of 22 findings upheld and fixed). Live round trips with real Linear
  deliveries passed on 2026-09-27: unsigned and badly signed requests got 401, a label change
  dispatched `linear-intake` in about 2 seconds, and a retried delivery did not duplicate work.

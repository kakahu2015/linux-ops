# TOOLS.md — Local Conventions

Environment-specific execution guidance. Supports `AGENTS.md` but never overrides it.

## 1) Integrations

Disabled integrations:
- `obsidian-vault-maintainer`
- `taskflow`
- `taskflow-inbox-triage`
- `element-call`

## 2) Workspace Paths

- Screenshots / captures: `/root/.openclaw/workspace/capture/`
- Temporary files / scripts: `/root/.openclaw/workspace/tmp/`
- When a task needs temporary files, create a dedicated `task-name-timestamp` directory under `/root/.openclaw/workspace/tmp/` so each run stays isolated.


## 3) Messaging / Media

- Send images with `MEDIA:./relative/path`.
- Use relative paths only — no absolute paths or `~`.
- Keep caption text separate from the `MEDIA:` line.

## 4) Environment Notes

- In this environment, use `systemctl restart caddy` instead of reload.
- Chromium is managed by `chromium-browser.service`; do not launch it via `/root/ca/chromium-inner.sh`.

## 5) Rollback-Minded Operations

For high-risk or red-line work, use rollback-friendly steps where practical:
- Back up before directly modifying important files outside tool-managed or atomic workflows.
- Use dry-run first when the tool supports it.
- Capture pre-change state with a diff, snapshot, or equivalent relevant state record.
- Prefer reversible actions such as rename-over-delete or side-by-side install over in-place replacement when uncertainty exists.

If rollback is not practical, say so before acting.

## 6) Git / GitHub

- No git operations inside `/root/.openclaw/`.
- Clone repositories only to `/root/projects/`.
- Prefer `gh` CLI and API over local git for external repository tasks when possible.
- Do not commit, push, open PRs, or publish changes without explicit user instruction.

## 7) SSH / Remote Access

- This section is subordinate to `AGENTS.md`; it may add restrictions but never relax constitutional boundaries.
- SSH remote operations must use `linux-ops` only.
- Host configuration comes from `/root/.openclaw/workspace/skills/linux-ops/hosts.yaml`.
- Get explicit user authorization before connecting.
- Before connecting, confirm the host exists in the hosts file.
- Use existing key paths; never read or print private key contents.
- Do not create persistent backdoors, hidden access paths, or credential changes.
- Clean up temporary files when they are security-relevant, persistent, or failure-prone.
- If a remote change is high-risk or irreversible, follow the same P1/P2 rules as local work.
- Production default: L1 patrol runs unattended; L2 routine fixes and L3 emergency/obvious vulnerability stop-the-bleed may run unattended through `linux-ops` policy/gate with verification, redacted audit logs, and a human-readable report. L4 high-risk changes require explicit approval; L5 red lines are forbidden.

## 8) Browser Automation

- Browser/devtools operations should use `chrome-devtools-mcp` when available.
- For browser/web page work, prefer the OpenCLI series (`opencli-usage`, `opencli-browser`, `opencli-adapter-author`, `opencli-autofix`) when it fits the task.
- If an existing browser window/tab is already open, bind to it first (`opencli browser <session> bind`) and do not open a new browser/session unless no usable old session exists.
- If a browser already exists, reuse it. Strictly forbid starting a new browser process when an existing one is available.
- Prefer browser observation before interaction.
- Do not enter credentials, change account/security settings, make purchases, or submit irreversible forms without explicit confirmation.
- For external writes, verify the final page state or resulting record.

## 9) Execution Style

- Use independent tools in parallel when safe.
- Verify outcomes instead of assuming success.
- After multi-step work, summarize briefly: what changed, what remains, and any risk.
- For ambiguous requests, ask one focused question unless the task is low-risk and the narrowest reasonable interpretation is obvious.
- When proceeding on an assumption, state it inline.

## 10) Instruction Formatting

For non-trivial instructions, prefer this structure:
- Objective
- Constraints
- Steps
- Output format
- Example when ambiguity matters

Prefer bullets and labels over dense paragraphs.

## 11) Coding Style — Simplicity First

- Do not add features beyond what was requested.
- Do not create abstractions for one-off code.
- Do not add error handling for impossible scenarios.
- Prefer smaller, clearer implementations over clever ones.
- Do not modify adjacent files or refactor unrelated code unless explicitly asked.
- Run task-relevant verification before finishing.
- If 200 lines can be written as 50, rewrite.
- Gut check: would a senior engineer call this over-engineered?

## 12) Logging Conventions

If `memory/` is an agent-managed path, record only items worth later review:
- red-line operations
- L2 → L1 review results
- failed operations
- rolled-back operations
- notable decisions

Avoid duplicate entries.

Format:
`[timestamp] [operation] [reason] [outcome]`

## 13) OpenCLI / OpenCL Series Skills

- Use `opencli list -f yaml` or `opencli list -f json` as the source of truth for installed adapters.
- Before using a site adapter, run `opencli <site> -h`; before a specific command, run `opencli <site> <command> -h`.
- Use `smart-search` for search/research routing, especially when the user asks for a platform-specific lookup.
- Use `opencli-browser` for live browser interaction, page inspection, and ad-hoc scraping.
- Use `opencli-adapter-author` when adding a new adapter or command.
- Use `opencli-autofix` when an opencli command fails due to adapter drift or site changes.
- Do not hard-code adapter lists; rely on the live registry and command help.

## 14) X Content Workflow

- X content is anchored to `Linux`, `tech`, `gadgets`, and `AI experience`.
- User supplies raw ideas; the agent checks fit, trims scope, and rewrites them into post-ready copy.
- Default outputs should be concise, on-theme, and suitable for either a post or a short thread.

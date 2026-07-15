# USER.md

## Long-Term User Preferences

- Prefer the minimum-change path. Do not refactor or redesign working systems unless explicitly requested.
- Prefer simpler, lower-maintenance solutions when multiple workable options exist.
- Discuss direction first when a change is architectural, high-impact, or hard to roll back.
- Answer questions first, then act. When asked "does X have Y?", confirm or deny before launching, installing, or changing anything.
- Before making changes, back up the current state when practical.
- After changes, verify on the real running system instead of assuming success.
- Prefer loosely coupled components. Use small dedicated services instead of stuffing business logic into Caddy or a large frontend file.
- Avoid unnecessary features such as directory browsing, speculative allowlists, or enhancements that were not explicitly requested.
- Keep documentation aligned with current reality. Do not leave outdated design notes as if they were still active.
- When reviewing policies or system prompts, optimize for safety, clarity, and execution quality rather than word count alone.
- Interpret target names literally. "本机" refers only to the current machine/session host; do not map it to "hk" or any other host unless explicitly stated.

# S7 local development

Read `docs/DEVELOPMENT-HANDOFF.md` for verified progress and the current blocker.
Read `docs/NATIVE-LOCAL-START.md` before changing the native adapter.

## Source navigation

TokenSave is initialized locally. Use its MCP status/context/search/read tools
with this repository's absolute path as `graph_root` when the MCP server serves
another directory. If it already serves this repository, omit `graph_root`.
Check freshness before trusting graph relationships.
Run `tokensave sync` after source changes. On a fresh checkout, run
`tokensave init --no-git-hook` once. The rebuildable `.tokensave/` directory
is ignored. Do not index the game installation or the separate test copy.
The index does not replace disassembly or runtime verification of native ABI.
Unsupported `.inc`/`.def` files still need direct inspection.

## Local game experiments

- Preserve the original installation. Change only the separate test copy.
- The user starts and stops the game. Never launch the game yourself.
- Do not overwrite a loaded adapter. Check host process paths before deployment.
- Retain executable hash, callsite-byte, object and ABI guards.
- Keep experiments loopback-only until LAN transport is deliberately implemented.
- Do not read account caches or commit game binaries, archives, disassembly,
  local identities, credentials, runtime configuration or raw packet payloads.
- Report observed game behavior separately from synthetic test results.
- An accessible menu or empty list does not establish working multiplayer.

## Git

After a completed and verified milestone, commit and push the current branch.
Use `Co-Authored-By: Codex <noreply@openai.com>` in Codex commits. Do not bypass
hooks/signing, force-push, rewrite history or open a PR without authorization.

# RustDesk transport + plugin system research

Two connected documents:

- **[`plugin-plan.html`](./plugin-plan.html)** — the plan for the work you
  actually want: a plugin system for T3 Code, with one generic contract across
  every extension axis, a runtime-ready loading model, and RustDesk as the
  first transport plugin.
- **[`plan.html`](./plan.html)** — the transport feasibility analysis: how
  RustDesk's rendezvous + relay works, where it would plug into T3 Code, and
  what the licence and policy constraints are.
- **[`evidence.md`](./evidence.md)** — the evidence log behind both. Every claim
  cited to `path:line` in the upstream repos.
- **[`poc/probe.py`](./poc/probe.py)** — a standard-library-only probe that
  speaks the RustDesk rendezvous wire protocol. It reaches the live public
  server's signed key-exchange handshake, the first thing a third-party client
  must implement.

## The short version

T3 Code already has three plugin-shaped extension axes — secret providers,
source control and agent providers — each with the same
`Definition → Driver → Registry → Definitions package` shape. The word
"plugin" appears nowhere, but the pattern is everywhere. **Transport is the
only axis with no mechanism**: `AdvertisedEndpointProvider` even carries an
`isAddon` flag, with Tailscale as the single hardcoded addon.

The plugin system is therefore mostly an extraction job, not a greenfield
framework. RustDesk is plugin #1 because it is the hardest case: it produces
peers rather than URLs, needs connectors on both ends, and — because
RustDesk's code is AGPL-3.0 — has to live outside this repository.

## Status

| Phase | Description | State |
|---|---|---|
| 1 | `packages/plugin-core` — generic contract, registry, catalog | not started |
| 2 | Transport becomes plugins (Cloudflare, Tailscale, Manual) | not started |
| 3 | RustDesk plugin, out of tree (AGPL) | protocol probed only |
| 4 | Conform secret / source-control / provider axes | not started |
| 5 | Out-of-process plugin loader | not started |
| 6 | Plugin settings surface | not started |

Phases 1 and 2 are worth shipping even if RustDesk never lands.

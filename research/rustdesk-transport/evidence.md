# RustDesk transport research — evidence log

Working notes behind [`plan.html`](./plan.html). Every claim below is sourced to a
file and line in the upstream repositories, or to a live observation recorded by
the probe in [`poc/probe.py`](./poc/probe.py).

Repositories referenced:

| Repo | Licence | Role |
|---|---|---|
| `pingdotgg/t3code` | MIT | The product being changed |
| `rustdesk/rustdesk-server` | AGPL-3.0 | `hbbs` (rendezvous/ID) + `hbbr` (relay) |
| `rustdesk/rustdesk` | AGPL-3.0 | Client; holds the protocol handshake |
| `rustdesk/hbb_common` | *no LICENSE file, no `license` field in `Cargo.toml`* | Shared protocol crate, vendored into `rustdesk-server` as `libs/hbb_common` |

---

## 1. RustDesk server anatomy

### Ports

From `rustdesk-server/docs/environment-variables.md:255-259`:

| Port | Proto | Server | Purpose |
|---|---|---|---|
| 21115 | TCP | hbbs | NAT type test (`PORT-1`) |
| 21116 | TCP + UDP | hbbs | ID registration / rendezvous / hole punching |
| 21117 | TCP | hbbr | Relay |
| 21118 | TCP | hbbs | WebSocket rendezvous (`PORT+2`) |
| 21119 | TCP | hbbr | WebSocket relay (`PORT+2`) |

Client-side constants agree — `rustdesk/hbb_common/src/config.rs:116-122`:

```rust
pub const RENDEZVOUS_SERVERS: &[&str] = &["rs-ny.rustdesk.com"];
pub const RS_PUB_KEY: &str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";
pub const RENDEZVOUS_PORT: i32 = 21116;
pub const RELAY_PORT: i32 = 21117;
pub const WS_RENDEZVOUS_PORT: i32 = 21118;
pub const WS_RELAY_PORT: i32 = 21119;
```

### The relay is a content-agnostic byte forwarder

This is the fact the whole design rests on.

`rustdesk-server/src/relay_server.rs:461-498` — the relay reads one protobuf
frame off the socket, and if it is a `RequestRelay` with a non-empty `uuid`, it
looks for a peer already registered under that UUID. If found, the two streams
are paired; otherwise this one is stored and waits 30 s for its partner.

`rustdesk-server/src/relay_server.rs:500-560` — once paired, the relay shuttles
bytes between the two streams:

```rust
res = peer.recv() => { ... stream.send_raw(bytes.into()).await?; }
res = stream.recv() => { ... peer.send_raw(bytes.into()).await?; }
```

`send_raw` writes the bytes with no framing and no interpretation. The relay
never parses the payload. Any protocol can therefore be tunnelled through it.

### Key enforcement

`rustdesk-server/src/relay_server.rs:466` and `src/rendezvous_server.rs:766`:

```rust
if !key.is_empty() && rf.licence_key != key {
    log::warn!("Authentication failed ... - invalid key");
    return Ok((msg_out, None));   // -> PunchHoleResponse.LICENSE_MISMATCH
}
```

The client sends the configured server key verbatim as `licence_key`
(`rustdesk/src/client.rs:1874-1880`, and `client.rs:959` for `PunchHoleRequest`).
For the public server that value is `RS_PUB_KEY`.

Note `docs/environment-variables.md:64`: the relay's default key is **empty**,
which disables validation entirely. hbbs, by contrast, defaults to `-`
(`:41`), meaning "load or generate a key pair".

### The protocol is fully specified

`rustdesk-server/libs/hbb_common/protos/rendezvous.proto` is a plain protobuf3
file. The messages a third party must implement:

- `RegisterPeer { id, serial }` — announce an ID.
- `RegisterPk { id, uuid, pk }` — publish the peer's public key.
- `PunchHoleRequest { id, nat_type, licence_key, conn_type, version, ... }`
  → `PunchHoleResponse { socket_addr, pk, failure, relay_server, ... }`
- `RequestRelay { id, uuid, licence_key, ... }` → `RelayResponse { relay_server, ... }`
- `TestNatRequest` / `TestNatResponse`
- `KeyExchange { keys, signed_params, version }`

`ConnType` already models `DEFAULT_CONN`, `FILE_TRANSFER`, `PORT_FORWARD`, `RDP`,
`VIEW_CAMERA`, `TERMINAL` — RustDesk already has first-class TCP tunnelling in
its protocol model.

### Transport encryption and key verification

The server initiates a signed key exchange immediately on connect. From
`rustdesk/src/common.rs:2306-2373`:

1. Server sends `KeyExchange { keys: [signed_bytes], signed_params, version }`.
2. Client verifies the Ed25519 signature with `rs_pk` — the raw 32 bytes of the
   configured key (`get_rs_pk`, `common.rs:2411-2417`).
3. Client replies with `KeyExchange { keys: [our_x25519_pk, sealed_symmetric_key] }`
   (`create_symmetric_key_msg`, `common.rs:2449-2456`): a NaCl `crypto_box`
   sealed symmetric key plus its own X25519 public key.
4. Both derive the session key; the TCP stream is then encrypted.

This is the "key verification" mechanism, and it is why `RS_PUB_KEY` is a
published constant rather than a secret: it is the server's **public** signing
key, and possession of it lets a client verify it is talking to the real
server.

### Relay addresses are runtime-distributed

`rustdesk-server/src/rendezvous_server.rs:995-1002` — `get_relay_server` returns
from the `-r` / `RELAY-SERVERS` list, round-robin when there is more than one,
falling back to the hbbs host itself when the list is empty. The relay hostnames
are therefore not published anywhere; clients learn them from hbbs at connection
time. The RustDesk uptime repo confirms this — its relay checks use environment
variables (`$HZ_SERVER`, `$EAST2`) rather than literal hostnames
(`rustdesk/uptime/.upptimerc.yml:14-21`).

---

## 2. Live observations against the public server

`rs-ny.rustdesk.com` resolves to `209.250.254.15`.

TCP reachability (mirrors what `rustdesk/uptime` does with `tcp-ping`):

```
OPEN      rs-ny.rustdesk.com:21116    rendezvous
CLOSED    rs-ny.rustdesk.com:21117    relay is not on the rendezvous host
OPEN      rs-ny.rustdesk.com:21118    websocket rendezvous
CLOSED    rs-ny.rustdesk.com:21119
```

The probe (`poc/probe.py`, stdlib only, implements the `BytesCodec` framing from
`rustdesk-server/libs/hbb_common/src/bytes_codec.rs`) connects to 21116 and
**receives a signed `KeyExchange` from the live server**. That confirms:

- the server accepts a non-RustDesk TCP client at the protocol level;
- the key-exchange handshake is server-initiated, so a client must implement it
  before `RegisterPeer` / `RegisterPk` will be understood.

The probe stops there because the remaining steps require NaCl
(`crypto_box`, `secretbox`) and Ed25519 verification, which is Phase 0 work.

---

## 3. Authentication and 2FA — what actually exists

| Capability | OSS `rustdesk-server` | Public servers | RustDesk Server Pro |
|---|---|---|---|
| Peer ID registry | yes | yes | yes |
| Byte relay | yes | yes | yes |
| Key / licence check | optional | yes (`RS_PUB_KEY`) | yes |
| User accounts | **no** | **no** | yes |
| OAuth (GitHub/Google/Apple) | **no** | **no** | yes, via `api.rustdesk.com` |
| OIDC / LDAP | **no** | **no** | yes |
| TOTP 2FA | **no** | **no** | yes |
| Web console / API server | **no** | **no** | yes |

RustDesk's own OSS documentation states the gap: "If you need a web console, API
access, OIDC, LDAP, 2FA, device management, or other centralized admin features,
compare it with RustDesk Server Pro."

The TOTP implementation lives in the **client**, `rustdesk/src/auth_2fa.rs`, and
is tied to a RustDesk *account* served by `api.rustdesk.com`
(`rustdesk/src/common.rs:1270-1310` derives the API server from the rendezvous
server; `is_public`, `common.rs:1315-1325`). It is a paid-account feature and
is **not** something the public relay inherits.

---

## 4. T3 Code side — verified facts

### The limit

- `packages/contracts/src/relay.ts:969` — `export const DEFAULT_MANAGED_TUNNEL_LIMIT = 3;`
- `packages/contracts/src/relay.ts:972` — `T3CHAT_PLAN_TUNNEL_LIMITS = { pro: 10, premier: 100 }`
- `packages/contracts/src/relay.ts:966` — plan literals `["free", "pro", "premier"]`
- `infra/relay/src/environments/ManagedTunnelLimits.ts:173` — `baseMaxTunnels = override ?? DEFAULT_MANAGED_TUNNEL_LIMIT`
- `infra/relay/src/environments/ManagedTunnelLimits.ts:159` — per-user serialisation via `pg_advisory_xact_lock`
- `infra/relay/src/environments/ManagedTunnelLimits.ts:73-99` — `countedAllocations` counts **allocation rows**, not links
- `packages/client-runtime/src/relay/errorPresentation.ts:69-72` — the user-facing copy
- `docs/user/remote-access.md` — "Each T3 Connect account can link up to 3 machines. **Phones and browsers do not count.**"

So: three *linked host machines* per account. Not concurrent connections. The
count lives in T3 Code's own Postgres and is independent of which transport
provides reachability.

### The seam that already exists

- `infra/relay/src/environments/ManagedEndpointProvider.ts:149-192` — the provider service
- `infra/relay/src/environments/ManagedEndpointProvider.ts:239-284` — `ManagedEndpointTunnelClient`
- `infra/relay/src/environments/ManagedEndpointProvider.ts:319+` — `ManagedEndpointDnsClient`
- `packages/contracts/src/relay.ts:155-159` — `RelayManagedEndpointProviderKind = ["manual", "cloudflare_tunnel", "t3_relay"]`
- `packages/contracts/src/relay.ts:178-184` — `RelayManagedEndpointRuntimeConfig`
- `packages/secret-provider-definitions/src/registry.ts:4` — `makeSecretProviderDefinitionRegistry([...])`, the house precedent for a pluggable registry

### The hard-coded parts

- `apps/server/src/cloud/ManagedEndpointRuntime.ts:729-756` — spawns `cloudflared tunnel … run`
- `packages/shared/src/relayClient.ts:31` — `CLOUDFLARED_VERSION = "2026.10.4"`
- `packages/client-runtime/src/authorization/service.ts:271-330` — builds URLs from `httpBaseUrl` / `wsBaseUrl`
- `docs/internals/t3-connect.md:5-6` — "the relay Worker does not proxy their HTTP or WebSocket sessions"

### Computer use

- `packages/shared/src/toolActivity.ts:31-35` — `COMPUTER_USE_TOOL_SOURCE` is a **label** for a Codex tool
- `apps/server/src/provider/CodexToolPresentation.ts:195,213` — presentation only
- SnapShot — one-way screenshot, no input injection, no remote transport
- Device panel — iOS/Android simulators over `packages/client-runtime/src/device/stream.ts` (frame sink in, control channel out)
- Browser preview — CDP relay
- No "take over this machine from my phone" path exists

---

## 5. Licensing

Confirmed via the GitHub API:

```
rustdesk/rustdesk-server  AGPL-3.0
rustdesk/rustdesk         AGPL-3.0
rustdesk/hbb_common       null   (no LICENSE file; Cargo.toml has no license field)
pingdotgg/t3code          MIT
```

`rustdesk-server/.gitmodules` points `libs/hbb_common` at
`https://github.com/rustdesk/hbb_common`, so the crate is inside the AGPL
server tree — but the standalone repository carries no licence of its own.

**Mitigation structure**: put the RustDesk client in its own AGPL-licensed
repository, as a separate binary, and have T3 Code download and launch it the
way it already handles `cloudflared`. That keeps the AGPL boundary at the
process edge rather than inside an MIT repository.

This is a legal judgement, not an engineering one. Get counsel before shipping.

---

## 6. Policy on the public servers

Not resolved. I found no published statement that either permits or forbids
third-party use of RustDesk's public community servers for a non-RustDesk
application. Rather than build on that ambiguity:

- use the public servers for local development and the Phase 0 spike only;
- self-host `rustdesk-server` OSS for anything real — it costs roughly a small
  VPS, removes the rate limits, and gives you your own key pair and relay list.

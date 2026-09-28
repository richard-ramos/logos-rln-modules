# RLN Module — logos-core wire binding

The contract for a consumer-side shim that implements the RLN-API spec surface
(e.g. Nim procs in logos-delivery) by calling `liblogos_rln_module`
over logos-core. The layering:

```
consumer (e.g. WAKU2-RLN-RELAY relay code)
    │  spec functions: Membership register(scope, …), validate_proof(scope, signal, timestamp, proof), …
shim (implements the spec API in the consumer's language)
    │  logos-core wire: the methods below (string args → QString-JSON reply)
liblogos_rln_module
```

The shim is intended to be **stateless**: every piece of state the spec
functions need (epoch derivation, allocations, root windows, credentials)
lives in the module. What the shim MUST still supply is the scope — every call
passes its `(registry_id, rln_identifier_hex)` explicitly (spec: the Module
holds no default) — and, on the rate-limiting calls, the message's
`timestamp` (Unix seconds): the module derives every epoch from that value,
never from consumer-side epoch math.

## Call conventions

- Every method takes positional string/int args. Replies come in two dialects,
  split by the method's declared return type:
  - **`result` methods** — the RLN-API surface (`start`, `stop`,
    `generate_proof`, `validate_proof`, `get_epoch_quota`,
    `get_registry_parameters`) — return a
    real `LogosResult`. On the consumer (lp) wire that is the envelope
    `{"success": bool, "value": <reply>, "error": <string>}`; on failure
    `error` is the JSON-encoded typed object `{"class":…,"kind":…,
    "message":…}`. Parse defensively: envelopes may arrive double-encoded
    (a JSON string containing the envelope), a known SDK wire quirk. These
    methods are **not** QML-bridge-safe (`LogosResult` nulls through the UI
    bridge) — they are for module/shim consumers, and the GUI never calls
    them.
  - **`tstr` methods** — the membership-management surface — return a QString
    carrying compact JSON; failures are the in-band envelope
    `{"error": {"class":…,"kind":…,"message":…}}` (QML-bridge-safe).
- JSON replies use serde_json ⇒ **alphabetical keys** in both dialects.
- Binary values are lowercase hex, **32-byte little-endian** for field
  elements. Hex inputs tolerate a `0x` prefix.
- A `MembershipScope` is the arg pair `(registry_id, rln_identifier_hex)`:
  the CAIP-10 registry id and the application's 32-byte identifier.
  **Every call passes its scope explicitly — the Module holds no default**;
  an empty `registry_id` or `rln_identifier_hex` fails `invalid_argument`.
- `signal` (spec `Bytes`) travels as `signal_hex` — the raw bytes hex-encoded.

## Error envelope

The typed error object is identical in both dialects:

```json
{"class": "<class>", "kind": "<kind>", "message": "<detail>"}
```

For `result` methods it arrives JSON-encoded in `LogosResult.error` (with
`success: false`); for `tstr` methods it arrives in-band under a reserved
top-level `error` key. `class` is the spec's `RlnErrorKind`, carried
explicitly so the shim switches on it with no mapping table of its own:

| `class` | Spec value | Meaning | Underlying `kind`s |
|---|---|---|---|
| `not_ready` | `RLN_ERR_NOT_READY` | retry once ready | `not_ready`, `locked` |
| `transient` | `RLN_ERR_TRANSIENT` | MAY retry | `transient`, `provider_failure` |
| `budget_exhausted` | `RLN_ERR_BUDGET_EXHAUSTED` | retry next epoch | `budget_exhausted` |
| `permanent` | `RLN_ERR_PERMANENT` | retrying as-is cannot succeed | everything else |

`kind` refines the class for diagnostics; new kinds may appear over time —
switch on `class`, log `kind`.

## Methods

| Spec function | Method (args) | Dialect | Success reply (the `value` for result methods) |
|---|---|---|---|
| `start(config)` | `start(config_json)` | result | `{"started":true,"epoch_size_sec":N,"max_epoch_gap":N,"registries":[…]}` + `"overrides":{registry:{…}}` when any registries entry set per-registry values. config: `{"epoch_size_sec":N (required default), "max_epoch_gap"?:N, "registries"?:[caip10 \| {"registry_id","epoch_size_sec"?,"max_epoch_gap"?}]}` — spec: epoch size and max gap are per-REGISTRY configuration; an object entry overrides the defaults for that registry |
| `stop()` | `stop()` | result | `{"stopped":true}` |
| `register(scope, options)` | `register_membership(registry_id, rln_identifier_hex, options_json)` | tstr | public Membership view (below), `"state":"pending"` on a fresh submit; `options_json` is the RegistryOptions ARRAY (below), the common `rate_limit` key defaulted when absent |
| `get_membership_state(scope)` | `get_membership_state(registry_id, rln_identifier_hex)` | tstr | `{"state":…}` + `membership_hash`/`leaf_index`/`rate_limit` when known |
| `generate_proof(scope, signal, timestamp)` | `generate_proof(registry_id, rln_identifier_hex, signal_hex, timestamp)` | result | RateLimitProof (below) + `"message_id"`, `"epoch_index"`, `"membership_hash"`; epoch derives from `timestamp` (Unix s), must be within now ± `max_epoch_gap`. Fails `permanent` (kind `permanent`) for an epoch below the membership's persisted allocation floor (backwards clock / widened `max_epoch_gap`) or an `epoch_size_sec` its allocations are not bound to — re-register to recover |
| `validate_proof(scope, signal, timestamp, proof)` | `validate_proof(registry_id, rln_identifier_hex, signal_hex, timestamp, proof_json)` | result | `{"verdict":str}` (see the verdict table); a cryptographically valid decomposed proof that omitted `external_nullifier` also carries the reconstructed value, and `rate_limit_violation` carries `"recovered_secret":hex`. `timestamp` is the value stamped on the message under validation: the proof's epoch must EQUAL its epoch and be within now ± `max_epoch_gap`, else `"invalid"` |
| `get_epoch_quota(scope, timestamp)` | `get_epoch_quota(registry_id, rln_identifier_hex, timestamp)` | result | `{"epoch_index":N,"rate_limit":N,"remaining":N}` — one observation of `timestamp`'s epoch, purely local; `epoch_index` is a NUMBER (`floor(timestamp/epoch_size)`, what a QuotaProvider's `epochIndex` consumes); no usable membership → `rate_limit`/`remaining` both 0 (the wall-clock-fallback cue — never an exhausted budget); a timestamp whose epoch is outside now ± `max_epoch_gap`, below the membership's persisted allocation floor, or denominated in an `epoch_size_sec` its allocations aren't bound to fails `permanent` — the same refusals `generate_proof` would answer (spec: test a timestamp before committing to it), so `{rate_limit>0, remaining:0}` always means spendable-next-epoch |
| registry parameters read (optional ext.) | `get_registry_parameters(registry_id, rln_identifier_hex)` | result | `{"epoch_size_sec","max_rate_limit","min_rate_limit","max_total_rate_limit","price_per_unit"}` |
| select (multiple-membership ext.) | `select_membership(registry_id, rln_identifier_hex, selector_json)` | tstr | public Membership view |
| list (helper) | `get_memberships(registry_id)` | tstr | `{"memberships":[…]}` |

The public **Membership view** (spec `Membership` + status):
`{"credential":{"identity_commitment":hex},"leaf_index":N,"membership_hash":hex,
"rate_limit":N,"registry_id":caip10,"rln_identifier":hex,"state":str,…}` — no
secret ever appears. A `"failed"` state carries `"failed_reason":str` and
`"retryable":bool` (spec: a failed submission SHALL report whether it is
retryable).

**Scope semantics.** `register` is idempotent **per scope** (spec): the scope's
live membership short-circuits; a different application registering on the
same registry mints its own membership (isolated slashing blast radius).
`get_membership_state` / `generate_proof` / `get_registry_parameters` resolve
the membership *backing* the scope: records registered under the scope's
`rln_identifier` (or carrying none — pre-scope legacy records back every
application) are preferred; with no usable match, any of the registry's
memberships backs the scope, per the spec's "a membership MAY back any
application whose scope names its registry". More than one candidate is
`ambiguous_selection` — use `select_membership`.

### Time budgets

Most calls answer in milliseconds. The exceptions a shim must pass explicit
lp timeouts for (the logos-core default is ~20 s):

| Method | Budget | Why |
|---|---|---|
| `register` | 90 s | a fresh registration first does a synchronous registry-bounds pre-check (one registry read, ≤70 s worst case) before it mints, durably persists, and returns; only the on-chain submission is background. The idempotent short-circuit (a live local membership for the scope) returns in milliseconds |
| `generate_proof` | 90 s | warm: served from the background-maintained Merkle-path cache, no registry read; cold miss: one registry read (Merkle path, ≤70 s worst case) + proving (~seconds) |
| `get_registry_parameters` | 90 s | one registry read (≤70 s worst case) |
| `get_membership_state` | 90 s | one registry read |
| `get_merkle_proof` / `get_valid_roots` | 90 s | one registry read |
| `validate_proof` | 5 s | pure local computation |
| `get_epoch_quota` | 5 s | pure local state |

## Events

A third channel, pushed over the lp event stream rather than returned by any
method call — no `result`/`tstr` envelope, no class/kind, just positional
args.

| Event | Args (positional order) | Fires when |
|---|---|---|
| `membership_state_changed` | `registry_id, rln_identifier, membership_hash, state, previous` | a membership's registry-observed state actually CHANGES — `pending`→`active`, `pending`→`failed`, `active`→`grace_period`/`expired`, observed→`erased` — never for a mere re-observation of the same state |

- `rln_identifier` is the registering scope's `rln_identifier_hex`, empty for
  a pre-scope legacy record; consumers filter on `(registry_id,
  membership_hash)`.
- `previous` is the state the record held immediately before this
  transition — one of the `MembershipStatus` wire strings below.
- Emitted from the confirmation poller's background tick (module docs point
  1/2) and from `get_membership_state`'s self-healing merge write, for
  whichever side observes the transition first.

**Consumer surface**: the module's proxy exposes the standard logos-core
event mechanism — `logos.<module>.on("membership_state_changed", [](const
QVariantList& args) { … })` in C++ (backed by the `eventResponse(QString,
QVariantList)` Qt signal every provider forwards through), `args` positional
in the table order above. From QML (`LogosQmlBridge`,
logos-view-module-runtime): arm with
`logos.onModuleEvent("<module>", "membership_state_changed")`, receive via
the `moduleEventReceived(moduleName, eventName, data)` signal — `data` is
the positional args as a native JS array, and unlike the call-reply path it
does NOT pass through the LogosResult-nulling serializer.
This implements the spec's optional "membership state subscriptions"
extension (RLN-MEMBERSHIP-MANAGEMENT) — **additive, not required**: a
consumer MUST NOT depend on it being wired up. Polling `get_membership_state`
remains the portable path every consumer can rely on.

## MembershipStatus wire strings

| Wire string | Spec enum |
|---|---|
| `unknown` | `MEMBERSHIP_UNKNOWN` |
| `pending` | `MEMBERSHIP_PENDING` |
| `failed` | `MEMBERSHIP_FAILED` |
| `active` | `MEMBERSHIP_ACTIVE` |
| `grace_period` | `MEMBERSHIP_GRACE_PERIOD` |
| `expired` | `MEMBERSHIP_EXPIRED` |
| `erased_awaits_withdrawal` | `MEMBERSHIP_ERASED_AWAITS_WITHDRAWAL` |
| `erased` | `MEMBERSHIP_ERASED` |
| `slashed` | `MEMBERSHIP_SLASHED` |

`erased_awaits_withdrawal` and `slashed` are in the vocabulary for spec
completeness but are never reported by the `logos` namespace: its registry
keeps no recoverable deposit and does not expose slashing as a removal
cause, so every removal surfaces as `erased` (spec-sanctioned).

## RateLimitProof

`generate_proof` returns the spec's DECOMPOSED `RateLimitProof` plus three
extras:

```json
{
  "proof": "<128B hex — the compressed Groth16 proof, spec proof[128]>",
  "root": "<32B hex>", "external_nullifier": "<32B hex>",
  "share_x": "<32B hex>", "share_y": "<32B hex>", "nullifier": "<32B hex>",
  "epoch": "<32B LE hex — spec epoch[32]>",
  "message_id": N, "epoch_index": N, "membership_hash": "<hex>",
  "proof_canonical": "<289B hex — the full zerokit serialization>"
}
```

- `share_x` is the circuit's signal hash `x`, `share_y` is `y`; `epoch` is
  the spec's `epoch[32]` (the u64 `epoch_index` alongside is a convenience,
  as is the spent `message_id` and the local `membership_hash` — from_json
  tolerates and ignores the extras).
- `proof_canonical` (0.6.1) is the message-wire transport shortcut: a
  consumer that carries ONE opaque blob on its own wire ships these bytes
  and validates with `{"proof": "<that hex>"}` alone — the canonical path
  below recovers every public value from the blob.
- `validate_proof` accepts this shape AND the canonical-blob form
  (`proof` = zerokit's full `RLNProof` LE serialization: proof[128] ‖ mode
  tag ‖ y ‖ root ‖ nullifier ‖ x ‖ external_nullifier — 289 bytes; canonical
  bytes trusted, decoded fields ignored). A decomposed proof is rebuilt and
  re-serialized, so both shapes land in the identical verified
  representation. `epoch` may cross as the 32-byte LE hex or the u64 index.
- A decomposed Mix proof may omit `external_nullifier`: the module derives it
  from the scope and timestamp, then verifies the proof against that binding.
  A cryptographically valid response includes the derived
  `external_nullifier` for Mix coordination; an `invalid` response omits it.
  This preserves Mix's existing proof wire format without putting Poseidon
  computation in the consumer. A wrong scope or signal still fails validation.
- Frozen byte-exact vectors (identity derivation, external nullifier, signal
  hash, public values, layout): `rust-lib/src/proof.rs`,
  `proof::tests::frozen_interop_vectors`.

## Epoch semantics

- `epoch = floor(unix_seconds / epoch_size_sec)`, a `u64` index on this wire
  (the `"epoch_index"` reply fields). Inside
  the crypto it is the spec's `epoch[32]`: the index as a 32-byte
  little-endian integer (logos-delivery's `toEpoch`), and
  `external_nullifier = poseidon(hash_to_field_le(epoch[32]),
  hash_to_field_le(rln_identifier))` — byte-identical to logos-delivery's
  `generateExternalNullifier`. (Note: NOT nwaku's keccak-based construction.)
- `epoch_size_sec` is a **required `start()` parameter** with no default:
  until `start()` configures it, `generate_proof` / `validate_proof` /
  `get_epoch_quota` (and the `get_registry_parameters` echo) fail
  `not_ready` rather than improvise an epoch base. It is an
  **application parameter** — every
  proof generator and verifier of a deployment must configure the same value.
  Both it and `max_epoch_gap` are per-REGISTRY (spec): a `registries` entry
  may override the instance defaults for its registry, and every
  epoch-dependent call resolves the values by the scope's registry.
- `validate_proof` enforces application binding + epoch agreement + freshness:
  the expected epoch derives from the supplied message `timestamp`; the
  proof's carried epoch, when present, must equal it; the proof's external
  nullifier must match the scope's expected value recomputed from it; and it
  must fall within the current epoch ± `max_epoch_gap`. Anything else is
  `{"verdict":"invalid"}`. Consumers implement no epoch math of their own —
  they relay the message's timestamp on both `generate_proof` and
  `validate_proof`, and the two ends agree on the epoch by construction.
  **Double-signal detection across
  messages is now the Module's job, not the consumer's** (a spec change): the
  Module keeps an in-memory nullifier log (per epoch, retained at least
  `max_epoch_gap` epochs, never on disk) and, when a proof reuses a nullifier
  under a different `share_x`, reconstructs the offender's identity secret from
  the two colliding shares and returns it as `recovered_secret`.

### validate_proof verdicts

A proof that fails any validity check (zk-invalid, root not in window, stale,
epoch not matching the message timestamp, or cross-application binding) is
`invalid`. A proof passing every check is then judged against the nullifier
log:

| `verdict` | Meaning | Suggested consumer action |
|---|---|---|
| `valid` | First valid proof for this nullifier | Accept the message |
| `invalid` | Failed a validity check (bad zk / root / binding) | Reject the message |
| `duplicate` | Nullifier already seen under the SAME `share_x` — a retransmission of an already-accepted message | Drop as already-seen (not a violation) |
| `rate_limit_violation` | Nullifier reused under a DIFFERENT `share_x` — a double-signal; `recovered_secret` (hex) is the offender's own identity secret, reconstructed from the two shares | Reject the message; `recovered_secret` is the slashing evidence |

## RegistryOptions (`options_json`)

The spec's `RegistryOptions` pair list crosses the wire verbatim as a JSON
ARRAY of `{"key": "<tstr>", "value": "<tstr>"}` entries — every value a
string (`char*` pairs), a non-string value, a non-array `options_json`, or a
duplicate key is `invalid_argument`. The common key `rate_limit` (decimal
string) requests the per-epoch rate; ABSENT, the module applies
`DEFAULT_RATE_LIMIT` (= 100) — the lez registry declares no default yet
(planned as a registry-declared parameter in logos-lez-rln). The remaining
keys are registry-specific:

- **`logos` namespace, direct**: no key. The registry takes the native asset
  and `liblogos_lez_rln_module` pays from its own account, so nothing here
  selects a payer — this module is registry-agnostic and holds no account ids.

  `funding_holding_account_id` was **mandatory** here until 0.8.0 and is now
  accepted and ignored (one deprecation line per call). It is ignored rather
  than rejected because every shipped caller still sends it and a stale conf
  should not become a permanent registration failure. The break is semantic
  and one layer down: the account that key names is no longer the account that
  pays. A caller that needs to pay from a specific account names it on
  `liblogos_lez_rln_module.register_member`'s `payer_account_id` instead.
- **`logos` namespace, delegated** (RLN Membership Allocation Protocol):
  `delegated`=`"true"` plus `gifter_peer_id`, `gifter_multiaddr` and the
  optional `auth_type`/`auth_payload`/`auth_provider`/`auth_args` pairs.
  register drives `rln_gifter_module` with the module-generated commitment.

  The auth surface is fully vector-agnostic — this module knows **no vector
  by name**. `auth_type` names the gifter auth vector verbatim in the wire's
  **open** `authentication_type` vocabulary (e.g. `"keycard-attestation"`);
  its payload comes from exactly ONE of `auth_payload` (raw hex, sent
  verbatim) or `auth_provider` — a module implementing the
  `rln_auth_vector` producer contract, which the gifter client calls with
  the commitment (`auth_args` forwarded verbatim). Omitting `auth_type`
  entirely makes an unauthenticated request for an open gifter. An
  application shipping its own allocation-auth strategy as
  `rln_auth_vector` plugin modules therefore needs **zero changes** here or
  in the gifter — configuration only. Example (keycard):
  `{"auth_type": "keycard-attestation", "auth_provider":
  "keycard_capture_module"}`.

  Rejected as `invalid_argument` **before a credential is minted** (the
  gifter client's own rules, checked early): payload material without
  `auth_type`; a named vector with no payload source, or with both at once;
  a non-hex `auth_payload`; auth options on the funded (non-delegated) path.
  Non-string values never coerce — they are rejected at the array binding
  ("value for '<key>' must be a string").

## start() config

```json
{
  "epoch_size_sec": 600,
  "max_epoch_gap": 1,
  "registries": [
    "logos:testnet:<64-hex>",
    { "registry_id": "logos:local:<64-hex>", "epoch_size_sec": 120, "max_epoch_gap": 2 }
  ]
}
```

Listed registries get their valid-root windows warmed immediately
(`epoch_size_sec` is required — see Epoch semantics). A `registries` entry
is either a CAIP-10 string or an object overriding `epoch_size_sec` /
`max_epoch_gap` for that registry; the reply echoes active overrides under
an `overrides` key. There is no
default-scope key: every other method takes its
`(registry_id, rln_identifier_hex)` scope explicitly. `stop()` tears the
maintenance workers down: sleeping workers join within a ~200 ms grace; a
worker blocked in one in-flight registry read (≤80 s) is detached and
self-exits after that single read without scheduling further work — the
one bounded deviation from the spec's "cancelled cleanly". `start()`
respawns and reconfigures — both idempotent.

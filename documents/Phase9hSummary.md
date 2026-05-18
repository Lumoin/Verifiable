# Phase 9h — Pipeline refactor for per-call dynamics

Status: shipped. Final suite count 2640 / 0 / 10 (Debug and Release).

## What shipped

The OAuth pipeline reshapes so every per-call decision flows through a
named typed delegate on `AuthorizationServerIntegration`, every per-call
resolved value lives on `RequestContext`, and every consumer reads from
one source of truth.

### Single source of truth: `EndpointChain`

`EndpointChain` is the authoritative description of a request's
endpoint shape. Built per-request via
`EndpointChain.BuildForRequestAsync`, which:

1. Reads `context.Server` (placed there at dispatch entry).
2. Calls `Integration.ResolveCapabilitiesAsync` once to get the
   per-call active capability set.
3. Asks each `EndpointBuilderDelegate` on
   `Configuration.EndpointBuilders` for `EndpointCandidate`s.
4. Filters candidates by capability membership in the active set.
5. Resolves each survivor's URL via
   `Integration.ResolveEndpointUriAsync` keyed by
   `WellKnownEndpointNames`.
6. Projects to `ServerEndpoint` with `required Uri ResolvedUri` and
   optional `DiscoveryMetadataKey`.

Three consumers read from the chain:

- **Matcher routing.** Matchers compare `req.Path` against
  `endpoint.ResolvedUri.AbsolutePath`. No path-template indirection
  in the library; matchers see whatever URL the application's
  `ResolveEndpointUriAsync` produced.
- **Dispatcher invocation.** The matched endpoint's `BuildInputAsync`
  and `BuildResponse` are invoked directly from the matched chain
  entry.
- **Discovery emission.** `MetadataEndpoints.BuildDiscovery` walks
  `context.EndpointChain` and emits one field per chain entry whose
  `DiscoveryMetadataKey` is non-null. Capability-vetoed endpoints are
  absent from the chain and therefore absent from discovery; URLs
  emitted in discovery are byte-identical to the URLs the matcher
  will match against, because both read the same `ResolvedUri`.

### Server-on-context discipline

`AuthorizationServer.DispatchAsync` calls `context.SetServer(this)` at
entry. Every per-request delegate signature is
`(..., RequestContext, CancellationToken)`. Implementations that need
server-level access read `context.Server!`. Uniform shape across:

- `EndpointBuilderDelegate(ClientRecord, RequestContext, CancellationToken)`
- `MatchRequestDelegate(RequestFields, RequestContext, ServerEndpoint, CancellationToken)`
- `BuildInputDelegate(RequestFields, RequestContext, OAuthFlowState, CancellationToken)`
- `OAuthActionExecutor.ExecuteAsync(OAuthAction, RequestContext, CancellationToken)`
- `TokenProducerBuildDelegate(IssuanceContext, KeyId, string, CancellationToken)`
- `FlowRunner.StepWithEffectsAsync(state, count, input, executor, context, timeProvider, ct)`

New per-request delegates added to the surface follow the same shape:
drop server, take context.

### Four-stage observability

`Integration.InspectAsync` is invoked at four stages with a
discriminated `InspectionStage` argument:

- `IncomingRequestStage` — at dispatch entry, before any pipeline work.
- `MatchedStage(Endpoint, Payload)` — after `EndpointChain.MatchAsync`,
  with both members nullable when no endpoint matched.
- `StateTransitionStage(Before, Input, After)` — after each successful
  PDA state transition. Both branches in `FlowRunner.StepWithEffectsAsync`
  (no-executor single-step and with-executor effectful loop) emit.
- `OutgoingResponseStage(Response)` — before the response returns.

`StateTransitionStage` fires only on completed transitions; exceptions
from `StepAsync` propagate without emitting the stage. This keeps the
audit trail consistent with what actually happened, not what attempted
to happen.

Inspection is the integration point for: CAEP/RISC threat-event
emission (deployment's lambda forwards stages into the event bus);
forensic replay event-log capture (per-step
`(before-state, input, after-state)` tuples written to whatever event
store the deployment uses, per `documents/AuthorizationServerDesign.md`
§2.4); operational tracing.

### `Guid.CreateVersion7()` for flowIds

`AuthorizationServer.HandleCoreAsync` generates `flowId` via
`Guid.CreateVersion7().ToString("N")` instead of `Guid.NewGuid()`. v7
UUIDs encode a 48-bit Unix-milliseconds timestamp in the high-order
bits, so sequential-generation flowIds sort lexicographically by
creation time. Database backends keyed by flowId get index locality
for free; forensic archive readers walking the event store get
generation-order reads.

### Deletions

The following are gone with no replacement — zero backwards-compat
phase:

- `ServerEndpointPaths.cs` — library-side path templates. Applications
  now compute URLs via `Integration.ResolveEndpointUriAsync`.
- `ServerPaths.cs` — `IsEndpoint` / `IsGlobalEndpoint` helpers. Path
  comparison happens via `Routing.PathEquals.Equals` against the
  chain's `ResolvedUri.AbsolutePath`.
- `WellKnownPathsServer` — library-side URI builder. Same reasoning;
  no library-side path templating.
- `AuthorizationServer.CheckCapabilityAsync` method — chain filter is
  the capability gate.
- `AuthorizationServer.GetEndpoints(Async)` private helper.
- `AuthorizationServerIntegration.IsCapabilityAllowedAsync` slot —
  subsumed by `ResolveCapabilitiesAsync` returning the active
  allowed set.
- `IsCapabilityAllowedDelegate` type.

### Test-side migration

- `TestHostShell.DispatchAtPathAsync` → `DispatchAtEndpointAsync`. 75
  call sites across ~14 test files. Tests now resolve URLs through
  `TestHostShell.ComposeEndpointPath` (the synchronous form), which
  shares its dispatch with the asynchronous `ResolveEndpointUriAsync`
  lambda via a private `EndpointPathSuffix` helper — single source of
  truth for the fixture's URL scheme.
- `TestHostShell.ComposeEndpointPath` / `ComposeEndpointUri` are
  public-static helpers for synchronous URL computation in tests that
  need it (e.g. dispatching to unknown segments for negative-path
  coverage).

### Test additions

15 new pipeline regression tests across six new flat-named files plus
one existing file:

- `InspectionStageTests.cs` — 5 tests: `StateTransitionStage` emission
  on PDA transitions; non-emission for stateless endpoints; four-stage
  envelope ordering; `MatchedStage` carries null endpoint on no match;
  envelope stages fire on unmatched requests.
- `ResolveCapabilitiesAsyncTests.cs` — 3 tests: chain attenuation by
  vetoing a capability; per-request consultation (load-bearing
  per-request dynamics test); filter-before-URI-resolution ordering.
- `RequestContextAccessorsTests.cs` — 2 tests: `Server` accessor
  populated at dispatch entry (visible to `IncomingRequestStage`);
  `EndpointChain` accessor populated post-chain-build (visible to
  `MatchedStage`).
- `RecursiveTenancyTests.cs` — 2 tests (structural variant): two
  tenants with different capability sets dispatch independently;
  per-request capability attenuation in one tenant doesn't leak into
  the other.
- `FlowIdentifierTests.cs` — 1 test: v7 GUID flowIds sort
  lexicographically in generation order; locks in the chunk 8 v7
  choice against silent regression to `Guid.NewGuid()`.
- `Oidc10IdTokenProducerTests.cs` — 1 test: byte-identical claim
  baseline for fixed deterministic input; guards wire output against
  silent payload changes.
- `AuthorizationServerFeatureTests.cs` (existing) — 1 added test:
  discovery emission drops fields for capabilities attenuated by
  `ResolveCapabilitiesAsync`.

Three behavioural tests in `AuthorizationServerFeatureTests.cs` were
rewritten in chunk 8 to reflect the new capability-gate model (the
gate moved from match-then-reject at 403 to filter-before-match at
404):

- `CapabilityRejectionByIntegrationDelegateReturns403UnauthorizedClient`
  → `CapabilityAttenuationByResolveCapabilitiesAsyncRemovesEndpointFromChain`.
- `DispatchPlacesMatchPayloadOnContextBeforeCapabilityCheck`
  → `DispatchPlacesMatchPayloadOnContextBeforeHandlerFires`.
- `SameRequestContextInstanceReachesEveryIntegrationDelegate` — name
  kept; probe delegate swapped from the deleted
  `IsCapabilityAllowedAsync` to `InspectAsync`.

## What is intentionally deferred

The following surfaced during 9h but is owned by downstream tracks:

- **Contributor migration to `Verifiable.Core.Assessment` pattern.**
  Existing `ClaimContributor` infrastructure stays in 9h. Phase A's
  UserInfo arrival is the forcing function; migration to
  `ClaimDelegate<ClaimContributionTarget>` +
  `ClaimIssuer<ClaimContributionTarget>` happens there. The
  `ContributorChainComposesInOrder` test from the v2 MD was skipped
  in 9h because locking in current composition order is premature
  work — the surface is about to change.
- **Discovery completion.** 9h's emission covers issuer + endpoint
  URLs from the chain. Capability-derived support arrays
  (`grant_types_supported`, `response_types_supported`, etc.),
  key-store-derived arrays
  (`id_token_signing_alg_values_supported`, etc.), and static
  behavioural flags (`claims_parameter_supported`, etc.) land in
  Phase A's Discovery completion track.
- **`ResolveSubjectIdentifierAsync` integration.** The slot is wired
  and required at `Validate()`. No production caller in 9h —
  `Oidc10IdTokenProducer.BuildAsync` doesn't invoke it. Phase A's
  UserInfo / ID Token wiring is the first caller, and the
  `ResolveSubjectIdentifierIsConsultedOnIdTokenIssuance` test from
  the v2 MD lands then.
- **Per-call attenuation of individual token producers.** 9h
  attenuates at the endpoint level via `ResolveCapabilitiesAsync`.
  Per-producer attenuation (e.g. CAEP signal saying "you can still
  receive `id_token` but no `access_token`") requires threading the
  resolved capability set into the token-endpoint flow. Phase D
  (SSF/CAEP/RISC) decides whether this is needed.
- **Replay-determinism event-log capture.** Documented in design-doc
  §2.4 as a deployment concern, not a library invariant.
  `InspectAsync(StateTransitionStage)` is the emission point;
  deployments wire their event-store recording lambda.
- **PIC-Protocol attenuation chain cryptography.** Agentic identity
  track. 9h's `RecursiveTenancyTests` cover structural
  multi-tenancy support; the cryptographic authority-chain proof is
  separate.

## What this enables for downstream phases

- **Phase A (OIDC basic + Assessment migration).** UserInfo endpoint
  composes naturally against `EndpointChain` and the four-stage
  inspection. The contributor migration to `Verifiable.Core.Assessment`
  is the bulk of Phase A's work.
- **Phase B (OpenID Federation).** Federation entity statement
  endpoint adds to `EndpointBuilders`; trust chain walking goes
  through the same delegate composition pattern.
- **Phase C (OID4VP completion).** Verifier endpoints and wallet
  holder side both use the same pipeline. Federation prefix
  resolution from Phase B plugs in via verifier-side trust delegate.
- **Phase D (SSF/CAEP/RISC).** Transmitter endpoints add to
  `EndpointBuilders`. CAEP/RISC signal ingestion attenuates
  `ResolveCapabilitiesAsync` output for affected tenants — the
  hooks are already in place.
- **Phase E (OID4VCI).** Credential endpoints add to
  `EndpointBuilders`. Credential claim contribution via the same
  Assessment pattern Phase A introduces.
- **Phase F (SIOPv2).** Wallet-as-one-tenant-AS. The pipeline runs
  unmodified; SIOPv2 is wiring against the existing shape.
- **Phase G (logout, Identity Assurance, etc.).** Logout endpoints
  add to `EndpointBuilders`; logout-token contributor target lands
  with the Assessment migration; Identity Assurance verified-claims
  contributor target likewise.

## Architectural reach

Every per-call decision is wireable. Every deployment shape — wallet
on a phone, agent runtime, single-tenant developer instance,
multi-tenant SaaS, recursive operator-customer-subcustomer — runs the
same pipeline with different wiring. SIOPv2 isn't an outlier; it's
one-tenant SaaS with the wallet as the AS. Agentic identity isn't an
outlier; it's recursive multi-tenancy with cryptographic authority
chains layered on top (the chain itself is in scope of a different
track; the multi-tenancy substrate isn't).

The pipeline is closed-shape — you can't add new dispatch stages or
reorder existing ones — and open-depth — every stage's behaviour is
wholly replaceable through delegate wiring. For OAuth/OIDC's
protocol-determined dispatch sequence this is the right trade-off.
For wildly different protocols, build a sibling dispatcher using the
same primitives: `EndpointChain`, `FlowKind`, `RequestContext`,
PDA `Verifiable.Core.Automata`, storage delegates. All
protocol-agnostic.

## Files of note

- `documents/AuthorizationServerDesign.md` — design doc, updated with
  the post-9h sequence diagram and §2.4 replay-determinism note.
- `tempdocs/PHASE_9H_PIPELINE_REFACTOR_V2.md` — step-by-step spec.
  Has known inaccuracies surfaced by the chunk handoffs; captures
  intent.
- `src/Verifiable.OAuth/Server/Pipeline/EndpointChain.cs` —
  `BuildForRequestAsync` is the single source of truth for
  per-request endpoint shape.
- `src/Verifiable.OAuth/Server/AuthorizationServer.cs` —
  `DispatchAsync` is the canonical pipeline shape; the four
  `InspectAsync` invocations and the v7 flowId generation live here.
- `src/Verifiable.OAuth/Server/InspectionStage.cs` — the four-stage
  discriminated hierarchy.
- `src/Verifiable.OAuth/Server/WellKnownEndpointNames.cs` — 15
  endpoint role identifiers covering AuthCode (with JAR variants),
  OID4VP, Metadata, Registration.
- `src/Verifiable.OAuth/Server/EndpointCandidate.cs` — pre-URI-resolution
  shape builders return.

## Open bugs surfaced (not 9h scope)

- **RSA-JWK modulus byte length mismatch.** `RsaUtilities.Decode`
  expects modulus bytes of length 270 (RSA-2048) or 526 (RSA-4096).
  The `PublicKeyJwk` extraction path produces a different length,
  causing `ArgumentOutOfRangeException` in
  `BouncyCastleCryptographicFunctions.ParseRsaPublicKey`. Multibase
  extraction variant works; only JWK is broken. Surfaced by
  `KeyDidBuilderTests` after the inverted `SupportsSigning()`
  condition was fixed during chunk 12 preparation. Guarded with
  `Assert.Inconclusive` in the test; tracked in
  `tempdocs/OPEN_BUGS.md`.
- **`KeyDidBuilderTests.CreateAndVerifySignatureUsingDidKey`
  inverted condition.** Fixed in commit `a7bdf84` ahead of chunk 12;
  the fix restored 10 previously-Inconclusive theory rows to
  running-and-passing state. Not in 9h scope but landed during 9h
  work because the chunk 12 author noticed it.

## Commit trail

| Commit | Chunk |
|---|---|
| `f983175` | 1 — design-doc + PathEquals + WellKnownEndpointNames |
| `77d209a` | 2-3 — ServerPaths forwarder + RequestContext accessors |
| `d3eee69` | 4 — foundation types + Integration slots |
| `d90a318` | 4-tidy — move Default* into Server/Pipeline/ |
| `e1a8ae8` | 5 — signature cascade (build red mid-cascade) |
| `d6e69c3` | 6 — builders return EndpointCandidate (build red) |
| `7aac854` | 7 — matcher rewrites + delete ServerPaths (build green again) |
| `f385e31` | 8 — proper EndpointChain.BuildForRequestAsync, 4-stage Inspect, v7 flowId, ResolvedUri required, deletions |
| `276022b` | 9 — metadata discovery walks the chain |
| `0e1190b` | 10+11 — InspectionStage + Oidc10IdTokenProducer regression tests |
| `a7bdf84` | (pre-12) — inverted SupportsSigning fix |
| `e12f99e` | 12 — DispatchAtPathAsync → DispatchAtEndpointAsync; delete ServerEndpointPaths + WellKnownPathsServer |
| `a288509` | 13 — pipeline regression tests across 5 new files |

Phase 9h ships at the chunk 14 commit on this branch.

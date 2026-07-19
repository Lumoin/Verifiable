# Token Producer Selection and openid⇒End-User Anchoring

## Context

`Verifiable.OAuth`'s token endpoint composes its response from a set of `TokenProducer` modules (RFC 9068 access tokens, OIDC ID Tokens, and any application-supplied producer following the same shape) walked once per request. Two things needed a settled answer: which axis gates a producer running at all, and what stops an identity-bearing token (an ID Token, or an access token whose presence unlocks UserInfo) from being minted for a subject the library has no basis to call an authenticated End-User.

Before this decision, `Rfc9068AccessTokenProducer.RequiredCapability` was pinned to `WellKnownCapabilityIdentifiers.OAuthAuthorizationCode` — a capability that has nothing to do with what the access-token producer actually needs (it needs "the grant that just matched is token-issuing", not "the grant that matched is specifically `authorization_code`"). A tenant configured for `jwt_bearer` only, `client_credentials` only, `token_exchange` only, or `pre_authorized_code` only would match its grant's endpoint successfully and then have the access-token producer skip itself, minting nothing. The defect was masked in the test suite by five test files granting the tenant `OAuthAuthorizationCode` as a capability it does not actually use, purely to satisfy the producer's gate.

Independently, `IssuanceContext` carried no grant identity. Both `Oidc10IdTokenProducer.IsApplicableAsync` and `UserInfoEndpoints` gated identity issuance on the same proxy — "is `openid` present in the token's scope?" — with no independent check that the token in question was ever capable of representing an End-User. `openid` reaching the granted scope of a `client_credentials` token (whose `sub` is the `client_id`, not a person) or a `token_exchange`/`jwt_bearer` token exchanged for a non-End-User subject would, absent any other check, have produced a genuine ID Token or a served UserInfo identity body for a machine. Two independent consumers shared the same single point of failure — a class of defect, not an isolated bug in one file.

The ID-JAG mint (`draft-ietf-oauth-identity-assertion-authz-grant`) already got this right elsewhere in the library: it gates on an explicit `requested_token_type` plus the app's own authorization decision, never on a scope proxy. This decision generalizes that pattern to the built-in producers.

## Decision

**Producer selection uses two independent, differently-scoped axes**, neither of which duplicates the endpoint-level capability match that already gated the grant itself:

- `TokenProducer.RequiredCapability` (`CapabilityIdentifier?`, not required) is an *optional coarse tenant-feature gate*. `null` means the producer is not feature-gated — its applicability rests entirely on `IsApplicable`. `Rfc9068AccessTokenProducer` sets it `null`: an access token is the default response of every token-issuing grant, and the grant's own endpoint match already proved the tenant may run this grant before the producer walk starts. `Oidc10IdTokenProducer` keeps `WellKnownCapabilityIdentifiers.OidcOpenIdConnect`: whether a tenant offers OIDC at all is a genuine opt-in feature orthogonal to which grant capability matched.
- `TokenProducer.IsApplicable` is the producer's own per-request decision, now able to read `IssuanceContext.GrantType` (a new required field carrying the wire `grant_type` from `WellKnownGrantTypes`, set at all six token-issuing call sites). The access-token producer is unconditionally applicable. The ID Token producer's applicability is `openid ∈ scope AND GrantType ∈ {authorization_code, refresh_token}` — grant-aware, independent of the scope check alone.

**The `openid` ⇒ authenticated-End-User invariant is enforced at three independent layers** (defense-in-depth, per explicit owner direction — not collapsed to a single check):

1. **Source.** The grants with no authenticated End-User by construction — `client_credentials` (subject is the client) and `pre_authorized_code` (no prior authorization session) — have `openid` and the OIDC Core §5.4 identity scopes (`profile`/`email`/`address`/`phone`) stripped from their granted scope before token issuance, per the RFC 6749 §3.3 narrowing allowance, with an OpenTelemetry span event naming what was dropped. `token_exchange` and `jwt_bearer` are exempted from this narrowing: their own authorization seams own whether the exchanged/asserted subject is an End-User, and the app opts in by granting `openid` itself.
2. **Consumer — ID Token producer.** The grant-type check in `IsApplicable` (above) is independent of the scope check, so a defect that somehow left `openid` on a non-end-user-grant token's scope still cannot make this producer synthesize an ID Token for it.
3. **Consumer — UserInfo.** The existing `openid`-in-token-scope check is kept, now provably correct because layer 1 guarantees it can never see `openid` on a `client_credentials` or `pre_authorized_code` token.

**One shared issuance routine.** The identical producer-walk loop present at all six token-issuing call sites (`authorization_code`, `refresh_token`, `client_credentials`, `token_exchange`, `jwt_bearer`, `pre_authorized_code`) is factored into a single `IssueTokensAsync` helper that owns the two-axis filter, key resolution, `BuildAsync`, claim-contributor merge, and signing, returning a structured per-response-field result. Each call site keeps only its grant-specific `IssuanceContext` construction and response shaping.

## Rationale

**Two axes instead of one.** A single `RequiredCapability` field cannot simultaneously mean "coarse tenant feature switch" and "the exact scope/grant condition under which this producer should fire" without one of those concerns leaking into the other, which is precisely how the access-token producer ended up gated on a capability that had nothing to do with its actual applicability. Keeping the axes separate lets each producer declare a real tenant-feature dependency (or none) while expressing its per-request logic in code, not in the capability-identifier vocabulary.

**Defense-in-depth over a single gate.** A single check — even a correct one — is one refactor away from silently becoming wrong again, and an identity-confusion defect (a machine's token read as a person's identity) is a security-relevant failure mode, not a cosmetic one. Three layers that each independently would have prevented the historical defect mean a regression in any one layer is caught by the other two, not by the next security audit.

**Grant identity as its own signal, not inferred from capability or scope.** Both historical defects trace back to the same root: `IssuanceContext` had no notion of which grant produced it, so every identity decision reached for a proxy (a capability that happened to be granted, or a scope token that happened to be present) instead of the actual fact the decision depends on. Adding `GrantType` lets every current and future producer or consumer ask the real question directly.

**One issuance routine.** Six byte-identical inlined loops is a correctness liability by construction — any fix to the walk (as this decision required) has to be applied and verified six times, or, more likely, applied once and left stale at the other five. Collapsing to one routine makes "correct at one site" mean "correct everywhere".

## Alternatives Considered

- **A single boolean or single capability expressing "identity issuance allowed".** Rejected: collapses the tenant-feature question ("does this tenant have OIDC configured?") and the per-request question ("is this specific token allowed to carry identity?") into one flag, which is exactly the shape that produced the original defect.
- **Inferring end-user status from scope alone, with no grant-identity field.** Rejected: this is the status quo the investigation found broken. A scope-only check has no independent signal to fall back on if the scope computation itself has a bug — which is what happened.
- **Gating only at the consumers (ID Token producer + UserInfo), leaving the source ungated.** Rejected: an app-configured claim contributor, a future producer, or an external system reading the granted scope directly all have no protection under a consumer-only design. Fixing the leak at its source removes it for every future consumer, not just the two known today.
- **A generic "capability implies grant" registration-time mapping instead of an explicit `IssuanceContext.GrantType` field.** Considered and rejected as more indirection for no benefit — the grant type is already known precisely at every one of the six call sites; carrying it through explicitly is simpler than reconstructing it from the matched capability.

## Consequences

1. A tenant configured for exactly one non-`authorization_code` token-issuing grant now correctly mints an access token; the five test files that worked around the prior defect by over-granting `OAuthAuthorizationCode` lose their reason to do so.
2. `client_credentials` and `pre_authorized_code` responses never carry `openid`-derived claims even if a caller requests `openid` in scope; the narrowing is silent to the caller (per RFC 6749 §3.3, narrowing does not require rejecting the request) but observable via the new OTel event.
3. Adding a new built-in or application-supplied `TokenProducer` follows a clear two-question template: does it need a tenant-feature gate (`RequiredCapability`), and what per-request condition governs it (`IsApplicable`, which may now read `GrantType`)? Neither question requires touching the six issuance call sites, which stay generic.
4. The six token-issuing call sites shrink to grant-specific setup and response shaping; the shared walk in `IssueTokensAsync` is the one place future producer-pipeline changes (a new key-resolution step, a new claim-contributor phase) need to land.
5. Applications composing their own `TokenProducer` for a non-standard token type inherit the same two-axis model and, if the token type carries identity claims, should apply the same three-layer discipline (source narrowing, grant-aware applicability, consumer-side re-check) rather than a single scope check.

## Status

Accepted.

## References

- [RFC 6749 §3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3) — scope narrowing.
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) — JWT access tokens.
- [OpenID Connect Core 1.0 §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) — ID Token.
- [OpenID Connect Core 1.0 §5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) — UserInfo Endpoint.
- [OpenID Connect Core 1.0 §5.4](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) — identity scopes (`profile`/`email`/`address`/`phone`).
- `draft-ietf-oauth-identity-assertion-authz-grant` — the ID-JAG mint's explicit-request-type pattern this decision generalizes.
- `documents/AuthorizationServerDesign.md` §9 — the resulting architecture in the working design document.

## Revision History

- Initial decision record, wave 4 of the CIMD arc (2026-07-18): grant identity on `IssuanceContext`, the optional-capability producer gate, grant-aware ID Token applicability, the three-layer `openid`⇒end-user invariant, and the shared `IssueTokensAsync` issuance routine.

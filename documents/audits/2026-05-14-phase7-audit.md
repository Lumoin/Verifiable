# OAuth Phase 7 Audit Report — Conformance, Rotation, Coverage, Consistency

**Date:** 2026-05-14
**Branch:** `oauth-subsystem`
**Baseline:** 2560 tests passed, 0 failed, 20 skipped (post-phase-6b)
**Scope:** Read-mostly review of the OAuth subsystem against external specs and internal design notes. No production code changes.

---

## Executive summary

The OAuth subsystem implements the **bulk of the OAuth 2.1 + RFC 9700 + RFC 9449 protocol surface correctly**. Most of the findings are real but narrow — clusters around three areas:

1. **DPoP wire integration is incomplete on the issuance side.** Phase 6b landed DPoP enforcement and JTI replay defense, but the issued access token JWT does not carry the `cnf.jkt` confirmation claim and the token response always emits `"token_type":"Bearer"`. The binding is recorded internally (`ServerTokenIssuedState.BoundJwkThumbprint`) but never reaches the wire. This is the highest-severity finding.
2. **The PKCE-PAR path lacks the registered-redirect-uri exact-match check** that the JAR-PAR path performs. RFC 9700 §2.1 + OAuth 2.1 §2.3.1 mandate it.
3. **No AS-side refresh-token grant handler exists** — the client-side `RefreshAsync` POSTs a `grant_type=refresh_token` request that no matching server matcher accepts. The library is missing roughly half of RFC 6749 §6 / OAuth 2.1 §4.3.

The rotation surfaces have meaningful drift between signing keys and HMAC keys (the HMAC side is the newer, more deliberate design); rotation tests on the signing side exercise JWKS publication but not the resolver lookup-by-kid semantics that the HMAC tests cover. Test coverage is solid (71% line / 48% branch on `Verifiable.OAuth`) with a few clear cold spots (`Oidc10IdTokenProducer.cs` at 0%, `ValidationChecks.cs` at 40% — many composable checks are wired into OID4VP validators but not exercised end-to-end).

**Findings counts:**

- Section 1 — OAuth 2.1 MUST audit: **8 GAPs, 6 PARTIALs, 40+ IMPLEMENTED, 4 OUT-OF-SCOPE**
- Section 2 — Rotation surface parity: **4 drift findings, 3 missing test scenarios**
- Section 3 — Coverage audit: **6 priority cold spots, 9 adversarial-gap recommendations, 4 opportunistic refactor candidates**
- Section 4 — Cross-cutting consistency: **mostly clean** — 1 borderline DebuggerDisplay omission, no naming drift, principled slot-shape divergence

**Top 5 recommended follow-up MDs in priority order:**

1. **MD-phase8-dpop-issuance-completion** — Wire `cnf.jkt` into the Rfc9068 access token JWT and switch `token_type` to `DPoP` when the issuance ran the DPoP enforcement block. Closes the highest-severity gap.
2. **MD-phase8-refresh-token-grant** — Implement the AS-side `grant_type=refresh_token` matcher. Includes rotation policy (RFC 9700 §2.2.2 — public clients MUST rotate or sender-constrain), and DPoP key-binding check on the refresh.
3. **MD-phase8-pkce-par-redirect-uri-check** — Add the `AllowedRedirectUris.Contains` check at PKCE-PAR. Small surgical change; aligns with the JAR-PAR path. Also add `Cache-Control: no-store` on token-bearing responses and fix the `Rfc9068AccessTokenProducer` issuer-URL truncation (the producer strips path from a multi-tenant issuer URL).
4. **MD-phase8-signing-key-resolver-parity** — Synchronise `ServerSigningKeyResolverDelegate` with the HMAC-side shape: optional `kid` for "current-for-issuance", echo-back kid in the result record, ship an `InProcessSigningKeyResolver` default. Extend `JwksRotationTests` with the four resolver-level scenarios (current/by-kid/unknown/rotation-overlap) that `InProcessHmacKeyResolverTests` covers.
5. **MD-phase8-validation-coverage-fillout** — Either prune unused `ValidationChecks` functions or add end-to-end tests that exercise them. The 40% coverage figure conceals a real signal: ~30 named checks that don't fire in any test path.

The OIDC implementation track and the deployment stress test (referenced at handoff time) should land after items 1–3. Items 4–5 are smaller and can land alongside or after.

---

## Section 1 — OAuth 2.1 MUST audit

### Source documents

| Spec | URL | Revision read |
|---|---|---|
| draft-ietf-oauth-v2-1 | https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1 | latest at 2026-05-14 |
| RFC 9700 (OAuth Security BCP) | https://www.rfc-editor.org/rfc/rfc9700 | published |
| RFC 9449 (DPoP) | https://www.rfc-editor.org/rfc/rfc9449 | published |
| RFC 9126 (PAR) | https://www.rfc-editor.org/rfc/rfc9126 | published |
| RFC 9101 (JAR) | https://www.rfc-editor.org/rfc/rfc9101 | published |
| RFC 9207 (iss parameter) | https://www.rfc-editor.org/rfc/rfc9207 | published |
| RFC 7591 (Dynamic Registration) | https://www.rfc-editor.org/rfc/rfc7591 | published |
| RFC 7592 (Client Configuration) | https://www.rfc-editor.org/rfc/rfc7592 | published |

~157 wire-behaviour MUST/MUST NOT/REQUIRED statements were extracted across these eight specs; the audit below summarises by status with details on every GAP and PARTIAL.

### draft-ietf-oauth-v2-1 + RFC 9700 (~50 MUSTs reviewed)

**GAPs:**

- **[RFC9700-§2.1] / [OAUTH-2.1-§2.3.1] Redirect URI exact-match — MISSING on PKCE-PAR path.**
  Status: GAP. The JAR-PAR `BuildInputAsync` at `src/Verifiable.OAuth/AuthCode/AuthCodeEndpoints.cs:988` validates `requestObject.RedirectUri` against `registration.AllowedRedirectUris.Contains(...)`. The plain PKCE-PAR `BuildInputAsync` (same file, lines 235-241) parses the `redirect_uri` form field into a `Uri` but never checks it against the registered set. Adversarial impact: a request with a malicious `redirect_uri` that the AS never registered is accepted at PAR and the code is later redirected to it. Severity: **HIGH**.

- **[OAUTH-2.1-§3.2.3] `Cache-Control: no-store` on token-bearing responses — NOT EMITTED.**
  Status: GAP. The token endpoint response in `AuthCodeEndpoints.cs:1492-1521` builds a JSON body and returns `ServerHttpResponse.Ok(...)`. No `Cache-Control` header is set. Grepping `src/Verifiable.OAuth` for `Cache-Control` returns zero matches. Severity: **MEDIUM** (most caches respect Content-Type but the spec is explicit).

- **[RFC6749-§6] / [OAUTH-2.1-§4.3] Refresh-token grant — NOT IMPLEMENTED ON AS SIDE.**
  Status: GAP. `OAuthRequestParameters.GrantTypeRefreshToken = "refresh_token"` exists. The client-side `AuthCodeFlowHandlers.RefreshAsync` at `AuthCodeFlowHandlers.cs:474` builds a `grant_type=refresh_token` POST and dispatches it. There is no AS-side matcher in `AuthCodeEndpoints.cs` for that `grant_type`; the request would route to the authorization-code Token matcher whose match predicate checks `grant_type == authorization_code` (line 1137) and fall through to 404. Severity: **HIGH** for any deployment relying on refresh.

- **[RFC9700-§2.2.2] Refresh-token rotation or sender-constraint for public clients — NOT ENFORCED.**
  Status: GAP. As a corollary of the missing AS-side refresh grant: there is no rotation policy and no DPoP-binding enforcement on refresh.

- **[RFC9449-§5] Token response `token_type` MUST be `DPoP` for DPoP-bound issuance — HARDCODED Bearer.**
  Status: GAP. `AuthCodeEndpoints.cs:1495` writes `"token_type":"Bearer"` unconditionally, even when the DPoP enforcement block at lines 1217-1333 has just bound the token to `cnf.jkt`. Severity: **HIGH** for any RS that uses `token_type` to discriminate the scheme.

- **[RFC9449-§6.1] DPoP access tokens MUST carry `cnf` with `jkt` member — NOT EMBEDDED.**
  Status: GAP. The `Rfc9068AccessTokenProducer.BuildAsync` in `src/Verifiable.OAuth/Server/Rfc9068AccessTokenProducer.cs:129-183` constructs the JWT payload from `JwtPayload.ForAccessToken(...)` but never adds a `cnf` claim. The producer does not even read `BoundJwkThumbprint` — that value is set on `ServerTokenIssuedState` after the producer has run, so the JWT payload is signed without the binding. Severity: **HIGH** — DPoP-bound tokens are issued without the proof binding the RS expects in §7.

- **[RFC8414] `iss` claim issuer URL — RFC9068 producer strips path component.**
  Status: GAP. `Rfc9068AccessTokenProducer.BuildAsync` line 146 sets `string issuerValue = context.IssuerUri.GetLeftPart(UriPartial.Authority);`. For a multi-tenant deployment where `IssuerUri = https://issuer.example.com/tenant-a`, the access token's `iss` claim becomes `https://issuer.example.com` (no tenant). This conflicts with how `BoundJwkThumbprint` and JTI-replay correlation use `issuerUri.OriginalString` (preserving the path; `AuthCodeEndpoints.cs:1300` and `:1319`). Severity: **MEDIUM** — degrades multi-tenant per-tenant token scoping; tests pass because the gate test issuer happens to use authority-only.

- **[RFC9126-§2.1] PAR endpoint MUST authenticate the client — PUBLIC-CLIENT-ONLY at present.**
  Status: PARTIAL/GAP depending on reading. The PAR `BuildInputAsync` (line 208) requires `client_id` in the body but performs no client_secret_basic / client_secret_post / private_key_jwt / mTLS check. For public clients, PKCE binding is the substitute; for confidential clients the spec requires actual authentication. The library currently has no `ClientAuthenticationMethod`-bearing authentication matcher anywhere — public-client only. Severity: **MEDIUM** (matches the present scope; flag when confidential-client support is added).

**PARTIALs:**

- **[OAUTH-2.1-§7.5.2] / [RFC9700-§4.2.4] Single-use authorization code.** Status: PARTIAL. Enforced implicitly by the state machine: after token exchange, `ServerCodeIssuedState` transitions to `ServerTokenIssuedState` (terminal — see `AuthCodeServerFlowTransitions.cs:166`), and a second redemption attempt at `BuildToken.BuildInputAsync` line 1155 will find `currentState is not ServerCodeIssuedState` and return `BadRequest(InvalidGrant, "Flow not in expected state.")`. Implemented but not directly tested. **Test gap.** RFC 9700 §4.2.4 SHOULD: on second redemption, revoke all tokens issued for that code — **not implemented**.

- **[RFC9700-§4.5.3.2] Until ID-Token nonce verification succeeds, client MUST discard tokens.** Status: PARTIAL — applicable only when OIDC is in play. The library has `Oidc10IdTokenProducer.cs` (currently at 0% coverage; see Section 3) but the client-side callback validator does not enforce ID-Token-nonce binding before persisting `AuthorizationCodeReceivedState`. Out of scope until OIDC track lands.

- **[RFC9207-§2] AS MUST return `iss` in every authorization response.** Status: PARTIAL. `AuthCodeEndpoints.cs:1640-1648` emits `iss` only when `context.EmitIssOnRedirect` is true. The HAIP/FAPI20 policy profiles set this to true. The RFC 6749-with-PKCE profile sets it to false. The spec MUST applies to *AS that support the parameter*, so the rfc6749 baseline is technically compliant by not advertising support. Verify that `authorization_response_iss_parameter_supported` metadata flag is emitted only when EmitIssOnRedirect is true. (Not verified in this pass.)

- **[OAUTH-2.1-§3.1] AS MUST ignore unrecognized authorization parameters.** Status: PARTIAL — matcher chain is positive-match (look for specific fields) but no explicit ignore-unknown logic. Probably fine because fields are read selectively; not verified end-to-end.

- **[OAUTH-2.1-§3.1] Parameters MUST NOT appear more than once.** Status: PARTIAL. The library reads via `RequestFields` (`Dictionary<string,string>`) which collapses duplicates — but the wire format may have allowed duplicates before reaching this layer. The skin (the application's HTTP layer) is responsible for rejecting duplicate query parameters; the library has no defence here. Documented as a skin obligation; not enforced.

- **[OAUTH-2.1-§3.1] CORS MUST NOT be supported at the authorization endpoint.** Status: PARTIAL — out-of-scope. The library produces `ServerHttpResponse` records; the application's skin decides which CORS headers to attach. Library should document this constraint in the discovery metadata or authorize-endpoint XML doc; currently not noted.

**IMPLEMENTED (high confidence):**

- [OAUTH-2.1-§7.5.1.2] PKCE verifier ≥43 chars / 256 bits entropy — `src/Verifiable.OAuth/Pkce/PkceGeneration.cs:26` uses 32 bytes from `CryptographicKeyEvents.GenerateNonce`. ✅
- [OAUTH-2.1-§7.5.2] PKCE method `S256` enforced — `IsAcceptedPkceMethod` at `AuthCodeEndpoints.cs:1662` checks against `OAuthRequestParameters.CodeChallengeMethodS256`; strict default policy (`PkceMethodSet.S256Only`) rejects `plain`. Tested in `OAuthAttackMitigationTests.Rfc9700Section4Point8PkceDowngradeCodeChallengeMethodIsAlwaysS256`. ✅
- [OAUTH-2.1-§4.1.3] PKCE verifier checked at token endpoint — `AuthCodeEndpoints.cs:1161-1180` computes `SHA256(verifier)` and ordinal-compares against `codeState.CodeChallenge`. ✅
- [OAUTH-2.1-§4.1.3] `client_id` mismatch rejected at token endpoint — `AuthCodeEndpoints.cs:1182-1187`. ✅
- [RFC9207-§2.4] iss exact-string comparison on client — `ValidationChecks.CheckCallbackIssuerMatches` at `ValidationChecks.cs:91-94` uses `StringComparison.Ordinal`. ✅
- [RFC9207-§2.4] iss-mismatch rejection — same site, returns `Failure` outcome which the callback handler propagates. Tested in `OAuthAttackMitigationTests.cs:144-165`. ✅
- [RFC9700-§4.4.2] Client stores issuer per request — `ParCompletedState.ExpectedIssuer` set at `AuthCodeFlowHandlers.cs:148`. ✅
- [RFC9700-§4.1] Client state CSRF binding — `ValidationChecks.CheckCallbackStateMatchesFlow` enforces ordinal match between state and FlowId. ✅
- [RFC9101-§10] JAR audience validation — `ValidateJarAudienceAsync` at `AuthCodeEndpoints.cs:1028-1049`. ✅
- [RFC9101-§6.2] JAR signature verification rejects `alg:none` — `WellKnownJwaValues.IsEcdsa` plus the verification path in `DpopProofValidation.cs:77-78` and analogous JAR paths. ✅
- [RFC9126-§2.2] PAR response shape — `AuthCodeEndpoints.cs:294` writes `{"request_uri":...,"expires_in":...}`. ✅ (Note: spec says `201 Created`; library uses `Ok` = 200. Minor finding.)
- [RFC9126-§4] request_uri single-use + expires — enforced via the secondary-index lookup (used once, then state transitions away from `ParRequestReceivedState`). ✅
- [RFC9449-§4.2] DPoP proof construction — `DpopProofConstruction.BuildAsync` (phase 6a). Tested in `DpopProofConstructionTests`. ✅
- [RFC9449-§4.3] DPoP proof validation MUSTs (every claim check, signature verify, jwk private-key scan, htm/htu match, iat skew, nonce/ath checks) — `DpopProofValidation.ValidateAsync` at `src/Verifiable.OAuth/Dpop/DpopProofValidation.cs:29-172`. 100% line coverage. Tested in `DpopProofValidationTests` (13 tests covering each rejection reason). ✅
- [RFC9449-§8] Server-issued nonce + use_dpop_nonce challenge — `DefaultDpopNonceIssuance/Validation` + `AuthCodeEndpoints.cs:1238-1297` (phase 6b). Tested by `DpopEndToEndTests.TokenIssuanceAndResourceCallValidateUnderDpopProtocol`. ✅
- [RFC9449-§11.1] JTI replay defence — `AuthCodeEndpoints.cs:1299-1330` (phase 6b). ✅
- [RFC7591-§3.1/3.2] Dynamic registration POST shape + response — `src/Verifiable.OAuth/Server/Registration/RegistrationEndpoints.cs`. 90% line coverage. ✅
- [RFC7592-§2] Management endpoint Bearer auth — `ValidateRegistrationAccessTokenAsync` slot + matcher gates. ✅

**OUT-OF-SCOPE (documented):**

- Implicit grant (`response_type=token`) — OAuth 2.1 removed; not implemented (correct).
- Resource Owner Password Credentials grant — OAuth 2.1 removed; not implemented (correct).
- Device flow (RFC 8628) — explicitly deferred per design notes; not implemented.
- Resource Server enforcement of DPoP `ath` — handled by the application playing the RS role; library exposes `DpopProofValidation.ValidateAsync` for that use. Tested in `DpopEndToEndTests` step 5.

### Specific 1.3 checklist results

| Check | Status | Notes |
|---|---|---|
| `iss` comparison uses `OriginalString` ordinal | ✅ IMPLEMENTED | `ValidationChecks.cs:93`, `:114`. State carries `ExpectedIssuer` as `OriginalString` (set at `AuthCodeFlowHandlers.cs:148,617`). No `.ToString()` or `.AbsoluteUri` found in iss-comparison sites. |
| PKCE S256 enforcement | ✅ IMPLEMENTED | Three sites: PAR `BuildInputAsync` (line 227), JAR PAR (line 1008), token endpoint (line 1175 verifies via re-hash). |
| State CSRF binding | ✅ IMPLEMENTED | `ValidationChecks.CheckCallbackStateMatchesFlow` + `CheckRequestStatePresent`. |
| PKCE verifier entropy | ✅ IMPLEMENTED | 32 bytes CSPRNG via `CryptographicKeyEvents.GenerateNonce`. |
| DPoP htm / htu / iat | ✅ IMPLEMENTED | `DpopProofValidation.cs:120-134`. |
| client_assertion jti replay | ⚠️ NOT IMPLEMENTED | No `private_key_jwt` or `client_assertion` flow exists. Library is public-client-only. |
| Refresh token rotation | ❌ GAP | No AS-side refresh implementation; rotation is moot. |

### Section 1 findings summary

```
draft-ietf-oauth-v2-1 + RFC 9700 (50 MUSTs reviewed)
- 36 IMPLEMENTED
-  6 PARTIAL  (single-use code direct-test, nonce-before-token discard, iss-on-every-response under policy, ignore-unknown, no-duplicate-params, CORS doc)
-  8 GAP      (redirect_uri PKCE-PAR check, Cache-Control: no-store, refresh grant absent, rotation absent, token_type Bearer, cnf.jkt absent, iss URL truncation, PAR client auth)
-  4 OUT-OF-SCOPE (implicit, password, device, RS)

RFC 9449 (DPoP) (~40 MUSTs reviewed)
- 35 IMPLEMENTED  (proof construction + validation + nonce + JTI replay)
-  0 PARTIAL
-  5 GAP        (cnf.jkt in issued JWT, token_type=DPoP wire, refresh-token key-binding, dpop_jkt at PAR per §10.1, DPoP refresh rotation per §5)

RFC 9126 (PAR) + RFC 9101 (JAR) + RFC 9207 (iss) — ~37 MUSTs
- 32 IMPLEMENTED
-  3 PARTIAL  (201 Created vs 200 OK on PAR response, iss-on-every-response under policy, ignore-outer-vs-Request-Object precedence)
-  2 GAP      (PAR confidential-client auth, dpop_jkt parameter cross-check)

RFC 7591 / RFC 7592 — ~17 MUSTs
- 15 IMPLEMENTED
-  0 PARTIAL
-  0 GAP
-  2 OUT-OF-SCOPE (software statement signature verification — present but tested only on happy path)
```

### Recommended follow-up MDs from Section 1

- **MD: dpop-issuance-completion** — cnf.jkt embedding + token_type=DPoP. (Item 1 in executive list.)
- **MD: refresh-grant-implementation** — AS-side refresh matcher + rotation policy + DPoP key-binding check on refresh. (Item 2.)
- **MD: tighten-pkce-par + token-response-headers + iss-url-fix** — three small things, one focused MD. (Item 3.)

---

## Section 2 — Rotation surface synchronization

### Signing side inventory

- `ServerSigningKeyResolverDelegate(keyId, context, ct) → PrivateKeyMemory?` — `src/Verifiable.OAuth/Server/AuthorizationServerDelegates.cs:102`
- `ServerVerificationKeyResolverDelegate(keyId, context, ct) → PublicKeyMemory?` — same file, line 113
- `BuildJwksDocumentDelegate(registration, context, ct) → JwksDocument` — line 161
- `SerializeJwksDelegate(publicKey, context, ct) → string` — line 122 (largely unused — JWKS is serialized inside `MetadataEndpoints` directly)
- `SelectSigningKeyDelegate` — `AuthorizationServerCryptography.cs:52` (optional; selects which kid to sign with)
- **No `InProcessSigningKeyResolver` default ships.** The test fixture (`TestHostShell`) wires its own dictionary-backed resolver.
- Test file: `test/Verifiable.Tests/OAuth/JwksRotationTests.cs` (6 tests).

### HMAC side inventory (phase 6b)

- `ResolveServerHmacKeyDelegate(kid?, tenantId, context, ct) → HmacKeyResolution?` — `src/Verifiable.OAuth/Server/ResolveServerHmacKeyDelegate.cs:29`
- `HmacKeyResolution { Key, Kid }` — `src/Verifiable.OAuth/Server/HmacKeyResolution.cs`
- `InProcessHmacKeyResolver(initialKey, initialKid, maxRetainedKeys = 4)` — ships as the default
- Test files: `InProcessHmacKeyResolverTests.cs` (6 tests) + `DpopRotationTests.cs` (1 test).

### Cross-side parity table

| Property | Signing | HMAC | Match? |
|---|---|---|---|
| Optional `kid` parameter (null = current for issuance) | ❌ kid is required | ✅ optional (null = current) | **DRIFT** |
| Returns wrapper record echoing kid back | ❌ returns `Key?` directly | ✅ `HmacKeyResolution{Key,Kid}` | **DRIFT** |
| In-process default backing exists | ❌ no `InProcessSigningKeyResolver` | ✅ `InProcessHmacKeyResolver` | **DRIFT** |
| Default supports current + N retired with bounded set | ❌ no default to evaluate | ✅ `maxRetainedKeys = 4` | **DRIFT** |
| Tests cover: current / by-kid / unknown / eviction | ❌ JWKS publication only (different concern) | ✅ all four | **DRIFT** |
| `Validate()` checks slot wired when required | ✅ required in `Validate()` | n/a (DPoP is opt-in) | principled difference |
| Documented in `AuthorizationServerDesign.md` §3 | ✅ table on §3 middle layer | ✅ same table, "planned, DPoP" annotation now stale | minor (doc update — annotation can be removed; the design landed) |
| Takes `tenantId` parameter | ❌ no | ✅ yes | **DRIFT** |

### Drift findings

- **D-1 (severity HIGH).** `ServerSigningKeyResolverDelegate` requires `keyId` and has no "give me current" mode. Every call site that needs the current signing key currently goes through `ClientRecord.GetDefaultSigningKeyId(usage)` or `SelectSigningKey` — a two-stage select-then-resolve. The HMAC side collapsed this to a single delegate call with optional kid. The HMAC pattern is the better design (less indirection, less to wire). Recommendation: synchronise signing side to match. Maintenance the SelectSigningKey delegate can stay (caller-context selection logic) but the resolver should accept `kid?`.
- **D-2 (severity MEDIUM).** No `InProcessSigningKeyResolver` parallel ships. Test fixtures duplicate the dictionary backing per test class. The HMAC side ships one with rotation semantics built in. Recommendation: add `InProcessSigningKeyResolver` to `Verifiable.OAuth/Server/` with the same `Rotate(newKey, newKid)` + `maxRetainedKeys` pattern. Tests in fixtures simplify.
- **D-3 (severity LOW).** `ResolveServerHmacKeyDelegate` takes `tenantId` but `ServerSigningKeyResolverDelegate` does not. Documented rationale in the signing-side XML doc: "the registration is already tenant-scoped, so this delegate does not take a tenant parameter directly" (line 96). This is principled — but if the HMAC side is the canonical shape going forward, tenants should be threaded through both. Recommendation: thread `tenantId` through `ServerSigningKeyResolverDelegate` for parity; the inert parameter at call sites that don't need it is cheap.
- **D-4 (severity LOW, doc only).** `AuthorizationServerDesign.md` §3 table still marks `ResolveServerHmacKeyDelegate` as "planned, DPoP". The work landed in phase 6b; remove the parenthetical annotation.

### Rotation scenario coverage

**HMAC side (canonical via `InProcessHmacKeyResolverTests` + `DpopRotationTests`):**

| Scenario | Covered |
|---|---|
| 1. Pre-rotation: resolver returns current under kid=A | ✅ `ResolveCurrentReturnsInitialKey`, `ResolveByKidReturnsMatch` |
| 2. Mid-rotation: kid=A returns retired material, kid=null returns kid=B current | ✅ `RotateMovesCurrentToRetired` + `ResolveRetiredKidReturnsRetiredKey` |
| 3. Post-window: rotating beyond maxRetainedKeys evicts oldest | ✅ `RotateBeyondMaxRetainedDropsOldest` |
| 4. Unknown kid returns null | ✅ `ResolveUnknownKidReturnsNull` |
| 5. Round-trip: artefact produced under retired key still validates | ✅ `NonceUnderRetiredKidStillValidatesDuringOverlapWindow` |

**Signing side (`JwksRotationTests`):**

| Scenario | Covered |
|---|---|
| 1. Pre-rotation: JWKS publishes Current+Incoming | ✅ `JwksIncludesIncomingKeysBeforeActivation` |
| 2. Mid-rotation: JWKS publishes Current+Retiring | ✅ `JwksIncludesRetiringKeysInGraceWindow` |
| 3. Post-window: JWKS omits Historical | ✅ `JwksOmitsHistoricalKeys` |
| 4. Resolver returns null on unknown kid | ❌ MISSING — there is no `ResolveAsync(unknownKid)` test |
| 5. Round-trip: JWS signed by retiring key validates against new resolver | ❌ MISSING — JWKS-publication-only coverage; no integration that signs with key A, rotates A to Retiring, and verifies the JWS still parses against the published key set |
| Resolver "give-me-current" (kid=null) | n/a — current delegate shape doesn't support this; would land with D-1 fix |

### Recommended follow-up MD from Section 2

- **MD: signing-key-resolver-parity** — addresses D-1, D-2, D-3 in one focused brief. Extends `JwksRotationTests` (or adds a new `InProcessSigningKeyResolverTests`) with the missing two scenarios. Cosmetic doc fix (D-4) can ride along.

---

## Section 3 — Test coverage audit

### Coverage tooling

- **Wired.** `test/Verifiable.Tests/Verifiable.Tests.csproj` references `Microsoft.Testing.Extensions.CodeCoverage` (versionOverride 18.6.2) via the MSTest SDK.
- **Invocation.** `cd test/Verifiable.Tests && dotnet test --no-build -- --coverage --coverage-output-format cobertura --coverage-output coverage.cobertura.xml`
- **Output.** `<repo>/bin/Debug/net10.0/TestResults/coverage.cobertura.xml` (the project's `OutputPath` redirect surfaces it at `bin/...` rather than under `test/...`).
- **Overall:** 62.3% line / 48.8% branch across all packages.
- **Verifiable.OAuth specifically:** 71.2% line / 47.8% branch.

### Handler coverage rubric

(Score is line-coverage% / branch-coverage% from the cobertura report; "x" / "—" indicates a qualitative read of test files for each adversarial axis.)

| Handler | Coverage | Happy | Missing-field | Malformed | Wrong-cred | Expiry | Replay | Concurrency |
|---|---|---|---|---|---|---|---|---|
| `AuthCodeEndpoints.BuildPar` (PKCE) | 88% / 83% | ✅ | ✅ | ✅ | partial | ✅ | n/a | — |
| `AuthCodeEndpoints.BuildJarPar` | 88% / 83% | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | — |
| `AuthCodeEndpoints.BuildAuthorize` | 88% / 83% | ✅ | ✅ | partial | partial | ✅ | n/a | — |
| `AuthCodeEndpoints.BuildToken` (with DPoP) | 88% / 83% | ✅ | ✅ | partial | ✅ | ✅ | ✅ (JTI) | — |
| `Oid4VpEndpoints.*` | 100% / 100% | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `RegistrationEndpoints.HandleCreateAsync` | 90% / 100% | ✅ | ✅ | partial | n/a | n/a | n/a | — |
| `RegistrationEndpoints.HandleUpdateAsync` | 90% / 100% | ✅ | ✅ | partial | ✅ | n/a | n/a | — |
| `DpopProofValidation.ValidateAsync` | 100% / — | ✅ | ✅ | ✅ | ✅ | ✅ | n/a (delegated) | — |
| `DefaultDpopNonceValidation.ValidateAsync` | 95% / 100% | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | — |
| `InProcessHmacKeyResolver.ResolveAsync` | 100% / 100% | ✅ | ✅ | n/a | ✅ | n/a (no time) | n/a | — |
| `MetadataEndpoints` (discovery + JWKS) | 70% / 44% | ✅ | partial | — | n/a | n/a | n/a | — |
| `AuthCodeFlowHandlers.HandleParAsync` (client) | 81% / 100% | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | — |
| `AuthCodeFlowHandlers.HandleCallbackAsync` | 81% / 100% | ✅ | ✅ | partial | ✅ | ✅ | n/a | — |
| `AuthCodeFlowHandlers.HandleTokenAsync` (DPoP retry) | 81% / 100% | ✅ | ✅ | ✅ | ✅ | n/a | n/a | — |

(Concurrency column: no concurrent-load tests exist for any handler. The library declares itself thread-safe at the delegate level; no race tests are wired. This is consistent with the design notes' "applications are responsible for backend SLO" stance, but a Section-3 finding worth noting.)

### Priority cold spots

- **`Oidc10IdTokenProducer.cs` — 0% line coverage.** Either dead code or wholly untested. If OIDC ID Token issuance is intended to ship, this is the OIDC track's lead test gap.
- **`TokenProducerSet.cs` — 14% line.** Most of the set's lookup/iteration logic is unexercised.
- **`ValidationChecks.cs` — 40% line.** Roughly 30 named checks; about half are wired into the OID4VP validator profile and exercised through that path, the other half (KB-JWT-specific, RFC-7523 hooks) aren't reached. Some functions may be dead.
- **`VerifierClientMetadata.cs` — 0% line, 58 lines.** Full file uncovered.
- **`WalletMetadata.cs` — 0% line, 30 lines.** Same.
- **`MetadataEndpoints.cs` — 70% line / 44% branch.** Many discovery-document rare-branch paths uncovered.

### Adversarial input opportunities

Per the §3.3 list, each scenario mapped:

| Scenario | Test exists? | Recommendation |
|---|---|---|
| Token endpoint: valid PKCE verifier but wrong code | ❌ | RECOMMENDED |
| Token endpoint: valid code but wrong PKCE verifier | ✅ (`AuthCodeEndpoints.cs:1175-1180` `InvalidGrant`; covered indirectly by `OAuthAttackMitigationTests.Rfc9700Section4Point5...`) | — |
| Authorize: redirect_uri mismatch between PAR and authorize | ❌ (PAR doesn't validate; see Section 1 GAP) | RECOMMENDED after Section-1 fix |
| PAR: client_id mismatching authenticated client | ⚠️ partial — for JAR-PAR (`AuthCodeEndpoints.cs` around the JAR client_id check); not for PKCE-PAR (no client auth) | RECOMMENDED when confidential client auth lands |
| JAR: valid signature, wrong audience | ✅ tested in `JarParTests` | — |
| DPoP proof: valid signature, tampered claims after signing | ✅ `DpopProofValidationTests.ValidateAsyncRejectsBadSignature` (post-phase-6a deflake) | — |
| DPoP: htm=POST against GET endpoint | ✅ `DpopProofValidationTests.ValidateAsyncRejectsWrongHtm` | — |
| DPoP: htu matches path but wrong host | ✅ `DpopProofValidationTests.ValidateAsyncRejectsWrongHtu` | — |
| Token request: `client_assertion` jti replay | n/a (no client_assertion flow) | OUT-OF-SCOPE for now |
| AuthCode: state altered between request and callback | ✅ `ValidationChecks.CheckCallbackStateMatchesFlow` + tested in `AuthCodeFlowTests` | — |
| Token endpoint: second redemption of same code | ⚠️ — implicit-via-state-machine but no direct test | RECOMMENDED |
| Token endpoint: response missing `Cache-Control: no-store` | ❌ (header isn't emitted; see Section 1 GAP) | follow Section-1 fix |
| DPoP-bound token: `token_type` wire value is `DPoP` | ❌ (hardcoded Bearer; see Section 1 GAP) | follow Section-1 fix |
| DPoP-bound token JWT: contains `cnf.jkt` | ❌ (not embedded; see Section 1 GAP) | follow Section-1 fix |
| RS-side: DPoP-bound token presented as `Authorization: Bearer` (must reject) | ❌ — library exposes the binding info; the application's RS code is responsible for the check. Out of library scope. Document the expectation. | DOC RECOMMENDATION |
| Refresh-token rotation | n/a (no AS refresh impl) | OUT-OF-SCOPE for now |
| Token request: missing `redirect_uri` when one was used at /authorize (RFC 6749 §4.1.3) | ❌ — library doesn't check redirect_uri at the token endpoint at all; relies on the bound-state RedirectUri | LOW PRIORITY (state-machine binding is the substitute) |

### Opportunistic refactor candidates

Smells noticed while reading:

- **`AuthCodeEndpoints.cs`** is 1700+ lines. `BuildPar`, `BuildJarPar`, `BuildAuthorize`, `BuildAuthorizeJarByValue`, `BuildToken`, `BuildRevocation`, `BuildIntrospection` could move to one-file-per-endpoint. Not a discipline violation, but the size is starting to bite on test mapping. Recommendation: defer; a focused split MD post-OIDC track.
- **DPoP enforcement block** (`AuthCodeEndpoints.cs:1217-1333`) is a ~115-line inline block inside `BuildToken.BuildInputAsync`. Splitting to a named `ValidateDpopAndPersistJtiAsync` helper inside `AuthCodeEndpoints` would aid readability and let the future refresh-token grant share the same enforcement. Recommendation: include this split in the refresh-grant MD.
- **`AuthCodeEndpoints.cs:1492-1521` token response body composition** uses ad-hoc `StringBuilder.Append("\",\"")` JSON building. Two other endpoint responses (PAR at line 294, BuildAuthorize at line 1640) use a similar shape. Same pattern at `RegistrationEndpoints.cs:566`. Could share a helper `BuildTokenResponseJson(IssuedTokenSet, audit, scope)`. Aesthetic; not urgent.
- **`Rfc9068AccessTokenProducer.cs:146` `issuerValue = context.IssuerUri.GetLeftPart(UriPartial.Authority)`** vs everywhere else in `AuthCodeEndpoints.cs` using `issuerUri.OriginalString`. Inconsistency in how the issuer is rendered. Fix per Section 1 GAP recommendation.

### Recommended follow-up MD from Section 3

- **MD: validation-coverage-fillout** — Decide which `ValidationChecks` functions are dead vs. genuinely-needed-but-untested. For genuinely-needed: add end-to-end tests; for dead: remove. Also addresses `Oidc10IdTokenProducer.cs` 0% (defer to the OIDC implementation MD), `TokenProducerSet.cs` 14% (small focused), `VerifierClientMetadata.cs` + `WalletMetadata.cs` 0% (probably exercised indirectly through serialization but not directly).
- **MD: code-reuse-test** — A small set of adversarial tests: second code redemption, redirect_uri mismatch after PKCE-PAR fix, Cache-Control assertion on token response. ~5 tests total; can ride with the Section-1 fix MD.

---

## Section 4 — Cross-cutting consistency

### Naming drift

Surveyed delegate-name prefixes across `src/Verifiable.OAuth`:

- `Resolve*Delegate` (15 instances): tenant→record, key id→key material, issuer→Uri, audience→list, etc.
- `Load*Delegate` (3 instances): `LoadClientRegistration`, `LoadFlowState`, `LoadServerFlowState` — DB-shaped lookups.
- `Save*Delegate` (1 instance): `SaveServerFlowState` — DB-shaped writes.
- `Send*Delegate` (5 instances): all transport (POST/GET/PUT/DELETE/form) on the client side.
- `Parse*Delegate` (~6 instances): wire→typed.
- `Lookup`: one instance, `DpopNonceLookupDelegate(authority) → string?`. Synchronous, no I/O semantics; pure cache lookup. Conceptually distinct from `Resolve*` (which may involve I/O). The name is principled.
- `Get*Delegate`: zero instances.
- `Fetch*Delegate`: zero instances.

**Finding:** naming is **substantially consistent**. `Resolve*` for "given identifier, return material or null"; `Load*` for "given key, return record"; `Send*` for transport; `Parse*` for wire→typed. The single `Lookup` is in a different semantic bucket (synchronous cache read) and the name is appropriate.

One minor note: `LoadFlowStateDelegate` (client side, `AuthCodeFlowDelegates.cs:46`) and `LoadServerFlowStateDelegate` (server side) are semantically near-identical but the server-side carries `(tenantId, correlationKey)` while the client-side just carries `(flowId)`. The `Server` prefix on the server-side version disambiguates well. ✅

### Slot shape audit

- `AuthorizationServerIntegration`: **21 slots, all `{ get; set; }`.** Allows post-construction wiring (used by `TestHostShell.EnableDpop()`).
- `OAuthClientInfrastructure`: **23 slots, all `{ get; private init; }`.** Set-once via `Create(...)` factory.

This is **principled drift**: the AS-side supports late wiring because tests and applications may need to attach DPoP/policy delegates after the server's primary integration is set; the client-side is immutable post-`Create` because `Create` performs the either-both-or-neither validation (`OAuthClientInfrastructure.cs:255-267`).

### `DebuggerDisplay` audit

- 204 of ~323 files in `src/Verifiable.OAuth` carry `[DebuggerDisplay]`.
- Files missing it but holding stateful types (records/classes with `required` `init` properties):
  - `src/Verifiable.OAuth/Dpop/DpopJwsPartParser.cs` — `sealed record` with two `Func<>` delegate properties. Borderline: not data state, just delegate wiring.
  - `src/Verifiable.OAuth/Dpop/DpopJwsPartSerializer.cs` — same shape.

Both are pure delegate bundles. Per the discipline note ("`DebuggerDisplay` on types with non-trivial state"), these are arguably out of scope. **No action.**

Other stateful types (e.g., `OAuthFormEncodedFields`, `HttpResponseData`, etc.) all have `[DebuggerDisplay]`. ✅

### XML doc completeness

Sampled 20 public types across `src/Verifiable.OAuth/`:

- 19 had a full XML doc on the declaring type.
- Per-property docs were comprehensive on records/structs (every `init` property documented).
- One exception: `DpopJwsPartParser` / `DpopJwsPartSerializer` — type-level XML doc present, property-level XML docs present, but the property summaries are terse ("Parses the JSON bytes of a header segment..."). Adequate; not a finding.

**Pattern note:** the codebase has a strong convention of long form `<remarks>` sections explaining *why* a slot exists and *who* should wire it. This is high-value and consistent.

### Section 4 findings summary

```
Naming drift: 0 findings
Slot shape drift: 0 findings (principled difference between AS/Client)
Missing DebuggerDisplay: 0 substantive (2 borderline, not flagged)
XML doc gaps: 0 substantive
```

### Recommended follow-up MD from Section 4

- **None.** The cross-cutting consistency is in good shape. The drift in Section 2 (rotation surfaces) is the only cross-cutting issue worth a focused MD, and it's already captured there.

---

## Build and test state

- **Build:** 0 errors, 0 warnings (Debug, `dotnet build Verifiable.slnx`).
- **Tests:** 2560 passed, 0 failed, 20 skipped (the 20 inconclusive entries are platform/algorithm-dependent skips inherited from prior phases).
- **Coverage:** Verifiable.OAuth 71% line / 48% branch. Cobertura report at `bin/Debug/net10.0/TestResults/coverage.cobertura.xml`.

Baseline maintained. No production code or test changes made as part of this audit phase.

---

## Top 5 recommended follow-up MDs in priority order

1. **MD-phase8-dpop-issuance-completion** — embed `cnf.jkt` in the issued access token JWT and emit `token_type=DPoP` when DPoP enforcement ran. Pre-condition for any RS deployment relying on DPoP-bound bearer tokens.
2. **MD-phase8-refresh-token-grant** — AS-side `grant_type=refresh_token` matcher with rotation (RFC 9700 §2.2.2 for public clients) and DPoP key-binding check on the refreshed token.
3. **MD-phase8-pkce-par-tighten** — AllowedRedirectUris exact-match on PKCE-PAR + `Cache-Control: no-store` on token responses + `Rfc9068AccessTokenProducer` issuer URL fix (use `OriginalString`, not `GetLeftPart(Authority)`). Three tight surgical fixes.
4. **MD-phase8-signing-key-resolver-parity** — Synchronise `ServerSigningKeyResolverDelegate` shape to the HMAC-side pattern (optional kid, echo-back kid, `InProcessSigningKeyResolver` default). Add resolver-level rotation tests on the signing side.
5. **MD-phase8-validation-coverage** — Decide dead vs. needed for ~30 unused `ValidationChecks` functions; remove or add tests. Address `Oidc10IdTokenProducer.cs` 0% as part of the OIDC implementation track.

After items 1–3 land, the OAuth subsystem is **deployable for production token issuance under DPoP** at parity with RFC 9449 §5–§6 and RFC 9700 §2–§4. Items 4–5 are quality/maintenance.

---

## Audit metadata

- **Coverage tool:** `Microsoft.Testing.Extensions.CodeCoverage` v18.6.2, Cobertura output.
- **Spec versions fetched:** all live URLs as of 2026-05-14 — `draft-ietf-oauth-v2-1` latest revision; RFC 9700, RFC 9449, RFC 9126, RFC 9101, RFC 9207, RFC 7591, RFC 7592 (published).
- **Time spent:** ~50 minutes (15 min spec fetch and extraction, 25 min code mapping + coverage run, 10 min report assembly).
- **Surprises:**
  - DPoP wire integration is genuinely incomplete — the binding lives on the persisted state but doesn't reach the issued JWT or the `token_type` field. Phase 6b landed the *enforcement* path but not the *issuance* path.
  - The AS-side refresh-token grant is entirely absent — the client-side `RefreshAsync` would silently route to 404 if a real test exercised it end-to-end.
  - `Rfc9068AccessTokenProducer.cs` truncates the issuer URL via `GetLeftPart(UriPartial.Authority)`; this conflicts with how the rest of the AS handles the issuer URI (`OriginalString`) and breaks path-segment-multitenanted deployments.
  - Rotation-test coverage on the signing side is **JWKS-publication-only** — there are no tests exercising the resolver's lookup-by-kid behaviour the way the new `InProcessHmacKeyResolverTests` exercises it. The two surfaces have meaningfully drifted.

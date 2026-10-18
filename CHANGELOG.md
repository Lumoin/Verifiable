# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!-- Available types of changes:
### Added
### Changed
### Fixed
### Deprecated
### Removed
### Security
-->

## [Unreleased]

### Added

- TPM feature work.
- `Verifiable.JCose.NumericDate`: a JWT NumericDate exactly as written (RFC 7519 section 2), the one reading every reader of a
  claims set shares (`NumericDate.Of`, `NumericDate.FromJsonNumber`, `NumericDate.FromSeconds`), with exact comparisons against an
  instant shifted by a tolerance (`CompareTo`, `CompareToLaterBy`, `CompareToEarlierBy`), against another date
  (`CompareTo`, `IsMoreThanAfter`) and the instants a clock holds around it (`AtOrBefore`, `AtOrAfter`, `AtOrAfterLaterBy`);
  issuers choose their precision (`FromInstant`, `FromUnixTimeSeconds`, `WholeSecondAtOrBefore`), and every `DateTimeOffset`
  converts to one implicitly.
- `Verifiable.JCose.DecimalNumber`: a number in decimal notation held exactly (`FromJsonNumber`, `FromInteger`, `FromDecimal`,
  `FromDouble`, `Of`), compared exactly and written back as the JSON number it is; `ToClaimValue` boxes it as the library's
  JSON layer boxes a number it reads.
- `JwkJsonReader.ExtractNumericDate`, the span reader's NumericDate, returning the date or none.
- `JwsAlgorithmVerification`, `JwsKeyAlgorithmBinding` and `JwsKeyAlgorithmRefusal`: a supplied JWS verification bound to the
  one algorithm it performs, and the header's algorithm judged against the key before anything is verified.
- `CryptoFormatConversions.ResolveJwaAlgorithm` and `JwaAlgorithmResolution`: the JWA algorithm a key type is named by, as a
  typed resolution.
- `ClientAssertionClaimRules`, `ClientAssertionHeaderRules` and their refusals: one judgement of a client assertion's header
  and claims for every key source and method.
- `AuthorizationServerIntegration.ResolveClaimsSupportedAsync` and `ResolveClaimsSupportedDelegate`: discovery composes
  `claims_supported` from the registration's own list.
- `JsonMemberNumber.ToNumericDate`: the NumericDate a member read as a number names, or none for a number naming an instant
  no clock represents, so a reader of a document's members tells an absent date from a present malformed one.
- `DpopProofHeader.Read` and `DpopProofClaims.Read`: the DPoP proof's protected header (`alg`, `typ`, `jwk` and every
  member of the `jwk`) and claims (`jti`, `htm`, `htu`, `iat` as written, `nonce`, `ath`) read once through
  `JwkJsonReader.ReadTopLevelMembers`, answering a typed reading (`DpopProofPartReading<TPart>`: `DpopProofPartRead<TPart>`,
  `DpopProofPartDocumentRefused<TPart>` carrying the JSON reader's own refusal, `DpopProofPartMemberRefused<TPart>` naming
  the member, its place (`DpopProofPartPlace`), the member as read and the defect (`DpopProofMemberDefect`)), never throwing;
  `DpopJwsPartParser.Default` is the pair, so a receiver parses no part of a proof itself.
- `ClientAssertionClaimRules.IsAcceptedToTheClocksEnd` and `ClientAssertionClaimsJudgement.AcceptedToTheClocksEnd`: whether a
  client assertion's window, its `exp` extended by the clock-skew tolerance, reaches past the clock's last instant, stated
  as a fact rather than an instant clipped to the clock; `ClientAssertionClaimsJudgement.Expiry` carries the `exp` as written.

### Changed

- Every reader of a NumericDate judges the date as written, every digit kept, against the bound each comparison keeps:
  a part of a tick past a bound is past it whichever side the bound is on, and no tolerance added to a date the clock
  represents overflows a comparison. The models that surface a received date carry it as a `NumericDate`: `JarVerified`,
  `AuthCodeRequestObject`, `AuthorizationRequestObject`, `DpopProofClaims.Iat`, `JwsAccessTokenClaims`, `Oidc10IdTokenClaims`,
  `Rfc7523AssertionValidationResult`, `IdJagAssertionValidationResult`, `PrivateKeyJwtClientAuthenticationResult`,
  `FederationClientAuthenticationResult`, `EntityStatement`, `TrustMark`, `TrustMarkDelegation`, `KeyAttestation`,
  `CredentialProofValidationResult`, `SelfIssuedIdTokenValidationResult`, `VpTokenParsed.KbJwtIat`,
  `ValidationContext.KbJwtIat`, `JwtBearerGrant.Expiration`, `SecurityEventToken`, `StatusListToken`, and the DIDComm unpack
  results' `RotationIat`;
  `JwtTemporalChecks` and `ClientAssertionClaimRules.ReplayRecordKeptUntil` take the received date as one.
- An expiry is exclusive everywhere (RFC 7519 section 4.1.4: the present must be before `exp`): the bearer access token,
  the time-bound checks of `JwtChecks`, the key attestation and the status list token are expired at their `exp`.
- `StatusListToken.TimeToLive` is the `ttl` exactly as written (`DecimalNumber`), a positive fraction among what it carries;
  a resolution is due for refresh once more than that has passed.
- The claims dictionary the JSON layer parses boxes a number no `long` holds as a `decimal` only where a decimal holds it
  exactly, and as the `DecimalNumber` it is otherwise, so no digit is rounded away and no magnitude past a decimal's range
  refuses the payload.
- A present date that is no NumericDate is refused where it was read as absent or converted: the time-bound checks of
  `JwtChecks` fail on it, the DIDComm `from_prior` verification refuses it as a malformed rotation JWT, and the status list
  token's JSON and CWT converters refuse it, and a count no clock represents, as content.
- Required arguments: `PrivateKeyJwtClientAuthentication.BuildValidator` takes every argument of both overloads explicitly,
  none defaulted.
- The written request objects, DPoP proofs and DIDComm rotations the library composes state their dates to the whole second
  at or before the instant (`NumericDate.WholeSecondAtOrBefore`, `ToUnixTimeSeconds`), the integers they always carried.
- `DpopJwsPartParser.ParseHeader` and `ParseClaims` answer a `DpopProofPartReading<TPart>` in place of a part or an
  exception; `DpopProofValidator` answers a refused part as `Malformed` and a header carrying no `typ` as `InvalidTyp`,
  as before. A proof whose claims or header name a member twice, hold a string naming no Unicode text, carry a `nonce` that
  is `null` or carry a `jwk` member that is no string is refused as `Malformed` through the library's reading.
- `ClientAssertionClaimRules.AcceptedUntil` is `ReplayRecordKeptUntil`, the instant the record of a first use is kept until,
  and `ClientAssertionClaimsJudgement.AcceptedUntil` is `ReplayRecordKeptUntil`; `ClientAssertionClaimsJudgement.Accepted`
  takes the `exp` and the tolerance; `ConsultClientAssertionFirstUseDelegate` names its instant `recordKeptUntil`. The
  expiry rule judges the `exp` as written under the tolerance (`JwtTemporalChecks.IsBeforeExpiry`), so an assertion whose
  `exp` is the clock's last tick is accepted at that tick, where the clipped instant refused it as expired.
- `KeyAttestationParser.TryParse` reads the body as the one JSON object it is (`JwkJsonReader.ReadTopLevelMembers`) and
  refuses a present `iat` or `exp` that is no NumericDate - a string of digits, another kind of value, a count no clock
  represents - so `KeyAttestationVerifier` refuses such an attestation as `Malformed` where a malformed `exp` was read as
  none and its expiry was not enforced; an attestation omitting `exp` (OPTIONAL, OID4VCI 1.0 Appendix D.1) still verifies.
  A body holding a string naming no Unicode text is refused too.

### Removed

- `JwtNumericDates` and its claim-name rounding: the direction a remainder is taken in was chosen per claim name, not per
  comparison.
- `AuthorizationServerCodecs.ClientAssertionPayloadDeserializer`: the payload codec states every member as written, so a
  client assertion's claims set is read through `JwtPayloadDeserializer` like every other.
- `JwkJsonReader.TryExtractNumericDate`, replaced by `ExtractNumericDate`.

### Fixed

- A NumericDate with more digits than a `decimal` keeps, or the smallest `double` below zero, no longer loses the remainder
  that decides a bound before the tick is judged.
- The status list token's JSON converter reads a fractional `iat`, `exp` and `ttl`, and refuses a date no clock represents as
  JSON instead of throwing from the date's construction.

## [0.0.0.2-alpha] - 2021-08-16

### Added

- CHANGELOG.md.

### Changed

- Improve NuGet automation.

## [0.0.0.1-alpha] - 2021-08-15

### Added

- Project readme files.
- The project files.
- The build files.
- Initial NuGet automation.

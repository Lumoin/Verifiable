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
- `DpopProofHeader.Read` and `DpopProofClaims.Read`: the DPoP proof's protected header (`alg`, `typ`, `jwk`) and claims
  (`jti`, `htm`, `htu`, `iat` as written, `nonce`, `ath`) read through `JwkJsonReader.ReadTopLevelMembers`, the embedded key read
  by the same reader and each of its members judged by its own rule (RFC 7517 section 4, RFC 7518 section 6): a member defined
  as a string as a string, `key_ops` as an array of strings, `x5c` as a non-empty array of base64-encoded strings, `ext` as a
  Boolean, private or symmetric material refused whatever its kind, a member no rule names ignored. Each answers a typed
  reading, `DpopProofPartReading<TPart>`: `DpopProofPartRead<TPart>`, or `DpopProofPartRefused<TPart>` carrying a
  `JwsPartRefusal` - the JSON reader's refusal of the part (`JwsPartDocumentRefusal`) or the member refused
  (`DpopProofMemberRefusal`: the member as the reading knows it, `DpopProofMember`; its name; the member as read; the defect,
  `DpopProofMemberDefect`, with `NotAnArrayOfStrings`, `NotACertificateChain`, `NotABoolean` and `PrivateKeyMaterial` beside
  the kinds; its object, `DpopProofPartPlace`) - never throwing on the bytes it is handed. `DpopJwsPartParser.Default` is the
  pair, so a receiver parses no part of a proof itself. These names, homes and visibilities await the owner's word.
- `JwsPart`, `JwsPartRefusal` and `JwsPartDocumentRefusal` (`Verifiable.JCose`, public): the one way a validation carries the
  reading's refusal of a JWS part whole, with the segment it concerns, beside its coarse category -
  `DpopProofValidationResult.PartRefusal`, `JwsAccessTokenValidationResult.PartRefusal` and
  `Oidc10IdTokenValidationResult.PartRefusal`, built by each result's `PartRefused` factory. Awaiting the owner's word.
- `JsonTopLevelMember.ArrayElements` (`Verifiable.JCose`): the elements of an array member, each a typed `JsonMemberLookup`,
  read by the reader that read the member, or none for a member that is no well-formed array of Unicode text.
- `DecimalNumber.IsInteger`: whether a number is an integer whatever its spelling.
- `WellKnownJwkMemberNames.Ext`, `ExtUtf8` and `IsExt`: the Web Cryptography API's `ext` member name and its recognition.
- `KeyAttestationProofUse` (`Verifiable.OAuth.Oid4Vci`, public): the use a key attestation is verified for - `NotStated`,
  `JwtProof` or `AttestationProof` - as a typed value, which decides whether its omitted `exp` is valid (OID4VCI 1.0 Appendix
  D.1), and `KeyAttestationVerificationFailureReason.ExpiryNotPresented`. Awaiting the owner's word.
- `ReplayRecordRetention`, `ReplayRecordKeptUntil` and `ReplayRecordKeptToTheClocksEnd` (`Verifiable.OAuth.Server`, public):
  how long a replay store keeps the record of a `jti`'s first use - until an instant, exclusive, or to the clock's end, which
  no instant represents - with `IsDueAt` the one rule a store drops a record by; `ClientAssertionClaimRules.ReplayRecordRetentionOf`
  computes it, `ClientAssertionClaimsJudgement.Retention` carries it, and `JtiSeenState.Retention` stores it. Awaiting the
  owner's word.
- `ClientAssertionClaimRules.IsAcceptedToTheClocksEnd`: whether a client assertion's window, its `exp` extended by the
  clock-skew tolerance, reaches past the clock's last instant, stated as a fact rather than an instant clipped to the clock;
  `ClientAssertionClaimsJudgement.Expiry` carries the `exp` as written.
- `OAuthMemberNotAString` (`Verifiable.OAuth`, public, an `OAuthParseError` case; its name, home and visibility await the
  owner's word): a token response carrying `access_token`, `token_type`, `refresh_token`, `scope`, `id_token` or
  `issued_token_type` as a value of another kind than the string each is defined as, naming the parameter and the kind
  (`JsonTopLevelValueKind`) and carrying no value.
- `OAuthRequiredMemberAbsent` (`Verifiable.OAuth`, public, an `OAuthParseError` case; awaiting the owner's word): a response
  omitting a parameter its specification requires - a token response's `access_token` or `token_type`, a token exchange
  answer's `issued_token_type` - naming the parameter and copying nothing of the response.
- `OAuthClientErrors.UnrecognisedRefusal`: the client error code a refusal of a kind the endpoint mapping does not name is
  answered with, never a category established for another.
- `JwsAccessTokenValidationFailureReason.UnsupportedConfirmationMethod`: a token whose `cnf` binds it by a confirmation method
  the library does not verify possession under.
- `SdJwtPresentationDefect` (`Verifiable.OAuth.Oid4Vp.Server`, public): why an SD-JWT VP token is a presentation no
  conformant Wallet produces, answered by `SdJwtVpTokenVerification.VerifyAsync` through the library's existing
  `Result<VpTokenParsed, SdJwtPresentationDefect>` and carried to the verifier's failed state as
  `VerifierPresentationRefused.PresentationDefect`, `VerifierFlowFailedState.PresentationDefect`,
  `SiopFlowFailed.PresentationDefect` and `SiopVerifierFlowFailedState.PresentationDefect`; the Wallet is answered the generic
  malformed description. Awaiting the owner's word.
- `JwkCertificateChain.DefectOf` and `JwkCertificateChainDefect` (`Verifiable.JCose`, public): a JWK's `x5c` read as RFC 7517
  section 4.7 has it - each element base64 (not base64url) text of a DER X.509 certificate (RFC 5280 section 4.1), the first
  certificate's subject public key the key the JWK's other members represent, for EC P-256/P-384/P-521, RSA, Ed25519 and
  ML-DSA keys - answering the defect, `NotBase64Text`, `NotACertificate` or `FirstCertificateNotOfTheKey`, or none. The
  certification of each certificate by the next is a matter of trust in the chain, which it does not judge. Awaiting the
  owner's word.
- `DpopProofMemberDefect.RepeatedKeyOperation`, `KeyOperationsInconsistentWithUse` and `CertificateNotOfTheKey`: an embedded
  `jwk` naming a `key_ops` operation twice, carrying `use` and `key_ops` that do not convey consistent information, or an
  `x5c` whose first certificate is of another key (RFC 7517 sections 4.3 and 4.7).
- `WellKnownJwkValues` `key_ops` values (`KeyOpsSign`, `KeyOpsVerify`, `KeyOpsEncrypt`, `KeyOpsDecrypt`, `KeyOpsWrapKey`,
  `KeyOpsUnwrapKey`, `KeyOpsDeriveKey`, `KeyOpsDeriveBits`, each with its UTF-8 form and recognition) and
  `WellKnownJwkMemberNames.IsPub`.
- `OAuthRequestParameterNames.IsRefreshToken`, `IsIdToken` and `IsNonce`: the recognitions of those parameter names beside
  `IsAccessToken`, each an exact ordinal comparison.
- `JwtHeader.Read` and `JwtPayload.Read` (`Verifiable.JCose`): a signed JWT's decoded header and claims set read through the
  one authority `JwkJsonReader.ReadTopLevelMembers` answers a document by - its strict judgement, then the admitted bytes read
  with the same reader's primitives, one authority and not one physical scan - every member at every depth held as a claims
  set holds it (a number every digit kept, an object as a dictionary, an array as a list, each declared to hold a value that
  may be none, the top-level claims set included, a present `null` as a member with no value), answering
  `JwtPartReading<TPart>` (`JwtPartRead<TPart>`, `JwtPartRefused<TPart>` carrying the reader's own refusal), never throwing
  on the bytes it is handed;
  `JwsAccessTokenJsonParser.Default` is the pair, so a receiver of an access token or an ID Token parses no part of it itself.
- Pending the owner's word before publication, on name, home and visibility: `OAuthMemberNotAString`, `JwtPartReading<TPart>`,
  `JwtPartRead<TPart>` and `JwtPartRefused<TPart>`, and with them this release's `JwsPart`, `JwsPartRefusal`,
  `JwsPartDocumentRefusal`, `DpopProofPartRefused<TPart>`, `DpopProofMemberRefusal`, `DpopProofMember`,
  `KeyAttestationProofUse`, `ReplayRecordRetention` and its two cases, `OAuthRequiredMemberAbsent` and the SD-JWT
  verification's `SdJwtPresentationDefect` with its carriage onto the failed states, `JwkCertificateChain` and
  `JwkCertificateChainDefect`, and the changed public signatures this release's nullable propagation brings (below).
  Recommendations recorded with the review for the owner: approve `JwsPart`, `JwsPartRefusal` and `JwsPartDocumentRefusal` as
  the common JCose concept, subject to naming; keep `DpopProofMemberRefusal`, `DpopProofMember`, `DpopProofPartRefused<TPart>`
  and the derived `Place` in OAuth's DPoP area, the mapping exhaustive; the new member-defect values as extensions of the
  existing enum; `PartRefusal` and `PartRefused` on the four results in place of new result hierarchies; the typed retention
  only with complete host storage consumption and no timestamp shim; the required `KeyAttestation.IssuedAt`,
  `ExpiryNotPresented` and the proof-use argument as a signature widening needing the owner's ruling, its general-validation
  case's name and meaning settled; `OAuthRequiredMemberAbsent` beside the pending `OAuthMemberNotAString` decision;
  `UnrecognisedRefusal` and `UnsupportedConfirmationMethod` as extensions of existing vocabularies; the presentation's typed
  refusal through an existing result mechanism rather than new wrapper records; `ArrayElements`, `IsInteger` and the `Ext`
  members as extensions of existing JCose types; the reading helpers and federation selections kept internal or private.

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
  `JwtTemporalChecks` and `ClientAssertionClaimRules.ReplayRecordRetentionOf` take the received date as one.
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
  exception. `DpopProofValidator` carries a refused part's `JwsPartRefusal` whole (`DpopProofValidationResult.PartRefusal`)
  and decides the coarse category from the typed refusal: a header carrying no `typ` is `InvalidTyp`; an embedded key
  carrying private or symmetric material is `JwkContainsPrivateKey` whatever the kind of its value; every other refusal is
  `Malformed`. Old answers that change: a `typ` carried as `null`, which the former parser read as an empty string answered
  `InvalidTyp`, is `Malformed`; a key member defined as a string carried as another kind, `null` among them, is refused as
  `Malformed` by its rule; a key carrying `key_ops`, `x5c` or `ext` of their own kinds, refused while every member was read
  as a string, is accepted; a member no rule names is ignored and no longer carried in `DpopProofHeader.Jwk`, which holds the
  key's string members; a proof whose claims or header name a member twice, hold a string naming no Unicode text or carry a
  `nonce` that is `null` is `Malformed`. A segment the decoder refuses as no base64url text (`FormatException`) is
  `Malformed`; any other exception of the decoder or of a composed reading surfaces as the fault it is.
- `ClientAssertionClaimRules.AcceptedUntil` is `ReplayRecordRetentionOf`, answering a `ReplayRecordRetention`;
  `ClientAssertionClaimsJudgement.Retention` carries it; `ClientAssertionClaimsJudgement.Accepted` takes the `exp` and the
  tolerance; `ConsultClientAssertionFirstUseDelegate` and `CheckClientAssertionJtiReplayDelegate` take the retention, and
  `JtiReplayGuard.ConsultClientAssertionAsync` stores it in the `JtiSeenState` it saves, a record kept to the clock's end with
  `DateTimeOffset.MaxValue` as its expiry and that fact beside it. The expiry rule judges the `exp` as written under the
  tolerance (`JwtTemporalChecks.IsBeforeExpiry`): an assertion whose `exp` is the clock's last tick is accepted at that tick
  under a positive tolerance, its window reaching past the clock's end, where the clipped instant refused it as expired; under
  a zero tolerance its window ends at that tick, which refuses it there.
- `KeyAttestationParser.TryParse` reads the body as the one JSON object it is (`JwkJsonReader.ReadTopLevelMembers`) and refuses
  an attestation omitting the REQUIRED `iat`, carrying an `iat` or an `exp` that is no NumericDate, or carrying one with a
  fraction, where OID4VCI 1.0 Appendix D.1 has each an integer, never truncating it; `KeyAttestation.IssuedAt` is required.
  `KeyAttestationVerifier.VerifyAsync` takes the attestation's `KeyAttestationProofUse` and refuses an omitted `exp` as
  `ExpiryNotPresented` where the attestation is used with the JWT proof type; outside that use an omitted `exp` stays valid,
  the attestation carrying no expiry of its own. A body holding a string naming no Unicode text is refused too.
- `OAuthResponseParsers.ReadTokenResponse` and `ParseTokenResponse` refuse a present `access_token`, `token_type`,
  `refresh_token`, `scope`, `id_token` or `issued_token_type` of another kind than a string as `OAuthMemberNotAString` where
  it was read as omitted or as missing: a `scope` that is a number, an array, an object or a literal no longer reads as the
  scope requested having been granted. An omitted `access_token` or `token_type` is `OAuthRequiredMemberAbsent`, where it was
  an `OAuthMalformedResponse` copying the body; an empty one is an `OAuthInvalidFieldValue`. The ID-JAG mint refuses an
  answer omitting `issued_token_type` as `OAuthRequiredMemberAbsent`, where it invented an empty received value.
- The code exchange's endpoint mapping names every parse refusal: a member of another kind, an absent required member, a
  repeated member name and a member naming no Unicode text are `invalid_response` of the client's judgement, where the last
  two fell to `server_error`; a refusal of a kind the mapping does not name is `unrecognised_refusal`.
- `JwsAccessTokenJsonParser.ParseHeader` and `ParseClaims` answer a `JwtPartReading<TPart>` in place of a part or an
  exception; the shared validator answers a refused header as `InvalidHeader` and a refused claims set as `Malformed`, each
  carrying the reader's refusal with its segment (`PartRefusal`), and answers only the decoder's `FormatException` as such,
  where any exception of a parser was answered as malformed input. A token whose header or claims set names a member twice
  at any depth, or holds a string naming no Unicode text, is refused through the library's reading; a present `null` claim is
  held as present, so a `null` `exp`, `nbf` or `act` is refused as malformed rather than read as absent. An `aud` array
  holding an element that is no non-empty string, an empty array or an empty string is `Malformed` as a whole, where its
  other elements were read as the audience. An ID Token's `amr` is read as OpenID Connect Core 1.0 section 2 defines it, a JSON
  array of strings, by a reader of its own: a single string, which `aud` admits, is `Malformed` for `amr`, as is an array
  holding an element that is no non-empty string or an empty array. A `cnf` that is no object, carries no member or
  carries a `jkt` that is no non-empty string is `Malformed`, and one carrying a confirmation method the library does not
  verify is `UnsupportedConfirmationMethod`, where each was read as an unbound token. Refusing a confirmation method beside
  `jkt` is the library's profile policy: RFC 7800 section 3.1 lets a `cnf` carry members of other methods, and this library
  verifies possession only under the one it implements, so a token bound by another is refused rather than accepted unbound.
- `CredentialProofValidator` reads the proof's claims set as the one JSON object it is and refuses an `iat` that is no
  NumericDate as `Malformed` where it was answered as `IatOutOfWindow`, an omitted `iat` staying `IatOutOfWindow`; a claims set
  holding a string naming no Unicode text is refused as `Malformed` too.
- `SelfIssuedIdTokenValidation` answers a token omitting `iat`, which SIOPv2 section 11 carries over from OpenID Connect Core
  1.0 section 2 as REQUIRED, or carrying an `exp` or an `iat` that is no NumericDate, as structurally invalid, returned as its
  judgement and never raised; an omitted `exp` is still not unexpired. The token's `iss`, `sub`, `aud`, `nonce` and `sub_jwk`
  are still read by the text scan beside the members reading the dates come from.
- `SdJwtVpTokenVerification.VerifyAsync` answers a `Result<VpTokenParsed, SdJwtPresentationDefect>`: the presentation read and
  assessed - its signature, `sd_hash` and binding outcomes stated for the caller's checks, not yet accepted - or the defect of
  an issuer-signed payload that is not well-formed or repeats a claim, a `status` claim outside Token Status List sections 6.1
  and 6.2, a KB-JWT payload that is not one JSON object, or a KB-JWT `iat` that is no NumericDate, where each was raised as a
  `FormatException`. An omitted KB-JWT `iat` is carried as absent; the OID4VP verifier's key-binding checks refuse it, and the
  SIOPv2 section 12 combined response now judges the KB-JWT's `iat` by the same checks (`CheckKbJwtIatNotInFuture`,
  `CheckKbJwtIatNotTooOld`) among its binding, where it accepted a KB-JWT omitting it or stating any instant. The HAIP and SIOP
  verifier executors answer the defect on their malformed route and carry it to the failed state. The KB-JWT's `nonce`, `aud`
  and `sd_hash`, and the Self-Issued ID Token's `iss`, `sub`, `aud`, `nonce` and `sub_jwk`, are still read by the older text
  scans beside the members reading the dates come from: those extractors are not part of the members-reading migration and
  remain library work.
- The JOSE dictionaries hold a value that may be none at the top level as at every depth: `JoseDictionary` (and with it
  `JwtHeader`, `JwtPayload`, `UnverifiedJwtHeader` and `UnverifiedJwtPayload`) is a `Dictionary<string, object?>`, and every
  seam that hands one on states the same - the JWT part serializers and deserializers (`JwtHeaderSerializer`,
  `JwtHeaderDeserializer`, the OAuth `JwtPayloadDeserializer`, `JwtHeaderDeserializer` and `JarDictionaryDeserializer`), the
  JWS and JAdES header and unprotected-header parameters and delegates, the DIDComm `from_prior` header deserializers, the
  security event token part deserializer and `SecurityEventTokenParsing.Parse`, `ClientAssertionClaimRules`'s and
  `ClientAssertionHeaderRules`' readings, `JarVerified.Claims`, `JarmResponseValidationResult.Parameters`,
  `ValidationContext.TokenClaims` and `JwsCredentialVerificationResult.Header`. `DictionaryEquality` and
  `JsonAppender.AppendObject` are generic over the value type. A reader of a value no longer receives a non-null claim it must
  then cast without a check; a `null` member is a member with no value, and the readings that require a value refuse it as
  they refuse any value of another kind.
- `JwkJsonReader`'s JWK Set selections answer a set carrying no `keys` member, or one whose `keys` is no array, as
  `MalformedDocument` (RFC 7517 section 5: the member is REQUIRED and its value an array); an empty `keys` array stays a set
  with no key the selection matches. `JsonTopLevelMember.ArrayElements` judges the whole array as Unicode text, a literal
  unpaired surrogate in the text it is read from among what it refuses, before any element is read.
- An embedded DPoP `jwk` is judged by RFC 7517 sections 4.3 and 4.7 as a whole once its members are read: `key_ops` naming no
  operation twice, `use` and `key_ops` consistent where both are carried, and `x5c` a chain of DER certificates whose first is
  of the key. `DpopProofValidator` answers a key it cannot construct, the decoder's or the key material's refusal, as
  `InvalidJwk`, and lets every other failure surface as the fault it is. `KeyAttestationParser.TryParse` and
  `KeyAttestationVerifier.VerifyAsync` answer only the decoder's refusal of a segment as no base64url text as a malformed
  attestation, where any exception of the header's reading was; a proof use of no defined value is refused as an
  `ArgumentOutOfRangeException`, never read as a use requiring no expiry. `JtiReplayGuard` refuses a retention of neither
  kind as an `ArgumentException` before the store is consulted, where it stored one as kept to the clock's end; a DPoP member
  refusal is constructed only for a member the reading knows.
- The JWK Set admission names the reader's `JsonNotOneObject` as `MalformedDocument` explicitly and throws
  `InvalidOperationException` for any other reading, an invariant failure of the reader rather than a refusal of the set, so
  no refusal the reader comes to answer is folded into `MalformedDocument` unread.
- `JwkJsonReader`'s readings of an admitted document throw `InvalidOperationException`, an invariant failure and never a
  refusal, where a member read to no text or value, rather than answering the admitted document as `JsonNotOneObject`.
- `FederationKeyResolver.ResolveInChainKeyAsync` tells a statement whose key set carries no key of the kid - an empty `keys`
  array among them - which passes the walk on, from one whose key set is refused - no JSON object, no `keys` member, a `keys`
  that is no array, or a set the selection refuses - or whose selected key builds no key, which ends the walk with no key,
  where every such statement passed the walk on to the next; a set carrying no `keys` member, or one that is no array, was
  read as one carrying no key of the kid and passed it on. `JwtVcIssuerMetadataDocuments.ResolveAsync` refuses an inline
  `jwks` that is no JWK Set as `InvalidDocument` before reporting the document resolved.

### Removed

- `JwtNumericDates` and its claim-name rounding: the direction a remainder is taken in was chosen per claim name, not per
  comparison.
- `AuthorizationServerCodecs.ClientAssertionPayloadDeserializer`: the payload codec states every member as written, so a
  client assertion's claims set is read through `JwtPayloadDeserializer` like every other.
- `JwkJsonReader.TryExtractNumericDate`, and its successor `JwkJsonReader.ExtractNumericDate` (published locally as 1023): the
  text-scan reader turned a present malformed date into absence; every reader of a date reads the members of its claims set
  (`JwkJsonReader.ReadTopLevelMembers`, `JsonMemberNumber.ToNumericDate`) and tells the two apart.
- The members `ClientAssertionClaimsJudgement.AcceptedToTheClocksEnd`, `ClientAssertionClaimsJudgement.ReplayRecordKeptUntil`
  (a `DateTimeOffset?` property) and the method `ClientAssertionClaimRules.ReplayRecordKeptUntil`: the clock-end fact and the
  instant are one typed retention (`ReplayRecordRetention`), carried through the replay delegates into the stored state. The
  record `ReplayRecordKeptUntil` added in this release, one of that retention's two cases, is a different thing of the same
  name and is not removed.
- `SdJwtVpTokenVerificationOutcome`, `SdJwtVpTokenVerified` and `SdJwtVpTokenRefused`, added earlier in this release: the
  presentation's outcome is the library's existing `Result<VpTokenParsed, SdJwtPresentationDefect>`.

### Host migration obligations

A host taking this release changes, beyond renamed or widened calls the compiler finds:

- Every replay store: both retention delegates (`ConsultClientAssertionFirstUseDelegate`,
  `CheckClientAssertionJtiReplayDelegate`), `JtiReplayGuard.ConsultClientAssertionAsync`, the removed judgement members, and
  every `JtiSeenState` it constructs carry the `ReplayRecordRetention`; its state serialization, expiry cleanup, storage TTL
  and the correlation and claim record's lifetime keep a record kept to the clock's end through the clock's last tick, which
  a successful compile does not establish.
- Both `KeyAttestationVerifier.VerifyAsync` overloads take the `KeyAttestationProofUse`; `KeyAttestation.IssuedAt` is
  required; every consumer of the SD-JWT VP token verification reads the `Result` and the typed defect.
- Every host switch over an extended failure enum (`JwsAccessTokenValidationFailureReason`, `DpopProofMemberDefect`,
  `KeyAttestationVerificationFailureReason`, the `OAuthParseError` cases) names the new cases, and every pending name the
  owner changes is taken.
- A host's own JWT part parser delegates are replaced by the library's readings, carrying the `JwtPartRead<TPart>` the host
  captured input from, and refused parts' `PartRefusal` objects are carried whole into its evidence by their typed member,
  place, kind and defect, never by logging the carried values, which can hold supplied key material.
- A host's code reading the JOSE dictionaries states their values as `object?`.
- The inventory covers every library change since the host's own pin, not this release's last commit alone.
- `DpopProofPartDocumentRefused<TPart>` and `DpopProofPartMemberRefused<TPart>`: a refused part is
  `DpopProofPartRefused<TPart>`, carrying the `JwsPartRefusal` a validation result carries whole.

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

using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth;

/// <summary>
/// Validates JWS-signed access tokens per RFC 7519 (JWT), RFC 9068 (JWT
/// Profile for OAuth 2.0 Access Tokens), and RFC 8725 (JWT BCP). Static
/// class with delegate-composed extension points; parallel of
/// <see cref="Verifiable.OAuth.Server.Rfc9068AccessTokenProducer"/> on
/// the consumption side.
/// </summary>
/// <remarks>
/// <para>
/// Validation order (cheap structural checks before expensive
/// cryptographic operations):
/// </para>
/// <list type="number">
///   <item><description>Structural parse — three base64url segments separated by <c>.</c>.</description></item>
///   <item><description>Header decode, alg check — reject <c>none</c> per RFC 8725 §3.1.</description></item>
///   <item><description><c>typ</c> check — require <c>at+jwt</c> or <c>application/at+jwt</c> per RFC 9068 §4.</description></item>
///   <item><description><c>kid</c> resolution via the supplied resolver.</description></item>
///   <item><description>Signature verification via <see cref="Jws.VerifyAsync(JwsMessage, EncodeDelegate, PublicKeyMemory, VerificationDelegate, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>.</description></item>
///   <item><description>Standard claim checks: <c>iss</c>, <c>aud</c>, <c>exp</c>, <c>nbf</c>, <c>iat</c>, <c>sub</c>.</description></item>
///   <item><description>Optional claim read: <c>client_id</c>, <c>scope</c>, <c>jti</c>, <c>cnf</c>, <c>act</c>, <c>may_act</c>.</description></item>
/// </list>
/// <para>
/// The nested-object claims <c>act</c> (RFC 8693 §4.1) and <c>may_act</c> (RFC 8693 §4.4) fail
/// closed: a claim that is present but not a well-formed actor object rejects the whole token with
/// <see cref="JwsAccessTokenValidationFailureReason.Malformed"/> rather than being surfaced
/// partially parsed or silently dropped. Dropping a malformed <c>act</c> would present a delegated
/// token to the resource server as though its subject were acting directly, and dropping a
/// malformed <c>may_act</c> would erase a constraint the subject placed on who may act for it —
/// both are the permissive reading of a token the issuer did not write. As with <c>cnf</c>, the
/// nested object is read through the dictionary shapes a JSON object materialises as:
/// <see cref="JwsAccessTokenJsonParser.Default"/> reads a JSON object as a
/// <see cref="Dictionary{TKey, TValue}"/>, and a parser composed otherwise must map JSON objects to
/// <see cref="IReadOnlyDictionary{TKey, TValue}"/> or <see cref="IDictionary{TKey, TValue}"/>
/// values.
/// </para>
/// <para>
/// DPoP binding (RFC 9449 §6.1) is NOT validated here. When the validated
/// token carries <see cref="ConfirmationMethod.JwkThumbprint"/>, the
/// resource-server caller chains
/// <see cref="Verifiable.OAuth.Dpop.DpopProofValidator.ValidateAsync"/>
/// against the inbound DPoP proof and compares the proof's computed
/// thumbprint against the access token's <c>cnf.jkt</c>. Composition is
/// the caller's concern; the validator stays focused on the JWS access
/// token semantics.
/// </para>
/// </remarks>
public static class JwsAccessTokenValidator
{
    /// <summary>
    /// Validates a JWS-signed access token against the receiver's
    /// expectations.
    /// </summary>
    /// <param name="accessToken">The compact-serialised JWS access token.</param>
    /// <param name="expectedIssuer">The expected <c>iss</c> value; compared by ordinal equality.</param>
    /// <param name="expectedAudience">The expected <c>aud</c> value; required to be present in the claim.</param>
    /// <param name="resolveVerificationKey">
    /// Resolves the public verification key for the header's <c>kid</c>, asked under
    /// <see cref="KeyUsageContext.AccessTokenIssuance"/>: the kind this validator verifies, and the only
    /// usage signal a resource server has, since
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see> "does not provide
    /// a mechanism for identifying a specific key as the one used to sign JWT access tokens". A resolver
    /// that keeps keys apart per kind answers <see langword="null"/> for a key it holds for another usage.
    /// </param>
    /// <param name="verifySignature">The signature-verification primitive threaded into <see cref="Jws.VerifyAsync(JwsMessage, EncodeDelegate, PublicKeyMemory, VerificationDelegate, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>.</param>
    /// <param name="parser">JSON parser for header and payload segments.</param>
    /// <param name="base64UrlDecoder">Base64url decoder.</param>
    /// <param name="timeProvider">Time provider for <c>exp</c>/<c>nbf</c>/<c>iat</c> checks.</param>
    /// <param name="memoryPool">Memory pool for transient decoded buffers and pooled signing-input bytes.</param>
    /// <param name="iatSkew">Tolerance for an <c>iat</c> claim slightly in the future.</param>
    /// <param name="tenantId">Tenant identifier threaded to the key resolver.</param>
    /// <param name="context">Per-request context bag threaded to the key resolver.</param>
    /// <param name="expectedAuthorizedParty">
    /// The authorized party (the recipient's own <c>client_id</c>) to validate the <c>azp</c> claim
    /// against per OIDC Core §3.1.3.7. When <see langword="null"/>, <c>azp</c> is surfaced but not
    /// enforced. When supplied: a present <c>azp</c> must equal it, and a multi-valued <c>aud</c> must
    /// carry <c>azp</c>. <c>azp</c> is an OIDC ID Token concept; leave this <see langword="null"/> for
    /// an RFC 9068 access token that legitimately carries multiple RFC 8707 resource-indicator
    /// audiences with no <c>azp</c>, since supplying it imposes that ID Token coordination and would
    /// reject such a token.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async ValueTask<JwsAccessTokenValidationResult> ValidateAsync(
        string accessToken,
        string expectedIssuer,
        string expectedAudience,
        ServerVerificationKeyResolverDelegate resolveVerificationKey,
        VerificationDelegate verifySignature,
        JwsAccessTokenJsonParser parser,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        BaseMemoryPool memoryPool,
        TimeSpan iatSkew,
        TenantId tenantId,
        ExchangeContext context,
        string? expectedAuthorizedParty,
        CancellationToken cancellationToken)
    {
        SignedJwtValidationOutcome outcome = await ValidateSignedJwtCoreAsync(
            accessToken,
            expectedIssuer,
            expectedAudience,
            resolveVerificationKey,
            verifySignature,
            parser,
            base64UrlDecoder,
            timeProvider,
            memoryPool,
            iatSkew,
            KeyUsageContext.AccessTokenIssuance,
            tenantId,
            context,
            expectedAuthorizedParty,
            JwtTypeEnforcement.RequireAtJwt,
            cancellationToken).ConfigureAwait(false);

        if(!outcome.IsSuccess)
        {
            return outcome.PartRefusal is { } partRefusal
                ? JwsAccessTokenValidationResult.PartRefused(outcome.FailureReason!.Value, outcome.FailureDescription, partRefusal)
                : JwsAccessTokenValidationResult.Failure(outcome.FailureReason!.Value, outcome.FailureDescription);
        }

        //Optional access-token-specific claims, read from the shared core's verified payload.
        _ = TryReadString(outcome.Payload!, WellKnownJwtClaimNames.ClientId, out string? clientId);
        _ = TryReadString(outcome.Payload!, WellKnownJwtClaimNames.Scope, out string? scope);
        _ = TryReadString(outcome.Payload!, WellKnownJwtClaimNames.Jti, out string? jti);

        //RFC 7800 section 3: a cnf names the key the token is bound to. A cnf that is malformed, or that binds by a method this
        //validator does not verify, refuses the token before success, never read as an unbound token.
        var confirmationRead = ReadConfirmation(outcome.Payload!, out var confirmation);

        if(ConfirmationRefusalOf(confirmationRead, "Access token") is { } confirmationRefusal)
        {
            return JwsAccessTokenValidationResult.Failure(confirmationRefusal.FailureReason!.Value, confirmationRefusal.FailureDescription);
        }

        //RFC 8693 §4.1/§4.4: act and may_act are nested JSON objects whose members identify a party.
        //A present-but-unparseable claim is a rejection, not an omission — the token asserts a
        //delegation (or a constraint on delegation) the resource server cannot read, and the
        //permissive reading of an unreadable assertion is exactly the one an attacker would want.
        if(!TryReadActor(outcome.Payload!, out CurrentActor? act))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.Malformed,
                "Access token act claim is not a well-formed RFC 8693 §4.1 actor object.");
        }

        if(!TryReadAuthorizedActor(outcome.Payload!, out string? mayActSubject, out string? mayActIssuer))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.Malformed,
                "Access token may_act claim is not a well-formed RFC 8693 §4.4 authorized-actor object.");
        }

        JwsAccessTokenClaims claims = new()
        {
            Subject = outcome.Subject!,
            Issuer = outcome.Issuer!,
            Audience = outcome.Audience!,
            IssuedAt = outcome.IssuedAt!,
            Expiration = outcome.Expiration!,
            NotBefore = outcome.NotBefore,
            ClientId = clientId,
            AuthorizedParty = outcome.AuthorizedParty,
            Scope = scope,
            JwtId = jti,
            Confirmation = confirmation,
            Act = act,
            MayActSubject = mayActSubject,
            MayActIssuer = mayActIssuer
        };

        return JwsAccessTokenValidationResult.Success(claims);
    }


    /// <summary>
    /// The shared signed-JWT validation core behind <see cref="ValidateAsync"/> (the OAuth 2.0
    /// access-token profile, RFC 9068 §4 <c>typ</c> = <c>at+jwt</c> enforced) and
    /// <see cref="Oidc10IdTokenValidator.ValidateAsync"/> (the OIDC Core §3.1.3.7 ID Token profile,
    /// which refuses the <c>at+jwt</c> access-token type). Runs the structural parse, header
    /// <c>alg</c>/<c>kid</c> checks, the
    /// optional RFC 9068 <c>typ</c> check per <paramref name="typeEnforcement"/>, signature
    /// verification, and the standard <c>iss</c>/<c>aud</c>/<c>azp</c>/<c>exp</c>/<c>iat</c>/
    /// <c>nbf</c>/<c>sub</c> checks (including the OIDC Core §3.1.3.7 <c>azp</c> coordination shared
    /// by both profiles). Returns a neutral <see cref="SignedJwtValidationOutcome"/> exposing the
    /// verified payload rather than either profile's public result type, so neither caller
    /// duplicates this parse: <see cref="ValidateAsync"/> maps the outcome to
    /// <see cref="JwsAccessTokenClaims"/> (reading <c>client_id</c>/<c>scope</c>/<c>jti</c>/<c>cnf</c>/
    /// <c>act</c>/<c>may_act</c>),
    /// while <see cref="Oidc10IdTokenValidator.ValidateAsync"/> maps it to
    /// <see cref="Oidc10IdTokenClaims"/> (reading <c>nonce</c>/<c>auth_time</c>/<c>acr</c>/<c>amr</c>/
    /// <c>sid</c>/<c>cnf</c>, plus its own nonce and trusted-audience checks).
    /// </summary>
    /// <param name="accessToken">The compact-serialised JWS access token.</param>
    /// <param name="expectedIssuer">The expected <c>iss</c> value; compared by ordinal equality.</param>
    /// <param name="expectedAudience">The expected <c>aud</c> value; required to be present in the claim.</param>
    /// <param name="resolveVerificationKey">Resolves the public verification key for the header's <c>kid</c> under <paramref name="usage"/>.</param>
    /// <param name="verifySignature">The signature-verification primitive threaded into <see cref="Jws.VerifyAsync(JwsMessage, EncodeDelegate, PublicKeyMemory, VerificationDelegate, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>.</param>
    /// <param name="parser">JSON parser for header and payload segments.</param>
    /// <param name="base64UrlDecoder">Base64url decoder.</param>
    /// <param name="timeProvider">Time provider for <c>exp</c>/<c>nbf</c>/<c>iat</c> checks.</param>
    /// <param name="memoryPool">Memory pool for transient decoded buffers and pooled signing-input bytes.</param>
    /// <param name="iatSkew">Tolerance for an <c>iat</c> claim slightly in the future.</param>
    /// <param name="usage">
    /// The <see cref="KeyUsageContext"/> passed to <paramref name="resolveVerificationKey"/>: the kind
    /// of token this call verifies, <see cref="KeyUsageContext.AccessTokenIssuance"/> from
    /// <see cref="ValidateAsync"/> and <see cref="KeyUsageContext.IdTokenIssuance"/> from
    /// <see cref="Oidc10IdTokenValidator.ValidateAsync"/>.
    /// </param>
    /// <param name="tenantId">Tenant identifier threaded to the key resolver.</param>
    /// <param name="context">Per-request context bag threaded to the key resolver.</param>
    /// <param name="expectedAuthorizedParty">
    /// The authorized party (the recipient's own <c>client_id</c>) to validate the <c>azp</c> claim
    /// against per OIDC Core §3.1.3.7, when the calling profile enforces it. <see langword="null"/> for a
    /// profile (or a token) where <c>azp</c> coordination does not apply.
    /// </param>
    /// <param name="typeEnforcement">
    /// The header <c>typ</c> policy: <see cref="JwtTypeEnforcement.RequireAtJwt"/> for access tokens
    /// (RFC 9068 §4); <see cref="JwtTypeEnforcement.RejectAtJwt"/> for ID Tokens — which refuses
    /// <c>at+jwt</c>/<c>application/at+jwt</c> so an access token is never accepted as an ID Token
    /// (RFC 8725 §3.11). <see cref="JwtTypeEnforcement.None"/> is used by neither production caller.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    internal static async ValueTask<SignedJwtValidationOutcome> ValidateSignedJwtCoreAsync(
        string accessToken,
        string expectedIssuer,
        string expectedAudience,
        ServerVerificationKeyResolverDelegate resolveVerificationKey,
        VerificationDelegate verifySignature,
        JwsAccessTokenJsonParser parser,
        DecodeDelegate base64UrlDecoder,
        TimeProvider timeProvider,
        BaseMemoryPool memoryPool,
        TimeSpan iatSkew,
        KeyUsageContext usage,
        TenantId tenantId,
        ExchangeContext context,
        string? expectedAuthorizedParty,
        JwtTypeEnforcement typeEnforcement,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        ArgumentNullException.ThrowIfNull(expectedIssuer);
        ArgumentNullException.ThrowIfNull(expectedAudience);
        ArgumentNullException.ThrowIfNull(resolveVerificationKey);
        ArgumentNullException.ThrowIfNull(verifySignature);
        ArgumentNullException.ThrowIfNull(parser);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(memoryPool);
        ArgumentNullException.ThrowIfNull(context);

        //1. Structural parse — reject obviously malformed input cheaply. A token longer than the
        //compact JWS the signature verification accepts (Jws.DefaultMaxJwsLength) is refused here,
        //before any split or decode, rather than raised as an exception from that verification.
        if(accessToken.Length > Jws.DefaultMaxJwsLength)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.Malformed,
                "Access token exceeds the longest compact JWS this validator verifies.");
        }

        string[] parts = accessToken.Split('.');
        if(parts.Length != 3
            || string.IsNullOrEmpty(parts[0])
            || string.IsNullOrEmpty(parts[1])
            || string.IsNullOrEmpty(parts[2]))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.Malformed,
                "Access token is not a well-formed compact JWS.");
        }

        //2. Decode and parse header to extract alg + kid before signature verify (alg=none is rejected without touching the
        //signature path). The token is client-supplied wire input, structurally unverified at this point; a segment the decoder
        //refuses as no base64url text is an invalid header rather than an internal fault, and only that refusal is answered so.
        var headerReading = JwsSegmentDecoding.ReadOrNone(parts[0], parser.ParseHeader, base64UrlDecoder, memoryPool);

        if(headerReading is null)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.InvalidHeader,
                "JWS header segment is no base64url text.");
        }

        //A header the reading refuses - no one JSON object, a member name repeated, a member naming no Unicode text - names no
        //alg, kid or typ one way, so it is an invalid header, carried with the reading's own refusal.
        if(headerReading is JwtPartRefused<JwtHeader> { Refusal: var headerRefusal })
        {
            return SignedJwtValidationOutcome.PartRefused(
                JwsAccessTokenValidationFailureReason.InvalidHeader,
                "JWS header is not one JSON object naming each member once and naming Unicode text throughout.",
                new JwsPartDocumentRefusal(JwsPart.ProtectedHeader, headerRefusal));
        }

        if(headerReading is not JwtPartRead<JwtHeader> { Part: var header })
        {
            throw new InvalidOperationException("A JWS header's reading answered neither the header nor its refusal.");
        }

        if(!header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algValue)
            || algValue is not string alg
            || string.IsNullOrEmpty(alg))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.InvalidHeader,
                "JWS header is missing the alg member.");
        }

        if(WellKnownJwaValues.IsNone(alg))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.AlgorithmNotAllowed,
                "JWS alg 'none' is rejected per RFC 8725 §3.1.");
        }

        //A kid of only whitespace names no key: it is refused here as missing, so it never reaches
        //the KeyId the resolver is asked with.
        if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidValue)
            || kidValue is not string kid
            || string.IsNullOrWhiteSpace(kid))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.InvalidHeader,
                "JWS header is missing the kid member.");
        }

        //RFC 9068 §4 requires the resource server to verify the header's typ is explicitly
        //"at+jwt" or "application/at+jwt" and reject any other value — the discriminator that
        //keeps an ID Token (typ "JWT") or another JWT profile from being confused for an access
        //token. Comparison follows the existing WellKnownMediaTypes helpers, case-insensitive
        //per RFC 7515 §4.1.9 (media type values are case insensitive per RFC 2045).
        if(typeEnforcement is JwtTypeEnforcement.RequireAtJwt
            && (!header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typValue)
                || typValue is not string typ
                || string.IsNullOrEmpty(typ)
                || !(WellKnownMediaTypes.Jwt.IsAtJwt(typ) || WellKnownMediaTypes.Application.IsAtJwt(typ))))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.InvalidType,
                "JWS header typ must be 'at+jwt' or 'application/at+jwt' per RFC 9068 §4.");
        }

        //The ID Token profile does the reverse (RFC 8725 §3.11 explicit typing): it refuses the
        //access-token type so a genuine RFC 9068 access token — which may carry a machine subject
        //with no authentication event — can never be accepted as an ID Token, the relying party's
        //proof of end-user authentication. Any other typ (or an absent one) is accepted.
        if(typeEnforcement is JwtTypeEnforcement.RejectAtJwt
            && header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? idTokenTypValue)
            && idTokenTypValue is string idTokenTyp
            && (WellKnownMediaTypes.Jwt.IsAtJwt(idTokenTyp) || WellKnownMediaTypes.Application.IsAtJwt(idTokenTyp)))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.InvalidType,
                "An ID Token must not carry the access-token type 'at+jwt' (RFC 8725 §3.11 explicit typing).");
        }

        //3. Resolve verification key. The reference is owned by the resolver
        //(typically a shared keyset/HSM handle); the validator does not
        //dispose it.
        PublicKeyMemory? publicKey = await resolveVerificationKey(
            new KeyId(kid), usage, tenantId, context, cancellationToken).ConfigureAwait(false);
        if(publicKey is null)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.UnknownKid,
                "Verification key for the presented kid could not be resolved.");
        }

        //4. Verify signature via JCose's Jws.VerifyAsync — composes the
        //library's existing JWS verification primitive instead of duplicating
        //the signing-input construction and signature dispatch here.
        //
        //A malformed signature segment (for example a non-canonical base64url
        //value the decoder rejects) cannot verify: Jws.VerifyAsync returns
        //false rather than throwing on untrusted input, so the caller maps the
        //resulting SignatureFailed to invalid_request instead of surfacing a 500.
        bool signatureValid = await Jws.VerifyAsync(
            accessToken,
            base64UrlDecoder,
            memoryPool,
            publicKey,
            verifySignature,
            cancellationToken).ConfigureAwait(false);

        if(!signatureValid)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.SignatureFailed,
                "JWS signature did not verify against the resolved key.");
        }

        //5. Decode and parse payload. Same rationale as the header decode above: the token is untrusted wire input, so a segment
        //the decoder refuses is malformed rather than an internal fault.
        var payloadReading = JwsSegmentDecoding.ReadOrNone(parts[1], parser.ParseClaims, base64UrlDecoder, memoryPool);

        if(payloadReading is null)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.Malformed,
                "JWS payload segment is no base64url text.");
        }

        //A claims set the reading refuses names no claim one way, so the token is malformed, carried with the reading's own refusal.
        if(payloadReading is JwtPartRefused<JwtPayload> { Refusal: var payloadRefusal })
        {
            return SignedJwtValidationOutcome.PartRefused(
                JwsAccessTokenValidationFailureReason.Malformed,
                "JWS payload is not one JSON object naming each claim once and naming Unicode text throughout.",
                new JwsPartDocumentRefusal(JwsPart.Payload, payloadRefusal));
        }

        if(payloadReading is not JwtPartRead<JwtPayload> { Part: var payload })
        {
            throw new InvalidOperationException("A JWS payload's reading answered neither the claims set nor its refusal.");
        }

        //6. Standard claim checks.
        if(!TryReadString(payload, WellKnownJwtClaimNames.Iss, out string? iss))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                "Access token is missing the iss claim.");
        }

        if(!string.Equals(iss, expectedIssuer, StringComparison.Ordinal))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.IssuerMismatch,
                "Access token iss does not match the expected issuer.");
        }

        //RFC 7519 section 4.1.3: aud is one StringOrURI or an array of them. A present aud of another shape - an array holding
        //an element that is no non-empty string among them - is refused whole, never filtered into the audiences it does name.
        var audienceRead = ReadStringList(payload, WellKnownJwtClaimNames.Aud, out var audience);
        if(audienceRead != ClaimReadResult.Value)
        {
            return audienceRead == ClaimReadResult.Absent
                ? SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                    "Access token is missing the aud claim.")
                : SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.Malformed,
                    "Access token aud claim is neither a non-empty string nor a non-empty array of non-empty strings.");
        }

        if(!ContainsAudience(audience, expectedAudience))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.AudienceMismatch,
                "Access token aud does not contain the expected audience.");
        }

        //OIDC Core §3.1.3.7 azp coordination — a present azp must equal the recipient's own client_id,
        //and a multi-valued aud must carry azp. Enforced only when the caller supplies the expected
        //authorized party (the party validating azp); azp is otherwise surfaced but not enforced.
        _ = TryReadString(payload, WellKnownJwtClaimNames.Azp, out string? azp);
        if(expectedAuthorizedParty is not null)
        {
            if(azp is null)
            {
                if(audience.Count > 1)
                {
                    return SignedJwtValidationOutcome.Failure(
                        JwsAccessTokenValidationFailureReason.AuthorizedPartyMissing,
                        "Access token has multiple audiences but no azp claim (OIDC Core §3.1.3.7).");
                }
            }
            else if(!string.Equals(azp, expectedAuthorizedParty, StringComparison.Ordinal))
            {
                return SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.AuthorizedPartyMismatch,
                    "Access token azp does not equal the expected authorized party.");
            }
        }

        var expRead = TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Exp, out var expiry);
        if(expRead != NumericDateReadResult.Value)
        {
            return expRead == NumericDateReadResult.Absent
                ? SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                    "Access token is missing the exp claim.")
                : SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.Malformed,
                    "Access token exp claim is not a NumericDate naming a representable instant.");
        }

        var iatRead = TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Iat, out var issuedAt);
        if(iatRead != NumericDateReadResult.Value)
        {
            return iatRead == NumericDateReadResult.Absent
                ? SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                    "Access token is missing the iat claim.")
                : SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.Malformed,
                    "Access token iat claim is not a NumericDate naming a representable instant.");
        }

        var exp = expiry!;
        var iat = issuedAt!;

        //Structural temporal consistency, independent of the current clock: a token whose exp is at or
        //before its iat has no positive lifetime and is nonsensical regardless of when it is checked.
        if(exp.CompareTo(iat) <= 0)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.InconsistentTemporalClaims,
                "Access token exp is at or before iat (non-positive lifetime).");
        }

        var now = timeProvider.GetUtcNow();

        if(exp.CompareTo(now) <= 0)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.Expired,
                "Access token has expired.");
        }

        if(iat.CompareToLaterBy(now, iatSkew) > 0)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.IssuedInFuture,
                "Access token iat is in the future beyond the skew tolerance.");
        }

        //RFC 7519 §4.1.5: "The "nbf" (not before) claim identifies the time before which the JWT MUST
        //NOT be accepted for processing." An absent nbf sets no such time; a present one no instant can
        //be read from names a time that cannot be checked, so the token is refused rather than read
        //as carrying no nbf.
        var nbf = default(NumericDate);
        var nbfRead = TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Nbf, out var nbfValue);
        if(nbfRead == NumericDateReadResult.Malformed)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.Malformed,
                "Access token nbf claim is not a NumericDate naming a representable instant.");
        }

        if(nbfRead == NumericDateReadResult.Value)
        {
            if(nbfValue!.CompareToLaterBy(now, iatSkew) > 0)
            {
                return SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.NotYetValid,
                    "Access token nbf is in the future.");
            }

            //Structural consistency (clock-independent): exp at or before nbf means the validity window
            //never opens.
            if(exp.CompareTo(nbfValue) <= 0)
            {
                return SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.InconsistentTemporalClaims,
                    "Access token exp is at or before nbf (the validity window never opens).");
            }

            nbf = nbfValue;
        }

        if(!TryReadString(payload, WellKnownJwtClaimNames.Sub, out string? sub))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                "Access token is missing the sub claim.");
        }

        return SignedJwtValidationOutcome.Success(payload, sub!, iss!, audience, azp, iat, exp, nbf);
    }


    internal static bool TryReadString(JwtPayload payload, string claimName, out string? value)
    {
        if(payload.TryGetValue(claimName, out object? raw) && raw is string s && !string.IsNullOrEmpty(s))
        {
            value = s;
            return true;
        }

        value = null;
        return false;
    }


    /// <summary>
    /// Reads a claim whose JSON value is either a single string or an array of strings — the RFC 7519 §4.1.3 <c>aud</c> shape,
    /// also the OIDC Core §2 <c>amr</c> claim's — normalising both wire shapes into a list; a single string becomes a one-element
    /// list. An absent claim is <see cref="ClaimReadResult.Absent"/>; a present one that is neither a non-empty string nor a
    /// non-empty array every element of which is a non-empty string - an array holding a number, a <c>null</c>, a nested value
    /// or an empty string among them - is <see cref="ClaimReadResult.Malformed"/> as a whole, never filtered into the strings it
    /// does hold (<see cref="JwtPayload"/> satisfies <see cref="IReadOnlyDictionary{TKey, TValue}"/>, so any verified claim
    /// dictionary reads through the same call).
    /// </summary>
    /// <param name="claims">The verified claims.</param>
    /// <param name="claimName">The claim.</param>
    /// <param name="list">The values when the result is <see cref="ClaimReadResult.Value"/>; otherwise empty.</param>
    /// <returns>Whether the claim is absent, a list of strings, or malformed.</returns>
    internal static ClaimReadResult ReadStringList(
        IReadOnlyDictionary<string, object> claims, string claimName, out IReadOnlyList<string> list)
    {
        list = [];

        if(!claims.TryGetValue(claimName, out var raw))
        {
            return ClaimReadResult.Absent;
        }

        var values = raw switch
        {
            string { Length: > 0 } single => new List<string> { single },
            IEnumerable<object?> elements => NonEmptyStringsOf(elements),
            _ => null
        };

        if(values is null)
        {
            return ClaimReadResult.Malformed;
        }

        list = values;

        return ClaimReadResult.Value;
    }


    /// <summary>The elements of an array as strings when it holds at least one and every one is a non-empty string; otherwise none.</summary>
    /// <param name="elements">The array's elements as the claims set holds them.</param>
    /// <returns>The strings, or <see langword="null"/>.</returns>
    private static List<string>? NonEmptyStringsOf(IEnumerable<object?> elements)
    {
        var strings = new List<string>();

        foreach(var element in elements)
        {
            if(element is not string { Length: > 0 } text)
            {
                return null;
            }

            strings.Add(text);
        }

        return strings.Count > 0 ? strings : null;
    }


    private static bool ContainsAudience(IReadOnlyList<string> audience, string expected)
    {
        for(int i = 0; i < audience.Count; i++)
        {
            if(string.Equals(audience[i], expected, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Reads the NumericDate claim <paramref name="claimName"/> (RFC 7519 §2, seconds since the Unix
    /// epoch, "other than that non-integer values can be represented") of a verified payload as the
    /// date written, every digit kept (<see cref="NumericDate.Of"/>), so a comparison with the clock
    /// judges the date against its bound exactly, never a value moved to a whole second or a tick. An
    /// absent claim is <see cref="NumericDateReadResult.Absent"/>; a present value that is not a number, or
    /// that names no instant a <see cref="DateTimeOffset"/> can hold, is
    /// <see cref="NumericDateReadResult.Malformed"/>, so every caller, the optional <c>nbf</c> and
    /// <c>auth_time</c> ones included, refuses the token as malformed instead of reading the value as
    /// absent or letting an exception escape from the conversion.
    /// </summary>
    /// <param name="payload">The verified payload.</param>
    /// <param name="claimName">The NumericDate claim to read.</param>
    /// <param name="value">The date when the result is <see cref="NumericDateReadResult.Value"/>.</param>
    /// <returns>Whether the claim is absent, holds a date, or is malformed.</returns>
    internal static NumericDateReadResult TryReadEpochSeconds(JwtPayload payload, string claimName, out NumericDate? value)
    {
        value = null;

        if(!payload.TryGetValue(claimName, out object? raw))
        {
            return NumericDateReadResult.Absent;
        }

        value = NumericDate.Of(raw);

        return value is null ? NumericDateReadResult.Malformed : NumericDateReadResult.Value;
    }


    /// <summary>
    /// Reads the <c>cnf</c> (confirmation) claim of a verified token (RFC 7800 section 3), the claim's members read through either
    /// dictionary shape a JSON object materialises as. An absent claim binds the token to no key; an object carrying only the
    /// <c>jkt</c> of RFC 9449 section 6.1, a non-empty string, binds it to that thumbprint; a claim that is no object, an object
    /// carrying no member, or a <c>jkt</c> that is no non-empty string is malformed; and an object carrying any other confirmation
    /// method - one this library does not verify possession under - is answered as that, so no reading invents a binding a token
    /// does not carry or the absence of one it does.
    /// </summary>
    /// <param name="payload">The verified payload.</param>
    /// <param name="confirmation">The binding when the result is <see cref="ConfirmationReadResult.Bound"/>; otherwise <see langword="null"/>.</param>
    /// <returns>What the claim was found to be.</returns>
    internal static ConfirmationReadResult ReadConfirmation(JwtPayload payload, out ConfirmationMethod? confirmation)
    {
        confirmation = null;

        if(!payload.TryGetValue(WellKnownJwtClaimNames.Cnf, out var raw))
        {
            return ConfirmationReadResult.Absent;
        }

        if(raw is not IEnumerable<KeyValuePair<string, object>> members)
        {
            return ConfirmationReadResult.Malformed;
        }

        string? jkt = null;

        foreach(var member in members)
        {
            if(!WellKnownJwtClaimNames.IsJwkThumbprint(member.Key))
            {
                return ConfirmationReadResult.UnsupportedMethod;
            }

            if(member.Value is not string { Length: > 0 } thumbprint)
            {
                return ConfirmationReadResult.Malformed;
            }

            jkt = thumbprint;
        }

        if(jkt is null)
        {
            return ConfirmationReadResult.Malformed;
        }

        confirmation = new ConfirmationMethod { JwkThumbprint = jkt };

        return ConfirmationReadResult.Bound;
    }


    /// <summary>
    /// The failure a token's <c>cnf</c> reading refuses it with, or <see langword="null"/> for an absent claim and a binding this
    /// library verifies: a malformed claim as <see cref="JwsAccessTokenValidationFailureReason.Malformed"/>, a confirmation method
    /// it does not verify as <see cref="JwsAccessTokenValidationFailureReason.UnsupportedConfirmationMethod"/>.
    /// </summary>
    /// <param name="read">What the reading found.</param>
    /// <param name="tokenKind">The kind of token, as its failure descriptions name it.</param>
    /// <returns>The failure, or <see langword="null"/>.</returns>
    internal static SignedJwtValidationOutcome? ConfirmationRefusalOf(ConfirmationReadResult read, string tokenKind) => read switch
    {
        ConfirmationReadResult.Absent or ConfirmationReadResult.Bound => null,
        ConfirmationReadResult.Malformed => SignedJwtValidationOutcome.Failure(
            JwsAccessTokenValidationFailureReason.Malformed,
            $"{tokenKind} cnf claim is not a JSON object carrying its confirmation method in the registered shape (RFC 7800 §3.1, RFC 9449 §6.1)."),
        ConfirmationReadResult.UnsupportedMethod => SignedJwtValidationOutcome.Failure(
            JwsAccessTokenValidationFailureReason.UnsupportedConfirmationMethod,
            $"{tokenKind} cnf claim binds the token by a confirmation method this validator does not verify possession under (RFC 7800 §3)."),
        _ => throw new InvalidOperationException($"The confirmation reading {read} is none this validator answers.")
    };


    /// <summary>
    /// Reads the <c>act</c> (actor) claim of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> into a
    /// <see cref="CurrentActor"/>, flattening the nested prior-actor chain into
    /// <see cref="CurrentActor.DelegationHistory"/> in nesting order: §4.1 states "The outermost 'act'
    /// claim represents the current actor while nested 'act' claims represent prior actors. The least
    /// recent actor is the most deeply nested", so the first history element is the actor nested
    /// immediately within the current one and the last is the least recent. Structural sibling of
    /// <see cref="ReadConfirmation"/>: the nested claim object is read through either dictionary
    /// shape a JSON parser materialises a JSON object as.
    /// </summary>
    /// <param name="payload">The signature-verified access token payload.</param>
    /// <param name="actor">
    /// The current actor when the claim is present and well formed; <see langword="null"/> when the
    /// token carries no <c>act</c> claim, and also <see langword="null"/> when the claim is malformed
    /// so no partially parsed actor can escape the failure path.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the claim is absent or fully parsed; <see langword="false"/> when it
    /// is present but malformed — a value that is not a JSON object, a nesting level that is not a JSON
    /// object, an actor naming no <c>sub</c>, or a <c>sub</c>/<c>iss</c> member that is not a non-empty
    /// string. The caller rejects the token on <see langword="false"/>: a delegation the resource server
    /// cannot read whole must not be reported as a token with no delegation at all.
    /// </returns>
    private static bool TryReadActor(JwtPayload payload, out CurrentActor? actor)
    {
        actor = null;
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Act, out object? raw))
        {
            return true;
        }

        if(!TryReadActorIdentity(raw, out string? subject, out string? issuer) || subject is null)
        {
            return false;
        }

        //§4.1: "A chain of delegation can be expressed by nesting one 'act' claim within another."
        //The walk follows that nesting one level per iteration instead of recursing, so a long chain
        //costs no stack; its length is bounded by the object depth the JSON parser already accepted.
        List<PriorActor> history = [];
        object? current = raw;
        while(TryReadClaimMember(current, WellKnownJwtClaimNames.Act, out object? nested))
        {
            if(!TryReadActorIdentity(nested, out string? priorSubject, out string? priorIssuer) || priorSubject is null)
            {
                return false;
            }

            history.Add(new PriorActor { Subject = priorSubject, Issuer = priorIssuer });
            current = nested;
        }

        actor = new CurrentActor { Subject = subject, Issuer = issuer, DelegationHistory = history };

        return true;
    }


    /// <summary>
    /// Reads the <c>may_act</c> (authorized actor) claim of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see> — "a
    /// statement that one party is authorized to become the actor and act on behalf of another party"
    /// — into the <c>sub</c>/<c>iss</c> pair §4.4 describes as "sometimes necessary to uniquely
    /// identify an authorized actor". Unlike <c>act</c> the claim has no nesting: it names a single
    /// eligible party.
    /// </summary>
    /// <param name="payload">The signature-verified access token payload.</param>
    /// <param name="subject">The <c>sub</c> member, or <see langword="null"/> when the claim is absent or names no subject.</param>
    /// <param name="issuer">The <c>iss</c> member, or <see langword="null"/> when the claim is absent or names no issuer.</param>
    /// <returns>
    /// <see langword="true"/> when the claim is absent or fully parsed; <see langword="false"/> when it
    /// is present but malformed — a value that is not a JSON object, a <c>sub</c>/<c>iss</c> member that
    /// is not a non-empty string, or an object naming neither. The last case is a rejection rather than
    /// an empty result because reducing an unreadable authorized-actor statement to "no constraint"
    /// erases the very restriction the subject placed on who may act for it.
    /// </returns>
    private static bool TryReadAuthorizedActor(JwtPayload payload, out string? subject, out string? issuer)
    {
        subject = null;
        issuer = null;
        if(!payload.TryGetValue(WellKnownJwtClaimNames.MayAct, out object? raw))
        {
            return true;
        }

        return TryReadActorIdentity(raw, out subject, out issuer) && (subject is not null || issuer is not null);
    }


    /// <summary>
    /// Reads the identity members of one <c>act</c>/<c>may_act</c> object. Per RFC 8693 §4.1/§4.4 the
    /// members of such an object "pertain only to the identity" of the party, so only <c>sub</c> and
    /// <c>iss</c> are mapped; any other member — including the non-identity <c>exp</c>/<c>nbf</c>/
    /// <c>aud</c> those sections declare "not meaningful" inside an actor object — is ignored and never
    /// treated as a validity input for the containing token.
    /// </summary>
    /// <param name="claimObject">The claim value, expected to be a JSON object.</param>
    /// <param name="subject">The <c>sub</c> member when present, otherwise <see langword="null"/>.</param>
    /// <param name="issuer">The <c>iss</c> member when present, otherwise <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="false"/> when the value is not a JSON object, or when a <c>sub</c>/<c>iss</c>
    /// member is present as anything other than a non-empty string; <see langword="true"/> otherwise,
    /// with absent members left <see langword="null"/> for the caller to require as its claim demands.
    /// </returns>
    private static bool TryReadActorIdentity(object? claimObject, out string? subject, out string? issuer)
    {
        subject = null;
        issuer = null;
        if(claimObject is not (IReadOnlyDictionary<string, object> or IDictionary<string, object>))
        {
            return false;
        }

        if(TryReadClaimMember(claimObject, WellKnownJwtClaimNames.Sub, out object? subValue))
        {
            if(subValue is not string sub || string.IsNullOrEmpty(sub))
            {
                return false;
            }

            subject = sub;
        }

        if(TryReadClaimMember(claimObject, WellKnownJwtClaimNames.Iss, out object? issValue))
        {
            if(issValue is not string iss || string.IsNullOrEmpty(iss))
            {
                return false;
            }

            issuer = iss;
        }

        return true;
    }


    /// <summary>
    /// Reads one member of a nested claim object, accepting either dictionary shape a JSON parser may
    /// materialise a JSON object as — the same dual read <see cref="ReadConfirmation"/> performs for
    /// <c>cnf</c>, factored out here because an actor chain looks up several members per level.
    /// </summary>
    /// <param name="claimObject">The claim value to read a member from.</param>
    /// <param name="memberName">The member name.</param>
    /// <param name="value">The member value when present, otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is a dictionary carrying the member.</returns>
    private static bool TryReadClaimMember(object? claimObject, string memberName, out object? value)
    {
        if(claimObject is IReadOnlyDictionary<string, object> readOnly)
        {
            bool isPresent = readOnly.TryGetValue(memberName, out object? readOnlyValue);
            value = readOnlyValue;

            return isPresent;
        }

        if(claimObject is IDictionary<string, object> writable)
        {
            bool isPresent = writable.TryGetValue(memberName, out object? writableValue);
            value = writableValue;

            return isPresent;
        }

        value = null;

        return false;
    }
}

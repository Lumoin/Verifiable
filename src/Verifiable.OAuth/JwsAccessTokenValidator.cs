using System.Buffers;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Server;

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
///   <item><description>Signature verification via <see cref="Jws.VerifyAsync"/>.</description></item>
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
/// nested object is read through the dictionary shapes a JSON object materialises as, so the
/// supplied <see cref="JwsAccessTokenJsonParser"/> must map JSON objects to
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
    /// <param name="resolveVerificationKey">Resolves the public verification key for the header's <c>kid</c>.</param>
    /// <param name="verifySignature">The signature-verification primitive threaded into <see cref="Jws.VerifyAsync"/>.</param>
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
            tenantId,
            context,
            expectedAuthorizedParty,
            JwtTypeEnforcement.RequireAtJwt,
            cancellationToken).ConfigureAwait(false);

        if(!outcome.IsSuccess)
        {
            return JwsAccessTokenValidationResult.Failure(outcome.FailureReason!.Value, outcome.FailureDescription);
        }

        //Optional access-token-specific claims, read from the shared core's verified payload.
        TryReadString(outcome.Payload!, WellKnownJwtClaimNames.ClientId, out string? clientId);
        TryReadString(outcome.Payload!, WellKnownJwtClaimNames.Scope, out string? scope);
        TryReadString(outcome.Payload!, WellKnownJwtClaimNames.Jti, out string? jti);
        ConfirmationMethod? confirmation = TryReadConfirmation(outcome.Payload!);

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
            IssuedAt = outcome.IssuedAt!.Value,
            Expiration = outcome.Expiration!.Value,
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
    /// <param name="typeEnforcement">
    /// The header <c>typ</c> policy: <see cref="JwtTypeEnforcement.RequireAtJwt"/> for access tokens
    /// (RFC 9068 §4); <see cref="JwtTypeEnforcement.RejectAtJwt"/> for ID Tokens — which refuses
    /// <c>at+jwt</c>/<c>application/at+jwt</c> so an access token is never accepted as an ID Token
    /// (RFC 8725 §3.11). <see cref="JwtTypeEnforcement.None"/> is used by neither production caller.
    /// </param>
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

        //1. Structural parse — reject obviously malformed input cheaply.
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

        //2. Decode and parse header to extract alg + kid before signature
        //verify (alg=none is rejected without touching the signature path).
        JwtHeader header;
        try
        {
            using IMemoryOwner<byte> headerBytes = base64UrlDecoder(parts[0], memoryPool);
            header = parser.ParseHeader(headerBytes.Memory);
        }
        catch
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.InvalidHeader,
                "Failed to parse JWS header.");
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

        if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidValue)
            || kidValue is not string kid
            || string.IsNullOrEmpty(kid))
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
        if(typeEnforcement is JwtTypeEnforcement.RequireAtJwt)
        {
            if(!header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typValue)
                || typValue is not string typ
                || string.IsNullOrEmpty(typ)
                || !(WellKnownMediaTypes.Jwt.IsAtJwt(typ) || WellKnownMediaTypes.Application.IsAtJwt(typ)))
            {
                return SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.InvalidType,
                    "JWS header typ must be 'at+jwt' or 'application/at+jwt' per RFC 9068 §4.");
            }
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
            new KeyId(kid), tenantId, context, cancellationToken).ConfigureAwait(false);
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

        //5. Decode and parse payload.
        JwtPayload payload;
        try
        {
            using IMemoryOwner<byte> payloadBytes = base64UrlDecoder(parts[1], memoryPool);
            payload = parser.ParseClaims(payloadBytes.Memory);
        }
        catch
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.Malformed,
                "Failed to parse JWS payload.");
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

        if(!TryReadAudience(payload, out IReadOnlyList<string> audience))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                "Access token is missing the aud claim.");
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
        TryReadString(payload, WellKnownJwtClaimNames.Azp, out string? azp);
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

        if(!TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Exp, out DateTimeOffset exp))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                "Access token is missing the exp claim.");
        }

        if(!TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Iat, out DateTimeOffset iat))
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                "Access token is missing the iat claim.");
        }

        //Structural temporal consistency, independent of the current clock: a token whose exp is at or
        //before its iat has no positive lifetime and is nonsensical regardless of when it is checked.
        if(exp <= iat)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.InconsistentTemporalClaims,
                "Access token exp is at or before iat (non-positive lifetime).");
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        if(exp <= now)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.Expired,
                "Access token has expired.");
        }

        if(iat > now + iatSkew)
        {
            return SignedJwtValidationOutcome.Failure(
                JwsAccessTokenValidationFailureReason.IssuedInFuture,
                "Access token iat is in the future beyond the skew tolerance.");
        }

        DateTimeOffset? nbf = null;
        if(TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Nbf, out DateTimeOffset nbfValue))
        {
            if(nbfValue > now + iatSkew)
            {
                return SignedJwtValidationOutcome.Failure(
                    JwsAccessTokenValidationFailureReason.NotYetValid,
                    "Access token nbf is in the future.");
            }

            //Structural consistency (clock-independent): exp at or before nbf means the validity window
            //never opens.
            if(exp <= nbfValue)
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


    private static bool TryReadAudience(JwtPayload payload, out IReadOnlyList<string> audience) =>
        TryReadStringList(payload, WellKnownJwtClaimNames.Aud, out audience);


    /// <summary>
    /// Reads a claim whose JSON value is either a single string or an array of strings — the
    /// RFC 7519 §4.1.3 <c>aud</c> shape, also used by the OIDC Core §2 <c>amr</c> claim and (in the
    /// AuthCode JAR projection) the RFC 8707 §2.1 <c>resource</c> claim. Normalises both wire
    /// shapes into a list; a single string becomes a one-element list. Returns
    /// <see langword="false"/> (with <paramref name="list"/> empty) when the claim is absent,
    /// carries a value of neither shape, or resolves to an empty list — the caller decides whether
    /// "absent" and "present but unparseable" need distinguishing (<see cref="JwtPayload"/>
    /// satisfies <see cref="IReadOnlyDictionary{TKey, TValue}"/> via <c>Dictionary&lt;string,
    /// object&gt;</c>, so any verified claim dictionary reads through the same call).
    /// </summary>
    internal static bool TryReadStringList(
        IReadOnlyDictionary<string, object> payload, string claimName, out IReadOnlyList<string> list)
    {
        if(payload.TryGetValue(claimName, out object? raw))
        {
            if(raw is string single && !string.IsNullOrEmpty(single))
            {
                list = [single];
                return true;
            }

            if(raw is IEnumerable<string> typed)
            {
                List<string> typedList = [.. typed];
                if(typedList.Count > 0)
                {
                    list = typedList;
                    return true;
                }
            }

            if(raw is IEnumerable<object> mixed)
            {
                List<string> mixedList = [];
                foreach(object item in mixed)
                {
                    if(item is string s && !string.IsNullOrEmpty(s))
                    {
                        mixedList.Add(s);
                    }
                }

                if(mixedList.Count > 0)
                {
                    list = mixedList;
                    return true;
                }
            }
        }

        list = [];
        return false;
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


    internal static bool TryReadEpochSeconds(JwtPayload payload, string claimName, out DateTimeOffset value)
    {
        if(payload.TryGetValue(claimName, out object? raw))
        {
            long seconds;
            switch(raw)
            {
                case long l: seconds = l; break;
                case int i: seconds = i; break;
                case double d: seconds = (long)d; break;
                case decimal dec: seconds = (long)dec; break;
                default:
                    value = default;
                    return false;
            }

            value = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return true;
        }

        value = default;
        return false;
    }


    internal static ConfirmationMethod? TryReadConfirmation(JwtPayload payload)
    {
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Cnf, out object? raw))
        {
            return null;
        }

        string? jkt = null;
        if(raw is IReadOnlyDictionary<string, object> ro
            && ro.TryGetValue(WellKnownJwtClaimNames.JwkThumbprint, out object? jktValue)
            && jktValue is string jktStr)
        {
            jkt = jktStr;
        }
        else if(raw is IDictionary<string, object> writable
            && writable.TryGetValue(WellKnownJwtClaimNames.JwkThumbprint, out object? jktValue2)
            && jktValue2 is string jktStr2)
        {
            jkt = jktStr2;
        }

        return jkt is null ? null : new ConfirmationMethod { JwkThumbprint = jkt };
    }


    /// <summary>
    /// Reads the <c>act</c> (actor) claim of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> into a
    /// <see cref="CurrentActor"/>, flattening the nested prior-actor chain into
    /// <see cref="CurrentActor.DelegationHistory"/> in nesting order: §4.1 states "The outermost 'act'
    /// claim represents the current actor while nested 'act' claims represent prior actors. The least
    /// recent actor is the most deeply nested", so the first history element is the actor nested
    /// immediately within the current one and the last is the least recent. Structural sibling of
    /// <see cref="TryReadConfirmation"/>: the nested claim object is read through either dictionary
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
    /// materialise a JSON object as — the same dual read <see cref="TryReadConfirmation"/> performs for
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

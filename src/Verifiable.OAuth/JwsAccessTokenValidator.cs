using System.Buffers;
using System.Diagnostics;
using System.Text;
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
///   <item><description><c>kid</c> resolution via the supplied resolver.</description></item>
///   <item><description>Signature verification over <c>header.payload</c>.</description></item>
///   <item><description>Standard claim checks: <c>iss</c>, <c>aud</c>, <c>exp</c>, <c>nbf</c>, <c>iat</c>, <c>sub</c>.</description></item>
///   <item><description>Optional claim read: <c>client_id</c>, <c>scope</c>, <c>jti</c>, <c>cnf</c>.</description></item>
/// </list>
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
[DebuggerDisplay("JwsAccessTokenValidator")]
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
    /// <param name="verifySignature">The signature-verification primitive.</param>
    /// <param name="parser">JSON parser for header and payload segments.</param>
    /// <param name="base64UrlDecoder">Base64url decoder.</param>
    /// <param name="timeProvider">Time provider for <c>exp</c>/<c>nbf</c>/<c>iat</c> checks.</param>
    /// <param name="memoryPool">Memory pool for transient decoded buffers.</param>
    /// <param name="iatSkew">Tolerance for an <c>iat</c> claim slightly in the future. Default 60 seconds.</param>
    /// <param name="tenantId">Tenant identifier threaded to the key resolver.</param>
    /// <param name="context">Per-request context bag threaded to the key resolver.</param>
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
        MemoryPool<byte> memoryPool,
        TimeSpan iatSkew,
        TenantId tenantId,
        RequestContext context,
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
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.Malformed,
                "Access token is not a well-formed compact JWS.");
        }

        //2. Decode and parse header.
        JwtHeader header;
        try
        {
            using IMemoryOwner<byte> headerBytes = base64UrlDecoder(parts[0], memoryPool);
            header = parser.ParseHeader(headerBytes.Memory);
        }
        catch
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.InvalidHeader,
                "Failed to parse JWS header.");
        }

        //2a. alg check — reject 'none', require a string value.
        if(!header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algValue)
            || algValue is not string alg
            || string.IsNullOrEmpty(alg))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.InvalidHeader,
                "JWS header is missing the alg member.");
        }
        if(WellKnownJwaValues.IsNone(alg))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.AlgorithmNotAllowed,
                "JWS alg 'none' is rejected per RFC 8725 §3.1.");
        }

        //2b. kid must be present and resolvable.
        if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidValue)
            || kidValue is not string kid
            || string.IsNullOrEmpty(kid))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.InvalidHeader,
                "JWS header is missing the kid member.");
        }

        //3. Resolve verification key.
        PublicKeyMemory? publicKey = await resolveVerificationKey(
            new KeyId(kid), tenantId, context, cancellationToken).ConfigureAwait(false);
        if(publicKey is null)
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.UnknownKid,
                "Verification key for the presented kid could not be resolved.");
        }

        //4. Verify signature. The resolved key reference is owned by the
        //resolver (typically a shared keyset/HSM handle); the validator MUST
        //NOT dispose it — disposing would break the next request that
        //resolves the same key.
        using IMemoryOwner<byte> signatureBytes = base64UrlDecoder(parts[2], memoryPool);
        byte[] dataToVerify = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

        bool signatureValid = await verifySignature(
            dataToVerify,
            signatureBytes.Memory,
            publicKey.AsReadOnlyMemory(),
            context: null,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(!signatureValid)
        {
            return JwsAccessTokenValidationResult.Failure(
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
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.Malformed,
                "Failed to parse JWS payload.");
        }

        //6. Standard claim checks.
        if(!TryReadString(payload, WellKnownJwtClaimNames.Iss, out string? iss))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                "Access token is missing the iss claim.");
        }
        if(!string.Equals(iss, expectedIssuer, StringComparison.Ordinal))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.IssuerMismatch,
                "Access token iss does not match the expected issuer.");
        }

        if(!TryReadAudience(payload, out IReadOnlyList<string> audience))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                "Access token is missing the aud claim.");
        }
        if(!ContainsAudience(audience, expectedAudience))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.AudienceMismatch,
                "Access token aud does not contain the expected audience.");
        }

        if(!TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Exp, out DateTimeOffset exp))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                "Access token is missing the exp claim.");
        }
        if(!TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Iat, out DateTimeOffset iat))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                "Access token is missing the iat claim.");
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        if(exp <= now)
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.Expired,
                "Access token has expired.");
        }
        if(iat > now + iatSkew)
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.IssuedInFuture,
                "Access token iat is in the future beyond the skew tolerance.");
        }

        DateTimeOffset? nbf = null;
        if(TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Nbf, out DateTimeOffset nbfValue))
        {
            if(nbfValue > now + iatSkew)
            {
                return JwsAccessTokenValidationResult.Failure(
                    JwsAccessTokenValidationFailureReason.NotYetValid,
                    "Access token nbf is in the future.");
            }
            nbf = nbfValue;
        }

        if(!TryReadString(payload, WellKnownJwtClaimNames.Sub, out string? sub))
        {
            return JwsAccessTokenValidationResult.Failure(
                JwsAccessTokenValidationFailureReason.MissingRequiredClaim,
                "Access token is missing the sub claim.");
        }

        //7. Optional claims.
        TryReadString(payload, WellKnownJwtClaimNames.ClientId, out string? clientId);
        TryReadString(payload, WellKnownJwtClaimNames.Scope, out string? scope);
        TryReadString(payload, WellKnownJwtClaimNames.Jti, out string? jti);
        ConfirmationMethod? confirmation = TryReadConfirmation(payload);

        JwsAccessTokenClaims claims = new()
        {
            Subject = sub!,
            Issuer = iss!,
            Audience = audience,
            IssuedAt = iat,
            Expiration = exp,
            NotBefore = nbf,
            ClientId = clientId,
            Scope = scope,
            JwtId = jti,
            Confirmation = confirmation
        };

        return JwsAccessTokenValidationResult.Success(claims);
    }


    private static bool TryReadString(JwtPayload payload, string claimName, out string? value)
    {
        if(payload.TryGetValue(claimName, out object? raw) && raw is string s && !string.IsNullOrEmpty(s))
        {
            value = s;
            return true;
        }
        value = null;
        return false;
    }


    private static bool TryReadAudience(JwtPayload payload, out IReadOnlyList<string> audience)
    {
        if(payload.TryGetValue(WellKnownJwtClaimNames.Aud, out object? raw))
        {
            if(raw is string single && !string.IsNullOrEmpty(single))
            {
                audience = [single];
                return true;
            }

            if(raw is IEnumerable<string> typed)
            {
                List<string> list = [.. typed];
                if(list.Count > 0)
                {
                    audience = list;
                    return true;
                }
            }

            if(raw is IEnumerable<object> mixed)
            {
                List<string> list = [];
                foreach(object item in mixed)
                {
                    if(item is string s && !string.IsNullOrEmpty(s))
                    {
                        list.Add(s);
                    }
                }
                if(list.Count > 0)
                {
                    audience = list;
                    return true;
                }
            }
        }

        audience = [];
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


    private static bool TryReadEpochSeconds(JwtPayload payload, string claimName, out DateTimeOffset value)
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


    private static ConfirmationMethod? TryReadConfirmation(JwtPayload payload)
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
}

using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Jar;

namespace Verifiable.OAuth.Jarm;

/// <summary>
/// Validates a JWT-secured authorization response on the client side per the
/// <see href="https://openid.net/specs/oauth-v2-jarm-final.html#section-2.4">JARM §2.4</see>
/// processing rules — the client half of FAPI 2.0 Message Signing §5.4.2.
/// </summary>
/// <remarks>
/// <para>
/// This is a free-standing client primitive: the caller extracts the <c>response</c>
/// parameter from whatever encoding arrived (query, fragment, or form POST body — see
/// <see cref="JarmResponseEncoding"/>) and passes the compact JWT here together with
/// the issuer and client id it remembered for the authorization request in flight.
/// </para>
/// <para>
/// The §2.4 sequence: the <c>iss</c> claim must identify the expected issuer — checked
/// BEFORE any key resolution, the §5.1 defence against specially crafted JWTs steering
/// the client to hostile JWK set URLs; the <c>aud</c> claim must match the client id;
/// <c>exp</c> must be in the future; the signature must verify under an allowed
/// algorithm with <c>alg=none</c> never accepted. The grant-type-specific response
/// parameters surface on the result only when every check passed.
/// </para>
/// <para>
/// An optional <see cref="KnownAuthorizationServerIssuerResolver"/> adds the
/// <see href="https://www.rfc-editor.org/rfc/rfc9207#section-4">RFC 9207 §4</see> known-issuer
/// gate: an <c>iss</c> that ordinally matches the expected issuer but is absent from the
/// application's known-issuer store is treated as an invalid issuer, so — exactly like an
/// unexpected issuer — it never triggers key resolution either. A <see langword="null"/>
/// resolver keeps the §2.4 ordinal match as the sole issuer check.
/// </para>
/// <para>
/// Signed-and-encrypted (Nested JWT) responses are out of this primitive's scope —
/// FAPI 2.0 Message Signing §6.1 recommends against response encryption; a deployment
/// that uses it decrypts the JWE first and passes the inner signed JWT here.
/// </para>
/// </remarks>
public static class JarmResponseValidation
{
    /// <summary>
    /// Validates a JWT Response Document and returns the per-check outcome.
    /// </summary>
    /// <param name="responseJwt">The compact JWT from the <c>response</c> parameter.</param>
    /// <param name="expectedIssuer">The issuer identifier of the Authorization Server the client sent the authorization request to.</param>
    /// <param name="expectedClientId">The client id the client used to identify itself in the authorization request.</param>
    /// <param name="allowedAlgorithms">The JWS algorithms the client accepts (e.g. from its <c>authorization_signed_response_alg</c> registration). <c>none</c> is always rejected.</param>
    /// <param name="validationTime">The instant to evaluate <c>exp</c> against; callers supply their time provider's current UTC time.</param>
    /// <param name="resolveVerificationKey">The application's AS-key resolution seam (JWKS, discovery metadata, …). Invoked only after the issuer matched.</param>
    /// <param name="payloadDeserializer">Deserialises the payload JSON into a claim dictionary, so response parameters keep their JSON types (strings, numbers).</param>
    /// <param name="base64UrlDecoder">Base64url decoder.</param>
    /// <param name="memoryPool">Memory pool for transient buffers.</param>
    /// <param name="isKnownAuthorizationServerIssuer">The application's <see href="https://www.rfc-editor.org/rfc/rfc9207#section-4">RFC 9207 §4</see> known-issuer gate over its own authorization-server store (each configured AS under a UNIQUE issuer identifier); see <see cref="KnownAuthorizationServerIssuerResolver"/>. <see langword="null"/> opts out. Evaluated before any key resolution, alongside the ordinal <c>iss</c> match.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="expirationLeeway">Clock-skew leeway added to <c>exp</c>; defaults to none.</param>
    /// <returns>The per-check validation outcome.</returns>
    public static async ValueTask<JarmResponseValidationResult> ValidateAsync(
        string responseJwt,
        string expectedIssuer,
        string expectedClientId,
        IReadOnlyCollection<string> allowedAlgorithms,
        DateTimeOffset validationTime,
        ResolveJarmVerificationKeyDelegate resolveVerificationKey,
        JwtPayloadDeserializer payloadDeserializer,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool,
        KnownAuthorizationServerIssuerResolver? isKnownAuthorizationServerIssuer = null,
        TimeSpan? expirationLeeway = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(responseJwt);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedClientId);
        ArgumentNullException.ThrowIfNull(allowedAlgorithms);
        ArgumentNullException.ThrowIfNull(resolveVerificationKey);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        //Decode the header and payload and extract all fields synchronously before
        //any await boundaries (ReadOnlySpan cannot cross await).
        string? alg = null;
        string? kid = null;
        IReadOnlyDictionary<string, object>? claims = null;
        bool isStructurallyValid = false;

        string[] parts = responseJwt.Split('.');
        if(parts.Length == 3 && parts[0].Length > 0 && parts[1].Length > 0)
        {
            try
            {
                using IMemoryOwner<byte> headerBytes = base64UrlDecoder(parts[0], memoryPool);
                ReadOnlySpan<byte> header = headerBytes.Memory.Span;
                alg = JwkJsonReader.ExtractStringValue(header, WellKnownJwkMemberNames.AlgUtf8);
                kid = JwkJsonReader.ExtractStringValue(header, WellKnownJwkMemberNames.KidUtf8);

                using IMemoryOwner<byte> payloadBytes = base64UrlDecoder(parts[1], memoryPool);
                claims = payloadDeserializer(payloadBytes.Memory.Span);

                isStructurallyValid = claims is not null;
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                isStructurallyValid = false;
            }
        }

        if(!isStructurallyValid)
        {
            return new JarmResponseValidationResult();
        }

        //§2.4 step 2 + §4: iss must identify the expected issuer and, when a known-issuer
        //resolver is supplied, resolve to a known, uniquely-configured authorization server —
        //checked before any key resolution per the §5.1 DoS consideration.
        bool isIssuerValid = claims!.TryGetValue(WellKnownJwtClaimNames.Iss, out object? issValue)
            && issValue is string iss
            && string.Equals(iss, expectedIssuer, StringComparison.Ordinal)
            && (isKnownAuthorizationServerIssuer is null || isKnownAuthorizationServerIssuer(iss));

        //§2.4 step 3: aud must match the client id used in the authorization request.
        bool isAudienceValid = claims.TryGetValue(WellKnownJwtClaimNames.Aud, out object? audValue)
            && AudienceContains(audValue, expectedClientId);

        //§2.4 step 4: exp must be in the future, within leeway.
        bool isUnexpired = claims.TryGetValue(WellKnownJwtClaimNames.Exp, out object? expValue)
            && JwtClaimReaders.TryToInt64(expValue, out long expSeconds)
            && validationTime < DateTimeOffset.FromUnixTimeSeconds(expSeconds)
                + (expirationLeeway ?? TimeSpan.Zero);

        //§2.4 step 5: alg=none is never accepted; the signature is only evaluated
        //under an allowed algorithm.
        bool isAlgorithmAllowed = alg is not null
            && !string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase)
            && ContainsOrdinal(allowedAlgorithms, alg);

        bool isSignatureValid = false;
        if(isIssuerValid && isAlgorithmAllowed)
        {
            PublicKeyMemory? verificationKey = await resolveVerificationKey(
                expectedIssuer, kid, cancellationToken).ConfigureAwait(false);

            if(verificationKey is not null)
            {
                using(verificationKey)
                {
                    try
                    {
                        isSignatureValid = await Jws.VerifyAsync(
                            responseJwt, base64UrlDecoder,
                            memoryPool,
                            verificationKey, cancellationToken).ConfigureAwait(false);
                    }
                    catch(Exception ex) when(ex is FormatException or InvalidOperationException or ArgumentException)
                    {
                        isSignatureValid = false;
                    }
                }
            }
        }

        bool allChecksPassed = isIssuerValid && isAudienceValid && isUnexpired
            && isAlgorithmAllowed && isSignatureValid;

        //§2.4: the grant-type-specific response parameters MUST NOT be processed
        //before all checks succeed — they are only surfaced on a fully valid result.
        IReadOnlyDictionary<string, object>? parameters = null;
        if(allChecksPassed)
        {
            Dictionary<string, object> responseParameters = new(claims.Count, StringComparer.Ordinal);
            foreach(KeyValuePair<string, object> claim in claims)
            {
                if(!WellKnownJwtClaimNames.IsIss(claim.Key)
                    && !WellKnownJwtClaimNames.IsAud(claim.Key)
                    && !WellKnownJwtClaimNames.IsExp(claim.Key))
                {
                    responseParameters[claim.Key] = claim.Value;
                }
            }

            parameters = responseParameters;
        }

        return new JarmResponseValidationResult
        {
            IsStructurallyValid = true,
            IsIssuerValid = isIssuerValid,
            IsAudienceValid = isAudienceValid,
            IsUnexpired = isUnexpired,
            IsAlgorithmAllowed = isAlgorithmAllowed,
            IsSignatureValid = isSignatureValid,
            Parameters = parameters
        };
    }


    //The aud claim is a string or an array of strings; deserializers materialise the
    //array shape as an object sequence.
    private static bool AudienceContains(object audValue, string expectedClientId) => audValue switch
    {
        string single => string.Equals(single, expectedClientId, StringComparison.Ordinal),
        IEnumerable<object> many => ContainsOrdinalObjects(many, expectedClientId),
        _ => false
    };


    private static bool ContainsOrdinalObjects(IEnumerable<object> values, string candidate)
    {
        foreach(object value in values)
        {
            if(value is string text && string.Equals(text, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    private static bool ContainsOrdinal(IEnumerable<string> values, string candidate)
    {
        foreach(string value in values)
        {
            if(string.Equals(value, candidate, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

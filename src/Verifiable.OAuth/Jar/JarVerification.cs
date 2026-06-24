using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Jar;

/// <summary>
/// Verifies the cryptographic signature, JOSE header validity, and JWT
/// timing claims of a compact JWT Authorization Request per
/// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>,
/// returning a discriminated-union result that callers map to OAuth wire
/// error responses.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Layering.</strong> This is the cryptographic-and-format-integrity
/// layer. Protocol-shaped claim validation — <c>iss</c> matches the
/// expected issuer, <c>aud</c> matches the AS, <c>client_id</c> matches
/// the registration, <c>jti</c> not replayed — is the matcher's job
/// because those checks depend on per-flow context the primitive does
/// not carry.
/// </para>
/// <para>
/// <strong>Timing-claim discipline.</strong> All three of <c>iat</c>,
/// <c>nbf</c>, and <c>exp</c> are required. FAPI 2.0 §5.2.2 Clause 13
/// mandates <c>exp</c>; <c>iat</c> and <c>nbf</c> are required here so
/// that the lifetime ceiling check (<c>exp - iat</c>) and the
/// not-yet-valid check (<c>nbf</c> after now+skew) are unambiguous. The
/// library applies one rule across both Authorization Code JAR and
/// OID4VP JAR consumption rather than profile-divergent leniency.
/// </para>
/// </remarks>
public static class JarVerification
{
    public static async ValueTask<JarVerificationResult> VerifyAsync(
        string compactJar,
        PublicKeyMemory signingPublicKey,
        DateTimeOffset now,
        TimeSpan clockSkew,
        TimeSpan maximumLifetime,
        DecodeDelegate base64UrlDecoder,
        JwtHeaderDeserializer headerDeserializer,
        JwtPayloadDeserializer payloadDeserializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactJar);
        ArgumentNullException.ThrowIfNull(signingPublicKey);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        // Step 1 — parse the compact JWS, asking the JCose layer to
        // materialise the protected header through the supplied
        // deserializer. JwsParsing.ParseCompact's third parameter is a
        // Func<ReadOnlySpan<byte>, object?> that produces the per-signature
        // protected-header view; the named JwtHeaderDeserializer adapts to
        // that shape via a lambda. This lambda DOES capture the
        // headerDeserializer parameter — it is a deliberate exception to
        // the "no closure capture" rule, justified by the JCose API taking
        // a different delegate type than the named one. The capture is
        // contained to one call site; do not spread the pattern.
        UnverifiedJwsMessage unverified;
        try
        {
            unverified = JwsParsing.ParseCompact(
                compactJar,
                base64UrlDecoder,
                bytes => headerDeserializer(bytes),
                memoryPool);
        }
        catch(FormatException ex)
        {
            return new JarRejected(
                OAuthErrors.InvalidRequestObject,
                $"JAR is not a well-formed compact JWS: {ex.Message}");
        }

        using(unverified)
        {
            // Step 2 — read the typ header. RFC 9101 §10.8 mandates
            // 'oauth-authz-req+jwt'; the wallet/AS MUST refuse anything else.
            UnverifiedJwtHeader unverifiedHeader = unverified.Signatures[0].ProtectedHeader;

            if(!unverifiedHeader.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typObj)
                || typObj is not string typ
                || !WellKnownMediaTypes.Jwt.IsOauthAuthzReqJwt(typ))
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR typ header must be '{WellKnownMediaTypes.Jwt.OauthAuthzReqJwt}'.");
            }

            // Step 3 — verify the JWS signature. Until this passes the
            // payload is untrusted; a hostile client can put any bytes in
            // the payload of an unsigned compact JWS.
            bool signatureValid;
            try
            {
                signatureValid = await Jws.VerifyAsync(
                    compactJar,
                    base64UrlDecoder,
                    memoryPool,
                    signingPublicKey,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR signature verification raised: {ex.Message}");
            }

            if(!signatureValid)
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    "JAR signature verification failed.");
            }

            // Step 4 — parse the payload now that the signature is verified.
            // A duplicate top-level key is rejected first: the span scanner that
            // re-slices native-JSON claims (e.g. RFC 9396 authorization_details) reads the
            // FIRST occurrence while a deserializer keeps the LAST, so a signed payload with
            // a repeated key is a validate-one / act-on-another smuggling vector. There is no
            // legitimate reason for a signed Request Object to carry a duplicate top-level
            // claim, so it is refused rather than silently resolved.
            if(JwkJsonReader.HasDuplicateTopLevelKeys(unverified.Payload.Span))
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    "JAR payload carries a duplicate top-level claim name.");
            }

            IReadOnlyDictionary<string, object> claims;
            try
            {
                claims = payloadDeserializer(unverified.Payload.Span);
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR payload could not be parsed: {ex.Message}");
            }

            // Step 5 — read iat/nbf/exp. All three are required so the
            // lifetime ceiling check (exp - iat) and the not-yet-valid
            // check (nbf vs now+skew) are unambiguous.
            DateTimeOffset iat;
            DateTimeOffset nbf;
            DateTimeOffset exp;
            try
            {
                iat = JwtClaimReaders.RequireInstant(claims, WellKnownJwtClaimNames.Iat);
                nbf = JwtClaimReaders.RequireInstant(claims, WellKnownJwtClaimNames.Nbf);
                exp = JwtClaimReaders.RequireInstant(claims, WellKnownJwtClaimNames.Exp);
            }
            catch(FormatException ex)
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    ex.Message);
            }

            // Step 5b — mutual temporal consistency, independent of the clock.
            // exp at or before iat is a non-positive lifetime; exp at or before nbf
            // is a validity window that never opens. Both are structurally invalid
            // regardless of skew, so they are checked before the clock comparisons.
            if(!JwtTemporalChecks.IsPositiveInterval(iat, exp))
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR exp {exp:O} is at or before iat {iat:O} (non-positive lifetime).");
            }

            if(!JwtTemporalChecks.IsPositiveInterval(nbf, exp))
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR exp {exp:O} is at or before nbf {nbf:O} (validity window never opens).");
            }

            // Step 6 — validate the timing claims against the supplied now
            // and clock-skew tolerance. nbf in the future beyond skew rejects;
            // exp in the past beyond skew rejects. iat is checked for
            // not-in-future to defend against a clock-skewed client signing
            // far ahead.
            if(!JwtTemporalChecks.IsNotInFuture(nbf, now, clockSkew))
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR is not yet valid (nbf {nbf:O} is after now {now:O} plus clock skew).");
            }

            if(!JwtTemporalChecks.IsBeforeExpiry(now, exp, clockSkew))
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR has expired (exp {exp:O} is before now {now:O} minus clock skew).");
            }

            if(!JwtTemporalChecks.IsNotInFuture(iat, now, clockSkew))
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR iat {iat:O} is in the future beyond clock skew.");
            }

            // Step 6b — nbf age ceiling. FAPI 2.0 Message Signing §5.3.1
            // requires nbf to be no longer than a bounded interval in the
            // past (60 minutes there; this library applies the supplied
            // maximumLifetime, which the strict default sets tighter). A
            // stale-but-unexpired window would otherwise let a long-lived
            // request object linger.
            if(!JwtTemporalChecks.IsNotStale(nbf, now, clockSkew + maximumLifetime))
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR nbf {nbf:O} is more than the maximum lifetime ({maximumLifetime}) in the past.");
            }

            // Step 7 — validate the lifetime ceilings. exp - iat must not
            // exceed maximumLifetime (FAPI 2.0 §5.2.2 Clause 13), and
            // exp - nbf must not either (FAPI 2.0 Message Signing §5.3.1
            // phrases the window from nbf). Both run so neither anchor claim
            // can stretch the validity window past the ceiling.
            TimeSpan declaredLifetime = exp - iat;
            if(!JwtTemporalChecks.IsWithinLifetimeCeiling(iat, exp, maximumLifetime))
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR lifetime ({declaredLifetime}) exceeds maximum ({maximumLifetime}).");
            }

            TimeSpan windowFromNbf = exp - nbf;
            if(!JwtTemporalChecks.IsWithinLifetimeCeiling(nbf, exp, maximumLifetime))
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR exp is {windowFromNbf} after nbf, exceeding the maximum lifetime ({maximumLifetime}).");
            }

            return new JarVerified(
                ProtectedHeader: unverifiedHeader,
                Claims: claims,
                Iat: iat,
                Nbf: nbf,
                Exp: exp);
        }
    }
}

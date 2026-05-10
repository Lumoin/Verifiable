using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;

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

            if(!unverifiedHeader.TryGetValue(WellKnownJwkValues.Typ, out object? typObj)
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
                    static (ReadOnlySpan<byte> _) => (object?)null,
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
                iat = JwtClaimReaders.RequireInstant(claims, WellKnownJwtClaims.Iat);
                nbf = JwtClaimReaders.RequireInstant(claims, WellKnownJwtClaims.Nbf);
                exp = JwtClaimReaders.RequireInstant(claims, WellKnownJwtClaims.Exp);
            }
            catch(FormatException ex)
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    ex.Message);
            }

            // Step 6 — validate the timing claims against the supplied now
            // and clock-skew tolerance. nbf in the future beyond skew rejects;
            // exp in the past beyond skew rejects. iat is checked for
            // not-in-future to defend against a clock-skewed client signing
            // far ahead.
            if(nbf > now + clockSkew)
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR is not yet valid (nbf {nbf:O} is after now {now:O} plus clock skew).");
            }

            if(exp + clockSkew <= now)
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR has expired (exp {exp:O} is before now {now:O} minus clock skew).");
            }

            if(iat > now + clockSkew)
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR iat {iat:O} is in the future beyond clock skew.");
            }

            // Step 7 — validate the lifetime ceiling. exp - iat must not
            // exceed maximumLifetime. FAPI 2.0 §5.2.2 Clause 13 constrains
            // the window; the library aligns with the most demanding profile
            // it supports.
            TimeSpan declaredLifetime = exp - iat;
            if(declaredLifetime > maximumLifetime)
            {
                return new JarRejected(
                    OAuthErrors.InvalidRequestObject,
                    $"JAR lifetime ({declaredLifetime}) exceeds maximum ({maximumLifetime}).");
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

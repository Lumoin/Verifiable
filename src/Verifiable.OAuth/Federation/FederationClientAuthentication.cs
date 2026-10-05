using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Validates the claim rules of a Federation §8.8 client-authentication JWT —
/// the default <c>private_key_jwt</c> method (OpenID Connect Core 1.0 §9) — a
/// requester presents when authenticating to a federation endpoint, per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.8">OpenID Federation 1.0 §8.8</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is crypto-agnostic: it operates on the already signature-verified,
/// decoded <see cref="JwtPayload"/>. The caller owns the §8.8 signature step —
/// the JWT MUST be signed with a Federation Entity Key, so the caller resolves
/// the requester's Federation Entity Key (the keys vouched for the requester's
/// Entity Identifier by its validated Trust Chain) and verifies the signature
/// before calling <see cref="Validate"/>. Resolving the verification key from
/// the requester's own chain — never from the JWT header — is how requester
/// trust is established.
/// </para>
/// <para>
/// The claim rules enforced:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>iss</c> and <c>sub</c> both equal the requester's Entity Identifier —
///     the <c>private_key_jwt</c> shape where the assertion's issuer and subject
///     are the <c>client_id</c> (OIDC Core §9).
///   </description></item>
///   <item><description>
///     <c>aud</c> is the endpoint entity's Entity Identifier as a string or a
///     single-element array of it, and nothing else — §8.8 requires the audience
///     to be the endpoint's Entity Identifier and the endpoint MUST NOT accept
///     other audience values (an audience-injection defense).
///   </description></item>
///   <item><description><c>jti</c> is present, surfaced for the endpoint's replay store.</description></item>
///   <item><description>
///     <c>exp</c> is present and the assertion is neither expired nor not-yet-valid;
///     temporal claims are mutually consistent.
///   </description></item>
///   <item><description>
///     an <c>iat</c>, when present, lies no later than the current instant plus the skew, the refusal
///     <see cref="Server.PrivateKeyJwtClientAuthentication"/> applies: this library's policy under
///     <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see>: "Application of
///     additional restrictions and policy are at the discretion of the authorization server."
///   </description></item>
/// </list>
/// </remarks>
public static class FederationClientAuthentication
{
    /// <summary>
    /// Validates a decoded (signature-verified) §8.8 client-authentication JWT
    /// against the <c>private_key_jwt</c> claim rules.
    /// </summary>
    /// <param name="payload">The decoded, signature-verified assertion payload.</param>
    /// <param name="endpointEntityId">
    /// The Entity Identifier of the entity whose federation endpoint is being
    /// authenticated to — the only value the assertion's <c>aud</c> may name.
    /// </param>
    /// <param name="requesterEntityId">
    /// The requester's Entity Identifier — the assertion's <c>iss</c>, <c>sub</c>,
    /// and <c>client_id</c> must all equal it, and the Federation Entity Key the
    /// caller verified the signature with must belong to it.
    /// </param>
    /// <param name="now">The instant the exp, nbf and iat are evaluated against.</param>
    /// <param name="clockSkew">
    /// Tolerance applied to the <c>exp</c>, <c>nbf</c> and <c>iat</c> comparisons: an <c>nbf</c> or an <c>iat</c>
    /// later than the current instant plus this tolerance is refused, and one equal to it is accepted.
    /// </param>
    /// <returns>
    /// A successful result carrying the authenticated <c>client_id</c>, <c>jti</c>,
    /// and expiry, or a failed result whose
    /// <see cref="FederationClientAuthenticationResult.FailureReason"/> the
    /// endpoint maps onto an <c>invalid_client</c> response.
    /// </returns>
    public static FederationClientAuthenticationResult Validate(
        JwtPayload payload,
        EntityIdentifier endpointEntityId,
        EntityIdentifier requesterEntityId,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
        ArgumentNullException.ThrowIfNull(payload);

        //OIDC Core §9 private_key_jwt: iss and sub are both the client_id, which
        //for a federation requester is its Entity Identifier.
        if(!TryReadString(payload, WellKnownJwtClaimNames.Iss, out string? iss)
            || !string.Equals(iss, requesterEntityId.Value, StringComparison.Ordinal))
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client authentication JWT iss must equal the requester's Entity Identifier (private_key_jwt).");
        }

        if(!TryReadString(payload, WellKnownJwtClaimNames.Sub, out string? sub)
            || !string.Equals(sub, requesterEntityId.Value, StringComparison.Ordinal))
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client authentication JWT sub must equal the requester's Entity Identifier (private_key_jwt).");
        }

        //§8.8: aud MUST be the endpoint entity's Entity Identifier, as a string or
        //a single-element array of it; the endpoint MUST NOT accept any other
        //audience value. Element count and type are preserved so an extra
        //non-string element cannot collapse a multi-valued array to one accepted entry.
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Aud, out object? audienceRaw))
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client authentication JWT is missing the aud claim.");
        }

        string? audience = ExtractSingleAudience(audienceRaw);
        if(audience is null || !string.Equals(audience, endpointEntityId.Value, StringComparison.Ordinal))
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client authentication JWT aud must be exactly the endpoint's Entity Identifier per §8.8; no other audience values are accepted.");
        }

        //OIDC Core §9 / RFC 7523: jti is REQUIRED so the endpoint can detect replay.
        if(!TryReadString(payload, WellKnownJwtClaimNames.Jti, out string? jti))
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client authentication JWT is missing the jti claim.");
        }

        //exp is REQUIRED; a present-but-malformed temporal claim is rejected
        //rather than silently ignored, which would suppress the expiry check. The time claims are read by the
        //NumericDate reader the RFC 7523 claim rules share: a long, int, short, byte, ulong, uint, double or decimal
        //is read, a fraction kept, and a float, any other shape, a JSON string or a number no instant can hold is
        //refused as malformed.
        if(JwtBearer.Rfc7523AssertionValidation.ReadNumericDate(
            payload, WellKnownJwtClaimNames.Exp, out _, out DateTimeOffset exp) != Validation.NumericDateReadResult.Value)
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client authentication JWT is missing or has a malformed exp claim.");
        }

        Validation.NumericDateReadResult iatRead = JwtBearer.Rfc7523AssertionValidation.ReadNumericDate(
            payload, WellKnownJwtClaimNames.Iat, out _, out DateTimeOffset iat);
        if(iatRead == Validation.NumericDateReadResult.Malformed)
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client authentication JWT iat claim is malformed.");
        }

        if(iatRead == Validation.NumericDateReadResult.Value && exp <= iat)
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client authentication JWT exp is at or before iat (non-positive lifetime).");
        }

        //A client authentication JWT issued later than the clock plus the skew names a time that has not come,
        //refused as the private_key_jwt client authentication refuses it; the instants are compared through their
        //difference, so no sum leaves the representable range.
        if(iatRead == Validation.NumericDateReadResult.Value && iat - now > clockSkew)
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client assertion iat is in the future beyond the skew tolerance.");
        }

        Validation.NumericDateReadResult nbfRead = JwtBearer.Rfc7523AssertionValidation.ReadNumericDate(
            payload, WellKnownJwtClaimNames.Nbf, out _, out DateTimeOffset nbf);
        if(nbfRead == Validation.NumericDateReadResult.Malformed)
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client authentication JWT nbf claim is malformed.");
        }

        if(nbfRead == Validation.NumericDateReadResult.Value)
        {
            if(exp <= nbf)
            {
                return FederationClientAuthenticationResult.Rejected(
                    "The client authentication JWT exp is at or before nbf (the validity window never opens).");
            }

            //The comparisons of a time claim with the clock and its skew go through the difference of the two
            //instants, which any two instants a DateTimeOffset holds can form, so no sum leaves the
            //representable range.
            if(nbf - now > clockSkew)
            {
                return FederationClientAuthenticationResult.Rejected(
                    "The client authentication JWT is not yet valid (nbf is in the future beyond the skew tolerance).");
            }
        }

        if(now - exp >= clockSkew)
        {
            return FederationClientAuthenticationResult.Rejected(
                "The client authentication JWT has expired.");
        }

        return FederationClientAuthenticationResult.Authenticated(iss!, jti!, exp);
    }


    /// <summary>
    /// Reads a non-empty string claim, or returns <see langword="false"/> when it
    /// is absent or not a non-empty string.
    /// </summary>
    private static bool TryReadString(JwtPayload payload, string claimName, out string? value)
    {
        if(payload.TryGetValue(claimName, out object? raw) && raw is string text && text.Length > 0)
        {
            value = text;
            return true;
        }

        value = null;
        return false;
    }


    /// <summary>
    /// Returns the single audience value when <paramref name="audienceRaw"/> is a
    /// non-empty string or an array containing exactly one non-empty string;
    /// otherwise <see langword="null"/> (a multi-element or malformed audience is
    /// not accepted).
    /// </summary>
    private static string? ExtractSingleAudience(object audienceRaw)
    {
        if(audienceRaw is string single)
        {
            return single.Length > 0 ? single : null;
        }

        if(audienceRaw is IEnumerable<object> values)
        {
            string? only = null;
            int count = 0;
            foreach(object value in values)
            {
                count++;
                if(count > 1)
                {
                    return null;
                }

                if(value is string text && text.Length > 0)
                {
                    only = text;
                }
            }

            return only;
        }

        return null;
    }
}

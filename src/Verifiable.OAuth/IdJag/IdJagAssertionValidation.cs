using System.Diagnostics;

using Verifiable.JCose;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// Validates the claim rules an Identity Assertion JWT Authorization Grant (ID-JAG) assertion must
/// satisfy when redeemed at a Resource Authorization Server's JWT Bearer (RFC 7523) token endpoint,
/// per draft-ietf-oauth-identity-assertion-authz-grant §4.4.1 and the §9.3 same-trust-domain rule.
/// </summary>
/// <remarks>
/// <para>
/// This helper is transport- and crypto-agnostic: it operates on the already signature-verified,
/// decoded <see cref="JwtHeader"/> and <see cref="JwtPayload"/>. The caller — its
/// <see cref="Server.ValidateJwtBearerAssertionDelegate"/> wiring — owns the §4.4.1 "All of
/// Section 5.2 of [RFC7521] applies" signature step: it resolves the verification key for the
/// grant's <c>iss</c> (only a trusted IdP's key resolves, which is how issuer trust is established —
/// §9.5 forbids deriving trust from <c>sub_id.issuer</c>), verifies the signature (for example via
/// <see cref="Jws.VerifyAndDecodeAsync"/>), and then calls <see cref="Validate"/> to enforce the
/// ID-JAG-specific claim rules. On success the caller shapes a
/// <see cref="JwtBearer.JwtBearerGrant"/> from <see cref="IdJagAssertionValidationResult.Subject"/>
/// and <see cref="IdJagAssertionValidationResult.Scope"/>; on failure it returns <see langword="null"/>
/// so the grant is refused with <c>invalid_grant</c>.
/// </para>
/// <para>
/// The rules enforced (each a §4.4.1 MUST unless noted):
/// </para>
/// <list type="bullet">
///   <item><description><c>typ</c> header is <c>oauth-id-jag+jwt</c>.</description></item>
///   <item><description><c>iss</c> is present and is not the Resource Authorization Server's own issuer (§9.3).</description></item>
///   <item><description><c>aud</c> is the Resource Authorization Server's issuer as a string, or a single-element array of it; any other shape (multi-element array, mismatch) is rejected.</description></item>
///   <item><description><c>client_id</c> equals the authenticated client.</description></item>
///   <item><description><c>sub</c> and <c>exp</c> are present, the temporal claims are consistent, and the grant is neither expired nor not-yet-valid (RFC 7521 §5.2).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("IdJagAssertionValidation")]
public static class IdJagAssertionValidation
{
    /// <summary>
    /// Validates a decoded ID-JAG assertion against the §4.4.1 / §9.3 claim rules.
    /// </summary>
    /// <param name="header">The decoded (signature-verified) JWT header.</param>
    /// <param name="payload">The decoded (signature-verified) JWT payload.</param>
    /// <param name="resourceServerIssuer">
    /// The Resource Authorization Server's own issuer identifier (RFC 8414) — the value the grant's
    /// <c>aud</c> must name and that its <c>iss</c> must not equal.
    /// </param>
    /// <param name="authenticatedClientId">
    /// The <c>client_id</c> of the client authenticated on the redeem request — the grant's
    /// <c>client_id</c> claim must equal it.
    /// </param>
    /// <param name="now">The current instant for expiry / not-before evaluation.</param>
    /// <param name="clockSkew">Tolerance applied to the <c>exp</c> and <c>nbf</c> comparisons.</param>
    /// <returns>
    /// A successful <see cref="IdJagAssertionValidationResult"/> carrying the validated claims, or a
    /// failed result whose <see cref="IdJagAssertionValidationResult.FailureReason"/> the caller maps
    /// to <c>invalid_grant</c>.
    /// </returns>
    public static IdJagAssertionValidationResult Validate(
        JwtHeader header,
        JwtPayload payload,
        string resourceServerIssuer,
        string authenticatedClientId,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceServerIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticatedClientId);

        //§4.4.1: validate the JWT typ is oauth-id-jag+jwt (per RFC 8725 §3.11). A missing or wrong
        //typ means the JWT is not an ID-JAG and could be a confused-deputy substitution of an access
        //token or ID Token.
        if(!header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typValue)
            || typValue is not string typ
            || !WellKnownMediaTypes.Jwt.IsOauthIdJagJwt(typ))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.InvalidType,
                "The assertion typ header is not oauth-id-jag+jwt.");
        }

        if(!TryReadString(payload, WellKnownJwtClaimNames.Iss, out string? iss))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingIssuer,
                "The assertion is missing the iss claim.");
        }

        //§9.3: a Resource Authorization Server MUST NOT redeem an ID-JAG that was issued in its own
        //trust domain. The degenerate same-domain case is an iss equal to this server's own issuer.
        if(string.Equals(iss, resourceServerIssuer, StringComparison.Ordinal))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.SameTrustDomain,
                "The assertion iss equals this Resource Authorization Server's issuer (same trust domain).");
        }

        //§4.4.1: the aud claim MUST be the Resource Authorization Server's issuer identifier as a
        //string, or an array containing EXACTLY ONE element equal to it. Any other shape — a
        //multi-element array, an array element that is not a non-empty string, or an empty value — is
        //rejected as an audience-injection attempt. Element count and type are preserved (never
        //filtered), so an extra non-string element cannot collapse the array to a single accepted entry.
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Aud, out object? audRaw))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingAudience,
                "The assertion is missing the aud claim.");
        }

        string? audienceValue = ExtractSingleAudience(audRaw);
        if(audienceValue is null
            || !string.Equals(audienceValue, resourceServerIssuer, StringComparison.Ordinal))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.AudienceMismatch,
                "The assertion aud must be the Resource Authorization Server's issuer as a string or single-element array.");
        }

        //§4.4.1: the client_id claim MUST identify the same client as the request's client
        //authentication. This preserves the OAuth client binding across the exchange.
        if(!TryReadString(payload, WellKnownJwtClaimNames.ClientId, out string? clientId))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingClientId,
                "The assertion is missing the client_id claim.");
        }

        if(!string.Equals(clientId, authenticatedClientId, StringComparison.Ordinal))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.ClientMismatch,
                "The assertion client_id does not match the authenticated client.");
        }

        //RFC 7521 §5.2 / RFC 7523 §3 rule 2.A: the subject the access is requested for.
        if(!TryReadString(payload, WellKnownJwtClaimNames.Sub, out string? sub))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingSubject,
                "The assertion is missing the sub claim.");
        }

        //RFC 7521 §5.2: exp is REQUIRED; an assertion with no expiry — or with an exp that is present
        //but not a numeric timestamp — is rejected (a present-but-malformed temporal claim must not be
        //silently ignored, which would suppress the expiry check).
        EpochReadResult expRead = TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Exp, out DateTimeOffset exp);
        if(expRead != EpochReadResult.Value)
        {
            return IdJagAssertionValidationResult.Failure(
                expRead == EpochReadResult.Absent
                    ? IdJagValidationFailureReason.MissingExpiration
                    : IdJagValidationFailureReason.InconsistentTemporalClaims,
                expRead == EpochReadResult.Absent
                    ? "The assertion is missing the exp claim."
                    : "The assertion exp claim is not a numeric timestamp.");
        }

        EpochReadResult iatRead = TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Iat, out DateTimeOffset iat);
        if(iatRead == EpochReadResult.Malformed)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.InconsistentTemporalClaims,
                "The assertion iat claim is not a numeric timestamp.");
        }

        //Structural temporal consistency, independent of the clock: an exp at or before iat has no
        //positive lifetime and is nonsensical regardless of when it is checked.
        if(iatRead == EpochReadResult.Value && exp <= iat)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.InconsistentTemporalClaims,
                "The assertion exp is at or before iat (non-positive lifetime).");
        }

        EpochReadResult nbfRead = TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Nbf, out DateTimeOffset nbf);
        if(nbfRead == EpochReadResult.Malformed)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.InconsistentTemporalClaims,
                "The assertion nbf claim is not a numeric timestamp.");
        }

        if(nbfRead == EpochReadResult.Value)
        {
            if(exp <= nbf)
            {
                return IdJagAssertionValidationResult.Failure(
                    IdJagValidationFailureReason.InconsistentTemporalClaims,
                    "The assertion exp is at or before nbf (the validity window never opens).");
            }

            if(nbf > now + clockSkew)
            {
                return IdJagAssertionValidationResult.Failure(
                    IdJagValidationFailureReason.NotYetValid,
                    "The assertion nbf is in the future beyond the skew tolerance.");
            }
        }

        if(exp + clockSkew <= now)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.Expired,
                "The assertion has expired.");
        }

        //§9.8.1: a cnf claim binds the grant to a key. A cnf that is present but yields no usable jkt
        //thumbprint is rejected rather than silently treated as unbound, which would let a malformed
        //binding downgrade to a Bearer token and skip the proof-of-possession requirement.
        string? confirmationThumbprint = ReadConfirmationThumbprint(payload);
        if(confirmationThumbprint is null && payload.ContainsKey(WellKnownJwtClaimNames.Cnf))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedConfirmation,
                "The assertion cnf claim carries no usable jkt thumbprint.");
        }

        string? scope = TryReadString(payload, WellKnownJwtClaimNames.Scope, out string? scopeValue)
            ? scopeValue
            : null;

        //§3.1 / RFC 7519 §4.1.7: surface jti so a Resource Authorization Server can apply the RFC 7523
        //§3 (rule 7) replay defense from its own store. Not a §4.4.1 MUST, so absence does not fail here.
        string? jti = TryReadString(payload, WellKnownJwtClaimNames.Jti, out string? jtiValue) ? jtiValue : null;

        //§3.1 tenant relationships: the issuer-tenant (tenant), the Resource Authorization Server tenant
        //(aud_tenant) and that server's own subject identifier (aud_sub) are surfaced for the Resource
        //Authorization Server's subject-identifier scoping (iss + tenant + sub) and subject resolution.
        string? tenant = TryReadString(payload, WellKnownJwtClaimNames.Tenant, out string? tenantValue) ? tenantValue : null;
        string? audienceTenant = TryReadString(payload, WellKnownJwtClaimNames.AudienceTenant, out string? audienceTenantValue) ? audienceTenantValue : null;
        string? audienceSubject = TryReadString(payload, WellKnownJwtClaimNames.AudienceSubject, out string? audienceSubjectValue) ? audienceSubjectValue : null;

        //§3.2 / §9.5: surface the saml-nameid sub_id (when well-formed) for the Resource Authorization
        //Server's subject resolution. Parsing never derives trust from sub_id — the grant is already
        //validated by iss / signature / audience / client binding above.
        SamlNameIdSubjectIdentifier? subjectIdentifier =
            payload.TryGetValue(WellKnownJwtClaimNames.SubId, out object? subIdRaw)
            && SamlNameIdSubjectIdentifier.TryParse(subIdRaw, out SamlNameIdSubjectIdentifier? parsedSubjectIdentifier)
                ? parsedSubjectIdentifier
                : null;

        return new IdJagAssertionValidationResult
        {
            Subject = sub,
            Issuer = iss,
            Audience = [audienceValue],
            Tenant = tenant,
            AudienceTenant = audienceTenant,
            AudienceSubject = audienceSubject,
            SubjectIdentifier = subjectIdentifier,
            Resource = ReadStringOrArray(payload, OAuthRequestParameterNames.Resource),
            AuthorizationDetails = ReadObjectArray(payload, OAuthRequestParameterNames.AuthorizationDetails),
            ClientId = clientId,
            ConfirmationKeyThumbprint = confirmationThumbprint,
            Scope = scope,
            Jti = jti,
            IssuedAt = iatRead == EpochReadResult.Value ? iat : null,
            Expiration = exp
        };
    }


    private static IReadOnlyList<object>? ReadObjectArray(JwtPayload payload, string claimName) =>
        payload.TryGetValue(claimName, out object? raw) && raw is IReadOnlyList<object> list
            ? list
            : null;


    private static string? ReadConfirmationThumbprint(JwtPayload payload)
    {
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Cnf, out object? raw))
        {
            return null;
        }

        //RFC 9449 §6.1: cnf is a JSON object whose jkt member is the JWK SHA-256 thumbprint.
        return raw switch
        {
            IReadOnlyDictionary<string, object> ro
                when ro.TryGetValue(WellKnownJwtClaimNames.JwkThumbprint, out object? v) && v is string jkt && !string.IsNullOrEmpty(jkt) => jkt,
            IDictionary<string, object> rw
                when rw.TryGetValue(WellKnownJwtClaimNames.JwkThumbprint, out object? v) && v is string jkt && !string.IsNullOrEmpty(jkt) => jkt,
            _ => null
        };
    }


    private static List<string> ReadStringOrArray(JwtPayload payload, string claimName)
    {
        if(!payload.TryGetValue(claimName, out object? raw))
        {
            return [];
        }

        if(raw is string s)
        {
            return string.IsNullOrEmpty(s) ? [] : [s];
        }

        //Array elements may decode as object (List<object>, including covariant string[]) or, when
        //a typed list is supplied, as string. Keep every non-empty string; ignore other shapes.
        if(raw is IEnumerable<object> mixed)
        {
            List<string> list = [];
            foreach(object item in mixed)
            {
                if(item is string str && !string.IsNullOrEmpty(str))
                {
                    list.Add(str);
                }
            }

            return list;
        }

        if(raw is IEnumerable<string> typed)
        {
            List<string> list = [];
            foreach(string item in typed)
            {
                if(!string.IsNullOrEmpty(item))
                {
                    list.Add(item);
                }
            }

            return list;
        }

        return [];
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


    /// <summary>
    /// Returns the single audience value from a decoded <c>aud</c> claim — the string itself, or the
    /// sole element of a single-element array — iff it is a non-empty string; otherwise
    /// <see langword="null"/>. A multi-element array, an array element that is not a non-empty string,
    /// or an empty value all yield <see langword="null"/> (no element is filtered out, so an extra
    /// non-string element cannot collapse the array to a single accepted entry).
    /// </summary>
    private static string? ExtractSingleAudience(object audRaw) => audRaw switch
    {
        string s => string.IsNullOrEmpty(s) ? null : s,
        IEnumerable<string> typed => SingleAudienceOrNull([.. typed]),
        IEnumerable<object> mixed => SingleAudienceOrNull([.. mixed]),
        _ => null
    };


    private static string? SingleAudienceOrNull(List<string> items) =>
        items.Count == 1 && !string.IsNullOrEmpty(items[0]) ? items[0] : null;


    private static string? SingleAudienceOrNull(List<object> items) =>
        items.Count == 1 && items[0] is string s && !string.IsNullOrEmpty(s) ? s : null;


    private enum EpochReadResult
    {
        Absent,
        Value,
        Malformed
    }


    private static EpochReadResult TryReadEpochSeconds(JwtPayload payload, string claimName, out DateTimeOffset value)
    {
        value = default;
        if(!payload.TryGetValue(claimName, out object? raw))
        {
            return EpochReadResult.Absent;
        }

        long? seconds = raw switch
        {
            long l => l,
            int i => i,
            double d => (long)d,
            decimal dec => (long)dec,
            _ => null
        };
        if(seconds is null)
        {
            return EpochReadResult.Malformed;
        }

        value = DateTimeOffset.FromUnixTimeSeconds(seconds.Value);

        return EpochReadResult.Value;
    }
}

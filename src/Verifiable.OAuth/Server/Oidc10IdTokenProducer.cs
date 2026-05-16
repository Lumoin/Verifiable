using System.Globalization;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oidc;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The library's built-in <see cref="TokenProducer"/> for OpenID Connect ID
/// Tokens per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
/// </summary>
/// <remarks>
/// <para>
/// The producer applies only when <c>openid</c> is in the granted scope. Signs
/// with <see cref="KeyUsageContext.IdTokenIssuance"/>, allowing deployments to
/// use different key material for ID Tokens than for access tokens via the
/// per-usage <see cref="ClientRecord.SigningKeys"/> map.
/// </para>
/// <para>
/// Scope-driven profile/email/address/phone claims per OIDC Core §5.4 are
/// resolved through
/// <see cref="AuthorizationServerIntegration.ResolveOidcClaimsAsync"/>. The
/// producer gates each claim set on the corresponding granted scope so an
/// application populating an <see cref="OidcClaims"/> with all sub-records
/// still emits only what the granted scope authorised.
/// </para>
/// <para>
/// When the token endpoint validated a DPoP proof for the request, the
/// access-token producer's RFC 9449 §6.1 <c>cnf</c> claim is mirrored onto
/// the ID Token via <see cref="IssuanceContext.Confirmation"/>. Verifiers
/// that bind ID Tokens to a sender's proof key (high-assurance flows) get
/// the binding for free.
/// </para>
/// <para>
/// Consumed indirectly via <see cref="TokenProducer.Oidc10IdToken"/>.
/// </para>
/// </remarks>
internal static class Oidc10IdTokenProducer
{
    /// <summary>
    /// The singleton producer instance.
    /// </summary>
    public static TokenProducer Instance { get; } = new()
    {
        Name = "oidc-1.0-id-token",
        ResponseField = WellKnownTokenTypes.IdToken,
        RequiredCapability = ServerCapabilityName.OpenIdConnect,
        KeyUsage = KeyUsageContext.IdTokenIssuance,
        IsApplicable = IsApplicableAsync,
        BuildAsync = BuildAsync
    };


    private static ValueTask<bool> IsApplicableAsync(
        IssuanceContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ValueTask.FromResult(WellKnownScopes.ContainsOpenId(context.Scope));
    }


    private static async ValueTask<TokenProducerOutput> BuildAsync(
        IssuanceContext context,
        AuthorizationServer server,
        KeyId signingKeyId,
        string algorithm,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(server);
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);

        TimeSpan lifetime =
            context.Registration.GetTokenLifetime(WellKnownTokenTypes.IdToken)
                ?? TimeSpan.FromHours(1);
        DateTimeOffset expiresAt = context.IssuedAt.Add(lifetime);

        //RFC 8414 §3 + RFC 9207 §2.4 require exact-string equality on the
        //issuer identifier; preserve the URL verbatim — matches the
        //access-token producer's reasoning.
        string issuerValue = context.IssuerUri.OriginalString;

        //Resolve scope-driven OIDC claims through the application's source.
        //Optional: a deployment may enrol the producer to honour openid scope
        //and emit a minimal ID Token (sub/iss/aud/exp/iat/nonce/auth_time
        //only — no scope-driven profile/email/etc claims) without wiring a
        //resolver. When the resolver IS wired but returns null for the
        //subject, fall back to the minimal shape as well — the AS already
        //authenticated this subject, so a null result is treated as "no
        //extra claims available," not as a hard error.
        OidcClaims claims;
        ResolveOidcClaimsDelegate? resolve = server.Integration.ResolveOidcClaimsAsync;
        if(resolve is not null)
        {
            OidcClaims? resolved = await resolve(
                context.Subject,
                context.Scope,
                context.Registration.TenantId,
                context.Context,
                cancellationToken).ConfigureAwait(false);

            claims = resolved ?? new OidcClaims { Subject = context.Subject };
        }
        else
        {
            claims = new OidcClaims { Subject = context.Subject };
        }

        //Authentication context overrides come from the resolved claim set;
        //fall back to the issuance-context's auth_time for the plain case.
        DateTimeOffset? authTime = claims.AuthContext?.AuthTime ?? context.AuthTime;
        string? acr = claims.AuthContext?.Acr;
        IReadOnlyList<string>? amr = claims.AuthContext?.Amr is { Count: > 0 } amrList
            ? amrList : null;

        //Scope-driven claim emission per OIDC Core §5.4. Each scope gates its
        //own claim set; an application populating an OidcClaims with all
        //sub-records still emits only what the granted scope authorised.
        List<KeyValuePair<string, object>> extraClaims = [];
        AppendProfileClaims(extraClaims, claims.Profile, context.Scope);
        AppendEmailClaims(extraClaims, claims.Email, context.Scope);
        AppendAddressClaims(extraClaims, claims.Address, context.Scope);
        AppendPhoneClaims(extraClaims, claims.Phone, context.Scope);

        //RFC 9449 §6.1 — when the token endpoint validated a DPoP proof the
        //ID Token gets the same cnf.jkt binding the access token receives.
        //Verifiers that check ID Token binding (rare today, increasingly
        //relevant for high-assurance flows) can rely on it without changes
        //elsewhere.
        if(context.Confirmation is { IsEmpty: false } confirmation
            && confirmation.JwkThumbprint is not null)
        {
            Dictionary<string, object> cnf = new(StringComparer.Ordinal)
            {
                [WellKnownJwtClaimNames.JwkThumbprint] = confirmation.JwkThumbprint
            };
            extraClaims.Add(new KeyValuePair<string, object>(WellKnownJwtClaimNames.Cnf, cnf));
        }

        JwtHeader header = JwtHeader.ForIdToken(algorithm, signingKeyId.Value);
        JwtPayload payload = JwtPayload.ForIdToken(
            issuer: issuerValue,
            subject: claims.Subject,
            audience: context.ClientId,
            issuedAt: context.IssuedAt,
            expiresAt: expiresAt,
            authTime: authTime,
            nonce: context.Nonce,
            acr: acr,
            amr: amr,
            azp: null,
            claims: extraClaims.Count > 0 ? extraClaims : null);

        return new TokenProducerOutput(header, payload);
    }


    private static void AppendProfileClaims(
        List<KeyValuePair<string, object>> sink, ProfileClaims? profile, string scope)
    {
        if(profile is null || !WellKnownScopes.ContainsProfile(scope)) { return; }

        Add(sink, WellKnownJwtClaimNames.Name, profile.Name);
        Add(sink, WellKnownJwtClaimNames.FamilyName, profile.FamilyName);
        Add(sink, WellKnownJwtClaimNames.GivenName, profile.GivenName);
        Add(sink, WellKnownJwtClaimNames.MiddleName, profile.MiddleName);
        Add(sink, WellKnownJwtClaimNames.Nickname, profile.Nickname);
        Add(sink, WellKnownJwtClaimNames.PreferredUsername, profile.PreferredUsername);
        if(profile.Profile is { } p) { sink.Add(new(WellKnownJwtClaimNames.Profile, p.OriginalString)); }
        if(profile.Picture is { } pic) { sink.Add(new(WellKnownJwtClaimNames.Picture, pic.OriginalString)); }
        if(profile.Website is { } w) { sink.Add(new(WellKnownJwtClaimNames.Website, w.OriginalString)); }
        Add(sink, WellKnownJwtClaimNames.Gender, profile.Gender);
        if(profile.Birthdate is { } bd)
        {
            sink.Add(new(WellKnownJwtClaimNames.Birthdate, bd.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)));
        }
        Add(sink, WellKnownJwtClaimNames.Zoneinfo, profile.Zoneinfo);
        Add(sink, WellKnownJwtClaimNames.Locale, profile.Locale);
        if(profile.UpdatedAt is { } ua)
        {
            sink.Add(new(WellKnownJwtClaimNames.UpdatedAt, ua.ToUnixTimeSeconds()));
        }
    }


    private static void AppendEmailClaims(
        List<KeyValuePair<string, object>> sink, EmailClaims? email, string scope)
    {
        if(email is null || !WellKnownScopes.ContainsEmail(scope)) { return; }

        sink.Add(new(WellKnownJwtClaimNames.Email, email.Email));
        if(email.EmailVerified is { } v) { sink.Add(new(WellKnownJwtClaimNames.EmailVerified, v)); }
    }


    private static void AppendAddressClaims(
        List<KeyValuePair<string, object>> sink, AddressClaims? address, string scope)
    {
        if(address is null || !WellKnownScopes.ContainsAddress(scope)) { return; }

        Dictionary<string, object> addressClaim = new(StringComparer.Ordinal);
        AddIfPresent(addressClaim, "formatted", address.Formatted);
        AddIfPresent(addressClaim, "street_address", address.StreetAddress);
        AddIfPresent(addressClaim, "locality", address.Locality);
        AddIfPresent(addressClaim, "region", address.Region);
        AddIfPresent(addressClaim, "postal_code", address.PostalCode);
        AddIfPresent(addressClaim, "country", address.Country);

        if(addressClaim.Count > 0)
        {
            sink.Add(new(WellKnownJwtClaimNames.Address, addressClaim));
        }
    }


    private static void AppendPhoneClaims(
        List<KeyValuePair<string, object>> sink, PhoneClaims? phone, string scope)
    {
        if(phone is null || !WellKnownScopes.ContainsPhone(scope)) { return; }

        sink.Add(new(WellKnownJwtClaimNames.PhoneNumber, phone.PhoneNumber));
        if(phone.PhoneNumberVerified is { } v) { sink.Add(new(WellKnownJwtClaimNames.PhoneNumberVerified, v)); }
    }


    private static void Add(List<KeyValuePair<string, object>> sink, string name, string? value)
    {
        if(value is not null) { sink.Add(new(name, value)); }
    }


    private static void AddIfPresent(Dictionary<string, object> sink, string name, string? value)
    {
        if(value is not null) { sink[name] = value; }
    }
}

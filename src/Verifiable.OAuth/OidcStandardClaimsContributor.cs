using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Library-shipped contributors for OpenID Connect Core 1.0 §5.4 standard
/// claim families — <c>profile</c>, <c>email</c>, <c>address</c>,
/// <c>phone</c>. Each method is a
/// <see cref="ClaimDelegateAsync{T}"/> registered on
/// <see cref="ContributionProfiles.StandardRules"/>; pattern-matches on
/// <see cref="IdTokenTarget"/> and <see cref="UserInfoTarget"/>;
/// scope-gates emission via <see cref="WellKnownScopes"/>; reads claim
/// values from <c>target.ResolvedOidcClaims</c> when populated and
/// otherwise invokes the application's
/// <see cref="AuthorizationServerIntegration.ResolveOidcClaimsAsync"/>
/// to resolve them.
/// </summary>
/// <remarks>
/// <para>
/// The four methods extract faithfully from the producer's
/// <c>AppendProfileClaims</c>, <c>AppendEmailClaims</c>,
/// <c>AppendAddressClaims</c>, and <c>AppendPhoneClaims</c> helpers —
/// same property handling, same wire-format claim names, same value
/// formatting (<see cref="Uri.OriginalString"/> for URIs, ISO-8601
/// <c>yyyy-MM-dd</c> for <see cref="DateOnly"/>, Unix-seconds for
/// <see cref="DateTimeOffset"/>).
/// </para>
/// <para>
/// Each emission produces one <see cref="Claim"/> per JWT claim, all
/// sharing the family's <see cref="WellKnownClaimIds"/> entry as the
/// <see cref="Claim.Id"/>. The walking site reads every
/// <see cref="ClaimOutcome.Success"/> claim and merges its
/// <see cref="ClaimContributionContext"/> (claim name and value) into the
/// response payload.
/// </para>
/// </remarks>
[DebuggerDisplay("OidcStandardClaimsContributor")]
public static class OidcStandardClaimsContributor
{
    /// <summary>
    /// Emits the OIDC Core §5.4 <c>profile</c>-scope claims (<c>name</c>,
    /// <c>family_name</c>, <c>given_name</c>, <c>middle_name</c>,
    /// <c>nickname</c>, <c>preferred_username</c>, <c>profile</c>,
    /// <c>picture</c>, <c>website</c>, <c>gender</c>, <c>birthdate</c>,
    /// <c>zoneinfo</c>, <c>locale</c>, <c>updated_at</c>).
    /// </summary>
    public static async ValueTask<List<Claim>> GenerateProfileClaims(
        ClaimContributionTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if(!TryExtractOidcContext(target, out OidcContributionContext? ctx)
            || !WellKnownScopes.ContainsProfile(ctx.Scope))
        {
            return [new Claim(WellKnownClaimIds.OidcProfile, ClaimOutcome.NotApplicable)];
        }

        OidcClaims? oidcClaims = await ResolveAsync(ctx, cancellationToken).ConfigureAwait(false);
        if(oidcClaims?.Profile is not { } profile)
        {
            return [new Claim(WellKnownClaimIds.OidcProfile, ClaimOutcome.NotApplicable)];
        }

        List<Claim> claims = [];
        AddString(claims, WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.Name, profile.Name);
        AddString(claims, WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.FamilyName, profile.FamilyName);
        AddString(claims, WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.GivenName, profile.GivenName);
        AddString(claims, WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.MiddleName, profile.MiddleName);
        AddString(claims, WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.Nickname, profile.Nickname);
        AddString(claims, WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.PreferredUsername, profile.PreferredUsername);

        if(profile.Profile is { } p)
        {
            claims.Add(Success(WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.Profile, p.OriginalString));
        }

        if(profile.Picture is { } pic)
        {
            claims.Add(Success(WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.Picture, pic.OriginalString));
        }

        if(profile.Website is { } w)
        {
            claims.Add(Success(WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.Website, w.OriginalString));
        }

        AddString(claims, WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.Gender, profile.Gender);

        if(profile.Birthdate is { } bd)
        {
            claims.Add(Success(
                WellKnownClaimIds.OidcProfile,
                WellKnownJwtClaimNames.Birthdate,
                bd.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)));
        }

        AddString(claims, WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.Zoneinfo, profile.Zoneinfo);
        AddString(claims, WellKnownClaimIds.OidcProfile, WellKnownJwtClaimNames.Locale, profile.Locale);

        if(profile.UpdatedAt is { } ua)
        {
            claims.Add(Success(
                WellKnownClaimIds.OidcProfile,
                WellKnownJwtClaimNames.UpdatedAt,
                ua.ToUnixTimeSeconds()));
        }

        if(claims.Count == 0)
        {
            claims.Add(new Claim(WellKnownClaimIds.OidcProfile, ClaimOutcome.NotApplicable));
        }

        return claims;
    }


    /// <summary>
    /// Emits the OIDC Core §5.4 <c>email</c>-scope claims (<c>email</c>,
    /// <c>email_verified</c>).
    /// </summary>
    public static async ValueTask<List<Claim>> GenerateEmailClaims(
        ClaimContributionTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if(!TryExtractOidcContext(target, out OidcContributionContext? ctx)
            || !WellKnownScopes.ContainsEmail(ctx.Scope))
        {
            return [new Claim(WellKnownClaimIds.OidcEmail, ClaimOutcome.NotApplicable)];
        }

        OidcClaims? oidcClaims = await ResolveAsync(ctx, cancellationToken).ConfigureAwait(false);
        if(oidcClaims?.Email is not { } email)
        {
            return [new Claim(WellKnownClaimIds.OidcEmail, ClaimOutcome.NotApplicable)];
        }

        List<Claim> claims =
        [
            Success(WellKnownClaimIds.OidcEmail, WellKnownJwtClaimNames.Email, email.Email)
        ];

        if(email.EmailVerified is { } v)
        {
            claims.Add(Success(WellKnownClaimIds.OidcEmail, WellKnownJwtClaimNames.EmailVerified, v));
        }

        return claims;
    }


    /// <summary>
    /// Emits the OIDC Core §5.4 <c>address</c>-scope structured claim per
    /// OIDC Core §5.1.1.
    /// </summary>
    public static async ValueTask<List<Claim>> GenerateAddressClaims(
        ClaimContributionTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if(!TryExtractOidcContext(target, out OidcContributionContext? ctx)
            || !WellKnownScopes.ContainsAddress(ctx.Scope))
        {
            return [new Claim(WellKnownClaimIds.OidcAddress, ClaimOutcome.NotApplicable)];
        }

        OidcClaims? oidcClaims = await ResolveAsync(ctx, cancellationToken).ConfigureAwait(false);
        if(oidcClaims?.Address is not { } address)
        {
            return [new Claim(WellKnownClaimIds.OidcAddress, ClaimOutcome.NotApplicable)];
        }

        Dictionary<string, object> addressObject = new(StringComparer.Ordinal);
        AddIfPresent(addressObject, "formatted", address.Formatted);
        AddIfPresent(addressObject, "street_address", address.StreetAddress);
        AddIfPresent(addressObject, "locality", address.Locality);
        AddIfPresent(addressObject, "region", address.Region);
        AddIfPresent(addressObject, "postal_code", address.PostalCode);
        AddIfPresent(addressObject, "country", address.Country);

        if(addressObject.Count == 0)
        {
            return [new Claim(WellKnownClaimIds.OidcAddress, ClaimOutcome.NotApplicable)];
        }

        return
        [
            Success(WellKnownClaimIds.OidcAddress, WellKnownJwtClaimNames.Address, addressObject)
        ];
    }


    /// <summary>
    /// Emits the OIDC Core §5.4 <c>phone</c>-scope claims
    /// (<c>phone_number</c>, <c>phone_number_verified</c>).
    /// </summary>
    public static async ValueTask<List<Claim>> GeneratePhoneClaims(
        ClaimContributionTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if(!TryExtractOidcContext(target, out OidcContributionContext? ctx)
            || !WellKnownScopes.ContainsPhone(ctx.Scope))
        {
            return [new Claim(WellKnownClaimIds.OidcPhone, ClaimOutcome.NotApplicable)];
        }

        OidcClaims? oidcClaims = await ResolveAsync(ctx, cancellationToken).ConfigureAwait(false);
        if(oidcClaims?.Phone is not { } phone)
        {
            return [new Claim(WellKnownClaimIds.OidcPhone, ClaimOutcome.NotApplicable)];
        }

        List<Claim> claims =
        [
            Success(WellKnownClaimIds.OidcPhone, WellKnownJwtClaimNames.PhoneNumber, phone.PhoneNumber)
        ];

        if(phone.PhoneNumberVerified is { } v)
        {
            claims.Add(Success(WellKnownClaimIds.OidcPhone, WellKnownJwtClaimNames.PhoneNumberVerified, v));
        }

        return claims;
    }


    /// <summary>
    /// Extracted view over an <see cref="IdTokenTarget"/> or
    /// <see cref="UserInfoTarget"/>: registration, subject, scope, request
    /// context, and the optional walking-site-resolved OIDC claims.
    /// </summary>
    internal sealed record OidcContributionContext(
        ClientRecord Registration,
        string Subject,
        string Scope,
        ExchangeContext ExchangeContext,
        OidcClaims? PreResolvedClaims);


    internal static bool TryExtractOidcContext(
        ClaimContributionTarget target,
        [NotNullWhen(true)] out OidcContributionContext? context)
    {
        switch(target)
        {
            case IdTokenTarget idt:
                context = new OidcContributionContext(
                    idt.Issuance.Registration,
                    idt.Issuance.Subject,
                    idt.Issuance.Scope,
                    idt.Issuance.Context,
                    idt.ResolvedOidcClaims);
                return true;

            case UserInfoTarget uit:
                context = new OidcContributionContext(
                    uit.Registration,
                    uit.Subject,
                    uit.Scope,
                    uit.Context,
                    uit.ResolvedOidcClaims);
                return true;

            default:
                context = null;
                return false;
        }
    }


    /// <summary>
    /// Returns the walking-site-resolved claims when populated; otherwise
    /// invokes the application's
    /// <see cref="AuthorizationServerIntegration.ResolveOidcClaimsAsync"/>
    /// directly. The (α) population strategy — contributors work standalone
    /// against either a pre-resolved target or a wired resolver, so per-rule
    /// unit tests can exercise either path without each test having to
    /// stand up the full walking-site infrastructure.
    /// </summary>
    private static async ValueTask<OidcClaims?> ResolveAsync(
        OidcContributionContext ctx,
        CancellationToken cancellationToken)
    {
        if(ctx.PreResolvedClaims is not null)
        {
            return ctx.PreResolvedClaims;
        }

        AuthorizationServer? server = ctx.ExchangeContext.Server;
        ResolveOidcClaimsDelegate? resolve = server?.Integration.ResolveOidcClaimsAsync;
        if(resolve is null)
        {
            return null;
        }

        return await resolve(
            ctx.Subject,
            ctx.Scope,
            ctx.Registration.TenantId,
            ctx.ExchangeContext,
            cancellationToken).ConfigureAwait(false);
    }


    private static Claim Success(ClaimId id, string claimName, object claimValue) =>
        new(id, ClaimOutcome.Success, new ClaimContributionContext(claimName, claimValue), Claim.NoSubClaims);


    private static void AddString(List<Claim> sink, ClaimId id, string name, string? value)
    {
        if(value is not null)
        {
            sink.Add(Success(id, name, value));
        }
    }


    private static void AddIfPresent(Dictionary<string, object> sink, string name, string? value)
    {
        if(value is not null)
        {
            sink[name] = value;
        }
    }
}

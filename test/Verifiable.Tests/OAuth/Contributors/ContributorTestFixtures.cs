using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.OAuth;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth.Contributors;

/// <summary>
/// Fixture helpers shared by the per-contributor unit tests. Each helper
/// constructs a minimal target shape — no <see cref="AuthorizationServer"/>
/// wiring, no full <see cref="TestHostShell"/>. The (α) population strategy
/// allows per-rule tests to pre-populate
/// <see cref="IdTokenTarget.ResolvedOidcClaims"/> so the contributor never
/// needs to invoke a resolver.
/// </summary>
internal static class ContributorTestFixtures
{
    public static readonly DateTimeOffset FixedIssuedAt = new(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);

    public static readonly DateTimeOffset FixedAuthTime = new(2026, 5, 17, 11, 30, 0, TimeSpan.Zero);


    public static ClientRecord BuildRegistration() => new()
    {
        ClientId = "client-contributor-test",
        TenantId = "tenant-contributor-test",
        IssuerUri = new Uri("https://issuer.contributor-test/"),
        AllowedCapabilities = ImmutableHashSet<CapabilityIdentifier>.Empty
            .Add(WellKnownCapabilityIdentifiers.OidcOpenIdConnect),
        AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
        AllowedScopes = ImmutableHashSet<string>.Empty
            .Add(WellKnownScopes.OpenId)
            .Add(WellKnownScopes.Profile)
            .Add(WellKnownScopes.Email)
            .Add(WellKnownScopes.Address)
            .Add(WellKnownScopes.Phone),
        SigningKeys = ImmutableDictionary<Verifiable.Cryptography.Context.KeyUsageContext,
            SigningKeySet>.Empty,
        TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
        ResponseUri = null,
        ClientMetadata = null
    };


    public static IssuanceContext BuildIssuance(
        string scope,
        ConfirmationMethod? confirmation = null,
        DateTimeOffset? authTime = null)
    {
        return new IssuanceContext
        {
            Registration = BuildRegistration(),
            Context = new ExchangeContext(),
            IssuerUri = new Uri("https://issuer.contributor-test/"),
            Subject = "subject-contributor-test",
            Scope = scope,
            ClientId = "client-contributor-test",
            IssuedAt = FixedIssuedAt,
            Nonce = null,
            AuthTime = authTime,
            Confirmation = confirmation
        };
    }


    public static IdTokenTarget BuildIdTokenTarget(
        string scope,
        OidcClaims? resolvedClaims = null,
        ConfirmationMethod? confirmation = null,
        DateTimeOffset? authTime = null)
    {
        return new IdTokenTarget(BuildIssuance(scope, confirmation, authTime))
        {
            ResolvedOidcClaims = resolvedClaims
        };
    }


    public static UserInfoTarget BuildUserInfoTarget(
        string scope,
        OidcClaims? resolvedClaims = null)
    {
        return new UserInfoTarget(
            BuildRegistration(),
            "subject-contributor-test",
            scope,
            new ExchangeContext())
        {
            ResolvedOidcClaims = resolvedClaims
        };
    }


    public static AccessTokenTarget BuildAccessTokenTarget(
        string scope,
        ConfirmationMethod? confirmation = null) =>
        new(BuildIssuance(scope, confirmation));


    public static IntrospectionTarget BuildIntrospectionTarget(string scope) =>
        new(BuildRegistration(), "jti-contributor-test", "subject-contributor-test",
            scope, new ExchangeContext());


    /// <summary>
    /// Projects <see cref="ClaimOutcome.Success"/> claims to a (name → value)
    /// map keyed on the <see cref="ClaimContributionContext.ClaimName"/>.
    /// </summary>
    public static Dictionary<string, object> ExtractEmitted(List<Claim> claims)
    {
        Dictionary<string, object> emitted = new(StringComparer.Ordinal);
        foreach(Claim c in claims)
        {
            if(c.Outcome == ClaimOutcome.Success && c.Context is ClaimContributionContext ctx)
            {
                emitted[ctx.ClaimName] = ctx.ClaimValue;
            }
        }

        return emitted;
    }
}

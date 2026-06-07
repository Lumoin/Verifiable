using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The library's built-in <see cref="TokenProducer"/> for OpenID Connect ID
/// Tokens per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
/// </summary>
/// <remarks>
/// <para>
/// The producer applies only when <c>openid</c> is in the granted scope.
/// Signs with <see cref="KeyUsageContext.IdTokenIssuance"/>, allowing
/// deployments to use different key material for ID Tokens than for access
/// tokens via the per-usage <see cref="ClientRecord.SigningKeys"/> map.
/// </para>
/// <para>
/// Composes the JWT structural baseline only: <c>iss</c>, <c>aud</c>,
/// <c>iat</c>, <c>exp</c>, and the optional <c>nonce</c>. The <c>sub</c>
/// claim is emitted by <see cref="SubjectIdentifierContributor"/> via
/// <see cref="AuthorizationServerIntegration.ResolveSubjectIdentifierAsync"/>;
/// the OIDC Core §2 authentication-context claims (<c>acr</c>,
/// <c>amr</c>, <c>auth_time</c>) are emitted by
/// <see cref="AcrAmrClaimContributor"/>; scope-driven OIDC Core §5.4
/// claims (<c>profile</c>, <c>email</c>, <c>address</c>, <c>phone</c>)
/// are emitted by <see cref="OidcStandardClaimsContributor"/>; the
/// RFC 7800 / RFC 9449 §6.1 <c>cnf</c> claim is emitted by
/// <see cref="CnfClaimContributor"/>. The token endpoint's walking site
/// merges every <see cref="ServerConfiguration.ClaimIssuer"/>
/// contribution into this payload before signing.
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
        RequiredCapability = WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
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


    private static ValueTask<TokenProducerOutput> BuildAsync(
        IssuanceContext context,
        KeyId signingKeyId,
        string algorithm,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);

        TimeSpan lifetime =
            context.Registration.GetTokenLifetime(WellKnownTokenTypes.IdToken)
                ?? TimeSpan.FromHours(1);
        DateTimeOffset expiresAt = context.IssuedAt.Add(lifetime);

        //RFC 8414 §3 + RFC 9207 §2.4 require exact-string equality on the
        //issuer identifier; preserve the URL verbatim — matches the
        //access-token producer's reasoning.
        string issuerValue = context.IssuerUri.OriginalString;

        JwtHeader header = JwtHeader.ForIdToken(algorithm, signingKeyId.Value);

        //Structural baseline only — sub, auth_time, acr, amr, and every
        //scope-driven claim arrive via the walking site's contributor
        //walk. JwtPayload.ForIdToken is not used here: its required
        //subject parameter would conflict with the producer's split-of-
        //responsibilities.
        JwtPayload payload = new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = issuerValue,
            [WellKnownJwtClaimNames.Aud] = context.ClientId,
            [WellKnownJwtClaimNames.Iat] = context.IssuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds()
        };

        if(context.Nonce is not null)
        {
            payload[WellKnownJwtClaimNames.Nonce] = context.Nonce;
        }

        return new ValueTask<TokenProducerOutput>(new TokenProducerOutput(header, payload));
    }
}

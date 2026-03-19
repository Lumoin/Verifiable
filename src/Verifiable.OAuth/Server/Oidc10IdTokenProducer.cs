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
/// The producer applies only when <c>openid</c> is in the granted scope. Signs
/// with <see cref="KeyUsageContext.IdTokenIssuance"/>, allowing deployments to
/// use different key material for ID Tokens than for access tokens via the
/// per-usage <see cref="ClientRegistration.SigningKeys"/> map.
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


    private static ValueTask<TokenProducerOutput> BuildAsync(
        IssuanceContext context,
        AuthorizationServerOptions options,
        KeyId signingKeyId,
        string algorithm,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);

        TimeSpan lifetime =
            context.Registration.GetTokenLifetime(WellKnownTokenTypes.IdToken)
                ?? TimeSpan.FromHours(1);
        DateTimeOffset expiresAt = context.IssuedAt.Add(lifetime);

        string issuerValue = context.IssuerUri.GetLeftPart(UriPartial.Authority);

        JwtHeader header = JwtHeader.ForIdToken(algorithm, signingKeyId.Value);
        JwtPayload payload = JwtPayload.ForIdToken(
            issuer: issuerValue,
            subject: context.Subject,
            audience: context.ClientId,
            issuedAt: context.IssuedAt,
            expiresAt: expiresAt,
            authTime: context.AuthTime,
            nonce: context.Nonce,
            acr: null,
            amr: null,
            azp: null);

        return ValueTask.FromResult(new TokenProducerOutput(header, payload));
    }
}

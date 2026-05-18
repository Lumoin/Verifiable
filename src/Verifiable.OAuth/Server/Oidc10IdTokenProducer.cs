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
/// Emits the spec-mandated baseline: <c>iss</c>, <c>sub</c>, <c>aud</c>,
/// <c>iat</c>, <c>exp</c>, <c>nonce</c> (when present), and the
/// <c>auth_time</c> value carried on <see cref="IssuanceContext.AuthTime"/>.
/// Scope-driven OIDC Core §5.4 claims (<c>profile</c>, <c>email</c>,
/// <c>address</c>, <c>phone</c>), the OIDC Core §2 authentication-context
/// claims (<c>acr</c>, <c>amr</c>), and the RFC 7800 / RFC 9449 §6.1
/// <c>cnf</c> claim are emitted by the
/// <see cref="ServerConfiguration.ClaimIssuer"/> contributor walk after the
/// producer returns; the token endpoint merges the contributed claims into
/// this payload before signing.
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
            azp: null,
            claims: null);

        return new ValueTask<TokenProducerOutput>(new TokenProducerOutput(header, payload));
    }
}

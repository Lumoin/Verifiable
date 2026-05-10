using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The library's built-in <see cref="TokenProducer"/> for OAuth 2.0 JWT access
/// tokens per <see href="https://www.rfc-editor.org/rfc/rfc9068">RFC 9068</see>.
/// </summary>
/// <remarks>
/// <para>
/// The producer always applies — every token-endpoint request emits an access
/// token unless an application replaces the producer list with one that excludes
/// it. Signs with <see cref="KeyUsageContext.AccessTokenIssuance"/>.
/// </para>
/// <para>
/// Consumed indirectly via <see cref="TokenProducer.Rfc9068AccessToken"/>.
/// </para>
/// <para>
/// <strong>Known gap (audit Finding 2): RFC 9068 access-token <c>aud</c>.</strong>
/// RFC 9068 §2.2 mandates the <c>aud</c> claim on access tokens. The producer
/// currently passes <c>audience: null</c> below because <see cref="IssuanceContext"/>
/// has no field surfacing the resource server identifier(s). Surfacing
/// <c>aud</c> requires a design conversation about how the resource server
/// identifier is supplied (per-registration metadata, per-request resolver,
/// scope-derived mapping, etc.) and is deferred until that conversation
/// concludes. The policy axis <c>policy.AccessTokenAudPolicy</c> is in place
/// (default <see cref="AccessTokenAudPolicy.Required"/>); only the producer's
/// audience-resolution side is missing.
/// </para>
/// </remarks>
internal static class Rfc9068AccessTokenProducer
{
    /// <summary>
    /// The singleton producer instance.
    /// </summary>
    public static TokenProducer Instance { get; } = new()
    {
        Name = "rfc9068-access-token",
        ResponseField = WellKnownTokenTypes.AccessToken,
        RequiredCapability = ServerCapabilityName.AuthorizationCode,
        KeyUsage = KeyUsageContext.AccessTokenIssuance,
        IsApplicable = static (_, _) => ValueTask.FromResult(true),
        BuildAsync = BuildAsync
    };


    private static ValueTask<TokenProducerOutput> BuildAsync(
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
            context.Registration.GetTokenLifetime(WellKnownTokenTypes.AccessToken)
                ?? TimeSpan.FromHours(1);
        DateTimeOffset expiresAt = context.IssuedAt.Add(lifetime);

        string jti = Guid.NewGuid().ToString();
        string issuerValue = context.IssuerUri.GetLeftPart(UriPartial.Authority);

        JwtHeader header = JwtHeader.ForAccessToken(algorithm, signingKeyId.Value);
        JwtPayload payload = JwtPayload.ForAccessToken(
            subject: context.Subject,
            jti: jti,
            scope: context.Scope,
            issuedAt: context.IssuedAt,
            expiresAt: expiresAt,
            issuer: issuerValue,
            audience: null,
            clientId: context.ClientId);

        return ValueTask.FromResult(new TokenProducerOutput(header, payload));
    }
}

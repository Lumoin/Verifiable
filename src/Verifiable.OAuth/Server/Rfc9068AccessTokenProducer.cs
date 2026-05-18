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
/// token unless an application replaces the producer list with one that
/// excludes it. Signs with <see cref="KeyUsageContext.AccessTokenIssuance"/>.
/// </para>
/// <para>
/// Consumed indirectly via <see cref="TokenProducer.Rfc9068AccessToken"/>.
/// </para>
/// <para>
/// <strong>Audience resolution.</strong> RFC 9068 §2.2 mandates the <c>aud</c>
/// claim. Audience values are resolved at issuance time through
/// <see cref="AuthorizationServerIntegration.ResolveAccessTokenAudienceAsync"/>;
/// when that slot is unwired the library's default
/// <see cref="DefaultResolveAccessTokenAudienceAsync"/> reads from
/// <see cref="ClientRecord.ScopeToAudience"/>. The active
/// <see cref="AccessTokenAudPolicy"/> from per-request policy decides what
/// happens when no audience can be resolved:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="AccessTokenAudPolicy.Required"/> — the producer raises
/// <see cref="InvalidOperationException"/> when no audience is available.
/// RFC 9068-conformant default.
/// </description></item>
/// <item><description>
/// <see cref="AccessTokenAudPolicy.Optional"/> — the producer emits the
/// token without an <c>aud</c> claim. Useful during migrations where
/// resource servers do not yet enforce the claim.
/// </description></item>
/// <item><description>
/// <see cref="AccessTokenAudPolicy.Suppressed"/> — the producer never
/// emits <c>aud</c>, even if audiences are available. Used by deployments
/// that explicitly opt out during a phased rollout.
/// </description></item>
/// </list>
/// <para>
/// Multi-audience tokens are supported per RFC 7519 §4.1.3:
/// <see cref="JwtPayloadExtensions.ForAccessToken"/> emits a single audience as
/// a JSON string and multiple audiences as a JSON array.
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


    /// <summary>
    /// Default audience resolver — reads the registration's
    /// <see cref="ClientRecord.ScopeToAudience"/> map and returns the
    /// union (deduplicated, ordinal-equal) of audiences across the granted
    /// scopes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Returns <see langword="null"/> when the registration has no
    /// <c>ScopeToAudience</c> map or when no granted scope maps to any
    /// audience. Applications with dynamic audience needs supply their own
    /// <see cref="ResolveAccessTokenAudienceDelegate"/> via
    /// <see cref="AuthorizationServerIntegration.ResolveAccessTokenAudienceAsync"/>.
    /// </para>
    /// <para>
    /// The default does not bake in the FAPI <c>aud == client_id</c> behaviour
    /// for client-credentials-style scopes. Applications that want that put
    /// <c>client_id</c> explicitly into <c>ScopeToAudience</c> entries, or
    /// supply a custom delegate that synthesises the value.
    /// </para>
    /// </remarks>
    public static ValueTask<IReadOnlyList<string>?> DefaultResolveAccessTokenAudienceAsync(
        ClientRecord registration,
        IssuanceContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if(registration.ScopeToAudience is null)
        {
            return ValueTask.FromResult<IReadOnlyList<string>?>(null);
        }

        HashSet<string> audiences = new(StringComparer.Ordinal);
        string[] grantedScopes = context.Scope.Split(
            ' ', StringSplitOptions.RemoveEmptyEntries);

        foreach(string scopeToken in grantedScopes)
        {
            if(registration.ScopeToAudience.TryGetValue(
                scopeToken, out IReadOnlyList<string>? mapped))
            {
                foreach(string aud in mapped)
                {
                    audiences.Add(aud);
                }
            }
        }

        if(audiences.Count == 0)
        {
            return ValueTask.FromResult<IReadOnlyList<string>?>(null);
        }

        return ValueTask.FromResult<IReadOnlyList<string>?>(audiences.ToArray());
    }


    private static async ValueTask<TokenProducerOutput> BuildAsync(
        IssuanceContext context,
        KeyId signingKeyId,
        string algorithm,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);

        AuthorizationServer server = context.Context.Server
            ?? throw new InvalidOperationException(
                "IssuanceContext.Context.Server must be set before "
                + nameof(Rfc9068AccessTokenProducer) + "." + nameof(BuildAsync) + ".");

        TimeSpan lifetime =
            context.Registration.GetTokenLifetime(WellKnownTokenTypes.AccessToken)
                ?? TimeSpan.FromHours(1);
        DateTimeOffset expiresAt = context.IssuedAt.Add(lifetime);

        string jti = Guid.NewGuid().ToString();

        //RFC 8414 §3 + RFC 9207 §2.4 require exact-string equality on the
        //issuer identifier. Preserve the URL verbatim — path component, port,
        //etc. — so multi-tenant deployments where the segment is in the path
        //emit the right iss claim. The previous GetLeftPart(UriPartial.Authority)
        //collapse stripped the tenant segment and broke exact-match comparison
        //at the relying-party side.
        string issuerValue = context.IssuerUri.OriginalString;

        ResolveAccessTokenAudienceDelegate resolver =
            server.Integration.ResolveAccessTokenAudienceAsync
            ?? DefaultResolveAccessTokenAudienceAsync;

        IReadOnlyList<string>? audiences = await resolver(
            context.Registration, context, cancellationToken).ConfigureAwait(false);

        AccessTokenAudPolicy policy = context.Context.AccessTokenAudPolicy;

        if(policy == AccessTokenAudPolicy.Required
            && (audiences is null || audiences.Count == 0))
        {
            throw new InvalidOperationException(
                "AccessTokenAudPolicy is Required but no audience was resolved. " +
                "Either wire ResolveAccessTokenAudienceAsync, populate " +
                "registration.ScopeToAudience, or set the policy to Optional or Suppressed.");
        }

        if(policy == AccessTokenAudPolicy.Suppressed)
        {
            audiences = null;
        }

        JwtHeader header = JwtHeader.ForAccessToken(algorithm, signingKeyId.Value);
        JwtPayload payload = JwtPayload.ForAccessToken(
            subject: context.Subject,
            jti: jti,
            scope: context.Scope,
            issuedAt: context.IssuedAt,
            expiresAt: expiresAt,
            issuer: issuerValue,
            audience: audiences,
            clientId: context.ClientId);

        return new TokenProducerOutput(header, payload);
    }
}

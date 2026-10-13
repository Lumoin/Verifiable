using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The library's built-in <see cref="TokenProducer"/> for OAuth 2.0 JWT access
/// tokens per <see href="https://www.rfc-editor.org/rfc/rfc9068">RFC 9068</see>.
/// </summary>
/// <remarks>
/// <para>
/// The producer always applies — every token-endpoint request emits an access
/// token unless an application replaces the producer list with one that
/// excludes it. <see cref="TokenProducer.RequiredCapability"/> is
/// <see langword="null"/>: the grant's own endpoint match (for example
/// <see cref="WellKnownCapabilityIdentifiers.OAuthClientCredentials"/>) already gated the
/// request before the producer walk runs, so this producer needs no separate tenant-feature
/// gate. Signs with <see cref="KeyUsageContext.AccessTokenIssuance"/>.
/// </para>
/// <para>
/// Consumed indirectly via <c>TokenProducer.Rfc9068AccessToken</c>.
/// </para>
/// <para>
/// <strong>Audience.</strong> Every access token this producer writes carries <c>aud</c>:
/// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 Section 2.2</see>, "aud
/// REQUIRED - as defined in Section 4.1.3 of [RFC7519].", and
/// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-3">Section 3</see>, "If the request does not
/// include a "resource" parameter, the authorization server MUST use a default resource indicator in the
/// "aud" claim." The value, in order:
/// </para>
/// <list type="number">
/// <item><description>
/// <see cref="IssuanceContext.Audience"/> when the grant populated it: the request's granted
/// <c>resource</c> set, or a Token Exchange target.
/// </description></item>
/// <item><description>
/// Otherwise the audiences the resolver answers, when it answers any:
/// <see cref="AuthorizationServerIntegration.ResolveAccessTokenAudienceAsync"/> when wired, else the
/// library's <see cref="DefaultResolveAccessTokenAudienceAsync"/>, the union of the granted scopes'
/// entries in <see cref="ClientRecord.ScopeToAudience"/>.
/// </description></item>
/// <item><description>
/// Otherwise the issuer, the value the token's <c>iss</c> takes: the default resource indicator, and the
/// identifier of this Authorization Server's own resources (UserInfo and the OID4VCI Credential,
/// Deferred Credential and Notification endpoints).
/// </description></item>
/// </list>
/// <para>
/// An audience that names no recipient, an entry that is null, empty or white space only from any of the three
/// sources or an <c>aud</c> a claim contributor writes over the composed one, fails the token request with 500
/// <c>server_error</c> and <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/>, and no token of the
/// request is issued.
/// </para>
/// <para>
/// The issuer is never added to an audience the request or the application named. Those resources
/// validate the token against the issuer
/// (<see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>), so a token
/// audienced only at another resource is refused there: a deployment whose clients call UserInfo or the
/// issuance endpoints with a token it audiences elsewhere names the issuer among that token's audiences in
/// its resolver or its scope map, or the client names the issuer as a <c>resource</c>.
/// </para>
/// <para>
/// Multi-audience tokens are supported per RFC 7519 §4.1.3:
/// <see cref="JwtPayloadExtensions.ForAccessToken"/> always emits <c>aud</c> as a JSON array,
/// including a single audience — RFC 7519 §4.1.3's general representation, deliberately not
/// taking the bare-string single-audience MAY special case (see its <c>audience</c> parameter
/// doc). <see cref="IssuanceContext.Audience"/> — populated by RFC 8693 §2.1.1 Token Exchange
/// target binding, or by the RFC 8707 §2.2 granted/narrowed resource set on the
/// <c>authorization_code</c>, <c>refresh_token</c>, and <c>client_credentials</c> grants — takes
/// precedence over <see cref="ClientRecord.ScopeToAudience"/> when populated; ScopeToAudience is
/// the fallback resolver for every issuance that resolved neither.
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
        RequiredCapability = null,
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
    /// audience; the producer then writes the issuer as the token's one
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
                    _ = audiences.Add(aud);
                }
            }
        }

        if(audiences.Count == 0)
        {
            return ValueTask.FromResult<IReadOnlyList<string>?>(null);
        }

        return ValueTask.FromResult<IReadOnlyList<string>?>(audiences.ToArray());
    }


    /// <summary>
    /// Builds a signed access token with the admitted issuer, its audience and signing resources.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 §2.2</see>:
    /// "The JWT access token MUST include the following claims."
    /// </summary>
    /// <param name="context">The issuance context; the <c>RequestServer</c> of its exchange context is the serving server.</param>
    /// <param name="signingKeyId">The identifier of the signing material, written as the header's <c>kid</c>.</param>
    /// <param name="algorithm">The JWA algorithm the token is signed with, written as the header's <c>alg</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The unsigned header and payload the token endpoint's walk merges contributions into and signs.</returns>
    /// <exception cref="InvalidOperationException">
    /// The issuance context names no serving server, or <see cref="TokenLifetimes.TryResolve"/> resolves no access-token
    /// lifetime: the resolved lifetime is not issuable (a value under one whole second or above
    /// <see cref="int.MaxValue"/> seconds, or a policy value of another type), whoever supplied it. The authorization
    /// server's endpoints resolve the lifetime before they call the producer and answer such a value 500
    /// <c>server_error</c> themselves; the exception is for a direct caller.
    /// </exception>
    private static async ValueTask<TokenProducerOutput> BuildAsync(
        IssuanceContext context,
        KeyId signingKeyId,
        string algorithm,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);

        EndpointServer server = context.Context.RequestServer
            ?? throw new InvalidOperationException(
                "IssuanceContext.Context.RequestServer must be set before "
                + nameof(Rfc9068AccessTokenProducer) + "." + nameof(BuildAsync) + ".");
        var oauth = server.OAuth();

        //The lifetime is the one resolution's: the registration's override, else the request's policy value, else the
        //server's TimingPolicy. A false answer means the resolved lifetime is not issuable, whoever supplied it; it is
        //thrown, as the missing request server above is, for a direct caller (the endpoints resolve it first).
        if(!TokenLifetimes.TryResolve(context.Registration, TokenType.AccessToken, context.Context, out TimeSpan lifetime))
        {
            throw new InvalidOperationException(
                nameof(TokenLifetimes) + "." + nameof(TokenLifetimes.TryResolve) + " resolved no access-token lifetime.");
        }

        DateTimeOffset expiresAt = context.IssuedAt.Add(lifetime);

        string jti = await oauth.GenerateIdentifierAsync!(
            WellKnownIdentifierPurposes.OAuthJti, context.Context, cancellationToken)
            .ConfigureAwait(false);

        //RFC 8414 Section 3 and RFC 9207 Section 2.4 require exact-string equality on the issuer
        //identifier. The URL is written verbatim, path component and port included, so a multi-tenant
        //deployment whose tenant segment is in the path writes the iss a relying party compares exactly.
        string issuerValue = context.IssuerUri.OriginalString;

        ResolveAccessTokenAudienceDelegate resolver =
            oauth.ResolveAccessTokenAudienceAsync
            ?? DefaultResolveAccessTokenAudienceAsync;

        //An audience on the issuance context (RFC 8693 Section 2.1.1 Token Exchange target binding,
        //or the RFC 8707 Section 2.2 granted or narrowed resource set on the authorization_code,
        //refresh_token and client_credentials grants) is the issued token's aud verbatim, taking
        //precedence over the scope-to-audience resolver per RFC 8707 Section 2's SHOULD. Otherwise
        //the resolver's answer is the aud when it names any audience, and otherwise the issuer is:
        //RFC 9068 Section 3, "If the request does not include a "resource" parameter, the
        //authorization server MUST use a default resource indicator in the "aud" claim." The issuer
        //is never added to an audience the request or the application named.
        IReadOnlyList<string>? resolvedAudiences = context.Audience is { Count: > 0 }
            ? context.Audience
            : await resolver(
                context.Registration, context, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<string> audiences = resolvedAudiences is { Count: > 0 }
            ? resolvedAudiences
            : [issuerValue];

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

        //RFC 9396 §9.1: "If the access token is a JWT [RFC7519], the AS is RECOMMENDED to add the
        //authorization details object ... as a top-level claim." The granted authorization details
        //resolved at the token endpoint — the same value the token response echoes, carrying the
        //OID4VCI 1.0 §6.2 credential_identifiers the Resource Server needs — are embedded verbatim;
        //the openid_credential profile's granted objects carry no per-audience locations, so there
        //is nothing to filter out for the resolved audience.
        IReadOnlyList<object>? grantedDetails = context.Context.GrantedAuthorizationDetailsClaim;
        if(grantedDetails is not null)
        {
            payload[OAuthRequestParameterNames.AuthorizationDetails] = grantedDetails;
        }

        //RFC 8693 §4.1: a delegating grant supplies the composite token's "act" (actor) claim — the
        //nested JSON object identifying the current actor (and any prior actors) — whether the
        //delegation was established by a Token Exchange actor_token or at an ID-JAG redemption. It is
        //null for every issuance where no party acts for another, so this is a no-op then. RFC 9068
        //§2.2.2 is why the value rides under the IANA-registered name rather than a private one.
        if(context.Act is not null)
        {
            payload[WellKnownJwtClaimNames.Act] = context.Act;
        }

        return new TokenProducerOutput(header, payload);
    }
}

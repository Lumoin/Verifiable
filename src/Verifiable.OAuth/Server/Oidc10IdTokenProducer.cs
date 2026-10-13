using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The library's built-in <see cref="TokenProducer"/> for OpenID Connect ID
/// Tokens per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
/// </summary>
/// <remarks>
/// <para>
/// The producer applies only when <c>openid</c> is in the granted scope AND the request's
/// <see cref="IssuanceContext.GrantType"/> is <c>authorization_code</c>, or <c>refresh_token</c>
/// whose <see cref="IssuanceContext.RefreshTokenOriginatingGrantType"/> is itself
/// <c>authorization_code</c> — the only shapes where the library knows an End-User was
/// authenticated. A refresh token minted alongside a non-End-User grant
/// (<c>client_credentials</c>, <c>token_exchange</c>, <c>jwt_bearer</c>,
/// <c>pre_authorized_code</c>) carries that origin verbatim across rotation via
/// <see cref="AuthCode.Server.States.ServerRefreshTokenIssuedState.OriginatingGrantType"/>, so its
/// redemption never satisfies this gate. This is one of three defense-in-depth layers enforcing
/// the <c>openid</c> ⇒ authenticated-end-user invariant, alongside the granted-scope narrowing in
/// <see cref="AuthCode.AuthCodeEndpoints"/> for non-end-user grants and the consumer-side check in
/// <see cref="Oidc.UserInfoEndpoints"/>: even if a defect ever left <c>openid</c> on a
/// <c>client_credentials</c> or <c>token_exchange</c> token's scope — or on the refresh token
/// minted alongside one — this grant-identity check independently keeps this producer from
/// synthesizing an ID Token for that non-end-user subject. Signs with
/// <see cref="KeyUsageContext.IdTokenIssuance"/>, allowing deployments to use different key
/// material for ID Tokens than for access tokens via the per-usage
/// <see cref="ClientRecord.SigningKeys"/> map.
/// </para>
/// <para>
/// Composes the JWT structural baseline only: <c>iss</c>, <c>aud</c>,
/// <c>iat</c>, <c>exp</c>, <c>jti</c>, and the optional <c>nonce</c>. The <c>sub</c>
/// claim is emitted by <see cref="SubjectIdentifierContributor"/> via
/// <see cref="AuthorizationServerIntegration.ResolveSubjectIdentifierAsync"/>;
/// the OIDC Core §2 authentication-context claims (<c>acr</c>,
/// <c>amr</c>, <c>auth_time</c>) are emitted by
/// <see cref="AcrAmrClaimContributor"/>; scope-driven OIDC Core §5.4
/// claims (<c>profile</c>, <c>email</c>, <c>address</c>, <c>phone</c>)
/// are emitted by <see cref="OidcStandardClaimsContributor"/>; the
/// RFC 7800 / RFC 9449 §6.1 <c>cnf</c> claim is emitted by
/// <see cref="CnfClaimContributor"/>. The token endpoint's walking site
/// merges every <see cref="AuthorizationServerIntegration.ClaimIssuer"/>
/// contribution into this payload before signing.
/// </para>
/// <para>
/// The <c>jti</c> is
/// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 section 4.1.7</see>'s
/// claim: "The "jti" (JWT ID) claim provides a unique identifier for the JWT." and "The identifier
/// value MUST be assigned in a manner that ensures that there is a negligible probability that the
/// same value will be accidentally assigned to a different data object; if the application uses
/// multiple issuers, collisions MUST be prevented among values produced by different issuers as
/// well." The section also states "Use of this claim is OPTIONAL." The producer writes it on every
/// ID Token, drawn from <see cref="Verifiable.Server.ServerIntegration.GenerateIdentifierAsync"/>
/// under <see cref="WellKnownIdentifierPurposes.OAuthJti"/>, the seam and purpose
/// <see cref="Rfc9068AccessTokenProducer"/> draws the access token's <c>jti</c> from, so the
/// uniqueness the clause asks for is the identifier seam's.
/// </para>
/// <para>
/// Consumed indirectly via <c>TokenProducer.Oidc10IdToken</c>.
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

        static bool IsEndUserAuthenticatingGrant(IssuanceContext context) => context switch
        {
            _ when WellKnownGrantTypes.IsAuthorizationCode(context.GrantType) => true,
            { RefreshTokenOriginatingGrantType: { } origin } when WellKnownGrantTypes.IsRefreshToken(context.GrantType) =>
                WellKnownGrantTypes.IsAuthorizationCode(origin),
            _ => false
        };

        return ValueTask.FromResult(
            WellKnownScopes.ContainsOpenId(context.Scope) && IsEndUserAuthenticatingGrant(context));
    }


    /// <summary>
    /// Builds the ID Token's header and structural baseline payload: <c>iss</c>, <c>aud</c>, <c>iat</c>,
    /// <c>exp</c>, a <c>jti</c> drawn from <see cref="Verifiable.Server.ServerIntegration.GenerateIdentifierAsync"/>
    /// under <see cref="WellKnownIdentifierPurposes.OAuthJti"/>, and the <c>nonce</c> when the request carried one.
    /// </summary>
    /// <param name="context">The issuance context; the <c>RequestServer</c> of its exchange context is the serving server.</param>
    /// <param name="signingKeyId">The identifier of the signing material, written as the header's <c>kid</c>.</param>
    /// <param name="algorithm">The JWA algorithm the token is signed with, written as the header's <c>alg</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The unsigned header and payload the token endpoint's walk merges contributions into and signs.</returns>
    /// <exception cref="InvalidOperationException">
    /// The issuance context names no serving server, or <see cref="TokenLifetimes.TryResolve"/> resolves no ID Token
    /// lifetime: the resolved lifetime is not issuable (a value under one whole second or above
    /// <see cref="int.MaxValue"/> seconds, or a policy value of another type), whoever supplied it. The authorization
    /// server's endpoints resolve the lifetime before they call the producer and answer such a value 500
    /// <c>server_error</c> themselves; the exception is for a direct caller.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// The identifier seam answers a <c>jti</c> that is null, empty or white space only, refused as
    /// <see cref="JwtPayloadExtensions.ForAccessToken"/> refuses it for the access token.
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
                + nameof(Oidc10IdTokenProducer) + "." + nameof(BuildAsync) + ".");

        //The lifetime is the one resolution's: the registration's override, else the request's policy value, else the
        //server's TimingPolicy. A false answer means the resolved lifetime is not issuable, whoever supplied it; it is
        //thrown, as the missing request server above is, for a direct caller (the endpoints resolve it first).
        if(!TokenLifetimes.TryResolve(context.Registration, TokenType.IdToken, context.Context, out TimeSpan lifetime))
        {
            throw new InvalidOperationException(
                nameof(TokenLifetimes) + "." + nameof(TokenLifetimes.TryResolve) + " resolved no ID Token lifetime.");
        }

        DateTimeOffset expiresAt = context.IssuedAt.Add(lifetime);

        //Two ID Tokens issued within one second for one subject and one client carry the same iss, sub,
        //aud, iat and exp, so without an identifier of their own they cannot be told apart; the jti is the
        //value a receiver's replay or audit record refers to. Each token draws its own value from the
        //server's identifier seam, the source the access token's jti is drawn from.
        string jti = await server.OAuth().GenerateIdentifierAsync!(
            WellKnownIdentifierPurposes.OAuthJti, context.Context, cancellationToken)
            .ConfigureAwait(false);

        //An answer that is null, empty or white space only gives the token no identifier of its own, and a token
        //without one cannot be told apart from another. The access token's builder, JwtPayload.ForAccessToken,
        //refuses the same answer with this check, so both producers end the token endpoint's walk alike.
        ArgumentException.ThrowIfNullOrWhiteSpace(jti);

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
        JwtPayload payload = new(capacity: 7)
        {
            [WellKnownJwtClaimNames.Iss] = issuerValue,
            [WellKnownJwtClaimNames.Aud] = context.ClientId,
            [WellKnownJwtClaimNames.Iat] = context.IssuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Jti] = jti
        };

        if(context.Nonce is not null)
        {
            payload[WellKnownJwtClaimNames.Nonce] = context.Nonce;
        }

        return new TokenProducerOutput(header, payload);
    }
}

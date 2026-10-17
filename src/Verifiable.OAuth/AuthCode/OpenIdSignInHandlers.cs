using System.Security.Cryptography;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The check of an OpenID Connect sign-in's code exchange that refused it
/// (<see cref="OpenIdSignInHandlers.ExchangeOpenIdTokenAsync"/>).
/// </summary>
public enum OpenIdSignInRefusal
{
    /// <summary>The flow names no code pending exchange, or its authentication request sent no <c>nonce</c> to hold the ID Token to.</summary>
    NonceNotHeld,

    /// <summary>The code exchange was refused: the token endpoint's answer or the client's judgement of the request (<see cref="OpenIdSignInResult.Exchange"/>).</summary>
    ExchangeRefused,

    /// <summary>The token endpoint answered no ID Token (OpenID Connect Core 1.0 §3.1.3.3: "id_token: ID Token value associated with the authenticated session").</summary>
    NoIdToken,

    /// <summary>
    /// No key of the OpenID Provider's published set verifies the ID Token under its header's algorithm: the header names no
    /// <c>kid</c> or no <c>alg</c>, or the resolver answers no key (RFC 8725 §3.1).
    /// </summary>
    KeyUnresolved,

    /// <summary>
    /// The ID Token's header names another algorithm than the one the client registered for its ID Tokens
    /// (<see cref="OpenIdTokenVerification.RegisteredAlgorithm"/>; OpenID Connect Core 1.0 §3.1.3.7 item 7), whatever key of the
    /// provider's published set would verify it.
    /// </summary>
    AlgorithmNotRegistered,

    /// <summary>A check of OpenID Connect Core 1.0 §3.1.3.7 refused the ID Token; the check is <see cref="OpenIdSignInResult.IdTokenFailure"/>.</summary>
    IdTokenRefused
}


/// <summary>
/// The inputs a relying party verifies an OpenID Provider's ID Token with (OpenID Connect Core 1.0 §3.1.3.7), the provider's
/// published key reached through the application's resolver.
/// </summary>
public sealed record OpenIdTokenVerification
{
    /// <summary>Resolves the provider's published key by the ID Token's header <c>kid</c> and <c>alg</c>.</summary>
    public required ResolveJwsVerificationKeyDelegate ResolveKey { get; init; }

    /// <summary>The parser of the ID Token's header and claims.</summary>
    public required JwsAccessTokenJsonParser Parser { get; init; }

    /// <summary>The base64url decoder.</summary>
    public required DecodeDelegate Base64UrlDecoder { get; init; }

    /// <summary>The tolerance an <c>iat</c> slightly in the future is judged with.</summary>
    public required TimeSpan ClockSkew { get; init; }

    /// <summary>
    /// The JWS algorithm the client registered for the ID Tokens issued to it: its <c>id_token_signed_response_alg</c>
    /// (OpenID Connect Dynamic Client Registration 1.0 §2: "The default, if omitted, is RS256"). OpenID Connect Core 1.0
    /// §3.1.3.7 item 7: "The alg value SHOULD be the default of RS256 or the algorithm sent by the Client in the
    /// id_token_signed_response_alg parameter during Registration"; an ID Token under any other algorithm is refused, so a
    /// provider publishing keys of several algorithms has its tokens judged under the one the client chose.
    /// </summary>
    public required string RegisteredAlgorithm { get; init; }
}


/// <summary>
/// What an OpenID Connect sign-in's code exchange came to: the exchange's result, and on success the verified ID Token, its
/// claims and the refresh token the provider issued beside it; on a refusal the check that refused it.
/// </summary>
public sealed record OpenIdSignInResult
{
    /// <summary>The code exchange's result as the authorization code flow answered it.</summary>
    public required AuthCodeFlowEndpointResult Exchange { get; init; }

    /// <summary>The check that refused the sign-in, or <see langword="null"/> where the ID Token verified.</summary>
    public OpenIdSignInRefusal? Refusal { get; init; }

    /// <summary>The §3.1.3.7 check that refused the ID Token, for <see cref="OpenIdSignInRefusal.IdTokenRefused"/>; otherwise <see langword="null"/>.</summary>
    public JwsAccessTokenValidationFailureReason? IdTokenFailure { get; init; }

    /// <summary>The verified ID Token, or <see langword="null"/> on a refusal.</summary>
    public string? IdToken { get; init; }

    /// <summary>The verified ID Token's claims, or <see langword="null"/> on a refusal.</summary>
    public Oidc10IdTokenClaims? Claims { get; init; }

    /// <summary>The refresh token the provider issued beside the ID Token, or <see langword="null"/>.</summary>
    public string? RefreshToken { get; init; }

    /// <summary>Whether the ID Token verified.</summary>
    public bool IsSignedIn => Refusal is null;


    /// <summary>Names the result by its refusal alone, never its tokens.</summary>
    /// <returns>The text.</returns>
    public override string ToString() =>
        $"{nameof(OpenIdSignInResult)} {{ {nameof(Refusal)} = {Refusal}, {nameof(IdTokenFailure)} = {IdTokenFailure} }}";
}


/// <summary>
/// The relying party's completion of an OpenID Connect sign-in of the authorization code flow
/// (<see href="https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">OpenID Connect Core 1.0 §3.1</see>): the
/// code exchanged for tokens and the ID Token verified as §3.1.3.7 orders, held to the <c>nonce</c> the authentication
/// request sent (<see cref="AuthCodeFlowHandlers.HandleOpenIdAuthorizeStartAsync"/>).
/// </summary>
public static class OpenIdSignInHandlers
{
    /// <summary>
    /// Exchanges the code a callback held (<see cref="AuthCodeFlowHandlers.HandleCallbackAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, CancellationToken)"/>)
    /// at the provider's token endpoint under the registration's client authentication, the PKCE verifier and the redirect URI
    /// named again (<see cref="AuthCodeFlowHandlers.HandleTokenAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, ClientAssertionOptions?, IReadOnlyList{string}?, CancellationToken)"/>),
    /// and verifies the ID Token it answered: its header's <c>alg</c> the one the client registered
    /// (<see cref="OpenIdTokenVerification.RegisteredAlgorithm"/>; §3.1.3.7 item 7), the key its header's <c>kid</c> names
    /// resolved under that <c>alg</c> alone (RFC 8725 §3.1), then through <see cref="Oidc10IdTokenValidator.ValidateAsync"/> its
    /// signature, its <c>iss</c> the registration's issuer, its <c>aud</c> naming the registration's client with no other
    /// audience trusted, an <c>azp</c> naming that client where present, <c>exp</c>, <c>iat</c> and the <c>nonce</c> the flow
    /// sent (§3.1.3.7 items 2, 3, 4, 5, 6, 9, 10 and 11). A flow whose request sent no nonce is refused before anything is sent.
    /// </summary>
    /// <param name="infrastructure">The long-lived infrastructure carrying transport, parsing, persistence, and time delegates.</param>
    /// <param name="registration">The registration identifying the OpenID Provider and the client's authentication there.</param>
    /// <param name="flowId">The flow identifier (the <c>state</c> value) the callback held the code under.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport and flow-state delegates.</param>
    /// <param name="clientAssertionOptions">The client-assertion inputs for an assertion method; <see langword="null"/> for every other method.</param>
    /// <param name="verification">How the ID Token is verified.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>What the sign-in came to.</returns>
    public static async ValueTask<OpenIdSignInResult> ExchangeOpenIdTokenAsync(
        OAuthClientInfrastructure infrastructure,
        ClientRegistration registration,
        string flowId,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        OpenIdTokenVerification verification,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(infrastructure);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(flowId);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(verification);

        //OpenID Connect Core 1.0 §3.1.3.7 item 11 holds the ID Token to the nonce the request sent; a flow holding none could
        //accept an ID Token replayed from another sign-in, so its code is never exchanged.
        if(await infrastructure.LoadStateAsync(flowId, context, cancellationToken).ConfigureAwait(false)
            is not AuthorizationCodeReceivedState { Nonce: { Length: > 0 } nonce })
        {
            return new OpenIdSignInResult
            {
                Exchange = AuthCodeFlowEndpointResult.Refused(
                    AuthCodeFlowEndpointOutcome.BadRequest,
                    AuthCodeFlowRefusalOrigin.ClientJudgement,
                    OAuthErrors.InvalidRequest,
                    "No code of an OpenID Connect authentication request that sent a nonce is pending exchange for the supplied flow (OpenID Connect Core 1.0 §3.1.3.7)."),
                Refusal = OpenIdSignInRefusal.NonceNotHeld
            };
        }

        var exchange = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string>(StringComparer.Ordinal) { [AuthCodeFlowRoutes.FlowIdField] = flowId },
            infrastructure,
            registration,
            context,
            clientAssertionOptions,
            resource: null,
            cancellationToken).ConfigureAwait(false);

        if(exchange.Outcome != AuthCodeFlowEndpointOutcome.Ok)
        {
            return new OpenIdSignInResult { Exchange = exchange, Refusal = OpenIdSignInRefusal.ExchangeRefused };
        }

        var refreshToken = exchange.Body?.GetValueOrDefault(OAuthRequestParameterNames.RefreshToken) as string;

        if(exchange.Body?.GetValueOrDefault(OAuthRequestParameterNames.IdToken) is not string { Length: > 0 } idToken)
        {
            return new OpenIdSignInResult { Exchange = exchange, Refusal = OpenIdSignInRefusal.NoIdToken, RefreshToken = refreshToken };
        }

        if(UnverifiedJwsFacts.Read(idToken, verification.Base64UrlDecoder, infrastructure.MemoryPool)
            is not { KeyId: { Length: > 0 } keyId, Algorithm: { Length: > 0 } algorithm })
        {
            return new OpenIdSignInResult { Exchange = exchange, Refusal = OpenIdSignInRefusal.KeyUnresolved, RefreshToken = refreshToken };
        }

        //§3.1.3.7 item 7: the token is judged under the algorithm the client registered, so no key of another algorithm the
        //provider publishes is ever asked for (RFC 8725 §3.1: the algorithm the client accepts is the client's to fix).
        if(!string.Equals(algorithm, verification.RegisteredAlgorithm, StringComparison.Ordinal))
        {
            return new OpenIdSignInResult { Exchange = exchange, Refusal = OpenIdSignInRefusal.AlgorithmNotRegistered, RefreshToken = refreshToken };
        }

        using var key = await verification.ResolveKey(keyId, algorithm, cancellationToken).ConfigureAwait(false);

        if(key is null)
        {
            return new OpenIdSignInResult { Exchange = exchange, Refusal = OpenIdSignInRefusal.KeyUnresolved, RefreshToken = refreshToken };
        }

        var verifySignature = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
            key.Tag.Get<CryptoAlgorithm>(), key.Tag.Get<Purpose>());
        var issuer = registration.AuthorizationServerIssuer.OriginalString;
        var clientId = registration.ClientId.Value;

        //The key the header named is the one key the validator verifies under: the validator asks by the header's kid, and is
        //answered the resolved key for that kid alone.
        var resolveNamedKey = new ServerVerificationKeyResolverDelegate((named, usage, tenant, exchangeContext, cancel) =>
            ValueTask.FromResult(string.Equals(named.Value, keyId, StringComparison.Ordinal) ? key : null));

        try
        {
            var validated = await Oidc10IdTokenValidator.ValidateAsync(
                idToken,
                issuer,
                clientId,
                resolveNamedKey,
                verifySignature,
                verification.Parser,
                verification.Base64UrlDecoder,
                infrastructure.TimeProvider,
                infrastructure.MemoryPool,
                verification.ClockSkew,
                new TenantId(issuer),
                [],
                clientId,
                nonce,
                [],
                cancellationToken).ConfigureAwait(false);

            if(validated is not { FailureReason: null, Claims: { } claims })
            {
                return new OpenIdSignInResult
                {
                    Exchange = exchange,
                    Refusal = OpenIdSignInRefusal.IdTokenRefused,
                    IdTokenFailure = validated.FailureReason ?? JwsAccessTokenValidationFailureReason.Malformed,
                    RefreshToken = refreshToken
                };
            }

            return new OpenIdSignInResult { Exchange = exchange, IdToken = idToken, Claims = claims, RefreshToken = refreshToken };
        }
        catch(Exception unreadable) when(unreadable is FormatException or InvalidOperationException or ArgumentException or CryptographicException)
        {
            return new OpenIdSignInResult
            {
                Exchange = exchange,
                Refusal = OpenIdSignInRefusal.IdTokenRefused,
                IdTokenFailure = JwsAccessTokenValidationFailureReason.Malformed,
                RefreshToken = refreshToken
            };
        }
    }
}

using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Introspection;

/// <summary>
/// The token introspection sub-client of <see cref="OAuthClient"/>: a per-call handle over an
/// <see cref="OAuthClientInfrastructure"/> through which a protected resource asks the authorization server about a
/// token presented to it, per <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2">RFC 7662 Section 2</see>.
/// </summary>
/// <remarks>
/// <para>
/// Constructed via the <c>Introspection</c> extension property on <see cref="OAuthClient"/>. The struct is cheap to
/// materialise (one reference field) and carries no per-authorization-server state: the one protocol method takes the
/// resource's <see cref="ClientRegistration"/> at the authorization server, which names the server and the resource's
/// client authentication.
/// </para>
/// <para>
/// <strong>Usage.</strong>
/// </para>
/// <code>
/// OAuthClient client = new(infrastructure);
/// Result&lt;TokenIntrospectionResult, OAuthParseError&gt; result = await client.Introspection.IntrospectAsync(
///     registration,
///     new TokenIntrospectionRequest { Token = presentedToken, TokenTypeHint = "access_token" },
///     context,
///     clientAssertionOptions: null,
///     cancellationToken);
/// </code>
/// </remarks>
[SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "TokenIntrospectionClient is a service-shaped wrapper around a single reference; value equality would compare reference identity of the underlying infrastructure, which is not a meaningful operation for callers.")]
public readonly struct TokenIntrospectionClient
{
    /// <summary>The long-lived infrastructure this client reads delegates from.</summary>
    public OAuthClientInfrastructure Infrastructure { get; }


    /// <summary>
    /// Creates a new token introspection client over the supplied infrastructure. Internal: use
    /// <c>Introspection</c> to access an instance.
    /// </summary>
    /// <param name="infrastructure">The infrastructure the client reads its transport, pool, clock and metadata from.</param>
    internal TokenIntrospectionClient(OAuthClientInfrastructure infrastructure)
    {
        ArgumentNullException.ThrowIfNull(infrastructure);

        Infrastructure = infrastructure;
    }


    /// <summary>
    /// Asks the authorization server whether <paramref name="request"/>'s token is active and what it knows of it, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.1">RFC 7662 Section 2.1</see>: the form
    /// <c>token</c> and, when present, <c>token_type_hint</c>, POSTed once to the metadata's
    /// <c>introspection_endpoint</c> through <see cref="OAuthClientInfrastructure.SendFormPostAsync"/>, authenticated by
    /// <see cref="ClientRegistration.AuthenticationMethod"/>, never with a DPoP proof, and the answer read by
    /// <see cref="OAuthResponseParsers.ParseTokenIntrospectionResponse"/>.
    /// </summary>
    /// <remarks>
    /// The operation caches nothing and retries nothing: every call is one exchange, a transport exception passes to
    /// the caller, and an application that caches a result stops at its <see cref="TokenIntrospectionResult.ExpiresAt"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7662#section-4">RFC 7662 Section 4</see>: "If the response
    /// contains the "exp" parameter (expiration), the response MUST NOT be cached beyond the time indicated therein.").
    /// </remarks>
    /// <param name="registration">
    /// The resource's registration at the authorization server: <see cref="ClientRegistration.AuthorizationServerIssuer"/>
    /// names the server whose metadata is resolved, and <see cref="ClientRegistration.AuthenticationMethod"/> the client
    /// authentication the request carries: <c>none</c>, <c>client_secret_post</c>, <c>client_secret_basic</c> or
    /// <c>private_key_jwt</c>; any other method throws <see cref="NotSupportedException"/>.
    /// </param>
    /// <param name="request">The token and the hint.</param>
    /// <param name="context">The per-operation exchange context threaded into the transport delegate.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 Section 2.2). Required when the
    /// registration's method is <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>; ignored for every other method.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The token's <see cref="TokenIntrospectionResult"/>, <see cref="TokenIntrospectionResult.IsActive"/>
    /// <see langword="false"/> for an inactive token; or the failure: <see cref="OAuthAuthorizationServerMetadataUnresolved"/>
    /// when the metadata does not resolve; <see cref="OAuthInvalidFieldValue"/> naming <c>issuer</c> for metadata of
    /// another issuer, <c>introspection_endpoint</c> for metadata naming none, or a response member the reader refuses;
    /// <see cref="OAuthOutboundFetchPolicyDenied"/> for an endpoint the outbound policy denies, which is never dialed;
    /// <see cref="OAuthRedirectRefused"/> for a redirect, which is never followed; <see cref="OAuthProtocolError"/> for
    /// the authorization server's error response; <see cref="OAuthMalformedResponse"/> for a body the reader cannot read.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="registration"/>, <paramref name="request"/> or <paramref name="context"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">The request's <see cref="TokenIntrospectionRequest.Token"/> is empty.</exception>
    /// <exception cref="NotSupportedException">The registration's method is not one of the four the operation attaches.</exception>
    /// <exception cref="InvalidOperationException">
    /// The registration's method needs <see cref="ClientRegistration.AuthenticationKeyMaterial"/> it does not carry, or is
    /// <c>private_key_jwt</c> with no <paramref name="clientAssertionOptions"/>.
    /// </exception>
    public ValueTask<Result<TokenIntrospectionResult, OAuthParseError>> IntrospectAsync(
        ClientRegistration registration,
        TokenIntrospectionRequest request,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken) =>
        TokenIntrospectionFlowHandlers.IntrospectAsync(
            request, Infrastructure, registration, context, clientAssertionOptions, cancellationToken);
}

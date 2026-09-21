using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.ClientCredentials;

/// <summary>
/// The Client Credentials sub-client of <see cref="OAuthClient"/>. A per-call handle over an
/// <see cref="OAuthClientInfrastructure"/> that requests an access token for the client itself,
/// with no end-user and no authorization code, per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4">RFC 6749 §4.4</see>.
/// </summary>
/// <remarks>
/// <para>
/// Constructed via the <c>ClientCredentials</c> extension property on <see cref="OAuthClient"/>. The
/// struct is cheap to materialise (one reference field) and carries no per-AS state — the single
/// protocol method takes a <see cref="ClientRegistration"/> as its first parameter, describing which
/// authorization server this call targets.
/// </para>
/// <para>
/// <strong>Usage.</strong>
/// </para>
/// <code>
/// OAuthClient client = new(infrastructure);
/// ClientRegistration registration = LoadFromStore(clientId);
///
/// AuthCodeFlowEndpointResult token = await client.ClientCredentials.RequestTokenAsync(
///     registration, scope: "telemetry.read", resource: null, [], clientAssertionOptions: null, ct);
/// </code>
/// </remarks>
[SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "ClientCredentialsClient is a service-shaped wrapper around a single reference; value equality would compare reference identity of the underlying infrastructure, which is not a meaningful operation for callers.")]
public readonly struct ClientCredentialsClient
{
    /// <summary>The long-lived infrastructure this client reads delegates from.</summary>
    public OAuthClientInfrastructure Infrastructure { get; }


    /// <summary>
    /// Creates a new Client Credentials client over the supplied infrastructure. Internal — use
    /// <c>ClientCredentials</c> to access an instance.
    /// </summary>
    internal ClientCredentialsClient(OAuthClientInfrastructure infrastructure)
    {
        ArgumentNullException.ThrowIfNull(infrastructure);

        Infrastructure = infrastructure;
    }


    /// <summary>
    /// Requests an access token for the client itself per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4.2">RFC 6749 §4.4.2</see>:
    /// composes <c>grant_type=client_credentials</c>, attaches confidential-client authentication by
    /// <see cref="ClientRegistration.AuthenticationMethod"/>, and sends through the same
    /// DPoP-retrying token request the Authorization Code token leg uses.
    /// </summary>
    /// <param name="registration">The registration identifying the authorization server.</param>
    /// <param name="scope">The requested scope, or <see langword="null"/> to request the AS's default.</param>
    /// <param name="resource">
    /// The RFC 8707 §2 <c>resource</c> indicator(s) to request. Each entry MUST be one absolute
    /// URI — several indicators are several list entries, threaded as genuinely REPEATED wire
    /// occurrences, never one occurrence carrying several space-joined URIs. <see langword="null"/>
    /// or empty omits the parameter entirely.
    /// </param>
    /// <param name="context">The per-operation exchange context threaded into the transport delegate.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2). Required when
    /// <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>; ignored for every other method.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see cref="AuthCodeFlowEndpointOutcome.Ok"/> with the token response fields on success, or the
    /// typed failure the token leg answers with: a refused request carries the authorization server's
    /// error code, and a token endpoint the outbound policy denies is never dialed.
    /// </returns>
    public ValueTask<AuthCodeFlowEndpointResult> RequestTokenAsync(
        ClientRegistration registration,
        string? scope,
        IReadOnlyList<string>? resource,
        ExchangeContext context,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        return ClientCredentialsFlowHandlers.HandleTokenRequestAsync(
            registration, scope, resource, Infrastructure, context, clientAssertionOptions, cancellationToken);
    }
}

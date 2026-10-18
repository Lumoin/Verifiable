using System.Diagnostics;
using Verifiable.OAuth.Client;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The introspection mode of the test resource server (<see cref="TestResourceServerShell"/>,
/// <see cref="ResourceServerHttpApplication"/>): the resource validates a presented access token by asking the
/// authorization server's introspection endpoint through the library's operation
/// (<see cref="Verifiable.OAuth.Introspection.TokenIntrospectionClient.IntrospectAsync"/>) rather than by verifying a
/// JWT itself
/// (<see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.1">RFC 7662 Section 2.1</see>: "The protected resource
/// calls the introspection endpoint using an HTTP POST [RFC7231] request with parameters sent as
/// "application/x-www-form-urlencoded" data").
/// </summary>
/// <remarks>
/// The client's infrastructure sends through an <see cref="System.Net.Http.HttpClient"/> whose outermost handler is
/// <see cref="Recorder"/>, so a row reads every exchange the resource had with the authorization server.
/// </remarks>
[DebuggerDisplay("ResourceServerIntrospection ClientId={Registration.ClientId}")]
internal sealed record ResourceServerIntrospection
{
    /// <summary>The resource's OAuth client, whose infrastructure carries the transport to the authorization server.</summary>
    public required OAuthClient Client { get; init; }

    /// <summary>The resource's registration at the authorization server, naming the server and the resource's client authentication.</summary>
    public required ClientRegistration Registration { get; init; }

    /// <summary>The <c>private_key_jwt</c> signing inputs, or <see langword="null"/> for every other method.</summary>
    public ClientAssertionOptions? ClientAssertionOptions { get; init; }

    /// <summary>The recording handler of the resource's outbound client.</summary>
    public required IntrospectionExchangeRecorder Recorder { get; init; }
}

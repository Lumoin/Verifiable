using System.Collections.Immutable;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.AuthCode.States;

/// <summary>
/// The authorization server redirected back with an authorization code.
/// This is the second DB persistence point.
/// </summary>
/// <remarks>
/// Transitions to <see cref="TokenReceivedState"/> after a successful token exchange.
/// </remarks>
public sealed record AuthorizationCodeReceivedState : FlowState
{
    /// <summary>
    /// The authorization code from the redirect. Single-use; must not be logged.
    /// </summary>
    public required string Code { get; init; }

    /// <summary>
    /// The <c>state</c> value echoed back in the redirect. Must be validated against the
    /// value sent in the authorization request to prevent CSRF per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public required string State { get; init; }

    /// <summary>
    /// The <c>iss</c> parameter echoed back in the redirect. Must be validated against
    /// <see cref="FlowState.ExpectedIssuer"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>
    /// when present. Absent in plain RFC 6749 flows that do not require issuer identification.
    /// </summary>
    public required string? IssuerId { get; init; }

    /// <summary>Carried forward for the token exchange request.</summary>
    public required PkceParameters Pkce { get; init; }

    /// <summary>Carried forward for the token exchange request.</summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>
    /// <c>resource</c> indicators the authorization request named, carried forward from
    /// <see cref="ParCompletedState.Resource"/> and empty when it named none. The token exchange
    /// request names them when its caller names none: the MCP authorization specification says the
    /// <c>resource</c> parameter "MUST be included in both authorization requests and token
    /// requests"
    /// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation">MCP
    /// authorization, Resource Parameter Implementation</see>), and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see> lets the
    /// parameter be used "on an access token request made to the token endpoint, for all grant
    /// types".
    /// </summary>
    public ImmutableArray<string> Resource { get; init; } = [];
}

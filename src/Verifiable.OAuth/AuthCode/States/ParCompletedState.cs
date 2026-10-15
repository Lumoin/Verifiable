using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.AuthCode.States;

/// <summary>
/// PAR has completed. The <c>request_uri</c> is ready to embed in the authorization redirect.
/// This is the first DB persistence point.
/// </summary>
/// <remarks>Transitions to <see cref="AuthorizationCodeReceivedState"/> when the code arrives.</remarks>
[DebuggerDisplay("ParCompleted FlowId={FlowId} RequestUri={Par.RequestUri}")]
public sealed record ParCompletedState : FlowState
{
    /// <summary>
    /// The PKCE parameters. Persisted here because the verifier is needed at the token
    /// endpoint and to enforce PKCE downgrade defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>.
    /// </summary>
    public required PkceParameters Pkce { get; init; }

    /// <summary>The redirect URI carried forward.</summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>The scopes carried forward.</summary>
    public required ImmutableArray<string> Scopes { get; init; }

    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>
    /// <c>resource</c> indicators the authorization request named, in the order sent, and empty when
    /// it named none. Carried so that the code redemption names them: the MCP authorization
    /// specification says the <c>resource</c> parameter "MUST be included in both authorization
    /// requests and token requests"
    /// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation">MCP
    /// authorization, Resource Parameter Implementation</see>).
    /// </summary>
    public ImmutableArray<string> Resource { get; init; } = [];

    /// <summary>
    /// The PAR response. <see cref="ParResponse.RequestUri"/> is used as both the
    /// deep-link redirect parameter and the DB secondary lookup key.
    /// </summary>
    public required ParResponse Par { get; init; }
}

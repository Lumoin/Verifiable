using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.OAuth.Pkce;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Initiates a new Authorization Code flow. Transitions to
/// <see cref="Verifiable.OAuth.AuthCode.States.PkceGeneratedState"/>.
/// </summary>
/// <param name="Pkce">The freshly generated PKCE parameters for this flow.</param>
/// <param name="RedirectUri">The redirect URI registered for this flow instance.</param>
/// <param name="Scopes">The requested scopes.</param>
/// <param name="FlowId">The stable flow identifier assigned by the caller.</param>
/// <param name="ExpectedIssuer">
/// The issuer identifier of the authorization server. Stored for mix-up attack defense per
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
/// </param>
/// <param name="InitiatedAt">The UTC instant of initiation.</param>
/// <param name="InitialExpiresAt">
/// The initial expiry applied before the PAR response provides its <c>expires_in</c>.
/// </param>
[DebuggerDisplay("Initiate FlowId={FlowId}")]
public sealed record Initiate(
    PkceParameters Pkce,
    Uri RedirectUri,
    ImmutableArray<string> Scopes,
    string FlowId,
    string ExpectedIssuer,
    DateTimeOffset InitiatedAt,
    DateTimeOffset InitialExpiresAt): FlowInput
{
    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>
    /// <c>resource</c> indicators the authorization request names, in the order sent, and empty when
    /// it names none. The transitions carry them to
    /// <see cref="Verifiable.OAuth.AuthCode.States.AuthorizationCodeReceivedState.Resource"/> so that
    /// the code redemption names them too: the MCP authorization specification says the
    /// <c>resource</c> parameter "MUST be included in both authorization requests and token
    /// requests"
    /// (<see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#resource-parameter-implementation">MCP
    /// authorization, Resource Parameter Implementation</see>).
    /// </summary>
    public ImmutableArray<string> Resource { get; init; } = [];
}

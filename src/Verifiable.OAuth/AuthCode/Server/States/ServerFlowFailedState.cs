using System.Diagnostics;

namespace Verifiable.OAuth.AuthCode.Server.States;

/// <summary>
/// The server-side Authorization Code flow failed. Terminal failure state.
/// </summary>
/// <remarks>
/// <para>
/// Produced by any transition that receives a <see cref="ServerFail"/> input, or
/// when the transition function encounters an invalid state/input combination.
/// </para>
/// <para>
/// <see cref="ErrorCode"/> maps directly to the OAuth 2.0 wire error value returned
/// in the token or authorize error response — <c>invalid_grant</c>,
/// <c>invalid_request</c>, <c>unauthorized_client</c>, <c>server_error</c>, etc.
/// <see cref="OAuthFlowState.FlowId"/> and <see cref="Reason"/> are for server-side
/// audit logging only and are never forwarded to the client.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerFlowFailed FlowId={FlowId} ErrorCode={ErrorCode}")]
public sealed record ServerFlowFailedState: OAuthFlowState
{
    /// <summary>
    /// The OAuth 2.0 error code for the wire response, e.g. <c>invalid_grant</c>,
    /// <c>invalid_request</c>, <c>server_error</c>.
    /// </summary>
    public required string ErrorCode { get; init; }

    /// <summary>
    /// Human-readable failure reason for server-side audit logging.
    /// Never forwarded to the client.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>The UTC instant at which the failure was recorded.</summary>
    public required DateTimeOffset FailedAt { get; init; }
}

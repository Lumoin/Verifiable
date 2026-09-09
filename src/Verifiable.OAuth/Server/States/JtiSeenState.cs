using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Server.States;

/// <summary>
/// A degenerate flow state recording that a specific <c>(issuer, jti)</c>
/// pair has been observed within the replay window. Used as the value
/// type behind the JTI secondary index built by the application's
/// <see cref="SaveServerFlowStateDelegate"/>.
/// </summary>
/// <remarks>
/// The state never transitions — once written, it serves as a presence
/// marker for replay detection. The replay window is governed by the
/// application's storage TTL on the secondary index; records older than
/// the window expire naturally.
/// </remarks>
[DebuggerDisplay("JtiSeenState Issuer={Issuer,nq} Jti={Jti,nq} SeenAt={SeenAt}")]
public sealed record JtiSeenState: FlowState
{
    /// <summary>The issuer URI string the jti was observed under.</summary>
    public required string Issuer { get; init; }

    /// <summary>The jti value from the DPoP proof.</summary>
    public required string Jti { get; init; }

    /// <summary>When the jti was first observed.</summary>
    public required DateTimeOffset SeenAt { get; init; }

    /// <summary>
    /// The one <c>(issuer, jti)</c> correlation key this state is indexed under, composed
    /// through <see cref="JtiReplayGuard.CorrelationKey"/> so a host's save switch never
    /// re-derives the shape by hand.
    /// </summary>
    public string CorrelationKey => JtiReplayGuard.CorrelationKey(Issuer, Jti);
}

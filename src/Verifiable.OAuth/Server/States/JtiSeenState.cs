using System.Diagnostics;

namespace Verifiable.OAuth.Server.States;

/// <summary>
/// A degenerate flow state recording that a specific <c>(purpose, issuer, jti)</c>
/// triple, a DPoP proof's with its target URI, has been observed within the replay window. Used as the value
/// type behind the JTI secondary index built by the application's
/// <see cref="SaveServerFlowStateDelegate"/>.
/// </summary>
/// <remarks>
/// The state never transitions — once written, it serves as a presence
/// marker for replay detection. The replay window is governed by the
/// application's storage TTL on the secondary index; records older than
/// the window expire naturally.
/// </remarks>
[DebuggerDisplay("JtiSeenState Purpose={Purpose} Issuer={Issuer,nq} Target={Target,nq} Jti={Jti,nq} SeenAt={SeenAt}")]
public sealed record JtiSeenState : FlowState
{
    /// <summary>The kind of object the <c>jti</c> identifies.</summary>
    public required JtiReplayPurpose Purpose { get; init; }

    /// <summary>The issuer URI string the jti was observed under.</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The normalized target URI a DPoP proof's <c>jti</c> was observed at, the context
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see> records it in;
    /// <see langword="null"/> for every other <see cref="Purpose"/>.
    /// </summary>
    public string? Target { get; init; }

    /// <summary>The presented <c>jti</c> value.</summary>
    public required string Jti { get; init; }

    /// <summary>When the jti was first observed.</summary>
    public required DateTimeOffset SeenAt { get; init; }

    /// <summary>
    /// The one <c>(purpose, issuer, jti)</c> correlation key this state is indexed under, composed
    /// through <see cref="JtiReplayGuard.CorrelationKey(JtiReplayPurpose, string, string?, string)"/> so a host's save switch never
    /// re-derives the shape by hand.
    /// </summary>
    public string CorrelationKey => JtiReplayGuard.CorrelationKey(Purpose, Issuer, Target, Jti);
}

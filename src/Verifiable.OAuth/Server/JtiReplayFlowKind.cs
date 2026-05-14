using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// A flow kind marker for the degenerate one-state JTI-replay defense flow.
/// </summary>
/// <remarks>
/// <para>
/// JTI tracking writes a <see cref="States.JtiSeenState"/> record under a
/// <c>(issuer, jti)</c> correlation key when the AS first observes a DPoP
/// proof's <c>jti</c>. The state never transitions; presence in storage is
/// the replay signal. The flow kind exists as the routing discriminator
/// for <see cref="ResolveCorrelationKeyDelegate"/> lookups against the
/// secondary index.
/// </para>
/// <para>
/// This kind is neither stateful (no PDA) nor stateless in the
/// <see cref="StatelessFlowKind"/> sense (which is for endpoints that
/// compute responses without persistence). It carries persistence — the
/// secondary index — but no transitions. Sealed singleton accessed via
/// <c>FlowKind.JtiReplay</c>.
/// </para>
/// </remarks>
[DebuggerDisplay("JtiReplayFlowKind")]
public sealed class JtiReplayFlowKind: FlowKind
{
    /// <summary>The singleton instance.</summary>
    public static JtiReplayFlowKind Instance { get; } = new();


    private JtiReplayFlowKind() { }


    /// <inheritdoc/>
    public override string Name => "jti-replay";
}

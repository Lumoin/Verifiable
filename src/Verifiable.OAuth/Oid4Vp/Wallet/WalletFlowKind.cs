using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// The OID4VP wallet-side flow per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// Accessed via <c>FlowKind.Wallet</c>.
/// </para>
/// <para>
/// Wallet flows require context (<c>request_uri</c> and the expected Verifier
/// <c>client_id</c>) that is not available through the generic
/// <see cref="CreateAsync"/> signature. Wallet flows are created directly via
/// <see cref="WalletFlowAutomaton.Create"/> with the needed parameters and then
/// persisted. The authorization-server dispatcher does not host wallet flows —
/// they are client-side — so <see cref="CreateAsync"/> is never reached in that
/// direction. It throws to signal incorrect use.
/// </para>
/// </remarks>
[DebuggerDisplay("WalletFlowKind")]
public sealed class WalletFlowKind: StatefulFlowKind
{
    /// <summary>The singleton instance.</summary>
    public static WalletFlowKind Instance { get; } = new();


    private WalletFlowKind() { }


    /// <inheritdoc/>
    public override string Name => "wallet";


    /// <inheritdoc/>
    /// <remarks>
    /// Wallet flows require context not expressible in the generic
    /// <see cref="CreateAsync"/> signature. Always throws — use
    /// <see cref="WalletFlowAutomaton.Create"/> directly.
    /// </remarks>
    public override ValueTask<(OAuthFlowState State, int StepCount)> CreateAsync(
        string runId,
        TimeProvider timeProvider) =>
        throw new InvalidOperationException(
            "Wallet flows must be created via WalletFlowAutomaton.Create with the " +
            "request_uri and expected Verifier client identifier.");


    /// <inheritdoc/>
    public override async ValueTask<(OAuthFlowState State, int StepCount)> StepAsync(
        OAuthFlowState state,
        int stepCount,
        OAuthFlowInput input,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var pda = WalletFlowAutomaton.CreateFromSnapshot(state, stepCount, timeProvider);

        await pda.StepAsync(input, cancellationToken).ConfigureAwait(false);

        return (pda.CurrentState, pda.StepCount);
    }
}

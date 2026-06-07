using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The OID4VP server-side verifier flow per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0</see>
/// and HAIP 1.0. Models the Verifier's HTTP endpoints: PAR, JAR serving, and
/// direct_post response receipt.
/// </summary>
/// <remarks>
/// Accessed via <c>FlowKind.Oid4VpVerifierServer</c>.
/// </remarks>
[DebuggerDisplay("Oid4VpVerifierServerFlowKind")]
public sealed class Oid4VpVerifierServerFlowKind: StatefulFlowKind
{
    /// <summary>The singleton instance.</summary>
    public static Oid4VpVerifierServerFlowKind Instance { get; } = new();


    private Oid4VpVerifierServerFlowKind() { }


    /// <inheritdoc/>
    public override string Name => "oid4vp_verifier_server";


    /// <inheritdoc/>
    public override bool RequiresActionExecutor => true;


    /// <inheritdoc/>
    public override ValueTask<(OAuthFlowState State, int StepCount)> CreateAsync(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var pda = Oid4VpVerifierFlowAutomaton.Create(runId, timeProvider);

        return ValueTask.FromResult<(OAuthFlowState, int)>(
            (pda.CurrentState, pda.StepCount));
    }


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

        var pda = Oid4VpVerifierFlowAutomaton.CreateFromSnapshot(state, stepCount, timeProvider);

        await pda.StepAsync(input, cancellationToken).ConfigureAwait(false);

        return (pda.CurrentState, pda.StepCount);
    }
}

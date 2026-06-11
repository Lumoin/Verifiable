using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// The SIOPv2 server-side Relying Party flow. Models the RP's HTTP boundaries — request
/// preparation and Self-Issued ID Token response receipt + §11.1 verification. Accessed via
/// <c>FlowKind.SiopVerifierServer</c>.
/// </summary>
/// <remarks>
/// <see cref="RequiresActionExecutor"/> is <see langword="true"/>: the §11.1 ID Token validation
/// is an effectful operation, so it runs through the <see cref="OAuthActionExecutor"/> (the
/// <see cref="States.SiopResponseReceivedState"/> declares a <see cref="ValidateSelfIssuedIdToken"/>
/// action) rather than inside a PDA transition, keeping the automaton pure and deterministic —
/// the same effect-channeling the OID4VP verifier flow uses.
/// </remarks>
[DebuggerDisplay("SiopVerifierServerFlowKind")]
public sealed class SiopVerifierServerFlowKind: StatefulFlowKind
{
    /// <summary>The singleton instance.</summary>
    public static SiopVerifierServerFlowKind Instance { get; } = new();


    private SiopVerifierServerFlowKind() { }


    /// <inheritdoc/>
    public override string Name => "siop_verifier_server";


    /// <inheritdoc/>
    public override bool RequiresActionExecutor => true;


    /// <inheritdoc/>
    public override ValueTask<(OAuthFlowState State, int StepCount)> CreateAsync(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var pda = SiopVerifierFlowAutomaton.Create(runId, timeProvider);

        return ValueTask.FromResult<(OAuthFlowState, int)>((pda.CurrentState, pda.StepCount));
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

        var pda = SiopVerifierFlowAutomaton.CreateFromSnapshot(state, stepCount, timeProvider);

        await pda.StepAsync(input, cancellationToken).ConfigureAwait(false);

        return (pda.CurrentState, pda.StepCount);
    }
}

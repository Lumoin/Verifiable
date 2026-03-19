using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.AuthCode.Server;

/// <summary>
/// The server-side Authorization Code flow per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1">RFC 6749 §4.1</see>
/// with PAR and PKCE.
/// </summary>
/// <remarks>
/// Accessed via <c>FlowKind.AuthCodeServer</c>.
/// </remarks>
[DebuggerDisplay("AuthCodeServerFlowKind")]
public sealed class AuthCodeServerFlowKind: StatefulFlowKind
{
    /// <summary>The singleton instance.</summary>
    public static AuthCodeServerFlowKind Instance { get; } = new();


    private AuthCodeServerFlowKind() { }


    /// <inheritdoc/>
    public override string Name => "authcode_server";


    /// <inheritdoc/>
    public override ValueTask<(OAuthFlowState State, int StepCount)> CreateAsync(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var pda = AuthCodeServerFlowAutomaton.Create(runId, timeProvider);

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

        var pda = AuthCodeServerFlowAutomaton.CreateFromSnapshot(state, stepCount, timeProvider);

        await pda.StepAsync(input, cancellationToken).ConfigureAwait(false);

        return (pda.CurrentState, pda.StepCount);
    }
}

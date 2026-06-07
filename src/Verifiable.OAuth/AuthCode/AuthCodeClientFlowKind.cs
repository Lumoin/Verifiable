using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// The client-side Authorization Code flow per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1">RFC 6749 §4.1</see>
/// with PAR and PKCE.
/// </summary>
/// <remarks>
/// Accessed via <c>FlowKind.AuthCodeClient</c>.
/// </remarks>
[DebuggerDisplay("AuthCodeClientFlowKind")]
public sealed class AuthCodeClientFlowKind: StatefulFlowKind
{
    /// <summary>The singleton instance.</summary>
    public static AuthCodeClientFlowKind Instance { get; } = new();


    private AuthCodeClientFlowKind() { }


    /// <inheritdoc/>
    public override string Name => "authcode_client";


    /// <inheritdoc/>
    public override ValueTask<(OAuthFlowState State, int StepCount)> CreateAsync(
        string runId,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var pda = AuthCodeFlowAutomaton.Create(runId, timeProvider);

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

        var pda = AuthCodeFlowAutomaton.CreateFromSnapshot(state, stepCount, timeProvider);

        await pda.StepAsync(input, cancellationToken).ConfigureAwait(false);

        return (pda.CurrentState, pda.StepCount);
    }
}

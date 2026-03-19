namespace Verifiable.Core.Automata;

/// <summary>
/// Sentinel action indicating that no effectful work is needed after this transition.
/// The next input arrives from an external source such as an HTTP request.
/// </summary>
/// <remarks>
/// States that wait for an external actor — a Wallet POSTing a response, a user
/// completing consent, a polling client — return <see cref="Instance"/> from their
/// <c>NextAction</c> property. The effectful dispatch loop stops and yields control
/// back to the caller when it encounters a <see cref="NullAction"/>.
/// </remarks>
public sealed record NullAction: PdaAction
{
    /// <summary>The singleton instance.</summary>
    public static NullAction Instance { get; } = new();

    private NullAction() { }
}

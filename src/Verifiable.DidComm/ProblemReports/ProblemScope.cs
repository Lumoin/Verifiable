namespace Verifiable.DidComm.ProblemReports;

/// <summary>
/// The scope component of a DIDComm problem code — the sender's opinion of how much context should be
/// undone if the problem is deemed an error — and the breadth ordering the warning-escalation rule relies
/// on, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#scope">DIDComm Messaging v2.1 §Scope</see>
/// and §Replying to Warnings.
/// </summary>
/// <remarks>
/// Two scope tokens are named: <see cref="Protocol"/> (<c>p</c>) resets the whole protocol, and
/// <see cref="Message"/> (<c>m</c>) rejects only the previous message. Any other scope token is a formal
/// state name from the sender's state machine, meaning the protocol reverts to that state rather than
/// being abandoned. When a recipient escalates a warning to an error it MUST NOT narrow the scope
/// (DIDComm v2.1 §Replying to Warnings); <see cref="BreadthRank(string)"/> and
/// <see cref="IsAtLeastAsBroadAs(string, string)"/> express that ordering — <c>p</c> is broadest, a state
/// name is intermediate, and <c>m</c> is narrowest.
/// </remarks>
public static class ProblemScope
{
    /// <summary>The <c>p</c> scope — the whole protocol (and co-protocols it depends on) is abandoned or reset (DIDComm v2.1 §Scope). The broadest scope.</summary>
    public static string Protocol => "p";

    /// <summary>The <c>m</c> scope — only the previous message on the thread is rejected; it has no effect (DIDComm v2.1 §Scope). The narrowest scope.</summary>
    public static string Message => "m";


    /// <summary>Whether <paramref name="scope"/> is the <see cref="Protocol"/> (<c>p</c>) scope.</summary>
    /// <param name="scope">The scope token from a problem code.</param>
    /// <returns><see langword="true"/> when <paramref name="scope"/> is <c>p</c>.</returns>
    public static bool IsProtocol(string scope) => string.Equals(scope, Protocol, StringComparison.Ordinal);

    /// <summary>Whether <paramref name="scope"/> is the <see cref="Message"/> (<c>m</c>) scope.</summary>
    /// <param name="scope">The scope token from a problem code.</param>
    /// <returns><see langword="true"/> when <paramref name="scope"/> is <c>m</c>.</returns>
    public static bool IsMessage(string scope) => string.Equals(scope, Message, StringComparison.Ordinal);


    /// <summary>
    /// Ranks a scope token by breadth for the warning-escalation rule: <see cref="Protocol"/> (<c>p</c>) is
    /// <c>2</c>, a formal state name is <c>1</c>, and <see cref="Message"/> (<c>m</c>) is <c>0</c>
    /// (DIDComm v2.1 §Scope: a state-name scope is a partial failure between abandoning the protocol and
    /// rejecting a single message).
    /// </summary>
    /// <param name="scope">The scope token from a problem code.</param>
    /// <returns>2 for <c>p</c>, 0 for <c>m</c>, 1 for any state-name scope.</returns>
    public static int BreadthRank(string scope)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if(IsProtocol(scope))
        {
            return 2;
        }

        if(IsMessage(scope))
        {
            return 0;
        }

        return 1;
    }


    /// <summary>
    /// Whether <paramref name="scope"/> is at least as broad as <paramref name="other"/> — the constraint a
    /// warning-to-error escalation MUST satisfy (DIDComm v2.1 §Replying to Warnings: the escalated scope
    /// MUST be at least as broad as the original).
    /// </summary>
    /// <param name="scope">The candidate (escalated) scope.</param>
    /// <param name="other">The original scope it must not narrow.</param>
    /// <returns><see langword="true"/> when <paramref name="scope"/>'s breadth rank is greater than or equal to <paramref name="other"/>'s.</returns>
    public static bool IsAtLeastAsBroadAs(string scope, string other) =>
        BreadthRank(scope) >= BreadthRank(other);
}

namespace Verifiable.DidComm;

/// <summary>
/// The sorter of a DIDComm problem code — its leftmost token, a single character stating whether the
/// consequences of the problem are fully understood, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#sorter">DIDComm Messaging v2.1 §Sorter</see>.
/// </summary>
/// <remarks>
/// The spec defines exactly two values; an unrecognized leading token is a malformed problem code, so
/// there is no "unknown" member — a code whose sorter is neither <c>e</c> nor <c>w</c> fails to parse.
/// What distinguishes an error from a warning is clarity about its consequences, not its severity
/// (DIDComm v2.1 §Sorter).
/// </remarks>
public enum ProblemSorter
{
    /// <summary>
    /// <c>e</c> — an error: the problem clearly defeats the intentions of at least one party
    /// (DIDComm v2.1 §Sorter).
    /// </summary>
    Error,

    /// <summary>
    /// <c>w</c> — a warning: the consequences are not obvious to the reporter and require judgment from a
    /// human or another system to evaluate (DIDComm v2.1 §Sorter).
    /// </summary>
    Warning
}

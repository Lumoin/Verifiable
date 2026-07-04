using System.Collections.Generic;

namespace Verifiable.Keri;

/// <summary>
/// The KERI message types (the three-character <c>t</c> field "ilk" values) and the classification that decides
/// how a stream consumer treats each: which messages are key events that belong in an AID's key event log (KEL),
/// which of those are establishment events that change the key state, and which are receipts or routed messages.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#message-type-field">
/// Message type field</see> table. Establishment events (<c>icp</c>, <c>rot</c>, <c>dip</c>, <c>drt</c>)
/// determine the current key state; the non-establishment key event <c>ixn</c> seals data without changing it.
/// The establishment classification is what a key-event-log replayer keys on to decide whether an event folds
/// new key state or only advances the sequence.
/// </para>
/// </remarks>
public static class KeriMessageTypes
{
    /// <summary>Inception <c>icp</c>: incepts an AID and initializes its key state (establishment event).</summary>
    public static string Inception { get; } = "icp";

    /// <summary>Rotation <c>rot</c>: rotates the AID's key state (establishment event).</summary>
    public static string Rotation { get; } = "rot";

    /// <summary>Interaction <c>ixn</c>: seals interaction data to the current key state (non-establishment event).</summary>
    public static string Interaction { get; } = "ixn";

    /// <summary>Delegated inception <c>dip</c>: incepts a delegated AID and initializes its key state (establishment event).</summary>
    public static string DelegatedInception { get; } = "dip";

    /// <summary>Delegated rotation <c>drt</c>: rotates a delegated AID's key state (establishment event).</summary>
    public static string DelegatedRotation { get; } = "drt";

    /// <summary>Receipt <c>rct</c>: associates a proof such as a signature or seal to a key event.</summary>
    public static string Receipt { get; } = "rct";

    /// <summary>Query <c>qry</c>: queries information associated with an AID.</summary>
    public static string Query { get; } = "qry";

    /// <summary>Reply <c>rpy</c>: replies with information associated with an AID.</summary>
    public static string Reply { get; } = "rpy";

    /// <summary>Prod <c>pro</c>: requests information associated with a seal.</summary>
    public static string Prod { get; } = "pro";

    /// <summary>Bare <c>bar</c>: responds with information associated with a seal.</summary>
    public static string Bare { get; } = "bar";

    /// <summary>Exchange inception <c>xip</c>: incepts a multi-exchange message transaction.</summary>
    public static string ExchangeInception { get; } = "xip";

    /// <summary>Exchange <c>exn</c>: a generic exchange of information.</summary>
    public static string Exchange { get; } = "exn";


    /// <summary>
    /// The key event message types: those that are part of an AID's key event log.
    /// </summary>
    private static HashSet<string> KeyEvents { get; } = new(System.StringComparer.Ordinal)
    {
        Inception, Rotation, Interaction, DelegatedInception, DelegatedRotation
    };

    /// <summary>
    /// The establishment event message types: the key events that determine (set or change) the key state.
    /// </summary>
    private static HashSet<string> EstablishmentEvents { get; } = new(System.StringComparer.Ordinal)
    {
        Inception, Rotation, DelegatedInception, DelegatedRotation
    };

    /// <summary>
    /// The delegated event message types: establishment events whose state is anchored in a delegator's KEL.
    /// </summary>
    private static HashSet<string> DelegatedEvents { get; } = new(System.StringComparer.Ordinal)
    {
        DelegatedInception, DelegatedRotation
    };


    /// <summary>
    /// Whether a message type is a key event (part of a key event log).
    /// </summary>
    /// <param name="messageType">The three-character message type value.</param>
    /// <returns><see langword="true"/> for <c>icp</c>, <c>rot</c>, <c>ixn</c>, <c>dip</c>, or <c>drt</c>.</returns>
    public static bool IsKeyEvent(string messageType)
    {
        ArgumentNullException.ThrowIfNull(messageType);

        return KeyEvents.Contains(messageType);
    }


    /// <summary>
    /// Whether a message type is an establishment event (a key event that determines the key state).
    /// </summary>
    /// <param name="messageType">The three-character message type value.</param>
    /// <returns><see langword="true"/> for <c>icp</c>, <c>rot</c>, <c>dip</c>, or <c>drt</c>.</returns>
    public static bool IsEstablishmentEvent(string messageType)
    {
        ArgumentNullException.ThrowIfNull(messageType);

        return EstablishmentEvents.Contains(messageType);
    }


    /// <summary>
    /// Whether a message type is a delegated establishment event.
    /// </summary>
    /// <param name="messageType">The three-character message type value.</param>
    /// <returns><see langword="true"/> for <c>dip</c> or <c>drt</c>.</returns>
    public static bool IsDelegatedEvent(string messageType)
    {
        ArgumentNullException.ThrowIfNull(messageType);

        return DelegatedEvents.Contains(messageType);
    }
}

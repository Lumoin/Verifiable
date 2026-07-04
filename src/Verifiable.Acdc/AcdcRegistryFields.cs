using System.Collections.Generic;

namespace Verifiable.Acdc;

/// <summary>
/// The reserved field labels of ACDC transaction-event-log registry events (<c>rip</c> and <c>upd</c>), which incept
/// and update the registry (TEL) that holds an ACDC's issuance and revocation state. These are a distinct vocabulary
/// from <see cref="AcdcMessageFields"/>: a registry event shares some wire labels with an ACDC body (<c>v</c>,
/// <c>t</c>, <c>d</c>, <c>u</c>, <c>i</c>, <c>rd</c>, <c>dt</c>) but gives others different meaning — notably <c>n</c>
/// is the event's sequence number here, not an edge node — and adds the prior-event, transaction-ACDC, and
/// transaction-state labels.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#registry-message-types-and-fields">
/// registry message types and fields</see>: the registry events form a hash-chained log whose events are sealed
/// (anchored) in the Issuer's KEL, so the registry's state is bound to the Issuer's key state at the anchoring
/// event. The non-blindable (public) events <c>rip</c> and <c>upd</c> are modeled here; the blindable update
/// <c>bup</c>, whose blinded attribute SAID <c>b</c> is computed over a CESR-native fixed-field concatenation, is a
/// separate path.
/// </para>
/// </remarks>
public static class AcdcRegistryFields
{
    /// <summary>The version string label <c>v</c>: protocol (ACDC), version, serialization, and size.</summary>
    public static string Version { get; } = "v";

    /// <summary>The message type label <c>t</c>: the registry event type (<c>rip</c>, <c>upd</c>, or <c>bup</c>).</summary>
    public static string MessageType { get; } = "t";

    /// <summary>The SAID label <c>d</c>: the self-addressing digest of the registry event, which is anchored in the Issuer's KEL.</summary>
    public static string Said { get; } = "d";

    /// <summary>The UUID label <c>u</c>: a high-entropy salty nonce that blinds the registry inception's SAID.</summary>
    public static string Uuid { get; } = "u";

    /// <summary>The Issuer AID label <c>i</c>: the AID of the Issuer, the KEL controller that seals the registry events.</summary>
    public static string Issuer { get; } = "i";

    /// <summary>The registry SAID label <c>rd</c>: the SAID of the registry inception (<c>rip</c>) event, carried by every update to bind it to the registry.</summary>
    public static string RegistryDigest { get; } = "rd";

    /// <summary>The sequence number label <c>n</c>: a hex-encoded, zero-based, strictly monotonically increasing integer; the inception is <c>0</c>.</summary>
    public static string SequenceNumber { get; } = "n";

    /// <summary>The prior event SAID label <c>p</c>: the SAID of the immediately prior event in the registry, backward-chaining the log.</summary>
    public static string PriorSaid { get; } = "p";

    /// <summary>The datetime label <c>dt</c>: the ISO-8601 datetime of the event relative to the Issuer's clock.</summary>
    public static string Datetime { get; } = "dt";

    /// <summary>The transaction ACDC SAID label <c>td</c>: the SAID of the ACDC whose state this event updates (its top-level <c>d</c>), binding the ACDC to the registry.</summary>
    public static string TransactionAcdcSaid { get; } = "td";

    /// <summary>The transaction state label <c>ts</c>: a string from the registry's finite state set (for an issuance/revocation registry, <c>issued</c> or <c>revoked</c>).</summary>
    public static string TransactionState { get; } = "ts";

    /// <summary>The blinded attribute SAID label <c>b</c>: the blinding SAID (BLID) of a blindable update's blinded attribute block.</summary>
    public static string BlindedAttributeSaid { get; } = "b";


    /// <summary>
    /// The field order of a registry inception (<c>rip</c>) event: <c>[v, t, d, u, i, n, dt]</c>. All are required,
    /// and the sequence number <c>n</c> MUST be <c>0</c>.
    /// </summary>
    public static IReadOnlyList<string> InceptionFieldOrder { get; } =
        [Version, MessageType, Said, Uuid, Issuer, SequenceNumber, Datetime];

    /// <summary>
    /// The field order of a non-blindable registry update (<c>upd</c>) event:
    /// <c>[v, t, d, rd, n, p, dt, td, ts]</c>. All are required.
    /// </summary>
    public static IReadOnlyList<string> UpdateFieldOrder { get; } =
        [Version, MessageType, Said, RegistryDigest, SequenceNumber, PriorSaid, Datetime, TransactionAcdcSaid, TransactionState];
}

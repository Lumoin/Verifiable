namespace Verifiable.Acdc;

/// <summary>
/// An ACDC transaction-event-log registry event: the common identity of every event in a registry (TEL) that holds
/// an ACDC's issuance and revocation state. Concrete events — the registry inception and the non-blindable update —
/// add their own fields. A registry is a hash-chained log whose events are sealed (anchored) in the Issuer's KEL, so
/// reading a registry event yields the typed, serialization-agnostic body that a chain validator and the KEL-anchor
/// binding check operate on.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#registry-message-types-and-fields">
/// registry message types and fields</see>. These records carry the registry event's fields after decode; the field
/// labels are <see cref="AcdcRegistryFields"/>. This follows the chained-log event shape the KERI key events use (a
/// positional abstract base with the common version, type, SAID, and sequence number, and the concrete events as
/// sibling records), since a registry is a transaction event log analogous to a key event log.
/// </para>
/// </remarks>
/// <param name="VersionString">The version string <c>v</c>: protocol, version, serialization, and size.</param>
/// <param name="MessageType">The message type <c>t</c>: <c>rip</c> or <c>upd</c>.</param>
/// <param name="Said">The event's self-addressing digest <c>d</c>, which is anchored in the Issuer's KEL.</param>
/// <param name="SequenceNumber">The event's sequence number <c>n</c> in the registry (decoded from hexadecimal).</param>
public abstract record AcdcRegistryEvent(string VersionString, string MessageType, string Said, long SequenceNumber);


/// <summary>
/// A registry inception (<c>rip</c>) event: the genesis event that incepts an ACDC state registry. Its SAID is the
/// registry's universally unique identifier — the value an ACDC carries in its registry SAID, <c>rd</c>, field — and
/// is anchored in the Issuer's KEL as the registry proof seal.
/// </summary>
/// <remarks>
/// Field order on the wire is <c>[v, t, d, u, i, n, dt]</c> (all required), and the sequence number <c>n</c> MUST be
/// zero. The UUID <c>u</c> gives the registry's SAID sufficient entropy to be a unique, unguessable identifier.
/// </remarks>
/// <param name="VersionString">The version string <c>v</c>.</param>
/// <param name="Said">The registry SAID <c>d</c>: the registry's unique identifier.</param>
/// <param name="Uuid">The UUID <c>u</c>: a high-entropy salty nonce.</param>
/// <param name="Issuer">The Issuer AID <c>i</c>: the KEL controller that seals the registry's events.</param>
/// <param name="SequenceNumber">The sequence number <c>n</c>; MUST be zero for an inception.</param>
/// <param name="Datetime">The datetime <c>dt</c>: the ISO-8601 datetime relative to the Issuer's clock.</param>
public sealed record RegistryInceptionEvent(
    string VersionString,
    string Said,
    string Uuid,
    string Issuer,
    long SequenceNumber,
    string Datetime): AcdcRegistryEvent(VersionString, AcdcMessageTypes.RegistryInception, Said, SequenceNumber);


/// <summary>
/// A non-blindable registry update (<c>upd</c>) event: a public state update that sets the transaction state of an
/// ACDC in the registry — for an issuance/revocation registry, <c>issued</c> or <c>revoked</c>. It chains to the
/// prior event and carries the SAID of the ACDC whose state it updates.
/// </summary>
/// <remarks>
/// Field order on the wire is <c>[v, t, d, rd, n, p, dt, td, ts]</c> (all required). The registry SAID <c>rd</c>
/// matches the inception's SAID, binding the update to the registry; the prior SAID <c>p</c> and the sequence number
/// <c>n</c> chain it to the prior event; the transaction ACDC SAID <c>td</c> matches the ACDC's top-level SAID,
/// binding the ACDC to the registry. The blindable update <c>bup</c>, whose state is committed by a blinded
/// attribute SAID over a CESR-native concatenation, is a separate path.
/// </remarks>
/// <param name="VersionString">The version string <c>v</c>.</param>
/// <param name="Said">The event SAID <c>d</c>, anchored in the Issuer's KEL.</param>
/// <param name="RegistryDigest">The registry SAID <c>rd</c>: the inception event's SAID.</param>
/// <param name="SequenceNumber">The sequence number <c>n</c>: one greater than the prior event's.</param>
/// <param name="PriorSaid">The prior event SAID <c>p</c>: the SAID of the immediately prior registry event.</param>
/// <param name="Datetime">The datetime <c>dt</c>: the ISO-8601 datetime relative to the Issuer's clock.</param>
/// <param name="TransactionAcdcSaid">The transaction ACDC SAID <c>td</c>: the top-level SAID of the ACDC whose state this updates.</param>
/// <param name="TransactionState">The transaction state <c>ts</c>: a value from the registry's finite state set.</param>
public sealed record RegistryUpdateEvent(
    string VersionString,
    string Said,
    string RegistryDigest,
    long SequenceNumber,
    string PriorSaid,
    string Datetime,
    string TransactionAcdcSaid,
    string TransactionState): AcdcRegistryEvent(VersionString, AcdcMessageTypes.RegistryUpdate, Said, SequenceNumber);

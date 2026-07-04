using System.Collections.Generic;

namespace Verifiable.Keri;

/// <summary>
/// The reserved top-level field labels of KERI message bodies. KERI uses compact one- and two-character labels
/// so the signed over-the-wire serialization is bandwidth-minimal; this centralizes them so a parser, a builder,
/// and the tests agree on the wire names.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#keri-field-labels-for-data-structures">
/// KERI field labels for data structures</see>. A field label MUST keep the same value type wherever it appears,
/// and the top-level fields of each message type MUST appear in a fixed order, defined per message type.
/// </para>
/// </remarks>
public static class KeriMessageFields
{
    /// <summary>The version string label <c>v</c>: the leading field that makes a message body regex-parsable in a CESR stream.</summary>
    public static string Version { get; } = "v";

    /// <summary>The message type label <c>t</c>: a three-character message type (see <see cref="KeriMessageTypes"/>).</summary>
    public static string MessageType { get; } = "t";

    /// <summary>The SAID label <c>d</c>: the fully qualified self-addressing digest of the block in which it appears.</summary>
    public static string Said { get; } = "d";

    /// <summary>The identifier prefix label <c>i</c>: the fully qualified controller AID.</summary>
    public static string Prefix { get; } = "i";

    /// <summary>The sequence number label <c>s</c>: a strictly monotonically increasing integer encoded in hexadecimal.</summary>
    public static string SequenceNumber { get; } = "s";

    /// <summary>The prior SAID label <c>p</c>: the fully qualified digest of the prior message.</summary>
    public static string PriorSaid { get; } = "p";

    /// <summary>The keys signing threshold label <c>kt</c>: a hexadecimal integer or a fractional weight list.</summary>
    public static string KeysSigningThreshold { get; } = "kt";

    /// <summary>The signing keys label <c>k</c>: the ordered list of fully qualified current signing keys.</summary>
    public static string SigningKeys { get; } = "k";

    /// <summary>The next keys signing threshold label <c>nt</c>: a hexadecimal integer or a fractional weight list.</summary>
    public static string NextKeysSigningThreshold { get; } = "nt";

    /// <summary>The next key digests label <c>n</c>: the ordered list of fully qualified digests of the pre-rotated next keys.</summary>
    public static string NextKeyDigests { get; } = "n";

    /// <summary>The backer threshold label <c>bt</c>: a hexadecimal integer threshold over the backers.</summary>
    public static string BackerThreshold { get; } = "bt";

    /// <summary>The backers label <c>b</c>: the ordered list of fully qualified backer (witness) AIDs.</summary>
    public static string Backers { get; } = "b";

    /// <summary>The backers-to-remove label <c>br</c>: the ordered list of backer AIDs a rotation removes.</summary>
    public static string BackersToRemove { get; } = "br";

    /// <summary>The backers-to-add label <c>ba</c>: the ordered list of backer AIDs a rotation adds.</summary>
    public static string BackersToAdd { get; } = "ba";

    /// <summary>The configuration traits label <c>c</c>: the list of configuration trait / mode strings.</summary>
    public static string ConfigurationTraits { get; } = "c";

    /// <summary>The anchors label <c>a</c>: the list of anchored seals (field maps).</summary>
    public static string Anchors { get; } = "a";

    /// <summary>The delegator prefix label <c>di</c>: the fully qualified delegator AID of a delegated event.</summary>
    public static string DelegatorPrefix { get; } = "di";


    /// <summary>The exhaustive, ordered top-level fields of an inception (<c>icp</c>) message body.</summary>
    public static IReadOnlyList<string> InceptionFieldOrder { get; } =
        [Version, MessageType, Said, Prefix, SequenceNumber, KeysSigningThreshold, SigningKeys, NextKeysSigningThreshold, NextKeyDigests, BackerThreshold, Backers, ConfigurationTraits, Anchors];

    /// <summary>The exhaustive, ordered top-level fields of an interaction (<c>ixn</c>) message body.</summary>
    public static IReadOnlyList<string> InteractionFieldOrder { get; } =
        [Version, MessageType, Said, Prefix, SequenceNumber, PriorSaid, Anchors];

    /// <summary>The exhaustive, ordered top-level fields of a rotation (<c>rot</c>) message body.</summary>
    public static IReadOnlyList<string> RotationFieldOrder { get; } =
        [Version, MessageType, Said, Prefix, SequenceNumber, PriorSaid, KeysSigningThreshold, SigningKeys, NextKeysSigningThreshold, NextKeyDigests, BackerThreshold, BackersToRemove, BackersToAdd, ConfigurationTraits, Anchors];

    /// <summary>The exhaustive, ordered top-level fields of a delegated inception (<c>dip</c>) message body: the inception fields followed by the delegator AID.</summary>
    public static IReadOnlyList<string> DelegatedInceptionFieldOrder { get; } =
        [Version, MessageType, Said, Prefix, SequenceNumber, KeysSigningThreshold, SigningKeys, NextKeysSigningThreshold, NextKeyDigests, BackerThreshold, Backers, ConfigurationTraits, Anchors, DelegatorPrefix];

    /// <summary>The exhaustive, ordered top-level fields of a delegated rotation (<c>drt</c>) message body, identical to a rotation's.</summary>
    public static IReadOnlyList<string> DelegatedRotationFieldOrder { get; } =
        [Version, MessageType, Said, Prefix, SequenceNumber, PriorSaid, KeysSigningThreshold, SigningKeys, NextKeysSigningThreshold, NextKeyDigests, BackerThreshold, BackersToRemove, BackersToAdd, ConfigurationTraits, Anchors];


    /// <summary>
    /// The exhaustive, ordered top-level fields of the key event whose message type is given, that is the
    /// <c>*FieldOrder</c> list a fixed-field CESR-native decode walks positionally (a native <c>-F</c> body
    /// carries the field values in this order with no labels).
    /// </summary>
    /// <param name="messageType">The message type label (<c>t</c> value), one of the five modeled key events.</param>
    /// <returns>The ordered field labels of that message type.</returns>
    /// <exception cref="KeriException">The message type is not a modeled key event.</exception>
    /// <remarks>
    /// Anchored on the KERI specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#key-event-messages">
    /// key event messages</see>, whose normative bodies fix the field order per type; the native examples in the
    /// same section list each type's "Field order by label" that this returns.
    /// </remarks>
    public static IReadOnlyList<string> FieldOrderFor(string messageType)
    {
        ArgumentNullException.ThrowIfNull(messageType);

        return messageType switch
        {
            var type when type == KeriMessageTypes.Inception => InceptionFieldOrder,
            var type when type == KeriMessageTypes.Interaction => InteractionFieldOrder,
            var type when type == KeriMessageTypes.Rotation => RotationFieldOrder,
            var type when type == KeriMessageTypes.DelegatedInception => DelegatedInceptionFieldOrder,
            var type when type == KeriMessageTypes.DelegatedRotation => DelegatedRotationFieldOrder,
            _ => throw new KeriException($"KERI message type '{messageType}' is not a modeled key event with a fixed field order.")
        };
    }


    /// <summary>
    /// The set of reserved KERI top-level field labels.
    /// </summary>
    private static HashSet<string> Reserved { get; } = new(System.StringComparer.Ordinal)
    {
        Version, MessageType, Said, Prefix, SequenceNumber, PriorSaid, KeysSigningThreshold, SigningKeys,
        NextKeysSigningThreshold, NextKeyDigests, BackerThreshold, Backers, BackersToRemove, BackersToAdd,
        ConfigurationTraits, Anchors, DelegatorPrefix
    };


    /// <summary>
    /// Whether a label is one of the reserved KERI top-level field labels.
    /// </summary>
    /// <param name="label">The field label to test.</param>
    /// <returns><see langword="true"/> when the label is reserved.</returns>
    public static bool IsReserved(string label)
    {
        ArgumentNullException.ThrowIfNull(label);

        return Reserved.Contains(label);
    }
}

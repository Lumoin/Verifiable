using System.Collections.Generic;

namespace Verifiable.Acdc;

/// <summary>
/// The reserved field labels of ACDC message bodies. ACDC uses compact one- and two-character labels so the signed
/// over-the-wire serialization is bandwidth-minimal; this centralizes them so a reader, a SAID computation, and the
/// tests agree on the wire names and on the canonical top-level order.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#top-level-fields">
/// top-level fields</see> and <see href="https://trustoverip.github.io/kswg-acdc-specification/#other-reserved-fields">
/// other reserved fields</see> tables. A reserved label MUST keep the same value type wherever it appears, and the
/// top-level fields that appear MUST appear in the fixed order <see cref="TopLevelFieldOrder"/>. The schema, attribute,
/// aggregate, edge, and rule fields (<see cref="SectionFields"/>) each hold either a section's detail block or, in
/// compact form, that block's SAID (the aggregate, <c>A</c>, is special — its compact form is its aggregate value
/// rather than a SAID).
/// </para>
/// </remarks>
public static class AcdcMessageFields
{
    /// <summary>The version string label <c>v</c>: the leading field that makes a non-native ACDC body regex-parsable in a stream.</summary>
    public static string Version { get; } = "v";

    /// <summary>The message type label <c>t</c>: the three-character ACDC message type (see <see cref="AcdcMessageTypes"/>).</summary>
    public static string MessageType { get; } = "t";

    /// <summary>The SAID label <c>d</c>: the fully qualified self-addressing digest of the block in which it appears.</summary>
    public static string Said { get; } = "d";

    /// <summary>The UUID label <c>u</c>: a high-entropy salty nonce that blinds the block's SAID; its presence makes an ACDC private.</summary>
    public static string Uuid { get; } = "u";

    /// <summary>The issuer AID label <c>i</c> at the top level: the issuer whose control authority is established via KERI key state (context-dependent, such as an issuee, when nested).</summary>
    public static string Issuer { get; } = "i";

    /// <summary>The registry SAID label <c>rd</c>: the SAID of the registry inception event that holds the ACDC's issuance and revocation state.</summary>
    public static string RegistryDigest { get; } = "rd";

    /// <summary>The schema section label <c>s</c>: the SAID of the ACDC's JSON Schema block, or the block itself.</summary>
    public static string Schema { get; } = "s";

    /// <summary>The attribute section label <c>a</c>: the SAID of the attribute block, or the block itself; mutually exclusive with the aggregate, <c>A</c>.</summary>
    public static string Attribute { get; } = "a";

    /// <summary>The attribute aggregate section label <c>A</c>: the aggregate of a selectively disclosable attribute set, or the block itself; mutually exclusive with the attribute, <c>a</c>.</summary>
    public static string AttributeAggregate { get; } = "A";

    /// <summary>The edge section label <c>e</c>: the SAID of the edge block, or the block itself.</summary>
    public static string Edge { get; } = "e";

    /// <summary>The rule section label <c>r</c>: the SAID of the rule block, or the block itself.</summary>
    public static string Rule { get; } = "r";

    /// <summary>The datetime label <c>dt</c>: a context-dependent ISO-8601 datetime string relative to the issuer's clock.</summary>
    public static string Datetime { get; } = "dt";

    /// <summary>The node label <c>n</c>: the SAID of another ACDC that is the terminating vertex of a directed edge.</summary>
    public static string Node { get; } = "n";

    /// <summary>The operator label <c>o</c>: a unary edge operator or an m-ary edge-group operator expressing edge logic.</summary>
    public static string Operator { get; } = "o";

    /// <summary>The weight label <c>w</c>: an edge weight property for directed weighted edges and operators over them.</summary>
    public static string Weight { get; } = "w";

    /// <summary>The legal language label <c>l</c>: the text of a Ricardian contract clause in the rule section.</summary>
    public static string LegalLanguage { get; } = "l";


    /// <summary>
    /// The canonical order of the ACDC top-level fields: <c>[v, t, d, u, i, rd, s, a, A, e, r]</c>. Some are
    /// optional, but every top-level field that appears MUST appear in this order.
    /// </summary>
    public static IReadOnlyList<string> TopLevelFieldOrder { get; } =
        [Version, MessageType, Said, Uuid, Issuer, RegistryDigest, Schema, Attribute, AttributeAggregate, Edge, Rule];

    /// <summary>
    /// The top-level fields that MUST appear in any ACDC: <c>[v, d, i, s]</c>.
    /// </summary>
    public static IReadOnlyList<string> RequiredFields { get; } =
        [Version, Said, Issuer, Schema];

    /// <summary>
    /// The top-level section fields whose value is either a section detail block or its compact form:
    /// <c>[s, a, A, e, r]</c>.
    /// </summary>
    public static IReadOnlyList<string> SectionFields { get; } =
        [Schema, Attribute, AttributeAggregate, Edge, Rule];

    /// <summary>
    /// The top-level section fields whose compact form is the section block's SAID: <c>[s, a, e, r]</c>. The
    /// aggregate section, <c>A</c>, is excluded because its compact form is its own aggregate value, not a SAID.
    /// </summary>
    public static IReadOnlyList<string> SaidableSectionFields { get; } =
        [Schema, Attribute, Edge, Rule];


    /// <summary>
    /// The set of reserved ACDC field labels, at the top level and nested.
    /// </summary>
    private static HashSet<string> Reserved { get; } = new(System.StringComparer.Ordinal)
    {
        Version, MessageType, Said, Uuid, Issuer, RegistryDigest, Schema, Attribute, AttributeAggregate, Edge,
        Rule, Datetime, Node, Operator, Weight, LegalLanguage
    };

    /// <summary>
    /// The set of top-level section fields, for membership tests.
    /// </summary>
    private static HashSet<string> Sections { get; } = new(System.StringComparer.Ordinal)
    {
        Schema, Attribute, AttributeAggregate, Edge, Rule
    };


    /// <summary>
    /// Whether a label is one of the reserved ACDC field labels.
    /// </summary>
    /// <param name="label">The field label to test.</param>
    /// <returns><see langword="true"/> when the label is reserved.</returns>
    public static bool IsReserved(string label)
    {
        ArgumentNullException.ThrowIfNull(label);

        return Reserved.Contains(label);
    }


    /// <summary>
    /// Whether a label is a top-level section field (<c>s</c>, <c>a</c>, <c>A</c>, <c>e</c>, or <c>r</c>).
    /// </summary>
    /// <param name="label">The field label to test.</param>
    /// <returns><see langword="true"/> when the label is a top-level section field.</returns>
    public static bool IsSection(string label)
    {
        ArgumentNullException.ThrowIfNull(label);

        return Sections.Contains(label);
    }
}

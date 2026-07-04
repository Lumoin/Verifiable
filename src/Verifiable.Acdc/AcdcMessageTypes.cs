using System.Collections.Generic;

namespace Verifiable.Acdc;

/// <summary>
/// The ACDC protocol message types (the three-character <c>t</c> field "ilk" values) and the classification that
/// decides how a stream consumer treats each: which are ACDC bodies, which are the section messages that carry an
/// ACDC's sections independently, and which are the transaction-event-log registry messages that hold an ACDC's
/// issuance and revocation state.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#message-type-table">
/// message type table</see>. An ACDC body is one of <c>acm</c> (a field map), <c>act</c> (fixed fields with an
/// attribute section), or <c>acg</c> (fixed fields with an aggregate section); <c>acm</c> is the default, so a
/// field-map message whose protocol is ACDC and that carries no <c>t</c> field is an <c>acm</c>. The section
/// messages (<c>sch</c>, <c>att</c>, <c>agg</c>, <c>edg</c>, <c>rul</c>) convey an ACDC's schema, attribute,
/// aggregate, edge, and rule sections as standalone packets, useful for caching or reusing a section across
/// ACDCs. The registry messages (<c>rip</c>, <c>upd</c>) incept and update the transaction event log that holds an
/// ACDC's dynamic state.
/// </para>
/// </remarks>
public static class AcdcMessageTypes
{
    /// <summary>ACDC field map <c>acm</c> ("ACdc field Map"): a top-level field map ACDC; the default ACDC message type.</summary>
    public static string Acdc { get; } = "acm";

    /// <summary>ACDC fixed-field attribute <c>act</c> ("ACdc fixed field with aTtribute section"): a top-level fixed-field ACDC carrying an attribute section.</summary>
    public static string AcdcFixedAttribute { get; } = "act";

    /// <summary>ACDC fixed-field aggregate <c>acg</c> ("ACdc fixed field with aGgregate section"): a top-level fixed-field ACDC carrying an aggregate section.</summary>
    public static string AcdcFixedAggregate { get; } = "acg";

    /// <summary>Schema section message <c>sch</c>: conveys an ACDC's schema section as a standalone packet.</summary>
    public static string SchemaSection { get; } = "sch";

    /// <summary>Attribute section message <c>att</c>: conveys an ACDC's attribute section as a standalone packet.</summary>
    public static string AttributeSection { get; } = "att";

    /// <summary>Aggregate section message <c>agg</c>: conveys an ACDC's aggregate attribute section as a standalone packet.</summary>
    public static string AggregateSection { get; } = "agg";

    /// <summary>Edge section message <c>edg</c>: conveys an ACDC's edge section as a standalone packet.</summary>
    public static string EdgeSection { get; } = "edg";

    /// <summary>Rule section message <c>rul</c>: conveys an ACDC's rule section as a standalone packet.</summary>
    public static string RuleSection { get; } = "rul";

    /// <summary>Registry inception <c>rip</c>: initializes the transaction event log registry that holds an ACDC's state.</summary>
    public static string RegistryInception { get; } = "rip";

    /// <summary>Registry update <c>upd</c>: updates the transaction state held in an ACDC's registry (non-blindable, public).</summary>
    public static string RegistryUpdate { get; } = "upd";

    /// <summary>Registry blindable update <c>bup</c>: updates the transaction state in a blinded (private) registry, committing to the state by a blinded attribute SAID.</summary>
    public static string RegistryBlindableUpdate { get; } = "bup";


    /// <summary>
    /// The ACDC body message types: the three types a top-level ACDC message may be.
    /// </summary>
    private static HashSet<string> AcdcBodies { get; } = new(System.StringComparer.Ordinal)
    {
        Acdc, AcdcFixedAttribute, AcdcFixedAggregate
    };

    /// <summary>
    /// The ACDC section message types: those that convey a single section of an ACDC as a standalone packet.
    /// </summary>
    private static HashSet<string> SectionMessages { get; } = new(System.StringComparer.Ordinal)
    {
        SchemaSection, AttributeSection, AggregateSection, EdgeSection, RuleSection
    };

    /// <summary>
    /// The transaction-event-log registry message types: those that incept or update an ACDC's state registry.
    /// </summary>
    private static HashSet<string> RegistryMessages { get; } = new(System.StringComparer.Ordinal)
    {
        RegistryInception, RegistryUpdate, RegistryBlindableUpdate
    };


    /// <summary>
    /// Whether a message type is an ACDC body (<c>acm</c>, <c>act</c>, or <c>acg</c>).
    /// </summary>
    /// <param name="messageType">The three-character message type value.</param>
    /// <returns><see langword="true"/> for <c>acm</c>, <c>act</c>, or <c>acg</c>.</returns>
    public static bool IsAcdc(string messageType)
    {
        ArgumentNullException.ThrowIfNull(messageType);

        return AcdcBodies.Contains(messageType);
    }


    /// <summary>
    /// Whether a message type is an ACDC section message (<c>sch</c>, <c>att</c>, <c>agg</c>, <c>edg</c>, or <c>rul</c>).
    /// </summary>
    /// <param name="messageType">The three-character message type value.</param>
    /// <returns><see langword="true"/> for a section message type.</returns>
    public static bool IsSectionMessage(string messageType)
    {
        ArgumentNullException.ThrowIfNull(messageType);

        return SectionMessages.Contains(messageType);
    }


    /// <summary>
    /// Whether a message type is a transaction-event-log registry message (<c>rip</c>, <c>upd</c>, or <c>bup</c>).
    /// </summary>
    /// <param name="messageType">The three-character message type value.</param>
    /// <returns><see langword="true"/> for <c>rip</c>, <c>upd</c>, or <c>bup</c>.</returns>
    public static bool IsRegistryMessage(string messageType)
    {
        ArgumentNullException.ThrowIfNull(messageType);

        return RegistryMessages.Contains(messageType);
    }
}

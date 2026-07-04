using System.Collections.Frozen;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// Reads a decoded ACDC field map into a typed <see cref="Acdc"/>. This is the serialization-agnostic half of ACDC
/// parsing: it works on a neutral field map, so it is identical whether the bytes were JSON, CBOR, MGPK, or
/// CESR-native — the bytes-to-field-map decode is a separate per-serialization seam. It validates the top-level
/// structure the specification fixes and produces each section as an <see cref="AcdcSection"/> that is either the
/// section's SAID (compact) or its expanded block.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#field-ordering">
/// field ordering</see> and <see href="https://trustoverip.github.io/kswg-acdc-specification/#required-fields">
/// required fields</see>: the top-level fields are optional except <c>[v, d, i, s]</c>, but every field that appears
/// MUST appear in the canonical order <see cref="AcdcMessageFields.TopLevelFieldOrder"/>, so the present fields must
/// form a subsequence of that order. The attribute, <c>a</c>, and aggregate, <c>A</c>, sections are mutually
/// exclusive. The reader handles the field-map body type, <c>acm</c> (the message type is optional in a field map
/// and implied when absent), and reads the aggregate section, <c>A</c>, into an <see cref="AcdcAggregateSection"/>
/// via <see cref="AcdcAggregateReader"/>; the fixed-field native types <c>act</c> and <c>acg</c> are read by another
/// path not yet present.
/// </para>
/// </remarks>
public static class AcdcReader
{
    /// <summary>
    /// The canonical position of each top-level field label, used to enforce that the present fields form a
    /// subsequence of the canonical order and to reject any unknown top-level field.
    /// </summary>
    private static FrozenDictionary<string, int> CanonicalIndex { get; } = BuildCanonicalIndex();


    /// <summary>
    /// Reads a decoded ACDC field map into a typed <see cref="Acdc"/>.
    /// </summary>
    /// <param name="fields">The decoded field map in serialization order (an order-preserving map, as every decode arm produces), keyed by <see cref="AcdcMessageFields"/>.</param>
    /// <returns>The typed ACDC message.</returns>
    /// <exception cref="AcdcException">A required field is missing, an unexpected top-level field appears, the fields are out of the canonical order, the attribute and aggregate sections are both present, the message type is not a field-map ACDC, or a section value is neither a SAID nor a block.</exception>
    public static AcdcMessage Read(MessageFieldMap fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        RequireCanonicalTopLevel(fields);
        RequireFieldMapAcdcType(fields);
        RequireAttributeAggregateExclusive(fields);
        RequireRequiredFields(fields);

        return new AcdcMessage(
            VersionString: RequireString(fields, AcdcMessageFields.Version),
            MessageType: ResolveMessageType(fields),
            Said: RequireString(fields, AcdcMessageFields.Said),
            Uuid: OptionalString(fields, AcdcMessageFields.Uuid),
            Issuer: RequireString(fields, AcdcMessageFields.Issuer),
            RegistryDigest: OptionalString(fields, AcdcMessageFields.RegistryDigest),
            Schema: RequireSection(fields, AcdcMessageFields.Schema),
            Attribute: OptionalSection(fields, AcdcMessageFields.Attribute),
            Aggregate: OptionalAggregate(fields),
            Edge: OptionalSection(fields, AcdcMessageFields.Edge),
            Rule: OptionalSection(fields, AcdcMessageFields.Rule));
    }


    //Every top-level field MUST be a known label and MUST appear in the canonical order: walking the present
    //fields in serialization order, each field's canonical position must be strictly greater than the previous,
    //which rejects both an unknown label and any field out of order in one pass.
    private static void RequireCanonicalTopLevel(MessageFieldMap fields)
    {
        int previous = -1;
        foreach(string label in fields.Keys)
        {
            if(!CanonicalIndex.TryGetValue(label, out int index))
            {
                throw new AcdcException($"ACDC carries an unexpected top-level field '{label}'; only the reserved top-level fields are allowed.");
            }

            if(index <= previous)
            {
                throw new AcdcException($"ACDC top-level field '{label}' is out of the canonical order; the top-level fields MUST appear in the order the specification fixes.");
            }

            previous = index;
        }
    }


    //A field-map ACDC body is message type acm, which is optional in a field map and implied when absent. The
    //fixed-field native types act and acg are read by another path, not here.
    private static void RequireFieldMapAcdcType(MessageFieldMap fields)
    {
        if(fields.TryGetString(AcdcMessageFields.MessageType, out string? messageType) && messageType != AcdcMessageTypes.Acdc)
        {
            throw new AcdcException($"ACDC field-map body must be message type '{AcdcMessageTypes.Acdc}', not '{messageType}'; the fixed-field types '{AcdcMessageTypes.AcdcFixedAttribute}' and '{AcdcMessageTypes.AcdcFixedAggregate}' are read by another path.");
        }
    }


    /// <summary>
    /// The attribute section <c>a</c> and the aggregate section <c>A</c> are mutually exclusive: an ACDC carries a
    /// partially disclosable attribute section or a selectively disclosable aggregate section, never both.
    /// </summary>
    /// <param name="fields">The decoded field map.</param>
    /// <exception cref="AcdcException">Both the attribute and aggregate sections are present.</exception>
    private static void RequireAttributeAggregateExclusive(MessageFieldMap fields)
    {
        if(fields.ContainsKey(AcdcMessageFields.Attribute) && fields.ContainsKey(AcdcMessageFields.AttributeAggregate))
        {
            throw new AcdcException("ACDC carries both the attribute section 'a' and the aggregate section 'A'; they are mutually exclusive.");
        }
    }


    private static void RequireRequiredFields(MessageFieldMap fields)
    {
        foreach(string required in AcdcMessageFields.RequiredFields)
        {
            if(!fields.ContainsKey(required))
            {
                throw new AcdcException($"ACDC is missing the required top-level field '{required}'.");
            }
        }
    }


    //The message type is acm whether present or implied by its absence in a field map.
    private static string ResolveMessageType(MessageFieldMap fields)
    {
        return fields.TryGetString(AcdcMessageFields.MessageType, out string? messageType) ? messageType : AcdcMessageTypes.Acdc;
    }


    private static string RequireString(MessageFieldMap fields, string label)
    {
        if(!fields.TryGetString(label, out string? text))
        {
            throw new AcdcException($"ACDC is missing the required string field '{label}'.");
        }

        return text;
    }


    private static string? OptionalString(MessageFieldMap fields, string label)
    {
        return fields.TryGetString(label, out string? text) ? text : null;
    }


    private static AcdcSection RequireSection(MessageFieldMap fields, string label)
    {
        if(!fields.TryGetValue(label, out object? value))
        {
            throw new AcdcException($"ACDC is missing the required section field '{label}'.");
        }

        return ReadSection(label, value);
    }


    private static AcdcSection? OptionalSection(MessageFieldMap fields, string label)
    {
        return fields.TryGetValue(label, out object? value) ? ReadSection(label, value) : null;
    }


    /// <summary>
    /// Reads the aggregate section <c>A</c> when present. Unlike the SAID-or-block sections read by
    /// <see cref="ReadSection"/>, its value is the compact AGID string or the blinded attribute list, so it is folded
    /// by <see cref="AcdcAggregateReader"/> into a typed <see cref="AcdcAggregateSection"/>.
    /// </summary>
    /// <param name="fields">The decoded field map.</param>
    /// <returns>The typed aggregate section, or <see langword="null"/> when the aggregate section is absent.</returns>
    /// <exception cref="AcdcException">The aggregate value is neither a string nor a list, or one of its blocks is malformed.</exception>
    private static AcdcAggregateSection? OptionalAggregate(MessageFieldMap fields)
    {
        return fields.TryGetValue(AcdcMessageFields.AttributeAggregate, out object? value) ? AcdcAggregateReader.Read(value) : null;
    }


    //A section value is either its SAID (compact) or its expanded detail block; any other shape is invalid.
    private static AcdcSection ReadSection(string label, object? value)
    {
        return value switch
        {
            string said => new CompactAcdcSection(said),
            MessageFieldMap detail => new ExpandedAcdcSection(detail),
            _ => throw new AcdcException($"ACDC section '{label}' is neither a SAID string nor a detail block.")
        };
    }


    private static FrozenDictionary<string, int> BuildCanonicalIndex()
    {
        var index = new Dictionary<string, int>(StringComparer.Ordinal);
        IReadOnlyList<string> order = AcdcMessageFields.TopLevelFieldOrder;
        for(int position = 0; position < order.Count; position++)
        {
            index[order[position]] = position;
        }

        return index.ToFrozenDictionary(StringComparer.Ordinal);
    }
}

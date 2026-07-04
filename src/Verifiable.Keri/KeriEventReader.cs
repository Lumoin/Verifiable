using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Verifiable.Cryptography;

namespace Verifiable.Keri;

/// <summary>
/// Reads a decoded KERI key event field map into a typed <see cref="KeriKeyEvent"/>. This is the
/// serialization-agnostic half of event parsing: it works on a neutral field map, so it is identical whether the
/// bytes were JSON, CBOR, MGPK, or CESR-native — the bytes-to-field-map decode is a separate per-serialization
/// seam, and proving MGPK conformance is a matter of feeding a real MessagePack decoder's field map through this
/// same reader.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's key event message bodies. The neutral field map keys are
/// <see cref="KeriMessageFields"/>; the value conventions a decoder MUST normalize to are: a scalar field is a
/// <see cref="string"/> (the sequence number <c>s</c> is its hexadecimal string, decoded here), and a list field
/// (<c>k</c>, <c>n</c>, <c>b</c>, <c>br</c>, <c>ba</c>, <c>c</c>) is an <see cref="IReadOnlyList{T}"/> of
/// <see cref="string"/>. The anchored seals (<c>a</c>) are the data plane and are not read here. The reader
/// rejects a field map that is missing a required field, carries an unexpected one, has a wrong-typed value, or
/// whose fields are not in the canonical order the message type defines — the field order is fixed and bears on
/// the SAID over the serialization. This requires the field map to enumerate its entries in serialization order,
/// which every decode arm produces (an order-preserving map).
/// </para>
/// </remarks>
public static class KeriEventReader
{
    /// <summary>
    /// Reads a decoded field map into the typed key event its message type (<c>t</c>) names.
    /// </summary>
    /// <param name="fields">The decoded field map in serialization order (an order-preserving map, as every decode arm produces), keyed by <see cref="KeriMessageFields"/>.</param>
    /// <returns>The typed key event.</returns>
    /// <exception cref="KeriException">A required field is missing, unexpected, wrong-typed, or out of the canonical order, the sequence number is not valid hexadecimal, or the message type is not a modeled key event.</exception>
    public static KeriKeyEvent Read(MessageFieldMap fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        string messageType = RequireString(fields, KeriMessageFields.MessageType);

        return messageType switch
        {
            var type when type == KeriMessageTypes.Inception => ReadInception(RequireExactFields(fields, KeriMessageFields.InceptionFieldOrder, type)),
            var type when type == KeriMessageTypes.Interaction => ReadInteraction(RequireExactFields(fields, KeriMessageFields.InteractionFieldOrder, type)),
            var type when type == KeriMessageTypes.Rotation => ReadRotation(RequireExactFields(fields, KeriMessageFields.RotationFieldOrder, type)),
            var type when type == KeriMessageTypes.DelegatedInception => ReadDelegatedInception(RequireExactFields(fields, KeriMessageFields.DelegatedInceptionFieldOrder, type)),
            var type when type == KeriMessageTypes.DelegatedRotation => ReadDelegatedRotation(RequireExactFields(fields, KeriMessageFields.DelegatedRotationFieldOrder, type)),
            _ => throw new KeriException($"KERI message type '{messageType}' is not a modeled key event (inception, interaction, rotation, delegated inception, or delegated rotation).")
        };
    }


    /// <summary>
    /// Enforces that a decoded field map carries exactly the top-level fields its message type defines, in the
    /// order it defines them — every required field present, no others, and in the canonical order. Each KERI
    /// event type's fields are exhaustive and ordered, and the specification forbids any other top-level field;
    /// the field order bears on the SAID over the serialization, so a reordered field map is rejected. This
    /// requires the field map to enumerate its entries in serialization order, which every decode arm produces.
    /// </summary>
    private static MessageFieldMap RequireExactFields(MessageFieldMap fields, IReadOnlyList<string> expectedFields, string messageType)
    {
        var expected = new HashSet<string>(expectedFields, StringComparer.Ordinal);
        foreach(string label in fields.Keys)
        {
            if(!expected.Contains(label))
            {
                throw new KeriException($"KERI '{messageType}' event carries an unexpected top-level field '{label}'; the event type's fields are exhaustive and no others are allowed.");
            }
        }

        foreach(string required in expectedFields)
        {
            if(!fields.ContainsKey(required))
            {
                throw new KeriException($"KERI '{messageType}' event is missing the required top-level field '{required}'.");
            }
        }

        if(!fields.Keys.SequenceEqual(expectedFields, StringComparer.Ordinal))
        {
            throw new KeriException($"KERI '{messageType}' event fields are not in the canonical order the message type defines; the field order is fixed and bears on the SAID over the serialization.");
        }

        return fields;
    }


    private static KeriInceptionEvent ReadInception(MessageFieldMap fields) => new(
        Said: RequireString(fields, KeriMessageFields.Said),
        Prefix: RequireString(fields, KeriMessageFields.Prefix),
        SequenceNumber: RequireSequenceNumber(fields),
        SigningThreshold: RequireThreshold(fields, KeriMessageFields.KeysSigningThreshold),
        SigningKeys: RequireStringList(fields, KeriMessageFields.SigningKeys),
        NextThreshold: RequireThreshold(fields, KeriMessageFields.NextKeysSigningThreshold),
        NextKeyDigests: RequireStringList(fields, KeriMessageFields.NextKeyDigests),
        BackerThreshold: RequireString(fields, KeriMessageFields.BackerThreshold),
        Backers: RequireStringList(fields, KeriMessageFields.Backers),
        ConfigurationTraits: RequireStringList(fields, KeriMessageFields.ConfigurationTraits));


    private static KeriInteractionEvent ReadInteraction(MessageFieldMap fields) => new(
        Said: RequireString(fields, KeriMessageFields.Said),
        Prefix: RequireString(fields, KeriMessageFields.Prefix),
        SequenceNumber: RequireSequenceNumber(fields),
        PriorSaid: RequireString(fields, KeriMessageFields.PriorSaid));


    private static KeriRotationEvent ReadRotation(MessageFieldMap fields) => new(
        Said: RequireString(fields, KeriMessageFields.Said),
        Prefix: RequireString(fields, KeriMessageFields.Prefix),
        SequenceNumber: RequireSequenceNumber(fields),
        PriorSaid: RequireString(fields, KeriMessageFields.PriorSaid),
        SigningThreshold: RequireThreshold(fields, KeriMessageFields.KeysSigningThreshold),
        SigningKeys: RequireStringList(fields, KeriMessageFields.SigningKeys),
        NextThreshold: RequireThreshold(fields, KeriMessageFields.NextKeysSigningThreshold),
        NextKeyDigests: RequireStringList(fields, KeriMessageFields.NextKeyDigests),
        BackerThreshold: RequireString(fields, KeriMessageFields.BackerThreshold),
        BackersToRemove: RequireStringList(fields, KeriMessageFields.BackersToRemove),
        BackersToAdd: RequireStringList(fields, KeriMessageFields.BackersToAdd),
        ConfigurationTraits: RequireStringList(fields, KeriMessageFields.ConfigurationTraits));


    private static KeriDelegatedInceptionEvent ReadDelegatedInception(MessageFieldMap fields) => new(
        Said: RequireString(fields, KeriMessageFields.Said),
        Prefix: RequireString(fields, KeriMessageFields.Prefix),
        SequenceNumber: RequireSequenceNumber(fields),
        SigningThreshold: RequireThreshold(fields, KeriMessageFields.KeysSigningThreshold),
        SigningKeys: RequireStringList(fields, KeriMessageFields.SigningKeys),
        NextThreshold: RequireThreshold(fields, KeriMessageFields.NextKeysSigningThreshold),
        NextKeyDigests: RequireStringList(fields, KeriMessageFields.NextKeyDigests),
        BackerThreshold: RequireString(fields, KeriMessageFields.BackerThreshold),
        Backers: RequireStringList(fields, KeriMessageFields.Backers),
        ConfigurationTraits: RequireStringList(fields, KeriMessageFields.ConfigurationTraits),
        DelegatorPrefix: RequireString(fields, KeriMessageFields.DelegatorPrefix));


    private static KeriDelegatedRotationEvent ReadDelegatedRotation(MessageFieldMap fields) => new(
        Said: RequireString(fields, KeriMessageFields.Said),
        Prefix: RequireString(fields, KeriMessageFields.Prefix),
        SequenceNumber: RequireSequenceNumber(fields),
        PriorSaid: RequireString(fields, KeriMessageFields.PriorSaid),
        SigningThreshold: RequireThreshold(fields, KeriMessageFields.KeysSigningThreshold),
        SigningKeys: RequireStringList(fields, KeriMessageFields.SigningKeys),
        NextThreshold: RequireThreshold(fields, KeriMessageFields.NextKeysSigningThreshold),
        NextKeyDigests: RequireStringList(fields, KeriMessageFields.NextKeyDigests),
        BackerThreshold: RequireString(fields, KeriMessageFields.BackerThreshold),
        BackersToRemove: RequireStringList(fields, KeriMessageFields.BackersToRemove),
        BackersToAdd: RequireStringList(fields, KeriMessageFields.BackersToAdd),
        ConfigurationTraits: RequireStringList(fields, KeriMessageFields.ConfigurationTraits));


    private static string RequireString(MessageFieldMap fields, string label)
    {
        if(!fields.TryGetString(label, out string? text))
        {
            throw new KeriException($"KERI event is missing the required string field '{label}'.");
        }

        return text;
    }


    private static IReadOnlyList<string> RequireStringList(MessageFieldMap fields, string label)
    {
        if(!fields.TryGetStringList(label, out IReadOnlyList<string>? list))
        {
            throw new KeriException($"KERI event is missing the required string-list field '{label}'.");
        }

        return list;
    }


    private static KeriThreshold RequireThreshold(MessageFieldMap fields, string label)
    {
        if(!fields.TryGetValue(label, out object? value) || value is null)
        {
            throw new KeriException($"KERI event is missing the required signing threshold field '{label}'.");
        }

        return KeriThreshold.Parse(value);
    }


    private static long RequireSequenceNumber(MessageFieldMap fields)
    {
        string text = RequireString(fields, KeriMessageFields.SequenceNumber);
        if(!long.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long sequenceNumber) || sequenceNumber < 0)
        {
            throw new KeriException($"KERI event has an invalid hexadecimal sequence number '{text}'.");
        }

        return sequenceNumber;
    }
}

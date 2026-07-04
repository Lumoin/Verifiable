using System.Collections.Generic;
using System.Globalization;

namespace Verifiable.Keri;

/// <summary>
/// Reads a decoded KERI seal field map into a typed <see cref="KeriSeal"/>, and an event's anchor list (field
/// <c>a</c>) into typed seals. This is the serialization-agnostic half of seal parsing: it works on the neutral
/// field map a per-serialization decoder produces, so it is identical whether the bytes were JSON, CBOR, MGPK, or
/// CESR-native — exactly as <see cref="KeriEventReader"/> reads the key event itself.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#seals">
/// seals</see>. The seal type is identified by the exact set of labels (<see cref="KeriSealFields"/>) a seal
/// carries — the seven seal types have pairwise distinct field sets — and a seal whose shape matches none of them
/// is rejected. The wire field order (which bears on a SAID over the serialization) is not verified here because
/// the decoded map is unordered; this reader extracts the typed fields and rejects a missing or wrong-typed one.
/// A decoder normalizes a seal to a string-keyed map whose scalar values are strings (the sequence number <c>s</c>
/// is its hexadecimal string, decoded here); the anchor list is a sequence of such maps.
/// </para>
/// </remarks>
public static class KeriSealReader
{
    /// <summary>
    /// Reads an event's anchor list value (field <c>a</c>) into typed seals.
    /// </summary>
    /// <param name="anchors">The decoded anchor list: a sequence of seal field maps, as a decoder produces it.</param>
    /// <returns>The typed seals, in list order.</returns>
    /// <exception cref="KeriException">The value is not a list, an element is not a seal field map, or a seal shape is not recognized.</exception>
    public static IReadOnlyList<KeriSeal> ReadList(object? anchors)
    {
        if(anchors is not IEnumerable<object?> items)
        {
            throw new KeriException("A KERI anchor list (field 'a') must be a list of seals.");
        }

        var seals = new List<KeriSeal>();
        foreach(object? item in items)
        {
            if(item is not IReadOnlyDictionary<string, object?> seal)
            {
                throw new KeriException("A KERI anchor list element must be a seal field map.");
            }

            seals.Add(Read(seal));
        }

        return seals;
    }


    /// <summary>
    /// Reads a single decoded seal field map into the typed seal its field set identifies.
    /// </summary>
    /// <param name="seal">The decoded seal field map, keyed by <see cref="KeriSealFields"/>.</param>
    /// <returns>The typed seal.</returns>
    /// <exception cref="KeriException">A field is missing or wrong-typed, the sequence number is not valid hexadecimal, or the field set matches no seal type.</exception>
    public static KeriSeal Read(IReadOnlyDictionary<string, object?> seal)
    {
        ArgumentNullException.ThrowIfNull(seal);

        bool hasMerkleRoot = seal.ContainsKey(KeriSealFields.MerkleRootDigest);
        bool hasDigest = seal.ContainsKey(KeriSealFields.Digest);
        bool hasSequenceNumber = seal.ContainsKey(KeriSealFields.SequenceNumber);
        bool hasPrefix = seal.ContainsKey(KeriSealFields.Prefix);
        bool hasBackerIdentifier = seal.ContainsKey(KeriSealFields.BackerIdentifier);
        bool hasSealType = seal.ContainsKey(KeriSealFields.SealType);
        int count = seal.Count;

        //Each seal type is identified by its exact field set; the sets are pairwise distinct, so the first match is
        //unambiguous, and a shape matching none is rejected rather than silently accepted.
        if(hasMerkleRoot && count == 1)
        {
            return new KeriMerkleRootSeal(RequireString(seal, KeriSealFields.MerkleRootDigest));
        }

        if(hasSealType && hasDigest && count == 2)
        {
            return new KeriTypedSeal(RequireString(seal, KeriSealFields.SealType), RequireString(seal, KeriSealFields.Digest));
        }

        if(hasBackerIdentifier && hasDigest && count == 2)
        {
            return new KeriRegistrarBackerSeal(RequireString(seal, KeriSealFields.BackerIdentifier), RequireString(seal, KeriSealFields.Digest));
        }

        if(hasPrefix && hasSequenceNumber && hasDigest && count == 3)
        {
            return new KeriKeyEventSeal(RequireString(seal, KeriSealFields.Prefix), RequireSequenceNumber(seal), RequireString(seal, KeriSealFields.Digest));
        }

        if(hasPrefix && count == 1)
        {
            return new KeriLatestEstablishmentEventSeal(RequireString(seal, KeriSealFields.Prefix));
        }

        if(hasSequenceNumber && hasDigest && count == 2)
        {
            return new KeriSourceEventSeal(RequireSequenceNumber(seal), RequireString(seal, KeriSealFields.Digest));
        }

        if(hasDigest && count == 1)
        {
            return new KeriDigestSeal(RequireString(seal, KeriSealFields.Digest));
        }

        throw new KeriException("A KERI seal field map does not match any known seal type.");
    }


    private static string RequireString(IReadOnlyDictionary<string, object?> seal, string label)
    {
        if(!seal.TryGetValue(label, out object? value) || value is not string text)
        {
            throw new KeriException($"KERI seal is missing the required string field '{label}'.");
        }

        return text;
    }


    private static long RequireSequenceNumber(IReadOnlyDictionary<string, object?> seal)
    {
        string text = RequireString(seal, KeriSealFields.SequenceNumber);
        if(!long.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long sequenceNumber) || sequenceNumber < 0)
        {
            throw new KeriException($"KERI seal has an invalid hexadecimal sequence number '{text}'.");
        }

        return sequenceNumber;
    }
}

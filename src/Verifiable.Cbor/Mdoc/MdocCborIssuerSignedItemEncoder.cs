using System.Buffers;
using Lumoin.Veritas.Cbor;
using Verifiable.Core.Model.Mdoc;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Encodes one <see cref="MdocIssuerSignedItem"/> into its on-wire CBOR
/// Tag 24 wrapper per ISO/IEC 18013-5 §9.1.2.4 — the byte form the issuer
/// hashes into the MSO <c>valueDigests</c> map and the wallet hashes back
/// to validate the digest binding.
/// </summary>
/// <remarks>
/// <para>
/// The inner map carries the four required keys
/// (<see cref="MdocWellKnownKeys.DigestId"/>,
/// <see cref="MdocWellKnownKeys.Random"/>,
/// <see cref="MdocWellKnownKeys.ElementIdentifier"/>,
/// <see cref="MdocWellKnownKeys.ElementValue"/>), and is then wrapped in
/// CBOR Tag 24 via <see cref="EncodedCborItem.Wrap"/>. The wrapper uses
/// canonical-form conformance mode so the bytes are deterministic — every
/// caller hashing the same parsed item produces the same digest commitment.
/// </para>
/// <para>
/// The element value is passed through verbatim: it is already a single
/// CBOR data item produced by the caller, so the writer copies its bytes
/// without re-encoding. Re-encoding would change the bytes the MSO commits
/// to.
/// </para>
/// </remarks>
public static class MdocCborIssuerSignedItemEncoder
{
    /// <summary>
    /// Encodes <paramref name="item"/> into its Tag 24 wire bytes.
    /// </summary>
    /// <param name="item">The logical item to encode.</param>
    /// <returns>
    /// The Tag 24 wrapper bytes (<c>0xD8 0x18 &lt;bstr-header&gt; &lt;inner&gt;</c>) ready
    /// to store as <see cref="MdocIssuerSignedItem.WireBytes"/> and to feed
    /// into the MSO digest computation.
    /// </returns>
    public static ReadOnlyMemory<byte> Encode(MdocLogicalIssuerSignedItem item)
    {
        ArgumentNullException.ThrowIfNull(item);

        ReadOnlyMemory<byte> innerBytes = EncodeInnerMap(item);
        EncodedCborItem wrapped = EncodedCborItem.Wrap(innerBytes.Span);

        return wrapped.WireBytes;
    }


    /// <summary>
    /// Encodes the inner four-field map of a logical
    /// <see cref="MdocLogicalIssuerSignedItem"/> without the Tag 24 wrapper.
    /// Exposed for the rare consumer that owns its own wrapping path (e.g.
    /// composing a deterministic digest input across a non-CBOR transport).
    /// </summary>
    public static ReadOnlyMemory<byte> EncodeInnerMap(MdocLogicalIssuerSignedItem item)
    {
        ArgumentNullException.ThrowIfNull(item);

        //ISO/IEC 18013-5 §9.1.2.4 lists the fields without prescribing map
        //order. RFC 8949 §4.2.1 sorts map keys by encoded length first, then
        //bytewise; the four text-string key lengths are 6 = random,
        //12 = elementValue, 8 = digestID, 17 = elementIdentifier, so the
        //canonical order is random < elementValue < digestID <
        //elementIdentifier regardless of the order they are written here —
        //the writer under RfcCanonical sorts every map on WriteEndMap.
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);

        writer.WriteStartMap(4);

        writer.WriteTextString(MdocWellKnownKeys.DigestId);
        writer.WriteUInt32(item.DigestId);

        writer.WriteTextString(MdocWellKnownKeys.Random);
        writer.WriteByteString(item.Random.AsReadOnlySpan());

        writer.WriteTextString(MdocWellKnownKeys.ElementIdentifier);
        writer.WriteTextString(item.ElementIdentifier);

        writer.WriteTextString(MdocWellKnownKeys.ElementValue);
        writer.WriteEncodedValue(item.EncodedElementValue.Span);

        writer.WriteEndMap();

        return buffer.WrittenSpan.ToArray();
    }
}

using System;
using System.Diagnostics;
using System.Formats.Cbor;

namespace Verifiable.Cbor;

/// <summary>
/// A CBOR value wrapped in Tag 24 (<c>#6.24(bstr .cbor)</c>) per
/// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.5.1">RFC 8949 §3.4.5.1</see>,
/// preserving the exact wire bytes the producer wrote.
/// </summary>
/// <remarks>
/// <para>
/// Tag 24 marks a byte string whose contents are an "encoded CBOR data item" —
/// a deferred-parsing wrapper that pins the producer's encoding choices
/// (length-prefix size, map ordering, indefinite-length usage) so downstream
/// digest commitments remain valid across decode → re-encode round-trips.
/// </para>
/// <para>
/// The <see cref="WireBytes"/> span is the full Tag 24 wrapper as it appeared
/// on the wire: <c>0xD8 0x18 &lt;byte-string-header&gt; &lt;inner-bytes&gt;</c>.
/// Consumers that compute digests over the wrapper (ISO/IEC 18013-5 §9.1.2.5
/// IssuerSignedItem digest binding, COSE_Sign1 detached-payload computation
/// over the MSO, DeviceAuth over SessionTranscript) hash <see cref="WireBytes"/>.
/// <see cref="InnerBytes"/> is a slice of <see cref="WireBytes"/> at the byte-
/// string contents offset and gives consumers that need the parsed shape
/// (claim name, element value, MSO field, …) the inner CBOR to decode.
/// </para>
/// <para>
/// The two construction paths have different byte-faithfulness properties:
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="Read"/> reads a wire-form Tag 24 wrapper and snapshots
///       its bytes verbatim. The producer's encoding choices survive intact —
///       this is the wallet-side path for verifying issuer-supplied digests.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="Wrap"/> constructs a Tag 24 wrapper around already-encoded
///       inner bytes by emitting the Tag 24 + byte-string header in
///       <see cref="CborConformanceMode.Canonical"/> form. This is the
///       issuer-side path that commits to a canonical wrapper encoding;
///       different conformance modes would produce different wire bytes, so
///       the issuer's choice is part of the published-digest contract.
///     </description>
///   </item>
/// </list>
/// </para>
/// <para>
/// SD-CWT's own claim-redaction machinery (<c>SdCwtClaimRedaction</c>) does
/// not use Tag 24 — its disclosures are bare CBOR arrays under
/// <see cref="CborConformanceMode.Canonical"/>, relying on canonical-form
/// determinism rather than byte preservation. This wrapper is independent
/// of that machinery and intentionally does NOT canonicalise on
/// <see cref="Read"/>; the byte-preservation contract is mdoc-driven.
/// </para>
/// </remarks>
[DebuggerDisplay("EncodedCborItem WireBytes={WireBytes.Length} InnerBytes={InnerBytes.Length}")]
public readonly struct EncodedCborItem: IEquatable<EncodedCborItem>
{
    /// <summary>The CBOR tag number for "Encoded CBOR data item" per RFC 8949 §3.4.5.1.</summary>
    public const ulong TagNumber = 24;

    private const CborTag Tag24 = (CborTag)24;


    /// <summary>
    /// The full wire bytes of the Tag 24 wrapper: <c>0xD8 0x18</c> + byte-string
    /// header + inner CBOR. The digest input for mdoc IssuerSignedItem binding.
    /// </summary>
    public ReadOnlyMemory<byte> WireBytes { get; }

    /// <summary>
    /// The inner CBOR-encoded payload — a slice of <see cref="WireBytes"/>
    /// starting at the byte-string contents offset. Decode this to get the
    /// typed shape the wrapper carries (e.g., an IssuerSignedItem map).
    /// </summary>
    public ReadOnlyMemory<byte> InnerBytes { get; }


    private EncodedCborItem(ReadOnlyMemory<byte> wireBytes, ReadOnlyMemory<byte> innerBytes)
    {
        WireBytes = wireBytes;
        InnerBytes = innerBytes;
    }


    /// <summary>
    /// Reads a Tag 24 wrapper from <paramref name="reader"/> at its current
    /// position, preserving the wrapper's wire bytes verbatim. The reader
    /// advances past the wrapper on return.
    /// </summary>
    /// <exception cref="CborContentException">
    /// Thrown when the value at the reader's current position is not a Tag 24
    /// wrapper over a byte string.
    /// </exception>
    public static EncodedCborItem Read(CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

        //ReadEncodedValue returns the bytes of the current item including any
        //tags. For Tag 24 this gives us the full 0xD8 0x18 + bstr-header +
        //inner sequence verbatim.
        ReadOnlyMemory<byte> wireBytes = reader.ReadEncodedValue();

        //Probe-reader pass to validate the shape and find the inner offset.
        //We never feed the probe-reader output back to the caller; only
        //wireBytes (verbatim) and a slice of it.
        var probe = new CborReader(wireBytes);
        if(probe.PeekState() != CborReaderState.Tag)
        {
            throw new CborContentException(
                "Expected a CBOR Tag 24 (encoded CBOR data item) wrapper, but the " +
                "value at the reader's position is not tagged.");
        }

        CborTag tag = probe.ReadTag();
        if(tag != Tag24)
        {
            throw new CborContentException(
                $"Expected CBOR Tag 24 (encoded CBOR data item) but got tag {(ulong)tag}.");
        }

        if(probe.PeekState() != CborReaderState.ByteString)
        {
            throw new CborContentException(
                "Tag 24 wrapper must contain a byte string per RFC 8949 §3.4.5.1.");
        }

        //ReadByteString returns the byte string contents as a byte[]. The
        //contents are at the END of wireBytes (since Tag 24 wraps a single
        //byte string and nothing else follows in this item's wire form).
        //Slice wireBytes from (length - contents.Length) to give InnerBytes
        //as a view rather than a copy.
        byte[] contents = probe.ReadByteString();
        int innerOffset = wireBytes.Length - contents.Length;
        ReadOnlyMemory<byte> innerBytes = wireBytes.Slice(innerOffset, contents.Length);

        return new EncodedCborItem(wireBytes, innerBytes);
    }


    /// <summary>
    /// Wraps already-encoded inner CBOR bytes in a Tag 24 wrapper using
    /// canonical-form encoding of the Tag 24 + byte-string header. Used on
    /// the issuer side; the resulting <see cref="WireBytes"/> is what the
    /// issuer publishes a digest commitment over.
    /// </summary>
    /// <param name="innerBytes">
    /// The already-encoded CBOR bytes to wrap. The bytes are stored verbatim;
    /// no re-encoding or canonicalisation is applied to the inner payload.
    /// </param>
    public static EncodedCborItem Wrap(ReadOnlySpan<byte> innerBytes)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag(Tag24);
        writer.WriteByteString(innerBytes);
        byte[] wireBytes = writer.Encode();

        int innerOffset = wireBytes.Length - innerBytes.Length;
        ReadOnlyMemory<byte> innerSlice = new(wireBytes, innerOffset, innerBytes.Length);

        return new EncodedCborItem(wireBytes, innerSlice);
    }


    /// <summary>
    /// Writes the wrapper to <paramref name="writer"/> using the verbatim
    /// <see cref="WireBytes"/>. Round-trip-faithful: a wrapper read via
    /// <see cref="Read"/> and written via <see cref="Write"/> produces byte-
    /// identical output to its input.
    /// </summary>
    public void Write(CborWriter writer)
    {
        ArgumentNullException.ThrowIfNull(writer);

        writer.WriteEncodedValue(WireBytes.Span);
    }


    /// <inheritdoc/>
    public bool Equals(EncodedCborItem other) =>
        WireBytes.Span.SequenceEqual(other.WireBytes.Span);


    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is EncodedCborItem other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        //Hash a bounded prefix of WireBytes to keep GetHashCode cheap on
        //large mdoc claims; full-span comparison still happens in Equals.
        ReadOnlySpan<byte> span = WireBytes.Span;
        int prefix = Math.Min(span.Length, 16);

        HashCode hash = new();
        hash.Add(WireBytes.Length);
        for(int i = 0; i < prefix; i++)
        {
            hash.Add(span[i]);
        }

        return hash.ToHashCode();
    }


    /// <summary>Determines whether two encoded items have byte-identical wire bytes.</summary>
    public static bool operator ==(EncodedCborItem left, EncodedCborItem right) => left.Equals(right);


    /// <summary>Determines whether two encoded items have differing wire bytes.</summary>
    public static bool operator !=(EncodedCborItem left, EncodedCborItem right) => !left.Equals(right);
}

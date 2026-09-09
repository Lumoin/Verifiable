using System;
using System.Buffers;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Pins the pooled output model contract ruling S4-5 settles on: a <see cref="CborWriter"/> streaming into a
/// pooled <see cref="SlabBufferWriter"/>, whose <see cref="SlabBufferWriter.Detach"/> hands back exactly the
/// bytes written as one pool-rented carrier. This replaced a writer-owned buffer snapshot, so the properties
/// the old snapshot gave for free — exact length, a complete document, no leaked rental — are the ones that
/// must now be proven.
/// </summary>
/// <remarks>
/// Every case here writes a document that outgrows a single 4096-octet slab, because a single-slab document
/// cannot distinguish a correct multi-slab assembly from one that returns only the first slab. The pool is
/// injected explicitly through <see cref="MeteredHousePool"/> — the house pool itself, with its own rent and
/// return counters read back — so the accounting is the pool's own telemetry rather than a test wrapper's.
/// </remarks>
[TestClass]
internal sealed class SlabBufferWriterCborTests
{
    /// <summary>The payload length in octets, chosen to span three of the writer's 4096-octet slabs.</summary>
    private const int PayloadLength = 10_000;

    /// <summary>
    /// The complete wire length of a definite-length byte string carrying <see cref="PayloadLength"/> octets:
    /// three header octets plus the payload. Derived in
    /// <see cref="TheDetachedCarrierHoldsExactlyTheBytesWrittenBeforeDetach"/>.
    /// </summary>
    private const int DocumentLength = 3 + PayloadLength;


    /// <summary>
    /// Builds the test payload: <see cref="PayloadLength"/> octets of a fixed, position-dependent pattern, so
    /// a slab boundary that dropped or duplicated a run shows up as a value mismatch rather than only as a
    /// length mismatch.
    /// </summary>
    /// <returns>The payload octets.</returns>
    private static byte[] CreatePayload()
    {
        byte[] payload = new byte[PayloadLength];
        for(int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(i % 251);
        }

        return payload;
    }


    /// <summary>
    /// A CBOR document larger than one slab, written through a pooled <see cref="SlabBufferWriter"/> and
    /// handed over by <see cref="SlabBufferWriter.Detach"/>, is read back byte-for-byte by a
    /// <see cref="CborReader"/> over the detached carrier.
    /// </summary>
    /// <remarks>
    /// The document is a definite-length byte string of 10 000 octets. Under
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> that is major type 2
    /// (<c>0b010</c> in the initial byte's high three bits) with the length as the argument, and under
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> the deterministic
    /// encoding takes the shortest argument that expresses it: 10 000 exceeds 255 and fits in two octets, so
    /// additional information 25 (a two-octet argument) is the minimal choice. Hence <c>0x59 0x27 0x10</c>
    /// (0x2710 = 10 000), then the payload — 10 003 octets in all, spanning three 4096-octet slabs. The reader
    /// runs over the detached carrier, not over the slabs, which is the property under test: the carrier is one
    /// contiguous, complete document.
    /// </remarks>
    [TestMethod]
    public void AMultiSlabDocumentRoundTripsThroughTheDetachedCarrier()
    {
        byte[] payload = CreatePayload();

        using MeteredHousePool metered = new();
        using SlabBufferWriter buffer = new(metered.Pool);
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteByteString(payload);

        using IMemoryOwner<byte> encoded = buffer.Detach();

        Assert.AreEqual((byte)0x59, encoded.Memory.Span[0], "RFC 8949 §3.1 major type 2 with additional information 25 is the initial byte 0x59.");
        Assert.AreEqual((byte)0x27, encoded.Memory.Span[1], "The high octet of the minimal two-octet argument 0x2710 = 10 000.");
        Assert.AreEqual((byte)0x10, encoded.Memory.Span[2], "The low octet of the minimal two-octet argument 0x2710 = 10 000.");

        var reader = new CborReader(encoded.Memory, CborOptions.RfcCanonical, metered.Pool);
        byte[] decoded = reader.ReadByteString();

        Assert.AreSequenceEqual(payload, decoded, "Every slab the writer filled must reach the detached carrier, in order and without duplication.");
        Assert.AreEqual(0, reader.BytesRemaining, "The detached carrier must hold the document and nothing else.");
    }


    /// <summary>
    /// The carrier <see cref="SlabBufferWriter.Detach"/> returns is exactly as long as the writer had
    /// reported through <see cref="SlabBufferWriter.BytesWritten"/> immediately before the call — not as long
    /// as the slabs it was assembled from.
    /// </summary>
    /// <remarks>
    /// This is the property the retired writer-owned snapshot supplied implicitly and that ruling S4-5 now
    /// requires of the pooled shape: the bytes that leave equal the bytes that went in. Three 4096-octet slabs
    /// hold 12 288 octets, so a carrier sized to its slabs rather than to its content would be 12 288 long and
    /// would carry 2 285 octets of slack past the document — trailing bytes any downstream reader would then
    /// have to guess at. The expected length is derived from the wire form, not read back from the writer:
    /// a definite-length byte string of 10 000 octets is three header octets
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see>, major type 2,
    /// minimal two-octet argument per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>) plus 10 000
    /// payload octets = 10 003.
    /// </remarks>
    [TestMethod]
    public void TheDetachedCarrierHoldsExactlyTheBytesWrittenBeforeDetach()
    {
        byte[] payload = CreatePayload();

        using MeteredHousePool metered = new();
        using SlabBufferWriter buffer = new(metered.Pool);
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteByteString(payload);

        int bytesWrittenBeforeDetach = buffer.BytesWritten;

        Assert.AreEqual(DocumentLength, bytesWrittenBeforeDetach, "A 10 000-octet byte string is 3 header octets plus 10 000 payload octets on the wire.");

        using IMemoryOwner<byte> encoded = buffer.Detach();
        int carrierLength = encoded.Memory.Length;

        Assert.AreEqual(bytesWrittenBeforeDetach, carrierLength, "The detached carrier must be trimmed to the document, never left at its slab capacity.");
    }


    /// <summary>
    /// <see cref="SlabBufferWriter.Detach"/> transfers the content out: the writer reports zero bytes written
    /// afterwards, so the count must be captured before the call, never after it.
    /// </summary>
    /// <remarks>
    /// Pinned deliberately, because reading <see cref="SlabBufferWriter.BytesWritten"/> after
    /// <see cref="SlabBufferWriter.Detach"/> is the natural-looking mistake at every migrated call site: it
    /// reads zero, and a caller that used it as a length would emit an empty document while the real bytes sat
    /// in a carrier it then discarded. Ruling S4-5's shape captures the count first for exactly this reason.
    /// </remarks>
    [TestMethod]
    public void DetachResetsTheWrittenCountToZero()
    {
        byte[] payload = CreatePayload();

        using MeteredHousePool metered = new();
        using SlabBufferWriter buffer = new(metered.Pool);
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteByteString(payload);

        Assert.AreEqual(DocumentLength, buffer.BytesWritten, "The precondition: the writer holds the whole document before the transfer.");

        using IMemoryOwner<byte> encoded = buffer.Detach();

        int carrierLength = encoded.Memory.Length;

        Assert.AreEqual(0, buffer.BytesWritten, "Detach transfers ownership out; the count it leaves behind is zero, not the document length.");
        Assert.AreEqual(DocumentLength, carrierLength, "The document is in the carrier, which is where the length must be read from after a Detach.");
    }


    /// <summary>
    /// Writing a multi-slab document, detaching it and disposing both the carrier and the writer returns every
    /// rented carrier to the pool.
    /// </summary>
    /// <remarks>
    /// The pooled output model of ruling S4-5 rents more than one buffer for a document this size — each slab,
    /// plus the exact-length carrier the transfer produces — and none of those rentals is visible to the call
    /// site, which sees only a <c>using</c> on the writer and one on the carrier. The balance is therefore the
    /// only evidence that those two disposals are sufficient. The rent assertion guards the balance assertion
    /// from being vacuous, and the multi-slab lower bound guards against a document that never crossed a slab
    /// boundary in the first place.
    /// </remarks>
    [TestMethod]
    public void EveryCarrierRentedForAMultiSlabDocumentIsReturnedOnDisposal()
    {
        byte[] payload = CreatePayload();

        using MeteredHousePool metered = new();
        using(SlabBufferWriter buffer = new(metered.Pool))
        {
            var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
            writer.WriteByteString(payload);

            using IMemoryOwner<byte> encoded = buffer.Detach();
            int carrierLength = encoded.Memory.Length;

            Assert.AreEqual(DocumentLength, carrierLength, "The precondition: the whole multi-slab document was assembled.");
        }

        Assert.IsGreaterThan(1, metered.RentedCount, "A 10 003-octet document must outgrow one 4096-octet slab, or the balance below proves nothing about assembly.");
        Assert.AreEqual(0, metered.OutstandingCount, "Disposing the writer and the detached carrier must return every slab and every transfer buffer.");
    }


    /// <summary>
    /// After <see cref="SlabBufferWriter.Reset"/> the same writer serves a second document exactly as it
    /// served the first: the new document is complete and correctly sized, with no residue of the first.
    /// </summary>
    /// <remarks>
    /// The reuse case matters because ruling S4-5 puts the buffer, not the CBOR writer, in charge of the
    /// bytes: a call site that encodes repeatedly holds one buffer and resets it between documents. The second
    /// document here is a different length from the first — a byte string of 9 000 octets, whose minimal
    /// definite-length header is <c>0x59 0x23 0x28</c> (0x2328 = 9 000) by the same
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> derivation as the
    /// first, for 9 003 octets in all — so a reset that left the first document's length or content behind
    /// cannot pass by coincidence, and it still spans more than one slab.
    /// </remarks>
    [TestMethod]
    public void ASecondDocumentAfterResetCarriesNoResidueOfTheFirst()
    {
        byte[] firstPayload = CreatePayload();
        byte[] secondPayload = new byte[9_000];
        for(int i = 0; i < secondPayload.Length; i++)
        {
            secondPayload[i] = (byte)(255 - (i % 251));
        }

        using MeteredHousePool metered = new();
        using SlabBufferWriter buffer = new(metered.Pool);

        var firstWriter = new CborWriter(buffer, CborOptions.RfcCanonical);
        firstWriter.WriteByteString(firstPayload);
        using(IMemoryOwner<byte> firstEncoded = buffer.Detach())
        {
            int firstCarrierLength = firstEncoded.Memory.Length;

            Assert.AreEqual(DocumentLength, firstCarrierLength, "The precondition: the first document was assembled whole.");
        }

        buffer.Reset();

        var secondWriter = new CborWriter(buffer, CborOptions.RfcCanonical);
        secondWriter.WriteByteString(secondPayload);
        int secondBytesWritten = buffer.BytesWritten;

        Assert.AreEqual(3 + secondPayload.Length, secondBytesWritten, "The second document is its own 3 header octets plus 9 000 payload octets, with nothing carried over.");

        using IMemoryOwner<byte> secondEncoded = buffer.Detach();
        int secondCarrierLength = secondEncoded.Memory.Length;

        Assert.AreEqual(secondBytesWritten, secondCarrierLength, "The reused writer must trim to the second document exactly as it did to the first.");
        Assert.AreEqual((byte)0x59, secondEncoded.Memory.Span[0], "RFC 8949 §3.1 major type 2 with the minimal two-octet argument.");
        Assert.AreEqual((byte)0x23, secondEncoded.Memory.Span[1], "The high octet of the minimal argument 0x2328 = 9 000.");
        Assert.AreEqual((byte)0x28, secondEncoded.Memory.Span[2], "The low octet of the minimal argument 0x2328 = 9 000.");

        var reader = new CborReader(secondEncoded.Memory, CborOptions.RfcCanonical, metered.Pool);
        byte[] decoded = reader.ReadByteString();

        Assert.AreSequenceEqual(secondPayload, decoded, "The second document must decode to the second payload, not to a splice of the two.");
        Assert.AreEqual(0, reader.BytesRemaining, "A reset that left slab residue behind would show as trailing bytes here.");
    }
}

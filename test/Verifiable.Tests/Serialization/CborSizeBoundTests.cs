using System;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Pins the two independent bounds a CBOR reader places on a declared length before it commits any work to
/// it: the wire bound — a declared count cannot stand for more data than the document actually carries — and
/// the policy bound — a declared count cannot exceed the ceiling the caller configured. Both are refusals at
/// the header, before a single element is read, which is what keeps a small hostile document from turning
/// into a large allocation.
/// </summary>
/// <remarks>
/// <para>
/// The wire bound is fixed-list item V6 of the ratified Veritas fix list, and it is the one that needs no
/// configuration to hold: a document of a few dozen octets that declares a million elements is
/// self-inconsistent by <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>'s own
/// arithmetic, since every data item occupies at least one octet. Such a document is malformed rather than
/// merely oversized, so it is refused as <see cref="CborContentException"/>.
/// </para>
/// <para>
/// The policy bound is the configured ceiling, and its refusal carries the cap that fired, the value that
/// exceeded it and the configured limit, so an operator can tell a legitimately large document from an attack
/// — the refusal is <see cref="CborSizeLimitExceededException"/>. The two are ordered: the ceiling is
/// consulted first, so a document that trips both is reported as the policy refusal, which is the actionable
/// one.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CborSizeBoundTests
{
    /// <summary>
    /// Builds an options instance whose ceilings are tight enough that a hand-typed document of a few octets
    /// can cross them, so the policy bound can be proven on documents small enough to derive by hand.
    /// </summary>
    /// <remarks>
    /// A fresh instance, never a shared <see cref="CborOptions"/> preset: the presets are process-wide shared
    /// state whose ceilings no test may move (contract ruling S4-3), and a call site needing its own ceilings
    /// builds its own instance exactly as this does.
    /// </remarks>
    /// <returns>Options in <see cref="CborConformanceMode.Strict"/> with four tightened ceilings.</returns>
    private static CborSerializerOptions CreateTightlyCappedOptions()
    {
        CborSerializerOptions options = CborSerializerOptions.Default(CborConformanceMode.Strict);
        options.MaxArrayLength = 4;
        options.MaxMapEntryCount = 2;
        options.MaxByteStringLength = 4;
        options.MaxDepth = 2;

        return options;
    }


    /// <summary>
    /// An array header declaring a million items in a ten-octet document is refused at the header as
    /// malformed content, before any item is read.
    /// </summary>
    /// <remarks>
    /// Derivation. <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see> puts the
    /// major type in the initial byte's high three bits and the argument in its low five: an array is major
    /// type 4, so the initial byte's high bits are <c>0b100</c> (0x80), and additional information 26 (0x1A)
    /// introduces a four-octet argument, giving <c>0x9A</c>. One million is 0x000F4240, so the header is
    /// <c>9A 00 0F 42 40</c>. Five octets of well-formed items follow, for ten in all. Since
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see> gives every data item a
    /// head of at least one octet, an array of a million items needs at least a million octets and five cannot
    /// supply them — the document is self-inconsistent whatever its items are, which is why the refusal is a
    /// content refusal and needs no configured ceiling. The declared count equals the default
    /// <see cref="CborSerializerOptions.MaxArrayLength"/> rather than exceeding it, so the policy bound is
    /// deliberately not in play here.
    /// </remarks>
    [TestMethod]
    public void AnArrayHeaderDeclaringMoreItemsThanTheDocumentCanHoldIsRefusedAtTheHeader()
    {
        byte[] document = [0x9A, 0x00, 0x0F, 0x42, 0x40, 0x01, 0x01, 0x01, 0x01, 0x01];

        var reader = new CborReader(document, CborOptions.Strict);

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(() => reader.ReadStartArray());

        Assert.Contains("1000000", exception.Message, StringComparison.Ordinal, "The refusal must name the count the wire declared.");
        Assert.AreEqual(0, reader.BytesConsumed, "A refusal at the header must consume nothing, so nothing is committed to the caller's parse.");
    }


    /// <summary>
    /// A map header declaring a million entries in a nine-octet document is refused at the header as malformed
    /// content, before any entry is read.
    /// </summary>
    /// <remarks>
    /// Derivation. A map is major type 5, so the initial byte's high bits are <c>0b101</c> (0xA0)
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>); additional information
    /// 26 (0x1A) again introduces the four-octet argument, giving <c>0xBA</c>, and one million is 0x000F4240 —
    /// the header is <c>BA 00 0F 42 40</c>. Four octets of two well-formed key/value pairs follow. A map's
    /// declared count stands for *twice* as many data items, so a million entries needs at least two million
    /// octets; four cannot supply them. The declared count equals the default
    /// <see cref="CborSerializerOptions.MaxMapEntryCount"/> rather than exceeding it, so this is the wire bound
    /// alone.
    /// </remarks>
    [TestMethod]
    public void AMapHeaderDeclaringMoreEntriesThanTheDocumentCanHoldIsRefusedAtTheHeader()
    {
        byte[] document = [0xBA, 0x00, 0x0F, 0x42, 0x40, 0x01, 0x01, 0x02, 0x02];

        var reader = new CborReader(document, CborOptions.Strict);

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(() => reader.ReadStartMap());

        Assert.Contains("1000000", exception.Message, StringComparison.Ordinal, "The refusal must name the entry count the wire declared.");
        Assert.AreEqual(0, reader.BytesConsumed, "A refusal at the header must consume nothing.");
    }


    /// <summary>
    /// A byte-string header declaring a million octets in a ten-octet document is refused at the header,
    /// before any payload octet is copied.
    /// </summary>
    /// <remarks>
    /// Derivation. A byte string is major type 2, so the initial byte's high bits are <c>0b010</c> (0x40)
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>); with additional
    /// information 26 (0x1A) that is <c>0x5A</c>, and one million is 0x000F4240 — the header is
    /// <c>5A 00 0F 42 40</c>, followed by five payload octets. A definite-length byte string's argument *is*
    /// its payload length, so the document declares 999 995 octets it does not carry. This is the case that
    /// most directly motivates the bound: without it, the declared length would size an allocation the
    /// document never has to justify. The default
    /// <see cref="CborSerializerOptions.MaxByteStringLength"/> is 256 MiB, far above the declared million, so
    /// again only the wire bound is in play.
    /// </remarks>
    [TestMethod]
    public void AByteStringHeaderDeclaringMoreOctetsThanTheDocumentCanHoldIsRefusedAtTheHeader()
    {
        byte[] document = [0x5A, 0x00, 0x0F, 0x42, 0x40, 0x01, 0x02, 0x03, 0x04, 0x05];

        var reader = new CborReader(document, CborOptions.Strict);

        CborContentException exception = Assert.ThrowsExactly<CborContentException>(() => reader.ReadByteString());

        Assert.Contains("1000000", exception.Message, StringComparison.Ordinal, "The refusal must name the length the wire declared.");
        Assert.AreEqual(0, reader.BytesConsumed, "A refusal at the header must consume nothing.");
    }


    /// <summary>
    /// An array whose declared item count the document could satisfy, but which exceeds the configured
    /// <see cref="CborSerializerOptions.MaxArrayLength"/>, is refused as a policy violation naming that cap.
    /// </summary>
    /// <remarks>
    /// Derivation. Five items is small enough for the immediate argument form: an array is major type 4 and
    /// additional information 5 encodes the count in the initial byte itself
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>), giving <c>0x85</c>,
    /// followed by five immediate unsigned integers <c>01 02 03 04 05</c> — six octets in all. The document is
    /// entirely well formed and the wire bound is satisfied (five items, five octets available), so the only
    /// thing that can refuse it is the ceiling of four, which is what makes this test distinguish the policy
    /// bound from the wire bound rather than conflating them.
    /// </remarks>
    [TestMethod]
    public void AnArrayLengthAboveTheConfiguredCapIsRefusedNamingMaxArrayLength()
    {
        byte[] document = [0x85, 0x01, 0x02, 0x03, 0x04, 0x05];

        var reader = new CborReader(document, CreateTightlyCappedOptions());

        CborSizeLimitExceededException exception = Assert.ThrowsExactly<CborSizeLimitExceededException>(() => reader.ReadStartArray());

        Assert.AreEqual(nameof(CborSerializerOptions.MaxArrayLength), exception.CapName, "The refusal must name the ceiling that fired, so an operator knows what to lift.");
        Assert.AreEqual(5L, exception.DeclaredValue, "The refusal must report the count the wire declared.");
        Assert.AreEqual(4L, exception.Cap, "The refusal must report the ceiling that was configured.");
    }


    /// <summary>
    /// A map whose declared entry count the document could satisfy, but which exceeds the configured
    /// <see cref="CborSerializerOptions.MaxMapEntryCount"/>, is refused as a policy violation naming that cap.
    /// </summary>
    /// <remarks>
    /// Derivation. Three entries fits the immediate argument form: a map is major type 5 and additional
    /// information 3 gives <c>0xA3</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>), followed by three
    /// key/value pairs of immediate unsigned integers <c>01 01 02 02 03 03</c> — seven octets in all, with the
    /// keys already in ascending order so no ordering rule interferes. Six octets remain after the header for
    /// the six data items three entries stand for, so the wire bound holds exactly; only the ceiling of two
    /// refuses.
    /// </remarks>
    [TestMethod]
    public void AMapEntryCountAboveTheConfiguredCapIsRefusedNamingMaxMapEntryCount()
    {
        byte[] document = [0xA3, 0x01, 0x01, 0x02, 0x02, 0x03, 0x03];

        var reader = new CborReader(document, CreateTightlyCappedOptions());

        CborSizeLimitExceededException exception = Assert.ThrowsExactly<CborSizeLimitExceededException>(() => reader.ReadStartMap());

        Assert.AreEqual(nameof(CborSerializerOptions.MaxMapEntryCount), exception.CapName, "The refusal must name the ceiling that fired.");
        Assert.AreEqual(3L, exception.DeclaredValue, "The refusal must report the entry count the wire declared.");
        Assert.AreEqual(2L, exception.Cap, "The refusal must report the ceiling that was configured.");
    }


    /// <summary>
    /// A byte string whose declared length the document does carry, but which exceeds the configured
    /// <see cref="CborSerializerOptions.MaxByteStringLength"/>, is refused as a policy violation naming that
    /// cap.
    /// </summary>
    /// <remarks>
    /// Derivation. Five octets fits the immediate argument form: a byte string is major type 2 and additional
    /// information 5 gives <c>0x45</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>), followed by the five
    /// payload octets <c>01 02 03 04 05</c> — six octets in all. Every payload octet the header promises is
    /// present, so this document is exactly the case a wire-bound check alone would admit: the ceiling of four
    /// is the only thing standing between the caller and a copy it did not budget for.
    /// </remarks>
    [TestMethod]
    public void AByteStringLengthAboveTheConfiguredCapIsRefusedNamingMaxByteStringLength()
    {
        byte[] document = [0x45, 0x01, 0x02, 0x03, 0x04, 0x05];

        var reader = new CborReader(document, CreateTightlyCappedOptions());

        CborSizeLimitExceededException exception = Assert.ThrowsExactly<CborSizeLimitExceededException>(() => reader.ReadByteString());

        Assert.AreEqual(nameof(CborSerializerOptions.MaxByteStringLength), exception.CapName, "The refusal must name the ceiling that fired.");
        Assert.AreEqual(5L, exception.DeclaredValue, "The refusal must report the length the wire declared.");
        Assert.AreEqual(4L, exception.Cap, "The refusal must report the ceiling that was configured.");
    }


    /// <summary>
    /// Opening a third nested container under a configured <see cref="CborSerializerOptions.MaxDepth"/> of two
    /// is refused as a policy violation naming that cap, while the two containers within the cap open normally.
    /// </summary>
    /// <remarks>
    /// Derivation. An array of one item is major type 4 with additional information 1
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>), that is <c>0x81</c>;
    /// three of them nested around the immediate unsigned integer 1 gives <c>81 81 81 01</c> — four octets.
    /// Nothing about this document is malformed and it is far inside every count and length ceiling; depth is
    /// an orthogonal bound, and the one that matters for an adversary who wants unbounded recursion out of a
    /// tiny document. Refusing the *third* open, after two succeed, is what distinguishes a working depth
    /// bound from a reader that refuses nesting outright.
    /// </remarks>
    [TestMethod]
    public void NestingDeeperThanTheConfiguredCapIsRefusedNamingMaxDepth()
    {
        byte[] document = [0x81, 0x81, 0x81, 0x01];

        var reader = new CborReader(document, CreateTightlyCappedOptions());

        _ = reader.ReadStartArray();
        _ = reader.ReadStartArray();

        Assert.AreEqual(2, reader.CurrentDepth, "The precondition: nesting up to the cap must be admitted.");

        CborSizeLimitExceededException exception = Assert.ThrowsExactly<CborSizeLimitExceededException>(() => reader.ReadStartArray());

        Assert.AreEqual(nameof(CborSerializerOptions.MaxDepth), exception.CapName, "The refusal must name the ceiling that fired.");
        Assert.AreEqual(3L, exception.DeclaredValue, "The refusal must report the depth the document asked for.");
        Assert.AreEqual(2L, exception.Cap, "The refusal must report the ceiling that was configured.");
        Assert.AreEqual(2, reader.CurrentDepth, "A refused open must not push a frame, so the two admitted containers are still the only ones open.");
    }


    /// <summary>
    /// A document that stays inside every configured ceiling reads through to completion under the same
    /// tightly capped options that refuse the documents above.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Derivation. The document is <c>82 42 01 02 A1 01 02</c>, seven octets
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see> throughout): <c>0x82</c>
    /// is major type 4 with immediate count 2, an array of two items; <c>0x42</c> is major type 2 with
    /// immediate length 2, a byte string, carrying <c>01 02</c>; <c>0xA1</c> is major type 5 with immediate
    /// count 1, a map of one entry, carrying the key <c>01</c> and the value <c>02</c> as immediate unsigned
    /// integers. That is the array <c>[h'0102', {1: 2}]</c>.
    /// </para>
    /// <para>
    /// Every ceiling is approached and none is crossed: two array items against a cap of four, one map entry
    /// against a cap of two, two byte-string octets against a cap of four, and a nesting depth of two — the map
    /// inside the array — against a cap of two. Without this case the ceilings above would be equally satisfied
    /// by a reader that refused everything, so this is what makes them bounds rather than a blanket refusal.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void ADocumentInsideEveryConfiguredCapReadsThroughToCompletion()
    {
        byte[] document = [0x82, 0x42, 0x01, 0x02, 0xA1, 0x01, 0x02];

        var reader = new CborReader(document, CreateTightlyCappedOptions());

        int? itemCount = reader.ReadStartArray();
        byte[] byteString = reader.ReadByteString();
        int? entryCount = reader.ReadStartMap();
        int key = reader.ReadInt32();
        int value = reader.ReadInt32();
        reader.ReadEndMap();
        reader.ReadEndArray();

        Assert.AreEqual(2, itemCount, "The array declares two items.");
        Assert.AreSequenceEqual(new byte[] { 0x01, 0x02 }, byteString, "The byte string carries the two octets its header declares.");
        Assert.AreEqual(1, entryCount, "The map declares one entry.");
        Assert.AreEqual(1, key, "The map's single key is the immediate unsigned integer 1.");
        Assert.AreEqual(2, value, "The map's single value is the immediate unsigned integer 2.");
        Assert.AreEqual(0, reader.BytesRemaining, "The document is consumed exactly, with nothing left over.");
    }
}

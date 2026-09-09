using System;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;

namespace Verifiable.Tests.JCose;

/// <summary>
/// The CB-AdES clause carrier <see cref="CborReaderExtensions.ReadAscendingMapKey"/>, proved one
/// normative case at a time: under a mode that orders nothing on the reader's behalf the extension
/// makes the comparison itself, under a deterministic mode the reader refuses first, and either way
/// the refusal is the same <see cref="CborConformanceException"/> naming
/// <see cref="CborConformanceException.MapKeyOrderRule"/>, so the twenty-one CB-AdES component readers
/// that call it see one refusal shape whatever mode they run under.
/// </summary>
/// <remarks>
/// <para>
/// The ordering the extension enforces is
/// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>'s
/// deterministic map-key sort as the length-first variant
/// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.3">§4.2.3</see> describes: the shorter
/// encoded key sorts first, and equal-length keys are compared bytewise. Length-first is not signed
/// integer order — 1, −1 and 24 encode as <c>01</c>, <c>20</c> and <c>18 18</c>, so they ascend in
/// exactly that sequence while their numeric values do not.
/// </para>
/// <para>
/// The carrier exists because
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> clause 4.7 (CB-4.7-02) requires CB-AdES signatures to be
/// deterministically encoded, so a CB-AdES component reader must refuse a map whose keys are not
/// ascending even when it is handed a reader whose own mode does not police that. S4-7 of the Veritas
/// leaf-consolidation contract is the arc-side statement these tests prove. Every document below is
/// hand-derived from RFC 8949 §3's initial-byte grammar, with the derivation in the test's own doc
/// comment.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ReadAscendingMapKeyTests
{
    /// <summary>
    /// A two-entry map whose keys ascend: <c>A2 01 01 02 02</c> — <c>{1: 1, 2: 2}</c>. The encoded keys
    /// <c>01</c> and <c>02</c> are the same length and ascend bytewise.
    /// </summary>
    private static ReadOnlyMemory<byte> AscendingPairDocument => new byte[] { 0xA2, 0x01, 0x01, 0x02, 0x02 };

    /// <summary>
    /// A two-entry map whose keys descend: <c>A2 02 01 01 02</c> — <c>{2: 1, 1: 2}</c>. Same-length
    /// encodings compared bytewise put <c>01</c> before <c>02</c>, so this wire order is descending.
    /// </summary>
    private static ReadOnlyMemory<byte> DescendingPairDocument => new byte[] { 0xA2, 0x02, 0x01, 0x01, 0x02 };

    /// <summary>
    /// A two-entry map stating the same key twice: <c>A2 01 01 01 02</c> — <c>{1: 1, 1: 2}</c>. The
    /// second key is equal to the first, and the required order is strictly ascending.
    /// </summary>
    private static ReadOnlyMemory<byte> EqualKeyDocument => new byte[] { 0xA2, 0x01, 0x01, 0x01, 0x02 };

    /// <summary>
    /// A three-entry map covering the length-first order across both integer major types:
    /// <c>A3 01 01 20 02 18 18 03</c> — <c>{1: 1, -1: 2, 24: 3}</c>. Key 1 is major type 0 with the
    /// argument inlined (<c>01</c>); key −1 is major type 1 whose argument is <c>-1 - n = 0</c>, inlined
    /// (<c>20</c>); key 24 is major type 0 with additional information 24 and a following byte
    /// (<c>18 18</c>). The first two are one byte each and ascend bytewise (<c>01</c> before <c>20</c>);
    /// the third is two bytes and so sorts after both regardless of its bytes.
    /// </summary>
    private static ReadOnlyMemory<byte> MixedSignAscendingDocument =>
        new byte[] { 0xA3, 0x01, 0x01, 0x20, 0x02, 0x18, 0x18, 0x03 };

    /// <summary>
    /// The mixed-sign pair in the order length-first forbids: <c>A2 18 18 01 20 02</c> —
    /// <c>{24: 1, -1: 2}</c>. Key 24 encodes in two bytes and key −1 in one, so the two-byte key must
    /// not precede the one-byte one. Under plain signed-integer order 24 does not precede −1 either,
    /// but the two orders part company on the first pair of the previous document, which is why both
    /// documents are needed.
    /// </summary>
    private static ReadOnlyMemory<byte> LongerKeyBeforeShorterDocument => new byte[] { 0xA2, 0x18, 0x18, 0x01, 0x20, 0x02 };


    /// <summary>
    /// Reads a two-entry integer-keyed map through
    /// <see cref="CborReaderExtensions.ReadAscendingMapKey"/> for both keys — the whole read the
    /// refusal tests need in one expression, since a throw assertion may hold only a single call.
    /// </summary>
    /// <param name="document">The wire bytes to read.</param>
    /// <param name="options">The conformance preset the reader runs under.</param>
    /// <returns>The caller's key cursor after both entries.</returns>
    private static int ReadTwoAscendingMapKeys(ReadOnlyMemory<byte> document, CborSerializerOptions options)
    {
        var reader = new CborReader(document, options);
        _ = reader.ReadStartMap();

        int previousKey = 0;
        _ = reader.ReadAscendingMapKey(ref previousKey);
        _ = reader.ReadInt32();
        _ = reader.ReadAscendingMapKey(ref previousKey);
        _ = reader.ReadInt32();
        reader.ReadEndMap();

        return previousKey;
    }


    /// <summary>
    /// Under <see cref="CborOptions.Lax"/> — a mode that orders no map key on the reader's own behalf —
    /// a descending key pair is refused by the extension itself, as
    /// <see cref="CborConformanceException"/> naming
    /// <see cref="CborConformanceException.MapKeyOrderRule"/>. This is the case the carrier exists for:
    /// the clause requirement holds even where the substrate does not enforce it.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> and
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> clause 4.7 (CB-4.7-02). S4-7.
    /// </remarks>
    [TestMethod]
    public void DescendingKeysAreRefusedByTheExtensionUnderLax()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadTwoAscendingMapKeys(DescendingPairDocument, CborOptions.Lax));

        Assert.AreEqual(CborConformanceException.MapKeyOrderRule, exception.RuleName);
    }


    /// <summary>
    /// Under <see cref="CborOptions.RfcCanonical"/> the identical bytes are refused before the
    /// extension's own comparison runs — the reader polices the map frame itself — and the refusal the
    /// caller sees is the same type naming the same rule, so a CB-AdES reader's error handling does not
    /// change with the mode it was handed.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>. S4-7
    /// records that under a deterministic mode the extension relies on the reader's own enforcement and
    /// only tracks the previous key.
    /// </remarks>
    [TestMethod]
    public void DescendingKeysAreRefusedByTheReaderUnderRfcCanonical()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadTwoAscendingMapKeys(DescendingPairDocument, CborOptions.RfcCanonical));

        Assert.AreEqual(CborConformanceException.MapKeyOrderRule, exception.RuleName);
    }


    /// <summary>
    /// Ascending keys pass through the extension under <see cref="CborOptions.Lax"/>, and the caller's
    /// <c>previousKey</c> cursor advances to the key just read, which is what makes the next call's
    /// comparison the right one.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>. S4-7.
    /// </remarks>
    [TestMethod]
    public void AscendingKeysPassUnderLaxAndAdvanceThePreviousKey()
    {
        var reader = new CborReader(AscendingPairDocument, CborOptions.Lax);
        _ = reader.ReadStartMap();

        int previousKey = 0;
        int firstKey = reader.ReadAscendingMapKey(ref previousKey);
        Assert.AreEqual(1, firstKey);
        Assert.AreEqual(1, previousKey);
        Assert.AreEqual(1, reader.ReadInt32());

        int secondKey = reader.ReadAscendingMapKey(ref previousKey);
        Assert.AreEqual(2, secondKey);
        Assert.AreEqual(2, previousKey);
        Assert.AreEqual(2, reader.ReadInt32());

        reader.ReadEndMap();
        Assert.AreEqual(0, reader.BytesRemaining);
    }


    /// <summary>
    /// The same ascending keys pass under <see cref="CborOptions.RfcCanonical"/>, where the reader's own
    /// map-key check runs in addition to the extension's tracking: the two agree, so a canonically
    /// encoded CB-AdES component is never refused by the carrier that guards it.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>. S4-7.
    /// </remarks>
    [TestMethod]
    public void AscendingKeysPassUnderRfcCanonicalAndAdvanceThePreviousKey()
    {
        var reader = new CborReader(AscendingPairDocument, CborOptions.RfcCanonical);
        _ = reader.ReadStartMap();

        int previousKey = 0;
        int firstKey = reader.ReadAscendingMapKey(ref previousKey);
        Assert.AreEqual(1, firstKey);
        Assert.AreEqual(1, previousKey);
        Assert.AreEqual(1, reader.ReadInt32());

        int secondKey = reader.ReadAscendingMapKey(ref previousKey);
        Assert.AreEqual(2, secondKey);
        Assert.AreEqual(2, previousKey);
        Assert.AreEqual(2, reader.ReadInt32());

        reader.ReadEndMap();
        Assert.AreEqual(0, reader.BytesRemaining);
    }


    /// <summary>
    /// The length-first order accepts the sequence 1, −1, 24 under <see cref="CborOptions.Lax"/>: their
    /// encodings <c>01</c>, <c>20</c> and <c>18 18</c> ascend, even though the numeric values do not.
    /// A naive signed comparison would refuse −1 after 1, which is exactly the defect this carrier's
    /// comparator must not have.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.3">RFC 8949 §4.2.3</see> (the
    /// length-first ordering: shorter encodings sort first, ties bytewise) with
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">§3.1</see>'s major type 1 argument
    /// convention (the encoded argument is <c>-1 - n</c>). S4-7.
    /// </remarks>
    [TestMethod]
    public void MixedSignKeysAscendInLengthFirstOrderUnderLax()
    {
        var reader = new CborReader(MixedSignAscendingDocument, CborOptions.Lax);
        _ = reader.ReadStartMap();

        int previousKey = 0;
        Assert.AreEqual(1, reader.ReadAscendingMapKey(ref previousKey));
        Assert.AreEqual(1, reader.ReadInt32());

        Assert.AreEqual(-1, reader.ReadAscendingMapKey(ref previousKey));
        Assert.AreEqual(2, reader.ReadInt32());

        Assert.AreEqual(24, reader.ReadAscendingMapKey(ref previousKey));
        Assert.AreEqual(3, reader.ReadInt32());

        reader.ReadEndMap();
        Assert.AreEqual(0, reader.BytesRemaining);
    }


    /// <summary>
    /// The extension refuses the two-byte key 24 before the one-byte key −1 under
    /// <see cref="CborOptions.Lax"/>: length decides first, so a longer encoding may never precede a
    /// shorter one however their values compare.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.3">RFC 8949 §4.2.3</see>. S4-7.
    /// </remarks>
    [TestMethod]
    public void ALongerEncodedKeyBeforeAShorterOneIsRefusedUnderLax()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadTwoAscendingMapKeys(LongerKeyBeforeShorterDocument, CborOptions.Lax));

        Assert.AreEqual(CborConformanceException.MapKeyOrderRule, exception.RuleName);
    }


    /// <summary>
    /// A repeated key is refused by the extension under <see cref="CborOptions.Lax"/> as well, since the
    /// required order is strictly ascending and an equal key is not after its predecessor. Lax gives the
    /// reader no duplicate-key check of its own, so this refusal is the carrier's alone, and it is
    /// reported under the ordering rule that decided it.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> (sorted
    /// keys, which excludes duplicates) with
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> clause 4.7 (CB-4.7-02). S4-7.
    /// </remarks>
    [TestMethod]
    public void AnEqualKeyIsRefusedByTheExtensionUnderLax()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadTwoAscendingMapKeys(EqualKeyDocument, CborOptions.Lax));

        Assert.AreEqual(CborConformanceException.MapKeyOrderRule, exception.RuleName);
    }
}

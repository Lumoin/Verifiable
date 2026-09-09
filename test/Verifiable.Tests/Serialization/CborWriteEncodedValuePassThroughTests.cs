using System;
using System.Buffers;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// The splice path — writing an already-encoded CBOR item verbatim into an open document — as this library
/// uses it: well-formedness is checked under every conformance preset, the deterministic presets
/// additionally require the spliced bytes to already satisfy their encoding rules, and a refused splice
/// commits nothing to the destination.
/// </summary>
/// <remarks>
/// <para>
/// Splicing is how this library relays bytes another party produced and signed (mdoc <c>IssuerAuth</c> and
/// <c>IssuerSignedItemBytes</c> per <see href="https://www.iso.org/standard/69084.html">ISO/IEC
/// 18013-5</see> §9.1.2, COSE parts, CTAP2 sub-structures): the bytes MUST reach the wire exactly as
/// received, because a digest or a signature commits to them. A splice that silently re-encoded, or that
/// half-committed before refusing, would break that commitment.
/// </para>
/// <para>
/// The deterministic rules a spliced item must already satisfy are those of
/// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> — preferred
/// (shortest) integer headers and ascending map keys — and, for the CTAP2 preset, the canonical CBOR
/// encoding form of <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form">CTAP 2.1 §6</see>.
/// </para>
/// <para>
/// Every destination here is the house pooled buffer writer over an explicitly injected pool, so a refused
/// splice is checked against the pooled sink the library actually writes into rather than a heap array.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CborWriteEncodedValuePassThroughTests
{
    /// <summary>
    /// A canonical two-entry map with the unsigned integer keys 1 and 2 in ascending order, each carrying
    /// its own key as value: <c>A2 01 01 02 02</c>. Head byte <c>0xA2</c> is major type 5 with additional
    /// information 2 (two key/value pairs) per RFC 8949 §3.1; each of <c>01</c> and <c>02</c> is a major
    /// type 0 unsigned integer in the direct additional-information form.
    /// </summary>
    private static byte[] CanonicalMap => [0xA2, 0x01, 0x01, 0x02, 0x02];

    /// <summary>
    /// The same two-entry map with its pairs emitted in descending key order: <c>A2 02 02 01 01</c>. Both
    /// keys encode to one byte, so RFC 8949 §4.2.1's length-then-bytewise key ordering places key
    /// <c>01</c> first; this document places it second.
    /// </summary>
    private static byte[] DescendingKeyMap => [0xA2, 0x02, 0x02, 0x01, 0x01];

    /// <summary>
    /// The unsigned integer 5 stated with a one-byte argument instead of the direct form: <c>18 05</c>.
    /// Head byte <c>0x18</c> is major type 0 with additional information 24 ("one-byte argument follows"),
    /// but 5 is below 24 and so fits the head byte itself as <c>05</c>.
    /// </summary>
    private static byte[] NonMinimalHeader => [0x18, 0x05];

    /// <summary>
    /// A map header declaring two pairs followed by a single item: <c>A2 03</c>. Four items are required
    /// and one byte remains, so the document is truncated.
    /// </summary>
    private static byte[] TruncatedMap => [0xA2, 0x03];

    /// <summary>
    /// The bytes an open two-element array with its first element already written puts on the wire:
    /// <c>82 01</c>. Head byte <c>0x82</c> is major type 4 with additional information 2; <c>01</c> is the
    /// unsigned integer 1.
    /// </summary>
    private static byte[] Preamble => [0x82, 0x01];


    /// <summary>
    /// Opens a pooled destination and a writer over it under the given preset, writes the two-byte
    /// <see cref="Preamble"/>, and hands both back so a splice can be attempted as the array's second
    /// element with committed bytes already behind it.
    /// </summary>
    /// <param name="pool">The explicitly injected house pool the destination rents from.</param>
    /// <param name="options">The conformance preset the writer runs under.</param>
    /// <returns>The destination and the writer positioned inside an open two-element array.</returns>
    private static (SlabBufferWriter Buffer, CborWriter Writer) OpenWithPreamble(BaseMemoryPool pool, CborSerializerOptions options)
    {
        var buffer = new SlabBufferWriter(pool);
        var writer = new CborWriter(buffer, options);
        writer.WriteStartArray(2);
        writer.WriteInt32(1);

        return (buffer, writer);
    }


    /// <summary>
    /// Asserts that a destination holds exactly the given bytes, draining it through <c>Detach</c> so the
    /// comparison runs over the exact-length carrier the sink hands out.
    /// </summary>
    /// <param name="expected">The bytes the destination is expected to hold.</param>
    /// <param name="buffer">The destination to drain and inspect.</param>
    private static void AssertBufferHolds(byte[] expected, SlabBufferWriter buffer)
    {
        int expectedLength = expected.Length;
        int bytesWritten = buffer.BytesWritten;
        using IMemoryOwner<byte> encoded = buffer.Detach();

        Assert.AreEqual(expectedLength, bytesWritten);
        Assert.HasCount(expectedLength, encoded.Memory);
        Assert.IsTrue(
            encoded.Memory.Span.SequenceEqual(expected),
            $"Expected {Convert.ToHexString(expected)}, got {Convert.ToHexString(encoded.Memory.Span)}.");
    }


    /// <summary>
    /// Splicing an already-canonical map under the RFC canonical preset succeeds and places the spliced
    /// bytes on the wire verbatim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>: the spliced
    /// map's keys 1 and 2 are both one byte long and ascend bytewise, and each of its four items uses the
    /// shortest head byte, so the document already satisfies the deterministic rules the preset enforces.
    /// </para>
    /// <para>
    /// Fix-list item V16. Verbatim pass-through is the whole point of the path: an mdoc relay's outer
    /// document is canonical while the issuer-signed item it carries must reach the verifier as the issuer
    /// signed it.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplicingACanonicalMapUnderRfcCanonicalPassesTheBytesThroughVerbatim()
    {
        using var housePool = new MeteredHousePool();
        using var buffer = new SlabBufferWriter(housePool.Pool);
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);

        writer.WriteEncodedValue(CanonicalMap);

        Assert.AreEqual(CanonicalMap.Length, writer.BytesWritten);
        AssertBufferHolds(CanonicalMap, buffer);
    }


    /// <summary>
    /// Splicing a map whose keys descend under the RFC canonical preset is refused as a map key ordering
    /// violation, and nothing of the refused item reaches the destination.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>: "The keys in
    /// every map MUST be sorted in the bytewise lexicographic order of their deterministic encodings." Keys
    /// <c>02</c> and <c>01</c> are both one byte, so <c>01</c> MUST come first; this document reverses them.
    /// </para>
    /// <para>
    /// Fix-list item V16. The commits-nothing half is the security-relevant half: a splice that emitted the
    /// map header before discovering the second key's order would leave a half-written item in a document a
    /// caller may go on to sign, so the refusal is asserted against both the writer's own byte count and the
    /// destination's contents, which must still hold only the two preamble bytes.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplicingADescendingKeyMapUnderRfcCanonicalRefusesWithMapKeyOrderRuleAndCommitsNothing()
    {
        using var housePool = new MeteredHousePool();
        (SlabBufferWriter buffer, CborWriter writer) = OpenWithPreamble(housePool.Pool, CborOptions.RfcCanonical);
        using(buffer)
        {
            int bytesWrittenBefore = writer.BytesWritten;

            CborConformanceException exception = Assert.Throws<CborConformanceException>(
                () => writer.WriteEncodedValue(DescendingKeyMap));

            Assert.AreEqual(CborConformanceException.MapKeyOrderRule, exception.RuleName);
            Assert.AreEqual(bytesWrittenBefore, writer.BytesWritten);
            AssertBufferHolds(Preamble, buffer);
        }
    }


    /// <summary>
    /// Splicing an integer stated with a wider head than it needs under the RFC canonical preset is refused
    /// as a minimal header violation, and nothing of the refused item reaches the destination.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>: "Preferred
    /// serialization" requires the argument to be "as short as possible", so the unsigned integer 5, being
    /// below 24, MUST be stated as the single head byte <c>05</c> rather than as <c>18 05</c>.
    /// </para>
    /// <para>
    /// Fix-list item V16. A non-minimal header is the classic re-encoding ambiguity: two byte strings that
    /// decode to the same value hash differently, so a deterministic document must admit only one of them.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplicingANonMinimalHeaderUnderRfcCanonicalRefusesWithMinimalHeaderRuleAndCommitsNothing()
    {
        using var housePool = new MeteredHousePool();
        (SlabBufferWriter buffer, CborWriter writer) = OpenWithPreamble(housePool.Pool, CborOptions.RfcCanonical);
        using(buffer)
        {
            int bytesWrittenBefore = writer.BytesWritten;

            CborConformanceException exception = Assert.Throws<CborConformanceException>(
                () => writer.WriteEncodedValue(NonMinimalHeader));

            Assert.AreEqual(CborConformanceException.MinimalHeaderRule, exception.RuleName);
            Assert.AreEqual(bytesWrittenBefore, writer.BytesWritten);
            AssertBufferHolds(Preamble, buffer);
        }
    }


    /// <summary>
    /// Splicing the descending-key map under the lax preset passes it through byte-identically, proving the
    /// map key ordering rule binds only where a deterministic profile is in force.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> places no ordering
    /// requirement on map keys; the requirement in
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">§4.2.1</see> is scoped to
    /// deterministically encoded CBOR.
    /// </para>
    /// <para>
    /// Fix-list item V16, and the ruling that lets a relay carry foreign bytes it did not produce: the relay
    /// writer runs lax precisely so a well-formed but non-canonical issuer item reaches the verifier
    /// unaltered.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplicingADescendingKeyMapUnderLaxPassesTheBytesThroughVerbatim()
    {
        using var housePool = new MeteredHousePool();
        using var buffer = new SlabBufferWriter(housePool.Pool);
        var writer = new CborWriter(buffer, CborOptions.Lax);

        writer.WriteEncodedValue(DescendingKeyMap);

        Assert.AreEqual(DescendingKeyMap.Length, writer.BytesWritten);
        AssertBufferHolds(DescendingKeyMap, buffer);
    }


    /// <summary>
    /// Splicing the non-minimal integer header under the lax preset passes it through byte-identically,
    /// proving the preferred-serialization rule likewise binds only under a deterministic profile.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see> admits any of the
    /// argument encodings for a value that fits them; only
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">§4.2.1</see> narrows the choice to
    /// the shortest.
    /// </para>
    /// <para>
    /// Fix-list item V16. The bytes must survive unchanged rather than being re-encoded into the preferred
    /// form, since a caller splicing them is asserting they are already what some digest committed to.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplicingANonMinimalHeaderUnderLaxPassesTheBytesThroughVerbatim()
    {
        using var housePool = new MeteredHousePool();
        using var buffer = new SlabBufferWriter(housePool.Pool);
        var writer = new CborWriter(buffer, CborOptions.Lax);

        writer.WriteEncodedValue(NonMinimalHeader);

        Assert.AreEqual(NonMinimalHeader.Length, writer.BytesWritten);
        AssertBufferHolds(NonMinimalHeader, buffer);
    }


    /// <summary>
    /// Splicing a truncated map under the RFC canonical preset is refused as malformed content rather than
    /// as a conformance violation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see>: a definite-length
    /// map head with argument 2 is followed by exactly four data items. <c>A2 03</c> supplies one, so the
    /// document is not well-formed at all — a defect of a different kind from an encoding-rule violation.
    /// </para>
    /// <para>
    /// Fix-list item V16. Separating the two refusal kinds matters to the fail-closed parsers above this
    /// layer, which decide whether a document is garbage or merely non-deterministic.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplicingATruncatedMapUnderRfcCanonicalRefusesAsMalformedContent()
    {
        using var housePool = new MeteredHousePool();
        (SlabBufferWriter buffer, CborWriter writer) = OpenWithPreamble(housePool.Pool, CborOptions.RfcCanonical);
        using(buffer)
        {
            int bytesWrittenBefore = writer.BytesWritten;

            _ = Assert.Throws<CborContentException>(() => writer.WriteEncodedValue(TruncatedMap));

            Assert.AreEqual(bytesWrittenBefore, writer.BytesWritten);
            AssertBufferHolds(Preamble, buffer);
        }
    }


    /// <summary>
    /// Splicing the same truncated map under the lax preset is refused identically, proving well-formedness
    /// is checked under every preset and is not a deterministic-mode concession.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> defines
    /// well-formedness independently of any encoding profile;
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-5.1">§5.1</see> requires a decoder to
    /// reject a not-well-formed item unconditionally.
    /// </para>
    /// <para>
    /// Fix-list item V16. This is the adversarial floor of the relay case: running lax to preserve foreign
    /// bytes must not become a way to smuggle malformed bytes into a document this library emits.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplicingATruncatedMapUnderLaxRefusesAsMalformedContent()
    {
        using var housePool = new MeteredHousePool();
        (SlabBufferWriter buffer, CborWriter writer) = OpenWithPreamble(housePool.Pool, CborOptions.Lax);
        using(buffer)
        {
            int bytesWrittenBefore = writer.BytesWritten;

            _ = Assert.Throws<CborContentException>(() => writer.WriteEncodedValue(TruncatedMap));

            Assert.AreEqual(bytesWrittenBefore, writer.BytesWritten);
            AssertBufferHolds(Preamble, buffer);
        }
    }


    /// <summary>
    /// Splicing the descending-key map under the CTAP2 canonical preset is refused with the same map key
    /// ordering rule the RFC canonical preset raises.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form">CTAP
    /// 2.1 §6</see> orders map keys by major type first, then by length, then bytewise. Keys <c>01</c> and
    /// <c>02</c> share major type 0 and both encode to one byte, so the first two criteria are ties and the
    /// bytewise comparison decides: <c>01</c> MUST precede <c>02</c>. The expected order is therefore the
    /// same one <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>
    /// gives, which is what makes this shape a valid probe of the CTAP2 preset despite the two profiles
    /// differing on mixed-major-type keys.
    /// </para>
    /// <para>
    /// Fix-list item V16 with ruling S4-9: every CTAP2 and FIDO2 map this library writes is keyed within a
    /// single major type, so the two comparators agree on all of them.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplicingADescendingKeyMapUnderCtap2CanonicalRefusesWithMapKeyOrderRule()
    {
        using var housePool = new MeteredHousePool();
        (SlabBufferWriter buffer, CborWriter writer) = OpenWithPreamble(housePool.Pool, CborOptions.Ctap2Canonical);
        using(buffer)
        {
            int bytesWrittenBefore = writer.BytesWritten;

            CborConformanceException exception = Assert.Throws<CborConformanceException>(
                () => writer.WriteEncodedValue(DescendingKeyMap));

            Assert.AreEqual(CborConformanceException.MapKeyOrderRule, exception.RuleName);
            Assert.AreEqual(bytesWrittenBefore, writer.BytesWritten);
            AssertBufferHolds(Preamble, buffer);
        }
    }


    /// <summary>
    /// Splicing the non-minimal integer header under the CTAP2 canonical preset is refused with the same
    /// minimal header rule the RFC canonical preset raises.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form">CTAP
    /// 2.1 §6</see> requires integers to be "encoded as small as possible", the same requirement
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> states as
    /// preferred serialization. The unsigned integer 5 is below 24 and so MUST occupy only its head byte.
    /// </para>
    /// <para>
    /// Fix-list item V16. An authenticator that hashed a client data or attestation structure would compute
    /// a different digest over the wider encoding, so the wider form must never reach the wire.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplicingANonMinimalHeaderUnderCtap2CanonicalRefusesWithMinimalHeaderRule()
    {
        using var housePool = new MeteredHousePool();
        (SlabBufferWriter buffer, CborWriter writer) = OpenWithPreamble(housePool.Pool, CborOptions.Ctap2Canonical);
        using(buffer)
        {
            int bytesWrittenBefore = writer.BytesWritten;

            CborConformanceException exception = Assert.Throws<CborConformanceException>(
                () => writer.WriteEncodedValue(NonMinimalHeader));

            Assert.AreEqual(CborConformanceException.MinimalHeaderRule, exception.RuleName);
            Assert.AreEqual(bytesWrittenBefore, writer.BytesWritten);
            AssertBufferHolds(Preamble, buffer);
        }
    }


    /// <summary>
    /// Splicing the already-canonical map under the CTAP2 canonical preset succeeds and passes the bytes
    /// through verbatim, the accepting counterpart to the two CTAP2 refusals.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form">CTAP
    /// 2.1 §6</see>: the map is definite-length, its integer keys are as small as possible, and they ascend
    /// under the major-type-then-length-then-bytewise order, so it is already in canonical form.
    /// </para>
    /// <para>
    /// Fix-list item V16 with ruling S4-9. Without this case the two refusals alone could be satisfied by a
    /// preset that refused everything.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void SplicingACanonicalMapUnderCtap2CanonicalPassesTheBytesThroughVerbatim()
    {
        using var housePool = new MeteredHousePool();
        using var buffer = new SlabBufferWriter(housePool.Pool);
        var writer = new CborWriter(buffer, CborOptions.Ctap2Canonical);

        writer.WriteEncodedValue(CanonicalMap);

        Assert.AreEqual(CanonicalMap.Length, writer.BytesWritten);
        AssertBufferHolds(CanonicalMap, buffer);
    }
}

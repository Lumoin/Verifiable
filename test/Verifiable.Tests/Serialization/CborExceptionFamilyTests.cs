using System;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// The CBOR exception family the fail-closed parse filters catch, proved one normative rule at a time
/// over hand-derived wire bytes: malformed content surfaces as <see cref="CborContentException"/>;
/// each deterministic-encoding rule surfaces as <see cref="CborConformanceException"/> naming the rule
/// it broke; both leaves are members of the <see cref="CborException"/> base the filters name; and the
/// same bytes under <see cref="CborOptions.Lax"/> read without complaint, since Lax binds none of the
/// deterministic rules.
/// </summary>
/// <remarks>
/// <para>
/// Every document below is hand-derived from
/// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3">RFC 8949 §3</see>'s initial-byte
/// grammar and written out as literal bytes with the derivation in the test's own doc comment — never
/// produced by the writer whose reader is under test. Every document below fails as MALFORMED CBOR — a
/// grammar violation the reader refuses outright — never as a well-formed document that merely violates a
/// profile rule the reader instead accepts and a validator would separately reject.
/// </para>
/// <para>
/// The fail-closed half exercises <see cref="CBAdESSerialization.TryParseSignatureProductionPlace"/>,
/// a <c>TryParse*</c> entry that reads its <c>sigPl</c> map under
/// <see cref="CborOptions.RfcCanonical"/> per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> clause 4.7 (CB-4.7-02: CB-AdES signatures shall be deterministically
/// encoded). A parser that fails closed converts every one of the refusals above into
/// <see langword="false"/>; a test method that throws instead of returning fails, which is how "never
/// throws" is proved here.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CborExceptionFamilyTests
{
    /// <summary>
    /// A two-entry map header followed by a single key byte and nothing else: <c>A2 03</c>.
    /// <c>A2</c> is major type 5 (map) with additional information 2, so two key/value pairs are
    /// declared; <c>03</c> is major type 0 with the argument inlined, the unsigned integer 3. The
    /// declared pairs are not present, so the document is truncated.
    /// </summary>
    private static ReadOnlyMemory<byte> TruncatedMapDocument => new byte[] { 0xA2, 0x03 };

    /// <summary>
    /// A two-entry map whose two keys are the same unsigned integer 1: <c>A2 01 01 01 02</c> —
    /// <c>{1: 1, 1: 2}</c>. Major type 5 with additional information 2, then the pairs
    /// <c>01</c>/<c>01</c> and <c>01</c>/<c>02</c>.
    /// </summary>
    private static ReadOnlyMemory<byte> DuplicateKeyDocument => new byte[] { 0xA2, 0x01, 0x01, 0x01, 0x02 };

    /// <summary>
    /// A two-entry map whose two distinct keys descend: <c>A2 02 01 01 02</c> — <c>{2: 1, 1: 2}</c>.
    /// The encoded keys <c>02</c> and <c>01</c> are the same length, so RFC 8949 §4.2.1's bytewise
    /// tie-break decides, and <c>02</c> sorts after <c>01</c>: the wire order is descending.
    /// </summary>
    private static ReadOnlyMemory<byte> DescendingKeyDocument => new byte[] { 0xA2, 0x02, 0x01, 0x01, 0x02 };

    /// <summary>
    /// The unsigned integer 5 stated in a one-byte-argument header instead of the inlined form:
    /// <c>18 05</c>. Additional information 24 announces a following one-byte argument, but 5 is under
    /// 24 and so has an inlined encoding (<c>05</c>) one byte shorter — the header is not minimal.
    /// </summary>
    private static ReadOnlyMemory<byte> NonMinimalIntegerHeaderDocument => new byte[] { 0x18, 0x05 };

    /// <summary>
    /// The value 1.5 stated in binary64: <c>FB 3F F8 00 00 00 00 00 00</c>. IEEE 754 binary64 for 1.5 is
    /// sign 0, biased exponent 1023 (<c>0x3FF</c>) and significand <c>0x8000000000000</c>, i.e.
    /// <c>0x3FF8000000000000</c>. The same value is exactly representable in binary16 as <c>0x3E00</c>
    /// (sign 0, biased exponent 16, significand <c>0x200</c>), so <c>F9 3E00</c> is three bytes shorter
    /// and the binary64 statement is not the shortest form.
    /// </summary>
    private static ReadOnlyMemory<byte> NonShortestFloatDocument =>
        new byte[] { 0xFB, 0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    /// <summary>
    /// A well-formed, canonically encoded <c>sigPl</c> map carrying only <c>addressCountry</c> (map key
    /// 1, <see cref="CBAdESWireKeys.SignatureProductionPlaceAddressCountry"/>): <c>A1 01 62 46 49</c> —
    /// <c>{1: "FI"}</c>. <c>62</c> is major type 3 with length 2, followed by the UTF-8 bytes
    /// <c>46 49</c> ("FI").
    /// </summary>
    private static ReadOnlyMemory<byte> SignatureProductionPlaceDocument => new byte[] { 0xA1, 0x01, 0x62, 0x46, 0x49 };

    /// <summary>
    /// The <c>sigPl</c> map with <c>addressCountry</c> stated twice: <c>A2 01 62 46 49 01 62 46 49</c> —
    /// <c>{1: "FI", 1: "FI"}</c>, the duplicate-key shape at the CB-AdES component boundary.
    /// </summary>
    private static ReadOnlyMemory<byte> SignatureProductionPlaceDuplicateKeyDocument =>
        new byte[] { 0xA2, 0x01, 0x62, 0x46, 0x49, 0x01, 0x62, 0x46, 0x49 };

    /// <summary>
    /// The <c>sigPl</c> map stating <c>addressLocality</c> (key 2) before <c>addressCountry</c> (key 1):
    /// <c>A2 02 61 61 01 62 46 49</c> — <c>{2: "a", 1: "FI"}</c>. <c>61 61</c> is a one-character text
    /// string "a". Both keys are legal <c>sigPl</c> members; only their wire order is wrong.
    /// </summary>
    private static ReadOnlyMemory<byte> SignatureProductionPlaceDescendingKeyDocument =>
        new byte[] { 0xA2, 0x02, 0x61, 0x61, 0x01, 0x62, 0x46, 0x49 };

    /// <summary>
    /// The <c>sigPl</c> map whose single key 1 is stated in a one-byte-argument header:
    /// <c>A1 18 01 62 46 49</c> — the key value is the legal member <c>addressCountry</c>, but
    /// <c>18 01</c> is a byte longer than the inlined <c>01</c>.
    /// </summary>
    private static ReadOnlyMemory<byte> SignatureProductionPlaceNonMinimalHeaderDocument =>
        new byte[] { 0xA1, 0x18, 0x01, 0x62, 0x46, 0x49 };


    /// <summary>
    /// Reads <paramref name="document"/> as a definite-length map of integer keys and integer values,
    /// consuming exactly the declared number of pairs and the map's end — the whole read the refusal
    /// tests need in one expression, since a throw assertion may hold only a single call.
    /// </summary>
    /// <param name="document">The wire bytes to read.</param>
    /// <param name="options">The conformance preset the reader runs under.</param>
    private static void ReadIntegerKeyedMap(ReadOnlyMemory<byte> document, CborSerializerOptions options)
    {
        var reader = new CborReader(document, options);

        int? entryCount = reader.ReadStartMap();
        for(int i = 0; i < entryCount!.Value; i++)
        {
            _ = reader.ReadInt32();
            _ = reader.ReadInt32();
        }

        reader.ReadEndMap();
    }


    /// <summary>
    /// Reads <paramref name="document"/> as a single integer data item.
    /// </summary>
    /// <param name="document">The wire bytes to read.</param>
    /// <param name="options">The conformance preset the reader runs under.</param>
    /// <returns>The integer read.</returns>
    private static int ReadIntegerItem(ReadOnlyMemory<byte> document, CborSerializerOptions options)
    {
        var reader = new CborReader(document, options);

        return reader.ReadInt32();
    }


    /// <summary>
    /// Reads <paramref name="document"/> as a single binary64 floating-point data item.
    /// </summary>
    /// <param name="document">The wire bytes to read.</param>
    /// <param name="options">The conformance preset the reader runs under.</param>
    /// <returns>The value read.</returns>
    private static double ReadDoubleItem(ReadOnlyMemory<byte> document, CborSerializerOptions options)
    {
        var reader = new CborReader(document, options);

        return reader.ReadDouble();
    }


    /// <summary>
    /// A truncated document — a map declaring two entries none of which are present — is malformed
    /// rather than non-conformant, so it surfaces as <see cref="CborContentException"/>, the family
    /// member reserved for bytes that cannot be parsed at all.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see>: a
    /// definite-length map's head is followed by exactly twice its declared argument of data items.
    /// S4-6 of the Veritas leaf-consolidation contract names this the malformed-content case.
    /// </remarks>
    [TestMethod]
    public void TruncatedMapIsRefusedAsMalformedContent()
    {
        _ = Assert.ThrowsExactly<CborContentException>(() => ReadIntegerKeyedMap(TruncatedMapDocument, CborOptions.RfcCanonical));
    }


    /// <summary>
    /// The same truncated document is refused under <see cref="CborOptions.Lax"/> as well:
    /// well-formedness is not a conformance rule a mode can relax, so the Lax reader refuses it exactly
    /// as the deterministic reader does. This is the adversarial complement to the Lax-accepts tests
    /// below — Lax is permissive about encoding form, never about bytes that are not a CBOR document.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-1.2">RFC 8949 §1.2</see> ("well-formed"
    /// is a property of the encoded data item itself, independent of any further validity criteria).
    /// </remarks>
    [TestMethod]
    public void TruncatedMapIsRefusedUnderLaxAsWell()
    {
        _ = Assert.ThrowsExactly<CborContentException>(() => ReadIntegerKeyedMap(TruncatedMapDocument, CborOptions.Lax));
    }


    /// <summary>
    /// A map stating the same integer key twice is refused under
    /// <see cref="CborOptions.RfcCanonical"/>, naming
    /// <see cref="CborConformanceException.DuplicateMapKeyRule"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>: the keys
    /// in every map must be sorted, and duplicate keys are therefore excluded by that ordering. S4-6
    /// requires the leaf exception plus the rule name wherever the broken rule is specific.
    /// </remarks>
    [TestMethod]
    public void DuplicateIntegerKeyIsRefusedUnderRfcCanonical()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadIntegerKeyedMap(DuplicateKeyDocument, CborOptions.RfcCanonical));

        Assert.AreEqual(CborConformanceException.DuplicateMapKeyRule, exception.RuleName);
    }


    /// <summary>
    /// The same duplicate-key map is refused under <see cref="CborOptions.Ctap2Canonical"/> under the
    /// same rule name — the CTAP2 canonical form inherits RFC 8949's map-key sorting requirement, so a
    /// repeated key is inadmissible there too.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form">
    /// CTAP2.1 §6 (CTAP2 canonical CBOR encoding form)</see>: map keys are sorted, shorter encodings
    /// first, ties broken bytewise. S4-6 requires both deterministic modes to be pinned.
    /// </remarks>
    [TestMethod]
    public void DuplicateIntegerKeyIsRefusedUnderCtap2Canonical()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadIntegerKeyedMap(DuplicateKeyDocument, CborOptions.Ctap2Canonical));

        Assert.AreEqual(CborConformanceException.DuplicateMapKeyRule, exception.RuleName);
    }


    /// <summary>
    /// A map whose two distinct keys descend is refused under
    /// <see cref="CborOptions.RfcCanonical"/>, naming
    /// <see cref="CborConformanceException.MapKeyOrderRule"/> — a different rule from the duplicate
    /// case even though both are decided by the same comparison.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see> (map keys
    /// sorted in bytewise lexicographic order of their deterministic encodings). S4-6.
    /// </remarks>
    [TestMethod]
    public void DescendingIntegerKeysAreRefusedUnderRfcCanonical()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadIntegerKeyedMap(DescendingKeyDocument, CborOptions.RfcCanonical));

        Assert.AreEqual(CborConformanceException.MapKeyOrderRule, exception.RuleName);
    }


    /// <summary>
    /// The same descending-key map is refused under <see cref="CborOptions.Ctap2Canonical"/> under the
    /// same rule name.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form">
    /// CTAP2.1 §6</see> (the canonical CBOR encoding form's map-key sort). S4-6.
    /// </remarks>
    [TestMethod]
    public void DescendingIntegerKeysAreRefusedUnderCtap2Canonical()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadIntegerKeyedMap(DescendingKeyDocument, CborOptions.Ctap2Canonical));

        Assert.AreEqual(CborConformanceException.MapKeyOrderRule, exception.RuleName);
    }


    /// <summary>
    /// An unsigned integer whose argument is carried in a following byte although it would fit inlined
    /// is refused under <see cref="CborOptions.RfcCanonical"/>, naming
    /// <see cref="CborConformanceException.MinimalHeaderRule"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>: preferred
    /// serialization states an argument in the shortest form that holds it, so an integer under 24 is
    /// stated in the initial byte. S4-6 names this rule explicitly.
    /// </remarks>
    [TestMethod]
    public void NonMinimalIntegerHeaderIsRefusedUnderRfcCanonical()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadIntegerItem(NonMinimalIntegerHeaderDocument, CborOptions.RfcCanonical));

        Assert.AreEqual(CborConformanceException.MinimalHeaderRule, exception.RuleName);
    }


    /// <summary>
    /// A floating-point value stated in binary64 although binary16 represents it exactly is refused
    /// under <see cref="CborOptions.RfcCanonical"/>, naming
    /// <see cref="CborConformanceException.ShortestFloatRule"/>.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>: a
    /// deterministically encoded floating-point value uses the shortest of the three IEEE 754 widths
    /// that preserves it. S4-6 names this rule explicitly.
    /// </remarks>
    [TestMethod]
    public void NonShortestFloatIsRefusedUnderRfcCanonical()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadDoubleItem(NonShortestFloatDocument, CborOptions.RfcCanonical));

        Assert.AreEqual(CborConformanceException.ShortestFloatRule, exception.RuleName);
    }


    /// <summary>
    /// The duplicate-key map reads through under <see cref="CborOptions.Lax"/>, both entries intact:
    /// Lax binds no map-key rule, so the wire form the deterministic reader refuses is data here.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2">RFC 8949 §4.2</see> makes
    /// deterministic encoding an option a protocol chooses, not a property of every CBOR document.
    /// S4-6 requires each refused document to be shown reading successfully under Lax.
    /// </remarks>
    [TestMethod]
    public void DuplicateIntegerKeyIsAcceptedUnderLax()
    {
        var reader = new CborReader(DuplicateKeyDocument, CborOptions.Lax);

        int? entryCount = reader.ReadStartMap();
        int firstKey = reader.ReadInt32();
        int firstValue = reader.ReadInt32();
        int secondKey = reader.ReadInt32();
        int secondValue = reader.ReadInt32();
        reader.ReadEndMap();

        Assert.AreEqual(2, entryCount!.Value);
        Assert.AreEqual(1, firstKey);
        Assert.AreEqual(1, firstValue);
        Assert.AreEqual(1, secondKey);
        Assert.AreEqual(2, secondValue);
        Assert.AreEqual(0, reader.BytesRemaining);
    }


    /// <summary>
    /// The descending-key map reads through under <see cref="CborOptions.Lax"/> in its wire order:
    /// Lax orders nothing on the reader's behalf.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2">RFC 8949 §4.2</see>. S4-6.
    /// </remarks>
    [TestMethod]
    public void DescendingIntegerKeysAreAcceptedUnderLax()
    {
        var reader = new CborReader(DescendingKeyDocument, CborOptions.Lax);

        int? entryCount = reader.ReadStartMap();
        int firstKey = reader.ReadInt32();
        int firstValue = reader.ReadInt32();
        int secondKey = reader.ReadInt32();
        int secondValue = reader.ReadInt32();
        reader.ReadEndMap();

        Assert.AreEqual(2, entryCount!.Value);
        Assert.AreEqual(2, firstKey);
        Assert.AreEqual(1, firstValue);
        Assert.AreEqual(1, secondKey);
        Assert.AreEqual(2, secondValue);
        Assert.AreEqual(0, reader.BytesRemaining);
    }


    /// <summary>
    /// The non-minimal integer header reads as the value it states under
    /// <see cref="CborOptions.Lax"/>: the wider header is a legal well-formed encoding of 5, just not
    /// the preferred one.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> (additional
    /// information 24 states a one-byte argument) with
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">§4.2.1</see>'s preference
    /// unbound under Lax. S4-6.
    /// </remarks>
    [TestMethod]
    public void NonMinimalIntegerHeaderIsAcceptedUnderLax()
    {
        var reader = new CborReader(NonMinimalIntegerHeaderDocument, CborOptions.Lax);

        int value = reader.ReadInt32();

        Assert.AreEqual(5, value);
        Assert.AreEqual(0, reader.BytesRemaining);
    }


    /// <summary>
    /// The binary64 statement of 1.5 reads as 1.5 under <see cref="CborOptions.Lax"/>: the wider width
    /// is a legal well-formed encoding, just not the shortest one.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.3">RFC 8949 §3.3</see> (major type 7
    /// additional information 27 states a binary64 value) with
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">§4.2.1</see>'s shortest-form
    /// requirement unbound under Lax. S4-6.
    /// </remarks>
    [TestMethod]
    public void NonShortestFloatIsAcceptedUnderLax()
    {
        var reader = new CborReader(NonShortestFloatDocument, CborOptions.Lax);

        double value = reader.ReadDouble();

        Assert.AreEqual(1.5d, value);
        Assert.AreEqual(0, reader.BytesRemaining);
    }


    /// <summary>
    /// The malformed-content leaf is a member of the <see cref="CborException"/> family: a fail-closed
    /// filter written against the base catches it without naming the leaf.
    /// </summary>
    /// <remarks>
    /// S4-6 of the Veritas leaf-consolidation contract widens every fail-closed filter in this library
    /// from the content leaf to the family base, so the base must actually cover the leaf.
    /// </remarks>
    [TestMethod]
    public void ContentExceptionIsAMemberOfTheCborExceptionFamily()
    {
        CborContentException exception = Assert.ThrowsExactly<CborContentException>(
            () => ReadIntegerKeyedMap(TruncatedMapDocument, CborOptions.RfcCanonical));

        Assert.IsInstanceOfType<CborException>(exception);
    }


    /// <summary>
    /// The deterministic-encoding leaf is a member of the <see cref="CborException"/> family too, so the
    /// one widened filter covers both the malformed and the non-conformant refusal.
    /// </summary>
    /// <remarks>
    /// S4-6. The conformance leaf is deliberately unsealed in the substrate so profile-specific rule
    /// vocabularies can derive from it while staying catchable as this base.
    /// </remarks>
    [TestMethod]
    public void ConformanceExceptionIsAMemberOfTheCborExceptionFamily()
    {
        CborConformanceException exception = Assert.ThrowsExactly<CborConformanceException>(
            () => ReadIntegerKeyedMap(DuplicateKeyDocument, CborOptions.RfcCanonical));

        Assert.IsInstanceOfType<CborException>(exception);
    }


    /// <summary>
    /// The positive control for the fail-closed cases below: the well-formed, canonically encoded
    /// <c>sigPl</c> map parses to its model, which proves the three malformed variants that follow do
    /// reach the CBOR read rather than being rejected by some earlier shape check.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> clause 5.2.4 (<c>sigPl</c>; <c>addressCountry</c> is map key 1).
    /// </remarks>
    [TestMethod]
    public void SignatureProductionPlaceParsesTheCanonicalMap()
    {
        bool isParsed = CBAdESSerialization.TryParseSignatureProductionPlace(
            SignatureProductionPlaceDocument,
            out AdESSignatureProductionPlace? result);

        Assert.IsTrue(isParsed);
        Assert.IsNotNull(result);
        Assert.AreEqual("FI", result!.AddressCountry);
    }


    /// <summary>
    /// A <c>sigPl</c> map carrying its key twice makes the fail-closed parser return
    /// <see langword="false"/> rather than propagate the substrate's
    /// <see cref="CborConformanceException"/> — the duplicate-key refusal is inside the family the
    /// parser's filter catches.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> clause 4.7 (CB-4.7-02, deterministic encoding required) with
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>. S4-6
    /// requires the fail-closed parser to return false and never throw on each refusal.
    /// </remarks>
    [TestMethod]
    public void SignatureProductionPlaceParseFailsClosedOnADuplicateKey()
    {
        bool isParsed = CBAdESSerialization.TryParseSignatureProductionPlace(
            SignatureProductionPlaceDuplicateKeyDocument,
            out AdESSignatureProductionPlace? result);

        Assert.IsFalse(isParsed);
        Assert.IsNull(result);
    }


    /// <summary>
    /// A <c>sigPl</c> map whose two legal members are stated in descending key order makes the
    /// fail-closed parser return <see langword="false"/> rather than propagate the map-key-order
    /// refusal.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> clause 4.7 (CB-4.7-02) with
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>. S4-6.
    /// </remarks>
    [TestMethod]
    public void SignatureProductionPlaceParseFailsClosedOnDescendingKeys()
    {
        bool isParsed = CBAdESSerialization.TryParseSignatureProductionPlace(
            SignatureProductionPlaceDescendingKeyDocument,
            out AdESSignatureProductionPlace? result);

        Assert.IsFalse(isParsed);
        Assert.IsNull(result);
    }


    /// <summary>
    /// A <c>sigPl</c> map whose key is stated in a wider-than-necessary header makes the fail-closed
    /// parser return <see langword="false"/> rather than propagate the minimal-header refusal — the key
    /// value itself is a legal member, so only the encoding form is at fault.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> clause 4.7 (CB-4.7-02) with
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1">RFC 8949 §4.2.1</see>. S4-6.
    /// </remarks>
    [TestMethod]
    public void SignatureProductionPlaceParseFailsClosedOnANonMinimalHeader()
    {
        bool isParsed = CBAdESSerialization.TryParseSignatureProductionPlace(
            SignatureProductionPlaceNonMinimalHeaderDocument,
            out AdESSignatureProductionPlace? result);

        Assert.IsFalse(isParsed);
        Assert.IsNull(result);
    }
}

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Round-trip and strict-conformance tests for the CB-AdES stage-2 unsigned components this agent owns —
/// <c>sigPSt</c>, <c>valData</c>, <c>refs</c>, and the four <see cref="CBAdESTimestampContainer"/> alias
/// wrappers (<c>sigTst</c>, <c>arcTst</c>, <c>sigRTst</c>, <c>rfsTst</c>) — through their
/// <see cref="CBAdESSerialization"/> encode/parse bindings, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clauses 5.3.2, 5.3.4, Annex A.1.1, and the <c>tstContainer</c> occurrences at
/// clauses 5.3.3, 5.3.5.1, Annex A.1.2.1.1, Annex A.1.2.2.1.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Independent oracle.</strong> Every encode-byte-comparison test builds its expected CBOR bytes with a
/// freshly constructed <see cref="CborWriter"/> in canonical mode, written directly against the clause text
/// (CDDL and Table N/Table A.1 key assignments) — map keys are written as SPEC-TABLE LITERAL integers (e.g.
/// <c>1</c>, <c>2</c>, citing the table in a comment), never the model's own <c>*Key</c> constants — never by
/// calling <see cref="CBAdESSerialization"/>'s own private writers.
/// </para>
/// <para>
/// <strong>Firewalled parsing.</strong> Every round-trip and strict-negative test hands
/// <see cref="CBAdESSerialization"/>'s <c>TryParse*</c> methods bytes assembled by this file's own oracle
/// helpers, never bytes produced by this file's own calls into the matching <c>Encode*</c> method — the parser
/// is exercised from wire bytes only.
/// </para>
/// <para>
/// <strong>Digest fixtures.</strong> Every <see cref="DigestValue"/> a MODEL instance carries is a real SHA-256
/// digest computed through the registered <see cref="CryptographicKeyEvents"/> digest delegate seam (via
/// <see cref="CreateDigestAsync"/>), never a hand-rolled hash; negative tests that never construct a model
/// instance (pure wire-level malformed-byte injection) use plain literal byte arrays in the digest position,
/// since no digest semantics are being claimed there.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESUnsignedComponentSerializationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Encoding and parsing round-trip for the <c>sigPolDoc</c> arm (clause 5.3.2) with <c>spDSpec</c> absent.</summary>
    [TestMethod]
    public void SignaturePolicyStoreRoundTripsWithDocumentArmAndNoSpDSpec()
    {
        byte[] document = [0x01, 0x02, 0x03, 0x04];
        byte[] expected = BuildSignaturePolicyStoreBytes(isDocumentArm: true, document, localUri: null, spDSpec: null);
        var model = new CBAdESSignaturePolicyStore(new CBAdESSignaturePolicyStoreDocument(document));

        using PooledMemory encoded = CBAdESSerialization.EncodeSignaturePolicyStore(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(expected, out CBAdESSignaturePolicyStore? result);
        Assert.IsTrue(parsed);
        var documentArm = (CBAdESSignaturePolicyStoreDocument)result!.Content;
        Assert.IsTrue(document.AsSpan().SequenceEqual(documentArm.Document.Span));
        Assert.IsNull(result.SpDSpec);
    }


    /// <summary>Encoding and parsing round-trip for the <c>sigPolDoc</c> arm (clause 5.3.2) with <c>spDSpec</c> present.</summary>
    [TestMethod]
    public void SignaturePolicyStoreRoundTripsWithDocumentArmAndSpDSpec()
    {
        byte[] document = [0x05, 0x06];
        var spDSpecId = new Uri("https://policy.example.org/spec/v1");
        byte[] expected = BuildSignaturePolicyStoreBytes(isDocumentArm: true, document, localUri: null, spDSpecId);
        var model = new CBAdESSignaturePolicyStore(new CBAdESSignaturePolicyStoreDocument(document), new CBAdESObjectIdentifier(spDSpecId));

        using PooledMemory encoded = CBAdESSerialization.EncodeSignaturePolicyStore(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(expected, out CBAdESSignaturePolicyStore? result);
        Assert.IsTrue(parsed);
        Assert.AreEqual(spDSpecId, result!.SpDSpec!.Id);
    }


    /// <summary>
    /// Encoding and parsing round-trip for the <c>sigPolLocalURI</c> arm (clause 5.3.2, tag-32 URI) with
    /// <c>spDSpec</c> absent.
    /// </summary>
    [TestMethod]
    public void SignaturePolicyStoreRoundTripsWithLocalUriArmAndNoSpDSpec()
    {
        var localUri = new Uri("file:///var/policies/policy-1.der");
        byte[] expected = BuildSignaturePolicyStoreBytes(isDocumentArm: false, document: null, localUri, spDSpec: null);
        var model = new CBAdESSignaturePolicyStore(new CBAdESSignaturePolicyStoreLocalUri(localUri));

        using PooledMemory encoded = CBAdESSerialization.EncodeSignaturePolicyStore(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(expected, out CBAdESSignaturePolicyStore? result);
        Assert.IsTrue(parsed);
        var localUriArm = (CBAdESSignaturePolicyStoreLocalUri)result!.Content;
        Assert.AreEqual(localUri, localUriArm.Location);
    }


    /// <summary>Encoding and parsing round-trip for the <c>sigPolLocalURI</c> arm with <c>spDSpec</c> present.</summary>
    [TestMethod]
    public void SignaturePolicyStoreRoundTripsWithLocalUriArmAndSpDSpec()
    {
        var localUri = new Uri("file:///var/policies/policy-2.der");
        var spDSpecId = new Uri("urn:oid:1.2.3.4.5");
        byte[] expected = BuildSignaturePolicyStoreBytes(isDocumentArm: false, document: null, localUri, spDSpecId);
        var model = new CBAdESSignaturePolicyStore(new CBAdESSignaturePolicyStoreLocalUri(localUri), new CBAdESObjectIdentifier(spDSpecId));

        using PooledMemory encoded = CBAdESSerialization.EncodeSignaturePolicyStore(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(expected, out CBAdESSignaturePolicyStore? result);
        Assert.IsTrue(parsed);
        Assert.AreEqual(spDSpecId, result!.SpDSpec!.Id);
    }


    /// <summary>
    /// CB-5.3.2-01's exclusive choice: a <c>DocOrLocalURI</c> submap declaring both arms (map length 2) must
    /// fail closed.
    /// </summary>
    [TestMethod]
    public void ParseSignaturePolicyStoreFailsClosedWhenDocOrLocalUriHasBothArms()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // docOrLocalUri, Table 9.
        writer.WriteStartMap(2);
        writer.WriteInt32(1); // sigPolDoc, Table 9.
        writer.WriteByteString([0x01]);
        writer.WriteInt32(2); // sigPolLocalURI, Table 9.
        WriteUriTag(writer, new Uri("https://example.org/policy"));
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(writer.Encode(), out CBAdESSignaturePolicyStore? result);

        Assert.IsFalse(parsed, "A DocOrLocalURI submap declaring both arms must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// CB-5.3.2-01's exclusive choice: a <c>DocOrLocalURI</c> submap declaring neither arm (map length 0) must
    /// fail closed.
    /// </summary>
    [TestMethod]
    public void ParseSignaturePolicyStoreFailsClosedWhenDocOrLocalUriHasNoArms()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // docOrLocalUri, Table 9.
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(writer.Encode(), out CBAdESSignaturePolicyStore? result);

        Assert.IsFalse(parsed, "A DocOrLocalURI submap declaring neither arm must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>A <c>sigPSt</c> map carrying only the optional <c>spDSpec</c> member, omitting the required <c>docOrLocalUri</c>, must fail closed.</summary>
    [TestMethod]
    public void ParseSignaturePolicyStoreFailsClosedOnMissingRequiredDocOrLocalUri()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // spDSpec, Table 9.
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // id, Table 11.
        WriteUriTag(writer, new Uri("https://example.org/spec"));
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(writer.Encode(), out CBAdESSignaturePolicyStore? result);

        Assert.IsFalse(parsed, "A sigPSt map missing the required 'docOrLocalUri' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>The <c>sigPolLocalURI</c> arm written as an untagged text string instead of a tag-32 URI must fail closed.</summary>
    [TestMethod]
    public void ParseSignaturePolicyStoreFailsClosedOnMissingTag32ForLocalUri()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // docOrLocalUri, Table 9.
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // sigPolLocalURI, Table 9.
        writer.WriteTextString("file:///var/policies/policy.der"); // Missing the mandatory tag 32 wrapper.
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(writer.Encode(), out CBAdESSignaturePolicyStore? result);

        Assert.IsFalse(parsed, "An untagged text string in place of the tag-32 URI 'sigPolLocalURI' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>Trailing bytes after a complete <c>sigPSt</c> value must fail closed and must not leak a partial result.</summary>
    [TestMethod]
    public void ParseSignaturePolicyStoreFailsClosedOnTrailingData()
    {
        byte[] valid = BuildSignaturePolicyStoreBytes(isDocumentArm: true, [0x01], localUri: null, spDSpec: null);
        byte[] withTrailer = [.. valid, 0x00];

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(withTrailer, out CBAdESSignaturePolicyStore? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete sigPSt value must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>An indefinite-length <c>sigPSt</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void ParseSignaturePolicyStoreFailsClosedOnIndefiniteLengthMap()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(null);
        writer.WriteInt32(1); // docOrLocalUri, Table 9.
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // sigPolDoc, Table 9.
        writer.WriteByteString([0x01]);
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(writer.Encode(), out CBAdESSignaturePolicyStore? result);

        Assert.IsFalse(parsed, "An indefinite-length sigPSt map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
    }


    /// <summary>Adversarially deep CBOR array nesting at the top level must fail closed, not throw or crash.</summary>
    [TestMethod]
    public void ParseSignaturePolicyStoreFailsClosedOnDepthBombNesting()
    {
        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(BuildDeeplyNestedArrayBytes(10_000), out CBAdESSignaturePolicyStore? result);

        Assert.IsFalse(parsed, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
    }


    /// <summary>Truncated <c>sigPSt</c> bytes (a well-formed value with its final byte removed) must fail closed.</summary>
    [TestMethod]
    public void ParseSignaturePolicyStoreFailsClosedOnTruncatedInput()
    {
        byte[] valid = BuildSignaturePolicyStoreBytes(isDocumentArm: true, [0x01, 0x02, 0x03], localUri: null, spDSpec: null);
        byte[] truncated = valid[..^1];

        bool parsed = CBAdESSerialization.TryParseSignaturePolicyStore(truncated, out CBAdESSignaturePolicyStore? result);

        Assert.IsFalse(parsed, "Truncated sigPSt input must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// <c>valData</c> round-trips with <c>xVals</c> carrying both an <c>x509Cert</c> and an <c>otherCert</c>
    /// entry, in wire order (clause 5.3.4).
    /// </summary>
    [TestMethod]
    public void ValidationDataRoundTripsWithMultipleCertificateValuesInWireOrder()
    {
        byte[] x509 = [0x30, 0x82, 0x01, 0x00];
        byte[] other = [0x04, 0x02, 0xCA, 0xFE];
        byte[] expected = BuildValidationDataBytes(
            certificateEntries: [(1, x509), (2, other)], // x509Cert=1, otherCert=2, Table 10.
            crlValues: null, ocspValues: null, otherValues: null);

        var model = new CBAdESValidationData(certificateValues:
        [
            new CBAdESX509Certificate(new CBAdESPkiObject { Val = x509 }),
            new CBAdESOtherCertificate(new CBAdESPkiObject { Val = other })
        ]);

        using PooledMemory encoded = CBAdESSerialization.EncodeValidationData(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseValidationData(expected, out CBAdESValidationData? result);
        Assert.IsTrue(parsed);
        Assert.HasCount(2, result!.CertificateValues!);
        Assert.IsInstanceOfType<CBAdESX509Certificate>(result.CertificateValues![0]);
        Assert.IsInstanceOfType<CBAdESOtherCertificate>(result.CertificateValues[1]);
        Assert.IsTrue(x509.AsSpan().SequenceEqual(((CBAdESX509Certificate)result.CertificateValues[0]).Certificate.Val.Span));
        Assert.IsTrue(other.AsSpan().SequenceEqual(((CBAdESOtherCertificate)result.CertificateValues[1]).Certificate.Val.Span));
    }


    /// <summary><c>valData</c> round-trips with only <c>rVals.crlVals</c> present (clause 5.3.4).</summary>
    [TestMethod]
    public void ValidationDataRoundTripsWithCrlValuesOnly()
    {
        byte[] crl = [0x30, 0x10];
        byte[] expected = BuildValidationDataBytes(certificateEntries: null, crlValues: [crl], ocspValues: null, otherValues: null);
        var model = new CBAdESValidationData(revocationValues: new CBAdESRevocationValues(crlValues: [new CBAdESPkiObject { Val = crl }]));

        using PooledMemory encoded = CBAdESSerialization.EncodeValidationData(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseValidationData(expected, out CBAdESValidationData? result);
        Assert.IsTrue(parsed);
        Assert.IsTrue(crl.AsSpan().SequenceEqual(result!.RevocationValues!.CrlValues![0].Val.Span));
        Assert.IsNull(result.RevocationValues.OcspValues);
        Assert.IsNull(result.RevocationValues.OtherValues);
    }


    /// <summary><c>valData</c> round-trips with only <c>rVals.ocspVals</c> present (clause 5.3.4).</summary>
    [TestMethod]
    public void ValidationDataRoundTripsWithOcspValuesOnly()
    {
        byte[] ocsp = [0x30, 0x20];
        byte[] expected = BuildValidationDataBytes(certificateEntries: null, crlValues: null, ocspValues: [ocsp], otherValues: null);
        var model = new CBAdESValidationData(revocationValues: new CBAdESRevocationValues(ocspValues: [new CBAdESPkiObject { Val = ocsp }]));

        using PooledMemory encoded = CBAdESSerialization.EncodeValidationData(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseValidationData(expected, out CBAdESValidationData? result);
        Assert.IsTrue(parsed);
        Assert.IsTrue(ocsp.AsSpan().SequenceEqual(result!.RevocationValues!.OcspValues![0].Val.Span));
    }


    /// <summary><c>valData</c> round-trips with only <c>rVals.otherVals</c> present (clause 5.3.4).</summary>
    [TestMethod]
    public void ValidationDataRoundTripsWithOtherValuesOnly()
    {
        byte[] otherVal = [0x30, 0x30];
        byte[] expected = BuildValidationDataBytes(certificateEntries: null, crlValues: null, ocspValues: null, otherValues: [otherVal]);
        var model = new CBAdESValidationData(revocationValues: new CBAdESRevocationValues(otherValues: [new CBAdESPkiObject { Val = otherVal }]));

        using PooledMemory encoded = CBAdESSerialization.EncodeValidationData(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseValidationData(expected, out CBAdESValidationData? result);
        Assert.IsTrue(parsed);
        Assert.IsTrue(otherVal.AsSpan().SequenceEqual(result!.RevocationValues!.OtherValues![0].Val.Span));
    }


    /// <summary><c>valData</c> round-trips with all three <c>rVals</c> kinds combined (clause 5.3.4).</summary>
    [TestMethod]
    public void ValidationDataRoundTripsWithAllThreeRevocationValueKindsCombined()
    {
        byte[] crl = [0x01];
        byte[] ocsp = [0x02];
        byte[] otherVal = [0x03];
        byte[] expected = BuildValidationDataBytes(certificateEntries: null, crlValues: [crl], ocspValues: [ocsp], otherValues: [otherVal]);
        var model = new CBAdESValidationData(revocationValues: new CBAdESRevocationValues(
            crlValues: [new CBAdESPkiObject { Val = crl }],
            ocspValues: [new CBAdESPkiObject { Val = ocsp }],
            otherValues: [new CBAdESPkiObject { Val = otherVal }]));

        using PooledMemory encoded = CBAdESSerialization.EncodeValidationData(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseValidationData(expected, out CBAdESValidationData? result);
        Assert.IsTrue(parsed);
        Assert.IsTrue(crl.AsSpan().SequenceEqual(result!.RevocationValues!.CrlValues![0].Val.Span));
        Assert.IsTrue(ocsp.AsSpan().SequenceEqual(result.RevocationValues.OcspValues![0].Val.Span));
        Assert.IsTrue(otherVal.AsSpan().SequenceEqual(result.RevocationValues.OtherValues![0].Val.Span));
    }


    /// <summary><c>valData</c> round-trips with both <c>xVals</c> and <c>rVals</c> present (clause 5.3.4).</summary>
    [TestMethod]
    public void ValidationDataRoundTripsWithBothCertificateAndRevocationValues()
    {
        byte[] x509 = [0x30, 0x01];
        byte[] crl = [0x30, 0x02];
        byte[] expected = BuildValidationDataBytes(certificateEntries: [(1, x509)], crlValues: [crl], ocspValues: null, otherValues: null);
        var model = new CBAdESValidationData(
            certificateValues: [new CBAdESX509Certificate(new CBAdESPkiObject { Val = x509 })],
            revocationValues: new CBAdESRevocationValues(crlValues: [new CBAdESPkiObject { Val = crl }]));

        using PooledMemory encoded = CBAdESSerialization.EncodeValidationData(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseValidationData(expected, out CBAdESValidationData? result);
        Assert.IsTrue(parsed);
        Assert.HasCount(1, result!.CertificateValues!);
        Assert.HasCount(1, result.RevocationValues!.CrlValues!);
    }


    /// <summary>An empty <c>valData</c> map (0 members) violates CB-5.3.4-01/02 and must fail closed.</summary>
    [TestMethod]
    public void ParseValidationDataFailsClosedOnEmptyMap()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(0);
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseValidationData(writer.Encode(), out CBAdESValidationData? result);

        Assert.IsFalse(parsed, "An empty valData map must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>An empty <c>xVals</c> array violates the CDDL's <c>+X509OrOther</c> cardinality and must fail closed.</summary>
    [TestMethod]
    public void ParseValidationDataFailsClosedOnEmptyCertificateValuesArray()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // xVals, Table 10.
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseValidationData(writer.Encode(), out CBAdESValidationData? result);

        Assert.IsFalse(parsed, "An empty xVals array must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>An empty <c>rVals.crlVals</c> array violates CB-5.3.4-06 and must fail closed.</summary>
    [TestMethod]
    public void ParseValidationDataFailsClosedOnEmptyCrlValuesArray()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // rVals, Table 10.
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // crlVals, Table 10.
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseValidationData(writer.Encode(), out CBAdESValidationData? result);

        Assert.IsFalse(parsed, "An empty rVals.crlVals array must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>An <c>X509OrOther</c> entry declaring both arms (map length 2) must fail closed.</summary>
    [TestMethod]
    public void ParseValidationDataFailsClosedOnX509OrOtherEntryWithBothKeysPresent()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // xVals, Table 10.
        writer.WriteStartArray(1);
        writer.WriteStartMap(2);
        writer.WriteInt32(1); // x509Cert, Table 10.
        WritePkiObOracle(writer, [0x01]);
        writer.WriteInt32(2); // otherCert, Table 10.
        WritePkiObOracle(writer, [0x02]);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseValidationData(writer.Encode(), out CBAdESValidationData? result);

        Assert.IsFalse(parsed, "An X509OrOther entry declaring both arms must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>An <c>X509OrOther</c> entry declaring neither arm (map length 0) must fail closed.</summary>
    [TestMethod]
    public void ParseValidationDataFailsClosedOnX509OrOtherEntryWithNoKeysPresent()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // xVals, Table 10.
        writer.WriteStartArray(1);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseValidationData(writer.Encode(), out CBAdESValidationData? result);

        Assert.IsFalse(parsed, "An X509OrOther entry declaring neither arm must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>The <c>xVals</c> member written as a map instead of an array (wrong type per member) must fail closed.</summary>
    [TestMethod]
    public void ParseValidationDataFailsClosedOnWrongMajorTypeForXValsMember()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // xVals, Table 10.
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseValidationData(writer.Encode(), out CBAdESValidationData? result);

        Assert.IsFalse(parsed, "A map in place of the array-typed 'xVals' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>Trailing bytes after a complete <c>valData</c> value must fail closed.</summary>
    [TestMethod]
    public void ParseValidationDataFailsClosedOnTrailingData()
    {
        byte[] valid = BuildValidationDataBytes(certificateEntries: [(1, [0x01])], crlValues: null, ocspValues: null, otherValues: null);
        byte[] withTrailer = [.. valid, 0x00];

        bool parsed = CBAdESSerialization.TryParseValidationData(withTrailer, out CBAdESValidationData? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete valData value must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>An indefinite-length <c>valData</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void ParseValidationDataFailsClosedOnIndefiniteLengthMap()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(null);
        writer.WriteInt32(1); // xVals, Table 10.
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // x509Cert, Table 10.
        WritePkiObOracle(writer, [0x01]);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseValidationData(writer.Encode(), out CBAdESValidationData? result);

        Assert.IsFalse(parsed, "An indefinite-length valData map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
    }


    /// <summary>Adversarially deep CBOR array nesting at the top level must fail closed, not throw or crash.</summary>
    [TestMethod]
    public void ParseValidationDataFailsClosedOnDepthBombNesting()
    {
        bool parsed = CBAdESSerialization.TryParseValidationData(BuildDeeplyNestedArrayBytes(10_000), out CBAdESValidationData? result);

        Assert.IsFalse(parsed, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
    }


    /// <summary>Truncated <c>valData</c> bytes must fail closed.</summary>
    [TestMethod]
    public void ParseValidationDataFailsClosedOnTruncatedInput()
    {
        byte[] valid = BuildValidationDataBytes(certificateEntries: [(1, [0x01, 0x02, 0x03])], crlValues: null, ocspValues: null, otherValues: null);
        byte[] truncated = valid[..^1];

        bool parsed = CBAdESSerialization.TryParseValidationData(truncated, out CBAdESValidationData? result);

        Assert.IsFalse(parsed, "Truncated valData input must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary><c>CertId.kid</c>'s <c>int</c> arm round-trips within a <c>refs</c> map (Annex A.1.1).</summary>
    [TestMethod]
    public async Task ReferencesRoundTripsWithCertificateReferenceKidAsIntegerAndNoLocationHint()
    {
        DigestValue digest = await CreateDigestAsync("certificate one"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] digestBytes = digest.AsReadOnlySpan().ToArray();

        byte[] expected = BuildReferencesBytes(
            certificateReferenceWriters: [w => WriteCertIdOracle(w, WellKnownCoseAlgorithms.Sha256, digestBytes, writeKid: k => k.WriteInt32(7), x5u: null)],
            crlReferenceWriters: null, ocspReferenceWriters: null, otherReferenceItems: null);

#pragma warning disable CA2000 // Dispose objects before losing scope: ownership chains into 'references' below, disposed by the trailing 'using'.
        var certificateReference = new CBAdESCertificateReference(
            new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest),
            new CBAdESCertificateReferenceKeyIdentifierInteger(7));
        using var references = new CBAdESReferences(certificateReferences: [certificateReference]);
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseReferences(expected, BaseMemoryPool.Shared, out CBAdESReferences? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            Assert.AreEqual(new CBAdESCertificateReferenceKeyIdentifierInteger(7), result!.CertificateReferences![0].KeyIdentifier);
            Assert.IsTrue(digestBytes.AsSpan().SequenceEqual(result.CertificateReferences[0].Thumbprint.Digest.AsReadOnlySpan()));
        }
    }


    /// <summary>
    /// <c>CertId.kid</c>'s <c>tstr</c> arm round-trips together with the optional <c>x5u</c> location hint
    /// (Annex A.1.1).
    /// </summary>
    [TestMethod]
    public async Task ReferencesRoundTripsWithCertificateReferenceKidAsTextAndLocationHint()
    {
        DigestValue digest = await CreateDigestAsync("certificate two"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] digestBytes = digest.AsReadOnlySpan().ToArray();
        var locationHint = new Uri("https://example.org/certs/two");

        byte[] expected = BuildReferencesBytes(
            certificateReferenceWriters: [w => WriteCertIdOracle(w, WellKnownCoseAlgorithms.Sha256, digestBytes, writeKid: k => k.WriteTextString("key-id-two"), locationHint)],
            crlReferenceWriters: null, ocspReferenceWriters: null, otherReferenceItems: null);

#pragma warning disable CA2000 // Dispose objects before losing scope
        var certificateReference = new CBAdESCertificateReference(
            new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest),
            new CBAdESCertificateReferenceKeyIdentifierText("key-id-two"),
            locationHint);
        using var references = new CBAdESReferences(certificateReferences: [certificateReference]);
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseReferences(expected, BaseMemoryPool.Shared, out CBAdESReferences? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            Assert.AreEqual(new CBAdESCertificateReferenceKeyIdentifierText("key-id-two"), result!.CertificateReferences![0].KeyIdentifier);
            Assert.AreEqual(locationHint, result.CertificateReferences[0].LocationHint);
        }
    }


    /// <summary>
    /// <c>CertId.kid</c>'s <c>bstr</c> arm round-trips byte-exactly (CB-A.1.1-07's recommended, opaque
    /// <c>IssuerSerial</c> payload — never force-parsed).
    /// </summary>
    [TestMethod]
    public async Task ReferencesRoundTripsWithCertificateReferenceKidAsBytesIssuerSerialPlaceholder()
    {
        DigestValue digest = await CreateDigestAsync("certificate three"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] digestBytes = digest.AsReadOnlySpan().ToArray();
        byte[] issuerSerial = [0x30, 0x0A, 0x02, 0x01, 0x01, 0x02, 0x05, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];

        byte[] expected = BuildReferencesBytes(
            certificateReferenceWriters: [w => WriteCertIdOracle(w, WellKnownCoseAlgorithms.Sha256, digestBytes, writeKid: k => k.WriteByteString(issuerSerial), x5u: null)],
            crlReferenceWriters: null, ocspReferenceWriters: null, otherReferenceItems: null);

#pragma warning disable CA2000 // Dispose objects before losing scope
        var certificateReference = new CBAdESCertificateReference(
            new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest),
            new CBAdESCertificateReferenceKeyIdentifierBytes(issuerSerial));
        using var references = new CBAdESReferences(certificateReferences: [certificateReference]);
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseReferences(expected, BaseMemoryPool.Shared, out CBAdESReferences? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            var bytesArm = (CBAdESCertificateReferenceKeyIdentifierBytes)result!.CertificateReferences![0].KeyIdentifier!;
            Assert.IsTrue(issuerSerial.AsSpan().SequenceEqual(bytesArm.Value.Span));
        }
    }


    /// <summary>
    /// Multiple <c>xRefs</c> entries, one with <c>kid</c> absent, round-trip in exact wire order.
    /// </summary>
    [TestMethod]
    public async Task ReferencesRoundTripsWithMultipleCertificateReferencesIncludingKidAbsentInWireOrder()
    {
        DigestValue firstDigest = await CreateDigestAsync("certificate first"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        DigestValue secondDigest = await CreateDigestAsync("certificate second"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] firstDigestBytes = firstDigest.AsReadOnlySpan().ToArray();
        byte[] secondDigestBytes = secondDigest.AsReadOnlySpan().ToArray();

        byte[] expected = BuildReferencesBytes(
            certificateReferenceWriters:
            [
                w => WriteCertIdOracle(w, WellKnownCoseAlgorithms.Sha256, firstDigestBytes, writeKid: null, x5u: null),
                w => WriteCertIdOracle(w, WellKnownCoseAlgorithms.Sha384, secondDigestBytes, writeKid: k => k.WriteInt32(1), x5u: null)
            ],
            crlReferenceWriters: null, ocspReferenceWriters: null, otherReferenceItems: null);

#pragma warning disable CA2000 // Dispose objects before losing scope
        var firstReference = new CBAdESCertificateReference(new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), firstDigest));
        var secondReference = new CBAdESCertificateReference(
            new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha384), secondDigest),
            new CBAdESCertificateReferenceKeyIdentifierInteger(1));
        using var references = new CBAdESReferences(certificateReferences: [firstReference, secondReference]);
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseReferences(expected, BaseMemoryPool.Shared, out CBAdESReferences? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            Assert.HasCount(2, result!.CertificateReferences!);
            Assert.IsNull(result.CertificateReferences![0].KeyIdentifier, "The first entry's kid must round-trip as absent.");
            Assert.IsTrue(firstDigestBytes.AsSpan().SequenceEqual(result.CertificateReferences[0].Thumbprint.Digest.AsReadOnlySpan()));
            Assert.IsTrue(secondDigestBytes.AsSpan().SequenceEqual(result.CertificateReferences[1].Thumbprint.Digest.AsReadOnlySpan()));
        }
    }


    /// <summary><c>CRLRef</c> round-trips without the optional <c>crlId</c> member (Annex A.1.1).</summary>
    [TestMethod]
    public async Task ReferencesRoundTripsWithCrlReferenceWithoutCrlId()
    {
        DigestValue digest = await CreateDigestAsync("crl one"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] digestBytes = digest.AsReadOnlySpan().ToArray();

        byte[] expected = BuildReferencesBytes(
            certificateReferenceWriters: null,
            crlReferenceWriters: [w => WriteCrlRefOracle(w, WellKnownCoseAlgorithms.Sha256, digestBytes, writeCrlId: null)],
            ocspReferenceWriters: null, otherReferenceItems: null);

#pragma warning disable CA2000 // Dispose objects before losing scope
        var crlReference = new CBAdESCrlReference(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);
        var revocationReferences = new CBAdESRevocationReferences(crlReferences: [crlReference]);
        using var references = new CBAdESReferences(revocationReferences: revocationReferences);
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseReferences(expected, BaseMemoryPool.Shared, out CBAdESReferences? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            Assert.IsNull(result!.RevocationReferences!.CrlReferences![0].CrlIdentifier);
            Assert.IsTrue(digestBytes.AsSpan().SequenceEqual(result.RevocationReferences.CrlReferences[0].Digest.AsReadOnlySpan()));
        }
    }


    /// <summary>
    /// <c>CRLRef</c> round-trips with every <c>crlId</c> member present, including the mandatory tag-0
    /// <c>issueTime</c> (Annex A.1.1).
    /// </summary>
    [TestMethod]
    public async Task ReferencesRoundTripsWithCrlReferenceWithCrlIdAllMembers()
    {
        DigestValue digest = await CreateDigestAsync("crl two"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] digestBytes = digest.AsReadOnlySpan().ToArray();
        byte[] issuer = [0x30, 0x0B, 0x31, 0x09];
        var issueTime = new DateTimeOffset(2026, 1, 15, 12, 30, 0, TimeSpan.Zero);
        var locationHint = new Uri("https://example.org/crls/two");

        byte[] expected = BuildReferencesBytes(
            certificateReferenceWriters: null,
            crlReferenceWriters: [w => WriteCrlRefOracle(w, WellKnownCoseAlgorithms.Sha256, digestBytes,
                writeCrlId: c => WriteCrlIdOracle(c, issuer, issueTime, number: 7UL, locationHint))],
            ocspReferenceWriters: null, otherReferenceItems: null);

#pragma warning disable CA2000 // Dispose objects before losing scope
        var crlReference = new CBAdESCrlReference(
            new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
            digest,
            new CBAdESCrlIdentifier { Issuer = issuer, IssueTime = issueTime, Number = 7UL, LocationHint = locationHint });
        var revocationReferences = new CBAdESRevocationReferences(crlReferences: [crlReference]);
        using var references = new CBAdESReferences(revocationReferences: revocationReferences);
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseReferences(expected, BaseMemoryPool.Shared, out CBAdESReferences? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            CBAdESCrlIdentifier crlId = result!.RevocationReferences!.CrlReferences![0].CrlIdentifier!;
            Assert.IsTrue(issuer.AsSpan().SequenceEqual(crlId.Issuer.Span));
            Assert.AreEqual(issueTime, crlId.IssueTime);
            Assert.AreEqual(7UL, crlId.Number);
            Assert.AreEqual(locationHint, crlId.LocationHint);
        }
    }


    /// <summary>
    /// Decouples one assertion from <see cref="WriteTDateOracle"/>'s format string, which mirrors the
    /// production <c>WriteTDate</c> format string exactly (a shared defect in both could otherwise hide
    /// behind it): encodes a <c>CRLId.issueTime</c> tag-0 <c>tdate</c> for the FIXED
    /// <see cref="TestClock.CanonicalEpoch"/> instant and asserts the resulting bytes contain a HAND-WRITTEN
    /// literal byte sequence, assembled directly from
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.1">RFC 8949, clause 3.4.1</see> (CBOR
    /// tag 0, "standard date/time string") and
    /// <see href="https://www.rfc-editor.org/rfc/rfc3339">RFC 3339</see>'s <c>date-time</c> production, never
    /// through the shared oracle helper.
    /// </summary>
    /// <remarks>
    /// <see cref="TestClock.CanonicalEpoch"/> is <c>2026-06-01T12:00:00Z</c> (UTC). CBOR tag 0 (RFC 8949
    /// clause 3.4.1) is major type 6 with tag value 0, which fits the single-byte header range
    /// (<c>0xC0 | 0 = 0xC0</c>). RFC 3339's <c>date-time</c> production for this instant, with zero
    /// fractional seconds and the <c>"Z"</c> UTC designator, is the 20-character ASCII text
    /// <c>"2026-06-01T12:00:00Z"</c>, itself a CBOR text string (major type 3) whose length (20) fits the
    /// single-byte header range (<c>0x60 | 20 = 0x74</c>).
    /// </remarks>
    [TestMethod]
    public async Task CrlIdentifierIssueTimeEncodesToHandWrittenRfc8949TDateLiteralBytes()
    {
        byte[] expectedTDateBytes =
        [
            0xC0, //tag(0) -- RFC 8949 clause 3.4.1, "standard date/time string".
            0x74, //tstr, length 20.
            0x32, 0x30, 0x32, 0x36, 0x2D, 0x30, 0x36, 0x2D, 0x30, 0x31, //"2026-06-01"
            0x54,                                                       //"T"
            0x31, 0x32, 0x3A, 0x30, 0x30, 0x3A, 0x30, 0x30,             //"12:00:00"
            0x5A                                                        //"Z"
        ];

        DigestValue digest = await CreateDigestAsync("crl tdate literal"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] issuer = [0x30, 0x0B, 0x31, 0x09];

#pragma warning disable CA2000 // Dispose objects before losing scope: ownership chains into 'references' below, disposed by the trailing 'using'.
        var crlReference = new CBAdESCrlReference(
            new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
            digest,
            new CBAdESCrlIdentifier { Issuer = issuer, IssueTime = TestClock.CanonicalEpoch });
        var revocationReferences = new CBAdESRevocationReferences(crlReferences: [crlReference]);
        using var references = new CBAdESReferences(revocationReferences: revocationReferences);
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);

        Assert.IsGreaterThanOrEqualTo(
            0, encoded.AsReadOnlySpan().IndexOf(expectedTDateBytes),
            "The encoded CRLId.issueTime tdate bytes must contain the hand-written RFC 8949/RFC 3339 literal exactly.");
    }


    /// <summary><c>OCSPRef</c> round-trips with a by-name responder identifier (Annex A.1.1).</summary>
    [TestMethod]
    public async Task ReferencesRoundTripsWithOcspReferenceResponderByName()
    {
        DigestValue digest = await CreateDigestAsync("ocsp one"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] digestBytes = digest.AsReadOnlySpan().ToArray();
        byte[] responderName = [0x30, 0x0B, 0x31, 0x09];
        var producedAt = new DateTimeOffset(2026, 2, 1, 9, 0, 0, TimeSpan.Zero);

        byte[] expected = BuildReferencesBytes(
            certificateReferenceWriters: null, crlReferenceWriters: null,
            ocspReferenceWriters: [w => WriteOcspRefOracle(w, WellKnownCoseAlgorithms.Sha256, digestBytes,
                writeOcspId: o => WriteOcspIdOracle(o, r => WriteResponderByNameOracle(r, responderName), producedAt, locationHint: null))],
            otherReferenceItems: null);

#pragma warning disable CA2000 // Dispose objects before losing scope
        var ocspReference = new CBAdESOcspReference(
            new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
            digest,
            new CBAdESOcspIdentifier(new CBAdESOcspResponderIdentifierByName(responderName), producedAt));
        var revocationReferences = new CBAdESRevocationReferences(ocspReferences: [ocspReference]);
        using var references = new CBAdESReferences(revocationReferences: revocationReferences);
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseReferences(expected, BaseMemoryPool.Shared, out CBAdESReferences? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            var byName = (CBAdESOcspResponderIdentifierByName)result!.RevocationReferences!.OcspReferences![0].OcspIdentifier.Responder;
            Assert.IsTrue(responderName.AsSpan().SequenceEqual(byName.Name.Span));
            Assert.AreEqual(producedAt, result.RevocationReferences.OcspReferences[0].OcspIdentifier.ProducedAt);
        }
    }


    /// <summary>
    /// D8 (contract R-6, RULED): <c>OCSPRef</c>'s by-key responder identifier round-trips the raw DER
    /// <c>ResponderID.byKey</c> bytes byte-exactly — no base64 transformation in either direction.
    /// </summary>
    [TestMethod]
    public async Task ReferencesRoundTripsWithOcspReferenceResponderByKeyPreservesRawDerBytes()
    {
        DigestValue digest = await CreateDigestAsync("ocsp two"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] digestBytes = digest.AsReadOnlySpan().ToArray();
        byte[] keyDigest = [0x04, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        var producedAt = new DateTimeOffset(2026, 2, 2, 10, 0, 0, TimeSpan.Zero);
        var locationHint = new Uri("https://example.org/ocsp/two");

        byte[] expected = BuildReferencesBytes(
            certificateReferenceWriters: null, crlReferenceWriters: null,
            ocspReferenceWriters: [w => WriteOcspRefOracle(w, WellKnownCoseAlgorithms.Sha256, digestBytes,
                writeOcspId: o => WriteOcspIdOracle(o, r => WriteResponderByKeyOracle(r, keyDigest), producedAt, locationHint))],
            otherReferenceItems: null);

#pragma warning disable CA2000 // Dispose objects before losing scope
        var ocspReference = new CBAdESOcspReference(
            new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
            digest,
            new CBAdESOcspIdentifier(new CBAdESOcspResponderIdentifierByKey(keyDigest), producedAt, locationHint));
        var revocationReferences = new CBAdESRevocationReferences(ocspReferences: [ocspReference]);
        using var references = new CBAdESReferences(revocationReferences: revocationReferences);
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "D8: the encoded byKey bytes must be the raw DER bytes, not a base64 transformation.");

        bool parsed = CBAdESSerialization.TryParseReferences(expected, BaseMemoryPool.Shared, out CBAdESReferences? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            var byKey = (CBAdESOcspResponderIdentifierByKey)result!.RevocationReferences!.OcspReferences![0].OcspIdentifier.Responder;
            Assert.IsTrue(keyDigest.AsSpan().SequenceEqual(byKey.KeyDigest.Span), "D8: the parsed byKey bytes must equal the raw DER bytes byte-exactly.");
            Assert.AreEqual(locationHint, result.RevocationReferences.OcspReferences[0].OcspIdentifier.LocationHint);
        }
    }


    /// <summary>
    /// <c>otherRefs</c> items round-trip as opaque, byte-exact CBOR values (leg-5 trap 3: not OCSP-only,
    /// CB-A.1.1-29).
    /// </summary>
    [TestMethod]
    public void ReferencesRoundTripsWithOtherReferencesOpaqueBytes()
    {
        var itemWriter = new CborWriter(CborConformanceMode.Canonical);
        itemWriter.WriteStartArray(2);
        itemWriter.WriteInt32(42);
        itemWriter.WriteTextString("alternative validation data");
        itemWriter.WriteEndArray();
        byte[] otherItem = itemWriter.Encode();

        byte[] expected = BuildReferencesBytes(
            certificateReferenceWriters: null, crlReferenceWriters: null, ocspReferenceWriters: null,
            otherReferenceItems: [otherItem]);

#pragma warning disable CA2000 // Dispose objects before losing scope: ownership chains into 'references' below, disposed by the trailing 'using'.
        using var references = new CBAdESReferences(revocationReferences: new CBAdESRevocationReferences(otherReferences: [otherItem]));
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseReferences(expected, BaseMemoryPool.Shared, out CBAdESReferences? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            Assert.IsTrue(otherItem.AsSpan().SequenceEqual(result!.RevocationReferences!.OtherReferences![0].Span));
        }
    }


    /// <summary>
    /// <c>refs</c> round-trips with <c>xRefs</c> present alongside an <c>rRefs</c> carrying all three
    /// revocation-reference kinds combined (Annex A.1.1).
    /// </summary>
    [TestMethod]
    public async Task ReferencesRoundTripsWithCertificateAndAllThreeRevocationReferenceKindsCombined()
    {
        DigestValue certificateDigest = await CreateDigestAsync("combined certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        DigestValue crlDigest = await CreateDigestAsync("combined crl"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        DigestValue ocspDigest = await CreateDigestAsync("combined ocsp"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] certificateDigestBytes = certificateDigest.AsReadOnlySpan().ToArray();
        byte[] crlDigestBytes = crlDigest.AsReadOnlySpan().ToArray();
        byte[] ocspDigestBytes = ocspDigest.AsReadOnlySpan().ToArray();
        var producedAt = new DateTimeOffset(2026, 3, 1, 0, 0, 0, TimeSpan.Zero);
        byte[] otherItem = [0xF5]; // CBOR 'true' — a minimal, opaque, self-contained item.

        byte[] expected = BuildReferencesBytes(
            certificateReferenceWriters: [w => WriteCertIdOracle(w, WellKnownCoseAlgorithms.Sha256, certificateDigestBytes, writeKid: null, x5u: null)],
            crlReferenceWriters: [w => WriteCrlRefOracle(w, WellKnownCoseAlgorithms.Sha256, crlDigestBytes, writeCrlId: null)],
            ocspReferenceWriters: [w => WriteOcspRefOracle(w, WellKnownCoseAlgorithms.Sha256, ocspDigestBytes,
                o => WriteOcspIdOracle(o, r => WriteResponderByNameOracle(r, [0x30, 0x00]), producedAt, locationHint: null))],
            otherReferenceItems: [otherItem]);

#pragma warning disable CA2000 // Dispose objects before losing scope
        var certificateReference = new CBAdESCertificateReference(new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), certificateDigest));
        var crlReference = new CBAdESCrlReference(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), crlDigest);
        var ocspReference = new CBAdESOcspReference(
            new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), ocspDigest,
            new CBAdESOcspIdentifier(new CBAdESOcspResponderIdentifierByName(new byte[] { 0x30, 0x00 }), producedAt));
        var revocationReferences = new CBAdESRevocationReferences(crlReferences: [crlReference], ocspReferences: [ocspReference], otherReferences: [otherItem]);
        using var references = new CBAdESReferences(certificateReferences: [certificateReference], revocationReferences: revocationReferences);
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferences(references, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseReferences(expected, BaseMemoryPool.Shared, out CBAdESReferences? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            Assert.HasCount(1, result!.CertificateReferences!);
            Assert.HasCount(1, result.RevocationReferences!.CrlReferences!);
            Assert.HasCount(1, result.RevocationReferences.OcspReferences!);
            Assert.HasCount(1, result.RevocationReferences.OtherReferences!);
        }
    }


    /// <summary>An empty <c>refs</c> map (0 members) violates CB-A.1.1-04 and must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnEmptyMap()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(0);
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "An empty refs map must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An empty <c>xRefs</c> array violates CB-A.1.1-05 and must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnEmptyCertificateReferencesArray()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // xRefs, Table A.1 (refs).
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "An empty xRefs array must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An empty <c>rRefs</c> map (0 members) violates CB-A.1.1-09 and must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnEmptyRevocationReferencesMap()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // rRefs, Table A.1 (refs).
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "An empty rRefs map must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An empty <c>crlRefs</c> array violates CB-A.1.1-10 and must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnEmptyCrlReferencesArray()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // rRefs, Table A.1 (refs).
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // crlRefs, Table A.1 (rRefs).
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "An empty crlRefs array must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An empty <c>ocspRefs</c> array violates CB-A.1.1-19 and must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnEmptyOcspReferencesArray()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // rRefs, Table A.1 (refs).
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // ocspRefs, Table A.1 (rRefs).
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "An empty ocspRefs array must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An empty <c>otherRefs</c> array violates the CDDL's <c>+</c> cardinality and must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnEmptyOtherReferencesArray()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // rRefs, Table A.1 (refs).
        writer.WriteStartMap(1);
        writer.WriteInt32(3); // otherRefs, Table A.1 (rRefs).
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "An empty otherRefs array must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>A <c>CertId</c> map omitting the required <c>x5t</c> member must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnMissingRequiredThumbprintInCertId()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // xRefs, Table A.1 (refs).
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(3); // x5u, Table A.1 (CertId) -- present without the mandatory x5t.
        WriteUriTag(writer, new Uri("https://example.org/cert"));
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "A CertId map missing the required x5t member must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>A <c>CRLId</c> map omitting the required <c>issuer</c> member must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnMissingRequiredIssuerInCrlId()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // rRefs, Table A.1 (refs).
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // crlRefs, Table A.1 (rRefs).
        writer.WriteStartArray(1);
        writer.WriteStartMap(2);
        writer.WriteInt32(1); // digAlgVal, Table A.1 (CRLRef).
        WriteHashAlgorithmDigestPairOracle(writer, WellKnownCoseAlgorithms.Sha256, [0x01]);
        writer.WriteInt32(2); // crlId, Table A.1 (CRLRef).
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // issueTime, Table A.1 (CRLId) -- present without the mandatory issuer.
        WriteTDateOracle(writer, TestClock.CanonicalEpoch);
        writer.WriteEndMap();
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "A CRLId map missing the required issuer member must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An <c>OCSPId</c> map omitting the required <c>responderChoice</c> member must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnMissingRequiredResponderInOcspId()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // rRefs, Table A.1 (refs).
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // ocspRefs, Table A.1 (rRefs).
        writer.WriteStartArray(1);
        writer.WriteStartMap(2);
        writer.WriteInt32(1); // digAlgVal, Table A.1 (OCSPRef).
        WriteHashAlgorithmDigestPairOracle(writer, WellKnownCoseAlgorithms.Sha256, [0x01]);
        writer.WriteInt32(2); // ocspId, Table A.1 (OCSPRef).
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // producedAt, Table A.1 (OCSPId) -- present without the mandatory responderChoice.
        WriteTDateOracle(writer, TestClock.CanonicalEpoch);
        writer.WriteEndMap();
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "An OCSPId map missing the required responderChoice member must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>A <c>ResponderIdChoice</c> map keyed neither 1 (<c>responderIdByName</c>) nor 2 (<c>responderIdByKey</c>) must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnUnknownResponderIdChoiceKey()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // rRefs, Table A.1 (refs).
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // ocspRefs, Table A.1 (rRefs).
        writer.WriteStartArray(1);
        writer.WriteStartMap(2);
        writer.WriteInt32(1); // digAlgVal, Table A.1 (OCSPRef).
        WriteHashAlgorithmDigestPairOracle(writer, WellKnownCoseAlgorithms.Sha256, [0x01]);
        writer.WriteInt32(2); // ocspId, Table A.1 (OCSPRef).
        writer.WriteStartMap(2);
        writer.WriteInt32(1); // responderChoice, Table A.1 (OCSPId).
        writer.WriteStartMap(1);
        writer.WriteInt32(3); // Neither responderIdByName (1) nor responderIdByKey (2).
        writer.WriteByteString([0x01]);
        writer.WriteEndMap();
        writer.WriteInt32(2); // producedAt, Table A.1 (OCSPId).
        WriteTDateOracle(writer, TestClock.CanonicalEpoch);
        writer.WriteEndMap();
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "An unknown ResponderIdChoice key must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>The <c>x5t</c> digest value written as a text string instead of a byte string must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnWrongMajorTypeForThumbprintDigestValue()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // xRefs, Table A.1 (refs).
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // x5t, Table A.1 (CertId).
        writer.WriteStartArray(2);
        writer.WriteInt32(WellKnownCoseAlgorithms.Sha256);
        writer.WriteTextString("not a byte string");
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "A text string in place of the byte-string x5t digest value must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>Trailing bytes after a complete <c>refs</c> value must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnTrailingData()
    {
        byte[] valid = BuildReferencesBytes(
            certificateReferenceWriters: [w => WriteCertIdOracle(w, WellKnownCoseAlgorithms.Sha256, new byte[32], writeKid: null, x5u: null)],
            crlReferenceWriters: null, ocspReferenceWriters: null, otherReferenceItems: null);
        byte[] withTrailer = [.. valid, 0x00];

        bool parsed = CBAdESSerialization.TryParseReferences(withTrailer, BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete refs value must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An indefinite-length <c>refs</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnIndefiniteLengthMap()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(null);
        writer.WriteInt32(1); // xRefs, Table A.1 (refs).
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // x5t, Table A.1 (CertId).
        WriteHashAlgorithmDigestPairOracle(writer, WellKnownCoseAlgorithms.Sha256, new byte[32]);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseReferences(writer.Encode(), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "An indefinite-length refs map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>Adversarially deep CBOR array nesting at the top level must fail closed, not throw or crash.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnDepthBombNesting()
    {
        bool parsed = CBAdESSerialization.TryParseReferences(BuildDeeplyNestedArrayBytes(10_000), BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>Truncated <c>refs</c> bytes must fail closed.</summary>
    [TestMethod]
    public void ParseReferencesFailsClosedOnTruncatedInput()
    {
        byte[] valid = BuildReferencesBytes(
            certificateReferenceWriters: [w => WriteCertIdOracle(w, WellKnownCoseAlgorithms.Sha256, new byte[32], writeKid: null, x5u: null)],
            crlReferenceWriters: null, ocspReferenceWriters: null, otherReferenceItems: null);
        byte[] truncated = valid[..^1];

        bool parsed = CBAdESSerialization.TryParseReferences(truncated, BaseMemoryPool.Shared, out CBAdESReferences? result);

        Assert.IsFalse(parsed, "Truncated refs input must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary><c>sigTst</c>'s wrapper codec round-trips through <see cref="CBAdESTimestampContainer"/>, disposing its parsed result.</summary>
    [TestMethod]
    public void SignatureTimestampRoundTripsThroughWrapperCodec()
    {
        byte[] expected = BuildMinimalTimestampContainerBytes();

        //CA2000: ownership of the inline CBAdESTimestampContainer transfers immediately into 'model' below,
        //disposed by the leading 'using'; the analyzer does not see through the nested-call argument.
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var model = new CBAdESSignatureTimestamp(CreateTimestampContainerFixture());
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeSignatureTimestamp(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseSignatureTimestamp(expected, out CBAdESSignatureTimestamp? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            Assert.HasCount(1, result!.TimestampContainer.TstTokens);
        }
    }


    /// <summary><c>arcTst</c>'s wrapper codec round-trips through <see cref="CBAdESTimestampContainer"/>, disposing its parsed result.</summary>
    [TestMethod]
    public void ArchiveTimestampRoundTripsThroughWrapperCodec()
    {
        byte[] expected = BuildMinimalTimestampContainerBytes();

        //CA2000: ownership of the inline CBAdESTimestampContainer transfers immediately into 'model' below,
        //disposed by the leading 'using'; the analyzer does not see through the nested-call argument.
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var model = new CBAdESArchiveTimestamp(CreateTimestampContainerFixture());
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeArchiveTimestamp(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseArchiveTimestamp(expected, out CBAdESArchiveTimestamp? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            Assert.HasCount(1, result!.TimestampContainer.TstTokens);
        }
    }


    /// <summary><c>sigRTst</c>'s wrapper codec round-trips through <see cref="CBAdESTimestampContainer"/>, disposing its parsed result.</summary>
    [TestMethod]
    public void SignatureAndReferencesTimestampRoundTripsThroughWrapperCodec()
    {
        byte[] expected = BuildMinimalTimestampContainerBytes();

        //CA2000: ownership of the inline CBAdESTimestampContainer transfers immediately into 'model' below,
        //disposed by the leading 'using'; the analyzer does not see through the nested-call argument.
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var model = new CBAdESSignatureAndReferencesTimestamp(CreateTimestampContainerFixture());
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeSignatureAndReferencesTimestamp(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseSignatureAndReferencesTimestamp(expected, out CBAdESSignatureAndReferencesTimestamp? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            Assert.HasCount(1, result!.TimestampContainer.TstTokens);
        }
    }


    /// <summary><c>rfsTst</c>'s wrapper codec round-trips through <see cref="CBAdESTimestampContainer"/>, disposing its parsed result.</summary>
    [TestMethod]
    public void ReferencesTimestampRoundTripsThroughWrapperCodec()
    {
        byte[] expected = BuildMinimalTimestampContainerBytes();

        //CA2000: ownership of the inline CBAdESTimestampContainer transfers immediately into 'model' below,
        //disposed by the leading 'using'; the analyzer does not see through the nested-call argument.
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var model = new CBAdESReferencesTimestamp(CreateTimestampContainerFixture());
#pragma warning restore CA2000 // Dispose objects before losing scope

        using PooledMemory encoded = CBAdESSerialization.EncodeReferencesTimestamp(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()));

        bool parsed = CBAdESSerialization.TryParseReferencesTimestamp(expected, out CBAdESReferencesTimestamp? result);
        Assert.IsTrue(parsed);
        using(result)
        {
            Assert.HasCount(1, result!.TimestampContainer.TstTokens);
        }
    }


    /// <summary><c>sigTst</c>'s wrapper <c>TryParse</c> fails closed on trailing bytes.</summary>
    [TestMethod]
    public void ParseSignatureTimestampFailsClosedOnTrailingData() =>
        AssertWrapperFailsClosedOnTrailingData<CBAdESSignatureTimestamp>(CBAdESSerialization.TryParseSignatureTimestamp);


    /// <summary><c>sigTst</c>'s wrapper <c>TryParse</c> fails closed on an indefinite-length container.</summary>
    [TestMethod]
    public void ParseSignatureTimestampFailsClosedOnIndefiniteLengthContainer() =>
        AssertWrapperFailsClosedOnIndefiniteLength<CBAdESSignatureTimestamp>(CBAdESSerialization.TryParseSignatureTimestamp);


    /// <summary><c>sigTst</c>'s wrapper <c>TryParse</c> fails closed on adversarially deep nesting.</summary>
    [TestMethod]
    public void ParseSignatureTimestampFailsClosedOnDepthBombNesting() =>
        AssertWrapperFailsClosedOnDepthBomb<CBAdESSignatureTimestamp>(CBAdESSerialization.TryParseSignatureTimestamp);


    /// <summary><c>sigTst</c>'s wrapper <c>TryParse</c> fails closed on truncated input.</summary>
    [TestMethod]
    public void ParseSignatureTimestampFailsClosedOnTruncatedInput() =>
        AssertWrapperFailsClosedOnTruncatedInput<CBAdESSignatureTimestamp>(CBAdESSerialization.TryParseSignatureTimestamp);


    /// <summary><c>arcTst</c>'s wrapper <c>TryParse</c> fails closed on trailing bytes.</summary>
    [TestMethod]
    public void ParseArchiveTimestampFailsClosedOnTrailingData() =>
        AssertWrapperFailsClosedOnTrailingData<CBAdESArchiveTimestamp>(CBAdESSerialization.TryParseArchiveTimestamp);


    /// <summary><c>arcTst</c>'s wrapper <c>TryParse</c> fails closed on an indefinite-length container.</summary>
    [TestMethod]
    public void ParseArchiveTimestampFailsClosedOnIndefiniteLengthContainer() =>
        AssertWrapperFailsClosedOnIndefiniteLength<CBAdESArchiveTimestamp>(CBAdESSerialization.TryParseArchiveTimestamp);


    /// <summary><c>arcTst</c>'s wrapper <c>TryParse</c> fails closed on adversarially deep nesting.</summary>
    [TestMethod]
    public void ParseArchiveTimestampFailsClosedOnDepthBombNesting() =>
        AssertWrapperFailsClosedOnDepthBomb<CBAdESArchiveTimestamp>(CBAdESSerialization.TryParseArchiveTimestamp);


    /// <summary><c>arcTst</c>'s wrapper <c>TryParse</c> fails closed on truncated input.</summary>
    [TestMethod]
    public void ParseArchiveTimestampFailsClosedOnTruncatedInput() =>
        AssertWrapperFailsClosedOnTruncatedInput<CBAdESArchiveTimestamp>(CBAdESSerialization.TryParseArchiveTimestamp);


    /// <summary><c>sigRTst</c>'s wrapper <c>TryParse</c> fails closed on trailing bytes.</summary>
    [TestMethod]
    public void ParseSignatureAndReferencesTimestampFailsClosedOnTrailingData() =>
        AssertWrapperFailsClosedOnTrailingData<CBAdESSignatureAndReferencesTimestamp>(CBAdESSerialization.TryParseSignatureAndReferencesTimestamp);


    /// <summary><c>sigRTst</c>'s wrapper <c>TryParse</c> fails closed on an indefinite-length container.</summary>
    [TestMethod]
    public void ParseSignatureAndReferencesTimestampFailsClosedOnIndefiniteLengthContainer() =>
        AssertWrapperFailsClosedOnIndefiniteLength<CBAdESSignatureAndReferencesTimestamp>(CBAdESSerialization.TryParseSignatureAndReferencesTimestamp);


    /// <summary><c>sigRTst</c>'s wrapper <c>TryParse</c> fails closed on adversarially deep nesting.</summary>
    [TestMethod]
    public void ParseSignatureAndReferencesTimestampFailsClosedOnDepthBombNesting() =>
        AssertWrapperFailsClosedOnDepthBomb<CBAdESSignatureAndReferencesTimestamp>(CBAdESSerialization.TryParseSignatureAndReferencesTimestamp);


    /// <summary><c>sigRTst</c>'s wrapper <c>TryParse</c> fails closed on truncated input.</summary>
    [TestMethod]
    public void ParseSignatureAndReferencesTimestampFailsClosedOnTruncatedInput() =>
        AssertWrapperFailsClosedOnTruncatedInput<CBAdESSignatureAndReferencesTimestamp>(CBAdESSerialization.TryParseSignatureAndReferencesTimestamp);


    /// <summary><c>rfsTst</c>'s wrapper <c>TryParse</c> fails closed on trailing bytes.</summary>
    [TestMethod]
    public void ParseReferencesTimestampFailsClosedOnTrailingData() =>
        AssertWrapperFailsClosedOnTrailingData<CBAdESReferencesTimestamp>(CBAdESSerialization.TryParseReferencesTimestamp);


    /// <summary><c>rfsTst</c>'s wrapper <c>TryParse</c> fails closed on an indefinite-length container.</summary>
    [TestMethod]
    public void ParseReferencesTimestampFailsClosedOnIndefiniteLengthContainer() =>
        AssertWrapperFailsClosedOnIndefiniteLength<CBAdESReferencesTimestamp>(CBAdESSerialization.TryParseReferencesTimestamp);


    /// <summary><c>rfsTst</c>'s wrapper <c>TryParse</c> fails closed on adversarially deep nesting.</summary>
    [TestMethod]
    public void ParseReferencesTimestampFailsClosedOnDepthBombNesting() =>
        AssertWrapperFailsClosedOnDepthBomb<CBAdESReferencesTimestamp>(CBAdESSerialization.TryParseReferencesTimestamp);


    /// <summary><c>rfsTst</c>'s wrapper <c>TryParse</c> fails closed on truncated input.</summary>
    [TestMethod]
    public void ParseReferencesTimestampFailsClosedOnTruncatedInput() =>
        AssertWrapperFailsClosedOnTruncatedInput<CBAdESReferencesTimestamp>(CBAdESSerialization.TryParseReferencesTimestamp);


    /// <summary>
    /// The shared signature every four-wrapper <c>TryParse*</c> method matches — lets the malformed-input
    /// assertion helpers below take any of them as a single delegate argument instead of duplicating the
    /// byte-construction/assertion logic per wrapper.
    /// </summary>
    /// <typeparam name="TResult">The wrapper's parsed result type.</typeparam>
    /// <param name="encoded">The encoded bytes.</param>
    /// <param name="result">The parsed value on success; <see langword="null"/> on failure.</param>
    /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
    private delegate bool TryParseTimestampWrapper<TResult>(ReadOnlyMemory<byte> encoded, out TResult? result) where TResult : class, IDisposable;


    /// <summary>Asserts that <paramref name="tryParse"/> fails closed when trailing bytes follow a complete <c>tstContainer</c>-shaped value.</summary>
    /// <typeparam name="TResult">The wrapper's parsed result type.</typeparam>
    /// <param name="tryParse">The wrapper's <c>TryParse*</c> method under test.</param>
    private static void AssertWrapperFailsClosedOnTrailingData<TResult>(TryParseTimestampWrapper<TResult> tryParse) where TResult : class, IDisposable
    {
        byte[] withTrailer = [.. BuildMinimalTimestampContainerBytes(), 0x00];

        bool parsed = tryParse(withTrailer, out TResult? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete tstContainer-shaped value must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>Asserts that <paramref name="tryParse"/> fails closed on an indefinite-length <c>tstContainer</c>-shaped map.</summary>
    /// <typeparam name="TResult">The wrapper's parsed result type.</typeparam>
    /// <param name="tryParse">The wrapper's <c>TryParse*</c> method under test.</param>
    private static void AssertWrapperFailsClosedOnIndefiniteLength<TResult>(TryParseTimestampWrapper<TResult> tryParse) where TResult : class, IDisposable
    {
        bool parsed = tryParse(BuildIndefiniteLengthTimestampContainerBytes(), out TResult? result);

        Assert.IsFalse(parsed, "An indefinite-length tstContainer-shaped map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>Asserts that <paramref name="tryParse"/> fails closed on adversarially deep top-level nesting, without throwing or crashing.</summary>
    /// <typeparam name="TResult">The wrapper's parsed result type.</typeparam>
    /// <param name="tryParse">The wrapper's <c>TryParse*</c> method under test.</param>
    private static void AssertWrapperFailsClosedOnDepthBomb<TResult>(TryParseTimestampWrapper<TResult> tryParse) where TResult : class, IDisposable
    {
        bool parsed = tryParse(BuildDeeplyNestedArrayBytes(10_000), out TResult? result);

        Assert.IsFalse(parsed, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>Asserts that <paramref name="tryParse"/> fails closed on a truncated <c>tstContainer</c>-shaped value.</summary>
    /// <typeparam name="TResult">The wrapper's parsed result type.</typeparam>
    /// <param name="tryParse">The wrapper's <c>TryParse*</c> method under test.</param>
    private static void AssertWrapperFailsClosedOnTruncatedInput<TResult>(TryParseTimestampWrapper<TResult> tryParse) where TResult : class, IDisposable
    {
        byte[] truncated = BuildMinimalTimestampContainerBytes()[..^1];

        bool parsed = tryParse(truncated, out TResult? result);

        Assert.IsFalse(parsed, "Truncated tstContainer-shaped input must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>Builds a minimal, single-token <see cref="CBAdESTimestampContainer"/> fixture shared by every wrapper positive/negative test in this file.</summary>
    /// <returns>The built fixture.</returns>
    private static CBAdESTimestampContainer CreateTimestampContainerFixture() =>
        new() { TstTokens = [new CBAdESTimestampToken { Val = new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 } }] };


    /// <summary>Assembles the expected canonical CBOR bytes for a minimal, single-token <c>tstContainer</c> map (clause 5.4.3.3), matching <see cref="CreateTimestampContainerFixture"/>.</summary>
    /// <returns>The expected canonical CBOR bytes.</returns>
    private static byte[] BuildMinimalTimestampContainerBytes()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // tstTokens, Table 13.
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // val, Table 13 (TstToken).
        writer.WriteByteString([0x30, 0x03, 0x02, 0x01, 0x01]);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>Builds an indefinite-length <c>tstContainer</c>-shaped map that must be rejected under canonical-mode parsing.</summary>
    /// <returns>The encoded bytes.</returns>
    private static byte[] BuildIndefiniteLengthTimestampContainerBytes()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(null);
        writer.WriteInt32(1); // tstTokens, Table 13.
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // val, Table 13 (TstToken).
        writer.WriteByteString([0x01]);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>Writes a CBOR tag-32 URI (RFC 8949 section 3.4.5.3) directly with <see cref="CborWriter"/> primitives — independent of the library's own <c>WriteUri</c> extension method.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="uri">The absolute URI to write.</param>
    private static void WriteUriTag(CborWriter writer, Uri uri)
    {
        writer.WriteTag(CborTag.Uri);
        writer.WriteTextString(uri.AbsoluteUri);
    }


    /// <summary>Writes a CBOR tag-0 (RFC 8949 section 3.4.1) "tdate" — an RFC 3339 date-time text string — matching the production codec's own format exactly.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="value">The date-time value to write.</param>
    private static void WriteTDateOracle(CborWriter writer, DateTimeOffset value)
    {
        writer.WriteTag(CborTag.DateTimeString);
        writer.WriteTextString(value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture));
    }


    /// <summary>Writes the shared "digest algorithm + digest value" two-element CBOR array shape (<c>COSE_CertHash</c>/<c>DigAlgVal</c>) directly, independent of the library's own writer.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="hashAlgorithm">The digest-algorithm identifier (the pair's <c>hashAlg</c> element).</param>
    /// <param name="digest">The digest bytes (the pair's <c>hashValue</c> element).</param>
    private static void WriteHashAlgorithmDigestPairOracle(CborWriter writer, int hashAlgorithm, byte[] digest)
    {
        writer.WriteStartArray(2);
        writer.WriteInt32(hashAlgorithm);
        writer.WriteByteString(digest);
        writer.WriteEndArray();
    }


    /// <summary>Writes a <c>pkiOb</c> map (clause 5.4.2, Table 12) with only the required <c>val</c> member, directly, independent of the library's own writer.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="val">The <c>val</c> member's bytes.</param>
    private static void WritePkiObOracle(CborWriter writer, byte[] val)
    {
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // val, Table 12.
        writer.WriteByteString(val);
        writer.WriteEndMap();
    }


    /// <summary>Writes an <c>X509OrOther</c> one-entry map (clause 5.3.4, Table 10) directly, independent of the library's own writer.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="key">The choice arm's key — <c>1</c> (<c>x509Cert</c>) or <c>2</c> (<c>otherCert</c>).</param>
    /// <param name="val">The encapsulated <c>pkiOb</c>'s <c>val</c> bytes.</param>
    private static void WriteX509OrOtherOracle(CborWriter writer, int key, byte[] val)
    {
        writer.WriteStartMap(1);
        writer.WriteInt32(key);
        WritePkiObOracle(writer, val);
        writer.WriteEndMap();
    }


    /// <summary>Assembles the expected canonical CBOR bytes for a <c>valData</c> map (clause 5.3.4, Table 10), directly with <see cref="CborWriter"/> — this suite's independent encode oracle.</summary>
    /// <param name="certificateEntries">The <c>xVals</c> entries as (choice-arm key, <c>pkiOb.val</c> bytes) pairs, or <see langword="null"/> to omit <c>xVals</c>.</param>
    /// <param name="crlValues">The <c>rVals.crlVals</c> entries' <c>pkiOb.val</c> bytes, or <see langword="null"/> to omit the member.</param>
    /// <param name="ocspValues">The <c>rVals.ocspVals</c> entries' <c>pkiOb.val</c> bytes, or <see langword="null"/> to omit the member.</param>
    /// <param name="otherValues">The <c>rVals.otherVals</c> entries' <c>pkiOb.val</c> bytes, or <see langword="null"/> to omit the member.</param>
    /// <returns>The expected canonical CBOR bytes.</returns>
    private static byte[] BuildValidationDataBytes(
        IReadOnlyList<(int Key, byte[] Val)>? certificateEntries,
        IReadOnlyList<byte[]>? crlValues,
        IReadOnlyList<byte[]>? ocspValues,
        IReadOnlyList<byte[]>? otherValues)
    {
        bool hasRVals = crlValues is not null || ocspValues is not null || otherValues is not null;
        int memberCount = (certificateEntries is not null ? 1 : 0) + (hasRVals ? 1 : 0);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(memberCount);

        if(certificateEntries is not null)
        {
            writer.WriteInt32(1); // xVals, Table 10.
            writer.WriteStartArray(certificateEntries.Count);
            foreach((int key, byte[] val) in certificateEntries)
            {
                WriteX509OrOtherOracle(writer, key, val);
            }

            writer.WriteEndArray();
        }

        if(hasRVals)
        {
            writer.WriteInt32(2); // rVals, Table 10.
            int rValsMemberCount = (crlValues is not null ? 1 : 0) + (ocspValues is not null ? 1 : 0) + (otherValues is not null ? 1 : 0);
            writer.WriteStartMap(rValsMemberCount);

            WritePkiObArrayIfPresent(writer, 1, crlValues); // crlVals, Table 10.
            WritePkiObArrayIfPresent(writer, 2, ocspValues); // ocspVals, Table 10.
            WritePkiObArrayIfPresent(writer, 3, otherValues); // otherVals, Table 10.

            writer.WriteEndMap();
        }

        writer.WriteEndMap();
        return writer.Encode();

        static void WritePkiObArrayIfPresent(CborWriter writer, int key, IReadOnlyList<byte[]>? values)
        {
            if(values is null)
            {
                return;
            }

            writer.WriteInt32(key);
            writer.WriteStartArray(values.Count);
            foreach(byte[] val in values)
            {
                WritePkiObOracle(writer, val);
            }

            writer.WriteEndArray();
        }
    }


    /// <summary>Assembles the expected canonical CBOR bytes for a <c>sigPSt</c> map (clause 5.3.2, Table 9), directly with <see cref="CborWriter"/> — this suite's independent encode oracle.</summary>
    /// <param name="isDocumentArm"><see langword="true"/> to write the <c>sigPolDoc</c> arm; <see langword="false"/> for <c>sigPolLocalURI</c>.</param>
    /// <param name="document">The <c>sigPolDoc</c> arm's bytes. Required when <paramref name="isDocumentArm"/> is <see langword="true"/>.</param>
    /// <param name="localUri">The <c>sigPolLocalURI</c> arm's URI. Required when <paramref name="isDocumentArm"/> is <see langword="false"/>.</param>
    /// <param name="spDSpec">The <c>spDSpec</c> member's <c>oId.id</c> URI, or <see langword="null"/> to omit the member.</param>
    /// <returns>The expected canonical CBOR bytes.</returns>
    private static byte[] BuildSignaturePolicyStoreBytes(bool isDocumentArm, byte[]? document, Uri? localUri, Uri? spDSpec)
    {
        int memberCount = 1 + (spDSpec is not null ? 1 : 0);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(1); // docOrLocalUri, Table 9.
        writer.WriteStartMap(1);
        if(isDocumentArm)
        {
            writer.WriteInt32(1); // sigPolDoc, Table 9.
            writer.WriteByteString(document!);
        }
        else
        {
            writer.WriteInt32(2); // sigPolLocalURI, Table 9.
            WriteUriTag(writer, localUri!);
        }

        writer.WriteEndMap();

        if(spDSpec is not null)
        {
            writer.WriteInt32(2); // spDSpec, Table 9.
            writer.WriteStartMap(1);
            writer.WriteInt32(1); // id, Table 11 (oId).
            WriteUriTag(writer, spDSpec);
            writer.WriteEndMap();
        }

        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>Writes a <c>CertId</c> map (Annex A.1.1, Table A.1) directly with <see cref="CborWriter"/>, independent of the library's own writer.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="hashAlgorithm">The <c>x5t</c> digest-algorithm identifier.</param>
    /// <param name="digest">The <c>x5t</c> digest bytes.</param>
    /// <param name="writeKid">Writes the <c>kid</c> member's value (the CDDL's <c>int / tstr / bstr</c> arm), or <see langword="null"/> to omit the member.</param>
    /// <param name="x5u">The <c>x5u</c> location-hint URI, or <see langword="null"/> to omit the member.</param>
    private static void WriteCertIdOracle(CborWriter writer, int hashAlgorithm, byte[] digest, Action<CborWriter>? writeKid, Uri? x5u)
    {
        int memberCount = 1 + (writeKid is not null ? 1 : 0) + (x5u is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(1); // x5t, Table A.1 (CertId).
        WriteHashAlgorithmDigestPairOracle(writer, hashAlgorithm, digest);

        if(writeKid is not null)
        {
            writer.WriteInt32(2); // kid, Table A.1 (CertId).
            writeKid(writer);
        }

        if(x5u is not null)
        {
            writer.WriteInt32(3); // x5u, Table A.1 (CertId).
            WriteUriTag(writer, x5u);
        }

        writer.WriteEndMap();
    }


    /// <summary>Writes a <c>CRLRef</c> map (Annex A.1.1, Table A.1) directly with <see cref="CborWriter"/>, independent of the library's own writer.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="hashAlgorithm">The <c>digAlgVal</c> digest-algorithm identifier.</param>
    /// <param name="digest">The <c>digAlgVal</c> digest bytes.</param>
    /// <param name="writeCrlId">Writes the <c>crlId</c> member's map, or <see langword="null"/> to omit the member.</param>
    private static void WriteCrlRefOracle(CborWriter writer, int hashAlgorithm, byte[] digest, Action<CborWriter>? writeCrlId)
    {
        int memberCount = 1 + (writeCrlId is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(1); // digAlgVal, Table A.1 (CRLRef).
        WriteHashAlgorithmDigestPairOracle(writer, hashAlgorithm, digest);

        if(writeCrlId is not null)
        {
            writer.WriteInt32(2); // crlId, Table A.1 (CRLRef).
            writeCrlId(writer);
        }

        writer.WriteEndMap();
    }


    /// <summary>Writes a <c>CRLId</c> map (Annex A.1.1, Table A.1) directly with <see cref="CborWriter"/>, independent of the library's own writer.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="issuer">The mandatory <c>issuer</c> bytes.</param>
    /// <param name="issueTime">The mandatory <c>issueTime</c> value.</param>
    /// <param name="number">The optional <c>number</c> value, or <see langword="null"/> to omit the member.</param>
    /// <param name="locationHint">The optional <c>uri</c> value, or <see langword="null"/> to omit the member.</param>
    private static void WriteCrlIdOracle(CborWriter writer, byte[] issuer, DateTimeOffset issueTime, ulong? number, Uri? locationHint)
    {
        int memberCount = 2 + (number is not null ? 1 : 0) + (locationHint is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(1); // issuer, Table A.1 (CRLId).
        writer.WriteByteString(issuer);

        writer.WriteInt32(2); // issueTime, Table A.1 (CRLId).
        WriteTDateOracle(writer, issueTime);

        if(number is not null)
        {
            writer.WriteInt32(3); // number, Table A.1 (CRLId).
            writer.WriteUInt64(number.Value);
        }

        if(locationHint is not null)
        {
            writer.WriteInt32(4); // uri, Table A.1 (CRLId).
            WriteUriTag(writer, locationHint);
        }

        writer.WriteEndMap();
    }


    /// <summary>Writes an <c>OCSPRef</c> map (Annex A.1.1, Table A.1) directly with <see cref="CborWriter"/>, independent of the library's own writer.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="hashAlgorithm">The <c>digAlgVal</c> digest-algorithm identifier.</param>
    /// <param name="digest">The <c>digAlgVal</c> digest bytes.</param>
    /// <param name="writeOcspId">Writes the mandatory <c>ocspId</c> member's map.</param>
    private static void WriteOcspRefOracle(CborWriter writer, int hashAlgorithm, byte[] digest, Action<CborWriter> writeOcspId)
    {
        writer.WriteStartMap(2);

        writer.WriteInt32(1); // digAlgVal, Table A.1 (OCSPRef).
        WriteHashAlgorithmDigestPairOracle(writer, hashAlgorithm, digest);

        writer.WriteInt32(2); // ocspId, Table A.1 (OCSPRef).
        writeOcspId(writer);

        writer.WriteEndMap();
    }


    /// <summary>Writes an <c>OCSPId</c> map (Annex A.1.1, Table A.1) directly with <see cref="CborWriter"/>, independent of the library's own writer.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="writeResponder">Writes the mandatory <c>responderChoice</c> member's map.</param>
    /// <param name="producedAt">The mandatory <c>producedAt</c> value.</param>
    /// <param name="locationHint">The optional <c>uri</c> value, or <see langword="null"/> to omit the member.</param>
    private static void WriteOcspIdOracle(CborWriter writer, Action<CborWriter> writeResponder, DateTimeOffset producedAt, Uri? locationHint)
    {
        int memberCount = 2 + (locationHint is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(1); // responderChoice, Table A.1 (OCSPId).
        writeResponder(writer);

        writer.WriteInt32(2); // producedAt, Table A.1 (OCSPId).
        WriteTDateOracle(writer, producedAt);

        if(locationHint is not null)
        {
            writer.WriteInt32(3); // uri, Table A.1 (OCSPId map).
            WriteUriTag(writer, locationHint);
        }

        writer.WriteEndMap();
    }


    /// <summary>Writes the <c>responderIdByName</c> arm of <c>ResponderIdChoice</c> (Annex A.1.1) directly with <see cref="CborWriter"/>.</summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="name">The DER-encoded responder name bytes.</param>
    private static void WriteResponderByNameOracle(CborWriter writer, byte[] name)
    {
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // responderIdByName, Table A.1 (ResponderIdChoice).
        writer.WriteByteString(name);
        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes the <c>responderIdByKey</c> arm of <c>ResponderIdChoice</c> (Annex A.1.1) directly with
    /// <see cref="CborWriter"/> — D8 (contract R-6, RULED): the raw DER bytes go straight into the <c>bstr</c>,
    /// with no base64 transformation, matching this suite's independent-oracle discipline for the D8 ruling.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="keyDigest">The raw DER <c>ResponderID.byKey</c> (<c>KeyHash</c>) bytes.</param>
    private static void WriteResponderByKeyOracle(CborWriter writer, byte[] keyDigest)
    {
        writer.WriteStartMap(1);
        writer.WriteInt32(2); // responderIdByKey, Table A.1 (ResponderIdChoice).
        writer.WriteByteString(keyDigest);
        writer.WriteEndMap();
    }


    /// <summary>Assembles the expected canonical CBOR bytes for a <c>refs</c> map (Annex A.1.1, Table A.1), directly with <see cref="CborWriter"/> — this suite's independent encode oracle.</summary>
    /// <param name="certificateReferenceWriters">Writes each <c>xRefs</c> entry, in order, or <see langword="null"/> to omit <c>xRefs</c>.</param>
    /// <param name="crlReferenceWriters">Writes each <c>rRefs.crlRefs</c> entry, in order, or <see langword="null"/> to omit the member.</param>
    /// <param name="ocspReferenceWriters">Writes each <c>rRefs.ocspRefs</c> entry, in order, or <see langword="null"/> to omit the member.</param>
    /// <param name="otherReferenceItems">The already-encoded, opaque <c>rRefs.otherRefs</c> item bytes, in order, or <see langword="null"/> to omit the member.</param>
    /// <returns>The expected canonical CBOR bytes.</returns>
    private static byte[] BuildReferencesBytes(
        IReadOnlyList<Action<CborWriter>>? certificateReferenceWriters,
        IReadOnlyList<Action<CborWriter>>? crlReferenceWriters,
        IReadOnlyList<Action<CborWriter>>? ocspReferenceWriters,
        IReadOnlyList<byte[]>? otherReferenceItems)
    {
        bool hasRRefs = crlReferenceWriters is not null || ocspReferenceWriters is not null || otherReferenceItems is not null;
        int memberCount = (certificateReferenceWriters is not null ? 1 : 0) + (hasRRefs ? 1 : 0);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(memberCount);

        if(certificateReferenceWriters is not null)
        {
            writer.WriteInt32(1); // xRefs, Table A.1 (refs).
            writer.WriteStartArray(certificateReferenceWriters.Count);
            foreach(Action<CborWriter> write in certificateReferenceWriters)
            {
                write(writer);
            }

            writer.WriteEndArray();
        }

        if(hasRRefs)
        {
            writer.WriteInt32(2); // rRefs, Table A.1 (refs).
            int rRefsMemberCount = (crlReferenceWriters is not null ? 1 : 0) + (ocspReferenceWriters is not null ? 1 : 0) + (otherReferenceItems is not null ? 1 : 0);
            writer.WriteStartMap(rRefsMemberCount);

            if(crlReferenceWriters is not null)
            {
                writer.WriteInt32(1); // crlRefs, Table A.1 (rRefs).
                writer.WriteStartArray(crlReferenceWriters.Count);
                foreach(Action<CborWriter> write in crlReferenceWriters)
                {
                    write(writer);
                }

                writer.WriteEndArray();
            }

            if(ocspReferenceWriters is not null)
            {
                writer.WriteInt32(2); // ocspRefs, Table A.1 (rRefs).
                writer.WriteStartArray(ocspReferenceWriters.Count);
                foreach(Action<CborWriter> write in ocspReferenceWriters)
                {
                    write(writer);
                }

                writer.WriteEndArray();
            }

            if(otherReferenceItems is not null)
            {
                writer.WriteInt32(3); // otherRefs, Table A.1 (rRefs) -- leg-5 trap 3: not OCSP-only.
                writer.WriteStartArray(otherReferenceItems.Count);
                foreach(byte[] item in otherReferenceItems)
                {
                    writer.WriteEncodedValue(item);
                }

                writer.WriteEndArray();
            }

            writer.WriteEndMap();
        }

        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>
    /// Builds well-formed but adversarially deep CBOR bytes — <paramref name="depth"/> singly-nested arrays,
    /// each containing exactly the next, with an integer at the innermost position — used by every
    /// depth-bomb negative test in this file. Definite-length throughout, so it remains valid CBOR under
    /// canonical-mode conformance; only its nesting depth is adversarial.
    /// </summary>
    /// <param name="depth">The nesting depth.</param>
    /// <returns>The encoded bytes.</returns>
    private static byte[] BuildDeeplyNestedArrayBytes(int depth)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        for(int i = 0; i < depth; i++)
        {
            writer.WriteStartArray(1);
        }

        writer.WriteInt32(0);

        for(int i = 0; i < depth; i++)
        {
            writer.WriteEndArray();
        }

        return writer.Encode();
    }


    /// <summary>
    /// Computes a real SHA-256 digest over <paramref name="input"/> through the registered digest delegate,
    /// tagged with <see cref="CryptoTags.Sha256Digest"/> — the fixture every digest-carrying model instance in
    /// this file builds from, rather than a hand-rolled hash.
    /// </summary>
    /// <param name="input">The bytes to digest.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The owned digest, tagged with <see cref="CryptoTags.Sha256Digest"/>.</returns>
    private static async ValueTask<DigestValue> CreateDigestAsync(byte[] input, CancellationToken cancellationToken)
    {
        return await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(input), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}

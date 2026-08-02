using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Round-trip and strict-conformance tests for the seven CB-AdES signed header parameter models
/// (<c>x5ts</c>, <c>srCms</c>, <c>sigPl</c>, <c>srAts</c>, <c>sigPId</c>, <c>adoTst</c>, <c>sigD</c>) and their
/// <see cref="CBAdESSerialization"/> bindings, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Independent oracle.</strong> Every encode-byte-comparison test builds its expected CBOR bytes with a
/// freshly constructed <see cref="CborWriter"/> in canonical mode, written directly against the clause text
/// (CDDL and Table N key assignments) documented on each <c>CBAdES*</c> model type — never by calling
/// <see cref="CBAdESSerialization"/>'s own private writers. The oracle helpers at the end of this file (
/// <see cref="WriteTag32Uri"/>, <see cref="WriteOId"/>, <see cref="WritePkiOb"/>) use only raw
/// <see cref="CborWriter"/> primitives and the <see cref="CborTag"/> BCL enum, never
/// <c>Verifiable.Cbor</c>'s own <c>CborWriterExtensions</c>/<c>CborValueConverter</c> helpers, so a defect
/// shared between the codec and a generic helper cannot hide behind this suite.
/// </para>
/// <para>
/// <strong>Firewalled parsing.</strong> Every strict-negative and per-qualifier round-trip test hands
/// <see cref="CBAdESSerialization"/>'s <c>TryParse*</c> methods bytes assembled by this file's own oracle
/// helpers (or, for malformed-input tests, hand-crafted byte layouts), never bytes produced by this file's own
/// calls into <see cref="CBAdESSerialization"/>'s <c>Encode*</c> methods — the parser is exercised from wire
/// bytes only, per the contract's firewalled-parse convention.
/// </para>
/// <para>
/// <strong>Digest fixtures.</strong> Every <see cref="DigestValue"/> fixture is a real SHA-256/384/512 digest
/// computed through the registered <see cref="CryptographicKeyEvents"/> digest delegate seam (via
/// <see cref="CreateDigestAsync"/>), never a hand-rolled hash.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESSignedHeaderModelTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <c>x5ts</c> (clause 5.2.2): a three-entry array of <c>COSE_CertHash</c> pairs — signing certificate
    /// first, then the rest of the certification path — encodes to exactly the independent oracle's bytes.
    /// </summary>
    [TestMethod]
    public async Task EncodeCertificateThumbprintsMatchesIndependentOracleForMultipleEntries()
    {
        DigestValue signingDigest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        DigestValue intermediateDigest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha384, "intermediate certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        DigestValue rootDigest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha512, "root certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);

        byte[] signingBytes = signingDigest.AsReadOnlySpan().ToArray();
        byte[] intermediateBytes = intermediateDigest.AsReadOnlySpan().ToArray();
        byte[] rootBytes = rootDigest.AsReadOnlySpan().ToArray();

        //CA2000: each thumbprint's ownership transfers immediately into the owning CBAdESCertificateThumbprints
        //array-literal argument below; disposing the outer 'thumbprints' (via 'using') disposes them all. The
        //analyzer cannot see through the array-literal-into-owning-constructor pattern.
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var thumbprints = new CBAdESCertificateThumbprints(
        [
            new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), signingDigest),
            new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha384), intermediateDigest),
            new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha512), rootDigest)
        ]);
#pragma warning restore CA2000 // Dispose objects before losing scope

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartArray(3);
        WriteX5tEntry(oracle, WellKnownCoseAlgorithms.Sha256, signingBytes);
        WriteX5tEntry(oracle, WellKnownCoseAlgorithms.Sha384, intermediateBytes);
        WriteX5tEntry(oracle, WellKnownCoseAlgorithms.Sha512, rootBytes);
        oracle.WriteEndArray();
        byte[] expected = oracle.Encode();

        using PooledMemory actual = CBAdESSerialization.EncodeCertificateThumbprints(thumbprints, BaseMemoryPool.Shared);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(actual.AsReadOnlySpan()));

        using var parsed = ParseCertificateThumbprintsOrFail(expected);
        Assert.HasCount(3, parsed.Thumbprints);
        Assert.AreEqual(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), parsed.SigningCertificateThumbprint.HashAlgorithm);
        Assert.IsTrue(signingBytes.AsSpan().SequenceEqual(parsed.Thumbprints[0].Digest.AsReadOnlySpan()));
        Assert.AreEqual(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha384), parsed.Thumbprints[1].HashAlgorithm);
        Assert.IsTrue(intermediateBytes.AsSpan().SequenceEqual(parsed.Thumbprints[1].Digest.AsReadOnlySpan()));
        Assert.AreEqual(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha512), parsed.Thumbprints[2].HashAlgorithm);
        Assert.IsTrue(rootBytes.AsSpan().SequenceEqual(parsed.Thumbprints[2].Digest.AsReadOnlySpan()));
    }


    /// <summary>
    /// The CDDL <c>2*x5t</c> occurrence operator (clause 5.2.2) requires at least two entries; constructing
    /// <see cref="CBAdESCertificateThumbprints"/> with a single entry throws.
    /// </summary>
    [TestMethod]
    public async Task ConstructingCertificateThumbprintsBelowMinimumCountThrows()
    {
        DigestValue digest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "only one"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        var singleEntry = new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);
        try
        {
            Assert.ThrowsExactly<ArgumentException>(() => new CBAdESCertificateThumbprints([singleEntry]));
        }
        finally
        {
            singleEntry.Dispose();
        }
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseCertificateThumbprints"/> fails closed on an independently
    /// crafted array carrying fewer than the CDDL-mandated two entries.
    /// </summary>
    [TestMethod]
    public void TryParseCertificateThumbprintsFailsClosedBelowMinimumCount()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartArray(1);
        WriteX5tEntry(oracle, WellKnownCoseAlgorithms.Sha256, new byte[32]);
        oracle.WriteEndArray();

        bool success = CBAdESSerialization.TryParseCertificateThumbprints(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESCertificateThumbprints? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseCertificateThumbprints"/> fails closed when trailing bytes follow
    /// an otherwise well-formed <c>x5ts</c> array.
    /// </summary>
    [TestMethod]
    public void TryParseCertificateThumbprintsFailsClosedOnTrailingBytes()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartArray(2);
        WriteX5tEntry(oracle, WellKnownCoseAlgorithms.Sha256, new byte[32]);
        WriteX5tEntry(oracle, WellKnownCoseAlgorithms.Sha384, new byte[48]);
        oracle.WriteEndArray();
        byte[] withTrailer = [.. oracle.Encode(), 0x00];

        bool success = CBAdESSerialization.TryParseCertificateThumbprints(withTrailer, BaseMemoryPool.Shared, out CBAdESCertificateThumbprints? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An indefinite-length <c>x5ts</c> array must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void TryParseCertificateThumbprintsFailsClosedOnIndefiniteLengthArray()
    {
        var oracle = new CborWriter(CborConformanceMode.Lax);
        oracle.WriteStartArray(null);
        WriteX5tEntry(oracle, WellKnownCoseAlgorithms.Sha256, new byte[32]);
        WriteX5tEntry(oracle, WellKnownCoseAlgorithms.Sha384, new byte[48]);
        oracle.WriteEndArray();

        bool success = CBAdESSerialization.TryParseCertificateThumbprints(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESCertificateThumbprints? result);

        Assert.IsFalse(success, "An indefinite-length x5ts array must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process.
    /// </summary>
    [TestMethod]
    public void TryParseCertificateThumbprintsFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool success = CBAdESSerialization.TryParseCertificateThumbprints(deeplyNested, BaseMemoryPool.Shared, out CBAdESCertificateThumbprints? result);

        Assert.IsFalse(success, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <c>srCms</c> (clause 5.2.3, Table 2): a two-commitment array — one qualified, one bare — encodes to
    /// exactly the independent oracle's bytes and round-trips through the oracle bytes with both commitments'
    /// identifiers and qualifiers preserved.
    /// </summary>
    [TestMethod]
    public void EncodeSignerCommitmentsMatchesIndependentOracleForMultipleCommitments()
    {
        var qualifiedCommitmentId = new CBAdESObjectIdentifier(new Uri(CBAdESCommitmentTypes.ProofOfOriginUri));
        var bareCommitmentId = new CBAdESObjectIdentifier(new Uri(CBAdESCommitmentTypes.ProofOfReceiptUri));

        var commitments = new CBAdESSignerCommitments
        {
            Commitments =
            [
                new CBAdESCommitment(qualifiedCommitmentId, commitmentQualifiers: ["a qualifying note", 7]),
                new CBAdESCommitment(bareCommitmentId)
            ]
        };

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartArray(2);

        oracle.WriteStartMap(2);
        oracle.WriteInt32(1);
        WriteOId(oracle, qualifiedCommitmentId.Id);
        oracle.WriteInt32(2);
        oracle.WriteStartArray(2);
        oracle.WriteTextString("a qualifying note");
        oracle.WriteInt32(7);
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        WriteOId(oracle, bareCommitmentId.Id);
        oracle.WriteEndMap();

        oracle.WriteEndArray();
        byte[] expected = oracle.Encode();

        using PooledMemory actual = CBAdESSerialization.EncodeSignerCommitments(commitments, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(actual.AsReadOnlySpan()));

        bool success = CBAdESSerialization.TryParseSignerCommitments(expected, out CBAdESSignerCommitments? parsed);
        Assert.IsTrue(success);
        Assert.HasCount(2, parsed!.Commitments);
        Assert.AreEqual(qualifiedCommitmentId.Id, parsed.Commitments[0].CommitmentId.Id);
        Assert.HasCount(2, parsed.Commitments[0].CommitmentQualifiers!);
        Assert.AreEqual("a qualifying note", parsed.Commitments[0].CommitmentQualifiers![0]);
        Assert.AreEqual(7, parsed.Commitments[0].CommitmentQualifiers![1]);
        Assert.AreEqual(bareCommitmentId.Id, parsed.Commitments[1].CommitmentId.Id);
        Assert.IsNull(parsed.Commitments[1].CommitmentQualifiers);
    }


    /// <summary>
    /// <c>SrCm</c>'s <c>commQuals</c> member (clause 5.2.3, CDDL <c>[+any]</c>) requires at least one entry
    /// when present; constructing <see cref="CBAdESCommitment"/> with an empty qualifiers array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingCommitmentWithEmptyQualifiersArrayThrows()
    {
        var commitmentId = new CBAdESObjectIdentifier(new Uri(CBAdESCommitmentTypes.ProofOfOriginUri));

        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESCommitment(commitmentId, commitmentQualifiers: []));
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignerCommitments"/> fails closed on an independently crafted
    /// empty array — the CDDL <c>[+SrCm]</c> occurrence operator requires at least one entry.
    /// </summary>
    [TestMethod]
    public void TryParseSignerCommitmentsFailsClosedOnEmptyArray()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartArray(0);
        oracle.WriteEndArray();

        bool success = CBAdESSerialization.TryParseSignerCommitments(oracle.Encode(), out CBAdESSignerCommitments? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignerCommitments"/> fails closed on an <c>SrCm</c> map carrying
    /// a map key outside Table 2's registry.
    /// </summary>
    [TestMethod]
    public void TryParseSignerCommitmentsFailsClosedOnUnknownMapKey()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartArray(1);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(3);
        oracle.WriteBoolean(true);
        oracle.WriteEndMap();
        oracle.WriteEndArray();

        bool success = CBAdESSerialization.TryParseSignerCommitments(oracle.Encode(), out CBAdESSignerCommitments? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignerCommitments"/> fails closed when trailing bytes follow an
    /// otherwise well-formed <c>srCms</c> array.
    /// </summary>
    [TestMethod]
    public void TryParseSignerCommitmentsFailsClosedOnTrailingBytes()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartArray(1);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        WriteOId(oracle, new Uri(CBAdESCommitmentTypes.ProofOfOriginUri));
        oracle.WriteEndMap();
        oracle.WriteEndArray();
        byte[] withTrailer = [.. oracle.Encode(), 0x00];

        bool success = CBAdESSerialization.TryParseSignerCommitments(withTrailer, out CBAdESSignerCommitments? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignerCommitments"/> fails closed on an <c>SrCm</c> map missing
    /// the required <c>commId</c> member (map key 1, Table 2), carrying only the optional <c>commQuals</c>.
    /// </summary>
    [TestMethod]
    public void TryParseSignerCommitmentsFailsClosedOnMissingRequiredCommitmentId()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartArray(1);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(2);
        oracle.WriteStartArray(1);
        oracle.WriteTextString("a qualifier with no commId");
        oracle.WriteEndArray();
        oracle.WriteEndMap();
        oracle.WriteEndArray();

        bool success = CBAdESSerialization.TryParseSignerCommitments(oracle.Encode(), out CBAdESSignerCommitments? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignerCommitments"/> fails closed when <c>commId</c> (map key 1)
    /// is written as a bare text string instead of the required <c>oId</c> map.
    /// </summary>
    [TestMethod]
    public void TryParseSignerCommitmentsFailsClosedOnWrongMajorTypeForCommitmentId()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartArray(1);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteTextString("not an oId map");
        oracle.WriteEndMap();
        oracle.WriteEndArray();

        bool success = CBAdESSerialization.TryParseSignerCommitments(oracle.Encode(), out CBAdESSignerCommitments? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>An indefinite-length <c>srCms</c> array must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void TryParseSignerCommitmentsFailsClosedOnIndefiniteLengthArray()
    {
        var oracle = new CborWriter(CborConformanceMode.Lax);
        oracle.WriteStartArray(null);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        WriteOId(oracle, new Uri(CBAdESCommitmentTypes.ProofOfOriginUri));
        oracle.WriteEndMap();
        oracle.WriteEndArray();

        bool success = CBAdESSerialization.TryParseSignerCommitments(oracle.Encode(), out CBAdESSignerCommitments? result);

        Assert.IsFalse(success, "An indefinite-length srCms array must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process.
    /// </summary>
    [TestMethod]
    public void TryParseSignerCommitmentsFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool success = CBAdESSerialization.TryParseSignerCommitments(deeplyNested, out CBAdESSignerCommitments? result);

        Assert.IsFalse(success, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// <c>sigPl</c> (clause 5.2.4, Table 3): all six members present encodes to exactly the independent
    /// oracle's ascending-key bytes.
    /// </summary>
    [TestMethod]
    public void EncodeSignatureProductionPlaceMatchesIndependentOracleForAllMembers()
    {
        var place = new CBAdESSignatureProductionPlace
        {
            AddressCountry = "FI",
            AddressLocality = "Helsinki",
            AddressRegion = "Uusimaa",
            PostOfficeBoxNumber = "PL 1",
            PostalCode = "00100",
            StreetAddress = "Mannerheimintie 1"
        };

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(6);
        oracle.WriteInt32(1);
        oracle.WriteTextString("FI");
        oracle.WriteInt32(2);
        oracle.WriteTextString("Helsinki");
        oracle.WriteInt32(3);
        oracle.WriteTextString("Uusimaa");
        oracle.WriteInt32(4);
        oracle.WriteTextString("PL 1");
        oracle.WriteInt32(5);
        oracle.WriteTextString("00100");
        oracle.WriteInt32(6);
        oracle.WriteTextString("Mannerheimintie 1");
        oracle.WriteEndMap();
        byte[] expected = oracle.Encode();

        using PooledMemory actual = CBAdESSerialization.EncodeSignatureProductionPlace(place, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(actual.AsReadOnlySpan()));
    }


    /// <summary>
    /// A partial <c>sigPl</c> (only region and postal code) round-trips through independently crafted bytes,
    /// with every absent member reading back <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public void TryParseSignatureProductionPlaceRoundTripsPartialMembers()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(2);
        oracle.WriteInt32(3);
        oracle.WriteTextString("Uusimaa");
        oracle.WriteInt32(5);
        oracle.WriteTextString("00100");
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignatureProductionPlace(oracle.Encode(), out CBAdESSignatureProductionPlace? result);

        Assert.IsTrue(success);
        Assert.IsNull(result!.AddressCountry);
        Assert.IsNull(result.AddressLocality);
        Assert.AreEqual("Uusimaa", result.AddressRegion);
        Assert.IsNull(result.PostOfficeBoxNumber);
        Assert.AreEqual("00100", result.PostalCode);
        Assert.IsNull(result.StreetAddress);
    }


    /// <summary>
    /// CB-5.2.4-04 requires at least one member; encoding an entirely empty <see cref="CBAdESSignatureProductionPlace"/> throws.
    /// </summary>
    [TestMethod]
    public void EncodeSignatureProductionPlaceThrowsWhenEveryMemberIsNull()
    {
        var empty = new CBAdESSignatureProductionPlace();

        Assert.ThrowsExactly<ArgumentException>(() => CBAdESSerialization.EncodeSignatureProductionPlace(empty, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignatureProductionPlace"/> fails closed on an independently
    /// crafted empty map — CB-5.2.4-04 requires at least one member.
    /// </summary>
    [TestMethod]
    public void TryParseSignatureProductionPlaceFailsClosedOnEmptyMap()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(0);
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignatureProductionPlace(oracle.Encode(), out CBAdESSignatureProductionPlace? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignatureProductionPlace"/> fails closed on a map key outside
    /// Table 3's 1-6 registry.
    /// </summary>
    [TestMethod]
    public void TryParseSignatureProductionPlaceFailsClosedOnUnknownMapKey()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(7);
        oracle.WriteTextString("out of range");
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignatureProductionPlace(oracle.Encode(), out CBAdESSignatureProductionPlace? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignatureProductionPlace"/> fails closed when trailing bytes
    /// follow an otherwise well-formed <c>sigPl</c> map.
    /// </summary>
    [TestMethod]
    public void TryParseSignatureProductionPlaceFailsClosedOnTrailingBytes()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteTextString("FI");
        oracle.WriteEndMap();
        byte[] withTrailer = [.. oracle.Encode(), 0x00];

        bool success = CBAdESSerialization.TryParseSignatureProductionPlace(withTrailer, out CBAdESSignatureProductionPlace? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>An indefinite-length <c>sigPl</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void TryParseSignatureProductionPlaceFailsClosedOnIndefiniteLengthMap()
    {
        var oracle = new CborWriter(CborConformanceMode.Lax);
        oracle.WriteStartMap(null);
        oracle.WriteInt32(1);
        oracle.WriteTextString("FI");
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignatureProductionPlace(oracle.Encode(), out CBAdESSignatureProductionPlace? result);

        Assert.IsFalse(success, "An indefinite-length sigPl map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process.
    /// </summary>
    [TestMethod]
    public void TryParseSignatureProductionPlaceFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool success = CBAdESSerialization.TryParseSignatureProductionPlace(deeplyNested, out CBAdESSignatureProductionPlace? result);

        Assert.IsFalse(success, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// <c>srAts.certified</c> (clause 5.2.5, Table 4): both <c>CertifiedAttrChoice</c> arms — X.509 and other —
    /// encode to exactly the independent oracle's bytes and round-trip with their <c>pkiOb</c> content intact.
    /// </summary>
    [TestMethod]
    public void EncodeSignerAttributesMatchesIndependentOracleForBothCertifiedArms()
    {
        byte[] x509Bytes = [1, 2, 3, 4, 5];
        byte[] otherBytes = [9, 8, 7];
        var otherSpecRef = new Uri("https://example.org/attr-cert-spec");

        var attributes = new CBAdESSignerAttributes(
            certified:
            [
                new CBAdESSignerAttributeX509AttributeCertificate(new CBAdESPkiObject { Val = x509Bytes }),
                new CBAdESSignerAttributeOtherAttributeCertificate(new CBAdESPkiObject { Val = otherBytes, SpecRef = otherSpecRef })
            ]);

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteStartArray(2);

        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        WritePkiOb(oracle, x509Bytes);
        oracle.WriteEndMap();

        oracle.WriteStartMap(1);
        oracle.WriteInt32(2);
        WritePkiOb(oracle, otherBytes, specRef: otherSpecRef);
        oracle.WriteEndMap();

        oracle.WriteEndArray();
        oracle.WriteEndMap();
        byte[] expected = oracle.Encode();

        using PooledMemory actual = CBAdESSerialization.EncodeSignerAttributes(attributes, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(actual.AsReadOnlySpan()));

        bool success = CBAdESSerialization.TryParseSignerAttributes(expected, out CBAdESSignerAttributes? parsed);
        Assert.IsTrue(success);
        Assert.HasCount(2, parsed!.Certified!);
        var x509 = Assert.ContainsSingle(c => c is CBAdESSignerAttributeX509AttributeCertificate, parsed.Certified!);
        var other = Assert.ContainsSingle(c => c is CBAdESSignerAttributeOtherAttributeCertificate, parsed.Certified!);
        Assert.IsTrue(x509Bytes.AsSpan().SequenceEqual(((CBAdESSignerAttributeX509AttributeCertificate)x509).Certificate.Val.Span));
        var otherCertificate = ((CBAdESSignerAttributeOtherAttributeCertificate)other).Certificate;
        Assert.IsTrue(otherBytes.AsSpan().SequenceEqual(otherCertificate.Val.Span));
        Assert.AreEqual(otherSpecRef, otherCertificate.SpecRef);
    }


    /// <summary>
    /// The D3 provisional <c>NotCertifiedItem</c> wire mapping carries each opaque qualifying value's raw CBOR
    /// bytes verbatim — an arbitrary nested item round-trips through independently crafted bytes byte-for-byte,
    /// uninterpreted.
    /// </summary>
    [TestMethod]
    public void TryParseSignerAttributesPreservesOpaqueQualifyingValueBytesExactly()
    {
        var nestedValueWriter = new CborWriter(CborConformanceMode.Canonical);
        nestedValueWriter.WriteStartArray(3);
        nestedValueWriter.WriteInt32(1);
        nestedValueWriter.WriteTextString("two");
        nestedValueWriter.WriteInt32(3);
        nestedValueWriter.WriteEndArray();
        byte[] nestedValueBytes = nestedValueWriter.Encode();

        var plainTextValueWriter = new CborWriter(CborConformanceMode.Canonical);
        plainTextValueWriter.WriteTextString("plain");
        byte[] plainTextValueBytes = plainTextValueWriter.Encode();

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(2);
        oracle.WriteStartArray(1);
        oracle.WriteStartArray(2);
        oracle.WriteTextString("application/x-example-assertion");
        oracle.WriteStartArray(2);
        oracle.WriteEncodedValue(nestedValueBytes);
        oracle.WriteEncodedValue(plainTextValueBytes);
        oracle.WriteEndArray();
        oracle.WriteEndArray();
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignerAttributes(oracle.Encode(), out CBAdESSignerAttributes? result);

        Assert.IsTrue(success);
        CBAdESSignerAttributeNotCertifiedItem item = result!.SignedAssertions![0];
        Assert.AreEqual("application/x-example-assertion", item.MediaType);
        Assert.HasCount(2, item.QualifyingValues);
        Assert.AreEqual(CBAdESSignerAttributeOpaqueQualifyingValueKind.Unspecified, item.QualifyingValues[0].Kind);
        Assert.IsTrue(nestedValueBytes.AsSpan().SequenceEqual(item.QualifyingValues[0].EncodedValue.Span));
        Assert.IsTrue(plainTextValueBytes.AsSpan().SequenceEqual(item.QualifyingValues[1].EncodedValue.Span));
    }


    /// <summary>
    /// CB-5.2.5-14 forbids an empty <c>srAts</c>; encoding a <see cref="CBAdESSignerAttributes"/> with every
    /// member <see langword="null"/> throws.
    /// </summary>
    [TestMethod]
    public void EncodeSignerAttributesThrowsWhenEveryMemberIsNull()
    {
        var empty = new CBAdESSignerAttributes();

        Assert.ThrowsExactly<ArgumentException>(() => CBAdESSerialization.EncodeSignerAttributes(empty, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignerAttributes"/> fails closed on an independently crafted
    /// empty <c>certified</c> array.
    /// </summary>
    [TestMethod]
    public void TryParseSignerAttributesFailsClosedOnEmptyCertifiedArray()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteStartArray(0);
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignerAttributes(oracle.Encode(), out CBAdESSignerAttributes? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignerAttributes"/> fails closed on a <c>CertifiedAttrChoice</c>
    /// map key outside Table 4's 1/2 registry.
    /// </summary>
    [TestMethod]
    public void TryParseSignerAttributesFailsClosedOnUnknownCertifiedAttrChoiceKey()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteStartArray(1);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(3);
        WritePkiOb(oracle, [1, 2, 3]);
        oracle.WriteEndMap();
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignerAttributes(oracle.Encode(), out CBAdESSignerAttributes? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignerAttributes"/> fails closed when trailing bytes follow an
    /// otherwise well-formed <c>srAts</c> map.
    /// </summary>
    [TestMethod]
    public void TryParseSignerAttributesFailsClosedOnTrailingBytes()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteStartArray(1);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        WritePkiOb(oracle, [1, 2, 3]);
        oracle.WriteEndMap();
        oracle.WriteEndArray();
        oracle.WriteEndMap();
        byte[] withTrailer = [.. oracle.Encode(), 0x00];

        bool success = CBAdESSerialization.TryParseSignerAttributes(withTrailer, out CBAdESSignerAttributes? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
    }


    /// <summary>An indefinite-length <c>srAts</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void TryParseSignerAttributesFailsClosedOnIndefiniteLengthMap()
    {
        var oracle = new CborWriter(CborConformanceMode.Lax);
        oracle.WriteStartMap(null);
        oracle.WriteInt32(1);
        oracle.WriteStartArray(1);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        WritePkiOb(oracle, [1, 2, 3]);
        oracle.WriteEndMap();
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignerAttributes(oracle.Encode(), out CBAdESSignerAttributes? result);

        Assert.IsFalse(success, "An indefinite-length srAts map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process.
    /// </summary>
    [TestMethod]
    public void TryParseSignerAttributesFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool success = CBAdESSerialization.TryParseSignerAttributes(deeplyNested, out CBAdESSignerAttributes? result);

        Assert.IsFalse(success, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// CB-5.2.5-05: when present, <c>srAts.certified</c> shall be non-empty; constructing
    /// <see cref="CBAdESSignerAttributes"/> with an empty <c>certified</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingSignerAttributesWithEmptyCertifiedArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESSignerAttributes(certified: []));
    }


    /// <summary>
    /// CB-5.2.5-06: when present, <c>srAts.signedAssertions</c> shall be non-empty; constructing
    /// <see cref="CBAdESSignerAttributes"/> with an empty <c>signedAssertions</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingSignerAttributesWithEmptySignedAssertionsArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESSignerAttributes(signedAssertions: []));
    }


    /// <summary>
    /// CB-5.2.5-07: when present, <c>srAts.claimed</c> shall be non-empty; constructing
    /// <see cref="CBAdESSignerAttributes"/> with an empty <c>claimed</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingSignerAttributesWithEmptyClaimedArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESSignerAttributes(claimed: []));
    }


    /// <summary>
    /// <c>adoTst</c> (clause 5.2.6, a straight <c>tstContainer</c> alias): two tokens — one minimal, one
    /// carrying every optional member — encode to exactly the independent oracle's bytes.
    /// </summary>
    [TestMethod]
    public void EncodePayloadTimestampMatchesIndependentOracleForMultipleTokens()
    {
        byte[] minimalToken = [10, 20, 30];
        byte[] fullToken = [40, 50, 60, 70];
        var fullTokenEncoding = new Uri("https://example.org/timestamp-encoding");
        var fullTokenSpecRef = new Uri("https://example.org/timestamp-spec");

        //CA2000: the inline CBAdESTimestampContainer's ownership transfers immediately into the owning
        //CBAdESPayloadTimestamp constructor argument below; disposing 'timestamp' (via 'using') disposes it.
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var timestamp = new CBAdESPayloadTimestamp(new CBAdESTimestampContainer
        {
            TstTokens =
            [
                new CBAdESTimestampToken { Val = minimalToken },
                new CBAdESTimestampToken { Val = fullToken, Type = "x-example-tst", Encoding = fullTokenEncoding, SpecRef = fullTokenSpecRef }
            ]
        });
#pragma warning restore CA2000 // Dispose objects before losing scope

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteStartArray(2);

        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteByteString(minimalToken);
        oracle.WriteEndMap();

        oracle.WriteStartMap(4);
        oracle.WriteInt32(1);
        oracle.WriteByteString(fullToken);
        oracle.WriteInt32(2);
        oracle.WriteTextString("x-example-tst");
        oracle.WriteInt32(3);
        WriteTag32Uri(oracle, fullTokenEncoding);
        oracle.WriteInt32(4);
        WriteTag32Uri(oracle, fullTokenSpecRef);
        oracle.WriteEndMap();

        oracle.WriteEndArray();
        oracle.WriteEndMap();
        byte[] expected = oracle.Encode();

        using PooledMemory actual = CBAdESSerialization.EncodePayloadTimestamp(timestamp, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(actual.AsReadOnlySpan()));

        bool success = CBAdESSerialization.TryParsePayloadTimestamp(expected, out CBAdESPayloadTimestamp? parsed);
        Assert.IsTrue(success);
        using(parsed)
        {
            Assert.HasCount(2, parsed!.TimestampContainer.TstTokens);
            CBAdESTimestampToken firstToken = parsed.TimestampContainer.TstTokens[0];
            Assert.IsTrue(minimalToken.AsSpan().SequenceEqual(firstToken.Val.Span));
            Assert.IsNull(firstToken.Type);
            CBAdESTimestampToken secondToken = parsed.TimestampContainer.TstTokens[1];
            Assert.IsTrue(fullToken.AsSpan().SequenceEqual(secondToken.Val.Span));
            Assert.AreEqual("x-example-tst", secondToken.Type);
            Assert.AreEqual(fullTokenEncoding, secondToken.Encoding);
            Assert.AreEqual(fullTokenSpecRef, secondToken.SpecRef);
        }
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParsePayloadTimestamp"/> fails closed on an independently crafted
    /// empty token array — the CDDL <c>+TstToken</c> occurrence operator requires at least one entry.
    /// </summary>
    [TestMethod]
    public void TryParsePayloadTimestampFailsClosedOnEmptyTokenArray()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteStartArray(0);
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParsePayloadTimestamp(oracle.Encode(), out CBAdESPayloadTimestamp? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParsePayloadTimestamp"/> fails closed on a <c>TstToken</c> map key
    /// outside Table 13's 1-4 registry.
    /// </summary>
    [TestMethod]
    public void TryParsePayloadTimestampFailsClosedOnUnknownTstTokenMapKey()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteStartArray(1);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(5);
        oracle.WriteTextString("out of range");
        oracle.WriteEndMap();
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParsePayloadTimestamp(oracle.Encode(), out CBAdESPayloadTimestamp? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParsePayloadTimestamp"/> fails closed when trailing bytes follow an
    /// otherwise well-formed <c>adoTst</c> map.
    /// </summary>
    [TestMethod]
    public void TryParsePayloadTimestampFailsClosedOnTrailingBytes()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteStartArray(1);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteByteString([0x01]);
        oracle.WriteEndMap();
        oracle.WriteEndArray();
        oracle.WriteEndMap();
        byte[] withTrailer = [.. oracle.Encode(), 0x00];

        bool success = CBAdESSerialization.TryParsePayloadTimestamp(withTrailer, out CBAdESPayloadTimestamp? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An indefinite-length <c>adoTst</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void TryParsePayloadTimestampFailsClosedOnIndefiniteLengthContainer()
    {
        var oracle = new CborWriter(CborConformanceMode.Lax);
        oracle.WriteStartMap(null);
        oracle.WriteInt32(1);
        oracle.WriteStartArray(1);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        oracle.WriteByteString([0x01]);
        oracle.WriteEndMap();
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParsePayloadTimestamp(oracle.Encode(), out CBAdESPayloadTimestamp? result);

        Assert.IsFalse(success, "An indefinite-length adoTst map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process.
    /// </summary>
    [TestMethod]
    public void TryParsePayloadTimestampFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool success = CBAdESSerialization.TryParsePayloadTimestamp(deeplyNested, out CBAdESPayloadTimestamp? result);

        Assert.IsFalse(success, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// CB-5.2.7-12: when <c>digPSp</c> is <see langword="true"/>, an <c>spDSpec</c> qualifier identifying the
    /// technical specification shall be present; constructing <see cref="CBAdESSignaturePolicyIdentifier"/>
    /// with <c>digestIsPerSpecification: true</c> and no qualifiers at all throws.
    /// </summary>
    [TestMethod]
    public async Task ConstructingSignaturePolicyIdentifierWithDigPSpTrueAndNoQualifiersThrows()
    {
        var id = new CBAdESObjectIdentifier(new Uri("https://policy.example.org/v1"));
        DigestValue digest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "policy document"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.ThrowsExactly<ArgumentException>(() =>
                new CBAdESSignaturePolicyIdentifier(id, new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest, digestIsPerSpecification: true));
        }
        finally
        {
            digest.Dispose();
        }
    }


    /// <summary>
    /// CB-5.2.7-12 also rejects a non-empty <c>sigPQuals</c> that lacks the required <c>spDSpec</c> qualifier
    /// when <c>digPSp</c> is <see langword="true"/> — a bare <c>spURI</c> qualifier is not enough.
    /// </summary>
    [TestMethod]
    public async Task ConstructingSignaturePolicyIdentifierWithDigPSpTrueAndQualifiersLackingDocumentSpecificationThrows()
    {
        var id = new CBAdESObjectIdentifier(new Uri("https://policy.example.org/v1"));
        DigestValue digest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "policy document"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.ThrowsExactly<ArgumentException>(() =>
                new CBAdESSignaturePolicyIdentifier(
                    id,
                    new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
                    digest,
                    digestIsPerSpecification: true,
                    qualifiers: [new CBAdESSignaturePolicyUri(new Uri("https://policy.example.org/v1/copy"))]));
        }
        finally
        {
            digest.Dispose();
        }
    }


    /// <summary>
    /// CB-5.2.7-13: when present, <c>sigPQuals</c> shall be non-empty; constructing with an empty qualifiers
    /// list throws.
    /// </summary>
    [TestMethod]
    public async Task ConstructingSignaturePolicyIdentifierWithEmptyQualifiersListThrows()
    {
        var id = new CBAdESObjectIdentifier(new Uri("https://policy.example.org/v1"));
        DigestValue digest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "policy document"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.ThrowsExactly<ArgumentException>(() =>
                new CBAdESSignaturePolicyIdentifier(
                    id, new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest, qualifiers: []));
        }
        finally
        {
            digest.Dispose();
        }
    }


    /// <summary>
    /// <c>sigPId</c> (clause 5.2.7.1, Table 5): <c>digPSp: true</c> with a satisfying <c>spDSpec</c> qualifier
    /// encodes to exactly the independent oracle's bytes, including the CB-5.2.7-11 <c>digPSp</c> presence.
    /// </summary>
    [TestMethod]
    public async Task EncodeSignaturePolicyIdentifierMatchesIndependentOracleWithDigPSpTrueAndDocumentSpecification()
    {
        var policyId = new CBAdESObjectIdentifier(new Uri("https://policy.example.org/v3"));
        DigestValue digest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha384, "policy document v3"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] digestBytes = digest.AsReadOnlySpan().ToArray();
        var location = new Uri("https://policy.example.org/v3/copy");
        var specificationId = new CBAdESObjectIdentifier(new Uri("urn:oid:1.2.3.4.5"));

        using var identifier = new CBAdESSignaturePolicyIdentifier(
            policyId,
            new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha384),
            digest,
            digestIsPerSpecification: true,
            qualifiers:
            [
                new CBAdESSignaturePolicyUri(location),
                new CBAdESSignaturePolicyDocumentSpecification(specificationId)
            ]);

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(4);
        oracle.WriteInt32(1);
        WriteOId(oracle, policyId.Id);
        oracle.WriteInt32(2);
        oracle.WriteStartArray(2);
        oracle.WriteInt32(WellKnownCoseAlgorithms.Sha384);
        oracle.WriteByteString(digestBytes);
        oracle.WriteEndArray();
        oracle.WriteInt32(3);
        oracle.WriteBoolean(true);
        oracle.WriteInt32(4);
        oracle.WriteStartArray(2);
        oracle.WriteStartMap(1);
        oracle.WriteInt32(1);
        WriteTag32Uri(oracle, location);
        oracle.WriteEndMap();
        oracle.WriteStartMap(1);
        oracle.WriteInt32(3);
        WriteOId(oracle, specificationId.Id);
        oracle.WriteEndMap();
        oracle.WriteEndArray();
        oracle.WriteEndMap();
        byte[] expected = oracle.Encode();

        using PooledMemory actual = CBAdESSerialization.EncodeSignaturePolicyIdentifier(identifier, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(actual.AsReadOnlySpan()));
    }


    /// <summary>
    /// CB-5.2.7-11: absence of <c>digPSp</c> on the wire is equivalent to <see langword="false"/>, and an
    /// independently crafted 2-member map (<c>id</c> + <c>digAlgVal</c> only) parses to
    /// <see cref="CBAdESSignaturePolicyIdentifier.DigestIsPerSpecification"/> <see langword="false"/>.
    /// </summary>
    [TestMethod]
    public void TryParseSignaturePolicyIdentifierDefaultsDigestIsPerSpecificationToFalseWhenAbsent()
    {
        var policyId = new Uri("https://policy.example.org/v1");
        byte[] digestBytes = new byte[32];

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(2);
        oracle.WriteInt32(1);
        WriteOId(oracle, policyId);
        oracle.WriteInt32(2);
        oracle.WriteStartArray(2);
        oracle.WriteInt32(WellKnownCoseAlgorithms.Sha256);
        oracle.WriteByteString(digestBytes);
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignaturePolicyIdentifier(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESSignaturePolicyIdentifier? result);

        Assert.IsTrue(success);
        using CBAdESSignaturePolicyIdentifier parsed = result!;
        Assert.AreEqual(policyId, parsed.Id.Id);
        Assert.IsFalse(parsed.DigestIsPerSpecification);
        Assert.IsNull(parsed.Qualifiers);
    }


    /// <summary>
    /// The <c>spURI</c> qualifier arm (clause 5.2.7.2, Table 6, map key 1) round-trips through independently
    /// crafted bytes.
    /// </summary>
    [TestMethod]
    public void TryParseSignaturePolicyIdentifierRoundTripsUriQualifier()
    {
        var location = new Uri("https://policy.example.org/v1/copy");
        CBAdESSignaturePolicyIdentifier parsed = ParseMinimalSigPIdOracleWithOneQualifier(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(1);
            WriteTag32Uri(writer, location);
            writer.WriteEndMap();
        });

        using(parsed)
        {
            var qualifier = Assert.ContainsSingle(q => q is CBAdESSignaturePolicyUri, parsed.Qualifiers!);
            Assert.AreEqual(location, ((CBAdESSignaturePolicyUri)qualifier).Location);
        }
    }


    /// <summary>
    /// The <c>spUserNotice</c> qualifier arm (clause 5.2.7.2, Table 6, map key 2) round-trips both its
    /// <c>noticeRef</c> and <c>explText</c> members through independently crafted bytes.
    /// </summary>
    [TestMethod]
    public void TryParseSignaturePolicyIdentifierRoundTripsUserNoticeQualifier()
    {
        CBAdESSignaturePolicyIdentifier parsed = ParseMinimalSigPIdOracleWithOneQualifier(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(2);
            writer.WriteStartMap(2);
            writer.WriteInt32(1);
            writer.WriteStartMap(2);
            writer.WriteInt32(1);
            writer.WriteTextString("Example Org");
            writer.WriteInt32(2);
            writer.WriteStartArray(3);
            writer.WriteUInt32(1);
            writer.WriteUInt32(2);
            writer.WriteUInt32(3);
            writer.WriteEndArray();
            writer.WriteEndMap();
            writer.WriteInt32(2);
            writer.WriteTextString("Please read before signing.");
            writer.WriteEndMap();
            writer.WriteEndMap();
        });

        using(parsed)
        {
            var qualifier = Assert.ContainsSingle(q => q is CBAdESSignaturePolicyUserNotice, parsed.Qualifiers!);
            var userNotice = (CBAdESSignaturePolicyUserNotice)qualifier;
            Assert.AreEqual("Example Org", userNotice.NoticeReference!.Organization);
            uint[] expectedNoticeNumbers = [1u, 2u, 3u];
            Assert.IsTrue(expectedNoticeNumbers.SequenceEqual(userNotice.NoticeReference.NoticeNumbers));
            Assert.AreEqual("Please read before signing.", userNotice.ExplicitText);
        }
    }


    /// <summary>
    /// The <c>spDSpec</c> qualifier arm (clause 5.2.7.2, Table 6, map key 3) round-trips through independently
    /// crafted bytes.
    /// </summary>
    [TestMethod]
    public void TryParseSignaturePolicyIdentifierRoundTripsDocumentSpecificationQualifier()
    {
        var specificationId = new Uri("urn:oid:1.2.3.4.5");
        CBAdESSignaturePolicyIdentifier parsed = ParseMinimalSigPIdOracleWithOneQualifier(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(3);
            WriteOId(writer, specificationId);
            writer.WriteEndMap();
        });

        using(parsed)
        {
            var qualifier = Assert.ContainsSingle(q => q is CBAdESSignaturePolicyDocumentSpecification, parsed.Qualifiers!);
            Assert.AreEqual(specificationId, ((CBAdESSignaturePolicyDocumentSpecification)qualifier).Specification.Id);
        }
    }


    /// <summary>
    /// The <c>otherQuals</c> extension point's integer-label arm round-trips through independently crafted
    /// bytes.
    /// </summary>
    [TestMethod]
    public void TryParseSignaturePolicyIdentifierRoundTripsOtherQualifierWithIntegerLabel()
    {
        CBAdESSignaturePolicyIdentifier parsed = ParseMinimalSigPIdOracleWithOneQualifier(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteInt32(100);
            writer.WriteTextString("custom-int-label-value");
            writer.WriteEndMap();
        });

        using(parsed)
        {
            var qualifier = Assert.ContainsSingle(q => q is CBAdESSignaturePolicyOtherQualifier, parsed.Qualifiers!);
            var other = (CBAdESSignaturePolicyOtherQualifier)qualifier;
            var label = (CBAdESSignaturePolicyQualifierIntegerLabel)other.Label;
            Assert.AreEqual(100, label.Value);
            Assert.AreEqual("custom-int-label-value", other.Value);
        }
    }


    /// <summary>
    /// The <c>otherQuals</c> extension point's text-label arm round-trips through independently crafted bytes.
    /// </summary>
    [TestMethod]
    public void TryParseSignaturePolicyIdentifierRoundTripsOtherQualifierWithTextLabel()
    {
        CBAdESSignaturePolicyIdentifier parsed = ParseMinimalSigPIdOracleWithOneQualifier(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString("x-custom-qualifier");
            writer.WriteInt32(42);
            writer.WriteEndMap();
        });

        using(parsed)
        {
            var qualifier = Assert.ContainsSingle(q => q is CBAdESSignaturePolicyOtherQualifier, parsed.Qualifiers!);
            var other = (CBAdESSignaturePolicyOtherQualifier)qualifier;
            var label = (CBAdESSignaturePolicyQualifierTextLabel)other.Label;
            Assert.AreEqual("x-custom-qualifier", label.Value);
            Assert.AreEqual(42, other.Value);
        }
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignaturePolicyIdentifier"/> fails closed on a map key outside
    /// Table 5's 1-4 registry.
    /// </summary>
    [TestMethod]
    public void TryParseSignaturePolicyIdentifierFailsClosedOnUnknownMapKey()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(2);
        oracle.WriteInt32(1);
        WriteOId(oracle, new Uri("https://policy.example.org/v1"));
        oracle.WriteInt32(99);
        oracle.WriteBoolean(true);
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignaturePolicyIdentifier(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESSignaturePolicyIdentifier? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseSignaturePolicyIdentifier"/> fails closed when trailing bytes
    /// follow an otherwise well-formed <c>sigPId</c> map.
    /// </summary>
    [TestMethod]
    public void TryParseSignaturePolicyIdentifierFailsClosedOnTrailingBytes()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(2);
        oracle.WriteInt32(1);
        WriteOId(oracle, new Uri("https://policy.example.org/v1"));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(2);
        oracle.WriteInt32(WellKnownCoseAlgorithms.Sha256);
        oracle.WriteByteString(new byte[32]);
        oracle.WriteEndArray();
        oracle.WriteEndMap();
        byte[] withTrailer = [.. oracle.Encode(), 0x00];

        bool success = CBAdESSerialization.TryParseSignaturePolicyIdentifier(withTrailer, BaseMemoryPool.Shared, out CBAdESSignaturePolicyIdentifier? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An indefinite-length <c>sigPId</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void TryParseSignaturePolicyIdentifierFailsClosedOnIndefiniteLengthMap()
    {
        var oracle = new CborWriter(CborConformanceMode.Lax);
        oracle.WriteStartMap(null);
        oracle.WriteInt32(1);
        WriteOId(oracle, new Uri("https://policy.example.org/v1"));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(2);
        oracle.WriteInt32(WellKnownCoseAlgorithms.Sha256);
        oracle.WriteByteString(new byte[32]);
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignaturePolicyIdentifier(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESSignaturePolicyIdentifier? result);

        Assert.IsFalse(success, "An indefinite-length sigPId map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process.
    /// </summary>
    [TestMethod]
    public void TryParseSignaturePolicyIdentifierFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool success = CBAdESSerialization.TryParseSignaturePolicyIdentifier(deeplyNested, BaseMemoryPool.Shared, out CBAdESSignaturePolicyIdentifier? result);

        Assert.IsFalse(success, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <c>sigD</c> under the <c>ObjectIdByURI</c> mechanism (clause 5.2.8.2.2): no <c>hashM</c>/<c>hashV</c>,
    /// no <c>ctys</c> — a two-reference map encodes to exactly the independent oracle's bytes.
    /// </summary>
    [TestMethod]
    public void EncodeDetachedObjectsMatchesIndependentOracleForObjectIdByUriMechanism()
    {
        //CA2000: each entry's ownership transfers immediately into the owning CBAdESDetachedObjects
        //array-literal argument below; disposing the outer 'detachedObjects' (via 'using') disposes them all.
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var detachedObjects = new CBAdESDetachedObjects(
            CBAdESDetachedMechanisms.ObjectIdByURI,
            [
                new CBAdESDetachedObjectEntry("urn:example:object-1"),
                new CBAdESDetachedObjectEntry("urn:example:object-2")
            ]);
#pragma warning restore CA2000 // Dispose objects before losing scope

        byte[] expected = BuildObjectIdByUriOracleBytes(CBAdESDetachedMechanisms.ObjectIdByURI, ["urn:example:object-1", "urn:example:object-2"]);

        using PooledMemory actual = CBAdESSerialization.EncodeDetachedObjects(detachedObjects, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(actual.AsReadOnlySpan()));
    }


    /// <summary>
    /// <c>sigD</c> under the <c>ObjectIdByURIHash</c> mechanism (clause 5.2.8.2.3): every entry carries a
    /// digest under a common algorithm and a content type (including the CB-5.2.8-25 "implied" CBOR-null
    /// sentinel) — the encoded bytes match the independent oracle exactly, and parsing the oracle bytes back
    /// preserves reference, digest, and content type in position order.
    /// </summary>
    [TestMethod]
    public async Task EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism()
    {
        DigestValue firstDigest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "object one"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        DigestValue secondDigest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "object two"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] firstDigestBytes = firstDigest.AsReadOnlySpan().ToArray();
        byte[] secondDigestBytes = secondDigest.AsReadOnlySpan().ToArray();

        //CA2000: each entry's ownership transfers immediately into the owning CBAdESDetachedObjects
        //array-literal argument below; disposing the outer 'detachedObjects' (via 'using') disposes them all.
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var detachedObjects = new CBAdESDetachedObjects(
            CBAdESDetachedMechanisms.ObjectIdByURIHash,
            [
                new CBAdESDetachedObjectEntry("urn:example:object-1", firstDigest, contentType: null),
                new CBAdESDetachedObjectEntry("urn:example:object-2", secondDigest, contentType: "text/plain")
            ],
            new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256));
#pragma warning restore CA2000 // Dispose objects before losing scope

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(5);
        oracle.WriteInt32(1);
        WriteTag32Uri(oracle, new Uri(CBAdESDetachedMechanisms.ObjectIdByURIHash));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(2);
        oracle.WriteTextString("urn:example:object-1");
        oracle.WriteTextString("urn:example:object-2");
        oracle.WriteEndArray();
        oracle.WriteInt32(3);
        oracle.WriteInt32(WellKnownCoseAlgorithms.Sha256);
        oracle.WriteInt32(4);
        oracle.WriteStartArray(2);
        oracle.WriteByteString(firstDigestBytes);
        oracle.WriteByteString(secondDigestBytes);
        oracle.WriteEndArray();
        oracle.WriteInt32(5);
        oracle.WriteStartArray(2);
        oracle.WriteNull();
        oracle.WriteTextString("text/plain");
        oracle.WriteEndArray();
        oracle.WriteEndMap();
        byte[] expected = oracle.Encode();

        using PooledMemory actual = CBAdESSerialization.EncodeDetachedObjects(detachedObjects, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(actual.AsReadOnlySpan()));

        bool success = CBAdESSerialization.TryParseDetachedObjects(expected, BaseMemoryPool.Shared, out CBAdESDetachedObjects? parsed);
        Assert.IsTrue(success);
        using(parsed)
        {
            Assert.AreEqual(CBAdESDetachedMechanisms.ObjectIdByURIHash, parsed!.MechanismIdentifier);
            Assert.HasCount(2, parsed.DetachedObjects);
            Assert.AreEqual("urn:example:object-1", parsed.DetachedObjects[0].Reference);
            Assert.IsTrue(firstDigestBytes.AsSpan().SequenceEqual(parsed.DetachedObjects[0].Digest!.AsReadOnlySpan()));
            Assert.IsNull(parsed.DetachedObjects[0].ContentType);
            Assert.AreEqual("urn:example:object-2", parsed.DetachedObjects[1].Reference);
            Assert.IsTrue(secondDigestBytes.AsSpan().SequenceEqual(parsed.DetachedObjects[1].Digest!.AsReadOnlySpan()));
            Assert.AreEqual("text/plain", parsed.DetachedObjects[1].ContentType);
        }
    }


    /// <summary>
    /// CB-5.2.8-21: <c>hashV</c>, when present, shall cover every <c>pars</c> position; encoding
    /// <see cref="CBAdESDetachedObjects"/> where some but not all entries carry a digest throws.
    /// </summary>
    [TestMethod]
    public async Task EncodeDetachedObjectsThrowsWhenSomeButNotAllEntriesCarryADigest()
    {
        DigestValue digest = await CreateDigestAsync(WellKnownCoseAlgorithms.Sha256, "object one"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);

        //CA2000: the entry's ownership transfers immediately into the owning CBAdESDetachedObjects
        //array-literal argument below; disposing the outer 'detachedObjects' (via 'using') disposes it.
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var detachedObjects = new CBAdESDetachedObjects(
            CBAdESDetachedMechanisms.ObjectIdByURIHash,
            [
                new CBAdESDetachedObjectEntry("urn:example:object-1", digest),
                new CBAdESDetachedObjectEntry("urn:example:object-2")
            ],
            new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256));
#pragma warning restore CA2000 // Dispose objects before losing scope

        Assert.ThrowsExactly<ArgumentException>(() => CBAdESSerialization.EncodeDetachedObjects(detachedObjects, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// CB-5.2.8-06: <c>sigD</c> shall reference one or more detached data objects; constructing
    /// <see cref="CBAdESDetachedObjects"/> with an empty list throws.
    /// </summary>
    [TestMethod]
    public void ConstructingDetachedObjectsWithAnEmptyListThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESDetachedObjects(CBAdESDetachedMechanisms.ObjectIdByURI, []));
    }


    /// <summary>
    /// CB-5.2.8-21: on parse, <c>hashV</c>'s element count shall equal <c>pars</c>'s; an independently crafted
    /// map with a shorter <c>hashV</c> array fails closed.
    /// </summary>
    [TestMethod]
    public void TryParseDetachedObjectsFailsClosedWhenHashValuesLengthMismatchesReferences()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(4);
        oracle.WriteInt32(1);
        WriteTag32Uri(oracle, new Uri(CBAdESDetachedMechanisms.ObjectIdByURIHash));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(2);
        oracle.WriteTextString("urn:example:object-1");
        oracle.WriteTextString("urn:example:object-2");
        oracle.WriteEndArray();
        oracle.WriteInt32(3);
        oracle.WriteInt32(WellKnownCoseAlgorithms.Sha256);
        oracle.WriteInt32(4);
        oracle.WriteStartArray(1);
        oracle.WriteByteString(new byte[32]);
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseDetachedObjects(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESDetachedObjects? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// CB-5.2.8-24: on parse, <c>ctys</c>'s element count shall equal <c>pars</c>'s; an independently crafted
    /// map with a shorter <c>ctys</c> array fails closed.
    /// </summary>
    [TestMethod]
    public void TryParseDetachedObjectsFailsClosedWhenContentTypesLengthMismatchesReferences()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(3);
        oracle.WriteInt32(1);
        WriteTag32Uri(oracle, new Uri(CBAdESDetachedMechanisms.ObjectIdByURI));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(2);
        oracle.WriteTextString("urn:example:object-1");
        oracle.WriteTextString("urn:example:object-2");
        oracle.WriteEndArray();
        oracle.WriteInt32(5);
        oracle.WriteStartArray(1);
        oracle.WriteTextString("text/plain");
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseDetachedObjects(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESDetachedObjects? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// CB-5.2.8-20/22: <c>hashM</c> and <c>hashV</c> shall be present together, or absent together; an
    /// independently crafted map carrying <c>hashM</c> without <c>hashV</c> fails closed.
    /// </summary>
    [TestMethod]
    public void TryParseDetachedObjectsFailsClosedWhenDigestAlgorithmPresentWithoutDigestValues()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(3);
        oracle.WriteInt32(1);
        WriteTag32Uri(oracle, new Uri(CBAdESDetachedMechanisms.ObjectIdByURIHash));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(1);
        oracle.WriteTextString("urn:example:object-1");
        oracle.WriteEndArray();
        oracle.WriteInt32(3);
        oracle.WriteInt32(WellKnownCoseAlgorithms.Sha256);
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseDetachedObjects(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESDetachedObjects? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseDetachedObjects"/> fails closed on an independently crafted
    /// empty <c>pars</c> array — CB-5.2.8-17/18 requires at least one reference.
    /// </summary>
    [TestMethod]
    public void TryParseDetachedObjectsFailsClosedOnEmptyReferencesArray()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(2);
        oracle.WriteInt32(1);
        WriteTag32Uri(oracle, new Uri(CBAdESDetachedMechanisms.ObjectIdByURI));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(0);
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseDetachedObjects(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESDetachedObjects? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseDetachedObjects"/> fails closed when <c>mId</c> carries a CBOR
    /// tag other than tag 32 (URI).
    /// </summary>
    [TestMethod]
    public void TryParseDetachedObjectsFailsClosedWhenMechanismIdentifierTagIsNotUri()
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(2);
        oracle.WriteInt32(1);
        oracle.WriteTag((CborTag)0);
        oracle.WriteTextString(CBAdESDetachedMechanisms.ObjectIdByURI);
        oracle.WriteInt32(2);
        oracle.WriteStartArray(1);
        oracle.WriteTextString("urn:example:object-1");
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseDetachedObjects(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESDetachedObjects? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <see cref="CBAdESSerialization.TryParseDetachedObjects"/> fails closed when trailing bytes follow an
    /// otherwise well-formed <c>sigD</c> map.
    /// </summary>
    [TestMethod]
    public void TryParseDetachedObjectsFailsClosedOnTrailingBytes()
    {
        byte[] valid = BuildObjectIdByUriOracleBytes(CBAdESDetachedMechanisms.ObjectIdByURI, ["urn:example:object-1"]);
        byte[] withTrailer = [.. valid, 0x00];

        bool success = CBAdESSerialization.TryParseDetachedObjects(withTrailer, BaseMemoryPool.Shared, out CBAdESDetachedObjects? result);

        Assert.IsFalse(success);
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An indefinite-length <c>sigD</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void TryParseDetachedObjectsFailsClosedOnIndefiniteLengthMap()
    {
        var oracle = new CborWriter(CborConformanceMode.Lax);
        oracle.WriteStartMap(null);
        oracle.WriteInt32(1);
        WriteTag32Uri(oracle, new Uri(CBAdESDetachedMechanisms.ObjectIdByURI));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(1);
        oracle.WriteTextString("urn:example:object-1");
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseDetachedObjects(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESDetachedObjects? result);

        Assert.IsFalse(success, "An indefinite-length sigD map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process.
    /// </summary>
    [TestMethod]
    public void TryParseDetachedObjectsFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool success = CBAdESSerialization.TryParseDetachedObjects(deeplyNested, BaseMemoryPool.Shared, out CBAdESDetachedObjects? result);

        Assert.IsFalse(success, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// The <c>hashM</c> member's <c>(int / tstr)</c> CDDL union (clause 5.2.8.1) round-trips a non-SHA-2
    /// integer digest-algorithm identifier (e.g. a MAC or future algorithm registered at a negative label
    /// this library carries no named <see cref="WellKnownCoseAlgorithms"/> mapping for) byte-exactly:
    /// parse then re-encode reproduces the original wire bytes exactly.
    /// </summary>
    [TestMethod]
    public void TryParseDetachedObjectsRoundTripsNonSha2IntegerHashAlgorithmByteExact()
    {
        byte[] digestBytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(4);
        oracle.WriteInt32(1);
        WriteTag32Uri(oracle, new Uri(CBAdESDetachedMechanisms.ObjectIdByURIHash));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(1);
        oracle.WriteTextString("urn:example:object-1");
        oracle.WriteEndArray();
        oracle.WriteInt32(3);
        oracle.WriteInt32(-18);
        oracle.WriteInt32(4);
        oracle.WriteStartArray(1);
        oracle.WriteByteString(digestBytes);
        oracle.WriteEndArray();
        oracle.WriteEndMap();
        byte[] expected = oracle.Encode();

        bool success = CBAdESSerialization.TryParseDetachedObjects(expected, BaseMemoryPool.Shared, out CBAdESDetachedObjects? parsed);

        Assert.IsTrue(success);
        using(parsed)
        {
            Assert.AreEqual(new CBAdESDigestAlgorithmIntegerIdentifier(-18), parsed!.HashAlgorithm);

            using PooledMemory reencoded = CBAdESSerialization.EncodeDetachedObjects(parsed, BaseMemoryPool.Shared);
            Assert.IsTrue(expected.AsSpan().SequenceEqual(reencoded.AsReadOnlySpan()), "A non-SHA-2 int hashM identifier must parse and re-encode byte-identically.");
        }
    }


    /// <summary>
    /// The <c>hashM</c> member's <c>(int / tstr)</c> CDDL union (clause 5.2.8.1) round-trips a <c>tstr</c>
    /// digest-algorithm identifier byte-exactly: parse then re-encode reproduces the original wire bytes
    /// exactly, even though no IANA COSE Algorithms registry entry has ever assigned a textual identifier.
    /// </summary>
    [TestMethod]
    public void TryParseDetachedObjectsRoundTripsTextHashAlgorithmByteExact()
    {
        byte[] digestBytes = [0xAA, 0xBB, 0xCC, 0xDD];

        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(4);
        oracle.WriteInt32(1);
        WriteTag32Uri(oracle, new Uri(CBAdESDetachedMechanisms.ObjectIdByURIHash));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(1);
        oracle.WriteTextString("urn:example:object-1");
        oracle.WriteEndArray();
        oracle.WriteInt32(3);
        oracle.WriteTextString("x-example-digest-alg");
        oracle.WriteInt32(4);
        oracle.WriteStartArray(1);
        oracle.WriteByteString(digestBytes);
        oracle.WriteEndArray();
        oracle.WriteEndMap();
        byte[] expected = oracle.Encode();

        bool success = CBAdESSerialization.TryParseDetachedObjects(expected, BaseMemoryPool.Shared, out CBAdESDetachedObjects? parsed);

        Assert.IsTrue(success);
        using(parsed)
        {
            Assert.AreEqual(new CBAdESDigestAlgorithmTextIdentifier("x-example-digest-alg"), parsed!.HashAlgorithm);

            using PooledMemory reencoded = CBAdESSerialization.EncodeDetachedObjects(parsed, BaseMemoryPool.Shared);
            Assert.IsTrue(expected.AsSpan().SequenceEqual(reencoded.AsReadOnlySpan()), "A tstr hashM identifier must parse and re-encode byte-identically.");
        }
    }


    /// <summary>
    /// Computes a real SHA-256/384/512 digest over <paramref name="input"/> through the registered digest
    /// delegate, tagged with the matching <see cref="CryptoTags"/> entry — the fixture every digest-carrying
    /// test in this file builds from, rather than a hand-rolled hash.
    /// </summary>
    /// <param name="coseHashAlgorithm">
    /// One of <see cref="WellKnownCoseAlgorithms.Sha256"/>, <see cref="WellKnownCoseAlgorithms.Sha384"/>, or
    /// <see cref="WellKnownCoseAlgorithms.Sha512"/>.
    /// </param>
    /// <param name="input">The bytes to digest.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The owned digest, tagged with the algorithm's <see cref="CryptoTags"/> entry.</returns>
    private static async ValueTask<DigestValue> CreateDigestAsync(int coseHashAlgorithm, byte[] input, CancellationToken cancellationToken)
    {
        (Tag tag, int outputByteLength) = coseHashAlgorithm switch
        {
            WellKnownCoseAlgorithms.Sha256 => (CryptoTags.Sha256Digest, 32),
            WellKnownCoseAlgorithms.Sha384 => (CryptoTags.Sha384Digest, 48),
            WellKnownCoseAlgorithms.Sha512 => (CryptoTags.Sha512Digest, 64),
            _ => throw new ArgumentOutOfRangeException(nameof(coseHashAlgorithm), coseHashAlgorithm, "Unsupported test digest algorithm.")
        };

        return await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(input), outputByteLength, tag, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Parses an independently crafted CBOR bytes into <see cref="CBAdESCertificateThumbprints"/>, failing the
    /// test outright if parsing did not succeed — a shared assertion point for the round-trip half of the
    /// <c>x5ts</c> tests.
    /// </summary>
    /// <param name="encoded">The encoded <c>x5ts</c> array bytes.</param>
    /// <returns>The parsed value.</returns>
    private static CBAdESCertificateThumbprints ParseCertificateThumbprintsOrFail(byte[] encoded)
    {
        bool success = CBAdESSerialization.TryParseCertificateThumbprints(encoded, BaseMemoryPool.Shared, out CBAdESCertificateThumbprints? result);
        Assert.IsTrue(success);
        return result!;
    }


    /// <summary>
    /// Builds a minimal, independently crafted <c>sigPId</c> map (a fixed <c>id</c>/<c>digAlgVal</c> pair plus
    /// exactly one qualifier written by <paramref name="writeQualifier"/>) and parses it, for the per-arm
    /// qualifier round-trip tests. Fails the test outright if parsing did not succeed.
    /// </summary>
    /// <param name="writeQualifier">Writes exactly one <c>SigPQual</c> one-key map to the oracle writer.</param>
    /// <returns>The parsed value; the caller disposes it.</returns>
    private static CBAdESSignaturePolicyIdentifier ParseMinimalSigPIdOracleWithOneQualifier(Action<CborWriter> writeQualifier)
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(3);
        oracle.WriteInt32(1);
        WriteOId(oracle, new Uri("https://policy.example.org/v1"));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(2);
        oracle.WriteInt32(WellKnownCoseAlgorithms.Sha256);
        oracle.WriteByteString(new byte[32]);
        oracle.WriteEndArray();
        oracle.WriteInt32(4);
        oracle.WriteStartArray(1);
        writeQualifier(oracle);
        oracle.WriteEndArray();
        oracle.WriteEndMap();

        bool success = CBAdESSerialization.TryParseSignaturePolicyIdentifier(oracle.Encode(), BaseMemoryPool.Shared, out CBAdESSignaturePolicyIdentifier? result);
        Assert.IsTrue(success);
        Assert.HasCount(1, result!.Qualifiers!);
        return result;
    }


    /// <summary>
    /// Builds the independent oracle bytes for a <c>sigD</c> map under the <c>ObjectIdByURI</c> mechanism — no
    /// <c>hashM</c>/<c>hashV</c>, no <c>ctys</c> — for reuse across the mechanism-shape and trailing-bytes
    /// tests.
    /// </summary>
    /// <param name="mechanismIdentifier">The <c>mId</c> URI.</param>
    /// <param name="references">The <c>pars</c> entries, in wire order.</param>
    /// <returns>The encoded <c>sigD</c> map bytes.</returns>
    private static byte[] BuildObjectIdByUriOracleBytes(string mechanismIdentifier, IReadOnlyList<string> references)
    {
        var oracle = new CborWriter(CborConformanceMode.Canonical);
        oracle.WriteStartMap(2);
        oracle.WriteInt32(1);
        WriteTag32Uri(oracle, new Uri(mechanismIdentifier));
        oracle.WriteInt32(2);
        oracle.WriteStartArray(references.Count);
        foreach(string reference in references)
        {
            oracle.WriteTextString(reference);
        }

        oracle.WriteEndArray();
        oracle.WriteEndMap();
        return oracle.Encode();
    }


    /// <summary>
    /// Writes one <c>x5ts</c> array entry — <c>COSE_CertHash</c>'s <c>[hashAlg, hashValue]</c> pair (RFC 9360
    /// §2, profiled by clause 5.1.7) — to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="hashAlgorithm">The digest algorithm identifier.</param>
    /// <param name="digest">The digest bytes.</param>
    private static void WriteX5tEntry(CborWriter writer, int hashAlgorithm, byte[] digest)
    {
        writer.WriteStartArray(2);
        writer.WriteInt32(hashAlgorithm);
        writer.WriteByteString(digest);
        writer.WriteEndArray();
    }


    /// <summary>
    /// Writes a <see cref="Uri"/> as a CBOR tag 32 (<c>#6.32(tstr)</c>) value per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.5.3">RFC 8949 §3.4.5.3</see>, using only
    /// raw <see cref="CborWriter"/>/<see cref="CborTag"/> primitives — independent of any
    /// <c>Verifiable.Cbor</c> helper the code under test might also use.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="uri">The URI to write.</param>
    private static void WriteTag32Uri(CborWriter writer, Uri uri)
    {
        writer.WriteTag(CborTag.Uri);
        writer.WriteTextString(uri.IsAbsoluteUri ? uri.AbsoluteUri : uri.OriginalString);
    }


    /// <summary>
    /// Writes an <c>oId</c> map (clause 5.4.1, Table 11: <c>id</c> required, <c>desc</c>/<c>docRefs</c>
    /// optional) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="id">The <c>id</c> member.</param>
    /// <param name="desc">The optional <c>desc</c> member.</param>
    /// <param name="docRefs">The optional, non-empty <c>docRefs</c> member.</param>
    private static void WriteOId(CborWriter writer, Uri id, string? desc = null, Uri[]? docRefs = null)
    {
        int memberCount = 1 + (desc is not null ? 1 : 0) + (docRefs is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);
        writer.WriteInt32(1);
        WriteTag32Uri(writer, id);

        if(desc is not null)
        {
            writer.WriteInt32(2);
            writer.WriteTextString(desc);
        }

        if(docRefs is not null)
        {
            writer.WriteInt32(3);
            writer.WriteStartArray(docRefs.Length);
            foreach(Uri docRef in docRefs)
            {
                WriteTag32Uri(writer, docRef);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes a <c>pkiOb</c> map (clause 5.4.2, Table 12: <c>val</c> required, <c>encoding</c>/<c>specRef</c>
    /// optional) to <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="val">The <c>val</c> member's raw octets.</param>
    /// <param name="encoding">The optional <c>encoding</c> member.</param>
    /// <param name="specRef">The optional <c>specRef</c> member.</param>
    private static void WritePkiOb(CborWriter writer, byte[] val, Uri? encoding = null, Uri? specRef = null)
    {
        int memberCount = 1 + (encoding is not null ? 1 : 0) + (specRef is not null ? 1 : 0);
        writer.WriteStartMap(memberCount);
        writer.WriteInt32(1);
        writer.WriteByteString(val);

        if(encoding is not null)
        {
            writer.WriteInt32(2);
            WriteTag32Uri(writer, encoding);
        }

        if(specRef is not null)
        {
            writer.WriteInt32(3);
            WriteTag32Uri(writer, specRef);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Builds well-formed but adversarially deep CBOR bytes — <paramref name="depth"/> singly-nested arrays,
    /// each containing exactly the next, with an integer at the innermost position — used by every
    /// depth-bomb negative test in this suite. Definite-length throughout, so it remains valid CBOR under
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
}

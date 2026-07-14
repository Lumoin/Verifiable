using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Covers the <see cref="MetadataBlobReader"/> "member is required"/"member repeated"/segment guards
/// <see cref="MetadataBlobReaderTests"/> leaves individually unexercised: of the reader's roughly 14
/// distinct guards, that file directly proves only the <c>entries</c> (missing) and <c>no</c> (repeated)
/// cases. Each test here removes or duplicates exactly one other guarded member (or, for the zero-dot
/// case, the segment separator itself) from an otherwise well-formed BLOB, so a removed guard would let
/// the corresponding malformed input either pass silently or leak an unrelated exception type instead of
/// this codec's own <see cref="Fido2FormatException"/> contract.
/// </summary>
/// <remarks>
/// Every fixture mints its MDS root certificate with a raw <see cref="ECDsa"/> P-256 key through
/// <see cref="MetadataBlobTestVectors.CreateMdsRootCa"/> — a
/// <see cref="System.Security.Cryptography.X509Certificates.CertificateRequest"/>-based certificate
/// factory, never this library's own key-material or certificate-issuance seam — and reuses that same
/// key to sign the compact-JWS BLOB bytes through <see cref="MetadataBlobTestVectors.SignEs256"/>.
/// </remarks>
[TestClass]
internal sealed class MetadataBlobReaderGuardTests
{
    /// <summary>A JWT Header missing the required <c>alg</c> member is rejected.</summary>
    [TestMethod]
    public void MissingHeaderAlgMemberIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NoAlg", signingKey);

        string x5cJson = Convert.ToBase64String(signerCertificate.RawData);
        string headerJson = $$"""{"typ":"JWT","x5c":["{{x5cJson}}"]}""";
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid())]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("alg", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A JWT Header missing the required <c>x5c</c> member is rejected.</summary>
    [TestMethod]
    public void MissingHeaderX5cMemberIsRejected()
    {
        //Judgment-keep: the header under test omits x5c entirely, so no certificate is minted here;
        //this key exists solely to satisfy MetadataBlobTestVectors.SignEs256's ECDsa parameter, and
        //no project surface converts pooled key material back into a live ECDsa instance.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        string headerJson = $$"""{"alg":"{{WellKnownJwaValues.Es256}}","typ":"JWT"}""";
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid())]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("x5c", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A Metadata BLOB Payload missing the required <c>nextUpdate</c> member is rejected.</summary>
    [TestMethod]
    public void MissingPayloadNextUpdateMemberIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NoNextUpdate", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        const string payloadJson = """{"no":1,"entries":[]}""";
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("nextUpdate", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A Metadata BLOB Payload entry missing the required <c>metadataStatement</c> member is rejected.</summary>
    [TestMethod]
    public void MissingEntryMetadataStatementMemberIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NoStatement", signingKey);

        const string entryJson = """{"aaguid":"11111111-1111-1111-1111-111111111111","statusReports":[{"status":"FIDO_CERTIFIED"}]}""";
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("metadataStatement", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A Metadata BLOB Payload entry missing the required <c>statusReports</c> member is rejected.</summary>
    [TestMethod]
    public void MissingEntryStatusReportsMemberIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NoStatusReports", signingKey);

        const string entryJson = """{"aaguid":"11111111-1111-1111-1111-111111111111","metadataStatement":{}}""";
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("statusReports", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A <c>metadataStatement</c> repeating the <c>attestationRootCertificates</c> member is rejected.</summary>
    [TestMethod]
    public void RepeatedAttestationRootCertificatesMemberIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer DupRoots", signingKey);

        //Cert-factory carve-out: unlike this file's signing-key pattern (see type remarks), this key
        //mints only the embeddable attestation-root certificate below and never signs the BLOB itself.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attestationRootCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test Attestation Root DupRoots", rootKey);

        string rootB64 = Convert.ToBase64String(attestationRootCertificate.RawData);
        string metadataStatementJson = $$"""{"attestationRootCertificates":["{{rootB64}}"],"attestationRootCertificates":["{{rootB64}}"]}""";
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid(), metadataStatementJson: metadataStatementJson);
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("attestationRootCertificates", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>A status report missing the required <c>status</c> member is rejected.</summary>
    [TestMethod]
    public void MissingStatusReportStatusMemberIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NoStatus", signingKey);

        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid(), statusReportJsons: ["""{"effectiveDate":"2020-01-01"}"""]);
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("status", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A buffer with zero segment-separating dots (not even the one-dot shape
    /// <see cref="MetadataBlobReaderTests.TwoSegmentBlobIsRejected"/> exercises) is rejected with this
    /// reader's own <see cref="Fido2FormatException"/> contract, never an unrelated exception type such
    /// as <see cref="ArgumentOutOfRangeException"/> from indexing a negative offset.
    /// </summary>
    [TestMethod]
    public void ZeroDotBufferIsRejected()
    {
        byte[] blobBytes = Encoding.UTF8.GetBytes("nodotsatall");

        Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// An entry setting NONE of <c>aaid</c>, <c>aaguid</c>, or <c>attestationCertificateKeyIdentifiers</c>
    /// is malformed — the §3.1.1 collective identifier requirement (snapshot lines 2399/2405/2418: each
    /// field's own MUST is conditioned on the authenticator protocol it identifies, and 2418 explicitly
    /// requires <c>attestationCertificateKeyIdentifiers</c> "if neither aaid nor aaguid are set," so an
    /// entry missing all three would be unreachable by every lookup helper yet still parse and sit
    /// inertly in <c>entries</c> without this guard).
    /// </summary>
    [TestMethod]
    public void EntryWithNoIdentifyingMemberIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NoIdentifier", signingKey);

        const string entryJson = """{"metadataStatement":{},"statusReports":[{"status":"FIDO_CERTIFIED"}]}""";
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("attestationCertificateKeyIdentifiers", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// The well-formed sibling of <see cref="EntryWithNoIdentifyingMemberIsRejected"/>: an entry setting
    /// ONLY <c>aaid</c> (neither <c>aaguid</c> nor <c>attestationCertificateKeyIdentifiers</c>) still
    /// parses — <see cref="MetadataBlobReaderTests.HappyPathParsesTwoEntriesOneAaguidOneAcki"/> already
    /// proves the <c>aaguid</c>-only and <c>attestationCertificateKeyIdentifiers</c>-only shapes, so this
    /// closes the third identifying member the collective-identifier guard must not overreach against.
    /// </summary>
    [TestMethod]
    public void EntryWithOnlyAaidIsAccepted()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer AaidOnly", signingKey);

        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaid: "1234#5678");
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        UnverifiedMetadataBlob blob = MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared);
        try
        {
            Assert.AreEqual("1234#5678", blob.Payload.Entries[0].Aaid);
            Assert.IsNull(blob.Payload.Entries[0].Aaguid);
            Assert.IsNull(blob.Payload.Entries[0].AttestationCertificateKeyIdentifiers);
        }
        finally
        {
            blob.Dispose();
        }
    }


    /// <summary>
    /// An <c>attestationCertificateKeyIdentifiers</c> element that is an empty string is rejected —
    /// the producer-format validation section 3.1.1 states for each hex string element (snapshot line
    /// 2411's "hex string"), enforced at parse time rather than left for the query layer to silently
    /// never match.
    /// </summary>
    [TestMethod]
    public void AttestationCertificateKeyIdentifierEmptyElementIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer AckiEmpty", signingKey);

        string entryJson = MetadataBlobTestVectors.BuildEntryJson(attestationCertificateKeyIdentifiers: [""]);
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("attestationCertificateKeyIdentifiers", exception.Message, StringComparison.Ordinal);
        Assert.Contains("empty", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// An <c>attestationCertificateKeyIdentifiers</c> element containing a non-hex character is
    /// rejected — snapshot line 2414: "The hex string MUST NOT contain any non-hex characters."
    /// </summary>
    [TestMethod]
    public void AttestationCertificateKeyIdentifierNonHexElementIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer AckiNonHex", signingKey);

        string entryJson = MetadataBlobTestVectors.BuildEntryJson(attestationCertificateKeyIdentifiers: ["gg112233445566778899aabbccddeeff0011223"]);
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("non-hex", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// An <c>attestationCertificateKeyIdentifiers</c> element containing an upper-case hex letter is
    /// rejected — snapshot line 2416: "All hex letters MUST be lower case." Distinct from
    /// <see cref="MetadataBlobPayloadQueriesTests.TryFindEntryByAttestationCertificateKeyIdentifierComparisonIsCaseSensitive"/>,
    /// which proves the QUERY comparison stays ordinal; this proves the READER itself refuses to parse
    /// a producer-malformed upper-case identifier in the first place.
    /// </summary>
    [TestMethod]
    public void AttestationCertificateKeyIdentifierUppercaseElementIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer AckiUpper", signingKey);

        string entryJson = MetadataBlobTestVectors.BuildEntryJson(attestationCertificateKeyIdentifiers: ["AABBCCDDEEFF00112233445566778899AABBCCDD"]);
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("lower case", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// An explicit JSON <c>null</c> supplied for the OPTIONAL <c>legalHeader</c> member is rejected —
    /// snapshot line 2338: "WebIDL dictionary members MUST NOT have a value of null," which binds an
    /// optional member's VALUE the same as a required one; only the member's ABSENCE is legal for an
    /// optional member (see <see cref="AbsentLegalHeaderIsAccepted"/>). The dedicated null-rejection
    /// message (asserted below) is distinct from the generic "MUST be a string" message an incidental
    /// token-type mismatch alone would produce.
    /// </summary>
    [TestMethod]
    public void ExplicitNullLegalHeaderIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NullLegalHeader", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid());
        string payloadJson = $$"""{"legalHeader":null,"no":1,"nextUpdate":"2030-01-01","entries":[{{entryJson}}]}""";
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("legalHeader", exception.Message, StringComparison.Ordinal);
        Assert.Contains("null", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// The well-formed sibling of <see cref="ExplicitNullLegalHeaderIsRejected"/>: an entirely ABSENT
    /// <c>legalHeader</c> member parses without complaint — absent and null are different, and only the
    /// latter is malformed per snapshot line 2338.
    /// </summary>
    [TestMethod]
    public void AbsentLegalHeaderIsAccepted()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer AbsentLegalHeader", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid());
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson], legalHeader: null);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        UnverifiedMetadataBlob blob = MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared);
        try
        {
            Assert.IsNull(blob.Payload.LegalHeader);
        }
        finally
        {
            blob.Dispose();
        }
    }


    /// <summary>
    /// An explicit JSON <c>null</c> supplied for the REQUIRED <c>entries</c> member (a WebIDL List) is
    /// rejected with the dedicated null message — distinct from both the "MUST be a JSON array" message
    /// a bare type mismatch would produce and from <see cref="EmptyEntriesArrayIsAccepted"/>'s legal
    /// present-but-empty shape: null, empty, and absent are three different shapes, and only null and
    /// absence-of-a-required-member are malformed here.
    /// </summary>
    [TestMethod]
    public void ExplicitNullEntriesMemberIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NullEntries", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        const string payloadJson = """{"no":1,"nextUpdate":"2030-01-01","entries":null}""";
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("entries", exception.Message, StringComparison.Ordinal);
        Assert.Contains("null", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// The well-formed sibling of <see cref="ExplicitNullEntriesMemberIsRejected"/> and the documented
    /// carve-out from the general WebIDL "List MUST NOT be an empty list" rule (snapshot line 2340): a
    /// present-but-EMPTY <c>entries</c> array parses successfully, per the specification's own "List of
    /// zero or more MetadataBLOBPayloadEntry objects" at snapshot line 2962.
    /// </summary>
    [TestMethod]
    public void EmptyEntriesArrayIsAccepted()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer EmptyEntries", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        const string payloadJson = """{"no":1,"nextUpdate":"2030-01-01","entries":[]}""";
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        UnverifiedMetadataBlob blob = MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared);
        try
        {
            Assert.IsEmpty(blob.Payload.Entries);
        }
        finally
        {
            blob.Dispose();
        }
    }


    /// <summary>
    /// An explicit JSON <c>null</c> supplied for the REQUIRED <c>metadataStatement</c> member (a WebIDL
    /// object-shaped member) is rejected with the dedicated null message rather than the generic "MUST
    /// be a JSON object" message a bare token-type mismatch alone would have produced — proving the null
    /// guard fires FIRST, not merely incidentally.
    /// </summary>
    [TestMethod]
    public void ExplicitNullMetadataStatementMemberIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NullStatement", signingKey);

        const string entryJson = """{"aaguid":"11111111-1111-1111-1111-111111111111","metadataStatement":null,"statusReports":[{"status":"FIDO_CERTIFIED"}]}""";
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("metadataStatement", exception.Message, StringComparison.Ordinal);
        Assert.Contains("null", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// An empty (zero-length) <c>legalHeader</c> DOMString is rejected — snapshot line 2339: "if a
    /// WebIDL dictionary member is DOMString, it MUST NOT be empty," distinct from the null case above:
    /// an empty string is a well-typed, present value, not a type mismatch and not <c>null</c>.
    /// </summary>
    [TestMethod]
    public void EmptyLegalHeaderIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer EmptyLegalHeader", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid());
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson], legalHeader: "");
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("legalHeader", exception.Message, StringComparison.Ordinal);
        Assert.Contains("empty", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A present-but-EMPTY <c>x5c</c> array in the JWT Header is rejected — this library's own secure
    /// default applying section 1's general WebIDL "List MUST NOT be an empty list" rule (snapshot line
    /// 2340) to <c>x5c</c> even though it is an RFC 7515 header member rather than an MDS v3.1 WebIDL
    /// dictionary member itself: a zero-certificate chain can never satisfy the signature-verification
    /// step that follows, so accepting it would only defer an inevitable rejection to a less precise
    /// failure point.
    /// </summary>
    [TestMethod]
    public void EmptyX5cArrayIsRejected()
    {
        //Judgment-keep: the header's x5c array is present but empty, so no certificate is minted
        //here; this key exists solely to satisfy MetadataBlobTestVectors.SignEs256's ECDsa
        //parameter, and no project surface converts pooled key material back into a live ECDsa
        //instance.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        const string headerJson = """{"alg":"ES256","typ":"JWT","x5c":[]}""";
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid());
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("x5c", exception.Message, StringComparison.Ordinal);
        Assert.Contains("empty", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A present-but-EMPTY <c>attestationCertificateKeyIdentifiers</c> array is rejected — snapshot line
    /// 2340's general WebIDL list-emptiness rule, with no carve-out for this member (unlike <c>entries</c>,
    /// see <see cref="EmptyEntriesArrayIsAccepted"/>).
    /// </summary>
    [TestMethod]
    public void EmptyAttestationCertificateKeyIdentifiersArrayIsRejected()
    {
        //Cert-factory + oracle carve-out (see type remarks): mints the MDS root CA and signs the BLOB.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer EmptyAcki", signingKey);

        const string entryJson = """{"attestationCertificateKeyIdentifiers":[],"metadataStatement":{},"statusReports":[{"status":"FIDO_CERTIFIED"}]}""";
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));

        Assert.Contains("attestationCertificateKeyIdentifiers", exception.Message, StringComparison.Ordinal);
        Assert.Contains("empty", exception.Message, StringComparison.Ordinal);
    }
}

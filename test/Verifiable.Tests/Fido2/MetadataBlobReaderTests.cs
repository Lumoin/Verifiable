using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="MetadataBlobReader"/> — the shipped default for
/// <see cref="ParseMetadataBlobDelegate"/>.
/// </summary>
/// <remarks>
/// Every vector is minted at test time via <see cref="MetadataBlobTestVectors"/>'s hand-assembled
/// compact-JWS builder, never a frozen external fixture, per
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob">FIDO
/// Metadata Service v3.1, section 3.1.7: Metadata BLOB</see>.
/// </remarks>
[TestClass]
internal sealed class MetadataBlobReaderTests
{
    /// <summary>
    /// A happy-path BLOB with two entries — one AAGUID'd FIDO2 entry carrying an attestation root
    /// certificate, one <c>attestationCertificateKeyIdentifiers</c>'d U2F entry — parses every
    /// modeled field correctly.
    /// </summary>
    [TestMethod]
    public void HappyPathParsesTwoEntriesOneAaguidOneAcki()
    {
        //Cert-factory carve-out: backs CreateMdsRootCa's CertificateRequest (requires a genuine ECDsa instance) and also signs the JWS tbsPayload via SignEs256, producing realistic (Read()-unverified) signature bytes.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //Cert-factory carve-out: backs CreateMdsRootCa's CertificateRequest below, which requires a genuine framework ECDsa instance.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer Standalone", signingKey);
        using var attestationRootCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test Attestation Root", rootKey);

        Guid aaguid = Guid.NewGuid();
        string entry1 = MetadataBlobTestVectors.BuildEntryJson(
            aaguid: aaguid,
            metadataStatementJson: MetadataBlobTestVectors.BuildMetadataStatementJson([attestationRootCertificate.RawData]));
        string entry2 = MetadataBlobTestVectors.BuildEntryJson(
            attestationCertificateKeyIdentifiers: ["aabbccddeeff00112233445566778899aabbccdd"]);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entry1, entry2]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        UnverifiedMetadataBlob blob = MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared);
        try
        {
            Assert.AreEqual(WellKnownJwaValues.Es256, blob.Algorithm);
            Assert.HasCount(1, blob.X5c);
            Assert.IsTrue(blob.X5c[0].AsReadOnlySpan().SequenceEqual(signerCertificate.RawData));
            Assert.AreEqual(1L, blob.Payload.No);
            Assert.AreEqual(new DateOnly(2030, 1, 1), blob.Payload.NextUpdate);
            Assert.HasCount(2, blob.Payload.Entries);

            MetadataBlobPayloadEntry fido2Entry = blob.Payload.Entries[0];
            Assert.AreEqual(aaguid, fido2Entry.Aaguid);
            Assert.IsNull(fido2Entry.Aaid);
            Assert.IsNotNull(fido2Entry.AttestationRootCertificates);
            Assert.HasCount(1, fido2Entry.AttestationRootCertificates!);
            Assert.IsTrue(fido2Entry.AttestationRootCertificates![0].AsReadOnlySpan().SequenceEqual(attestationRootCertificate.RawData));
            Assert.HasCount(1, fido2Entry.StatusReports);
            Assert.AreEqual(WellKnownAuthenticatorStatuses.FidoCertified, fido2Entry.StatusReports[0].Status);

            MetadataBlobPayloadEntry u2fEntry = blob.Payload.Entries[1];
            Assert.IsNull(u2fEntry.Aaguid);
            Assert.IsNotNull(u2fEntry.AttestationCertificateKeyIdentifiers);
            Assert.Contains("aabbccddeeff00112233445566778899aabbccdd", u2fEntry.AttestationCertificateKeyIdentifiers!);
        }
        finally
        {
            blob.Dispose();
        }
    }


    /// <summary>A two-segment (header.payload, no signature) buffer is rejected.</summary>
    [TestMethod]
    public void TwoSegmentBlobIsRejected()
    {
        byte[] blobBytes = Encoding.UTF8.GetBytes("aGVhZGVy.cGF5bG9hZA");

        Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));
    }


    /// <summary>A four-segment (JWE-shaped) buffer is rejected.</summary>
    [TestMethod]
    public void FourSegmentBlobIsRejected()
    {
        byte[] blobBytes = Encoding.UTF8.GetBytes("aGVhZGVy.cGF5bG9hZA.c2ln.ZXh0cmE");

        Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));
    }


    /// <summary>A payload segment that is not valid base64url is rejected.</summary>
    [TestMethod]
    public void BadBase64UrlPayloadSegmentIsRejected()
    {
        //Cert-factory carve-out: backs CreateMdsRootCa's CertificateRequest below, which requires a genuine framework ECDsa instance.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer BadB64", signingKey);
        string headerSegment = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(
            MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData])));
        byte[] blobBytes = Encoding.UTF8.GetBytes($"{headerSegment}.!!!not-base64url!!!.c2ln");

        Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));
    }


    /// <summary>A JWT Header carrying an <c>x5u</c> member is rejected outright — out of this library's fetcher-free scope.</summary>
    [TestMethod]
    public void X5uHeaderIsRejected()
    {
        //Cert-factory carve-out: backs CreateMdsRootCa's CertificateRequest (requires a genuine ECDsa instance) and also signs the JWS tbsPayload via SignEs256, producing realistic (Read()-unverified) signature bytes.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer X5u", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData], includeX5u: true);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid())]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));
    }


    /// <summary>A Metadata BLOB Payload with a repeated top-level member (<c>no</c> twice) is rejected.</summary>
    [TestMethod]
    public void DuplicateTopLevelPayloadMemberIsRejected()
    {
        //Cert-factory carve-out: backs CreateMdsRootCa's CertificateRequest (requires a genuine ECDsa instance) and also signs the JWS tbsPayload via SignEs256, producing realistic (Read()-unverified) signature bytes.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer Dup", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        const string payloadJson = """{"no":1,"no":2,"nextUpdate":"2030-01-01","entries":[]}""";
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));
    }


    /// <summary>A Metadata BLOB Payload whose top level is a JSON array, not an object, is rejected.</summary>
    [TestMethod]
    public void NonObjectPayloadIsRejected()
    {
        //Cert-factory carve-out: backs CreateMdsRootCa's CertificateRequest (requires a genuine ECDsa instance) and also signs the JWS tbsPayload via SignEs256, producing realistic (Read()-unverified) signature bytes.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NonObj", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        const string payloadJson = "[]";
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));
    }


    /// <summary>A Metadata BLOB Payload missing the required <c>entries</c> member is rejected.</summary>
    [TestMethod]
    public void MissingEntriesMemberIsRejected()
    {
        //Cert-factory carve-out: backs CreateMdsRootCa's CertificateRequest (requires a genuine ECDsa instance) and also signs the JWS tbsPayload via SignEs256, producing realistic (Read()-unverified) signature bytes.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer NoEntries", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        const string payloadJson = """{"no":1,"nextUpdate":"2030-01-01"}""";
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));
        Assert.Contains("entries", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>An entry whose <c>aaguid</c> is not a canonical GUID string is rejected.</summary>
    [TestMethod]
    public void NonCanonicalAaguidIsRejected()
    {
        //Cert-factory carve-out: backs CreateMdsRootCa's CertificateRequest (requires a genuine ECDsa instance) and also signs the JWS tbsPayload via SignEs256, producing realistic (Read()-unverified) signature bytes.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer BadGuid", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        const string entryJson = """{"aaguid":"not-a-guid","metadataStatement":{},"statusReports":[{"status":"FIDO_CERTIFIED"}]}""";
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));
    }


    /// <summary>Nesting beyond the reader's depth bound is rejected.</summary>
    [TestMethod]
    public void ExcessiveNestingDepthIsRejected()
    {
        //Cert-factory carve-out: backs CreateMdsRootCa's CertificateRequest (requires a genuine ECDsa instance) and also signs the JWS tbsPayload via SignEs256, producing realistic (Read()-unverified) signature bytes.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Signer DeepNest", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string deeplyNestedValue = BuildDeeplyNestedJsonValue(24);
        string entryJson = $$"""{"aaguid":"{{Guid.NewGuid():D}}","metadataStatement":{"poison":{{deeplyNestedValue}}},"statusReports":[{"status":"FIDO_CERTIFIED"}]}""";
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        Assert.ThrowsExactly<Fido2FormatException>(() => MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Builds a JSON value nested <paramref name="depth"/> levels deep — <c>{"a":{"a":…1…}}</c> —
    /// deep enough to exceed <see cref="MetadataBlobReader"/>'s <c>MaxDepth</c> bound when embedded
    /// within an already-nested payload/entry/metadataStatement structure.
    /// </summary>
    private static string BuildDeeplyNestedJsonValue(int depth)
    {
        var builder = new System.Text.StringBuilder();
        for(int i = 0; i < depth; i++)
        {
            builder.Append("{\"a\":");
        }

        builder.Append('1');
        for(int i = 0; i < depth; i++)
        {
            builder.Append('}');
        }

        return builder.ToString();
    }
}

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="MetadataBlobPayloadQueries"/>'s query-layer edge cases: <c>attestationCertificateKeyIdentifiers</c>
/// (U2F) lookup, the no-status-reports and equal-effective-date branches of <see cref="MetadataBlobPayloadQueries.EvaluateStatus"/>,
/// and the absent/empty-array branches of <see cref="MetadataBlobPayloadQueries.GetAttestationTrustAnchors"/> — every
/// entry parsed through the SHIPPED <see cref="MetadataBlobReader"/> default, never hand-constructed, so a defect in
/// the reader's own field wiring would surface here too.
/// </summary>
/// <remarks>
/// These tests exercise <see cref="MetadataBlobPayloadQueries"/> in isolation from
/// <see cref="MetadataBlobVerification"/>'s signature/chain/status-gate machinery (already covered by
/// <c>MetadataBlobVerificationTests</c>) — mirroring <c>MetadataBlobReaderTests</c>'s lighter shape of calling
/// <see cref="MetadataBlobReader.Read"/> directly, since none of these findings concern BLOB trust establishment.
/// </remarks>
[TestClass]
internal sealed class MetadataBlobPayloadQueriesTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// An entry with zero <c>statusReports</c> is accepted with no deciding report — the specification's
    /// "assumed effective while present" reading for an unreported authenticator, per
    /// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-stat-rep">FIDO
    /// Metadata Service v3.1, section 3.1.3</see>. Distinguishes the dedicated empty-list early return from a
    /// mutation that would instead throw on <c>StatusReports[0]</c> or silently reject the entry.
    /// </summary>
    [TestMethod]
    public void EvaluateStatusWithZeroStatusReportsAcceptsWithNoDecidingReport()
    {
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid(), statusReportJsons: []);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);
        MetadataBlobPayloadEntry entry = blob.Payload.Entries[0];
        Assert.IsEmpty(entry.StatusReports);

        MetadataStatusEvaluation evaluation = MetadataBlobPayloadQueries.EvaluateStatus(entry);

        Assert.IsTrue(evaluation.Accepted);
        Assert.IsNull(evaluation.DecidingStatusReport);
    }


    /// <summary>
    /// A query for an <c>attestationCertificateKeyIdentifiers</c> value present on an entry finds that exact entry —
    /// the FIDO2-MDS §3.1.1 U2F lookup path, per
    /// <see cref="MetadataBlobPayloadQueries.TryFindEntryByAttestationCertificateKeyIdentifier"/>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The out entry aliases an element already owned by blob.Payload.Entries, disposed via blob.Dispose() — not separately; the analyzer cannot see that ownership relationship from the call site alone.")]
    public void TryFindEntryByAttestationCertificateKeyIdentifierFindsExactMatch()
    {
        const string keyIdentifier = "aabbccddeeff00112233445566778899aabbccdd";
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(attestationCertificateKeyIdentifiers: [keyIdentifier]);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);

        bool found = MetadataBlobPayloadQueries.TryFindEntryByAttestationCertificateKeyIdentifier(blob.Payload, keyIdentifier, out MetadataBlobPayloadEntry? entry);

        Assert.IsTrue(found);
        Assert.AreSame(blob.Payload.Entries[0], entry);
    }


    /// <summary>
    /// A query for an <c>attestationCertificateKeyIdentifiers</c> value that matches no entry reports a miss rather
    /// than a false hit.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TryFindEntryByAttestationCertificateKeyIdentifier reports a miss here, so the out entry is null — there is nothing to dispose; the analyzer cannot see that from the call site alone.")]
    public void TryFindEntryByAttestationCertificateKeyIdentifierReportsMissForUnknownIdentifier()
    {
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(attestationCertificateKeyIdentifiers: ["aabbccddeeff00112233445566778899aabbccdd"]);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);

        bool found = MetadataBlobPayloadQueries.TryFindEntryByAttestationCertificateKeyIdentifier(blob.Payload, "0011223344556677889900112233445566778899", out MetadataBlobPayloadEntry? entry);

        Assert.IsFalse(found);
        Assert.IsNull(entry);
    }


    /// <summary>
    /// A differently-cased query string misses even the entry whose identifier is otherwise identical — proving
    /// the lookup compares ordinally, as its own documentation states, rather than case-insensitively. A mutation
    /// widening the comparison to <see cref="StringComparison.OrdinalIgnoreCase"/> would pass every other test in
    /// this file while failing only this one.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TryFindEntryByAttestationCertificateKeyIdentifier reports a miss here, so the out entry is null — there is nothing to dispose; the analyzer cannot see that from the call site alone.")]
    public void TryFindEntryByAttestationCertificateKeyIdentifierComparisonIsCaseSensitive()
    {
        const string keyIdentifier = "aabbccddeeff00112233445566778899aabbccdd";
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(attestationCertificateKeyIdentifiers: [keyIdentifier]);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);

        bool found = MetadataBlobPayloadQueries.TryFindEntryByAttestationCertificateKeyIdentifier(blob.Payload, keyIdentifier.ToUpperInvariant(), out MetadataBlobPayloadEntry? entry);

        Assert.IsFalse(found);
        Assert.IsNull(entry);
    }


    /// <summary>
    /// An identifier DERIVED from an attestation certificate — RFC 5280 §4.2.1.2 method 1, the same
    /// formula .NET's own <see cref="X509SubjectKeyIdentifierExtension.CreateFromSubjectPublicKeyInfo(PublicKey, bool)"/>
    /// computes as an independent oracle — finds the entry whose <c>attestationCertificateKeyIdentifiers</c>
    /// carries that exact value. This is the consumer-side mirror of FIDO Metadata Service v3.1 section
    /// 3.1.1's "MUST be calculated according to method 1… as defined in [RFC5280] section 4.2.1.2": the
    /// caller hands over the certificate itself via
    /// <see cref="MetadataBlobPayloadQueries.TryFindEntryByAttestationCertificateKeyIdentifierAsync"/>,
    /// never a self-reported string it would otherwise have to trust blindly.
    /// </summary>
    [TestMethod]
    public async Task TryFindEntryByAttestationCertificateKeyIdentifierAsyncDerivesIdentifierFromCertificateAndFindsMatch()
    {
        //The key feeds MetadataBlobTestVectors.CreateMdsRootCa's CertificateRequest-based minting, the
        //test-side X.509 certificate factory carve-out — the certificate itself is the fixture, not the key.
        using ECDsa attestationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 attestationCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test Attestation Cert SKI Match", attestationKey);

        //Independent oracle: X509SubjectKeyIdentifierExtension computes RFC 5280 method 1 from the certificate's
        //own SubjectPublicKeyInfo, so the library's internally derived identifier is proven against it below.
        var expectedSkiExtension = new X509SubjectKeyIdentifierExtension(attestationCertificate.PublicKey, critical: false);
        string expectedHexSki = Convert.ToHexStringLower(expectedSkiExtension.SubjectKeyIdentifierBytes.Span);

        string entryJson = MetadataBlobTestVectors.BuildEntryJson(attestationCertificateKeyIdentifiers: [expectedHexSki]);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);
        using PkiCertificateMemory certificateMemory = MetadataBlobTestVectors.ToPkiCertificateMemory(attestationCertificate.RawData);

        (bool isFound, MetadataBlobPayloadEntry? entry) = await MetadataBlobPayloadQueries.TryFindEntryByAttestationCertificateKeyIdentifierAsync(
            blob.Payload, certificateMemory, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(isFound);
        Assert.AreSame(blob.Payload.Entries[0], entry);
    }


    /// <summary>
    /// An identifier derived from a certificate that matches no entry's <c>attestationCertificateKeyIdentifiers</c>
    /// reports a miss rather than a false hit — proving
    /// <see cref="MetadataBlobPayloadQueries.TryFindEntryByAttestationCertificateKeyIdentifierAsync"/>
    /// does not degenerate into an always-true stub once the identifier is computed.
    /// </summary>
    [TestMethod]
    public async Task TryFindEntryByAttestationCertificateKeyIdentifierAsyncReportsMissForUnrelatedCertificate()
    {
        const string keyIdentifier = "aabbccddeeff00112233445566778899aabbccdd";
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(attestationCertificateKeyIdentifiers: [keyIdentifier]);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);

        //The key feeds MetadataBlobTestVectors.CreateMdsRootCa's CertificateRequest-based minting, the
        //test-side X.509 certificate factory carve-out — the certificate itself is the fixture, not the key.
        using ECDsa unrelatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 unrelatedCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test Attestation Cert SKI Miss", unrelatedKey);
        using PkiCertificateMemory certificateMemory = MetadataBlobTestVectors.ToPkiCertificateMemory(unrelatedCertificate.RawData);

        (bool isFound, MetadataBlobPayloadEntry? entry) = await MetadataBlobPayloadQueries.TryFindEntryByAttestationCertificateKeyIdentifierAsync(
            blob.Payload, certificateMemory, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsFalse(isFound);
        Assert.IsNull(entry);
    }


    /// <summary>
    /// A status report carrying a non-null <c>certificate</c> round-trips through the reader and is
    /// retrievable from the deciding <see cref="MetadataStatusEvaluation.DecidingStatusReport"/> — the
    /// minimum honest evidence for FIDO Metadata Service v3.1 section 3.1.3's batch-identification
    /// SHOULD ("the relying party SHOULD check the certificate field and use it to identify the
    /// compromised authenticator batch"), distinct from the coarser blanket default-policy rejection
    /// <c>MetadataBlobVerificationTests.AttestationKeyCompromiseRejectsTrustUnderDefaultPolicy</c> proves.
    /// </summary>
    [TestMethod]
    public void DecidingStatusReportCarriesCertificateWhenPresent()
    {
        //The key feeds MetadataBlobTestVectors.CreateMdsRootCa's CertificateRequest-based minting, the
        //test-side X.509 certificate factory carve-out — the certificate itself is the fixture, not the key.
        using ECDsa compromisedBatchKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 compromisedBatchCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test Compromised Batch Certificate", compromisedBatchKey);
        string certificateBase64 = Convert.ToBase64String(compromisedBatchCertificate.RawData);

        string statusReportJson = MetadataBlobTestVectors.BuildStatusReportJson(WellKnownAuthenticatorStatuses.AttestationKeyCompromise, "2025-01-01", certificateBase64);
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid(), statusReportJsons: [statusReportJson]);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);
        MetadataBlobPayloadEntry entry = blob.Payload.Entries[0];

        MetadataStatusEvaluation evaluation = MetadataBlobPayloadQueries.EvaluateStatus(entry);

        Assert.AreEqual(certificateBase64, evaluation.DecidingStatusReport!.Certificate);
    }


    /// <summary>
    /// An entry whose sole status report carries an invented, unrecognized status string parses and
    /// evaluates without throwing, and is ACCEPTED because the invented value is absent from
    /// <see cref="WellKnownAuthenticatorStatuses.DefaultTrustTerminating"/> — closing FIDO Metadata
    /// Service v3.1 section 3.1.4's "FIDO Servers MUST silently ignore all unknown AuthenticatorStatus
    /// values" non-vacuously: the reader's unconstrained-string parsing and the evaluator's
    /// set-membership check both structurally satisfy the MUST, but only supplying an actual
    /// unrecognized value proves it holds rather than merely being structurally compatible with it.
    /// </summary>
    [TestMethod]
    public void UnrecognizedStatusValueIsSilentlyAcceptedRatherThanRejected()
    {
        const string inventedStatus = "SOME_FUTURE_STATUS";
        string statusReportJson = MetadataBlobTestVectors.BuildStatusReportJson(inventedStatus, "2025-01-01");
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid(), statusReportJsons: [statusReportJson]);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);
        MetadataBlobPayloadEntry entry = blob.Payload.Entries[0];

        MetadataStatusEvaluation evaluation = MetadataBlobPayloadQueries.EvaluateStatus(entry);

        Assert.AreEqual(inventedStatus, evaluation.DecidingStatusReport!.Status);
        Assert.IsTrue(evaluation.Accepted);
    }


    /// <summary>
    /// An entry whose <c>metadataStatement</c> omits <c>attestationRootCertificates</c> entirely (so
    /// <see cref="MetadataBlobPayloadEntry.AttestationRootCertificates"/> is <see langword="null"/>) yields no trust
    /// anchors rather than throwing — the shape <see cref="MetadataBlobTestVectors.BuildMetadataStatementJson"/>'s
    /// own default produces, and the one no test in <c>MetadataDrivenRegistrationTests</c> exercises (its only
    /// caller always supplies exactly one root certificate).
    /// </summary>
    [TestMethod]
    public void GetAttestationTrustAnchorsReturnsEmptyWhenMemberIsAbsent()
    {
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid());
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);
        MetadataBlobPayloadEntry entry = blob.Payload.Entries[0];
        Assert.IsNull(entry.AttestationRootCertificates);

        IReadOnlyList<PkiCertificateMemory> anchors = MetadataBlobPayloadQueries.GetAttestationTrustAnchors(entry, BaseMemoryPool.Shared);

        Assert.IsEmpty(anchors);
    }


    /// <summary>
    /// An entry whose <c>metadataStatement</c> carries a present-but-empty <c>attestationRootCertificates</c>
    /// array also yields no trust anchors — the distinct "member present, zero elements" shape from the
    /// "member absent" case above, both routed through the same <c>{ Count: &gt; 0 }</c> guard.
    /// </summary>
    [TestMethod]
    public void GetAttestationTrustAnchorsReturnsEmptyWhenArrayIsPresentButEmpty()
    {
        string metadataStatementJson = MetadataBlobTestVectors.BuildMetadataStatementJson(attestationRootCertificates: []);
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid(), metadataStatementJson: metadataStatementJson);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);
        MetadataBlobPayloadEntry entry = blob.Payload.Entries[0];
        Assert.IsNotNull(entry.AttestationRootCertificates);
        Assert.IsEmpty(entry.AttestationRootCertificates!);

        IReadOnlyList<PkiCertificateMemory> anchors = MetadataBlobPayloadQueries.GetAttestationTrustAnchors(entry, BaseMemoryPool.Shared);

        Assert.IsEmpty(anchors);
    }


    /// <summary>
    /// Two status reports dated on the SAME <c>effectiveDate</c> break their tie in favor of the one appearing
    /// LAST in wire order — proving the comparison is <c>&gt;=</c>, not <c>&gt;</c>. A <c>&gt;</c> mutation would
    /// leave the first-listed report deciding instead, flipping this assertion.
    /// </summary>
    [TestMethod]
    public void EvaluateStatusTieBreakWithEqualDatesPicksLastInWireOrder()
    {
        string[] statusReports =
        [
            MetadataBlobTestVectors.BuildStatusReportJson(WellKnownAuthenticatorStatuses.FidoCertified, "2025-01-01"),
            MetadataBlobTestVectors.BuildStatusReportJson(WellKnownAuthenticatorStatuses.Revoked, "2025-01-01")
        ];
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid(), statusReportJsons: statusReports);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);
        MetadataBlobPayloadEntry entry = blob.Payload.Entries[0];

        MetadataStatusEvaluation evaluation = MetadataBlobPayloadQueries.EvaluateStatus(entry);

        Assert.AreEqual(WellKnownAuthenticatorStatuses.Revoked, evaluation.DecidingStatusReport!.Status);
        Assert.IsFalse(evaluation.Accepted);
    }


    /// <summary>
    /// Two status reports that carry no <c>effectiveDate</c> at all (both treated as effective from
    /// <see cref="DateOnly.MinValue"/>, per <see cref="MetadataBlobPayloadQueries.EvaluateStatus"/>'s own remarks)
    /// break their tie the same way — the one appearing LAST in wire order decides — proving the "latest…
    /// entry" wire-order fallback holds even when dates cannot distinguish the reports at all, not merely when
    /// they happen to coincide.
    /// </summary>
    [TestMethod]
    public void EvaluateStatusTieBreakWithBothReportsUndatedPicksLastInWireOrder()
    {
        string[] statusReports =
        [
            MetadataBlobTestVectors.BuildStatusReportJson(WellKnownAuthenticatorStatuses.FidoCertified),
            MetadataBlobTestVectors.BuildStatusReportJson(WellKnownAuthenticatorStatuses.Revoked)
        ];
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid(), statusReportJsons: statusReports);
        using MetadataBlob blob = ParseSingleEntryBlob(entryJson);
        MetadataBlobPayloadEntry entry = blob.Payload.Entries[0];

        MetadataStatusEvaluation evaluation = MetadataBlobPayloadQueries.EvaluateStatus(entry);

        Assert.AreEqual(WellKnownAuthenticatorStatuses.Revoked, evaluation.DecidingStatusReport!.Status);
        Assert.IsFalse(evaluation.Accepted);
    }


    /// <summary>
    /// Parses a Metadata BLOB carrying a single entry through the SHIPPED <see cref="MetadataBlobReader.Read"/>
    /// default. The BLOB-signing certificate is a throwaway, self-signed fixture: none of this file's tests
    /// exercise <see cref="MetadataBlobVerification"/>'s signature/chain machinery, so the signing key never
    /// needs to chain to any particular trust anchor.
    /// </summary>
    /// <param name="entryJson">The single entry's JSON text.</param>
    /// <returns>The verified projection of the parsed BLOB; the caller owns and disposes it.</returns>
    private static MetadataBlob ParseSingleEntryBlob(string entryJson)
    {
        //The key feeds MetadataBlobTestVectors.CreateMdsRootCa's CertificateRequest-based minting, the
        //test-side X.509 certificate factory carve-out, and is reused below to sign the BLOB bytes themselves.
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 signerCertificate = MetadataBlobTestVectors.CreateMdsRootCa("CN=Test MDS Query Signer", signingKey);

        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [signerCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, "2030-01-01", [entryJson]);
        byte[] blobBytes = MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(signingKey, data));

        UnverifiedMetadataBlob unverifiedBlob = MetadataBlobReader.Read(blobBytes, BaseMemoryPool.Shared);

        //Trust establishment (signature/chain verification) is out of scope for these findings, per
        //this file's own remarks — the verified projection is constructed directly from parse-only output.
        return unverifiedBlob.ToVerified();
    }
}

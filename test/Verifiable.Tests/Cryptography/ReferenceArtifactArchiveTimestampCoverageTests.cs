using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.X509;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using AlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The reference-artifact leg of the CAdES-A / B-LTA archive-time-stamp coverage computation of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clauses 5.5.2 and 5.5.3</see>: third-party CAdES artifacts carrying at least one
/// embedded archive time-stamp are driven through <see cref="ArchiveTimestampV3.StateCoverageAsync"/> and, for
/// the ones this leg names individually, through the shipped
/// <see cref="SignatureValidation.ValidateAsync"/> engine, and the precise outcome each one reaches is asserted.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Where the artifacts come from.</strong> The same local reference-artifact clone under
/// <c>tempdocs/etsi-ades-reference/</c> that <c>ReferenceArtifactSignatureValidationTests</c> reads, discovered
/// by the identical directory-layout search (a "validation" directory under "src/test/resources" that actually
/// holds signed CAdES artifacts). Nothing is copied into this repository, and when the clone is absent every
/// test here reports <see cref="Assert.Inconclusive(string)"/> instead of failing.
/// </para>
/// <para>
/// <strong>The selection rule.</strong> Every file of that same corpus (<c>.p7m</c>, <c>.p7s</c>, <c>.pkcs7</c>,
/// enumerated recursively and ordered ordinally — the exact set <c>ReferenceArtifactSignatureValidationTests</c>
/// pins at 110) whose CAdES signature facts extraction succeeds and whose
/// <see cref="SignatureFacts.TimestampsOfClass"/> reports at least one timestamp of
/// <see cref="SignatureTimestampClass.ArchiveTimestamp"/>. This is the ENTIRE such subset of the pinned corpus,
/// not a curated pick: nothing is selected for a favourable outcome, and <see cref="TheArchiveTimestampBearingSubsetProducesExactlyTheDocumentedCoverageDistribution"/>
/// pins the whole distribution, so an artifact silently changing bucket is a failure rather than a shrug. Five
/// of the twenty-eight carry a genuine <c>ats-hash-index-v3</c> (Annex D's <c>archive-time-stamp-v3</c> form,
/// clause 5.5.3); the remaining twenty-three are classified <see cref="SignatureTimestampClass.ArchiveTimestamp"/>
/// through the deprecated ATSv2 object identifier (Annex A.2.4) and carry no such index, which
/// <see cref="ArchiveTimestampV3.StateCoverageAsync"/> reports precisely as
/// <see cref="ArchiveTimestampCoverageStatus.HashIndexAbsent"/> rather than mistaking for an error.
/// </para>
/// <para>
/// <strong>What "real coverage" means here.</strong> Every status this leg asserts is reached by recomputing the
/// clause 5.5.2 hash indexes over the artifact's own current certificates, revocation information and unsigned
/// attribute values and checking them against the index a third party's own tooling wrote — the same component
/// (<see cref="ArchiveTimestampV3"/>) the creation surface of this wave computes an index with. Where the index
/// is well-formed, this leg additionally verifies the assembled clause 5.5.3 message-imprint input against the
/// third-party time-stamp token's own <c>messageImprint</c> field through
/// <see cref="TimestampTokenInfo.VerifyMessageImprintAsync"/> — a genuine cryptographic check against a signature
/// this library never produced, not merely a status flag.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ReferenceArtifactArchiveTimestampCoverageTests
{
    /// <summary>How many artifacts of the pinned 110-artifact corpus carry at least one archive time-stamp, at the clone revision this class was written against.</summary>
    private const int ExpectedArchiveTimestampArtifactCount = 28;


    /// <summary>How many individual embedded archive time-stamps the twenty-eight artifacts carry in total (three artifacts carry two each).</summary>
    private const int ExpectedArchiveTimestampCount = 37;


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The coverage status every embedded archive time-stamp of the subset reaches, tallied by
    /// <see cref="ArchiveTimestampCoverageStatus"/>. Every bucket is a documented consequence of the artifact's
    /// own shape, recorded in this class's build-log section.
    /// </summary>
    private static FrozenDictionary<ArchiveTimestampCoverageStatus, int> ExpectedCoverageStatusDistribution { get; } =
        new Dictionary<ArchiveTimestampCoverageStatus, int>
        {
            //A genuine ats-hash-index-v3 whose entries all match the material the signature carries now.
            [ArchiveTimestampCoverageStatus.Stated] = 5,

            //The deprecated ATSv2 form: a genuine archive time-stamp classified by its object identifier, whose
            //token carries no ats-hash-index-v3 attribute to state anything about (Annex A.2.4).
            [ArchiveTimestampCoverageStatus.HashIndexAbsent] = 26,

            //A genuine ats-hash-index-v3 that no longer matches the material it names — five deliberately
            //tampered fixtures of the corpus (their own names say so: "wrong-cert", "wrong-crl", "wrong-ocsp",
            //"rev-val-crl", "rev-val-ocsp").
            [ArchiveTimestampCoverageStatus.HashIndexInvalid] = 5,

            //A genuine ats-hash-index-v3 over a detached signature: the index itself is valid, but step 2) of
            //the clause 5.5.3 message-imprint input has no signed content to hash (NOTE 1), so nothing is stated.
            [ArchiveTimestampCoverageStatus.SignedContentUnavailable] = 1
        }.ToFrozenDictionary();


    /// <summary>
    /// The sub-indication of clause 5.1.3 every artifact of the subset reaches when the Driving Application
    /// supplies no trust anchor and no revocation material at all, tallied. Every run is
    /// <c>INDETERMINATE</c>, never <c>TOTAL-PASSED</c> (clause 5.1.3 makes that unreachable without a trust
    /// anchor) and never <c>TOTAL-FAILED</c> (nothing about any of these twenty-eight artifacts' own signatures
    /// is wrong; they are simply artifacts the Driving Application does not yet trust).
    /// </summary>
    private static FrozenDictionary<string, int> ExpectedNoContextSubIndicationDistribution { get; } =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            //Step 2)a) of clause 5.2.6.4 ends chain building with no trust anchor to reach.
            ["NO_CERTIFICATE_CHAIN_FOUND"] = 20,

            //Detached artifacts: the shipped CMS verification seam verifies encapsulated content only and the
            //Driving Application supplied no Signer's Document (clause 5.2.7.4 step 1)).
            ["SIGNED_DATA_NOT_FOUND"] = 8
        }.ToFrozenDictionary(StringComparer.Ordinal);


    /// <summary>
    /// Every archive-time-stamp-bearing artifact of the corpus states a coverage status through
    /// <see cref="ArchiveTimestampV3.StateCoverageAsync"/>, none of them throws, and the distribution of
    /// statuses across all thirty-seven embedded archive time-stamps is exactly the documented one.
    /// </summary>
    [TestMethod]
    public async Task TheArchiveTimestampBearingSubsetProducesExactlyTheDocumentedCoverageDistribution()
    {
        IReadOnlyList<ArchiveTimestampBearingArtifact>? artifacts = await TryEnumerateArchiveTimestampBearingArtifactsAsync().ConfigureAwait(false);
        if(artifacts is null)
        {
            return;
        }

        Assert.HasCount(ExpectedArchiveTimestampArtifactCount, artifacts,
            "The selection rule is expected to yield exactly the pinned number of archive-time-stamp-bearing artifacts; the local reference-artifact corpus changed.");

        Dictionary<ArchiveTimestampCoverageStatus, int> distribution = [];
        int totalTimestamps = 0;
        for(int i = 0; i < artifacts.Count; ++i)
        {
            ArchiveTimestampBearingArtifact artifact = artifacts[i];
            using CmsSignedData signedData = CmsSignedData.FromBytes(artifact.Bytes, BaseMemoryPool.Shared);
            for(int t = 0; t < artifact.Facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp).Count; ++t)
            {
                ++totalTimestamps;
                EmbeddedTimestamp timestamp = artifact.Facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp)[t];
                using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
                    new ArchiveTimestampCoverageContext { SignedData = signedData, ArchiveTimestampToken = timestamp.Token, SignerIndex = 0 },
                    BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

                distribution[coverage.Status] = distribution.TryGetValue(coverage.Status, out int count) ? count + 1 : 1;
            }

            artifact.Facts.Dispose();
        }

        Assert.AreEqual(ExpectedArchiveTimestampCount, totalTimestamps, "The pinned artifact set carries exactly this many embedded archive time-stamps.");

        foreach(KeyValuePair<ArchiveTimestampCoverageStatus, int> expected in ExpectedCoverageStatusDistribution)
        {
            Assert.IsTrue(distribution.TryGetValue(expected.Key, out int actual) && actual == expected.Value,
                $"The bucket '{expected.Key}' is expected to hold {expected.Value} archive time-stamps but holds {(distribution.TryGetValue(expected.Key, out int found) ? found : 0)}.");
        }

        Assert.HasCount(ExpectedCoverageStatusDistribution.Count, distribution,
            "Every status the subset produces has to be one of the documented buckets: " + string.Join(", ", distribution.Keys));
    }


    /// <summary>
    /// The same subset, validated through the shipped engine with no trust context at all: every artifact lands
    /// on <c>INDETERMINATE</c>, none makes the process throw, and the sub-indication distribution is exactly
    /// the documented one — the fail-closed staging property of clause 5.1.3, generalized from
    /// <c>ReferenceArtifactSignatureValidationTests</c> to the archive-time-stamp-bearing subset.
    /// </summary>
    [TestMethod]
    public async Task TheArchiveTimestampBearingSubsetReachesExactlyOneIndeterminateSubIndicationPerArtifactWithNoTrustContext()
    {
        IReadOnlyList<ArchiveTimestampBearingArtifact>? artifacts = await TryEnumerateArchiveTimestampBearingArtifactsAsync().ConfigureAwait(false);
        if(artifacts is null)
        {
            return;
        }

        Dictionary<string, int> distribution = [];
        for(int i = 0; i < artifacts.Count; ++i)
        {
            SignatureValidationConclusion conclusion = await ValidateWithoutTrustContextAsync(artifacts[i].Bytes).ConfigureAwait(false);
            Assert.AreEqual(SignatureValidationIndication.Indeterminate, conclusion.Indication,
                $"'{artifacts[i].RelativePath}' carries no known defect; with no trust context the only honest conclusion is INDETERMINATE.");

            string subIndication = conclusion.SubIndications[0].Value;
            distribution[subIndication] = distribution.TryGetValue(subIndication, out int count) ? count + 1 : 1;

            artifacts[i].Facts.Dispose();
        }

        foreach(KeyValuePair<string, int> expected in ExpectedNoContextSubIndicationDistribution)
        {
            Assert.IsTrue(distribution.TryGetValue(expected.Key, out int actual) && actual == expected.Value,
                $"The bucket '{expected.Key}' is expected to hold {expected.Value} artifacts but holds {(distribution.TryGetValue(expected.Key, out int found) ? found : 0)}.");
        }

        Assert.HasCount(ExpectedNoContextSubIndicationDistribution.Count, distribution,
            "Every sub-indication the subset produces has to be one of the documented buckets: " + string.Join(", ", distribution.Keys));
    }


    /// <summary>
    /// A third-party <c>archive-time-stamp-v3</c> states non-empty coverage over every kind of object clause
    /// 5.5.2 names, and the message-imprint input assembled from that coverage verifies against the token's own
    /// <c>messageImprint</c> — a genuine cryptographic check the archive time-stamp's own issuer signed, not a
    /// status this library invented. The same artifact also shows clause 5.5.2 NOTE 5 on real material: two of
    /// its three unsigned attribute values were added after the archive time-stamp and are reported uncovered
    /// rather than as a failure.
    /// </summary>
    [TestMethod]
    public async Task AWellFormedThirdPartyArchiveTimestampStatesNonEmptyCoverageThatVerifiesAgainstItsOwnMessageImprint()
    {
        byte[]? bytes = await TryReadArtifactAsync("cades-extended-a.pkcs7").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        using CmsSignedData signedData = CmsSignedData.FromBytes(bytes, BaseMemoryPool.Shared);
        using SignatureFacts facts = await ExtractFactsAsync(signedData).ConfigureAwait(false);
        IReadOnlyList<EmbeddedTimestamp> archiveTimestamps = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp);
        Assert.HasCount(1, archiveTimestamps, "This test names an artifact carrying exactly one archive time-stamp.");

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = signedData, ArchiveTimestampToken = archiveTimestamps[0].Token, SignerIndex = 0 },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status, "This artifact's own tooling produced a well-formed ats-hash-index-v3.");
        Assert.IsNotNull(coverage.ProtectedObjects, "A stated coverage always carries what it protects.");
        Assert.IsTrue(coverage.ProtectedObjects!.EveryIndexEntryMatched, "Every entry of the third party's own index matches material the signature still carries.");

        Assert.IsNotEmpty(coverage.ProtectedObjects.Certificates, "The signature carries certificates the index covers.");
        Assert.IsTrue(coverage.ProtectedObjects.Certificates.All(c => c.IsCovered), "Every certificate present when the index was built is named by it.");

        Assert.IsNotEmpty(coverage.ProtectedObjects.RevocationInformation, "The signature carries revocation information the index covers.");
        Assert.IsTrue(coverage.ProtectedObjects.RevocationInformation.All(c => c.IsCovered), "Every revocation object present when the index was built is named by it.");

        Assert.IsGreaterThan(0, coverage.ProtectedObjects.UnsignedAttributeValues.Count(v => v.IsCovered),
            "At least one unsigned attribute value — the archive time-stamp's own signature-time-stamp predecessor — is named by the index.");
        Assert.IsGreaterThan(0, coverage.ProtectedObjects.UnsignedAttributeValues.Count(v => !v.IsCovered),
            "Clause 5.5.2 NOTE 5 on real material: unsigned attribute values this third party added after the archive time-stamp are reported uncovered, not invalid.");

        Assert.IsNotNull(coverage.MessageImprintInput, "A stated coverage carries the octets the token's message imprint should be the digest of.");

        using TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(
            archiveTimestamps[0].Token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(tokenInfo.IsRead, "The third party's own token reads as a well-formed RFC 3161 TimeStampToken.");
        Assert.IsTrue(
            await tokenInfo.VerifyMessageImprintAsync(coverage.MessageImprintInput!.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "Clause 5.5.3: the imprint this leg recomputed from the artifact's current material is the one this third party's own time-stamping authority signed.");
    }


    /// <summary>
    /// Two independent <c>archive-time-stamp-v3</c> attributes on the same third-party signature both state
    /// valid coverage and both verify against their own message imprints — a real-world instance of the
    /// succession clause 5.5.3 NOTE 6 describes, rather than one this wave minted.
    /// </summary>
    [TestMethod]
    public async Task TwoIndependentArchiveTimestampsOnTheSameThirdPartyArtifactBothStateValidCoverage()
    {
        byte[]? bytes = await TryReadArtifactAsync("cades-lta-duplicated-atst.p7m").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        using CmsSignedData signedData = CmsSignedData.FromBytes(bytes, BaseMemoryPool.Shared);
        using SignatureFacts facts = await ExtractFactsAsync(signedData).ConfigureAwait(false);
        IReadOnlyList<EmbeddedTimestamp> archiveTimestamps = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp);
        Assert.HasCount(2, archiveTimestamps, "This artifact's own tooling attached two archive time-stamps.");

        for(int i = 0; i < archiveTimestamps.Count; ++i)
        {
            using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
                new ArchiveTimestampCoverageContext { SignedData = signedData, ArchiveTimestampToken = archiveTimestamps[i].Token, SignerIndex = 0 },
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status, $"Archive time-stamp [{i}] carries a well-formed ats-hash-index-v3.");
            Assert.IsTrue(coverage.ProtectedObjects!.EveryIndexEntryMatched, $"Archive time-stamp [{i}]'s own index matches the material the signature carries.");

            using TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(
                archiveTimestamps[i].Token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                await tokenInfo.VerifyMessageImprintAsync(coverage.MessageImprintInput!.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
                $"Archive time-stamp [{i}]'s own issuer signed exactly the imprint this leg recomputed.");
        }
    }


    /// <summary>
    /// A detached third-party signature carrying a genuine <c>archive-time-stamp-v3</c> states no coverage —
    /// not because the index is wrong, but because clause 5.5.3 NOTE 1's signed-content hash has no source: the
    /// Driving Application supplied neither the detached content nor its digest. The same absence of context
    /// reaches the shipped engine's exact <c>SIGNED_DATA_NOT_FOUND</c> sub-indication, with or without a trust
    /// anchor, because clause 5.2.7.4 step 1) is what stops the run before any archive-time-stamp handling is
    /// reached.
    /// </summary>
    [TestMethod]
    public async Task ADetachedThirdPartyArchiveTimestampStatesNoCoverageBecauseTheSignedContentIsUnavailable()
    {
        byte[]? bytes = await TryReadArtifactAsync("dss-2011/cades-lta-detached.pkcs7").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        using ArchiveTimestampCoverage coverage = await StateSoleArchiveTimestampCoverageInOwnScopeAsync(bytes).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.SignedContentUnavailable, coverage.Status,
            "The index itself is well-formed (asserted below); only step 2) of the clause 5.5.3 imprint input is missing its source.");
        Assert.IsNotNull(coverage.ProtectedObjects, "SignedContentUnavailable is reached only after the index has already been checked and found valid — clause 5.5.2 runs before clause 5.5.3.");
        Assert.IsTrue(coverage.ProtectedObjects!.EveryIndexEntryMatched, "The index this third party wrote is itself valid; only the content to re-hash is absent.");
        Assert.IsNull(coverage.MessageImprintInput, "No imprint input is assembled when step 2) has no value.");

        SignatureValidationConclusion noContext = await ValidateWithoutTrustContextAsync(bytes).ConfigureAwait(false);
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, noContext.Indication, "Nothing about this signature is wrong; the Signer's Document is simply not supplied.");
        Assert.AreEqual(SignatureValidationSubIndication.SignedDataNotFound, noContext.SubIndications[0],
            "Clause 5.2.7.4 step 1) reports SIGNED_DATA_NOT_FOUND before certification-path building or archive-time-stamp handling is ever reached.");
    }


    /// <summary>
    /// A third-party fixture whose <c>ats-hash-index-v3</c> was deliberately tampered ("wrong-cert" is the
    /// corpus's own name for it) is reported invalid, and clause 5.5.2's asymmetric membership check localizes
    /// the defect rather than failing every object: the certificates and revocation information the index
    /// covered before the tampering are still each individually reported covered.
    /// </summary>
    [TestMethod]
    public async Task AThirdPartyArchiveTimestampWithATamperedIndexEntryIsReportedInvalidWhileUnaffectedMaterialStaysCovered()
    {
        byte[]? bytes = await TryReadArtifactAsync("cades-ats-v3-wrong-cert.p7m").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        using ArchiveTimestampCoverage coverage = await StateSoleArchiveTimestampCoverageInOwnScopeAsync(bytes).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.HashIndexInvalid, coverage.Status, "This corpus fixture's own name states it was deliberately tampered.");
        Assert.IsNotNull(coverage.ProtectedObjects, "The evaluation still names what it did and did not find a match for.");
        Assert.IsFalse(coverage.ProtectedObjects!.EveryIndexEntryMatched, "Clause 5.5.2: an index entry with no matching current material makes the index invalid.");
        Assert.IsNull(coverage.MessageImprintInput, "An invalid index yields no imprint input (clause 5.5.2 is checked before clause 5.5.3).");

        Assert.IsTrue(coverage.ProtectedObjects.Certificates.All(c => c.IsCovered),
            "The asymmetric check does not fail material it did find a matching entry for.");
        Assert.IsTrue(coverage.ProtectedObjects.RevocationInformation.All(c => c.IsCovered),
            "The tampering this fixture carries does not touch the revocation information the index also covers.");
        Assert.IsGreaterThan(0, coverage.ProtectedObjects.UnsignedAttributeValues.Count(v => !v.IsCovered),
            "The uncovered unsigned attribute value is where the tampering — and the resulting unmatched index entry — is localized.");
    }


    /// <summary>
    /// When the Driving Application supplies its own trust context — the self-signed certificate this artifact
    /// itself carries as a trust anchor, and the artifact's own embedded revocation material — the outcome
    /// moves past the missing-trust-anchor stage into a conclusion the archive time-stamp's derived proof of
    /// existence genuinely participates in deciding.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>cades-lta-duplicated-atst.p7m</c> reaches <c>CRYPTO_CONSTRAINTS_FAILURE_NO_POE</c>: the root and
    /// time-stamping-authority certificates this artifact carries are signed under <c>sha512WithRSAEncryption</c>
    /// (RFC 8017), an algorithm the constraints table this test supplies does not list (the table names bare
    /// digest algorithms only, mirroring the shape <c>CAdESCapstoneFirewalledFlowTests</c> uses). Clause 5.1.4.1
    /// forbids treating an unlisted algorithm as reliable, so <c>PastSignatureValidation</c> step 4) consults the
    /// proof of existence this leg's own <see cref="AWellFormedThirdPartyArchiveTimestampStatesNonEmptyCoverageThatVerifiesAgainstItsOwnMessageImprint"/>
    /// proved genuine — and correctly reports that no proof can rescue a certificate signed under an algorithm
    /// the Driving Application's own policy never asserted reliable. This is the archive time-stamp's derived
    /// proof of existence genuinely deciding an outcome, not a status this test invented: the reported reliability
    /// assessment is asserted to name the exact algorithm and verdict below.
    /// </para>
    /// <para>
    /// <c>cades-extended-a.pkcs7</c> reaches <c>TRY_LATER</c>: with the artifact's own embedded self-signed
    /// certificate as a trust anchor and its own embedded CRL as the only revocation source, nothing establishes
    /// a certificate's revocation status at the chosen validation instant (the CRL's own freshness window does
    /// not cover it) — the same well-established outcome
    /// <c>ReferenceArtifactSignatureValidationTests.AnArtifactValidatedAgainstItsOwnEmbeddedTrustAnchorStopsOnlyAtTheMissingRevocationStatusInformation</c>
    /// asserts for a different artifact of the same corpus.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task WhenGivenItsOwnEmbeddedTrustAnchorAndRevocationMaterialTheEngineConsultsTheArchiveTimestampDerivedProofOfExistence()
    {
        byte[]? weakAlgorithm = await TryReadArtifactAsync("cades-lta-duplicated-atst.p7m").ConfigureAwait(false);
        byte[]? staleRevocation = await TryReadArtifactAsync("cades-extended-a.pkcs7").ConfigureAwait(false);
        if(weakAlgorithm is null || staleRevocation is null)
        {
            return;
        }

        SignatureValidationConclusion noPoe = await ValidateAgainstOwnAnchorsAsync(weakAlgorithm).ConfigureAwait(false)
            ?? throw new InvalidOperationException("This artifact carries a self-signed certificate this test configures as a trust anchor.");
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, noPoe.Indication);
        Assert.AreEqual(SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence, noPoe.SubIndications[0],
            "PastSignatureValidation step 4) consulted the proof of existence the archive time-stamp derived and it could not rescue an algorithm this run's constraints table never asserted reliable.");
        CryptographicConstraintsFailureReportData reportData = (CryptographicConstraintsFailureReportData)noPoe.ReportData.Single(d => d is CryptographicConstraintsFailureReportData);
        Assert.IsNotEmpty(reportData.UnreliableAlgorithms, "Table 6 mandates naming the offending material and algorithm.");
        Assert.IsTrue(reportData.UnreliableAlgorithms.All(a => a.Verdict == AlgorithmReliabilityVerdict.Unknown),
            "The table this test supplies lists bare digest algorithms only; sha512WithRSAEncryption is unlisted, which clause 5.1.4.1 makes Unknown rather than Reliable.");

        SignatureValidationConclusion tryLater = await ValidateAgainstOwnAnchorsAsync(staleRevocation).ConfigureAwait(false)
            ?? throw new InvalidOperationException("This artifact carries a self-signed certificate this test configures as a trust anchor.");
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, tryLater.Indication);
        Assert.AreEqual(SignatureValidationSubIndication.TryLater, tryLater.SubIndications[0],
            "Step 4) of clause 5.2.6.4 reports TRY_LATER when no revocation status information establishes a certificate's status at the chosen instant.");
    }


    /// <summary>One archive-time-stamp-bearing artifact of the corpus: its clone-relative path, its octets, and its already-extracted facts.</summary>
    /// <param name="RelativePath">The clone-relative path with forward slashes.</param>
    /// <param name="Bytes">The artifact's octets.</param>
    /// <param name="Facts">The already-extracted signature facts, which the caller disposes once its own sweep no longer needs them.</param>
    private sealed record ArchiveTimestampBearingArtifact(string RelativePath, byte[] Bytes, SignatureFacts Facts);


    /// <summary>
    /// Enumerates every artifact of the pinned corpus whose CAdES signature facts extract successfully and
    /// which carries at least one embedded timestamp of <see cref="SignatureTimestampClass.ArchiveTimestamp"/>,
    /// or reports <see cref="Assert.Inconclusive(string)"/> and returns <see langword="null"/> when the local
    /// reference-artifact clone is absent.
    /// </summary>
    /// <returns>The archive-time-stamp-bearing subset, ordered ordinally by clone-relative path.</returns>
    private async ValueTask<IReadOnlyList<ArchiveTimestampBearingArtifact>?> TryEnumerateArchiveTimestampBearingArtifactsAsync()
    {
        string? directory = TryFindArtifactDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return null;
        }

        List<string> candidates =
        [
            .. Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                .Where(IsSignedCadesArtifact)
                .Select(path => Path.GetRelativePath(directory, path).Replace('\\', '/'))
                .OrderBy(path => path, StringComparer.Ordinal)
        ];

        List<ArchiveTimestampBearingArtifact> selected = [];
        for(int i = 0; i < candidates.Count; ++i)
        {
            byte[] bytes = await File.ReadAllBytesAsync(
                Path.Combine(directory, candidates[i].Replace('/', Path.DirectorySeparatorChar)), TestContext.CancellationToken).ConfigureAwait(false);

            using CmsSignedData signedData = CmsSignedData.FromBytes(bytes, BaseMemoryPool.Shared);
            SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
                new SignatureFactsExtractionContext { SignedDataObject = signedData }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            if(facts.Status == SignatureFactsStatus.Extracted && facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp).Count > 0)
            {
                selected.Add(new ArchiveTimestampBearingArtifact(candidates[i], bytes, facts));
            }
            else
            {
                facts.Dispose();
            }
        }

        return selected;
    }


    /// <summary>States the coverage of the single archive time-stamp a named artifact carries.</summary>
    /// <param name="artifactBytes">The artifact's octets.</param>
    /// <returns>The coverage, which the caller disposes.</returns>
    /// <remarks>
    /// The Signed Data Object and the extracted facts stay open for the whole computation: the embedded
    /// time-stamp token <see cref="ArchiveTimestampV3.StateCoverageAsync"/> reads is a view into the facts'
    /// own pooled memory, so it has to remain valid until the call that reads it has returned. Only the
    /// resulting <see cref="ArchiveTimestampCoverage"/> — which owns independently rented memory of its own —
    /// survives the two <see langword="using"/> declarations this method disposes on the way out.
    /// </remarks>
    /// <param name="artifactBytes">The artifact's octets.</param>
    /// <returns>The coverage of the single archive time-stamp the named artifact carries, which the caller disposes.</returns>
    private async ValueTask<ArchiveTimestampCoverage> StateSoleArchiveTimestampCoverageInOwnScopeAsync(byte[] artifactBytes)
    {
        using CmsSignedData signedData = CmsSignedData.FromBytes(artifactBytes, BaseMemoryPool.Shared);
        using SignatureFacts facts = await ExtractFactsAsync(signedData).ConfigureAwait(false);
        IReadOnlyList<EmbeddedTimestamp> archiveTimestamps = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp);
        Assert.HasCount(1, archiveTimestamps, "This test names an artifact carrying exactly one archive time-stamp.");

        return await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = signedData, ArchiveTimestampToken = archiveTimestamps[0].Token, SignerIndex = 0 },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Extracts CAdES signature facts from an already-opened Signed Data Object, asserting that extraction succeeded.</summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <returns>The extracted facts, which the caller disposes.</returns>
    private async ValueTask<SignatureFacts> ExtractFactsAsync(CmsSignedData signedData)
    {
        SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = signedData }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status, "The artifact has to parse before its embedded timestamps can be named.");

        return facts;
    }


    /// <summary>
    /// Runs the validation process for Signatures providing Long Term Availability and Integrity of Validation
    /// Material over an artifact with no trust anchor, no revocation material and no signature policy mapping.
    /// </summary>
    /// <param name="artifactBytes">The artifact's octets.</param>
    /// <returns>The conclusion of clause 5.1.3.</returns>
    private async ValueTask<SignatureValidationConclusion> ValidateWithoutTrustContextAsync(byte[] artifactBytes)
    {
        using CmsSignedData signedData = CmsSignedData.FromBytes(artifactBytes, BaseMemoryPool.Shared);
        var completer = new CertificateChainCompleter([]);
        var crlChecker = new CrlRevocationChecker([]);
        var inputs = new SignatureValidationInputs
        {
            SignedDataObject = signedData,
            Constraints = BuildConstraints([]),
            UnmappedSignaturePolicyHandling = UnmappedSignaturePolicyHandling.ApplyDefaultConstraints
        };

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            inputs, BuildSeams(completer, crlChecker), SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return outcome.Conclusion;
    }


    /// <summary>
    /// Runs the same validation process over an artifact with every self-signed certificate it carries
    /// configured as a trust anchor, its own embedded certificate revocation lists as the only revocation
    /// source, and the validation instant at the midpoint of its signing certificate's own validity window.
    /// </summary>
    /// <param name="artifactBytes">The artifact's octets.</param>
    /// <returns>The conclusion, or <see langword="null"/> when the artifact carries no self-signed certificate or no readable signing certificate.</returns>
    private async ValueTask<SignatureValidationConclusion?> ValidateAgainstOwnAnchorsAsync(byte[] artifactBytes)
    {
        using CmsSignedData signedData = CmsSignedData.FromBytes(artifactBytes, BaseMemoryPool.Shared);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = signedData }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        if(facts.Status != SignatureFactsStatus.Extracted || facts.SigningCertificate is null)
        {
            return null;
        }

        var parser = new X509CertificateParser();
        List<TrustAnchorConstraint> anchors = [];
        for(int i = 0; i < facts.EmbeddedCertificates.Count; ++i)
        {
            BcX509Certificate candidate = parser.ReadCertificate(facts.EmbeddedCertificates[i].AsReadOnlySpan().ToArray());
            if(candidate.SubjectDN.Equivalent(candidate.IssuerDN))
            {
                anchors.Add(new TrustAnchorConstraint(facts.EmbeddedCertificates[i], SunsetDate: null));
            }
        }

        if(anchors.Count == 0)
        {
            return null;
        }

        BcX509Certificate signer = parser.ReadCertificate(facts.SigningCertificate.AsReadOnlySpan().ToArray());
        DateTimeOffset notBefore = new(signer.NotBefore, TimeSpan.Zero);
        DateTimeOffset notAfter = new(signer.NotAfter, TimeSpan.Zero);
        DateTimeOffset validationTime = notBefore + ((notAfter - notBefore) / 2);

        var completer = new CertificateChainCompleter(facts.EmbeddedCertificates);
        var crlChecker = new CrlRevocationChecker(facts.EmbeddedCertificateRevocationLists);
        var inputs = new SignatureValidationInputs
        {
            SignedDataObject = signedData,
            Constraints = BuildConstraints(anchors),
            UnmappedSignaturePolicyHandling = UnmappedSignaturePolicyHandling.ApplyDefaultConstraints
        };

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            inputs, BuildSeams(completer, crlChecker), SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, validationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return outcome.Conclusion;
    }


    /// <summary>
    /// Builds the validation constraints every run of this class uses: the supplied trust anchors under the
    /// shell validity model, bare digest-algorithm reliability with no expiry, and the long-term-availability
    /// attribute-validity constraint clause 5.6.3.4 step 3) names for a Driving Application that wants the
    /// archive-time-stamp mechanism exercised rather than skipped.
    /// </summary>
    /// <param name="anchors">The trust anchors, empty for a run with no trust context.</param>
    /// <returns>The constraints.</returns>
    private static SignatureValidationConstraints BuildConstraints(IReadOnlyList<TrustAnchorConstraint> anchors) => new()
    {
        Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
        X509 = new X509ValidationConstraints { TrustAnchors = anchors, ValidityModel = CertificateValidityModel.Shell },
        Cryptographic = new CryptographicConstraints
        {
            Entries =
            [
                new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha1, MinimumKeySizeBits: null, TrustedUntil: null),
                new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null),
                new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha384, MinimumKeySizeBits: null, TrustedUntil: null),
                new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha512, MinimumKeySizeBits: null, TrustedUntil: null)
            ]
        },
        SignatureElements = new SignatureElementsConstraints { RequireLongTermAvailabilityAttributeValidity = true }
    };


    /// <summary>Builds the seams every run of this class composes: the shipped CAdES binding, an offline chain completer, the platform certification path validator and a CRL-only revocation checker.</summary>
    /// <param name="completer">The chain completion seam over whatever certificates the run may use.</param>
    /// <param name="crlChecker">The revocation seam over whatever certificate revocation lists the run may use.</param>
    /// <returns>The seams.</returns>
    private static SignatureValidationSeams BuildSeams(CertificateChainCompleter completer, CrlRevocationChecker crlChecker) => new()
    {
        Format = CAdESSignatureFacts.Seam,
        CompleteCertificateChain = completer.CompleteAsync,
        ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync,
        CheckRevocation = crlChecker.CheckAsync
    };


    /// <summary>Reports whether a path names a signed CAdES artifact under the corpus's own selection rule.</summary>
    /// <param name="path">The candidate path.</param>
    /// <returns><see langword="true"/> when its extension is one the rule names.</returns>
    private static bool IsSignedCadesArtifact(string path) =>
        path.EndsWith(".p7m", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase)
        || path.EndsWith(".pkcs7", StringComparison.OrdinalIgnoreCase);


    /// <summary>
    /// Reads one named artifact, or reports <see cref="Assert.Inconclusive(string)"/> and returns
    /// <see langword="null"/> when the local reference-artifact clone, or the named artifact within it, is
    /// not present.
    /// </summary>
    /// <param name="relativePath">The clone-relative path with forward slashes.</param>
    /// <returns>The artifact's octets, or <see langword="null"/>.</returns>
    private async ValueTask<byte[]?> TryReadArtifactAsync(string relativePath)
    {
        string? directory = TryFindArtifactDirectory();
        if(directory is null)
        {
            Assert.Inconclusive(MissingCloneMessage);

            return null;
        }

        string path = Path.Combine(directory, relativePath.Replace('/', Path.DirectorySeparatorChar));
        if(!File.Exists(path))
        {
            Assert.Inconclusive($"The artifact '{relativePath}' is not present in the local reference-artifact corpus.");

            return null;
        }

        return await File.ReadAllBytesAsync(path, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>What every test reports when the optional local reference-artifact clone is not present.</summary>
    private static string MissingCloneMessage =>
        "The local reference-artifact clone (tempdocs/etsi-ades-reference) was not found; the signed CAdES corpus is optional local reference material, not a repository asset.";


    /// <summary>
    /// Walks up from the test assembly's output directory to the repository root and resolves the CAdES
    /// validation-resources directory of the local reference-artifact clone relative to it — the same
    /// marker-file search <c>TrustedListFixtureTests</c> and <c>ReferenceArtifactSignatureValidationTests</c>
    /// use for their own corpora.
    /// </summary>
    /// <returns>The directory's full path, or <see langword="null"/> when it is not present.</returns>
    private static string? TryFindArtifactDirectory()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while(current is not null && !File.Exists(Path.Combine(current.FullName, "Verifiable.slnx")))
        {
            current = current.Parent;
        }

        if(current is null)
        {
            return null;
        }

        string referenceMaterial = Path.Combine(current.FullName, "tempdocs", "etsi-ades-reference");
        if(!Directory.Exists(referenceMaterial))
        {
            return null;
        }

        //The clone's own directory names are not spelled here. The CAdES validation resources are found by the
        //layout every module of that corpus shares — a "validation" directory under "src/test/resources" — and
        //the first such directory in ordinal order that actually holds signed CAdES artifacts is the one used.
        string tail = Path.Combine("src", "test", "resources", "validation");

        return Directory.EnumerateDirectories(referenceMaterial, "validation", SearchOption.AllDirectories)
            .Where(directory => directory.EndsWith(tail, StringComparison.OrdinalIgnoreCase))
            .Where(directory => Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).Any(IsSignedCadesArtifact))
            .OrderBy(directory => directory, StringComparer.Ordinal)
            .FirstOrDefault();
    }
}

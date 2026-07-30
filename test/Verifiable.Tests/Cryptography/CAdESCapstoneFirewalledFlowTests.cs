using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Tsp;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The firewalled capstone for CAdES creation and long-term augmentation of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1</see>: a signing party mints a CAdES-B-B signature and raises it to B-T, B-LT and
/// B-LTA entirely through the shipped <see cref="CAdESSignatureCreation"/>/<see cref="CAdESSignatureAugmentation"/>
/// surfaces, emits nothing but wire octets and public instants, and a verifying party that never saw the signing
/// party's objects reconstructs every input from those octets and runs the shipped CAdES binding of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> clause 5.6 to <c>TOTAL-PASSED</c> with proofs of existence derived from the
/// archive time-stamp.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The firewall.</strong> <see cref="MintCapstoneWorldAsync"/> builds the Root CA, the Time-Stamping
/// Authority and the signer entirely inside a local scope, mints B-B through B-LTA over that material, copies
/// out DER octets and public instants into a <see cref="CapstoneWireMessage"/>, and disposes every certificate,
/// key and carrier before returning. The verifying party (<see cref="ReconstructedCapstoneVerifyingParty"/>)
/// rents its own carriers from its own pool and reads them out of the received Signed Data Object alone — an
/// assertion that passes here cannot be passing because the two sides share an object.
/// </para>
/// <para>
/// <strong>Leg 3 — "Verifiable creates → independent oracle verifies."</strong>
/// <see cref="MintCapstoneWorldAsync"/> checks its own output, before the firewall closes, against three
/// readers that share no code with the creation/augmentation surfaces: the independently-registered
/// BouncyCastle <see cref="VerifyCmsSignedDataDelegate"/> backend for the outer CMS signature, the independent
/// BouncyCastle TSP validator (<c>Org.BouncyCastle.Tsp.TimeStampToken.Validate</c>) for both time-stamp tokens,
/// and stage 3's independent <see cref="AtsHashIndexV3Oracle"/> reimplementation for the
/// <c>ats-hash-index-v3</c> the archive time-stamp carries.
/// </para>
/// <para>
/// <strong>TSA and OCSP material.</strong> Both time-stamp tokens are minted through the independent BouncyCastle
/// TSP oracle (<see cref="X509ChainTestRingTimestamping"/>, via <see cref="MintingTimestampResponder"/> answering
/// the RFC 3161 request octets that actually crossed the shipped transport seam) and the OCSP response placed as
/// B-LT material is minted through the independent OCSP oracle (<see cref="X509ChainTestRingRevocation"/>, backed
/// by <see cref="OcspTestFixtures"/>) — never a stand-in. The signer and the Time-Stamping Authority are both
/// leaves of one <see cref="X509ChainTestRing"/> Root CA, so both carry an Authority Key Identifier chained to
/// the root's Subject Key Identifier (the Linux chain-building requirement the wave's other legs already state).
/// </para>
/// </remarks>
[TestClass]
internal sealed class CAdESCapstoneFirewalledFlowTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.capstone.example.test/";

    /// <summary>The DNS name the signer's leaf certificate carries.</summary>
    private const string SignerDnsName = "cades-capstone.example.test";

    /// <summary>The content every minted signature encapsulates and covers.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the CAdES capstone content"u8.ToArray());


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Mints B-B → B-T → B-LT → B-LTA through the shipped surfaces, hands only wire octets across the firewall,
    /// and the reconstructed verifying party reaches <c>TOTAL-PASSED</c> through the validation process for
    /// Signatures providing Long Term Availability and Integrity of Validation Material of clause 5.6, with no
    /// <c>AcceptsUnverifiableTimestampCoverage</c> knob — coverage is verified, not declared. The report of
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
    /// ETSI TS 119 102-2 V1.4.1</see> clause 4.4.7 attributes the proof of existence to the archive time-stamp.
    /// </summary>
    [TestMethod]
    public async Task FirewalledCapstoneReachesTotalPassedFromWireBytesAloneWithPoesFromTheArchiveTimestamp()
    {
        CapstoneWireMessage message = await MintCapstoneWorldAsync(includeContentTimestamp: false, TestContext.CancellationToken).ConfigureAwait(false);

        using ReconstructedCapstoneVerifyingParty verifier = await ReconstructedCapstoneVerifyingParty.CreateAsync(
            message, TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            verifier.Inputs, verifier.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, message.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationConclusion conclusion = outcome.Conclusion;
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, conclusion.Indication,
            "Clause 5.6.3.4: a B-LTA signature whose material and time-stamps all verify reaches TOTAL-PASSED.");
        Assert.IsNotNull(outcome.LongTermValidation, "The process that ran is the one of clause 5.6.3.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.LongTermAvailability, conclusion.ProcessIdentifier,
            "The conclusion states the process that produced it.");

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, verifier.Inputs, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        List<ValidationObject> tokens = [.. report.SignatureValidationObjects.Where(o => o.ObjectType == ValidationObjectKind.TimestampToken)];
        Assert.HasCount(2, tokens, "Clause 4.4: the signature time-stamp and the archive time-stamp are both objects the validation used, so both are projected.");

        ValidationObject archiveToken = tokens.Single(t => t.ProvidesProofOfExistenceFor.Count > 0);
        ProofOfExistenceProvisioning provisioning = archiveToken.ProvidesProofOfExistenceFor.Single();
        Assert.AreEqual(message.ArchiveTimestampTime, provisioning.ProofTime,
            "Clause 4.4.7.1: the time value of the proof is the archive time-stamp's own generation time.");

        List<SensitiveMemory> covered = [.. provisioning.CoveredObjects];
        ValidationObject earlierToken = tokens.Single(t => !ReferenceEquals(t, archiveToken));
        Assert.Contains(earlierToken.Representation, covered,
            "An archive time-stamp protects the whole signature except itself, so the earlier signature time-stamp token is among the objects it proves existed.");

        List<ValidationObject> certificateObjects = [.. report.SignatureValidationObjects.Where(o => o.ObjectType == ValidationObjectKind.Certificate)];
        Assert.IsNotEmpty(certificateObjects, "The signing certificate and the trust anchor placed as B-LT material are both projected as objects.");
        foreach(ValidationObject certificateObject in certificateObjects)
        {
            Assert.Contains(certificateObject.Representation, covered,
                "Clause 4.4.7: every certificate placed before the archive time-stamp travels inside the signature it protects.");
        }
    }


    /// <summary>
    /// The regression of defect D-F at the report level (TS 119 102-2 clause 4.4.7): a firewalled B-LTA signature
    /// carrying a <c>content-time-stamp</c> (clause 5.2.8, a SIGNED attribute) reaches <c>TOTAL-PASSED</c>, and the
    /// archive time-stamp's <c>ProvidesProofOfExistenceFor</c> lists the content-time-stamp token. The
    /// <c>ats-hash-index-v3</c> never names it — it indexes unsigned attribute values alone — so the report can
    /// list it only because the CAdES binding's <c>StateTimestampProtectsObject</c> filter admits a signed
    /// attribute value through step 3) of clause 5.5.3's whole-<c>signedAttrs</c> concatenation.
    /// </summary>
    [TestMethod]
    public async Task FirewalledCapstoneAttributesAContentTimestampsProofToTheArchiveTimestamp()
    {
        CapstoneWireMessage message = await MintCapstoneWorldAsync(includeContentTimestamp: true, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsNotNull(message.ContentTimestampToken, "The minted signature carries a content-time-stamp token.");

        using ReconstructedCapstoneVerifyingParty verifier = await ReconstructedCapstoneVerifyingParty.CreateAsync(
            message, TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            verifier.Inputs, verifier.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, message.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalPassed, outcome.Conclusion.Indication,
            "Clause 5.6.3.4: a B-LTA signature whose material and time-stamps all verify reaches TOTAL-PASSED, the content-time-stamp included.");

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, verifier.Inputs, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        List<ValidationObject> tokens = [.. report.SignatureValidationObjects.Where(o => o.ObjectType == ValidationObjectKind.TimestampToken)];
        Assert.HasCount(3, tokens, "Clause 4.4: the content-time-stamp, the signature time-stamp and the archive time-stamp are all objects the validation used.");

        //Several tokens provide proofs (the content-time-stamp itself proves the signed content existed); the
        //archive time-stamp is the one whose proof time is its own generation instant.
        ValidationObject archiveToken = tokens.Single(t => t.ProvidesProofOfExistenceFor.Any(p => p.ProofTime == message.ArchiveTimestampTime));
        ValidationObject? contentToken = null;
        foreach(ValidationObject token in tokens)
        {
            if(token.Representation.AsReadOnlySpan().SequenceEqual(message.ContentTimestampToken))
            {
                contentToken = token;

                break;
            }
        }

        Assert.IsNotNull(contentToken, "The report projects the content-time-stamp token as one of the objects the validation used.");

        ProofOfExistenceProvisioning provisioning = archiveToken.ProvidesProofOfExistenceFor.Single(p => p.ProofTime == message.ArchiveTimestampTime);
        Assert.AreEqual(message.ArchiveTimestampTime, provisioning.ProofTime,
            "Clause 4.4.7.1: the time value of the proof is the archive time-stamp's own generation time.");

        List<SensitiveMemory> covered = [.. provisioning.CoveredObjects];
        Assert.Contains(contentToken!.Representation, covered,
            "TS 119 102-2 clause 4.4.7 (D-F): the archive time-stamp's ProvidesProofOfExistenceFor lists the content-time-stamp token — a signed attribute value step 3) of clause 5.5.3 binds through the whole signedAttrs, not through the ats-hash-index-v3.");
        Assert.IsNotNull(contentToken.ProofOfExistence, "Clause 4.4.6: the content-time-stamp token carries the proof of existence the archive time-stamp establishes for it.");
        Assert.AreEqual(message.ArchiveTimestampTime, contentToken.ProofOfExistence!.Instant,
            "The content-time-stamp is proven to have existed at the archive time-stamp's generation time.");
    }


    /// <summary>
    /// Leg 3 of the charter's testing architecture — "Verifiable creates → independent oracle verifies" — stated
    /// as its own test. The assertions live inside <see cref="MintCapstoneWorldAsync"/> (see its remarks): the
    /// independent BouncyCastle CMS reader recovers the signed content, the independent BouncyCastle TSP
    /// validator accepts both time-stamp tokens, and stage 3's independent hash-index reimplementation recomputes
    /// exactly the <c>ats-hash-index-v3</c> the shipped augmentation surface grafted into the archive token.
    /// </summary>
    [TestMethod]
    public async Task MintedArtifactsPassTheIndependentBouncyCastleOracleChainAcrossCmsTspAndTheHashIndex()
    {
        CapstoneWireMessage message = await MintCapstoneWorldAsync(includeContentTimestamp: false, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotEmpty(message.SignedDataObject, "Minting completed and produced a wire Signed Data Object; the leg-3 assertions above already ran against it.");
    }


    /// <summary>
    /// Post-augmentation property (R-4/§5.5.2 NOTE 5): a caller who received the B-LTA signature and augments it
    /// further — through the same shipped surface — leaves the earlier archive time-stamp's own octets and its
    /// coverage of everything already present untouched; only the newly added object is uncovered, which is not
    /// an error, and the engine still reaches <c>TOTAL-PASSED</c> on the augmented wire bytes.
    /// </summary>
    [TestMethod]
    public async Task MaterialAddedAfterTheArchiveTimestampStillVerifiesAndLeavesTheEarlierCoverageUnchanged()
    {
        CapstoneWireMessage message = await MintCapstoneWorldAsync(includeContentTimestamp: false, TestContext.CancellationToken).ConfigureAwait(false);

        using CmsSignedData received = CmsSignedData.FromBytes(message.SignedDataObject, BaseMemoryPool.Shared);
        List<byte[]> tokensBefore = UnsignedAttributeValues(message.SignedDataObject, signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        Assert.HasCount(1, tokensBefore, "The capstone attaches exactly one archive-time-stamp-v3.");
        using PkiCertificateMemory archiveToken = ToTokenCarrier(tokensBefore[0]);

        using ArchiveTimestampCoverage coverageBefore = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = received, ArchiveTimestampToken = archiveToken },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverageBefore.Status, "The received archive time-stamp's coverage is stated from the wire bytes alone.");

        //A caller who received the signature augments it further, entirely through the shipped surface — an
        //unrelated certificate is the simplest object clause 5.5.2 NOTE 5 says the earlier index need not cover.
        using X509ChainTestRingNode laterRoot = X509ChainTestRing.CreateRootCa(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using PkiCertificateMemory laterCertificate = ToCertificateCarrier(laterRoot.Certificate.RawData);
        using CmsSignedData augmented = CAdESSignatureAugmentation.AddValidationData(
            received, signerIndex: 0, new CAdESValidationMaterial { Certificates = [laterCertificate] }, BaseMemoryPool.Shared);
        byte[] augmentedBytes = augmented.AsReadOnlySpan().ToArray();

        List<byte[]> tokensAfter = UnsignedAttributeValues(augmentedBytes, signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        Assert.AreSequenceEqual(tokensBefore[0], tokensAfter[0], "R-4/§5.5.3 preservation: the earlier archive time-stamp's own octets are untouched by a later augmentation.");

        using ArchiveTimestampCoverage coverageAfter = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = augmented, ArchiveTimestampToken = archiveToken },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverageAfter.Status, "NOTE 5: material added after the archive time-stamp does not invalidate it.");
        Assert.HasCount(coverageBefore.ProtectedObjects!.Certificates.Count + 1, coverageAfter.ProtectedObjects!.Certificates,
            "One new, uncovered certificate joined the set the coverage describes.");
        for(int i = 0; i < coverageBefore.ProtectedObjects!.Certificates.Count; ++i)
        {
            Assert.AreEqual(coverageBefore.ProtectedObjects!.Certificates[i].IsCovered, coverageAfter.ProtectedObjects!.Certificates[i].IsCovered,
                $"Certificate {i}'s coverage flag is unchanged by the later augmentation.");
        }

        Assert.IsFalse(coverageAfter.ProtectedObjects!.Certificates[^1].IsCovered,
            "The newly added certificate sits outside the earlier archive time-stamp's index — uncovered, not invalid (the asymmetric §5.5.2 check).");

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(archiveToken, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            await info.VerifyMessageImprintAsync(coverageAfter.MessageImprintInput!.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "The earlier archive time-stamp still verifies against the imprint input recomputed after the later augmentation.");

        CapstoneWireMessage augmentedMessage = message with { SignedDataObject = augmentedBytes };
        using ReconstructedCapstoneVerifyingParty verifier = await ReconstructedCapstoneVerifyingParty.CreateAsync(
            augmentedMessage, TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            verifier.Inputs, verifier.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, message.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, outcome.Conclusion.Indication,
            "The engine still reaches TOTAL-PASSED on the augmented wire bytes: the prior archive time-stamp still verifies.");
    }


    /// <summary>
    /// Post-augmentation property (fail-closed, §5.5.2/NOTE 7): mutating one octet of a material the archive
    /// time-stamp's index covers — here the embedded certificate revocation list — makes that index entry match
    /// no current material, which the asymmetric membership check reports as invalid, and the engine degrades
    /// from <c>TOTAL-PASSED</c> exactly as clause 5.6.3.4's fail-closed handling mandates.
    /// </summary>
    [TestMethod]
    public async Task MutatingACoveredValidationObjectInvalidatesTheArchiveTimestampsCoverageAndDegradesTheOutcome()
    {
        CapstoneWireMessage message = await MintCapstoneWorldAsync(includeContentTimestamp: false, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] originalCrl = AtsHashIndexV3Oracle.RevocationEncodings(message.SignedDataObject)[0];
        Assert.AreEqual(0x30, originalCrl[0], "The first crls member is the CertificateList alternative (requirement q): a plain SEQUENCE.");

        int offset = LocateSubsequence(message.SignedDataObject, originalCrl);
        Assert.IsGreaterThanOrEqualTo(0, offset, "The independently-read CRL encoding must occur verbatim inside the Signed Data Object it was read from.");

        byte[] mutated = (byte[])message.SignedDataObject.Clone();
        mutated[offset + originalCrl.Length - 1] ^= 0xFF;

        using CmsSignedData mutatedSignedData = CmsSignedData.FromBytes(mutated, BaseMemoryPool.Shared);
        List<byte[]> archiveTokens = UnsignedAttributeValues(mutated, signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        using PkiCertificateMemory archiveToken = ToTokenCarrier(archiveTokens[0]);

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = mutatedSignedData, ArchiveTimestampToken = archiveToken },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.HashIndexInvalid, coverage.Status,
            "§5.5.2: the archived index entry for the CRL's original bytes now matches no current material — the asymmetric membership check reports this as invalid.");

        CapstoneWireMessage mutatedMessage = message with { SignedDataObject = mutated };
        using ReconstructedCapstoneVerifyingParty verifier = await ReconstructedCapstoneVerifyingParty.CreateAsync(
            mutatedMessage, TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            verifier.Inputs, verifier.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, message.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(SignatureValidationIndication.TotalPassed, outcome.Conclusion.Indication,
            "Fail-closed: once a covered element's bytes no longer match the archive time-stamp's own index, the engine must not report TOTAL-PASSED.");
    }


    /// <summary>
    /// The signing party: mints a Root CA, a Time-Stamping Authority and a signer leaf of one
    /// <see cref="X509ChainTestRing"/>, produces a CAdES-B-B signature through <see cref="CAdESSignatureCreation"/>'s
    /// data-to-sign/signature-value split (R-3), raises it to B-T, B-LT and B-LTA through
    /// <see cref="CAdESSignatureAugmentation"/>, checks the result against the independent BouncyCastle oracle
    /// chain (leg 3), and releases every certificate, key and carrier before returning the wire message.
    /// </summary>
    /// <param name="includeContentTimestamp">Whether the minted B-B carries a <c>content-time-stamp</c> signed attribute (clause 5.2.8), acquired before the archive time-stamp so the archive time-stamp protects it through step 3) of clause 5.5.3.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The wire message. Nothing else survives this call.</returns>
    private static async ValueTask<CapstoneWireMessage> MintCapstoneWorldAsync(bool includeContentTimestamp, CancellationToken cancellationToken)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset contentTimestampTime = signingTime.AddMinutes(1);
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset validationDataTime = signingTime.AddHours(2);
        DateTimeOffset archiveTimestampTime = signingTime.AddHours(3);
        DateTimeOffset validationTime = signingTime.AddDays(30);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);
        DateTimeOffset revocationThisUpdate = validationDataTime.AddMinutes(-30);
        DateTimeOffset revocationNextUpdate = signingTime.AddYears(1);

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, SignerDnsName, timeProvider, notBefore: notBefore, notAfter: notAfter);

        using PkiCertificateMemory signerCertificate = ToCertificateCarrier(signer.Certificate.RawData);

        //B-B, through the data-to-sign/signature-value split (R-3): phase (1)'s output is signed by the leaf's
        //own platform key directly — the shape a remote signer (CSC, ETSI TS 119 432) uses — and phase (2)
        //assembles the final SignedData. When asked, a content-time-stamp (clause 5.2.8, a SIGNED attribute) is
        //acquired and embedded through the same shipped surface, over the independent TSP oracle.
        var contentResponder = new MintingTimestampResponder(authority, [authority, root], contentTimestampTime);
        CAdESOptionalSignedAttributes? optionalAttributes = includeContentTimestamp
            ? new CAdESOptionalSignedAttributes
            {
                ContentTimestampRequests = [new CAdESContentTimestampRequest { TsaUri = TsaUri, FetchResponse = contentResponder.FetchAsync }]
            }
            : null;
        using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareAsync(
            signerCertificate, Content, null, PkiDigestAlgorithm.Sha256, signingTime, algorithmConstraints: null,
            cmsAlgorithmProtectionSignatureAlgorithmOid: null, BaseMemoryPool.Shared, cancellationToken, optionalAttributes).ConfigureAwait(false);
        byte[] signatureValueP1363 = signer.SigningKey.SignData(preparation.SigningInput.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
        using IMemoryOwner<byte> signatureValueDer = EcdsaSignatureEncoding.ConvertP1363ToDer(signatureValueP1363, BaseMemoryPool.Shared, out int derLength);
        using CmsSignedData baseline = CAdESSignatureCreation.Complete(
            preparation, signerCertificate, CryptoAlgorithm.P256, signatureValueDer.Memory[..derLength], additionalCertificates: null, BaseMemoryPool.Shared);

        //B-T, over the independent BouncyCastle TSP oracle answering the RFC 3161 request octets that actually
        //crossed the shipped transport seam.
        var signatureResponder = new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime);
        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = signatureResponder.FetchAsync,
                SigningCertificate = signerCertificate
            },
            BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        //B-LT: the root's certificate, a clean certificate revocation list, and an OCSP response about the
        //signer — the CRL and the certificate into SignedData.certificates/.crls, the OCSP response as the RFC
        //5940 other alternative (requirements d, q, r).
        using PkiCertificateMemory rootCertificate = ToCertificateCarrier(root.Certificate.RawData);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(
            root, revocationThisUpdate, revocationNextUpdate, []);
        using PkiCertificateMemory ocspResponse = X509ChainTestRingRevocation.MintOcspResponse(
            signer, root, OcspCertificateStatus.Good, revocationThisUpdate, revocationNextUpdate);

        //The OCSP response placed as B-LT material is independently verified through the shipped reader against
        //a freshly built matching request, before the firewall closes — the material is real, not inert filler.
        using OcspRequestContent probe = await X509ChainTestRingRevocation.CreateOcspRequestAsync(
            signer, root, BaseMemoryPool.Shared, includeNonce: false, cancellationToken).ConfigureAwait(false);
        OcspResponseVerificationResult probeResult = await OcspResponseVerification.VerifyAsync(
            ocspResponse, probe, rootCertificate, validationDataTime, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        if(probeResult.Outcome != OcspResponseVerificationOutcome.Verified)
        {
            throw new InvalidOperationException($"The minted OCSP response did not independently verify ({probeResult.Outcome}).");
        }

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            timestamped,
            signerIndex: 0,
            new CAdESValidationMaterial
            {
                Certificates = [rootCertificate],
                CertificateRevocationLists = [revocationList],
                OcspResponses = [ocspResponse]
            },
            BaseMemoryPool.Shared);

        //The ats-hash-index-v3 the archive time-stamp will carry covers the material present at THIS instant —
        //B-LT, before the archive-time-stamp attribute itself exists (clause 5.5.2: an archive time-stamp cannot
        //index itself) — so the independent oracle below is run over these octets, not the post-B-LTA ones.
        byte[] longTermBytes = longTerm.AsReadOnlySpan().ToArray();

        //B-LTA, over the same independent TSP oracle; the ats-hash-index-v3 graft is the shipped surface's own
        //work (R-4/R-6), asserted against stage 3's independent reimplementation below.
        var archiveResponder = new MintingTimestampResponder(authority, [authority, root], archiveTimestampTime);
        using CmsSignedData archived = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = longTerm,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = archiveResponder.FetchAsync,
                ValidationMaterial = CAdESValidationMaterial.None,
                SigningCertificate = signerCertificate
            },
            BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        byte[] sdoBytes = archived.AsReadOnlySpan().ToArray();

        //---- Leg 3: "Verifiable creates → independent oracle verifies" (charter testing-architecture leg 3). ----
        using CmsSignedData forCmsOracle = CmsSignedData.FromBytes(sdoBytes, BaseMemoryPool.Shared);
        using CmsVerifiedContent verifiedByBouncyCastle = await ResolveBouncyCastleCmsVerifier()(
            forCmsOracle, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(Content.Span.SequenceEqual(verifiedByBouncyCastle.Content.Span),
            "Leg 3: the independent BouncyCastle CMS oracle recovers exactly the content the shipped creation surface signed.");

        List<byte[]> signatureTimestampTokens = UnsignedAttributeValues(sdoBytes, signerIndex: 0, CAdESSignatureFacts.SignatureTimestampAttributeOid);
        List<byte[]> archiveTimestampTokens = UnsignedAttributeValues(sdoBytes, signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        Assert.HasCount(1, signatureTimestampTokens, "Table 1 requirement l: exactly one signature-time-stamp.");
        Assert.HasCount(1, archiveTimestampTokens, "Clause 5.5.3: exactly one archive-time-stamp-v3.");
        Assert.IsTrue(VerifiesUnderAnyEmbeddedCertificate(signatureTimestampTokens[0]),
            "Leg 3: the independent BouncyCastle TSP validator accepts the signature-time-stamp token under a certificate the token itself carries.");
        Assert.IsTrue(VerifiesUnderAnyEmbeddedCertificate(archiveTimestampTokens[0]),
            "Leg 3: the independent BouncyCastle TSP validator accepts the archive-time-stamp token under a certificate the token itself carries.");

        using PooledMemory independentIndex = AtsHashIndexV3Oracle.EncodeHashIndex(longTermBytes, signerIndex: 0, PkiDigestAlgorithm.Sha256);
        using PkiCertificateMemory archiveTokenCarrier = ToTokenCarrier(archiveTimestampTokens[0]);
        using AtsHashIndexV3? attachedIndex = ArchiveTimestampV3.ReadHashIndexFromToken(archiveTokenCarrier, BaseMemoryPool.Shared);
        Assert.IsNotNull(attachedIndex, "The archive time-stamp token carries the ats-hash-index-v3 unsigned attribute.");
        Assert.AreSequenceEqual(independentIndex.AsReadOnlySpan().ToArray(), attachedIndex!.AsReadOnlySpan().ToArray(),
            "Leg 3: stage 3's independent hash-index reimplementation recomputes exactly the index the shipped augmentation surface grafted into the token.");
        //---- end leg 3 ----

        //The content-time-stamp token octets, read back through the shipped signed-attribute reader, so the
        //verifying party's report can be checked against the exact token the archive time-stamp protects.
        byte[]? contentTimestampToken = includeContentTimestamp
            ? CmsSignedDataAugmentation.ReadSignedAttributeValue(archived, signerIndex: 0, CAdESSignatureFacts.ContentTimestampAttributeOid)?.ToArray()
            : null;

        return new CapstoneWireMessage
        {
            SignedDataObject = sdoBytes,
            TrustAnchorCertificate = root.Certificate.RawData,
            ValidationTime = validationTime,
            SigningTime = signingTime,
            SignatureTimestampTime = signatureTimestampTime,
            ArchiveTimestampTime = archiveTimestampTime,
            ContentTimestampToken = contentTimestampToken
        };
    }


    /// <summary>Resolves the registered BouncyCastle <see cref="VerifyCmsSignedDataDelegate"/> — an independent backend sharing no code with the creation/augmentation surfaces.</summary>
    /// <returns>The delegate.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no such delegate is registered.</exception>
    private static VerifyCmsSignedDataDelegate ResolveBouncyCastleCmsVerifier() =>
        CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate), "BouncyCastle")
            ?? throw new InvalidOperationException("No BouncyCastle VerifyCmsSignedDataDelegate has been registered.");


    /// <summary>
    /// Checks a time-stamp token against the independent BouncyCastle TSP validator, trying each certificate the
    /// token itself embeds until one authenticates it — the oracle never needs the minting party's own
    /// <see cref="X509ChainTestRingNode"/>, only the token's own octets.
    /// </summary>
    /// <param name="tokenBytes">The DER-encoded RFC 3161 <c>TimeStampToken</c>.</param>
    /// <returns><see langword="true"/> when the independent validator accepts the token under one of its own embedded certificates.</returns>
    private static bool VerifiesUnderAnyEmbeddedCertificate(byte[] tokenBytes)
    {
        var token = new TimeStampToken(new BcCmsSignedData(tokenBytes));
        foreach(BcX509Certificate candidate in token.GetCertificates().EnumerateMatches(null))
        {
            try
            {
                token.Validate(candidate);

                return true;
            }
            catch(TspException)
            {
                //This embedded certificate is not the one that signed the token (for example, the chain's
                //issuer rather than the authority itself); try the next.
            }
        }

        return false;
    }


    /// <summary>Finds the first byte offset at which <paramref name="needle"/> occurs verbatim inside <paramref name="haystack"/>.</summary>
    /// <param name="haystack">The array to search.</param>
    /// <param name="needle">The byte sequence to locate.</param>
    /// <returns>The zero-based offset, or <c>-1</c> when no occurrence exists.</returns>
    private static int LocateSubsequence(byte[] haystack, byte[] needle)
    {
        if(needle.Length == 0 || needle.Length > haystack.Length)
        {
            return -1;
        }

        for(int start = 0; start <= haystack.Length - needle.Length; ++start)
        {
            if(haystack.AsSpan(start, needle.Length).SequenceEqual(needle))
            {
                return start;
            }
        }

        return -1;
    }


    /// <summary>
    /// Returns every value of every unsigned attribute of one attribute type, walked independently of the
    /// library's own locator, through <see cref="CmsStructureOracle"/>.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer.</param>
    /// <param name="attributeType">The attribute's object identifier.</param>
    /// <returns>The whole encodings of the matching values.</returns>
    private static List<byte[]> UnsignedAttributeValues(byte[] signedData, int signerIndex, string attributeType)
    {
        List<byte[]> values = [];
        List<CmsTlvBounds> attributes = CmsStructureOracle.UnsignedAttributes(signedData, signerIndex);
        for(int i = 0; i < attributes.Count; ++i)
        {
            List<CmsTlvBounds> parts = CmsStructureOracle.Children(signedData, attributes[i]);
            string oid = System.Formats.Asn1.AsnDecoder.ReadObjectIdentifier(
                signedData.AsSpan()[parts[0].Start..parts[0].End], System.Formats.Asn1.AsnEncodingRules.BER, out _);
            if(!string.Equals(oid, attributeType, StringComparison.Ordinal))
            {
                continue;
            }

            List<CmsTlvBounds> members = CmsStructureOracle.Children(signedData, parts[1]);
            for(int j = 0; j < members.Count; ++j)
            {
                values.Add(signedData[members[j].Start..members[j].End]);
            }
        }

        return values;
    }


    /// <summary>Copies DER bytes into a pooled carrier tagged as an X.509 certificate.</summary>
    /// <param name="certificate">The DER-encoded certificate.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate) => ToCarrier(certificate, PkiCertificateTags.X509Certificate);


    /// <summary>Copies DER bytes into a pooled carrier tagged as a time-stamp token.</summary>
    /// <param name="token">The DER-encoded token.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToTokenCarrier(byte[] token) => ToCarrier(token, PkiCertificateTags.TimestampToken);


    /// <summary>Copies received DER octets into a pooled carrier of the stated kind — the shared helper every wire-boundary crossing in this class goes through.</summary>
    /// <param name="derBytes">The octets to copy.</param>
    /// <param name="tag">The kind discriminator the carrier states.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// Everything that crosses the firewall: the DER octets of the B-LTA Signed Data Object, the DER octets of
    /// the trust anchor certificate, and the public instants a verifying party would learn from its own clock
    /// and from the received material.
    /// </summary>
    /// <remarks>Deliberately nothing but octets and instants — no carrier, no key, no record of the validation model.</remarks>
    private sealed record CapstoneWireMessage
    {
        /// <summary>The DER-encoded CMS <c>SignedData</c> the signing party produced, raised through B-LTA.</summary>
        public required byte[] SignedDataObject { get; init; }

        /// <summary>The DER-encoded Root CA certificate the verifier is configured to trust.</summary>
        public required byte[] TrustAnchorCertificate { get; init; }

        /// <summary>The instant the verifier validates at.</summary>
        public required DateTimeOffset ValidationTime { get; init; }

        /// <summary>The claimed signing time the signature states.</summary>
        public required DateTimeOffset SigningTime { get; init; }

        /// <summary>The generation time of the signature time-stamp.</summary>
        public required DateTimeOffset SignatureTimestampTime { get; init; }

        /// <summary>The generation time of the archive time-stamp.</summary>
        public required DateTimeOffset ArchiveTimestampTime { get; init; }

        /// <summary>The DER octets of the <c>content-time-stamp</c> token the signature carries, or <see langword="null"/> when it carries none.</summary>
        public byte[]? ContentTimestampToken { get; init; }
    }


    /// <summary>
    /// The verifying party: it owns everything it built from the received octets and nothing else, and exposes
    /// the inputs and seams one run of the validation algorithm of clause 5 takes.
    /// </summary>
    private sealed class ReconstructedCapstoneVerifyingParty: IDisposable
    {
        /// <summary>The carriers this party rented, released in reverse order.</summary>
        private readonly List<IDisposable> owned = [];

        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>The Signed Data Object rebuilt from the received octets.</summary>
        public CmsSignedData SignedDataObject { get; private set; } = null!;

        /// <summary>The trust anchor rebuilt from the received octets.</summary>
        public PkiCertificateMemory TrustAnchor { get; private set; } = null!;

        /// <summary>The certificate revocation lists this party read out of the received Signed Data Object's own embedded material.</summary>
        public IReadOnlyList<PkiCertificateMemory> EmbeddedRevocationLists { get; private set; } = [];

        /// <summary>The inputs of Tables 18, 20 and 27, assembled from the received octets alone.</summary>
        public SignatureValidationInputs Inputs { get; private set; } = null!;

        /// <summary>The seams the run composes: the shipped CAdES binding, an offline chain completer, the platform path validator, and an offline CRL checker over the embedded material.</summary>
        public SignatureValidationSeams Seams { get; private set; } = null!;


        /// <summary>
        /// Reconstructs a verifying party from a wire message.
        /// </summary>
        /// <param name="message">The octets and public instants the party received.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The party, which the caller disposes.</returns>
        public static async ValueTask<ReconstructedCapstoneVerifyingParty> CreateAsync(
            CapstoneWireMessage message,
            CancellationToken cancellationToken)
        {
            var party = new ReconstructedCapstoneVerifyingParty();
            try
            {
                await party.BuildAsync(message, cancellationToken).ConfigureAwait(false);

                return party;
            }
            catch
            {
                party.Dispose();

                throw;
            }
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            disposed = true;
            for(int i = owned.Count - 1; i >= 0; --i)
            {
                owned[i].Dispose();
            }

            owned.Clear();
        }


        /// <summary>
        /// Rebuilds every carrier and assembles the inputs and seams.
        /// </summary>
        /// <param name="message">The received message.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        private async ValueTask BuildAsync(CapstoneWireMessage message, CancellationToken cancellationToken)
        {
            SignedDataObject = Own(CmsSignedData.FromBytes(message.SignedDataObject, BaseMemoryPool.Shared));
            TrustAnchor = Own(ToCarrier(message.TrustAnchorCertificate, PkiCertificateTags.X509Certificate));

            using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
                new SignatureFactsExtractionContext { SignedDataObject = SignedDataObject },
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status,
                "The received octets have to be a CMS SignedData the shipped CAdES binding can read.");

            List<PkiCertificateMemory> revocationLists = [];
            for(int i = 0; i < facts.EmbeddedCertificateRevocationLists.Count; ++i)
            {
                revocationLists.Add(Own(ToCarrier(facts.EmbeddedCertificateRevocationLists[i].AsReadOnlySpan().ToArray(), PkiCertificateTags.X509Crl)));
            }

            EmbeddedRevocationLists = [.. revocationLists];
            Assert.IsNotEmpty(EmbeddedRevocationLists, "The received Signed Data Object carries the certificate revocation list the B-LT augmentation placed.");
            Assert.IsNotEmpty(facts.EmbeddedOcspResponses,
                "The OCSP response the B-LT augmentation placed into SignedData.crls under RFC 5940 §2's id-ri-ocsp-response is surfaced back out of the wire bytes (clause 5.4.2.2) — the shipped reader recognises the form the shipped writer produces.");

            AssembleInputs();
        }


        /// <summary>
        /// Assembles the verifier's own X.509 and cryptographic constraints, the seams the run composes, and
        /// the inputs of Tables 18, 20 and 27.
        /// </summary>
        private void AssembleInputs()
        {
            var x509Constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(TrustAnchor, SunsetDate: null)]
            };

            var cryptographicConstraints = new CryptographicConstraints
            {
                Entries =
                [
                    new AlgorithmReliabilityEntry(
                        new PkiAlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid),
                        MinimumKeySizeBits: X509ChainTestRing.SigningKeySizeBits,
                        TrustedUntil: null),
                    new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null)
                ]
            };

            var constraints = new SignatureValidationConstraints
            {
                Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
                X509 = x509Constraints,
                Cryptographic = cryptographicConstraints,

                //Clause 5.6.3.4 step 3): with the current-time process already Passed and this left false, the
                //process for Signatures providing Long Term Availability returns immediately without ever
                //walking the archive time-stamp — nothing this capstone is chartered to demonstrate would run.
                //Asserting it exercises the archive time-stamp's own coverage and proof-of-existence extraction
                //for real, which is the policy choice a Driving Application makes when it wants long-term
                //material validated regardless of whether the simpler process already sufficed.
                SignatureElements = new SignatureElementsConstraints { RequireLongTermAvailabilityAttributeValidity = true }
            };

            var completer = new CertificateChainCompleter([TrustAnchor]);
            var revocationChecker = new CrlRevocationChecker(EmbeddedRevocationLists);

            Seams = new SignatureValidationSeams
            {
                Format = CAdESSignatureFacts.Seam,
                CompleteCertificateChain = completer.CompleteAsync,
                ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync,
                CheckRevocation = revocationChecker.CheckAsync
            };

            Inputs = new SignatureValidationInputs
            {
                SignedDataObject = SignedDataObject,
                Constraints = constraints,
                TimestampConstraints = constraints
            };
        }


        /// <summary>Takes ownership of one carrier.</summary>
        /// <typeparam name="T">The carrier's type.</typeparam>
        /// <param name="carrier">The carrier.</param>
        /// <returns>The same carrier.</returns>
        private T Own<T>(T carrier) where T: IDisposable
        {
            owned.Add(carrier);

            return carrier;
        }
    }
}

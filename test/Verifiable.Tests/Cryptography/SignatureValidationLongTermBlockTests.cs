using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Drives the additional building blocks of ETSI EN 319 102-1 V1.4.1 clause 5.6.2 directly, at a granularity the
/// composed process tests of <c>SignatureValidationProcessTests</c> do not isolate: every distinct outcome of the
/// past certificate validation building block (clause 5.6.2.1), the validation time sliding process's freshness-
/// and cryptographic-constraints-triggered slides (clause 5.6.2.2 steps 2)c) and 2)d)), and the POE extraction
/// building block's indirect derivation together with the hash-reliability gate that refuses it (clause 5.6.2.3
/// step 4).
/// </summary>
/// <remarks>
/// Certificate material comes from <see cref="X509ChainTestRing"/>'s platform certificate requests for the
/// self-contained block-level tests, and from <see cref="AnnexAValidationScenario"/>'s real CAdES signature with a
/// real archive time-stamp for the POE extraction tests, which need a genuine ESS signing-certificate reference to
/// derive an indirect proof from. Nothing here hashes directly; every digest an assertion needs is the block's own,
/// taken through the registered digest seam.
/// </remarks>
[TestClass]
internal sealed class SignatureValidationLongTermBlockTests
{
    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Step 2)c) of clause 5.6.2.2: when the latest-issued revocation data about a certificate is not fresh at
    /// control-time, control-time slides to the earlier of its current value and that data's issuance time — as
    /// opposed to step 2)b)'s revocation-triggered slide, which the composed process tests already exercise.
    /// </summary>
    [TestMethod]
    public async Task ValidationTimeSlidingAppliesTheFreshnessTriggeredSlideOfStep2C()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("freshness-slide.example.test", timeProvider);
        DateTimeOffset currentTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        using var resources = new SignatureValidationResources();
        try
        {
            using PkiCertificateMemory intermediateRevocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x01]);
            using PkiCertificateMemory leafRevocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x02]);
            DateTimeOffset staleThisUpdate = currentTime.AddDays(-10);
            List<RevocationStatusInformation> certificateValidationData =
            [
                Good(intermediateRevocationData, chain[1], currentTime.AddHours(-1), currentTime.AddDays(2)),
                Good(leafRevocationData, chain[0], staleThisUpdate, staleThisUpdate.AddDays(1))
            ];
            ProofOfExistenceSet proofs = await ProofsAtAsync(
                chain, [intermediateRevocationData, leafRevocationData], currentTime, resources, TestContext.CancellationToken).ConfigureAwait(false);
            var x509Constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(anchors[0], SunsetDate: null)],
                MaximumAcceptedRevocationFreshness = TimeSpan.FromDays(1)
            };

            ValidationTimeSlidingResult result = await ValidationTimeSliding.SlideAsync(
                chain, proofs, certificateValidationData, trustAnchorSunsetDate: null, ReliableEllipticCurveAlgorithms(),
                x509Constraints, currentTime, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(BuildingBlockIndication.Passed, result.Conclusion.Indication, "Step 2)e): every certificate of the chain has been considered.");
            Assert.AreEqual(staleThisUpdate, result.ControlTime,
                "Step 2)c): a freshness failure slides control-time to the issuance time of the revocation data that failed it, not to the revocation time — the certificate was never marked revoked.");
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>
    /// Step 2)d) of clause 5.6.2.2: applying the cryptographic constraints to a certificate slides control-time to
    /// the latest instant the dated table asserts every listed algorithm was reliable, distinct from both the
    /// revocation-triggered slide of step 2)b) and the freshness-triggered slide of step 2)c).
    /// </summary>
    [TestMethod]
    public async Task ValidationTimeSlidingAppliesTheCryptographicConstraintsTriggeredSlideOfStep2D()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("crypto-slide.example.test", timeProvider);
        DateTimeOffset currentTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        using var resources = new SignatureValidationResources();
        try
        {
            using PkiCertificateMemory intermediateRevocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x01]);
            using PkiCertificateMemory leafRevocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x02]);
            DateTimeOffset trustedUntil = currentTime.AddDays(-5);
            List<RevocationStatusInformation> certificateValidationData =
            [
                Good(intermediateRevocationData, chain[1], currentTime.AddDays(-2), currentTime.AddDays(30)),
                Good(leafRevocationData, chain[0], currentTime.AddDays(-6), currentTime.AddDays(30))
            ];
            //Every proof is anchored well before the control-time the slide is expected to land on, so it still
            //covers the leaf's own turn after the intermediate's turn has already slid control-time backwards.
            ProofOfExistenceSet proofs = await ProofsAtAsync(
                chain, [intermediateRevocationData, leafRevocationData], currentTime.AddDays(-6), resources, TestContext.CancellationToken).ConfigureAwait(false);
            var x509Constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(anchors[0], SunsetDate: null)],
                MaximumAcceptedRevocationFreshness = TimeSpan.FromDays(7)
            };
            CryptographicConstraints dated = new()
            {
                Entries = [new AlgorithmReliabilityEntry(new AlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid), MinimumKeySizeBits: 256, trustedUntil)]
            };

            ValidationTimeSlidingResult result = await ValidationTimeSliding.SlideAsync(
                chain, proofs, certificateValidationData, trustAnchorSunsetDate: null, dated, x509Constraints,
                currentTime, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(BuildingBlockIndication.Passed, result.Conclusion.Indication);
            Assert.AreEqual(trustedUntil, result.ControlTime,
                "Step 2)d): the cryptographic constraints slide control-time to the latest instant every listed algorithm was reliable.");
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>Clause 5.6.2.1: a certificate whose revoked intermediate can be proven revoked passes, at the revocation instant control-time slid to.</summary>
    [TestMethod]
    public async Task PastCertificateValidationPassesAtTheControlTimeAssignedByARevokedIntermediate()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("past-passed.example.test", timeProvider);
        DateTimeOffset currentTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        using var resources = new SignatureValidationResources();
        try
        {
            DateTimeOffset revocationTime = currentTime.AddDays(-30);
            using PkiCertificateMemory intermediateRevocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x01]);
            using PkiCertificateMemory leafRevocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x02]);
            List<RevocationStatusInformation> revocationStatusInformation =
            [
                Revoked(intermediateRevocationData, chain[1], revocationTime, currentTime.AddDays(-29)),
                Good(leafRevocationData, chain[0], revocationTime.AddDays(-5), revocationTime.AddDays(60))
            ];
            ProofOfExistenceSet proofs = await ProofsAtAsync(
                chain, [intermediateRevocationData, leafRevocationData], revocationTime.AddDays(-6), resources, TestContext.CancellationToken).ConfigureAwait(false);
            var x509Constraints = new X509ValidationConstraints { TrustAnchors = [new TrustAnchorConstraint(anchors[0], SunsetDate: null)] };
            SignatureValidationSeams seams = BuildSeams([chain[1], chain[2]], MicrosoftX509Functions.ValidateChainAsync);

            PastCertificateValidationResult result = await PastCertificateValidation.ValidateAsync(
                chain[0], x509Constraints, proofs, [chain[1], chain[2]], revocationStatusInformation,
                ReliableEllipticCurveAlgorithms(), seams, currentTime, resources, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(BuildingBlockIndication.Passed, result.Conclusion.Indication, "Clause 5.6.2.1: a chain the sliding process could validate at a past control-time passes.");
            Assert.AreEqual(revocationTime, result.ValidationTime, "Step 5) returns the control-time step 3)'s validation time sliding calculated.");
            Assert.HasCount(3, result.CertificateChain,
                "Step 1) of clause 5.6.2.1.4 builds the chain from the certificate validation data Table 21 makes mandatory, so the intermediate and the anchor it supplies are both in the prospective chain.");
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>Step 1)a) of clause 5.6.2.1.4: an offline store that cannot reach any trust anchor at all leaves no chain to consider.</summary>
    [TestMethod]
    public async Task PastCertificateValidationReportsNoCertificateChainFoundWhenNoChainCanBeBuiltAtAll()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("past-no-chain.example.test", timeProvider);
        DateTimeOffset currentTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        using var resources = new SignatureValidationResources();
        try
        {
            var x509Constraints = new X509ValidationConstraints { TrustAnchors = [new TrustAnchorConstraint(anchors[0], SunsetDate: null)] };
            SignatureValidationSeams seams = BuildSeams([], MicrosoftX509Functions.ValidateChainAsync);

            PastCertificateValidationResult result = await PastCertificateValidation.ValidateAsync(
                chain[0], x509Constraints, ProofOfExistenceSet.Empty, [], [], CryptographicConstraints.Empty,
                seams, currentTime, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication);
            Assert.Contains(SignatureValidationSubIndication.NoCertificateChainFound, result.Conclusion.SubIndications, "Step 1)a) names NO_CERTIFICATE_CHAIN_FOUND.");
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>Step 2)b) of clause 5.6.2.1.4: a path validation seam that fails for any reason other than the certificates' own facts sets CERTIFICATE_CHAIN_GENERAL_FAILURE.</summary>
    [TestMethod]
    public async Task PastCertificateValidationReportsCertificateChainGeneralFailureWhenPathValidationFails()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("past-general-failure.example.test", timeProvider);
        DateTimeOffset currentTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        using var resources = new SignatureValidationResources();
        try
        {
            var x509Constraints = new X509ValidationConstraints { TrustAnchors = [new TrustAnchorConstraint(anchors[0], SunsetDate: null)] };
            SignatureValidationSeams seams = BuildSeams([chain[1], chain[2]], AlwaysFailingPathValidation);

            PastCertificateValidationResult result = await PastCertificateValidation.ValidateAsync(
                chain[0], x509Constraints, ProofOfExistenceSet.Empty, [], [], CryptographicConstraints.Empty,
                seams, currentTime, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication);
            Assert.Contains(SignatureValidationSubIndication.CertificateChainGeneralFailure, result.Conclusion.SubIndications, "Step 2)b) names CERTIFICATE_CHAIN_GENERAL_FAILURE.");
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>Step 4) of clause 5.6.2.1.4: a chain that fails the X.509 validation constraints (here, a certificate policy none of the ring's certificates carry) is CHAIN_CONSTRAINTS_FAILURE, even after the chain otherwise slides successfully.</summary>
    [TestMethod]
    public async Task PastCertificateValidationReportsChainConstraintsFailureWhenTheMetadataConstraintIsUnmet()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("past-chain-constraints.example.test", timeProvider);
        DateTimeOffset currentTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        using var resources = new SignatureValidationResources();
        try
        {
            DateTimeOffset revocationTime = currentTime.AddDays(-30);
            using PkiCertificateMemory intermediateRevocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x01]);
            using PkiCertificateMemory leafRevocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x02]);
            List<RevocationStatusInformation> revocationStatusInformation =
            [
                Revoked(intermediateRevocationData, chain[1], revocationTime, currentTime.AddDays(-29)),
                Good(leafRevocationData, chain[0], revocationTime.AddDays(-5), revocationTime.AddDays(60))
            ];
            ProofOfExistenceSet proofs = await ProofsAtAsync(
                chain, [intermediateRevocationData, leafRevocationData], revocationTime.AddDays(-6), resources, TestContext.CancellationToken).ConfigureAwait(false);
            var x509Constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(anchors[0], SunsetDate: null)],
                CertificateMetadataConstraints =
                [
                    new RequiredCertificatePolicyConstraint
                    {
                        Identifier = ValidationConstraintIdentifier.CertificateMetadata,
                        AppliesToWholeChain = false,
                        PolicyOids = ["2.99.99.99.1"]
                    }
                ]
            };
            SignatureValidationSeams seams = BuildSeams([chain[1], chain[2]], MicrosoftX509Functions.ValidateChainAsync);

            PastCertificateValidationResult result = await PastCertificateValidation.ValidateAsync(
                chain[0], x509Constraints, proofs, [chain[1], chain[2]], revocationStatusInformation,
                ReliableEllipticCurveAlgorithms(), seams, currentTime, resources, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication, "Step 4): the chain slid successfully in step 3) but does not carry the required policy.");
            Assert.Contains(SignatureValidationSubIndication.ChainConstraintsFailure, result.Conclusion.SubIndications);
            Assert.IsInstanceOfType<ChainConstraintsFailureReportData>(result.Conclusion.ReportData[0]);
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>
    /// Step 4) of clause 5.6.2.3: a signing-certificate reference the archive time-stamp protects derives the
    /// digest-of-object proof of step 4)a) whenever the reference's hash function is trusted at the time-stamp's
    /// own generation time, and derives the additional object-scope proof of step 4)b) only when that hash
    /// function is <em>also</em> trusted until at least the later instant an external proof already places the
    /// referenced object at — the hash-reliability gate that keeps step 4)b) from over-deriving.
    /// </summary>
    [TestMethod]
    public async Task PoeExtractionDerivesTheIndirectProofOnlyWhenTheHashIsReliableUntilTheLaterInstant()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificationAuthorityWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using var resources = new SignatureValidationResources();
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = scenario.SignedDataObject }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp archiveTimestamp = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp)[0];
        DateTimeOffset generationTime = scenario.ArchiveTimestampCreated!.Value;

        SignatureElementsConstraints elements = scenario.Constraints.SignatureElements;
        ProtectedObjectSet protectedObjects = await ProofOfExistenceExtraction.DetermineProtectedObjectsAsync(
            facts, archiveTimestamp, elements, scenario.Seams, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsNotEmpty(protectedObjects.References, "The archive time-stamp protects the ESS signing-certificate reference, which names the signing certificate by a SHA-256 digest.");
        ValidationObjectIdentity referencedCertificate = protectedObjects.References[0].ReferencedObject;

        //An external proof that the referenced object itself existed at a later instant T2, distinct from the
        //time-stamp's own generation time T1 — exactly step 4)b)'s own precondition.
        DateTimeOffset laterInstant = generationTime.AddDays(1);
        ProofOfExistenceSet incomingProofs = ProofOfExistenceSet.Empty.With(new ProofOfExistence
        {
            ObjectIdentity = referencedCertificate,
            Instant = laterInstant,
            Scope = ProofOfExistenceScope.Object,
            Origin = ProofOfExistenceOrigin.DrivingApplicationAssertion
        });

        CryptographicConstraints trustedUntilLaterInstant = new()
        {
            Entries = [new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, laterInstant)]
        };
        CryptographicConstraints trustedPastGenerationTimeOnly = new()
        {
            Entries = [new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, generationTime.AddHours(1))]
        };
        CryptographicConstraints trustedExactlyUntilGenerationTime = new()
        {
            Entries = [new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, generationTime)]
        };
        CryptographicConstraints notTrustedAtGenerationTime = new()
        {
            Entries = [new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, generationTime.AddDays(-1))]
        };

        ProofOfExistenceSet withIndirectDerivation = await ProofOfExistenceExtraction.ExtractAsync(
            facts, archiveTimestamp, generationTime, incomingProofs, trustedUntilLaterInstant, elements, scenario.Seams,
            resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        ProofOfExistenceSet withDigestOnly = await ProofOfExistenceExtraction.ExtractAsync(
            facts, archiveTimestamp, generationTime, incomingProofs, trustedPastGenerationTimeOnly, elements, scenario.Seams,
            resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        ProofOfExistenceSet atTheGenerationTimeBoundary = await ProofOfExistenceExtraction.ExtractAsync(
            facts, archiveTimestamp, generationTime, incomingProofs, trustedExactlyUntilGenerationTime, elements, scenario.Seams,
            resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        ProofOfExistenceSet withNeitherDerived = await ProofOfExistenceExtraction.ExtractAsync(
            facts, archiveTimestamp, generationTime, incomingProofs, notTrustedAtGenerationTime, elements, scenario.Seams,
            resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //The referenced certificate is also protected directly (step 5), so ExistsAtOrBefore alone cannot isolate
        //step 4)'s own derivation; the check is against the specific proofs step 4) itself adds.
        Assert.IsTrue(HasIndirectDerivation(withIndirectDerivation, referencedCertificate, generationTime),
            "Step 4)b): trusted until at least T2, the referenced object itself is additionally proven to have existed at T1.");
        Assert.IsTrue(withIndirectDerivation.DigestExistsAtOrBefore(referencedCertificate, AlgorithmIdentifier.Sha256, generationTime),
            "Step 4)a) still runs regardless of whether step 4)b)'s stronger condition also holds.");

        Assert.IsFalse(HasIndirectDerivation(withDigestOnly, referencedCertificate, generationTime),
            "Step 4)b)'s own gate: trusted past T1 but not until T2, so the additional object-scope proof must not be derived.");
        Assert.IsTrue(withDigestOnly.DigestExistsAtOrBefore(referencedCertificate, AlgorithmIdentifier.Sha256, generationTime),
            "Step 4)a)'s own, weaker gate (trusted until a date after T1) is satisfied on its own.");

        Assert.IsFalse(atTheGenerationTimeBoundary.DigestExistsAtOrBefore(referencedCertificate, AlgorithmIdentifier.Sha256, generationTime),
            "Step 4) admits a reference only where the hash function is trusted until at least a date AFTER T1, so a reliability assertion ending exactly at T1 derives nothing.");
        Assert.IsFalse(HasIndirectDerivation(atTheGenerationTimeBoundary, referencedCertificate, generationTime),
            "The same boundary keeps step 4)b) from deriving the object-scope proof.");

        Assert.IsFalse(HasIndirectDerivation(withNeitherDerived, referencedCertificate, generationTime),
            "The hash-reliability gate of step 4) refuses the indirect derivation once the hash is not trusted even at T1.");
        Assert.IsFalse(withNeitherDerived.DigestExistsAtOrBefore(referencedCertificate, AlgorithmIdentifier.Sha256, generationTime),
            "The same gate refuses the digest-of-object proof of step 4)a) too: nothing about the reference is derived once the hash function is not asserted reliable at the time-stamp's own generation time.");
    }


    /// <summary>
    /// Step 1) of clause 5.6.2.3.4 puts into the set <c>S</c> the objects "protected by the time-stamp". A
    /// time-stamp token obtained from a trusted Time-Stamping Authority over unrelated octets and appended as an
    /// unsigned signature time-stamp attribute protects none of this signature's objects, so it derives no proof
    /// of existence — not even for a caller that declared it accepts a coverage the format binding cannot state,
    /// because for the signature time-stamp class the binding does state it and the imprint does not match.
    /// </summary>
    [TestMethod]
    public async Task PoeExtractionDerivesNothingFromATimestampWhoseImprintDoesNotBindTheSignature()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificationAuthorityWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using var resources = new SignatureValidationResources();

        //A signature of the same world that carries no signature time-stamp of its own, so the only one it ends
        //up carrying is the appended token.
        using CmsSignedData baseline = CAdESSignatureTestFactory.SignBaseline(
            scenario.SignedContent.AsReadOnlyMemory(), scenario.Signer, scenario.SignatureCreated);

        //A genuine token from the same authority the world trusts, over octets that have nothing to do with this
        //signature, appended as a signature time-stamp attribute — which anyone can do, since unsigned attributes
        //are outside what the signature covers.
        byte[] unrelatedOctets = "octets this signature never touched"u8.ToArray();
        using CmsSignedData tampered = await CAdESSignatureTestFactory.AttachUnboundTimestampAsync(
            baseline,
            CAdESSignatureFacts.SignatureTimestampAttributeOid,
            scenario.SignatureTimestampAuthority,
            [scenario.SignatureTimestampAuthority, scenario.TimeStampingCertificationAuthority],
            unrelatedOctets,
            scenario.SignatureTimestampCreated,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = tampered }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        IReadOnlyList<EmbeddedTimestamp> signatureTimestamps = facts.TimestampsOfClass(SignatureTimestampClass.SignatureTimestamp);
        EmbeddedTimestamp farmed = signatureTimestamps[^1];

        ProtectedObjectSet protectedObjects = await ProofOfExistenceExtraction.DetermineProtectedObjectsAsync(
            facts, farmed, scenario.Constraints.SignatureElements, scenario.Seams, resources, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        ProofOfExistenceSet derived = await ProofOfExistenceExtraction.ExtractAsync(
            facts, farmed, scenario.SignatureTimestampCreated, ProofOfExistenceSet.Empty, scenario.CryptographicConstraints,
            scenario.Constraints.SignatureElements, scenario.Seams, resources, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        ValidationObjectIdentity signatureValueIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            facts.SignatureValue!.AsReadOnlyMemory(), ValidationObjectKind.SignatureValue, reference: null, resources,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, signatureTimestamps, "The appended token is surfaced as a signature time-stamp attribute; what it protects is decided by its imprint, not by the attribute it sits in.");
        Assert.IsEmpty(protectedObjects.Objects, "The set S holds only objects the time-stamp protects, and this token's message imprint binds none of this signature's octets.");
        Assert.IsEmpty(protectedObjects.References, "A token that protects nothing carries no protected reference either.");
        Assert.IsFalse(derived.ExistsAtOrBefore(signatureValueIdentity, scenario.SignatureTimestampCreated),
            "Step 5) adds a proof of existence for each object in S, and S is empty, so an unbound token can never lower best-signature-time in step 6) of clause 5.6.3.4.");
    }


    /// <summary>Decides whether a set carries a proof step 4)b)'s indirect derivation added for an object at an instant.</summary>
    /// <param name="proofs">The set to search.</param>
    /// <param name="objectIdentity">The object.</param>
    /// <param name="instant">The instant the derived proof states.</param>
    /// <returns><see langword="true"/> when such a proof is present.</returns>
    private static bool HasIndirectDerivation(ProofOfExistenceSet proofs, ValidationObjectIdentity objectIdentity, DateTimeOffset instant) =>
        proofs.For(objectIdentity).Any(proof =>
            proof.Origin == ProofOfExistenceOrigin.IndirectDerivation
            && proof.Scope == ProofOfExistenceScope.Object
            && proof.Instant == instant);


    /// <summary>Builds a cryptographic constraints table asserting the ring's own elliptic-curve signature algorithm reliable without expiry, so a test is decided by the step under test and not by an empty table.</summary>
    /// <returns>The table.</returns>
    private static CryptographicConstraints ReliableEllipticCurveAlgorithms() => new()
    {
        Entries = [new AlgorithmReliabilityEntry(new AlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid), MinimumKeySizeBits: 256, TrustedUntil: null)]
    };


    /// <summary>Builds the seam bundle a past-certificate-validation call composes, over a stated offline CA store and path validation seam.</summary>
    /// <param name="caCertificates">The offline store the chain completion seam draws from.</param>
    /// <param name="validateCertificateChain">The path validation seam.</param>
    /// <returns>The seams.</returns>
    private static SignatureValidationSeams BuildSeams(
        IReadOnlyList<PkiCertificateMemory> caCertificates,
        ValidateCertificateChainAsyncDelegate validateCertificateChain)
    {
        var completer = new CertificateChainCompleter(caCertificates);

        return new SignatureValidationSeams
        {
            Format = CAdESSignatureFacts.Seam,
            CompleteCertificateChain = completer.CompleteAsync,
            ValidateCertificateChain = validateCertificateChain
        };
    }


    /// <summary>A path validation seam that always fails, for the CERTIFICATE_CHAIN_GENERAL_FAILURE branch of step 2)b) of clause 5.6.2.1.4.</summary>
    /// <param name="chain">The chain, unused.</param>
    /// <param name="trustAnchors">The trust anchors, unused.</param>
    /// <param name="validationTime">The validation time, unused.</param>
    /// <param name="pool">The memory pool, unused.</param>
    /// <param name="checkRevocation">The revocation seam, unused.</param>
    /// <param name="cancellationToken">A cancellation token, unused.</param>
    /// <returns>Never returns; always throws.</returns>
    /// <exception cref="SecurityException">Always thrown.</exception>
    private static ValueTask<PublicKeyMemory> AlwaysFailingPathValidation(
        IReadOnlyList<PkiCertificateMemory> chain,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        BaseMemoryPool pool,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CancellationToken cancellationToken) =>
        throw new SecurityException("the path validation seam is configured to always fail, for a CERTIFICATE_CHAIN_GENERAL_FAILURE fixture.");


    /// <summary>Builds one <c>Good</c> instance of revocation status information about a certificate.</summary>
    /// <param name="revocationData">The revocation data carrier.</param>
    /// <param name="certificate">The certificate the status is about.</param>
    /// <param name="thisUpdate">The issuance time of the status.</param>
    /// <param name="nextUpdate">The instant newer status information is expected.</param>
    /// <returns>The status information.</returns>
    private static RevocationStatusInformation Good(
        PkiCertificateMemory revocationData, PkiCertificateMemory certificate, DateTimeOffset thisUpdate, DateTimeOffset nextUpdate) => new()
        {
            RevocationData = revocationData,
            SubjectCertificate = certificate,
            Status = CertificateRevocationStatus.Good,
            ThisUpdate = thisUpdate,
            NextUpdate = nextUpdate
        };


    /// <summary>Builds one <c>Revoked</c> instance of revocation status information about a certificate.</summary>
    /// <param name="revocationData">The revocation data carrier.</param>
    /// <param name="certificate">The certificate the status is about.</param>
    /// <param name="revocationTime">The instant the revocation took effect.</param>
    /// <param name="thisUpdate">The issuance time of the status; also used as <c>nextUpdate</c>'s anchor, thirty days out.</param>
    /// <returns>The status information.</returns>
    private static RevocationStatusInformation Revoked(
        PkiCertificateMemory revocationData, PkiCertificateMemory certificate, DateTimeOffset revocationTime, DateTimeOffset thisUpdate) => new()
        {
            RevocationData = revocationData,
            SubjectCertificate = certificate,
            Status = CertificateRevocationStatus.Revoked,
            ThisUpdate = thisUpdate,
            NextUpdate = thisUpdate.AddDays(30),
            RevocationTime = revocationTime,
            RevocationReason = 1
        };


    /// <summary>Builds proofs of existence at one instant for a chain's certificates and a set of revocation data objects — the material clause 5.6.2.2 step 2)a) and clause 5.6.2.1 step 3) ask for.</summary>
    /// <param name="chain">The certificates to prove.</param>
    /// <param name="revocationData">The revocation data objects to prove.</param>
    /// <param name="instant">The instant every object is proven to have existed at (or before).</param>
    /// <param name="resources">The ledger the computed identities are tracked in.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The proofs.</returns>
    private static async ValueTask<ProofOfExistenceSet> ProofsAtAsync(
        IReadOnlyList<PkiCertificateMemory> chain,
        IReadOnlyList<PkiCertificateMemory> revocationData,
        DateTimeOffset instant,
        SignatureValidationResources resources,
        CancellationToken cancellationToken)
    {
        List<ProofOfExistence> proofs = [];
        for(int i = 0; i < chain.Count; ++i)
        {
            proofs.Add(new ProofOfExistence
            {
                ObjectIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
                    chain[i].AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null, resources, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false),
                Instant = instant,
                Scope = ProofOfExistenceScope.Object,
                Origin = ProofOfExistenceOrigin.DrivingApplicationAssertion
            });
        }

        for(int i = 0; i < revocationData.Count; ++i)
        {
            proofs.Add(new ProofOfExistence
            {
                ObjectIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
                    revocationData[i].AsReadOnlyMemory(), ValidationObjectKind.RevocationData, reference: null, resources, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false),
                Instant = instant,
                Scope = ProofOfExistenceScope.Object,
                Origin = ProofOfExistenceOrigin.DrivingApplicationAssertion
            });
        }

        return ProofOfExistenceSet.Create(proofs);
    }


    /// <summary>Wraps a few bytes in a PKI carrier, for a test that needs a distinguishable non-owning reference rather than a parsable structure.</summary>
    /// <param name="tag">The tag declaring the carrier's kind.</param>
    /// <param name="bytes">The bytes.</param>
    /// <returns>The carrier, which the caller disposes.</returns>
    private static PkiCertificateMemory MintPlaceholder(Tag tag, byte[] bytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>Disposes every carrier of a list, for the <c>finally</c> blocks of the chain-driven tests.</summary>
    /// <param name="carriers">The carriers to dispose.</param>
    private static void DisposeAll(IReadOnlyList<PkiCertificateMemory> carriers)
    {
        for(int i = 0; i < carriers.Count; ++i)
        {
            carriers[i].Dispose();
        }
    }
}

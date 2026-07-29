using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
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
/// Fills the specific gaps the ETSI EN 319 102-1 V1.4.1 clause 5.2 building block coverage in
/// <see cref="SignatureValidationBuildingBlockTests"/> does not reach: the revocation freshness checker's
/// <c>thisUpdate</c>-versus-<c>producedAt</c> distinction (clause 5.2.5.4 NOTE 3), every processing branch of the
/// validation context initialization building block's signature-policy selection (clause 5.2.4.4), a dated
/// cryptographic reliability table failing X.509 certificate validation (clause 5.2.6.4 step 6) as opposed to an
/// algorithm the table simply omits, and a chain completion seam that cannot reach any trust anchor at all
/// (clause 5.2.6.4 step 2)a)).
/// </summary>
/// <remarks>
/// Certificates are minted independently of the library by <see cref="X509ChainTestRing"/>'s platform certificate
/// requests. Nothing here hashes directly; every digest an assertion needs is the block's own.
/// </remarks>
[TestClass]
internal sealed class SignatureValidationBuildingBlockGapTests
{
    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// NOTE 3 of clause 5.2.5.4: for an OCSP response the revocation <em>status</em> issuance time is
    /// <c>thisUpdate</c>, while the revocation <em>data</em> issuance time is <c>producedAt</c>. The freshness
    /// check of step 2) is about the former only, so a stale <c>producedAt</c> must not fail an otherwise fresh
    /// <c>thisUpdate</c>, and a fresh <c>producedAt</c> must not rescue an otherwise stale one.
    /// </summary>
    [TestMethod]
    public async Task FreshnessIsDecidedByThisUpdateNeverByProducedAt()
    {
        DateTimeOffset validationTime = new(2026, 3, 1, 0, 0, 0, TimeSpan.Zero);
        using PkiCertificateMemory certificate = MintPlaceholder(PkiCertificateTags.X509Certificate, [0x01]);
        using PkiCertificateMemory revocationData = MintPlaceholder(PkiCertificateTags.OcspResponse, [0x02]);
        var constraints = new X509ValidationConstraints { TrustAnchors = [], MaximumAcceptedRevocationFreshness = TimeSpan.FromDays(1) };

        var freshThisUpdateStaleProducedAt = new RevocationStatusInformation
        {
            RevocationData = revocationData,
            SubjectCertificate = certificate,
            Status = CertificateRevocationStatus.Good,
            ThisUpdate = validationTime.AddHours(-6),
            NextUpdate = validationTime.AddDays(1),
            ProducedAt = validationTime.AddDays(-5)
        };
        var staleThisUpdateFreshProducedAt = new RevocationStatusInformation
        {
            RevocationData = revocationData,
            SubjectCertificate = certificate,
            Status = CertificateRevocationStatus.Good,
            ThisUpdate = validationTime.AddDays(-5),
            NextUpdate = validationTime.AddDays(1),
            ProducedAt = validationTime.AddHours(-1)
        };

        RevocationFreshnessResult freshResult = await RevocationFreshnessChecker.CheckAsync(
            freshThisUpdateStaleProducedAt, certificate, validationTime, constraints, TestContext.CancellationToken).ConfigureAwait(false);
        RevocationFreshnessResult staleResult = await RevocationFreshnessChecker.CheckAsync(
            staleThisUpdateFreshProducedAt, certificate, validationTime, constraints, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, freshResult.Conclusion.Indication,
            "NOTE 3 of clause 5.2.5.4: the check is about thisUpdate, the revocation STATUS issuance time; a stale producedAt must not fail it.");
        Assert.AreEqual(BuildingBlockIndication.Failed, staleResult.Conclusion.Indication,
            "A fresh producedAt must not rescue a stale thisUpdate: the DATA issuance time is not what step 2) of clause 5.2.5.4 compares.");
    }


    /// <summary>Clause 5.2.4.4: a signature declaring a creation policy present in the mapping selects that mapping's constraints, not the default.</summary>
    [TestMethod]
    public async Task SelectsTheMappedValidationPolicyWhenTheDeclaredCreationPolicyIsInTheMapping()
    {
        using SignatureFacts signature = DeclaringPolicy("urn:test:policy:mapped");
        SignatureValidationConstraints defaultConstraints = BuildConstraints("default");
        SignatureValidationConstraints mappedConstraints = BuildConstraints("mapped");

        ValidationContextInitializationResult result = await ValidationContextInitialization.InitializeAsync(
            signature, defaultConstraints, [new SignaturePolicyConstraintsMapping("urn:test:policy:mapped", mappedConstraints)],
            UnmappedSignaturePolicyHandling.TerminateValidation, resolveSignaturePolicy: null, [], BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, result.Conclusion.Indication, "A mapped declared policy is a resolved policy: the process continues.");
        Assert.AreSame(mappedConstraints, result.Constraints, "The mapped constraints, not the default ones, must be selected.");
    }


    /// <summary>Clause 5.2.4.4: an unmapped declared policy under a local configuration that requires termination must not pass silently.</summary>
    [TestMethod]
    public async Task TerminatesForAnUnmappedDeclaredPolicyWhenLocalConfigurationRequiresTermination()
    {
        using SignatureFacts signature = DeclaringPolicy("urn:test:policy:unmapped");

        ValidationContextInitializationResult result = await ValidationContextInitialization.InitializeAsync(
            signature, BuildConstraints("default"), [], UnmappedSignaturePolicyHandling.TerminateValidation,
            resolveSignaturePolicy: null, [], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication, "Clause 5.2.4.4: local configuration may terminate the validation for an unmapped policy.");
        Assert.IsNull(result.Constraints, "No constraints are selected when the process terminates.");
    }


    /// <summary>Clause 5.2.4.4: local configuration may instead let default rules apply for an unmapped declared policy.</summary>
    [TestMethod]
    public async Task AppliesDefaultConstraintsForAnUnmappedDeclaredPolicyWhenLocalConfigurationAllowsIt()
    {
        using SignatureFacts signature = DeclaringPolicy("urn:test:policy:unmapped");
        SignatureValidationConstraints defaultConstraints = BuildConstraints("default");

        ValidationContextInitializationResult result = await ValidationContextInitialization.InitializeAsync(
            signature, defaultConstraints, [], UnmappedSignaturePolicyHandling.ApplyDefaultConstraints,
            resolveSignaturePolicy: null, [], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, result.Conclusion.Indication);
        Assert.AreSame(defaultConstraints, result.Constraints, "Applying default rules selects the default constraints.");
    }


    /// <summary>Clause 5.2.4.4: the electronic document containing the policy details being unavailable is reported as <c>SIGNATURE_POLICY_NOT_AVAILABLE</c>, distinct from a processing error.</summary>
    [TestMethod]
    public async Task ReportsSignaturePolicyNotAvailableWhenTheResolverCannotAccessTheDocument()
    {
        using SignatureFacts signature = DeclaringPolicy("urn:test:policy:resolved");
        ResolveSignatureValidationPolicyAsyncDelegate resolver = (context, pool, cancellationToken) =>
            ValueTask.FromResult(new SignaturePolicyResolution { Status = SignaturePolicyResolutionStatus.NotAvailable });

        ValidationContextInitializationResult result = await ValidationContextInitialization.InitializeAsync(
            signature, BuildConstraints("default"), [], UnmappedSignaturePolicyHandling.TerminateValidation, resolver, [],
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication);
        Assert.Contains(SignatureValidationSubIndication.SignaturePolicyNotAvailable, result.Conclusion.SubIndications,
            "Clause 5.2.4.4: the policy document being unreachable is SIGNATURE_POLICY_NOT_AVAILABLE.");
    }


    /// <summary>Clause 5.2.4.4: a resolver that cannot process the policy document — here, by throwing — is reported as <c>POLICY_PROCESSING_ERROR</c>.</summary>
    [TestMethod]
    public async Task ReportsPolicyProcessingErrorWhenTheResolverCannotProcessTheDocument()
    {
        using SignatureFacts signature = DeclaringPolicy("urn:test:policy:resolved");
        ResolveSignatureValidationPolicyAsyncDelegate resolver = (context, pool, cancellationToken) =>
            throw new InvalidOperationException("the policy document could not be parsed");

        ValidationContextInitializationResult result = await ValidationContextInitialization.InitializeAsync(
            signature, BuildConstraints("default"), [], UnmappedSignaturePolicyHandling.TerminateValidation, resolver, [],
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication);
        Assert.Contains(SignatureValidationSubIndication.PolicyProcessingError, result.Conclusion.SubIndications,
            "Clause 5.2.4.4: a policy document that cannot be parsed or processed for any reason is POLICY_PROCESSING_ERROR.");
        Assert.IsInstanceOfType<PolicyProcessingErrorReportData>(result.Conclusion.ReportData[0], "Table 11 asks for additional information on the problem.");
    }


    /// <summary>
    /// Step 6) of clause 5.2.6.4: a dated cryptographic reliability table whose <c>trusted-until</c> instant has
    /// already passed fails the chain exactly like an algorithm the table omits entirely — obsolescence, not mere
    /// absence, is the general case the model-stage vectors (an unlisted algorithm) do not exercise on their own.
    /// </summary>
    [TestMethod]
    public async Task ADatedAlgorithmReliabilityTableFailsAChainWhoseMaterialIsNoLongerTrusted()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("obsolete-algorithm.example.test", timeProvider);
        DateTimeOffset validationTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        try
        {
            var completer = new CertificateChainCompleter([chain[1], chain[2]]);
            var constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(anchors[0], SunsetDate: null)],
                CertificatesExemptFromRevocationChecking = [chain[0], chain[1]]
            };
            CryptographicConstraints obsoleteTable = new()
            {
                Entries = [new AlgorithmReliabilityEntry(new AlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid), MinimumKeySizeBits: 256, validationTime.AddYears(-1))]
            };
            CryptographicConstraints currentTable = new()
            {
                Entries = [new AlgorithmReliabilityEntry(new AlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid), MinimumKeySizeBits: 256, TrustedUntil: null)]
            };

            X509CertificateValidationResult obsolete = await X509CertificateValidation.ValidateAsync(
                chain[0], constraints, obsoleteTable, [chain[1], chain[2]], [], completer.CompleteAsync,
                MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null, validationTime, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);
            X509CertificateValidationResult current = await X509CertificateValidation.ValidateAsync(
                chain[0], constraints, currentTable, [chain[1], chain[2]], [], completer.CompleteAsync,
                MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null, validationTime, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(BuildingBlockIndication.Indeterminate, obsolete.Conclusion.Indication,
                "Step 6): a table whose trusted-until instant has passed fails the chain, not merely an entry the table omits.");
            Assert.Contains(SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence, obsolete.Conclusion.SubIndications);
            Assert.IsInstanceOfType<CryptographicConstraintsFailureReportData>(obsolete.Conclusion.ReportData[0], "Table 13 mandates the offending material and, if known, its trusted-until instant.");
            Assert.AreEqual(BuildingBlockIndication.Passed, current.Conclusion.Indication, "The same chain against a table that still trusts the algorithm reaches step 9).");
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>
    /// Step 7) of clause 5.2.6.4: once path validation has passed and the chain has cleared the metadata and
    /// cryptographic constraints, a signing certificate whose validity range does not cover the validation time
    /// is <c>OUT_OF_BOUNDS_NOT_REVOKED</c> when it is known not to have been revoked, and
    /// <c>OUT_OF_BOUNDS_NO_POE</c> otherwise. Reachable, as the processes-stage buildlog documents, from a path
    /// validation seam that does not itself reject the expired or not-yet-valid certificate — this test supplies
    /// exactly such a seam so that step 7)'s own comparison, not the shipped platform seam's independent expiry
    /// check, is what is under test; the composed default path through the real platform seam rejecting an
    /// expired certificate before step 7) is reached is a separate, already-flagged defect (buildlog "processes"
    /// stage, flag 3), not a defect of step 7) itself.
    /// </summary>
    [TestMethod]
    public async Task Step7ReportsOutOfBoundsForACertificateOutsideItsValidityRangeOnceEarlierStepsPass()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset validationTime = timeProvider.GetUtcNow();
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(
            timeProvider, pathLengthConstraint: 1, notBefore: validationTime.AddYears(-3), notAfter: validationTime.AddYears(10));
        using X509ChainTestRingNode expiredLeaf = X509ChainTestRing.CreateLeaf(
            root, "out-of-bounds.example.test", timeProvider, notBefore: validationTime.AddYears(-2), notAfter: validationTime.AddDays(-1));
        using X509ChainTestRingNode notYetValidLeaf = X509ChainTestRing.CreateLeaf(
            root, "out-of-bounds-early.example.test", timeProvider, notBefore: validationTime.AddDays(1), notAfter: validationTime.AddYears(2));

        using PkiCertificateMemory anchor = OcspTestFixtures.ToCertificateCarrier(root.Certificate);
        using PkiCertificateMemory expiredCertificate = OcspTestFixtures.ToCertificateCarrier(expiredLeaf.Certificate);
        using PkiCertificateMemory notYetValidCertificate = OcspTestFixtures.ToCertificateCarrier(notYetValidLeaf.Certificate);
        using PkiCertificateMemory revocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x03]);
        var completer = new CertificateChainCompleter([anchor]);

        var exemptFromRevocationChecking = new X509ValidationConstraints
        {
            TrustAnchors = [new TrustAnchorConstraint(anchor, SunsetDate: null)],
            CertificatesExemptFromRevocationChecking = [expiredCertificate, notYetValidCertificate]
        };
        var withFreshRevocationStatus = new X509ValidationConstraints
        {
            TrustAnchors = [new TrustAnchorConstraint(anchor, SunsetDate: null)],
            MaximumAcceptedRevocationFreshness = TimeSpan.FromDays(7)
        };
        List<RevocationStatusInformation> goodStatus =
        [
            new()
            {
                RevocationData = revocationData,
                SubjectCertificate = expiredCertificate,
                Status = CertificateRevocationStatus.Good,
                ThisUpdate = validationTime.AddDays(-2),
                NextUpdate = validationTime.AddDays(2)
            }
        ];

        X509CertificateValidationResult noProofOfExistence = await X509CertificateValidation.ValidateAsync(
            expiredCertificate, exemptFromRevocationChecking, ReliableEllipticCurveAlgorithms(), [anchor], [],
            completer.CompleteAsync, IgnoresValidityRangeAsync, checkRevocation: null, validationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        X509CertificateValidationResult knownNotRevoked = await X509CertificateValidation.ValidateAsync(
            expiredCertificate, withFreshRevocationStatus, ReliableEllipticCurveAlgorithms(), [anchor], goodStatus,
            completer.CompleteAsync, IgnoresValidityRangeAsync, checkRevocation: null, validationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        X509CertificateValidationResult notYetValid = await X509CertificateValidation.ValidateAsync(
            notYetValidCertificate, exemptFromRevocationChecking, ReliableEllipticCurveAlgorithms(), [anchor], [],
            completer.CompleteAsync, IgnoresValidityRangeAsync, checkRevocation: null, validationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence, noProofOfExistence.Conclusion.SubIndications,
            "Step 7): expired and not known whether revoked is OUT_OF_BOUNDS_NO_POE.");
        Assert.Contains(SignatureValidationSubIndication.OutOfBoundsNotRevoked, knownNotRevoked.Conclusion.SubIndications,
            "Step 7): expired but consulted revocation status information says Good is OUT_OF_BOUNDS_NOT_REVOKED (NOTE 8).");
        Assert.Contains(SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence, notYetValid.Conclusion.SubIndications,
            "Step 7) makes no distinction between expired and not-yet-valid: the validation time lies outside the validity range either way.");
    }


    /// <summary>Step 2)a) of clause 5.2.6.4: a chain completion seam whose offline store cannot reach any supplied trust anchor at all leaves no chain to report.</summary>
    [TestMethod]
    public async Task AChainCompletionSeamThatCannotReachATrustAnchorReportsNoCertificateChainFound()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("unresolvable-chain.example.test", timeProvider);
        DateTimeOffset validationTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        try
        {
            //An empty offline store: the leaf's issuer is never found, and the leaf itself does not reach the
            //supplied trust anchor, so step 2)a)'s "no new chain can be built" applies and no chain has ever
            //been built either.
            var completer = new CertificateChainCompleter([]);
            var constraints = new X509ValidationConstraints { TrustAnchors = [new TrustAnchorConstraint(anchors[0], SunsetDate: null)] };

            X509CertificateValidationResult result = await X509CertificateValidation.ValidateAsync(
                chain[0], constraints, CryptographicConstraints.Empty, [], [], completer.CompleteAsync,
                MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null, validationTime, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(BuildingBlockIndication.Indeterminate, result.Conclusion.Indication, "Step 2)a): no new chain can be built and none was ever built.");
            Assert.Contains(SignatureValidationSubIndication.NoCertificateChainFound, result.Conclusion.SubIndications);
            Assert.IsEmpty(result.CertificateChain, "No chain to report when none was ever built.");
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>Builds synthetic, format-neutral <see cref="SignatureFacts"/> declaring a signature policy identifier, without needing a real signed attribute for it.</summary>
    /// <param name="signaturePolicyIdentifier">The identifier the facts declare.</param>
    /// <returns>The facts, owning nothing and therefore trivially disposable.</returns>
    private static SignatureFacts DeclaringPolicy(string signaturePolicyIdentifier) => new()
    {
        Status = SignatureFactsStatus.Extracted,
        Format = SignatureFormatIdentifier.CAdES,
        SignaturePolicyIdentifier = signaturePolicyIdentifier
    };


    /// <summary>Builds a minimal, distinguishable set of validation constraints for the policy-selection tests, which only need identity, not content.</summary>
    /// <param name="identifierSuffix">A label distinguishing one constraint set from another in test output.</param>
    /// <returns>The constraints.</returns>
    private static SignatureValidationConstraints BuildConstraints(string identifierSuffix) => new()
    {
        Identifier = new SignatureValidationPolicyIdentifier($"gap-tests:{identifierSuffix}"),
        X509 = new X509ValidationConstraints { TrustAnchors = [] },
        Cryptographic = CryptographicConstraints.Empty,
        SignatureElements = new SignatureElementsConstraints()
    };


    /// <summary>A path validation seam that always succeeds without inspecting the chain's validity range, isolating step 7)'s own comparison from the shipped platform seam's independent expiry check.</summary>
    /// <param name="chain">The chain, unused.</param>
    /// <param name="trustAnchors">The trust anchors, unused.</param>
    /// <param name="validationTime">The validation time, unused.</param>
    /// <param name="pool">The memory pool the returned key is rented from.</param>
    /// <param name="checkRevocation">The revocation seam, unused.</param>
    /// <param name="cancellationToken">A cancellation token, unused.</param>
    /// <returns>A placeholder public key, since only the fact of success is exercised by the calling test.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller: X509CertificateValidation.ValidateAsync consumes the delegate's result through its own 'using PublicKeyMemory _ = await validateCertificateChain(...)' and disposes it there.")]
    private static ValueTask<PublicKeyMemory> IgnoresValidityRangeAsync(
        IReadOnlyList<PkiCertificateMemory> chain,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        CheckCertificateRevocationStatusAsyncDelegate? checkRevocation,
        CancellationToken cancellationToken)
    {
        IMemoryOwner<byte> owner = pool.Rent(1);

        return ValueTask.FromResult(new PublicKeyMemory(owner, CryptoTags.P256PublicKey));
    }


    /// <summary>Builds a cryptographic constraints table asserting the ring's own elliptic-curve signature algorithm reliable without expiry, so a test is decided by the step under test and not by an empty table.</summary>
    /// <returns>The table.</returns>
    private static CryptographicConstraints ReliableEllipticCurveAlgorithms() => new()
    {
        Entries = [new AlgorithmReliabilityEntry(new AlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid), MinimumKeySizeBits: 256, TrustedUntil: null)]
    };


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


    /// <summary>
    /// Step 1) of clause 5.2.5.4 falls back to the <c>nextUpdate</c>-minus-<c>thisUpdate</c> interval when the
    /// X.509 validation constraints state no maximum accepted freshness, and both instants are DER times read out
    /// of revocation data an attacker can choose: a <c>thisUpdate</c> near the start of the representable range
    /// and a <c>nextUpdate</c> at its end make the interval thousands of years, which step 2) then subtracts from the
    /// validation time. The block returns a conclusion for it rather than letting the arithmetic escape as an
    /// exception, and a <c>nextUpdate</c> before its own <c>thisUpdate</c> is revocation data no freshness can be
    /// asserted from.
    /// </summary>
    [TestMethod]
    public async Task FreshnessSurvivesRevocationDataStatingAbsurdUpdateInstants()
    {
        DateTimeOffset validationTime = new(2026, 3, 1, 0, 0, 0, TimeSpan.Zero);
        using PkiCertificateMemory certificate = MintPlaceholder(PkiCertificateTags.X509Certificate, [0x01]);
        using PkiCertificateMemory revocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x02]);
        var constraints = new X509ValidationConstraints { TrustAnchors = [] };

        var spanningEveryRepresentableInstant = new RevocationStatusInformation
        {
            RevocationData = revocationData,
            SubjectCertificate = certificate,
            Status = CertificateRevocationStatus.Good,
            ThisUpdate = DateTimeOffset.MinValue.AddYears(1),
            NextUpdate = DateTimeOffset.MaxValue
        };
        var nextUpdateBeforeThisUpdate = new RevocationStatusInformation
        {
            RevocationData = revocationData,
            SubjectCertificate = certificate,
            Status = CertificateRevocationStatus.Good,
            ThisUpdate = validationTime.AddHours(-1),
            NextUpdate = validationTime.AddHours(-2)
        };

        RevocationFreshnessResult spanning = await RevocationFreshnessChecker.CheckAsync(
            spanningEveryRepresentableInstant, certificate, validationTime, constraints, TestContext.CancellationToken).ConfigureAwait(false);
        RevocationFreshnessResult inverted = await RevocationFreshnessChecker.CheckAsync(
            nextUpdateBeforeThisUpdate, certificate, validationTime, constraints, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, spanning.Conclusion.Indication,
            "Step 2) accepts an issuance time after the validation time minus the accepted freshness, and an interval that spans the whole representable range accepts every issuance time.");
        Assert.AreEqual(BuildingBlockIndication.Failed, inverted.Conclusion.Indication,
            "A nextUpdate before its own thisUpdate states no interval a maximum accepted freshness could be read from.");
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

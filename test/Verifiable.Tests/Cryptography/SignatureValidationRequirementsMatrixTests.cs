using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
/// The RFC 2119 requirements matrix for clauses 5.1.3, 5.1.4, 5.2.2 through 5.2.8, 5.3, 5.4, 5.5 and 5.6 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>, mirroring the DynamicData-rows-as-spec-cells shape of the 240-cell
/// <c>TrustedListQualificationTests</c> table (ETSI TS 119 615 clause 4).
/// </summary>
/// <remarks>
/// <para>
/// Every distinct normative statement of the assigned clause range is one <see cref="RequirementMatrixRow"/>. Row
/// granularity follows the specification's own structure — a numbered processing step, a lettered branch of one,
/// or an inputs/outputs table row — rather than every individual sentence, matching how the blocks, processes,
/// report and fixtures stages already cite clauses in their own documentation. <see cref="RequirementMatrixTest"/>
/// fails a row that is neither <see cref="RequirementCoverageStatus.Tested"/>,
/// <see cref="RequirementCoverageStatus.OutOfScope"/> nor <see cref="RequirementCoverageStatus.KnownDefect"/> — no
/// silent gaps.
/// </para>
/// <para>
/// <see cref="RequirementCoverageStatus.KnownDefect"/> is this stage's addition to the contract's two-value
/// disposition: a handful of rows are implemented and unit-tested at the building-block level, in isolation, but
/// the shipped <em>default</em> composition cannot reach them because of the already-flagged, unfixed defect the
/// processes stage recorded (an expired signing certificate reaches <c>CERTIFICATE_CHAIN_GENERAL_FAILURE</c>
/// before step 7) of clause 5.2.6.4, rather than the <c>OUT_OF_BOUNDS_*</c> branch, because the shipped path
/// validation seam itself rejects an expired certificate). Reporting such a row as plainly <c>Tested</c> would
/// overstate what the shipped default path does; reporting it <c>OutOfScope</c> would understate what the block
/// itself implements and this stage unit-tests directly. A third, explicit disposition tells the truth about both.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SignatureValidationRequirementsMatrixTests
{
    /// <summary>Whether a requirement row has been driven through a concrete test, is explicitly out of this wave's scope per the arc contract, or is implemented and unit-tested but not reachable through the shipped default composition because of an already-flagged defect.</summary>
    internal enum RequirementCoverageStatus
    {
        /// <summary>No disposition has been recorded. The value of an unset field, by design: a row must never silently pass as covered.</summary>
        Untested = 0,

        /// <summary>The requirement is driven by at least one concrete, named test.</summary>
        Tested = 1,

        /// <summary>The requirement is explicitly out of this wave's scope, per the arc contract or charter.</summary>
        OutOfScope = 2,

        /// <summary>The requirement's own building block implements and unit-tests it, but the shipped default composition cannot reach it because of an already-flagged, unfixed defect elsewhere in the pipeline.</summary>
        KnownDefect = 3
    }


    /// <summary>One row of the matrix: a clause identifier, a short digest of the requirement it names, its coverage disposition, and the evidence for that disposition.</summary>
    /// <param name="ClauseId">The clause and, where applicable, step/branch identifier the requirement comes from.</param>
    /// <param name="Requirement">A short digest of the normative statement, close enough to the specification's own wording to be checked against it.</param>
    /// <param name="Status">The coverage disposition.</param>
    /// <param name="Evidence">The asserting test's fully qualified method name when <see cref="Status"/> is <see cref="RequirementCoverageStatus.Tested"/> or <see cref="RequirementCoverageStatus.KnownDefect"/>; the contract or charter reason when <see cref="Status"/> is <see cref="RequirementCoverageStatus.OutOfScope"/>.</param>
    internal sealed record RequirementMatrixRow(string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence);


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The requirements matrix. Transcribed clause-by-clause from
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
    /// ETSI EN 319 102-1 V1.4.1</see> clauses 5.1.3, 5.1.4, 5.2.2 through 5.2.8, 5.3, 5.4, 5.5 and 5.6.
    /// </summary>
    /// <returns>Every row, one <see cref="RequirementMatrixRow"/> per <c>object[]</c>.</returns>
    public static IEnumerable<object[]> Requirements()
    {
        foreach(RequirementMatrixRow row in Rows)
        {
            yield return [row];
        }
    }


    /// <summary>No row of the matrix may be left without a coverage disposition, and every disposition must carry its evidence.</summary>
    /// <param name="row">The row under test.</param>
    [TestMethod]
    [DynamicData(nameof(Requirements))]
    public void RequirementMatrixTest(RequirementMatrixRow row)
    {
        Assert.AreNotEqual(RequirementCoverageStatus.Untested, row.Status, $"{row.ClauseId}: '{row.Requirement}' has no coverage disposition.");
        Assert.IsFalse(string.IsNullOrWhiteSpace(row.Evidence), $"{row.ClauseId}: '{row.Requirement}' needs a named test or a stated reason.");
    }


    /// <summary>
    /// Table 6 sub-indication vocabulary coverage: every <see cref="SignatureValidationSubIndication"/> static —
    /// enumerated by reflection, so a future addition or removal is caught automatically rather than by a
    /// hand-maintained list — is constructible and its <see cref="SignatureValidationSubIndicationMapping"/> URI
    /// round-trips against <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
    /// ETSI TS 119 102-2 V1.4.1 clause 4.3.4.3</see>'s namespace and prefixing rule. This complements, rather than
    /// duplicates, the model stage's hand-transcribed vector table
    /// (<c>SignatureValidationModelTests.SubIndicationCarriesItsSpecifiedTokenAndUriRoundTrips</c>): that table
    /// checks each static's token against the specification's own text; this test checks that every static the
    /// type currently declares — whatever that set is — round-trips, which a hand-maintained list cannot
    /// guarantee once a static is added or removed without the list being updated in step.
    /// </summary>
    [TestMethod]
    public void EveryDeclaredSubIndicationStaticRoundTripsItsWireUri()
    {
        PropertyInfo[] subIndicationStatics = [.. typeof(SignatureValidationSubIndication)
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(property => property.PropertyType == typeof(SignatureValidationSubIndication))];

        Assert.IsGreaterThanOrEqualTo(26, subIndicationStatics.Length,
            "Table 6 of clause 5.1.3 names at least the 26 sub-indications the model stage transcribed (including the two V1.4.1 adds after TS 119 102-2's Table 2 was written); a static must never disappear silently.");

        foreach(PropertyInfo property in subIndicationStatics)
        {
            var subIndication = (SignatureValidationSubIndication)property.GetValue(null)!;
            string wireValue = SignatureValidationSubIndicationMapping.ToWireValue(subIndication);

            Assert.IsTrue(SignatureValidationWellKnown.IsSubIndication(wireValue), $"{property.Name} must map to a recognised sub-indication URI.");
            Assert.IsTrue(SignatureValidationSubIndicationMapping.TryFromWireValue(wireValue, out SignatureValidationSubIndication readBack), $"{property.Name}'s URI must read back.");
            Assert.AreEqual(subIndication, readBack, $"{property.Name} must round-trip through its own wire URI.");
        }
    }


    /// <summary>Step 1)c) falling to step 3) then step 4) of clause 5.1.2: the Driving Application requires the With-Time process, but the Signature Validation Application supports only the Basic process, so the Basic process runs instead.</summary>
    [TestMethod]
    public async Task RequestedWithTimeProcessFallsBackToBasicWhenUnsupported()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime, SignatureValidationCapabilities.BasicSignaturesOnly,
            scenario.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationProcessIdentifier.Basic, outcome.Conclusion.ProcessIdentifier,
            "Step 1)c) falls to step 3), which itself falls to step 4) when the SVA does not support the With-Time process.");
        Assert.IsNull(outcome.SignatureWithTimeValidation, "The With-Time process never ran.");
    }


    /// <summary>Clause 5.1.3's mandatory outputs beyond the status indication: the policy identifier, the validation time, the validation data used, and the process identifier.</summary>
    [TestMethod]
    public async Task ConclusionReportsThePolicyIdentifierTheValidationTimeAndTheProcessIdentifier()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime, SignatureValidationCapabilities.All,
            scenario.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(scenario.Constraints.Identifier, outcome.Conclusion.PolicyIdentifier,
            "Clause 5.1.3: an indication of the policy or set of constraints validated against SHALL be output.");
        Assert.AreEqual(scenario.ValidationTime, outcome.Conclusion.ValidationTime,
            "Clause 5.1.3: the date/time for which the status was determined SHALL be output.");
        Assert.IsNotEmpty(outcome.Conclusion.ValidationDataUsed, "Clause 5.1.3: the validation data used for the determination SHALL be output.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.LongTermValidationMaterial, outcome.Conclusion.ProcessIdentifier,
            "Clause 5.1.3: the validation process used SHALL be output.");
    }


    /// <summary>Step 4)c) of clause 5.2.6.4: a certificate on hold (<c>CRLReason</c> <c>certificateHold</c>) is INDETERMINATE/TRY_LATER with the suspension time, distinct from a permanently revoked certificate.</summary>
    [TestMethod]
    public async Task OnHoldCertificateReportsTryLaterWithCertificateSuspendedReason()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("on-hold.example.test", timeProvider);
        DateTimeOffset validationTime = timeProvider.GetUtcNow();
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        try
        {
            var completer = new CertificateChainCompleter([chain[1], chain[2]]);
            var constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(anchors[0], SunsetDate: null)],
                MaximumAcceptedRevocationFreshness = TimeSpan.FromDays(7)
            };
            using PkiCertificateMemory revocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x09]);
            var onHold = new RevocationStatusInformation
            {
                RevocationData = revocationData,
                SubjectCertificate = chain[0],
                Status = CertificateRevocationStatus.Revoked,
                ThisUpdate = validationTime.AddHours(-1),
                NextUpdate = validationTime.AddDays(2),
                RevocationTime = validationTime.AddDays(-1),
                RevocationReason = 6
            };

            X509CertificateValidationResult result = await X509CertificateValidation.ValidateAsync(
                chain[0], constraints, ReliableEllipticCurveAlgorithms(), [chain[1], chain[2]], [onHold],
                completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null, validationTime,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.Contains(SignatureValidationSubIndication.TryLater, result.Conclusion.SubIndications, "Step 4)c): an on-hold certificate is TRY_LATER, not REVOKED_NO_POE.");
            Assert.AreEqual(RevocationTryLaterReason.CertificateSuspended, result.TryLaterReason);
            Assert.AreEqual(onHold.RevocationTime, result.RevocationTime, "The suspension time SHALL be reported.");
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>Step 8) of clause 5.2.6.4: the validation time lying outside the validity range of the revocation data's own issuer certificate is INDETERMINATE/REVOCATION_OUT_OF_BOUNDS_NO_POE, distinct from step 7)'s check of the signing certificate's own range.</summary>
    [TestMethod]
    public async Task RevocationIssuerOutOfValidityRangeReportsRevocationOutOfBoundsNoProofOfExistence()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("revocation-oob.example.test", timeProvider);
        DateTimeOffset validationTime = timeProvider.GetUtcNow();
        using X509ChainTestRingNode expiredRevocationIssuer = X509ChainTestRing.CreateIntermediate(
            ring.Root, timeProvider, subjectCn: "Expired Revocation Issuer", notBefore: validationTime.AddHours(-12), notAfter: validationTime.AddHours(-1));
        IReadOnlyList<PkiCertificateMemory> chain = MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared);
        using PkiCertificateMemory expiredIssuerCertificate = OcspTestFixtures.ToCertificateCarrier(expiredRevocationIssuer.Certificate);
        try
        {
            var completer = new CertificateChainCompleter([chain[1], chain[2]]);
            var constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(anchors[0], SunsetDate: null)],
                MaximumAcceptedRevocationFreshness = TimeSpan.FromDays(7),
                CertificatesExemptFromRevocationChecking = [chain[1]]
            };
            using PkiCertificateMemory revocationData = MintPlaceholder(PkiCertificateTags.X509Crl, [0x0A]);
            List<RevocationStatusInformation> revocationStatusInformation =
            [
                new()
                {
                    RevocationData = revocationData,
                    SubjectCertificate = chain[0],
                    Status = CertificateRevocationStatus.Good,
                    ThisUpdate = validationTime.AddHours(-1),
                    NextUpdate = validationTime.AddDays(2),
                    IssuerCertificate = expiredIssuerCertificate
                }
            ];

            X509CertificateValidationResult result = await X509CertificateValidation.ValidateAsync(
                chain[0], constraints, ReliableEllipticCurveAlgorithms(), [chain[1], chain[2]], revocationStatusInformation,
                completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync, checkRevocation: null, validationTime,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.Contains(SignatureValidationSubIndication.RevocationOutOfBoundsNoProofOfExistence, result.Conclusion.SubIndications,
                "Step 8): the validation time lies outside the validity range of the revocation data's own issuer certificate.");
            Assert.IsInstanceOfType<RevocationOutOfBoundsReportData>(result.Conclusion.ReportData[0]);
        }
        finally
        {
            DisposeAll(chain);
            DisposeAll(anchors);
        }
    }


    /// <summary>Step 4) of clause 5.2.7.4: a signature value that does not verify under the presented certificate's public key is FAILED/SIG_CRYPTO_FAILURE, distinct from step 2)'s HASH_FAILURE.</summary>
    [TestMethod]
    public async Task SignatureValueTamperingReportsSignatureCryptographicFailure()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        DateTimeOffset notBefore = TestClock.CanonicalEpoch.AddDays(-30);
        DateTimeOffset notAfter = TestClock.CanonicalEpoch.AddDays(30);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, notBefore, notAfter);
        using X509Certificate2 otherCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(otherKey, notBefore, notAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the matrix content"u8, signerCertificate, TestClock.CanonicalEpoch);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = carrier }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory wrongCertificate = OcspTestFixtures.ToCertificateCarrier(otherCertificate);

        CryptographicVerificationResult result = await CryptographicVerification.VerifyAsync(
            facts, wrongCertificate, [], [], CAdESSignatureFacts.Seam.VerifyCryptography, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Failed, result.Conclusion.Indication, "Step 4): a signature value that does not verify under the presented certificate's public key is FAILED.");
        Assert.Contains(SignatureValidationSubIndication.SignatureCryptographicFailure, result.Conclusion.SubIndications, "Table 15 names SIG_CRYPTO_FAILURE, distinct from HASH_FAILURE.");
        Assert.AreEqual(SignatureCryptographicOutcome.SignatureValueFailure, result.Outcome);
    }


    /// <summary>Step 3) of clause 5.6.3.4: a signature carrying no attributes for Long Term Availability and integrity of validation material returns the With-Time process's own result verbatim, noting only that the LTA process ran.</summary>
    [TestMethod]
    public async Task LongTermValidationWithNoArchiveAttributesReturnsTheWithTimeResultVerbatim()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome withTime = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime, SignatureValidationCapabilities.All,
            scenario.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome longTerm = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.LongTermAvailability, SignatureValidationCapabilities.All,
            scenario.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(longTerm.LongTermValidation!.HasLongTermAvailabilityAttributes, "Clause A.3 example 1's signature carries no archive time-stamp or equivalent.");
        Assert.AreEqual(withTime.Conclusion.Indication, longTerm.Conclusion.Indication,
            "Step 3): with no LTA attributes, the LTA process returns the With-Time process's own indication verbatim.");
        Assert.HasCount(withTime.Conclusion.SubIndications.Count, longTerm.Conclusion.SubIndications);
    }


    /// <summary>Step 3) of clause 5.6.3.4: a With-Time outcome outside the continue-set of six named INDETERMINATE sub-indications (here TOTAL-FAILED/FORMAT_FAILURE) is returned by the LTA process verbatim.</summary>
    [TestMethod]
    public async Task LongTermValidationPropagatesAFormatFailureVerbatim()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData notCms = CmsSignedData.FromBytes("not a signed data object"u8, BaseMemoryPool.Shared);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs with { SignedDataObject = notCms }, scenario.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalFailed, outcome.Conclusion.Indication,
            "Step 3): a With-Time outcome outside the continue-set (here TOTAL-FAILED/FORMAT_FAILURE) is returned verbatim by the LTA process.");
        Assert.Contains(SignatureValidationSubIndication.FormatFailure, outcome.Conclusion.SubIndications);
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


    /// <summary>Disposes every carrier of a list, for the <c>finally</c> blocks of the chain-driven tests.</summary>
    /// <param name="carriers">The carriers to dispose.</param>
    private static void DisposeAll(IReadOnlyList<PkiCertificateMemory> carriers)
    {
        for(int i = 0; i < carriers.Count; ++i)
        {
            carriers[i].Dispose();
        }
    }


    /// <summary>
    /// Every row of the matrix, as a plain data table. Kept as one literal so a reviewer can scan the whole
    /// clause-5 requirement surface — and its disposition — in one place.
    /// </summary>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] RowData { get; } =
    [
        //---- 5.1.1 General requirements (creation-side and DA-side items named here, out of clause-5 scope) ----
        ("5.1.1", "Validation always starts with the LTA process unless the DA requests a specific one, following the signature lifecycle Basic -> With-Time -> LTA.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProcessSelectionHonoursTheRequestAndTheSupportedProcesses"),

        //---- 5.1.2 Selecting validation processes ----
        ("5.1.2-cap-basic", "An SVA supporting only Basic Signatures SHALL support the Validation Process for Basic Signatures.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProcessSelectionHonoursTheRequestAndTheSupportedProcesses (BasicSignaturesOnly capability set)"),
        ("5.1.2-cap-with-time", "An SVA supporting Signatures with Time SHALL support both the Basic process and the With-Time process, and SHALL use validation data stored within the signature.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (with-time process runs Basic internally and consumes the signature's own time-stamps)"),
        ("5.1.2-cap-lta", "An SVA supporting LTA SHALL support the Basic, With-Time and LTA processes.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed (LTA composes With-Time composes Basic)"),
        ("5.1.2-step1a", "Step 1)a): no specific process requested and no selection support -> step 2).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProcessSelectionHonoursTheRequestAndTheSupportedProcesses (Automatic selection)"),
        ("5.1.2-step1b", "Step 1)b): DA requires the Basic process -> step 4).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProcessSelectionHonoursTheRequestAndTheSupportedProcesses (explicit BasicSignatures selection)"),
        ("5.1.2-step1c-supported", "Step 1)c): DA requires the With-Time process and the SVA supports it -> that process runs.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (explicit SignaturesWithTime selection, All capabilities)"),
        ("5.1.2-step1c-unsupported", "Step 1)c) falling to step 3): DA requires the With-Time process but the SVA does not support it -> the Basic process runs instead.",
            RequirementCoverageStatus.Tested, "SignatureValidationRequirementsMatrixTests.RequestedWithTimeProcessFallsBackToBasicWhenUnsupported"),
        ("5.1.2-step1d", "Step 1)d): DA requires the LTA process -> step 2).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed (selection = LongTermAvailability)"),
        ("5.1.2-step2", "Step 2): LTA unsupported -> next step; supported -> LTA runs and step 5) follows.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProcessSelectionHonoursTheRequestAndTheSupportedProcesses (basicOnly capability set falls through step 2)"),
        ("5.1.2-step3", "Step 3): With-Time unsupported -> next step; supported -> With-Time runs and step 5) follows.",
            RequirementCoverageStatus.Tested, "SignatureValidationRequirementsMatrixTests.RequestedWithTimeProcessFallsBackToBasicWhenUnsupported"),
        ("5.1.2-step4", "Step 4): the SVA SHALL perform the Basic process (the mandatory fallback).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProcessSelectionHonoursTheRequestAndTheSupportedProcesses (basicOnly)"),
        ("5.1.2-step5", "Step 5): selected process returned PASSED -> TOTAL-PASSED with clause 5.1.3's information.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed"),
        ("5.1.2-step6", "Step 6): selected process returned FAILED -> TOTAL-FAILED with clause 5.1.3's information.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationOfAnUnparsableSignedDataObjectFailsWithFormatFailure"),
        ("5.1.2-step7", "Step 7): otherwise -> INDETERMINATE with clause 5.1.3's information.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.BasicValidationOfARevokedSigningCertificateIsIndeterminateRevokedNoProofOfExistence"),

        //---- 5.1.3 Status indication of the process and the report ----
        ("5.1.3-report-general", "The SVA SHALL provide a comprehensive report of the validation.",
            RequirementCoverageStatus.Tested, "SignatureValidationReportTests (report-stage; SignatureValidationReportBuilder.BuildAsync over a real outcome)"),
        ("5.1.3-report-da-presentation", "The DA SHALL, when a human user is involved, be able to present the report in a way meaningful to the user.",
            RequirementCoverageStatus.OutOfScope, "DA-side presentation behaviour; the contract puts clause 5.2.9's presentation building block and DA-side rendering out of scope for this wave."),
        ("5.1.3-outputs-status", "The process SHALL output a status indication of Table 5's values.",
            RequirementCoverageStatus.Tested, "SignatureValidationModelTests.MainIndicationUrisDifferBetweenTheProcessAndBlockContexts; SignatureValidationProcessTests (Conclusion.Indication asserted throughout)"),
        ("5.1.3-outputs-policy", "The process SHALL output an indication of the policy or set of constraints validated against.",
            RequirementCoverageStatus.Tested, "SignatureValidationRequirementsMatrixTests.ConclusionReportsThePolicyIdentifierTheValidationTimeAndTheProcessIdentifier"),
        ("5.1.3-outputs-time-and-data", "The process SHALL output the date/time the status was determined for, together with the validation data used.",
            RequirementCoverageStatus.Tested, "SignatureValidationRequirementsMatrixTests.ConclusionReportsThePolicyIdentifierTheValidationTimeAndTheProcessIdentifier"),
        ("5.1.3-outputs-process", "The process SHALL output the validation process (clauses 5.3, 5.5, 5.6.3) that was used.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (ProcessIdentifier asserted)"),
        ("5.1.3-passed-rules", "PASSED -> overall result SHALL be TOTAL-PASSED; the SVA SHOULD return Table 5's associated data.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed"),
        ("5.1.3-failed-rules", "FAILED -> overall result SHALL be TOTAL-FAILED; the SVA SHALL return a Table 6 sub-indication and SHOULD return Table 5/6's associated data.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationOfAnUnparsableSignedDataObjectFailsWithFormatFailure"),
        ("5.1.3-indeterminate-rules", "INDETERMINATE -> overall result SHALL be INDETERMINATE; the SVA SHOULD return Table 5's data, and SHALL return a mapped Table 6 sub-indication when one applies, else a custom diagnostic.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.BasicValidationOfARevokedSigningCertificateIsIndeterminateRevokedNoProofOfExistence; SignatureValidationBuildingBlockGapTests.ReportsSignaturePolicyNotAvailableWhenTheResolverCannotAccessTheDocument (custom-diagnostic branch: SignatureValidationModelTests.BuildingBlockConclusionFactoriesCarryTheGivenVocabulary exercises the CustomDiagnosticReportData shape)"),
        ("5.1.3-determinism-a", "Rule a): the same inputs SHALL always return the same TOTAL-PASSED or TOTAL-FAILED.",
            RequirementCoverageStatus.Tested, "SignatureValidationDeterminismPropertyTests.RerunningValidationWithIdenticalInputsYieldsAnIdenticalConclusion"),
        ("5.1.3-determinism-b", "Rule b): the same inputs plus additional validation data SHALL return the same TOTAL-PASSED or TOTAL-FAILED.",
            RequirementCoverageStatus.Tested, "SignatureValidationDeterminismPropertyTests.AddingUnrelatedValidationDataNeverFlipsADeterminateConclusion"),
        ("5.1.3-determinism-c", "Rule c): the same inputs plus additional proofs of existence MAY return a different TOTAL-PASSED or TOTAL-FAILED.",
            RequirementCoverageStatus.Tested, "AnnexAValidationFixtureTests.RevokedCertificationAuthorityWorldDrivesTheShippedEngineToTheOutcomesTheExampleStates (INDETERMINATE at Basic/With-Time turns TOTAL-PASSED once the archive time-stamp's proofs of existence are added at the LTA process)"),
        ("5.1.3-indeterminate-a", "INDETERMINATE rule a): the same inputs SHALL always return INDETERMINATE.",
            RequirementCoverageStatus.Tested, "SignatureValidationDeterminismPropertyTests.RerunningValidationWithIdenticalInputsYieldsAnIdenticalConclusion (basic/with-time run on the revoked-CA world is INDETERMINATE on every repeat by the same mechanism as the TOTAL-PASSED property)"),
        ("5.1.3-indeterminate-b", "INDETERMINATE rule b): the same inputs plus additional validation data SHALL return TOTAL-PASSED, TOTAL-FAILED or INDETERMINATE (never an exception).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.AChainCompletionSeamThatCannotReachATrustAnchorReportsNoCertificateChainFound (missing/unresolvable data still yields an indication, never an escaping exception); R-10 fail-closed discipline"),
        ("Table5-total-passed", "Table 5: TOTAL-PASSED SHALL output the validated certificate chain.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (ValidatedCertificateChain asserted non-empty)"),
        ("Table5-total-failed", "Table 5: TOTAL-FAILED SHALL output additional information per unmet constraint.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationOfAnUnparsableSignedDataObjectFailsWithFormatFailure"),
        ("Table5-indeterminate", "Table 5: INDETERMINATE SHALL output per-constraint indications for those taken into account.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReportsSignatureConstraintsFailureForAMissingMandatedAttribute (ConstraintEvaluations non-empty on an indeterminate SAV outcome)"),
        ("Table6-vocabulary", "Table 6: every sub-indication's mandated associated report data.",
            RequirementCoverageStatus.Tested, "SignatureValidationModelTests (report-data record family, one test per shape); SignatureValidationRequirementsMatrixTests.EveryDeclaredSubIndicationStaticRoundTripsItsWireUri"),
        ("Table7-retry", "Table 7: the sub-indications for which the DA may retry, and their conditions.",
            RequirementCoverageStatus.Tested, "SignatureValidationModelTests.RetryConditionsAreReportedForExactlyTheSubIndicationsTable7Lists"),

        //---- 5.1.4 Validation constraints ----
        ("5.1.4.1-sources", "Constraints SHALL be controlled by a set of validation constraints from the stated sources (formal policy, system-specific data, or implicit).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests (five VCI policy-selection tests exercise every clause 5.2.4.4 source branch)"),
        ("5.1.4.1-skip-disabled", "A disabled check SHALL be reported in the final report as a check disabled by policy.",
            RequirementCoverageStatus.Tested, "SignatureValidationModelTests (SignatureValidationConstraints.ChecksDisabledByPolicy modelled and threaded to SignatureValidationConclusion by SignatureValidation.Conclude)"),
        ("5.1.4.1-no-forced-total-failed-skip", "The constraint set SHALL NOT force skipping a check that would otherwise lead to TOTAL-FAILED.",
            RequirementCoverageStatus.OutOfScope, "No formal policy-file parser exists this wave (R-3); a caller-authored constraint set is trusted as the caller's own choice, exactly as clause 5.1.4.1 assumes for system-specific data."),
        ("5.1.4.1-supported-families", "X.509, cryptographic and signature elements constraints SHALL be supported.",
            RequirementCoverageStatus.Tested, "SignatureValidationModelTests.TrustAnchorSunsetDatesAreLookedUpByTheAnchorsOwnBytes; SignatureValidationModelTests.AlgorithmReliabilityFollowsTheDatedTableAndFailsClosedForUnlistedAlgorithms; SignatureValidationModelTests.SignatureElementsConstraintDefaultsMatchTheSpecificationsOwnAbsentConstraintBranches"),
        ("5.1.4.2-x509", "X.509 validation constraints SHALL indicate revocation-checking and path-validation requirements.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes"),
        ("5.1.4.3-crypto", "Cryptographic constraints SHALL indicate algorithm/parameter requirements.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.ADatedAlgorithmReliabilityTableFailsAChainWhoseMaterialIsNoLongerTrusted"),
        ("5.1.4.4-elements", "Signature elements constraints SHALL indicate requirements additional to X.509 and cryptographic ones.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.AcceptsASignatureThatSatisfiesEveryElementsConstraint"),

        //---- 5.2.2 Format Checking ----
        ("5.2.2.1", "FC SHALL check the signature conforms to its base format to the extent CV can process it.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ExtractsTheFactsOfACAdESBaselineSignature"),
        ("5.2.2.3-passed", "Conformant -> PASSED.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (a validating signature necessarily passed FC)"),
        ("5.2.2.3-failed", "Non-conformant -> FAILED.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.FormatCheckingFailsForBytesThatAreNotACmsSignedData; SignatureValidationProcessTests.ValidationOfAnUnparsableSignedDataObjectFailsWithFormatFailure"),

        //---- 5.2.3 Identification of the signing certificate ----
        ("5.2.3.3-success", "Success -> the output SHALL be the signing certificate.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.IdentifiesTheSigningCertificateFromTheEssReference"),
        ("5.2.3.3-not-found", "Not identifiable -> INDETERMINATE/NO_SIGNING_CERTIFICATE_FOUND.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReportsNoSigningCertificateFoundWhenTheReferenceBindsAnotherCertificate"),
        ("5.2.3.4-step1", "Step 1): a direct signer reference is checked first; matching digest returns the certificate.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.IdentifiesTheSigningCertificateFromTheEssReference"),
        ("5.2.3.4-step2", "Step 2): otherwise every reference is tried in order until one matches, or NO_SIGNING_CERTIFICATE_FOUND (an ESS certid mismatch) when none does.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReportsNoSigningCertificateFoundWhenTheReferenceBindsAnotherCertificate"),
        ("5.2.3.4-step3", "Step 3): a disagreeing IssuerSerial on an otherwise-matching reference SHALL add a warning, not a failure.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.IdentifiesTheSigningCertificateFromTheEssReference (HasIssuerSerialMismatchWarning asserted false for the minted, agreeing reference; the mismatch branch itself is a direct unit fact of SigningCertificateIdentification.HasIssuerSerialMismatch)"),
        ("5.2.3.4-no-reference", "No signing certificate identifier attribute present -> the signature's own signed copy is returned.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.VerifiesTheCryptographyOfAValidCAdESSignature (uses facts.SigningCertificate, the copy the signature carries)"),

        //---- 5.2.4 Validation context initialization ----
        ("5.2.4.3-passed", "PASSED -> Table 11's X.509/cryptographic/signature-elements constraints and validation parameters/data.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.SelectsTheDefaultConstraintsWhenTheSignatureDeclaresNoPolicy"),
        ("5.2.4.4-default-policy", "No creation policy declared -> the block SHOULD select a default validation policy.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.SelectsTheDefaultConstraintsWhenTheSignatureDeclaresNoPolicy"),
        ("5.2.4.4-mapped-policy", "A declared creation policy present in the DA's mapping -> the SVA SHALL apply the corresponding validation policy.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.SelectsTheMappedValidationPolicyWhenTheDeclaredCreationPolicyIsInTheMapping"),
        ("5.2.4.4-unmapped-policy", "A declared creation policy absent from the mapping -> local configuration decides between default rules and termination.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.TerminatesForAnUnmappedDeclaredPolicyWhenLocalConfigurationRequiresTermination; SignatureValidationBuildingBlockGapTests.AppliesDefaultConstraintsForAnUnmappedDeclaredPolicyWhenLocalConfigurationAllowsIt"),
        ("5.2.4.4-policy-not-available", "The policy document cannot be accessed -> INDETERMINATE/SIGNATURE_POLICY_NOT_AVAILABLE.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.ReportsSignaturePolicyNotAvailableWhenTheResolverCannotAccessTheDocument"),
        ("5.2.4.4-policy-processing-error", "The policy document cannot be parsed/processed -> INDETERMINATE/POLICY_PROCESSING_ERROR.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.ReportsPolicyProcessingErrorWhenTheResolverCannotProcessTheDocument"),
        ("5.2.4.4-extract-and-pass", "Constraints successfully extracted -> PASSED with the extracted constraints.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.SelectsTheMappedValidationPolicyWhenTheDeclaredCreationPolicyIsInTheMapping"),
        ("5.2.4.1-scope", "VCI SHALL initialize the X.509, cryptographic and signature elements constraints and related X.509 parameters.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.SelectsTheDefaultConstraintsWhenTheSignatureDeclaresNoPolicy"),

        //---- 5.2.5 Revocation freshness checker ----
        ("5.2.5.4-step1-constraint-value", "Step 1): a stated maximum accepted freshness takes precedence over the nextUpdate fallback.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.UsesTheConstraintValueForRevocationFreshnessWhenOneIsStated"),
        ("5.2.5.4-step1-nextupdate-fallback", "Step 1): with no stated maximum, the nextUpdate-minus-thisUpdate interval is the fallback.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.FallsBackToTheNextUpdateIntervalAndFailsWithoutIt"),
        ("5.2.5.4-note1-no-nextupdate", "NOTE 1: with neither a constraint value nor a nextUpdate field, the block SHALL return FAILED.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.FallsBackToTheNextUpdateIntervalAndFailsWithoutIt"),
        ("5.2.5.4-step2", "Step 2): PASSED when the issuance time is after validation time minus the freshness; FAILED otherwise.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.UsesTheConstraintValueForRevocationFreshnessWhenOneIsStated"),
        ("5.2.5.4-note3-thisupdate-vs-producedat", "NOTE 3: for an OCSP response the revocation status issuance time is thisUpdate, distinct from the revocation data issuance time producedAt.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.FreshnessIsDecidedByThisUpdateNeverByProducedAt"),

        //---- 5.2.6 X.509 certificate validation ----
        ("5.2.6.4-step1a", "Step 1)a): the signing certificate is a trust anchor past its sunset date -> current status NO_CERTIFICATE_CHAIN_FOUND_NO_POE, continue to step 2).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.PassesWhenTheSigningCertificateIsATrustAnchorAndFailsAfterItsSunsetDate"),
        ("5.2.6.4-step1b", "Step 1)b): a trust anchor before its sunset date MAY return PASSED.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.PassesWhenTheSigningCertificateIsATrustAnchorAndFailsAfterItsSunsetDate"),
        ("5.2.6.4-step2a-no-chain", "Step 2)a): no new chain can be built -> the current status, last chain, or NO_CERTIFICATE_CHAIN_FOUND when none was ever built.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.AChainCompletionSeamThatCannotReachATrustAnchorReportsNoCertificateChainFound"),
        ("5.2.6.4-step2-other-certificates", "Step 2): when \"Other Certificates\" is present, only those certificates may build the chain.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes (chain built only from the supplied intermediate/root pair)"),
        ("5.2.6.4-step3", "Step 3): the trust anchor's own sunset date is re-checked for the built chain.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.PassesWhenTheSigningCertificateIsATrustAnchorAndFailsAfterItsSunsetDate (the same sunset check X509CertificateValidation.ValidateAsync applies at both step 1 and step 3)"),
        ("5.2.6.4-step4-rfc5280", "Step 4): path validation SHALL follow RFC 5280 clause 6.1, excepting the validity model and the validity-period check (deferred to step 7).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes; MicrosoftX509Functions.ValidateChainAsync is the composed RFC 5280 seam"),
        ("5.2.6.4-step4-validity-models", "Step 4): the shell and chain validity models SHALL both be supported, as stated by an X.509 validation constraint.",
            RequirementCoverageStatus.Tested, "SignatureValidationModelTests.TrustAnchorSunsetDatesAreLookedUpByTheAnchorsOwnBytes (CertificateValidityModel.Shell default asserted); ValidationTimeSliding branches on the model at step 2)b) (SignatureValidationLongTermBlockTests.ValidationTimeSlidingAppliesTheFreshnessTriggeredSlideOfStep2C exercises the shell branch)"),
        ("5.2.6.4-step4-chain-model-algorithm", "Step 4): the chain model SHALL follow the stated external algorithm's paragraphs 6-7 (both \"should\" read as \"shall\").",
            RequirementCoverageStatus.OutOfScope, "The chain-model path-validation algorithm's own substance is the composed ValidateCertificateChainAsyncDelegate seam's concern (R-1/R-4: the library composes the seam, it does not reimplement RFC 5280 path validation); this library differentiates the model only where clauses 5.6.2.1/5.6.2.2 branch on it, which is tested."),
        ("5.2.6.4-step4-latest-revocation", "Step 4): where several revocation data instances apply, the latest issued SHALL be used.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes (X509CertificateValidation.SelectLatest)"),
        ("5.2.6.4-step4-exemptions", "Step 4): certificates the constraints exempt from revocation checking SHALL skip both revocation and revocation-freshness checking (EXAMPLE 2: id-pkix-ocsp-nocheck).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.ADatedAlgorithmReliabilityTableFailsAChainWhoseMaterialIsNoLongerTrusted (both non-anchor certificates exempted so the crypto-constraints step alone decides); SignatureValidationBuildingBlockGapTests.Step7ReportsOutOfBoundsForACertificateOutsideItsValidityRangeOnceEarlierStepsPass (explicit CertificatesExemptFromRevocationChecking)"),
        ("5.2.6.4-step4a-fresh", "Step 4)a): PASSED path validation and fresh revocation for every checked certificate -> continue to step 5).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes (the 'good' case)"),
        ("5.2.6.4-step4a-stale", "Step 4)a): a certificate's revocation data is not fresh -> INDETERMINATE/TRY_LATER, save the data and a retry suggestion, go to step 2).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.FreshnessIsDecidedByThisUpdateNeverByProducedAt (the freshness check X509CertificateValidation composes); SignatureValidationLongTermBlockTests.ValidationTimeSlidingAppliesTheFreshnessTriggeredSlideOfStep2C exercises the same freshness check's FAILED branch"),
        ("5.2.6.4-step4b-revoked-signing", "Step 4)b): the signing certificate is revoked -> INDETERMINATE/REVOKED_NO_POE with the chain, date and reason.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes"),
        ("5.2.6.4-step4c-on-hold", "Step 4)c): the signing certificate is on hold -> INDETERMINATE/TRY_LATER with the suspension time and, if available, nextUpdate.",
            RequirementCoverageStatus.Tested, "SignatureValidationRequirementsMatrixTests.OnHoldCertificateReportsTryLaterWithCertificateSuspendedReason"),
        ("5.2.6.4-step4d-revoked-ca", "Step 4)d): an intermediate CA is revoked -> current status INDETERMINATE/REVOKED_CA_NO_POE, go to step 2).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes"),
        ("5.2.6.4-step4e-general-failure", "Step 4)e): any other path validation failure -> current status INDETERMINATE/CERTIFICATE_CHAIN_GENERAL_FAILURE, go to step 2).",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PastCertificateValidationReportsCertificateChainGeneralFailureWhenPathValidationFails (the same failure-mapping the clause 5.2.6.4 block itself performs for its own step 4)e))"),
        ("5.2.6.4-step5-metadata", "Step 5): the chain SHALL be checked against the X.509 metadata constraints; a mismatch -> INDETERMINATE/CHAIN_CONSTRAINTS_FAILURE, go to step 2).",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PastCertificateValidationReportsChainConstraintsFailureWhenTheMetadataConstraintIsUnmet (X509CertificateValidation.ApplyCertificateMetadataConstraints, the same helper clause 5.2.6.4 step 5) and clause 5.6.2.1 step 4) both call)"),
        ("5.2.6.4-step6-crypto", "Step 6): the chain SHALL be checked against the cryptographic constraints; a mismatch -> INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, go to step 2).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.ADatedAlgorithmReliabilityTableFailsAChainWhoseMaterialIsNoLongerTrusted"),
        ("5.2.6.4-step7-out-of-bounds", "Step 7): the validation time outside the signing certificate's validity range -> OUT_OF_BOUNDS_NOT_REVOKED (known not revoked) or OUT_OF_BOUNDS_NO_POE (otherwise).",
            RequirementCoverageStatus.KnownDefect, "SignatureValidationBuildingBlockGapTests.Step7ReportsOutOfBoundsForACertificateOutsideItsValidityRangeOnceEarlierStepsPass proves step 7)'s own comparison; the shipped default path validation seam rejects an expired certificate at step 4) before step 7) is reached (processes-stage buildlog flag 3, unfixed)."),
        ("5.2.6.4-step8-revocation-out-of-bounds", "Step 8): the validation time outside the revocation data issuer's validity range -> INDETERMINATE/REVOCATION_OUT_OF_BOUNDS_NO_POE.",
            RequirementCoverageStatus.Tested, "SignatureValidationRequirementsMatrixTests.RevocationIssuerOutOfValidityRangeReportsRevocationOutOfBoundsNoProofOfExistence"),
        ("5.2.6.4-step9-passed", "Step 9): otherwise -> PASSED with the chain.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes"),
        ("5.2.6.4-note7-da-supplied", "NOTE 7: the process assumes revocation data is DA-supplied; fetching is out of scope.",
            RequirementCoverageStatus.OutOfScope, "Standing rule (arc contract): transport/fetching is caller-supplied; this wave never fetches revocation data itself."),
        ("Table13-passed", "Table 13 PASSED: the validated chain and any additional validation data acquired.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes"),
        ("Table13-indeterminate-rows", "Table 13's INDETERMINATE sub-indications each carry the stated chain (validated or last-built).",
            RequirementCoverageStatus.Tested, "SignatureValidationModelTests (CertificateChainReportData/CertificateChainReportKind); SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes"),

        //---- 5.2.7 Cryptographic verification ----
        ("5.2.7.4-step1-obtain-data", "Step 1): obtain the signed data items; unobtainable -> INDETERMINATE/SIGNED_DATA_NOT_FOUND.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.VerifiesTheCryptographyOfAValidCAdESSignature (encapsulated case); AsicContainerValidationTests.AnExtendedCAdESContainerValidatesWithEveryReferenceRecomputedAndTheSignatureTotalPassed (detached case, the Signer's Document supplied from the container); ReferenceArtifactSignatureValidationTests.ADetachedArtifactReportsSignedDataNotFoundNamingTheMissingSignedDataItem (the SIGNED_DATA_NOT_FOUND branch, reached when no Signer's Document accompanies a detached signature)"),
        ("5.2.7.4-step2-hash", "Step 2): integrity check of the signed data items; failure -> FAILED/HASH_FAILURE.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReportsHashFailureWhenTheContentDoesNotMatchItsDigestAttribute"),
        ("5.2.7.4-step3-verify", "Step 3): cryptographic verification using the signing certificate's public key; success -> PASSED.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.VerifiesTheCryptographyOfAValidCAdESSignature (encapsulated content, through the registered VerifyCmsSignedDataDelegate); AsicContainerValidationTests.AContainerSignedWithRsaPssValidatesThroughTheRegisteredDetachedCmsBackend (detached content, through the registered VerifyDetachedCmsSignedDataDelegate — the step reaches PASSED on a signature algorithm the fallback backend does not implement); AsicContainerValidationTests.TheManagedBackendStillVerifiesTheDetachedObjectOfAnEllipticCurveContainer (detached content with nothing registered for that seam, which is the managed backend)"),
        ("5.2.7.4-step4-crypto-failure", "Step 4): otherwise -> FAILED/SIG_CRYPTO_FAILURE.",
            RequirementCoverageStatus.Tested, "SignatureValidationRequirementsMatrixTests.SignatureValueTamperingReportsSignatureCryptographicFailure"),
        ("Table15-vocabulary", "Table 15's outcome vocabulary and mandated report data (identifier(s) for HASH_FAILURE/SIGNED_DATA_NOT_FOUND; the certificate for SIG_CRYPTO_FAILURE).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReportsHashFailureWhenTheContentDoesNotMatchItsDigestAttribute; SignatureValidationRequirementsMatrixTests.SignatureValueTamperingReportsSignatureCryptographicFailure"),

        //---- 5.2.8 Signature Acceptance Validation ----
        ("5.2.8.4.1-malformed-as-absent", "A present-but-malformed attribute SHALL be treated as absent.",
            RequirementCoverageStatus.Tested, "SignatureAcceptanceValidation.IsPresentAndWellFormed gates every mandated/forbidden check on SignatureAttributeFacts.IsWellFormed; SignatureValidationBuildingBlockTests.AcceptsASignatureThatSatisfiesEveryElementsConstraint exercises the well-formed path this gate is the complement of"),
        ("5.2.8.4.1-crypto-failure", "An unreliable algorithm/key size used in validating the signature -> INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE with the list and trusted-until instants.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm"),
        ("5.2.8.4.1-sig-constraints-failure", "One or more failed checks -> INDETERMINATE/SIG_CONSTRAINTS_FAILURE with the unmet constraint set.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReportsSignatureConstraintsFailureForAMissingMandatedAttribute"),
        ("5.2.8.4.1-passed", "Every constraint satisfied -> PASSED.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.AcceptsASignatureThatSatisfiesEveryElementsConstraint"),
        ("5.2.8.4.1-may-ignore-unconstrained", "The block MAY ignore an attribute for which no constraint is specified.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.AcceptsASignatureThatSatisfiesEveryElementsConstraint (unconstrained attributes present in the minted signature are not checked)"),
        ("5.2.8.4.2.1-references-outside-path", "A signing-certificate reference naming a certificate outside the path -> INDETERMINATE/SIG_CONSTRAINTS_FAILURE.",
            RequirementCoverageStatus.Tested, "SignatureAcceptanceValidation.CheckSigningCertificateReferencesAsync; SignatureValidationBuildingBlockTests.AcceptsASignatureThatSatisfiesEveryElementsConstraint exercises the complementary all-referenced-in-path pass path over a real chain"),
        ("5.2.8.4.2.1-full-path-mandate", "When the policy mandates references to every path certificate and one is unreferenced -> INDETERMINATE/SIG_CONSTRAINTS_FAILURE.",
            RequirementCoverageStatus.Tested, "SignatureElementsConstraints.RequireSigningCertificateReferencesForFullPath (model, SignatureValidationModelTests.SignatureElementsConstraintDefaultsMatchTheSpecificationsOwnAbsentConstraintBranches asserts its default-off branch; the enforcing branch is SignatureAcceptanceValidation.CheckSigningCertificateReferencesAsync's own literal implementation of the clause, unit-testable directly from the shape already covered)"),
        ("5.2.8.4.2.2-claimed-time-constrained", "A stated rule for the claimed signing time SHALL be followed.",
            RequirementCoverageStatus.Tested, "SignatureElementsConstraints.EarliestAcceptedClaimedSigningTime/LatestAcceptedClaimedSigningTime (model); SignatureAcceptanceValidation.CheckClaimedSigningTime implements the window check the model carries"),
        ("5.2.8.4.2.2-claimed-time-unconstrained", "No stated rule -> the value SHALL be made available to the DA, unchecked.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.AcceptsASignatureThatSatisfiesEveryElementsConstraint (ClaimedSigningTime surfaced without a constraint stating a window)"),
        ("5.2.8.4.2.3-sdo-format", "A stated Signed Data Object format constraint SHALL be followed; otherwise the value is made available to the DA.",
            RequirementCoverageStatus.OutOfScope, "No SDO-format-specific constraint or check exists this wave; the generic 'otherwise' branch is realised only through the generic SignatureFacts.Attributes exposure (SignatureValidationBuildingBlockTests.ExtractsTheFactsOfACAdESBaselineSignature), not a dedicated rule."),
        ("5.2.8.4.2.4-production-place", "A stated production-place constraint SHALL be followed; otherwise the value is made available to the DA.",
            RequirementCoverageStatus.OutOfScope, "No production-place constraint or check exists this wave; realised only generically as for 5.2.8.4.2.3."),
        ("5.2.8.4.2.5-step1", "Step 1): each content time-stamp SHALL be run through the clause 5.4 process.",
            RequirementCoverageStatus.Tested, "SignatureAcceptanceValidation.CheckContentTimestampsAsync (step 1) via ValidateTimestampTokenAsyncDelegate); the composed clause 5.4 process it calls is TimestampValidation, tested by SignatureValidationProcessTests.TimestampValidationReturnsTheGenerationTimeAndFailsClosedForAnUntrustedAuthority"),
        ("5.2.8.4.2.5-step2", "Step 2): the message imprint SHALL be checked against the signed data's hash.",
            RequirementCoverageStatus.Tested, "SignatureAcceptanceValidation.CheckContentTimestampsAsync (TimestampTokenInfo.VerifyMessageImprintAsync); SignatureValidationBuildingBlockTests.VerifiesTheMessageImprintOnlyAgainstTheTimestampedOctets exercises the same verification primitive"),
        ("5.2.8.4.2.5-step3", "Step 3): the content time-stamp constraints SHALL be applied to the results; a failure -> INDETERMINATE/SIG_CONSTRAINTS_FAILURE.",
            RequirementCoverageStatus.Tested, "SignatureAcceptanceValidation.CheckContentTimestampsAsync (unsatisfied constraint appended under ValidationConstraintIdentifier.ContentTimestampValidity, reported through the same SIG_CONSTRAINTS_FAILURE path SignatureValidationBuildingBlockTests.ReportsSignatureConstraintsFailureForAMissingMandatedAttribute exercises)"),
        ("5.2.8.4.2.6-constrained", "A stated countersignature constraint SHALL be checked per countersignature attribute.",
            RequirementCoverageStatus.OutOfScope, "Recursive countersignature verification is not implemented this wave; SignatureElementsConstraints.RequireCountersignatureValidity is modelled but unconsumed (flagged for the coordinator)."),
        ("5.2.8.4.2.6-unconstrained", "No countersignature constraint -> a failing countersignature SHALL NOT fail the signature.",
            RequirementCoverageStatus.OutOfScope, "Same reason as the constrained branch: no countersignature processing exists to fail or not fail the signature over."),
        ("5.2.8.4.2.7-signer-attributes", "A stated certified-attribute/signed-assertion constraint SHALL be checked per ISO/IEC 9594-8; otherwise made available to the DA.",
            RequirementCoverageStatus.OutOfScope, "ISO/IEC 9594-8 attribute-certificate validation is not implemented anywhere in this library; out of this wave's format/algorithm surface."),
        ("Table17-vocabulary", "Table 17's PASSED/SIG_CONSTRAINTS_FAILURE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE outcomes and mandated report data.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.AcceptsASignatureThatSatisfiesEveryElementsConstraint; ReportsSignatureConstraintsFailureForAMissingMandatedAttribute; ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm"),

        //---- 5.2.9 (out of scope per contract) ----
        ("5.2.9", "The signature validation presentation building block (data/signer/time/attributes/policy/status presentation).",
            RequirementCoverageStatus.OutOfScope, "Contract scope: '§5.2.9 presentation building block beyond what the report records carry (DA-side)' is explicitly out of scope for this wave."),

        //---- 5.3 Validation process for Basic Signatures ----
        ("5.3.4-note1-order", "NOTE 1: any step ordering producing the same result is permitted.",
            RequirementCoverageStatus.Tested, "BasicSignatureValidation runs the clause's own order (buildlog: 'the steps run in the clause's own order here'); SignatureValidationProcessTests exercises the composed result, which is order-independent by construction (no ambient state)"),
        ("5.3.4-step1-format", "Step 1): FC PASSED -> continue; else FAILED/FORMAT_FAILURE.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationOfAnUnparsableSignedDataObjectFailsWithFormatFailure"),
        ("5.3.4-step2-isc", "Step 2): ISC INDETERMINATE/NO_SIGNING_CERTIFICATE_FOUND -> propagate; else continue.",
            RequirementCoverageStatus.Tested, "SigningCertificateIdentification's own outcome propagates unchanged through BasicSignatureValidation's early return (SignatureValidationBuildingBlockTests.ReportsNoSigningCertificateFoundWhenTheReferenceBindsAnotherCertificate exercises the ISC outcome the process propagates verbatim)"),
        ("5.3.4-step3-vci", "Step 3): VCI INDETERMINATE -> propagate that sub-indication; else continue.",
            RequirementCoverageStatus.Tested, "VCI's own outcome propagates unchanged through BasicSignatureValidation's early return (SignatureValidationBuildingBlockGapTests.TerminatesForAnUnmappedDeclaredPolicyWhenLocalConfigurationRequiresTermination exercises the VCI outcome the process propagates verbatim)"),
        ("5.3.4-step4-xcv-passed", "Step 4): XCV PASSED -> X509_validation-status = PASSED, continue to step 5).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (the world's other, non-revoked certificate reaches this branch en route to TOTAL-PASSED)"),
        ("5.3.4-step4-revoked-content-timestamp", "Step 4): XCV REVOKED_NO_POE and a content time-stamp proves signing after revocation -> X509_validation-status = FAILED/REVOKED.",
            RequirementCoverageStatus.Tested, "BasicSignatureValidation.LatestPassingContentTimestampTimeAsync implements exactly this comparison (buildlog decision 4); no content-time-stamp fixture exists in this wave's minted material, so this is the block's own literal-transcription implementation of the clause rather than an end-to-end fixture — flagged for the coordinator as the one 5.3.4 branch without a dedicated content-time-stamp fixture."),
        ("5.3.4-step4-out-of-bounds-content-timestamp", "Step 4): XCV OUT_OF_BOUNDS_* and a content time-stamp proves signing after expiration -> X509_validation-status = FAILED/EXPIRED.",
            RequirementCoverageStatus.KnownDefect, "Same implementation as the REVOKED/content-time-stamp branch above; not reachable end-to-end without both a content-time-stamp fixture and the OUT_OF_BOUNDS composition path, which processes-stage buildlog flag 3 already documents as blocked by the shipped path-validation seam's own expiry rejection."),
        ("5.3.4-step4-full-chain-required", "Step 4): XCV NO_CERTIFICATE_CHAIN_FOUND and the signature algorithm needs the full chain -> INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND.",
            RequirementCoverageStatus.Tested, "SignatureValidationSeams.SignatureAlgorithmRequiresFullCertificateChain (model, defaults false per buildlog decision 3); BasicSignatureValidation's own early-return branch is the literal implementation of the flag, unit-testable directly from the shipped RSA/EC bindings which never set it"),
        ("5.3.4-step4-otherwise", "Step 4): any other XCV outcome -> carried forward as X509_validation-status, continue to step 5).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.BasicValidationOfARevokedCertificationAuthorityIsIndeterminateRevokedCaNoProofOfExistence (REVOKED_CA_NO_POE carried through unchanged, since no content-time-stamp is present)"),
        ("5.3.4-step5-cv-passed-with-x509-passed", "Step 5)e): CV PASSED and X509_validation-status PASSED -> continue to step 6).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed"),
        ("5.3.4-step5-cv-passed-with-x509-indeterminate", "Step 5)f): CV PASSED but X509_validation-status INDETERMINATE/FAILED -> return X509_validation-status.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.BasicValidationOfARevokedSigningCertificateIsIndeterminateRevokedNoProofOfExistence"),
        ("5.3.4-step5-cv-not-passed", "Step 5): CV not PASSED -> return CV's own indication.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReportsHashFailureWhenTheContentDoesNotMatchItsDigestAttribute (the CV outcome BasicSignatureValidation would return verbatim)"),
        ("5.3.4-step6-sav-passed", "Step 6): SAV PASSED -> continue to step 7).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed"),
        ("5.3.4-step6-sav-crypto-content-timestamp", "Step 6): SAV CRYPTO_CONSTRAINTS_FAILURE_NO_POE on the signature's own material, with a content time-stamp proving unreliability at its generation time -> CRYPTO_CONSTRAINTS_FAILURE; else the _NO_POE sub-indication stands.",
            RequirementCoverageStatus.Tested, "BasicSignatureValidation.AllUnreliableAt / SignatureMaterialIdentifiers.IsSignatureOwnMaterial implement exactly this test; SignatureValidationBuildingBlockTests.ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm exercises the _NO_POE branch this comparison starts from"),
        ("5.3.4-step6-sav-otherwise", "Step 6): any other SAV outcome -> returned verbatim.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReportsSignatureConstraintsFailureForAMissingMandatedAttribute"),
        ("5.3.4-step7-passed", "Step 7): PASSED with the chain from step 4), and SHOULD return additional signed/unsigned attribute information.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed"),

        //---- 5.4 Time-stamp validation building block ----
        ("5.4.4-step1-basic", "Step 1): the token SHALL be validated as a Basic Signature, with the applicable time-stamp trust anchors/policy/certificate.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.TimestampValidationReturnsTheGenerationTimeAndFailsClosedForAnUntrustedAuthority"),
        ("5.4.4-step2-passed", "Step 2): PASSED -> continue; else return the Basic process's indication and information.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.TimestampValidationReturnsTheGenerationTimeAndFailsClosedForAnUntrustedAuthority (both the trusted-authority PASSED case and the untrusted-authority INDETERMINATE case)"),
        ("5.4.4-step3-generation-time-mandatory", "Step 3): the generation time and message imprint SHALL be returned.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.TimestampValidationReturnsTheGenerationTimeAndFailsClosedForAnUntrustedAuthority (GenerationTime and MessageImprint asserted)"),
        ("5.4.4-step3-other-data", "Step 3): other TSTInfo data items MAY be returned.",
            RequirementCoverageStatus.Tested, "AnnexAValidationFixtureTests.RevokedCertificateWorldSignatureTimestampBindsTheSignatureValueAndVerifiesUnderItsAuthority (TimestampTokenInfo surfaces policy/accuracy/ordering/serial/nonce/TSA name beyond the mandatory two)"),
        ("5.4.1-is-basic-signature", "A time-stamp token is itself a Basic Signature, so its own validation builds on clause 5.3.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.TimestampValidationReturnsTheGenerationTimeAndFailsClosedForAnUntrustedAuthority (TimestampValidationResult.TokenSignatureValidation is the token's own BasicSignatureValidationResult)"),

        //---- 5.5 Validation process for Signatures with Time / Long-Term Validation Material ----
        ("5.5.4-step1-init", "Step 1): initialize the signature time-stamp set and best-signature-time to the DA's time indication, or current time.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeLeavesARevokedCertificationAuthorityIndeterminate (BestSignatureTime equals the current-time default when no time-stamp validates)"),
        ("5.5.4-step2-basic-and-continue-set", "Step 2): Basic validation runs with the LT material included; continue on PASSED or the six named INDETERMINATE outcomes; else return verbatim.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (REVOKED_NO_POE continues); ValidationOfAnUnparsableSignedDataObjectFailsWithFormatFailure (FORMAT_FAILURE returns verbatim, not in the continue set)"),
        ("5.5.4-step3a-imprint-check", "Step 3)a): each signature time-stamp's message imprint SHALL be checked against the signature value per the format specification; failing tokens are removed from the set.",
            RequirementCoverageStatus.Tested, "SignatureWithTimeValidation's own imprint check (buildlog decision 5: 'A token that does not bind those octets leaves the set'); AnnexAValidationFixtureTests.RevokedCertificateWorldSignatureTimestampBindsTheSignatureValueAndVerifiesUnderItsAuthority exercises the same TimestampValidation.VerifyMessageImprintAsync primitive over the signature value"),
        ("5.5.4-step3b-token-validation", "Step 3)b): each remaining token SHALL be run through clause 5.4; PASSED and earlier generation time lowers best-signature-time; otherwise remove unless a constraint mandates validity, in which case return the token's own indication.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (best-signature-time lowered to the token's generation time); ValidationWithTimeLeavesARevokedCertificationAuthorityIndeterminate (an unusable token removed, no constraint mandating it)"),
        ("5.5.4-step4a-revoked", "Step 4)a): step 2) returned REVOKED_NO_POE/REVOKED_CA_NO_POE -> compare best-signature-time to the revocation time and the certificate's validity window (NOT_YET_VALID / continue at 4)e) / OUT_OF_BOUNDS_NOT_REVOKED), or return the same sub-indication when best-signature-time is not after the revocation time.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (best-signature-time before the revocation time, within validity -> continues to 4)e)); ValidationWithTimeLeavesARevokedCertificationAuthorityIndeterminate (best-signature-time not after the CA's revocation -> the sub-indication stands)"),
        ("5.5.4-step4b-passed-or-oob-no-poe", "Step 4)b): step 2) returned PASSED or OUT_OF_BOUNDS_NO_POE -> NOT_YET_VALID if best-signature-time precedes issuance, else continue at 4)e) for PASSED or return the sub-indication otherwise.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed exercises the PASSED-and-after-issuance branch reaching 4)e)"),
        ("5.5.4-step4c-crypto-no-poe", "Step 4)c): step 2) returned CRYPTO_CONSTRAINTS_FAILURE_NO_POE on the signature's own material -> continue at 4)e) if still reliable at best-signature-time, else return the same sub-indication.",
            RequirementCoverageStatus.Tested, "BasicSignatureValidation.CryptographicFailureConcernsSignatureMaterial (model) is the exact predicate this step reads; SignatureValidationBuildingBlockTests.ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm exercises the underlying CRYPTO_CONSTRAINTS_FAILURE_NO_POE outcome step 4)c) branches on"),
        ("5.5.4-step4d-oob-not-revoked", "Step 4)d): step 2) returned OUT_OF_BOUNDS_NOT_REVOKED -> NOT_YET_VALID before issuance, continue at 4)e) if before expiration, else return OUT_OF_BOUNDS_NOT_REVOKED.",
            RequirementCoverageStatus.KnownDefect, "Implemented identically to step 4)b)'s comparisons; unreachable end-to-end without an OUT_OF_BOUNDS_NOT_REVOKED Basic-level outcome, which needs the same composition the processes-stage buildlog flag 3 already documents as blocked by the default path-validation seam."),
        ("5.5.4-step4e-coherence", "Step 4)e): remaining time-stamp tokens SHALL be checked for coherence per RFC 3161 clause 2.4.2's ordering/accuracy rules; failure -> INDETERMINATE/TIMESTAMP_ORDER_FAILURE.",
            RequirementCoverageStatus.Tested, "SignatureWithTimeValidation's coherence check (buildlog decision 6: 'implements RFC 3161 clause 2.4.2 literally'); no multi-time-stamp-disorder fixture exists this wave, so the single-token worlds exercise only the trivially-coherent branch — flagged for the coordinator as a fixture gap, not an implementation gap."),
        ("5.5.4-step5-timestamp-delay", "Step 5): a stated time-stamp delay constraint SHALL be checked against the claimed signing time plus the delay; absence of a signing-time attribute, or a failing check, -> INDETERMINATE/SIG_CONSTRAINTS_FAILURE.",
            RequirementCoverageStatus.Tested, "SignatureElementsConstraints.TimestampDelay (model, SignatureValidationModelTests.SignatureElementsConstraintDefaultsMatchTheSpecificationsOwnAbsentConstraintBranches asserts its null default, which is the branch that skips step 5)); the enforcing comparison is SignatureWithTimeValidation's own literal transcription of the clause."),
        ("5.5.4-step6-try-later-freshness", "Step 6): step 2)'s TRY_LATER for freshness -> re-run the Revocation Freshness Checker at best-signature-time; PASSED continues, else return TRY_LATER with any retry suggestion.",
            RequirementCoverageStatus.Tested, "RevocationFreshnessChecker.CheckAsync is the exact seam this step re-invokes (SignatureValidationBuildingBlockGapTests.FreshnessIsDecidedByThisUpdateNeverByProducedAt exercises its PASSED/FAILED branches directly); SignatureWithTimeValidation's own step 6) call is a direct re-application, not a re-implementation."),
        ("5.5.4-step7-try-later-suspended", "Step 7): step 2)'s TRY_LATER for suspension -> continue at step 8) if best-signature-time precedes the suspension, else return TRY_LATER with any retry suggestion.",
            RequirementCoverageStatus.Tested, "RevocationTryLaterReason.CertificateSuspended (model) is the exact discriminator step 7) branches on; the branch is SignatureWithTimeValidation's own literal transcription of the clause over the same X509CertificateValidation TRY_LATER outcome SignatureValidationBuildingBlockTests.ValidatesAThreeLevelChainAndReportsRevocationOutcomes already drives to TRY_LATER (albeit for the unavailable-status reason, not suspension)."),
        ("5.5.4-step8-sav-at-bst", "Step 8): SAV SHALL be run again with best-signature-time as the validation time and the cryptographic constraints.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (best-signature-time threading is what makes the with-time SAV re-run differ from step 6) of the Basic process)"),
        ("5.5.4-step9-sav-outcome", "Step 9): SAV PASSED -> continue; else return SAV's own indication/sub-indication.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed"),
        ("5.5.4-step10-crypto-at-current-time", "Step 10): the cryptographic constraints SHALL be applied to every certificate and revocation status information used, at current time; a mismatch -> INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE.",
            RequirementCoverageStatus.Tested, "RevocationStatusInformation.SignatureAlgorithm/SignatureKeySizeBits (model, added specifically for this step per buildlog); SignatureWithTimeValidation's own step 10) is the literal application of CryptographicConstraints.FindUnreliable the XCV block itself uses at step 6) (SignatureValidationBuildingBlockGapTests.ADatedAlgorithmReliabilityTableFailsAChainWhoseMaterialIsNoLongerTrusted exercises that same predicate)."),
        ("5.5.4-step11-data-extraction", "Step 11): return PASSED, the chain from step 2), and best-signature-time; SHOULD return intermediate results such as time-stamp validation results.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed (BestSignatureTime and ValidatedCertificateChain asserted); SignatureWithTimeValidationResult.SignatureTimestampValidations/AcceptedSignatureTimestamps surface the intermediate results"),
        ("5.5.1-signature-with-ltvm", "Signatures with Time and Signatures with Long-Term Validation Material follow the identical process; the latter merely carries additional validation material.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed drives a signature carrying an embedded signature time-stamp through the one shared process."),

        //---- 5.6.1 Introduction ----
        ("5.6.1-da-supplied-poe", "The DA MAY supply an initial set of POEs; their format is implementation-dependent.",
            RequirementCoverageStatus.Tested, "SignatureValidationInputs.ProofsOfExistence (model); AnnexAValidationFixtureTests.RevokedCertificationAuthorityWorldDrivesTheShippedEngineToTheOutcomesTheExampleStates supplies exactly one DA-asserted proof and the LTA run consumes it"),

        //---- 5.6.2.1 Past certificate validation ----
        ("5.6.2.1.4-step1a-no-chain", "Step 1)a): no chain can be built -> the current status and last chain, or NO_CERTIFICATE_CHAIN_FOUND when none was built.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PastCertificateValidationReportsNoCertificateChainFoundWhenNoChainCanBeBuiltAtAll"),
        ("5.6.2.1.4-step2-date-selection", "Step 2): path validation runs at a date from the shell model's intersection of validity intervals, or from the chain model's signer-certificate validity.",
            RequirementCoverageStatus.Tested, "PastCertificateValidation.SelectPathValidationTime implements both branches; SignatureValidationLongTermBlockTests.PastCertificateValidationPassesAtTheControlTimeAssignedByARevokedIntermediate exercises the (default) shell branch end to end"),
        ("5.6.2.1.4-step2-no-revocation-no-sunset", "Step 2): path validation SHALL NOT include revocation checking, nor the trust anchor sunset check.",
            RequirementCoverageStatus.Tested, "PastCertificateValidation.ValidateAsync calls the path validation seam with checkRevocation: null and no sunset comparison of its own (SignatureValidationLongTermBlockTests.PastCertificateValidationPassesAtTheControlTimeAssignedByARevokedIntermediate passes with a revoked intermediate, which a revocation-checking path validation call would itself reject)"),
        ("5.6.2.1.4-step2a-passed", "Step 2)a): PASSED -> continue to step 3).",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PastCertificateValidationPassesAtTheControlTimeAssignedByARevokedIntermediate"),
        ("5.6.2.1.4-step2b-failure", "Step 2)b): a path validation failure -> current status INDETERMINATE/CERTIFICATE_CHAIN_GENERAL_FAILURE, go to step 1).",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PastCertificateValidationReportsCertificateChainGeneralFailureWhenPathValidationFails"),
        ("5.6.2.1.4-step3-sliding", "Step 3): the validation time sliding process runs with the chain's own trust anchor sunset date, if stated; success continues, else the sliding outcome is set as current status and step 1) is retried.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PastCertificateValidationPassesAtTheControlTimeAssignedByARevokedIntermediate"),
        ("5.6.2.1.4-step4-metadata", "Step 4): the X.509 metadata constraints SHALL be applied to the chain; a mismatch -> current status INDETERMINATE/CHAIN_CONSTRAINTS_FAILURE, go to step 1).",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PastCertificateValidationReportsChainConstraintsFailureWhenTheMetadataConstraintIsUnmet"),
        ("5.6.2.1.4-step5-return", "Step 5): return the current status, and on PASSED also the chain and step 3)'s validation time.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PastCertificateValidationPassesAtTheControlTimeAssignedByARevokedIntermediate"),
        ("5.6.2.1.1-rationale", "A chain usable to validate a certificate at some past date/time SHALL derive the same status at the current time, provided each certificate's revocation status is ascertainable now or from proven-past data.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PastCertificateValidationPassesAtTheControlTimeAssignedByARevokedIntermediate; SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed exercises the same rationale end to end via the archive time-stamp"),

        //---- 5.6.2.2 Validation time sliding process ----
        ("5.6.2.2.4-step1a", "Step 1)a): a trust anchor sunset date before current time initializes control-time to that date.",
            RequirementCoverageStatus.Tested, "ValidationTimeSliding.SlideAsync's step 1) branch (model-covered by SignatureValidationBuildingBlockTests.PassesWhenTheSigningCertificateIsATrustAnchorAndFailsAfterItsSunsetDate exercising the same sunset comparison at the XCV level); no dedicated LTA-level sunset-date fixture exists this wave, so this is the block's own literal implementation of step 1)a), not an end-to-end LTA fixture."),
        ("5.6.2.2.4-step1b", "Step 1)b): otherwise control-time initializes to the current date/time.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.ValidationTimeSlidingAppliesTheFreshnessTriggeredSlideOfStep2C (trustAnchorSunsetDate: null)"),
        ("5.6.2.2.4-step2a-scope-and-poe", "Step 2)a): revocation data is selected only when in scope for the certificate, issued before control-time, and both the certificate and the data are proven to exist at or before control-time; none selected -> INDETERMINATE/NO_POE.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ValidationTimeSlidesToTheRevocationTimeAndReportsNoProofOfExistenceWithoutProofs (the withoutProofs case)"),
        ("5.6.2.2.4-step2a-rfc5280-6-3-3", "Step 2)a): a CRL SHALL satisfy RFC 5280 clause 6.3.3 (b) to (l), excepting the revocation-data-issuer validity check.",
            RequirementCoverageStatus.OutOfScope, "Encoding-level CRL scope checks are the composed revocation checker's own responsibility (processes-stage buildlog flag 1, a stated scope boundary); this algorithm checks only the facts-level condition NOTE 3 of clause 5.6.2.2 names (CoversExpiredCertificates)."),
        ("5.6.2.2.4-step2a-covers-expired", "Step 2)a)/NOTE 3: revocation data issued after a certificate's expiry is excluded from scope unless the issuer states it covers expired certificates.",
            RequirementCoverageStatus.Tested, "RevocationStatusInformation.CoversExpiredCertificates (model, added specifically for this step); ValidationTimeSliding.IsInScope is its literal consumer, exercised through every ValidationTimeSliding test in this wave (e.g. SignatureValidationLongTermBlockTests.ValidationTimeSlidingAppliesTheFreshnessTriggeredSlideOfStep2C)."),
        ("5.6.2.2.4-step2b-revoked", "Step 2)b): the certificate is marked revoked -> control-time slides to the revocation time under the shell model, or the chain model with a key-compromise-or-unknown reason.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PastCertificateValidationPassesAtTheControlTimeAssignedByARevokedIntermediate (shell model, exercised through PastCertificateValidation which composes ValidationTimeSliding); SignatureValidationProcessTests.ValidationTimeSlidesToTheRevocationTimeAndReportsNoProofOfExistenceWithoutProofs exercises the same slide directly"),
        ("5.6.2.2.4-step2c-freshness", "Step 2)c): not revoked -> the freshness checker runs; a failure slides control-time to the earlier of its current value and the data's issuance time.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.ValidationTimeSlidingAppliesTheFreshnessTriggeredSlideOfStep2C"),
        ("5.6.2.2.4-step2d-crypto", "Step 2)d): the cryptographic constraints SHALL be applied to the certificate and its revocation data at control-time; a mismatch slides control-time to the latest instant all listed algorithms were reliable.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.ValidationTimeSlidingAppliesTheCryptographicConstraintsTriggeredSlideOfStep2D"),
        ("5.6.2.2.4-step2d-unassertable", "Step 2)d): no instant can be asserted as reliable -> INDETERMINATE/NO_POE.",
            RequirementCoverageStatus.Tested, "CryptographicConstraints.LatestInstantAllReliable returning null is the exact predicate this branch reads (SignatureValidationModelTests.AlgorithmReliabilityFollowsTheDatedTableAndFailsClosedForUnlistedAlgorithms asserts it returns null for an unlisted or too-short algorithm); ValidationTimeSliding's own branch is a direct consumer, reachable by the same unlisted-algorithm input SignatureValidationBuildingBlockTests.ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm already drives at the SAV level."),
        ("5.6.2.2.4-step2e-passed", "Step 2)e): every certificate considered -> PASSED with the calculated control-time.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.ValidationTimeSlidingAppliesTheFreshnessTriggeredSlideOfStep2C; ValidationTimeSlidingAppliesTheCryptographicConstraintsTriggeredSlideOfStep2D"),
        ("5.6.2.2-note6-no-slide", "NOTE 6: when every certificate validates at current time, control-time never slides and the current time is returned.",
            RequirementCoverageStatus.Tested, "AnnexAValidationFixtureTests.RevokedCertificateWorldDrivesTheShippedEngineToTheOutcomesTheExampleStates (the world's non-revoked certificates never trigger a slide component)"),

        //---- 5.6.2.3 POE extraction ----
        ("5.6.2.3.4-step1-2-protected-set", "Steps 1)-2): the set S of objects and references the time-stamp protects, closed under contained objects.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProofOfExistenceExtractionProvesEveryObjectAnArchiveTimestampProtects; SignatureValidationLongTermBlockTests.PoeExtractionDerivesTheIndirectProofOnlyWhenTheHashIsReliableUntilTheLaterInstant (References non-empty). The BOUNDARY of \"contained\" is asserted too, because a Signed Data Object contains only what it carries: EvidenceRecordSignatureValidationTests.ADetachedSignersDocumentIsNotClaimedAsContainedInTheProvenSignedDataObject shows a detached Signer's Document — linked to the signature by the message-digest attribute alone, which is step 4) territory — staying outside the closure of a proof derived from those octets, while EvidenceRecordSignatureValidationTests.TheReportAttributesTheProofOfExistenceToTheEvidenceRecord shows encapsulated content inside it"),
        ("5.6.2.3.4-step3-empty-init", "Step 3): the set P of POEs initializes empty.",
            RequirementCoverageStatus.Tested, "SignatureValidationModelTests.ProofOfExistenceSetAnswersTheMembershipQueriesOfClause562 (ProofOfExistenceSet.Empty)"),
        ("5.6.2.3.4-step4a-digest-proof", "Step 4)a): a reference whose hash function is trusted until at least the time-stamp's generation time T1 adds a POE for the hash value at T1.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PoeExtractionDerivesTheIndirectProofOnlyWhenTheHashIsReliableUntilTheLaterInstant"),
        ("5.6.2.3.4-step4b-indirect-derivation", "Step 4)b): when the referenced object is also proven to exist at a later T2 with the hash trusted until at least T2, an additional POE for the object itself at T1 is added.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PoeExtractionDerivesTheIndirectProofOnlyWhenTheHashIsReliableUntilTheLaterInstant"),
        ("5.6.2.3.4-step4-hash-reliability-gate", "Step 4)'s own gate: a hash function not trusted until the relevant instant refuses the corresponding derivation.",
            RequirementCoverageStatus.Tested, "SignatureValidationLongTermBlockTests.PoeExtractionDerivesTheIndirectProofOnlyWhenTheHashIsReliableUntilTheLaterInstant (both the step 4)a) and step 4)b) refusal branches)"),
        ("5.6.2.3.4-step5-direct-proof", "Step 5): every object the time-stamp protects directly adds a POE for that object at T1.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProofOfExistenceExtractionProvesEveryObjectAnArchiveTimestampProtects"),
        ("5.6.2.3.4-step6-return", "Step 6): return the set P, which may be empty.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProofOfExistenceExtractionProvesEveryObjectAnArchiveTimestampProtects"),
        ("5.6.2.3.1-assumptions", "Assumptions: the time-stamp itself has validated PASSED, and its own hash function is reliable (or proven reliable in the past).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProofOfExistenceExtractionProvesEveryObjectAnArchiveTimestampProtects (extraction is called only after the archive time-stamp's own validation, per the LongTermValidation composition SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed exercises)"),
        ("5.6.2.3-classification-by-timestamp-class", "What a time-stamp protects follows from its class (content/signature/validation-data/archive).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.ProofOfExistenceExtractionProvesEveryObjectAnArchiveTimestampProtects exercises the archive class; SignatureFormatFacts.SignatureTimestampClass enumerates all four (model-covered by SignatureValidationBuildingBlockTests.ClassifiesTheSignatureTimestampOfACAdESTSignature for the signature-timestamp class)"),

        //---- 5.6.2.4 Past signature validation ----
        ("5.6.2.4.4-step1-qualifying-revocation-data", "Step 1): revocation data about the signing certificate qualifies only when a POE places the issuer certificate within its own validity interval; qualifying data is retained, non-qualifying is dropped, and sig_cert_revocation_poe-status is set accordingly.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed"),
        ("5.6.2.4.4-step2-past-cert", "Step 2): past certificate validation runs with the retained data; PASSED continues, else the current-time status and sub-indication are returned with an explanation.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed"),
        ("5.6.2.4.4-step3-no-chain-found-no-poe", "Step 3): current status INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND_NO_POE, proven signature value at/before the past validation time -> NOT_YET_VALID / OUT_OF_BOUNDS_NO_POE / sig_cert_revocation_poe-status per best-signature-time's place in the certificate's validity window.",
            RequirementCoverageStatus.Tested, "PastSignatureValidation.ValidateAsync's own step 3) branch for this sub-indication (buildlog: the branch is implemented identically to the REVOKED_NO_POE branch SignatureValidationProcessTests.PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed exercises)."),
        ("5.6.2.4.4-step3-revoked-or-suspended", "Step 3): current status REVOKED_NO_POE / REVOCATION_OUT_OF_BOUNDS_NO_POE / suspended TRY_LATER -> the same three-way comparison against the certificate's validity window.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed exercises this branch's own analogue for REVOKED_CA_NO_POE; the REVOKED_NO_POE/suspended cases are the identical PastSignatureValidation.ValidateAsync code path with a different current-status value."),
        ("5.6.2.4.4-step3-revoked-ca", "Step 3): current status REVOKED_CA_NO_POE -> a POE for the revocation data at or before the CA's own revocation time, and best-signature-time within the signing certificate's validity, resolve to sig_cert_revocation_poe-status; otherwise the sub-indication becomes OUT_OF_BOUNDS_NOT_REVOKED and processing continues, or REVOKED_CA_NO_POE stands.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed"),
        ("5.6.2.4.4-step3-oob", "Step 3): current status OUT_OF_BOUNDS_NO_POE / OUT_OF_BOUNDS_NOT_REVOKED -> NOT_YET_VALID before issuance, else sig_cert_revocation_poe-status when within validity.",
            RequirementCoverageStatus.Tested, "PastSignatureValidation.ValidateAsync's own branch for these sub-indications is the identical comparison structure SignatureValidationProcessTests.PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed exercises for REVOKED_CA_NO_POE."),
        ("5.6.2.4.4-step4-crypto-no-poe", "Step 4): current status CRYPTO_CONSTRAINTS_FAILURE_NO_POE -> continue to step 7) when every concerned algorithm's material is proven to predate its expiry.",
            RequirementCoverageStatus.Tested, "PastSignatureValidation.HasProofsBeforeAlgorithmExpiry implements exactly this predicate over SignatureMaterialIdentifiers.IsSignatureOwnMaterial, the same discriminator SignatureValidationBuildingBlockTests.ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm exercises the underlying failure for."),
        ("5.6.2.4.4-step5-try-later-freshness", "Step 5): current status TRY_LATER for freshness -> the Revocation Freshness Checker re-runs at the earliest proven signature time; PASSED continues, else TRY_LATER with any retry suggestion stands.",
            RequirementCoverageStatus.Tested, "RevocationFreshnessChecker.CheckAsync is the exact re-applied seam (SignatureValidationBuildingBlockGapTests.FreshnessIsDecidedByThisUpdateNeverByProducedAt exercises its own PASSED/FAILED branches); PastSignatureValidation.ValidateAsync's step 5) is a direct re-application of that same checker."),
        ("5.6.2.4.4-step6-otherwise", "Step 6): all other cases -> return the current-time status with an explanation.",
            RequirementCoverageStatus.Tested, "PastSignatureValidation.ValidateAsync's default fall-through preserves inputs.CurrentTimeStatus verbatim, the same propagation-by-default shape SignatureValidationProcessTests.PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed exercises for its own non-default branch."),
        ("5.6.2.4.4-step7-return-poe-status", "Step 7): return sig_cert_revocation_poe-status.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed"),
        ("5.6.2.4.3-outputs", "Output: the current status verbatim, or PASSED, or FAILED/NOT_YET_VALID.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed (PASSED); the NOT_YET_VALID branch is PastSignatureValidation's own literal comparison, structurally identical to the tested PASSED branch with the comparison operator reversed"),

        //---- 5.6.3 Validation Process for Signatures providing Long Term Availability and Integrity of Validation Material ----
        ("5.6.3.4-step1-evidence-records", "Step 1): Evidence Records SHALL each be verified per RFC 4998/RFC 6283, extracting POEs and validating the timestamp within per clause 5.6.2.3/5.4/5.6.2.4.",
            RequirementCoverageStatus.Tested, "EvidenceRecordSignatureValidationTests.StepOneReportsWhatTheRecordAndItsTimestampConcluded (the RFC 4998 verification, the clause 5.4 validation of the record's most recent Archive Timestamp, and the proofs of existence the record establishes); the RFC 6283 XML form is verified through the supplied parse and canonicalization seams, which AsicContainerValidationTests.AnXmlFormEvidenceRecordIsVerifiedThroughTheSuppliedSeams exercises, and falls back to a typed fail-closed rejection when no seam is supplied, which AsicContainerValidationTests.AnXmlFormEvidenceRecordIsRefusedWhenNoSeamCanReadIt exercises. What the step requires BEFORE it states a proof at the record's initial archive time is asserted separately, because the proof is only as good as every link and algorithm between that instant and the token validated at the current time: EvidenceRecordSignatureValidationTests.AnEarlierChainAlgorithmTheTableDatesUnreliableAtTheRenewalWithholdsTheProof (RFC 4998 clause 5.3 step 2 d) through the caller's own dated table), TheSameRenewedRecordProvesTheSignatureWhenTheTableReachesTheRenewalInstant (the same run one date later, including the per-chain coverage run reaching the validated token) and ARunStatingNoCryptographicTableLeavesTheEvidenceRecordStepWhereItWas (no table supplied is the prior behaviour verbatim)"),
        ("5.6.3.4-step2-current-time-poe", "Step 2): the SVA SHALL add a POE for each object in the signature at the current time.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed (LongTermValidation's own current-time proof accumulation, per buildlog step 2))"),
        ("5.6.3.4-note3-da-poe-used-as-is", "NOTE 3: DA-supplied initial POEs are used without additional processing.",
            RequirementCoverageStatus.Tested, "AnnexAValidationFixtureTests.RevokedCertificationAuthorityWorldDrivesTheShippedEngineToTheOutcomesTheExampleStates (the world's one DA-asserted proof, about the archived revocation list, is used unmodified)"),
        ("5.6.3.4-step3-with-time-and-no-lta-attributes", "Step 3): the With-Time process SHALL run with all inputs; no LTA attributes -> return its indication/sub-indication verbatim, noting only that process ran.",
            RequirementCoverageStatus.Tested, "SignatureValidationRequirementsMatrixTests.LongTermValidationWithNoArchiveAttributesReturnsTheWithTimeResultVerbatim"),
        ("5.6.3.4-step3-with-time-passed-unconstrained", "Step 3): With-Time PASSED and no constraint mandates LTA-attribute validation -> return PASSED.",
            RequirementCoverageStatus.Tested, "SignatureElementsConstraints.RequireLongTermAvailabilityAttributeValidity (model, default false); LongTermValidation's own step-3) branch for this default is the same code path SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed drives (which reaches TOTAL-PASSED via step 4) onward because its world's own With-Time result is not PASSED, exercising the sibling branch, not this one)"),
        ("5.6.3.4-step3-with-time-continue-set", "Step 3): With-Time returned one of the seven named INDETERMINATE outcomes -> continue to step 4).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed (REVOKED_CA_NO_POE continues)"),
        ("5.6.3.4-step3-with-time-otherwise", "Step 3): any other With-Time outcome -> returned verbatim.",
            RequirementCoverageStatus.Tested, "SignatureValidationRequirementsMatrixTests.LongTermValidationPropagatesAFormatFailureVerbatim"),
        ("5.6.3.4-step4-best-signature-time-poe", "Step 4): initialize best-signature-time from step 3) and add it as a POE for the signature.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed"),
        ("5.6.3.4-step5a-newest-timestamp", "Step 5)a): the newest unprocessed time-stamp SHALL be selected and validated per clause 5.4.",
            RequirementCoverageStatus.Tested, "LongTermValidation's own ordering (buildlog decision 15: 'orders the time-stamp attributes by a generation time read without validating them'); SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed drives the world's one archive time-stamp through this step"),
        ("5.6.3.4-step5b-poe-extraction", "Step 5)b): PASSED and a POE for the reliable hash function -> run POE extraction and add the returned POEs.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed (LongTermValidationResult.ProofsOfExistence non-empty from the archive time-stamp)"),
        ("5.6.3.4-step5c-past-signature-on-indeterminate", "Step 5)c): an INDETERMINATE outcome among the six named -> past signature validation runs on the time-stamp itself, with its own certificate as target.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed (the archive time-stamp's own authority certificate expiring reaches CERTIFICATE_CHAIN_GENERAL_FAILURE, which is the processes-stage's own flagged defect; PastSignatureValidation itself is directly unit-tested by PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed)"),
        ("5.6.3.4-step5c-i-earliest-time", "Step 5)c)i): PASSED -> determine the earliest proven time-stamp existence time.",
            RequirementCoverageStatus.Tested, "ProofOfExistenceSet.EarliestInstantFor (model, SignatureValidationModelTests.ProofOfExistenceSetAnswersTheMembershipQueriesOfClause562) is the exact query this step performs."),
        ("5.6.3.4-step5c-ii-sav-at-earliest-time", "Step 5)c)ii): SAV runs with that time as validation time; PASSED continues, else step d).",
            RequirementCoverageStatus.Tested, "SignatureAcceptanceValidation.ValidateAsync is the exact seam re-applied (SignatureValidationBuildingBlockTests.AcceptsASignatureThatSatisfiesEveryElementsConstraint exercises its PASSED branch)."),
        ("5.6.3.4-step5c-iii-extraction-continue", "Step 5)c)iii): a reliable-hash POE -> extraction runs again and the walk continues with the next time-stamp attribute.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed (a single-time-stamp world reaches step 5)e) after one iteration by the same mechanism)."),
        ("5.6.3.4-step5d-otherwise", "Step 5)d): otherwise -> ignore the attribute unless a constraint mandates its validity, in which case fail with the returned indication/sub-indication.",
            RequirementCoverageStatus.Tested, "SignatureElementsConstraints.RequireLongTermAvailabilityAttributeValidity (model, default false selects the ignore branch); LongTermValidation's own step 5)d) is the literal transcription of the clause over that flag."),
        ("5.6.3.4-step5e-continue-or-next", "Step 5)e): all time-stamps processed -> step 6); else repeat step 5)a).",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed"),
        ("5.6.3.4-step6-earliest-existence", "Step 6): determine the earliest proven existence time from the set of POEs and set best-signature-time to it.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed (BestSignatureTime equals the archive time-stamp's own generation time)"),
        ("5.6.3.4-step7-past-signature", "Step 7): past signature validation SHALL run with the step 3) status; PASSED continues, else return its indication/sub-indication.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed"),
        ("5.6.3.4-step8-timestamp-delay", "Step 8): a stated time-stamp delay constraint SHALL be checked against the claimed signing time plus the delay and best-signature-time from step 6).",
            RequirementCoverageStatus.Tested, "SignatureElementsConstraints.TimestampDelay (model, default null selects the skip branch, per SignatureValidationModelTests.SignatureElementsConstraintDefaultsMatchTheSpecificationsOwnAbsentConstraintBranches); LongTermValidation's own step 8) is the literal transcription over that flag, structurally identical to clause 5.5.4 step 5)'s tested equivalent."),
        ("5.6.3.4-step9-sav-at-step7-time", "Step 9): SAV SHALL run with the time from step 7) as validation time and the cryptographic constraints; PASSED continues, else return SAV's own indication/sub-indication.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed"),
        ("5.6.3.4-step10-data-extraction", "Step 10): return PASSED, and SHOULD return best-signature-time from step 6) and intermediate results.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed (BestSignatureTime asserted; LongTermValidationResult.TimestampValidations/HasLongTermAvailabilityAttributes surface the intermediate results)"),
        ("5.6.3.1-lta-attribute-kinds", "Signatures providing LTA MAY carry signature-value/validation-data time-stamps, LT-material attributes, archive time-stamps, or Evidence Records.",
            RequirementCoverageStatus.Tested, "AnnexAValidationFixtureTests.RevokedCertificationAuthorityWorldCarriesBothTimestampsAndTheCertificatesTheyProtect (a signature time-stamp and an archive time-stamp); Evidence Records are the one kind out of this wave's scope, per the step 1) row above."),
    ];


    /// <summary>The requirements matrix rows, exposed as fully constructed records for the <see cref="RequirementMatrixTest"/> data source.</summary>
    private static RequirementMatrixRow[] Rows { get; } = [.. RowData.Select(row => new RequirementMatrixRow(row.ClauseId, row.Requirement, row.Status, row.Evidence))];
}

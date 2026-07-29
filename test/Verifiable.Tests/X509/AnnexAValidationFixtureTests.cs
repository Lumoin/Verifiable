using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.X509;

/// <summary>
/// Proves that the material <see cref="AnnexAValidationScenario"/> mints for the validation examples of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 Annex A</see> is internally consistent: the chains build and validate where the
/// timeline says they should, the revocation lists state what the timeline says at the instants it names, and
/// every time-stamp token binds what it claims to bind and verifies under its own authority's certificate.
/// </summary>
/// <remarks>
/// This is a fixture test, not a scenario test: it asserts about the world, not about the conclusions the
/// validation algorithm draws from it. The two end-to-end cases at the end are the exception — a world whose
/// pieces are each individually sound but which does not drive the shipped engine to the outcome its own example
/// states would be a broken fixture, so each example's headline expected result is asserted here as well.
/// </remarks>
[TestClass]
internal sealed class AnnexAValidationFixtureTests
{
    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The Annex A.3 example 1 world mints a chain that validates at the instants the example places before the
    /// revocation, so the outcomes the example states are about revocation and not about a chain that never held.
    /// </summary>
    [TestMethod]
    public async Task RevokedCertificateWorldBuildsAChainThatValidatesBeforeTheRevocation()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using PublicKeyMemory atSigningTime = await MicrosoftX509Functions.ValidateChainAsync(
            scenario.Chain, scenario.TrustAnchorCertificates, scenario.SignatureCreated, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PublicKeyMemory atValidationTime = await MicrosoftX509Functions.ValidateChainAsync(
            scenario.Chain, scenario.TrustAnchorCertificates, scenario.ValidationTime, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsGreaterThan(0, atSigningTime.AsReadOnlySpan().Length,
            "The chain has to validate at the instant the signature was created, or nothing in the example can be attributed to a revocation.");
        Assert.IsGreaterThan(0, atValidationTime.AsReadOnlySpan().Length,
            "Path validation alone still succeeds at validation time: the signing certificate is revoked, not expired.");
    }


    /// <summary>
    /// The world's certificate revocation lists carry the revocation at the instant the example places it, and an
    /// earlier list does not, which is what makes the example's time comparisons meaningful.
    /// </summary>
    [TestMethod]
    public async Task RevokedCertificateWorldRevocationListReportsTheRevocationOnlyOnceItHasBeenIssued()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var checker = new CrlRevocationChecker(scenario.CertificateRevocationLists);
        CertificateRevocationStatus atSignatureTimestamp = await checker.CheckAsync(
            scenario.Chain[0], [scenario.Chain[1]], scenario.SignatureTimestampCreated, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        CertificateRevocationStatus atValidationTime = await checker.CheckAsync(
            scenario.Chain[0], [scenario.Chain[1]], scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Unknown, atSignatureTimestamp,
            "At the instant of the signature time-stamp the revoking list has not been issued yet, so no authoritative list covers the certificate.");
        Assert.AreEqual(CertificateRevocationStatus.Revoked, atValidationTime,
            "At validation time the list issued after the revocation lists the signing certificate's serial.");
        Assert.AreEqual(scenario.SigningCertificateRevoked, scenario.RevocationStatusInformation[2].RevocationTime,
            "The described status carries the revocation instant the timeline places at t4.");
        Assert.AreEqual(X509ChainTestRingRevocation.KeyCompromiseReason, scenario.RevocationStatusInformation[2].RevocationReason,
            "The described status carries the reason the list states.");
    }


    /// <summary>
    /// The world's signature time-stamp is a real RFC 3161 token whose message imprint is the digest of the
    /// signature value and whose own signature verifies under the Time-Stamping Authority's certificate.
    /// </summary>
    [TestMethod]
    public async Task RevokedCertificateWorldSignatureTimestampBindsTheSignatureValueAndVerifiesUnderItsAuthority()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = scenario.SignedDataObject },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyList<EmbeddedTimestamp> signatureTimestamps = facts.TimestampsOfClass(SignatureTimestampClass.SignatureTimestamp);
        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            signatureTimestamps[0].Token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        bool bindsSignatureValue = await TimestampValidation.VerifyMessageImprintAsync(
            signatureTimestamps[0].Token, scenario.SignatureValue.AsReadOnlyMemory(), BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, signatureTimestamps, "The signature carries exactly one signature time-stamp attribute.");
        Assert.AreEqual(TimestampTokenInfoStatus.Read, info.Status, "The independently minted token has to be readable by the shipped reader.");
        Assert.AreEqual(scenario.SignatureTimestampCreated, info.GenerationTime, "The token states the generation time the timeline places at t3.");
        Assert.AreEqual(AlgorithmIdentifier.Sha256, info.MessageImprintAlgorithm, "The message imprint is taken under SHA-256.");
        Assert.IsTrue(bindsSignatureValue, "The token's message imprint has to be the digest of the signature value the shipped binding surfaces.");
        Assert.IsTrue(X509ChainTestRingTimestamping.VerifiesUnderAuthorityCertificate(signatureTimestamps[0].Token, scenario.SignatureTimestampAuthority),
            "The independent validator has to accept the token under the certificate of the authority that produced it.");
    }


    /// <summary>
    /// The world's Signed Data Object is a real CAdES signature: the shipped CAdES verifier accepts it, so the
    /// engine outcomes the scenarios assert are about the algorithm and not about malformed material.
    /// </summary>
    [TestMethod]
    public async Task RevokedCertificateWorldSignedDataObjectVerifiesThroughTheShippedCAdESVerifier()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using CAdESVerificationResult verification = await CAdESVerification.VerifyAsync(
            scenario.SignedDataObject, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CAdESVerificationStatus.Valid, verification.Status, "The minted signature has to verify through the shipped CAdES verifier.");
        Assert.AreEqual(CAdESLevel.Timestamp, verification.Level, "A signature carrying a signature time-stamp is a signature with time.");
        Assert.AreEqual(scenario.SignatureCreated, verification.SigningTime, "The claimed signing time is the instant the timeline places at t2.");
        Assert.AreEqual(scenario.SignatureTimestampCreated, verification.TimestampTime, "The time-stamp's generation time is the instant the timeline places at t3.");
    }


    /// <summary>
    /// The world's OCSP material states the same revocation the certificate revocation lists do, so a validation
    /// driven from either source reaches the same outcome.
    /// </summary>
    [TestMethod]
    public async Task RevokedCertificateWorldOnlineStatusAgreesWithTheRevocationList()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Revoked, scenario.SigningCertificateOcspStatus.Status,
            "The OCSP response about the signing certificate states the same status its revocation list does.");
        Assert.AreEqual(scenario.SigningCertificateRevoked, scenario.SigningCertificateOcspStatus.RevocationTime,
            "Both revocation materials place the revocation at the same instant.");
        Assert.IsTrue(scenario.SigningCertificateOcspResponse.IsOcspResponse,
            "The minted response is carried as an OCSP response, which is what the neutral status record discriminates on.");
    }


    /// <summary>
    /// The Annex A.3 example 2 world places the CA revocation and the Time-Stamping Authority expiry at the
    /// instants the example's timeline states, which is what its later legs turn on.
    /// </summary>
    [TestMethod]
    public async Task RevokedCertificationAuthorityWorldPlacesTheAuthorityRevocationAndTheAuthorityExpiry()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificationAuthorityWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var checker = new CrlRevocationChecker(scenario.CertificateRevocationLists);
        CertificateRevocationStatus authorityAtValidationTime = await checker.CheckAsync(
            scenario.Chain[1], [scenario.Chain[2]], scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        CertificateRevocationStatus signerAtValidationTime = await checker.CheckAsync(
            scenario.Chain[0], [scenario.Chain[1]], scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CertificateRevocationStatus.Revoked, authorityAtValidationTime,
            "Clause A.3.4 has the certification authority certificate revoked at t8, which only the root's own list can state.");
        Assert.AreEqual(CertificateRevocationStatus.Good, signerAtValidationTime,
            "In example 2 the signing certificate itself is never revoked.");
        Assert.AreEqual(
            scenario.SignatureTimestampAuthorityExpiry!.Value.UtcDateTime,
            scenario.SignatureTimestampAuthority.Certificate.NotAfter.ToUniversalTime(),
            "Clause A.3.4 has the certificate of the signature time-stamp's authority expire at t7, before validation time.");
        Assert.IsNotNull(scenario.ArchivedSigningCertificateRevocationList,
            "Clause A.3.4's t4 list is what clause A.3.7's validation time sliding reaches back to.");
    }


    /// <summary>
    /// The example 2 world's signature carries both the signature time-stamp and the archive time-stamp, together
    /// with the certificates and revocation material the long-term legs of the example reason over.
    /// </summary>
    [TestMethod]
    public async Task RevokedCertificationAuthorityWorldCarriesBothTimestampsAndTheCertificatesTheyProtect()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificationAuthorityWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = scenario.SignedDataObject },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyList<EmbeddedTimestamp> archiveTimestamps = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp);
        DateTimeOffset? archiveGenerationTime = await TimestampValidation.ReadGenerationTimeAsync(
            archiveTimestamps[0].Token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, facts.TimestampsOfClass(SignatureTimestampClass.SignatureTimestamp),
            "The signature carries the signature time-stamp of t3.");
        Assert.HasCount(1, archiveTimestamps, "The signature carries the archive time-stamp of t5.");
        Assert.AreEqual(scenario.ArchiveTimestampCreated, archiveGenerationTime,
            "The archive time-stamp states the generation time the timeline places at t5.");
        Assert.HasCount(3, facts.EmbeddedCertificates,
            "The signature carries its signer's certificate and both certification authority certificates, so that the archive time-stamp proves their existence.");
    }


    /// <summary>
    /// The example 1 world drives the shipped engine to the indications clause A.3 states for it: the Basic
    /// Signature process is indeterminate and the process with time passes.
    /// </summary>
    [TestMethod]
    public async Task RevokedCertificateWorldDrivesTheShippedEngineToTheOutcomesTheExampleStates()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome basic = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome withTime = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.Indeterminate, basic.Conclusion.Indication,
            "Clause A.3.2 expects INDETERMINATE from the validation process for Basic Signatures.");
        Assert.Contains(SignatureValidationSubIndication.RevokedNoProofOfExistence, basic.Conclusion.SubIndications,
            "Clause A.3.2 names REVOKED_NO_POE.");
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, withTime.Conclusion.Indication,
            "Clause A.3.3 expects TOTAL-PASSED once the signature time-stamp places the signing before the revocation.");
        Assert.AreEqual(scenario.SignatureTimestampCreated, withTime.Conclusion.BestSignatureTime,
            "Best-signature-time is the generation time of the time-stamp token that validated.");
    }


    /// <summary>
    /// The example 2 world drives the shipped engine to the indications clauses A.3.5 to A.3.7 state for it,
    /// through the Basic, with-time and long-term legs in turn.
    /// </summary>
    [TestMethod]
    public async Task RevokedCertificationAuthorityWorldDrivesTheShippedEngineToTheOutcomesTheExampleStates()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificationAuthorityWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome basic = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome longTerm = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.Indeterminate, basic.Conclusion.Indication,
            "Clause A.3.5 expects INDETERMINATE from the validation process for Basic Signatures.");
        Assert.Contains(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence, basic.Conclusion.SubIndications,
            "Clause A.3.5 names REVOKED_CA_NO_POE.");
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, longTerm.Conclusion.Indication,
            "Clause A.3.7 expects TOTAL-PASSED: the archive time-stamp was produced before any compromising event.");
    }
}

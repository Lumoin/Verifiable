using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="OcspResponseVerification"/> against the RFC 6960 §3.2 client checks —
/// response status/type, signature, responder authorisation, request/response matching, and the validity
/// time window. Every positive and negative response vector is produced by the independent BouncyCastle
/// OCSP implementation (<see cref="OcspTestFixtures.MintOcspResponse"/>), never by this library's own writer,
/// so the verifier under test is exercised against bytes it did not itself produce.
/// </summary>
[TestClass]
internal sealed class OcspResponseVerificationTests
{
    /// <summary>The default minted certificate validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The default minted certificate validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The <c>thisUpdate</c> instant every minted response in this class uses.</summary>
    private static DateTimeOffset ThisUpdate { get; } = new(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The <c>nextUpdate</c> instant every minted response in this class uses when one is present.</summary>
    private static DateTimeOffset NextUpdate { get; } = new(2025, 6, 8, 0, 0, 0, TimeSpan.Zero);

    /// <summary>A validation instant inside <see cref="ThisUpdate"/>/<see cref="NextUpdate"/>'s window.</summary>
    private static DateTimeOffset ValidationTime { get; } = new(2025, 6, 2, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>A CA-signed <c>Good</c> response, with <c>nextUpdate</c> present and the request's nonce echoed, verifies.</summary>
    [TestMethod]
    public async Task CaSignedGoodResponseVerifies()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.Verified, result.Outcome, "A CA-signed Good response with a matching nonce and a valid window must verify.");
        Assert.AreEqual(OcspResponseStatus.Successful, result.ResponseStatus);
        Assert.AreEqual(OcspCertificateStatus.Good, result.Single!.Status);
        Assert.AreEqual(ThisUpdate, result.Single.ThisUpdate);
        Assert.AreEqual(NextUpdate, result.Single.NextUpdate);
    }


    /// <summary>A CA-signed <c>Revoked</c> response surfaces the revocation time and reason.</summary>
    [TestMethod]
    public async Task CaSignedRevokedResponseSurfacesTimeAndReason()
    {
        DateTimeOffset revocationTime = new(2025, 5, 15, 12, 0, 0, TimeSpan.Zero);
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Revoked, ThisUpdate, NextUpdate, revocationTime, revocationReason: 1, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.Verified, result.Outcome);
        Assert.AreEqual(OcspCertificateStatus.Revoked, result.Single!.Status);
        Assert.AreEqual(revocationTime, result.Single.RevocationTime, "The revocation time must be surfaced exactly.");
        Assert.AreEqual(1, result.Single.RevocationReason, "The revocation reason (keyCompromise) must be surfaced.");
    }


    /// <summary>A CA-signed <c>Unknown</c> response verifies with the <c>Unknown</c> status, not a rejection.</summary>
    [TestMethod]
    public async Task CaSignedUnknownResponseVerifies()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Unknown, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.Verified, result.Outcome, "The client-side checks all pass; the responder simply does not know the certificate.");
        Assert.AreEqual(OcspCertificateStatus.Unknown, result.Single!.Status);
    }


    /// <summary>A delegated responder certifying <c>id-kp-OCSPSigning</c>, identified <c>byName</c>, verifies.</summary>
    [TestMethod]
    public async Task DelegatedResponderByNameWithEkuVerifies()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using MintedCertificate delegatedResponder = OcspTestFixtures.MintCertificate(
            scenario.Root.Certificate, scenario.Root.Key, "OCSP Verify Delegated ByName", NotBefore, NotAfter, [OcspSigningEkuExtension()]);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            delegatedResponder.Certificate, delegatedResponder.Key, responderIdByKey: false, embeddedCertificates: [delegatedResponder.Certificate],
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.Verified, result.Outcome, "An issuer-issued, EKU-bearing, in-window delegated responder identified byName must verify.");
    }


    /// <summary>A delegated responder identified <c>byKey</c> (a SHA-1 responder key hash) verifies.</summary>
    [TestMethod]
    public async Task DelegatedResponderByKeyWithEkuVerifies()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using MintedCertificate delegatedResponder = OcspTestFixtures.MintCertificate(
            scenario.Root.Certificate, scenario.Root.Key, "OCSP Verify Delegated ByKey", NotBefore, NotAfter, [OcspSigningEkuExtension()]);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            delegatedResponder.Certificate, delegatedResponder.Key, responderIdByKey: true, embeddedCertificates: [delegatedResponder.Certificate],
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.Verified, result.Outcome, "A delegated responder identified byKey (RFC 6960 §4.2.1 KeyHash) must verify identically to byName.");
    }


    /// <summary>A <c>tryLater</c> or <c>unauthorized</c> envelope status is <c>NotSuccessful</c>; no <c>SingleResponse</c> is read.</summary>
    [DataRow(Org.BouncyCastle.Ocsp.OcspRespStatus.TryLater, OcspResponseStatus.TryLater, DisplayName = "TryLater")]
    [DataRow(Org.BouncyCastle.Ocsp.OcspRespStatus.Unauthorized, OcspResponseStatus.Unauthorized, DisplayName = "Unauthorized")]
    [TestMethod]
    public async Task NonSuccessfulEnvelopeStatusesAreNotSuccessful(int oracleStatus, OcspResponseStatus expectedStatus)
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = OcspTestFixtures.MintNonSuccessfulOcspResponse(oracleStatus);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.NotSuccessful, result.Outcome);
        Assert.AreEqual(expectedStatus, result.ResponseStatus);
        Assert.IsNull(result.Single, "A non-successful envelope carries no SingleResponse facts.");
    }


    /// <summary>A <c>responseType</c> other than <c>id-pkix-ocsp-basic</c> is <c>MalformedResponse</c>, per RFC 6960 §4.2.1.</summary>
    [TestMethod]
    public async Task UnrecognisedResponseTypeIsMalformed()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = OcspTestFixtures.BuildResponseWithUnrecognisedResponseType();

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.MalformedResponse, result.Outcome);
    }


    /// <summary>A bit-flipped signature over an otherwise well-formed, correctly-authorised response fails signature verification.</summary>
    [TestMethod]
    public async Task BitFlippedSignatureIsInvalid()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory goodResponse = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);
        using PkiCertificateMemory corrupted = OcspTestFixtures.FlipLastByte(goodResponse);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            corrupted, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.SignatureInvalid, result.Outcome, "A corrupted signature byte must fail signature verification, not silently pass.");
    }


    /// <summary>A response signed by a key with no authorisation path to the issuer — not the issuer itself, not an embedded delegated certificate — is <c>ResponderNotAuthorized</c>.</summary>
    [TestMethod]
    public async Task ResponseSignedByAnUnrelatedKeyIsResponderNotAuthorized()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using MintedCertificate unrelatedRoot = OcspTestFixtures.MintRootCa("OCSP Verify Unrelated Root", NotBefore, NotAfter);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            unrelatedRoot.Certificate, unrelatedRoot.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.ResponderNotAuthorized, result.Outcome, "No identity — the issuer's own, or an embedded certificate's — matches this responderID, so no authorization path can even be attempted.");
    }


    /// <summary>A delegated responder certificate lacking <c>id-kp-OCSPSigning</c> is found but is <c>ResponderCertificateInvalid</c>.</summary>
    [TestMethod]
    public async Task DelegatedResponderWithoutEkuIsResponderCertificateInvalid()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using MintedCertificate delegatedWithoutEku = OcspTestFixtures.MintCertificate(
            scenario.Root.Certificate, scenario.Root.Key, "OCSP Verify Delegated No EKU", NotBefore, NotAfter, []);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            delegatedWithoutEku.Certificate, delegatedWithoutEku.Key, responderIdByKey: false, embeddedCertificates: [delegatedWithoutEku.Certificate],
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.ResponderCertificateInvalid, result.Outcome, "The candidate is issuer-issued and in its validity window, but lacks the OCSP-signing key purpose.");
    }


    /// <summary>A delegated responder certificate expired at <c>validationTime</c> is <c>ResponderCertificateInvalid</c>.</summary>
    [TestMethod]
    public async Task ExpiredDelegatedResponderIsResponderCertificateInvalid()
    {
        DateTimeOffset expiredNotBefore = new(2024, 2, 1, 0, 0, 0, TimeSpan.Zero);
        DateTimeOffset expiredNotAfter = new(2024, 6, 1, 0, 0, 0, TimeSpan.Zero);
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using MintedCertificate expiredDelegate = OcspTestFixtures.MintCertificate(
            scenario.Root.Certificate, scenario.Root.Key, "OCSP Verify Expired Delegate", expiredNotBefore, expiredNotAfter, [OcspSigningEkuExtension()]);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            expiredDelegate.Certificate, expiredDelegate.Key, responderIdByKey: false, embeddedCertificates: [expiredDelegate.Certificate],
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.ResponderCertificateInvalid, result.Outcome, "The candidate has the EKU and is issuer-issued but its own validity window excludes validationTime.");
    }


    /// <summary>A response whose <c>CertID</c> names a different serial number than the request's does not match.</summary>
    [TestMethod]
    public async Task DifferentSerialNumberCertIdIsUnmatched()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        BcBigInteger differentSerial = OcspTestFixtures.ToBouncyCastleCertificate(scenario.Leaf.Certificate).SerialNumber.Add(BcBigInteger.One);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce, serialOverride: differentSerial);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.UnmatchedCertificateId, result.Outcome);
    }


    /// <summary>A response echoing a different nonce than the request carried is a replay signal, not accepted.</summary>
    [TestMethod]
    public async Task MismatchedNonceIsRejected()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using Nonce differentNonce = CryptographicKeyEvents.GenerateNonce(32, Tag.Create(Purpose.Nonce).With(EntropySource.Csprng), BaseMemoryPool.Shared);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: differentNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.NonceMismatch, result.Outcome);
    }


    /// <summary>
    /// A response carrying no nonce, though the request carried one, is rejected by default and accepted only
    /// with <c>allowResponsesWithoutNonce: true</c>.
    /// </summary>
    [TestMethod]
    public async Task AbsentNonceIsRejectedByDefaultAndAcceptedWithTheOptIn()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: null);

        OcspResponseVerificationResult rejected = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(OcspResponseVerificationOutcome.MissingRequiredNonce, rejected.Outcome, "The secure default rejects a nonce-less response when the request carried a nonce.");

        OcspResponseVerificationResult accepted = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, allowResponsesWithoutNonce: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(OcspResponseVerificationOutcome.Verified, accepted.Outcome, "The opt-in flag accepts an RFC 5019-profile pre-produced, nonce-less response.");
    }


    /// <summary>A response evaluated before its <c>thisUpdate</c> is not yet valid.</summary>
    [TestMethod]
    public async Task ValidationBeforeThisUpdateIsStaleOrNotYetValid()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ThisUpdate.AddDays(-1), BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.StaleOrNotYetValid, result.Outcome);
    }


    /// <summary>A response evaluated after its <c>nextUpdate</c> is stale.</summary>
    [TestMethod]
    public async Task ValidationAfterNextUpdateIsStaleOrNotYetValid()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, NextUpdate.AddDays(1), BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.StaleOrNotYetValid, result.Outcome);
    }


    /// <summary>
    /// A response with no <c>nextUpdate</c> at all is rejected by default (no freshness bound) and accepted
    /// only with <c>allowResponsesWithoutNextUpdate: true</c>.
    /// </summary>
    [TestMethod]
    public async Task AbsentNextUpdateIsRejectedByDefaultAndAcceptedWithTheOptIn()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, nextUpdate: null, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult rejected = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(OcspResponseVerificationOutcome.StaleOrNotYetValid, rejected.Outcome, "The secure default rejects a response with no freshness bound.");

        OcspResponseVerificationResult accepted = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, allowResponsesWithoutNextUpdate: true, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(OcspResponseVerificationOutcome.Verified, accepted.Outcome, "The opt-in flag accepts a response that omits nextUpdate.");
    }


    /// <summary>Trailing bytes after the outermost <c>OCSPResponse</c> SEQUENCE closes are <c>MalformedResponse</c>, never silently ignored.</summary>
    [TestMethod]
    public async Task TrailingDataAfterTheOuterSequenceIsMalformed()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory wellFormed = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);
        byte[] withTrailingByte = [.. wellFormed.AsReadOnlySpan(), 0x00];
        using PkiCertificateMemory trailing = OcspTestFixtures.ToResponseCarrier(withTrailingByte);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            trailing, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.MalformedResponse, result.Outcome);
    }


    /// <summary>Trailing content inside <c>tbsResponseData</c>, past its legitimate RFC 6960 §4.2.1 fields, is <c>MalformedResponse</c>.</summary>
    [TestMethod]
    public async Task TrailingDataInsideTbsResponseDataIsMalformed()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory malformed = OcspTestFixtures.BuildStructurallyMalformedBasicResponse(trailingDataInTbsResponseData: true, misTaggedCertsBlock: false);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            malformed, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.MalformedResponse, result.Outcome);
    }


    /// <summary>A mis-tagged <c>certs</c> block (not the conformant <c>[0]</c>) leaves unread bytes and is <c>MalformedResponse</c>.</summary>
    [TestMethod]
    public async Task MisTaggedCertsBlockIsMalformed()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory malformed = OcspTestFixtures.BuildStructurallyMalformedBasicResponse(trailingDataInTbsResponseData: false, misTaggedCertsBlock: true);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            malformed, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.MalformedResponse, result.Outcome);
    }


    /// <summary>
    /// <c>certs</c> is unsigned (RFC 6960 §4.2.1), so an on-path attacker can prepend a decoy certificate
    /// sharing the genuine delegated responder's subject Name. The decoy alone (not issuer-issued) must not
    /// veto the second, genuinely authorised candidate embedded right after it.
    /// </summary>
    [TestMethod]
    public async Task DelegatedResponderDecoyDoesNotVetoALaterAuthorisedCandidate()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using MintedCertificate unrelatedRoot = OcspTestFixtures.MintRootCa("OCSP Verify Decoy Root", NotBefore, NotAfter);
        using MintedCertificate decoy = OcspTestFixtures.MintCertificate(
            unrelatedRoot.Certificate, unrelatedRoot.Key, "OCSP Verify Shared Responder Name", NotBefore, NotAfter, []);
        using MintedCertificate authorised = OcspTestFixtures.MintCertificate(
            scenario.Root.Certificate, scenario.Root.Key, "OCSP Verify Shared Responder Name", NotBefore, NotAfter, [OcspSigningEkuExtension()]);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            authorised.Certificate, authorised.Key, responderIdByKey: false, embeddedCertificates: [decoy.Certificate, authorised.Certificate],
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.Verified, result.Outcome,
            "A decoy identity match that fails authorisation must be stepped over, not treated as the only candidate.");
    }


    /// <summary>
    /// The security-critical half of RFC 6960 §4.2.2.2: a delegated responder embedded certificate that is
    /// found by identity, carries the EKU, and is in its validity window, but was issued by a DIFFERENT CA
    /// than the target's issuer, must still be rejected.
    /// </summary>
    [TestMethod]
    public async Task DelegatedResponderIssuedByAForeignCaWithEkuInWindowIsResponderCertificateInvalid()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using MintedCertificate foreignRoot = OcspTestFixtures.MintRootCa("OCSP Verify Foreign Root", NotBefore, NotAfter);
        using MintedCertificate foreignDelegate = OcspTestFixtures.MintCertificate(
            foreignRoot.Certificate, foreignRoot.Key, "OCSP Verify Foreign Delegate", NotBefore, NotAfter, [OcspSigningEkuExtension()]);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            foreignDelegate.Certificate, foreignDelegate.Key, responderIdByKey: false, embeddedCertificates: [foreignDelegate.Certificate],
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.ResponderCertificateInvalid, result.Outcome,
            "An EKU-bearing, in-window candidate issued by a CA other than the target's issuer must fail the issuedByIssuer conjunct.");
    }


    /// <summary>An embedded certificate carrying trailing content inside its own outer <c>Certificate</c> SEQUENCE (RFC 5280 §4.1.1) is <c>MalformedResponse</c>.</summary>
    [TestMethod]
    public async Task EmbeddedCertificateWithTrailingDataInsideItsOuterSequenceIsMalformed()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory malformed = OcspTestFixtures.BuildResponseWithMalformedEmbeddedCertificate();

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            malformed, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.MalformedResponse, result.Outcome,
            "Trailing bytes inside an embedded certificate's own Certificate SEQUENCE must be rejected, not silently accepted.");
    }


    /// <summary>
    /// The registered RSA verification seam hard-codes public exponent 65537 regardless of a certificate's own
    /// stated exponent; a certificate whose real signing key genuinely uses 65537 but whose DER falsely
    /// declares a different exponent must be rejected rather than verified against a key it does not name.
    /// </summary>
    [TestMethod]
    public async Task RsaSignerWithForgedNonStandardExponentIsRejected()
    {
        (X509Certificate2 rsaRootCertificate, RSA rsaRootKey) = OcspTestFixtures.MintRsaRootCa("OCSP Verify RSA Root", NotBefore, NotAfter);
        try
        {
            using X509Certificate2 forgedExponentRoot = OcspTestFixtures.PatchRsaPublicExponent(rsaRootCertificate, forgedExponent: 65535);
            using PkiCertificateMemory issuer = OcspTestFixtures.ToCertificateCarrier(forgedExponentRoot);
            using MintedCertificate leaf = OcspTestFixtures.MintRootCa("OCSP Verify RSA Leaf Stand-In", NotBefore, NotAfter);
            using PkiCertificateMemory leafCarrier = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
            using OcspRequestContent request = await OcspRequests.CreateAsync(
                leafCarrier, issuer, OcspCertIdDigestAlgorithm.Sha256, BaseMemoryPool.Shared, includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponseRsaSigned(
                leaf.Certificate, forgedExponentRoot, forgedExponentRoot, rsaRootKey, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);

            OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
                response, request, issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(OcspResponseVerificationOutcome.SignatureInvalid, result.Outcome,
                "A response signed with a real 65537-consistent key must not verify once the certificate's own (forged, non-65537) exponent is consulted.");
        }
        finally
        {
            rsaRootCertificate.Dispose();
            rsaRootKey.Dispose();
        }
    }


    /// <summary>
    /// The RSA responder arm accepts moduli by the same policy band the managed CMS verifier uses rather than a
    /// 2048-/4096-bit whitelist with SHA-256 alone: every combined identifier of
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/01.04.03_60/ts_119312v010403p.pdf">
    /// ETSI TS 119 312 V1.4.3</see>'s SHA-2 family verifies, including the 3072-bit key Table 10 makes the
    /// natural post-2025 modulus, and the 2048-bit SHA-256 baseline that predates the widening.
    /// </summary>
    /// <param name="keySizeBits">The RSA modulus size the responder's key is minted at.</param>
    /// <param name="signatureAlgorithm">The BouncyCastle name of the combined RSA signature algorithm the response is signed under.</param>
    [TestMethod]
    [DataRow(2048, "SHA256withRSA")]
    [DataRow(2048, "SHA384withRSA")]
    [DataRow(3072, "SHA512withRSA")]
    public async Task RsaResponderSignaturesInsideTheAcceptanceBandVerify(int keySizeBits, string signatureAlgorithm)
    {
        (X509Certificate2 rsaRootCertificate, RSA rsaRootKey) = OcspTestFixtures.MintRsaRootCa($"OCSP Verify RSA {keySizeBits} Root", NotBefore, NotAfter, keySizeBits);
        try
        {
            using PkiCertificateMemory issuer = OcspTestFixtures.ToCertificateCarrier(rsaRootCertificate);
            using MintedCertificate leaf = OcspTestFixtures.MintRootCa($"OCSP Verify RSA {keySizeBits} Leaf Stand-In", NotBefore, NotAfter);
            using PkiCertificateMemory leafCarrier = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
            using OcspRequestContent request = await OcspRequests.CreateAsync(
                leafCarrier, issuer, OcspCertIdDigestAlgorithm.Sha256, BaseMemoryPool.Shared, includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponseRsaSigned(
                leaf.Certificate, rsaRootCertificate, rsaRootCertificate, rsaRootKey, OcspCertificateStatus.Good, ThisUpdate, NextUpdate,
                signatureAlgorithm);

            OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
                response, request, issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(OcspResponseVerificationOutcome.Verified, result.Outcome,
                $"A {keySizeBits}-bit {signatureAlgorithm} responder signature is inside the acceptance band and must verify.");
        }
        finally
        {
            rsaRootCertificate.Dispose();
            rsaRootKey.Dispose();
        }
    }


    /// <summary>
    /// The band's floor holds on the responder arm exactly as on the managed CMS verifier: a sub-2048-bit
    /// responder key fails closed to <see cref="OcspResponseVerificationOutcome.SignatureInvalid"/> rather than
    /// being verified at a strength ETSI TS 119 312 V1.4.3 no longer lists.
    /// </summary>
    [TestMethod]
    public async Task RsaResponderWithASubFloorKeyIsSignatureInvalid()
    {
        (X509Certificate2 rsaRootCertificate, RSA rsaRootKey) = OcspTestFixtures.MintRsaRootCa("OCSP Verify RSA Sub-Floor Root", NotBefore, NotAfter, keySizeBits: 1024);
        try
        {
            using PkiCertificateMemory issuer = OcspTestFixtures.ToCertificateCarrier(rsaRootCertificate);
            using MintedCertificate leaf = OcspTestFixtures.MintRootCa("OCSP Verify RSA Sub-Floor Leaf Stand-In", NotBefore, NotAfter);
            using PkiCertificateMemory leafCarrier = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
            using OcspRequestContent request = await OcspRequests.CreateAsync(
                leafCarrier, issuer, OcspCertIdDigestAlgorithm.Sha256, BaseMemoryPool.Shared, includeNonce: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponseRsaSigned(
                leaf.Certificate, rsaRootCertificate, rsaRootCertificate, rsaRootKey, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);

            OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
                response, request, issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(OcspResponseVerificationOutcome.SignatureInvalid, result.Outcome,
                "A genuine signature from a sub-floor responder key must fail closed, never verify below the acceptance band.");
        }
        finally
        {
            rsaRootCertificate.Dispose();
            rsaRootKey.Dispose();
        }
    }


    /// <summary>Trailing bytes appended to the content of the outer signature BIT STRING, past the genuine <c>ECDSA-Sig-Value</c> SEQUENCE, must not be silently ignored.</summary>
    [TestMethod]
    public async Task TrailingBytesInsideTheEcdsaSignatureAreRejected()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        PkiCertificateMemory wellFormed = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce);
        using PkiCertificateMemory extended = OcspTestFixtures.AppendByteToBasicResponseSignature(wellFormed);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            extended, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.MalformedResponse, result.Outcome,
            "A genuine signature with trailing bytes appended past its ECDSA-Sig-Value SEQUENCE must be rejected, not silently accepted as still Verified.");
    }


    /// <summary>Trailing bytes inside a nonce extension's <c>extnValue</c>, past the <c>Nonce</c> OCTET STRING it wraps, must not be silently ignored.</summary>
    [TestMethod]
    public async Task TrailingDataInsideTheNonceExtensionValueIsMalformed()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory malformed = OcspTestFixtures.BuildResponseWithMalformedNonceExtension();

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            malformed, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.MalformedResponse, result.Outcome);
    }


    /// <summary>
    /// RFC 6960 §3.2(1) requires only that the CertID CORRESPOND, not that the response echo the request's
    /// exact DER bytes: a responder that re-encodes <c>hashAlgorithm</c> with the tolerated explicit-NULL
    /// parameters form, rather than echoing the request's absent-parameters form, must still match.
    /// </summary>
    [TestMethod]
    public async Task ReEncodedCertIdWithExplicitNullHashParametersStillMatches()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var sha256WithExplicitNull = new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(
            new Org.BouncyCastle.Asn1.DerObjectIdentifier(WellKnownOids.Sha256), Org.BouncyCastle.Asn1.DerNull.Instance);
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce,
            certIdHashAlgorithmOverride: sha256WithExplicitNull);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.Verified, result.Outcome,
            "A CertID differing only in the tolerated absent-vs-NULL hashAlgorithm parameters encoding must still match, not raw-DER-compare unequal.");
    }


    /// <summary>A response carrying an extra, unrelated <c>SingleResponse</c> alongside the one answering the request must still match on the corresponding entry, not reject the whole response for cardinality.</summary>
    [TestMethod]
    public async Task ExtraUnrelatedSingleResponseIsTolerated()
    {
        using OcspVerificationScenario scenario = await BuildScenarioAsync(TestContext.CancellationToken).ConfigureAwait(false);
        BcBigInteger unrelatedSerial = OcspTestFixtures.ToBouncyCastleCertificate(scenario.Leaf.Certificate).SerialNumber.Add(BcBigInteger.ValueOf(12345));
        using PkiCertificateMemory response = OcspTestFixtures.MintOcspResponse(
            scenario.Leaf.Certificate, scenario.Root.Certificate, OcspCertIdDigestAlgorithm.Sha256,
            scenario.Root.Certificate, scenario.Root.Key, responderIdByKey: false, embeddedCertificates: null,
            OcspCertificateStatus.Good, ThisUpdate, NextUpdate, echoNonce: scenario.Request.RequestNonce,
            extraCertIdSerialNumbers: [unrelatedSerial]);

        OcspResponseVerificationResult result = await OcspResponseVerification.VerifyAsync(
            response, scenario.Request, scenario.Issuer, ValidationTime, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OcspResponseVerificationOutcome.Verified, result.Outcome,
            "The requested certificate's own matching SingleResponse must be found and used, even alongside an extra, unrelated entry.");
        Assert.AreEqual(OcspCertificateStatus.Good, result.Single!.Status);
    }


    /// <summary>The <c>id-kp-OCSPSigning</c> Extended Key Usage extension (RFC 6960 §4.2.2.2) a delegated responder certificate must assert.</summary>
    /// <returns>The extension.</returns>
    private static System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension OcspSigningEkuExtension()
    {
        var oids = new System.Security.Cryptography.OidCollection { new System.Security.Cryptography.Oid(WellKnownOids.OcspSigningKeyPurpose) };
        return new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(oids, critical: false);
    }


    /// <summary>Builds the Root CA, target leaf (with an AIA extension so the shape mirrors production use), and a default nonce-carrying request against it.</summary>
    /// <param name="cancellationToken">A cancellation token observed by the request-building digest computation.</param>
    /// <returns>The scenario; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every minted certificate and carrier transfers to the returned OcspVerificationScenario, which the caller disposes; the nested try/catch disposes already-minted parts if a later step throws.")]
    private static async ValueTask<OcspVerificationScenario> BuildScenarioAsync(CancellationToken cancellationToken)
    {
        MintedCertificate root = OcspTestFixtures.MintRootCa("OCSP Verify Root", NotBefore, NotAfter);
        try
        {
            MintedCertificate leaf = OcspTestFixtures.MintCertificate(root.Certificate, root.Key, "OCSP Verify Leaf", NotBefore, NotAfter, []);
            try
            {
                PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(leaf.Certificate);
                try
                {
                    PkiCertificateMemory issuer = OcspTestFixtures.ToCertificateCarrier(root.Certificate);
                    try
                    {
                        OcspRequestContent request = await OcspRequests.CreateAsync(
                            certificate, issuer, OcspCertIdDigestAlgorithm.Sha256, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

                        return new OcspVerificationScenario(root, leaf, certificate, issuer, request);
                    }
                    catch
                    {
                        issuer.Dispose();
                        throw;
                    }
                }
                catch
                {
                    certificate.Dispose();
                    throw;
                }
            }
            catch
            {
                leaf.Dispose();
                throw;
            }
        }
        catch
        {
            root.Dispose();
            throw;
        }
    }


    /// <summary>A minted Root CA and leaf, the leaf's certificate carrier, its issuer carrier, and a default OCSP request against it — disposed together.</summary>
    /// <param name="Root">The Root CA.</param>
    /// <param name="Leaf">The target leaf certificate.</param>
    /// <param name="Certificate">The leaf's DER carrier.</param>
    /// <param name="Issuer">The Root CA's DER carrier.</param>
    /// <param name="Request">The default nonce-carrying request against <see cref="Certificate"/>.</param>
    private sealed record OcspVerificationScenario(
        MintedCertificate Root,
        MintedCertificate Leaf,
        PkiCertificateMemory Certificate,
        PkiCertificateMemory Issuer,
        OcspRequestContent Request): IDisposable
    {
        /// <inheritdoc/>
        public void Dispose()
        {
            Request.Dispose();
            Issuer.Dispose();
            Certificate.Dispose();
            Leaf.Dispose();
            Root.Dispose();
        }
    }
}

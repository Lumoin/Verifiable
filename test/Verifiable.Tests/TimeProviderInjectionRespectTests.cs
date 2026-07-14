using System.Buffers;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.Federation;
using Verifiable.Tests.Fido2;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests;

/// <summary>
/// Cross-domain proof that a caller-supplied <see cref="TimeProvider"/> is genuinely threaded end to
/// end by the surfaces that accept one, rather than merely accepted and left unused in favor of
/// <see cref="TimeProvider.System"/>.
/// </summary>
/// <remarks>
/// Every test here injects a <see cref="FakeTimeProvider"/> pinned to <see cref="TestClock.CanonicalEpoch"/>
/// — an instant far from any real "now" — and asserts the surface's time-bearing observable equals
/// that pinned instant, or flips a verdict exactly at the boundary that instant defines. An unthreaded
/// <see cref="TimeProvider.System"/> read would land nowhere near <see cref="TestClock.CanonicalEpoch"/>,
/// so a broken injection path fails these tests outright rather than as an intermittent near-miss.
/// </remarks>
[TestClass]
internal sealed class TimeProviderInjectionRespectTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <see cref="ClaimIssuer{TInput}.GenerateClaimsAsync"/> stamps
    /// <see cref="ClaimIssueResult.CreationTimestampInUtc"/> from the constructor-injected
    /// <see cref="TimeProvider"/> rather than <see cref="TimeProvider.System"/>.
    /// </summary>
    [TestMethod]
    public async Task ClaimIssuerStampsCreationTimestampFromInjectedTimeProvider()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        var issuer = new ClaimIssuer<string>(
            "time-provider-injection-respect-claim-issuer", new List<ClaimDelegate<string>>(), timeProvider);

        ClaimIssueResult result = await issuer.GenerateClaimsAsync(
            "irrelevant-input", "time-provider-injection-respect-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TestClock.CanonicalEpoch.UtcDateTime, result.CreationTimestampInUtc);
    }


    /// <summary>
    /// The <see cref="TimeProvider"/>-taking <see cref="Fido2RegistrationVerifier.VerifyAsync(string, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, RegistrationCeremonyInput, SelectAttestationVerifierDelegate, IsCredentialIdUniqueDelegate, IReadOnlyList{PkiCertificateMemory}, TimeProvider, string, MemoryPool{byte}, IReadOnlyList{string}?, string?, bool, CancellationToken)"/>
    /// overload reads its injected provider once and threads that single instant to BOTH
    /// <c>validationTime</c> and the internally-built <see cref="ClaimIssuer{TInput}"/>: a minimal
    /// none-attestation registration run through this overload succeeds identically — same
    /// acceptability, same <see cref="ClaimIssueResult.CreationTimestampInUtc"/> — to the same
    /// ceremony run through the explicit-instant overload with both <c>validationTime</c> and
    /// <c>timeProvider</c> pinned to the same instant by hand.
    /// </summary>
    [TestMethod]
    public async Task Fido2RegistrationVerifierTimeProviderOverloadThreadsToValidationTimeAndClaimIssuer()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        const string challenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";
        const string origin = "https://relyingparty.example";

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = Fido2RegistrationVerifierTests.BuildRegistrationAuthenticatorData(
            rpIdHash, Guid.NewGuid(), credentialPublicKey, [0x01, 0x02, 0x03, 0x04], out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(challenge, origin);
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);

        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

        Fido2RegistrationOutcome outcomeViaTimeProvider = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.None,
            attestationStatement: new byte[] { Fido2RegistrationVerifierTests.CanonicalEmptyMap },
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            Fido2RegistrationVerifierTests.AlwaysUnique,
            trustAnchors: [],
            timeProvider,
            correlationId: "time-provider-injection-respect-registration-via-provider",
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        Fido2RegistrationOutcome outcomeViaExplicitInstant = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.None,
            attestationStatement: new byte[] { Fido2RegistrationVerifierTests.CanonicalEmptyMap },
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            Fido2RegistrationVerifierTests.AlwaysUnique,
            trustAnchors: [],
            TestClock.CanonicalEpoch,
            correlationId: "time-provider-injection-respect-registration-explicit",
            BaseMemoryPool.Shared,
            timeProvider: timeProvider,
            cancellationToken: TestContext.CancellationToken);

        try
        {
            Assert.IsTrue(outcomeViaTimeProvider.IsAcceptable, "The TimeProvider-overload registration should succeed against a valid none-attestation ceremony.");
            Assert.AreEqual(outcomeViaExplicitInstant.IsAcceptable, outcomeViaTimeProvider.IsAcceptable);
            Assert.AreEqual(TestClock.CanonicalEpoch.UtcDateTime, outcomeViaTimeProvider.Claims.CreationTimestampInUtc);
            Assert.AreEqual(outcomeViaExplicitInstant.Claims.CreationTimestampInUtc, outcomeViaTimeProvider.Claims.CreationTimestampInUtc);
        }
        finally
        {
            outcomeViaTimeProvider.CredentialRecord?.Dispose();
            outcomeViaExplicitInstant.CredentialRecord?.Dispose();
        }
    }


    /// <summary>
    /// The <see cref="TimeProvider"/>-taking <see cref="MetadataBlobVerificationRequest"/> constructor
    /// reads its injected provider once for <see cref="MetadataBlobVerificationRequest.ValidationTime"/>:
    /// a BLOB whose <c>nextUpdate</c> falls on the same calendar date as the injected instant verifies,
    /// while the same BLOB minted with <c>nextUpdate</c> one day earlier is rejected as stale — the
    /// staleness verdict flips purely because of the injected clock.
    /// </summary>
    [TestMethod]
    public async Task MetadataBlobVerificationRequestTimeProviderCtorDrivesStalenessBoundary()
    {
        using MdsPkiFixture fixture = MetadataBlobTestVectors.CreateMdsPkiFixture();
        using PkiCertificateMemory rootPki = MetadataBlobTestVectors.ToPkiCertificateMemory(fixture.RootCertificate.RawData);
        var tenantId = new TenantId("time-provider-injection-respect-mds");

        byte[] justInsideBlobBytes = BuildMetadataBlob(fixture, nextUpdate: "2026-06-01");
        byte[] justOutsideBlobBytes = BuildMetadataBlob(fixture, nextUpdate: "2026-05-31");

        VerifyMetadataBlobAsyncDelegate verify = MetadataBlobVerification.Build(MetadataBlobReader.Read, MicrosoftX509Functions.ValidateChainAsync);

        var justInsideRequest = new MetadataBlobVerificationRequest(
            justInsideBlobBytes, [rootPki], new FakeTimeProvider(TestClock.CanonicalEpoch), tenantId,
            MetadataBlobSerialNumberPolicy.NotTracked, MetadataBlobRevocationPolicy.NotChecked, BaseMemoryPool.Shared);
        var justOutsideRequest = new MetadataBlobVerificationRequest(
            justOutsideBlobBytes, [rootPki], new FakeTimeProvider(TestClock.CanonicalEpoch), tenantId,
            MetadataBlobSerialNumberPolicy.NotTracked, MetadataBlobRevocationPolicy.NotChecked, BaseMemoryPool.Shared);

        MetadataBlobResult justInsideResult = await verify(justInsideRequest, TestContext.CancellationToken);
        MetadataBlobResult justOutsideResult = await verify(justOutsideRequest, TestContext.CancellationToken);

        Assert.IsInstanceOfType<VerifiedMetadataBlobResult>(justInsideResult, "nextUpdate on the same calendar date as the injected instant must not be stale.");
        ((VerifiedMetadataBlobResult)justInsideResult).Blob.Dispose();

        Assert.IsInstanceOfType<RejectedMetadataBlobResult>(justOutsideResult, "nextUpdate one day before the injected instant must be stale.");
        Assert.AreEqual(Fido2MetadataErrors.BlobStale.Code, ((RejectedMetadataBlobResult)justOutsideResult).Error.Code);
    }


    /// <summary>
    /// <see cref="EntityStatementValidationContext.Now"/>, when populated from the injected
    /// <see cref="TimeProvider"/> rather than <see cref="TimeProvider.System"/>, drives the
    /// <see cref="WellKnownFederationClaimIds.ExpInFuture"/> verdict: a statement whose <c>exp</c> is
    /// one minute after the injected instant passes, while the same statement minted one minute
    /// before it fails.
    /// </summary>
    [TestMethod]
    public async Task EntityStatementValidatorExpInFutureTracksInjectedTimeProviderNow()
    {
        DateTimeOffset now = new FakeTimeProvider(TestClock.CanonicalEpoch).GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/time-provider-injection-respect"));

        MintedStatement notYetExpired = await FederationTestRing.MintEntityConfigurationAsync(
            node, issuedAt: now.AddMinutes(-1), expiresAt: now.AddMinutes(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        bool notYetExpiredSignatureVerified = await FederationTestRing.VerifyAsync(
            node, notYetExpired.CompactJws, TestContext.CancellationToken).ConfigureAwait(false);

        MintedStatement alreadyExpired = await FederationTestRing.MintEntityConfigurationAsync(
            node, issuedAt: now.AddMinutes(-10), expiresAt: now.AddMinutes(-1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        bool alreadyExpiredSignatureVerified = await FederationTestRing.VerifyAsync(
            node, alreadyExpired.CompactJws, TestContext.CancellationToken).ConfigureAwait(false);

        EntityStatementValidator validator = EntityStatementValidator.Default();

        ClaimIssueResult notYetExpiredResult = await validator.ValidateAsync(
            new EntityStatementValidationContext
            {
                Header = notYetExpired.Header,
                Statement = notYetExpired.Statement,
                SignatureVerified = notYetExpiredSignatureVerified,
                Now = now,
                ClockSkew = TimeSpan.Zero
            },
            "time-provider-injection-respect-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        ClaimIssueResult alreadyExpiredResult = await validator.ValidateAsync(
            new EntityStatementValidationContext
            {
                Header = alreadyExpired.Header,
                Statement = alreadyExpired.Statement,
                SignatureVerified = alreadyExpiredSignatureVerified,
                Now = now,
                ClockSkew = TimeSpan.Zero
            },
            "time-provider-injection-respect-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Claim notYetExpiredExpClaim = notYetExpiredResult.Claims.Single(claim => claim.Id.Code == WellKnownFederationClaimIds.ExpInFuture.Code);
        Claim alreadyExpiredExpClaim = alreadyExpiredResult.Claims.Single(claim => claim.Id.Code == WellKnownFederationClaimIds.ExpInFuture.Code);

        Assert.AreEqual(ClaimOutcome.Success, notYetExpiredExpClaim.Outcome, "exp one minute after the injected Now must pass.");
        Assert.AreEqual(ClaimOutcome.Failure, alreadyExpiredExpClaim.Outcome, "exp one minute before the injected Now must fail.");
    }


    /// <summary>Builds a single-entry, ES256-signed Metadata BLOB carrying <paramref name="nextUpdate"/>.</summary>
    /// <param name="fixture">The MDS root/signer PKI to sign under.</param>
    /// <param name="nextUpdate">The <c>nextUpdate</c> ISO-8601 date string.</param>
    /// <returns>The compact-JWS BLOB bytes.</returns>
    private static byte[] BuildMetadataBlob(MdsPkiFixture fixture, string nextUpdate)
    {
        string entryJson = MetadataBlobTestVectors.BuildEntryJson(aaguid: Guid.NewGuid());
        string headerJson = MetadataBlobTestVectors.BuildHeaderJson(WellKnownJwaValues.Es256, [fixture.SigningCertificate.RawData]);
        string payloadJson = MetadataBlobTestVectors.BuildPayloadJson(1, nextUpdate, [entryJson]);

        return MetadataBlobTestVectors.BuildBlobBytes(headerJson, payloadJson, data => MetadataBlobTestVectors.SignEs256(fixture.SigningKey, data));
    }
}

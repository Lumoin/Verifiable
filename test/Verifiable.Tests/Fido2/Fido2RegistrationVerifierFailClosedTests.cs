using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="Fido2RegistrationVerifier"/>'s fail-closed backstop: the outer
/// <c>catch(Exception)</c> in its private <c>ResolveAttestationResultAsync</c> that maps any
/// unexpected exception a registered <see cref="AttestationVerifyDelegate"/> throws to
/// <see cref="Fido2AttestationErrors.VerificationFailed"/> rather than letting it escape the whole
/// registration ceremony.
/// </summary>
/// <remarks>
/// <see cref="Fido2AttestationErrors.VerificationFailed"/>'s own doc comment names this exact
/// contract: "the fail-closed backstop <c>Fido2RegistrationVerifier</c> applies if [a registered
/// <see cref="AttestationVerifyDelegate"/>] throws anyway." Every other negative test in this suite
/// drives a graceful <see cref="RejectedAttestationResult"/> from inside a format's own
/// <c>VerifyAsync</c> (a documented <see cref="Fido2FormatException"/> caught internally); this file
/// is the one place a registered delegate itself misbehaves and throws an entirely different
/// exception type, reaching the orchestrator's own backstop instead.
/// </remarks>
[TestClass]
internal sealed class Fido2RegistrationVerifierFailClosedTests
{
    /// <summary>The base64url-encoded challenge a valid ceremony embeds and expects.</summary>
    private const string ValidChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";

    /// <summary>The relying party origin a valid ceremony embeds and expects.</summary>
    private const string ValidOrigin = "https://relyingparty.example";

    /// <summary>The correlation identifier every verification call in this fixture uses.</summary>
    private const string CorrelationId = "fido2-registration-verifier-fail-closed-test-correlation";

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>An <see cref="IsCredentialIdUniqueDelegate"/> reporting every credential ID as unique.</summary>
    private static IsCredentialIdUniqueDelegate AlwaysUnique { get; } = static (_, _) => ValueTask.FromResult(true);


    /// <summary>
    /// A registered <see cref="AttestationVerifyDelegate"/> that throws an exception unrelated to
    /// the documented <see cref="Fido2FormatException"/> contract is rejected with
    /// <see cref="Fido2AttestationErrors.VerificationFailed"/> — the exception never escapes
    /// <see cref="Fido2RegistrationVerifier.VerifyAsync"/> — and the ceremony is unacceptable with no
    /// credential record built.
    /// </summary>
    [TestMethod]
    public async Task AttestationVerifierThrowingAnUnexpectedExceptionIsRejectedWithVerificationFailed()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        Guid aaguid = Guid.NewGuid();
        byte[] credentialId = [0x01, 0x02, 0x03, 0x04];
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = Fido2RegistrationVerifierTests.BuildRegistrationAuthenticatorData(rpIdHash, aaguid, credentialPublicKey, credentialId, out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(ValidChallenge, ValidOrigin);
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);

        AttestationVerifyDelegate throwingVerify = static (_, _) => throw new InvalidOperationException("Simulated unexpected attestation verifier failure.");
        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, throwingVerify));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.Packed,
            attestationStatement: ReadOnlyMemory<byte>.Empty,
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        RejectedAttestationResult rejected = Assert.IsInstanceOfType<RejectedAttestationResult>(outcome.AttestationResult);
        Assert.AreEqual(Fido2AttestationErrors.VerificationFailed.Code, rejected.Error.Code);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.IsNull(outcome.CredentialRecord);
    }


    /// <summary>
    /// The same fail-closed backstop applies when the registered delegate's exception surfaces only
    /// after genuine asynchronous work has started (an <c>await</c> inside the delegate throws),
    /// not only when the delegate throws synchronously before returning any
    /// <see cref="ValueTask{TResult}"/> — both shapes reach the same outer <c>catch(Exception)</c>.
    /// </summary>
    [TestMethod]
    public async Task AttestationVerifierThrowingAfterAnAwaitIsRejectedWithVerificationFailed()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> credentialKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(credentialKeys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);
        MdocTestFixtures.DisposeKeyMaterial(credentialKeys);
        Guid aaguid = Guid.NewGuid();
        byte[] credentialId = [0x05, 0x06, 0x07, 0x08];
        byte[] rpIdHash = Fido2TestVectors.CreateRpIdHash();

        using AuthenticatorData authenticatorData = Fido2RegistrationVerifierTests.BuildRegistrationAuthenticatorData(rpIdHash, aaguid, credentialPublicKey, credentialId, out byte[] authDataBytes);
        byte[] clientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(ValidChallenge, ValidOrigin);
        using RegistrationCeremonyInput ceremonyInput = Fido2CeremonyInputFactory.CreateValidRegistrationInput(
            clientDataOverride: ClientDataJsonReader.Read(clientDataJson),
            authenticatorDataOverride: authenticatorData,
            expectedRpIdHash: rpIdHash);

        SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, ThrowAfterAwaitAsync));

        Fido2RegistrationOutcome outcome = await Fido2RegistrationVerifier.VerifyAsync(
            WellKnownWebAuthnAttestationFormats.Packed,
            attestationStatement: ReadOnlyMemory<byte>.Empty,
            authDataBytes,
            clientDataJson,
            ceremonyInput,
            selectVerifier,
            AlwaysUnique,
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            CorrelationId,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken);

        RejectedAttestationResult rejected = Assert.IsInstanceOfType<RejectedAttestationResult>(outcome.AttestationResult);
        Assert.AreEqual(Fido2AttestationErrors.VerificationFailed.Code, rejected.Error.Code);
        Assert.IsFalse(outcome.IsAcceptable);
        Assert.IsNull(outcome.CredentialRecord);

        //A malformed-statement rejection would also be RejectedAttestationResult; pinning the exact
        //error code above already distinguishes this from the format's own graceful failure path, but
        //this negative assertion documents that distinction explicitly.
        Assert.AreNotEqual(Fido2AttestationErrors.MalformedStatement.Code, rejected.Error.Code);
    }


    /// <summary>An <see cref="AttestationVerifyDelegate"/> that yields control once, then throws.</summary>
    private static async ValueTask<AttestationResult> ThrowAfterAwaitAsync(AttestationVerificationRequest request, CancellationToken cancellationToken)
    {
        await Task.Yield();
        throw new InvalidOperationException("Simulated unexpected attestation verifier failure after an await.");
    }
}

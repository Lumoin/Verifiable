using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The capstone firewalled flow tests: three rounds over the real, unmodified <c>ApduExecutor</c>/
/// <c>ApduDevice</c> transport stack (<see cref="CtapWave2TransportHarness"/>), each driven by
/// <see cref="CtapAuthenticatorMakeCredentialClient"/>/<see cref="CtapAuthenticatorGetAssertionClient"/>/
/// <see cref="CtapAuthenticatorGetNextAssertionClient"/> and ending at the SHIPPED
/// <see cref="Fido2RegistrationVerifier"/>/<see cref="Fido2AssertionVerifier"/> orchestrators — a full
/// <c>fmt=none</c> registration-then-assertion ceremony, a packed self-attestation registration, and a
/// two-account resident <c>authenticatorGetAssertion</c>/<c>authenticatorGetNextAssertion</c> sequence.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Firewalled.</strong> The relying-party side reconstructs every ceremony input from wire
/// bytes only — the decoded CTAP responses and an independently-computed <c>rpIdHash</c>
/// (<see cref="CtapWave2CapstoneFixtures.ComputeExpectedRpIdHash"/>, from the known <c>rpId</c> string,
/// never read back from the simulator's own state) — mirroring
/// <c>CtapAuthenticatorGetInfoFlowTests</c>'s own firewalling. The credential's private key never
/// leaves the simulator: only the minted COSE public key and the assertion's signature bytes cross the
/// wire.
/// </para>
/// <para>
/// <strong>Independent oracle.</strong> Beyond the SHIPPED <see cref="Fido2AssertionVerifier"/>, the
/// assertion signature is additionally checked with the framework's own <see cref="ECDsa"/>, converting
/// the stored COSE_Key to raw EC coordinates itself rather than through this library's own COSE-to-key
/// conversion path used elsewhere — the same "second, independently implemented verifier" pattern
/// <c>Fido2CredentialSignerTests</c> and <c>Fido2RegistrationVerifierTests</c> already establish for this
/// codebase, applied here to a signature that travelled over a live simulated transport rather than one
/// signed directly in-process.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CtapAuthenticatorCapstoneFlowTests
{
    /// <summary>The relying party identifier this capstone's ceremonies are scoped to.</summary>
    private const string RpId = "capstone.example";

    /// <summary>The relying party origin this capstone's ceremonies embed and expect.</summary>
    private const string Origin = "https://capstone.example";

    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A registration ceremony followed by an authentication ceremony both succeed end to end over the
    /// real APDU transport: the minted discoverable credential's public key verifies the assertion
    /// signature through the shipped verifier and an independent <see cref="ECDsa"/> oracle, and the
    /// asserted <c>signCount</c> (1) exceeds the stored value (0), exercising the RP's clone-detection
    /// regression check on its normal, non-triggering path.
    /// </summary>
    [TestMethod]
    public async Task RegistrationThenAssertionRoundTripSucceedsOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("capstone-authenticator");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken);

        byte[] userIdBytes = CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x70);
        UserHandle registrationUserId = UserHandle.Create(userIdBytes, pool);

        var registrationOptionsBuilder = new Fido2RegistrationOptionsBuilder();
        PublicKeyCredentialCreationOptions creationOptions = await registrationOptionsBuilder.BuildAsync(
            rpId: RpId,
            rpName: "Capstone RP",
            userId: registrationUserId,
            userName: "alice",
            userDisplayName: "Alice Example",
            pool: pool,
            residentKey: ResidentKeyRequirement.Required,
            requireResidentKey: true,
            cancellationToken: cancellationToken);

        byte[] createClientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(
            new ClientData(WellKnownClientDataTypes.Create, creationOptions.Challenge!, Origin));
        DigestValue createClientDataHash = Fido2ClientDataHash.Compute(createClientDataJson, pool);

        //Requests the none format explicitly: wave 3's authenticator default (attestationFormatsPreference
        //absent) is packed self-attestation, but this capstone's registration-verifier assertions target
        //the none shape specifically — the packed self-attestation round is a distinct capstone extension.
        CtapMakeCredentialRequest makeCredentialRequest = CtapWave2CapstoneFixtures.BuildMakeCredentialRequest(
            creationOptions, createClientDataHash, pool, attestationFormatsPreference: [WellKnownWebAuthnAttestationFormats.None]);
        registrationUserId.Dispose();

        CtapMakeCredentialResponse makeCredentialResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, makeCredentialRequest, CtapMakeCredentialResponseCborReader.Read,
            pool, cancellationToken);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(makeCredentialRequest);

        TaggedMemory<byte> attestationObject = CtapAuthenticatorMakeCredentialClient.BuildAttestationObject(
            makeCredentialResponse, AttestationObjectCborWriter.Write);

        AttestationObjectParts attestationParts = AttestationObjectCborReader.Parse(attestationObject.Memory);

        //Ownership of the parsed authenticator data and the independently computed rpIdHash transfers
        //directly into the ceremony input, which disposes both — the single-owner dispose tree the
        //project convention favors over a separate using declaration per carrier.
        AuthenticatorData registrationAuthenticatorData = AuthenticatorDataReader.Read(
            attestationParts.AuthenticatorData, CredentialPublicKeyCborReader.Read, pool);

        using RegistrationCeremonyInput registrationCeremonyInput = new()
        {
            ClientData = ClientDataJsonReader.Read(createClientDataJson),
            AuthenticatorData = registrationAuthenticatorData,
            ExpectedChallenge = creationOptions.Challenge!,
            ExpectedOrigins = new HashSet<string> { Origin },
            ExpectedRpIdHash = CtapWave2CapstoneFixtures.ComputeExpectedRpIdHash(RpId, pool),
            UserVerification = UserVerificationRequirement.Discouraged,
            AllowedAlgorithms = [WellKnownCoseAlgorithms.Es256]
        };

        SelectAttestationVerifierDelegate selectAttestationVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.None, NoneAttestation.Build()));

        Fido2RegistrationOutcome registrationOutcome = await Fido2RegistrationVerifier.VerifyAsync(
            attestationParts.Format,
            attestationParts.AttestationStatement,
            attestationParts.AuthenticatorData,
            createClientDataJson,
            registrationCeremonyInput,
            selectAttestationVerifier,
            static (_, _) => ValueTask.FromResult(true),
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            correlationId: "ctap-wave2-capstone-registration",
            pool,
            transports: ["nfc"],
            cancellationToken: cancellationToken);

        Assert.IsInstanceOfType<NoneAttestationResult>(registrationOutcome.AttestationResult);
        Assert.IsTrue(registrationOutcome.IsAcceptable, "The registration ceremony must be acceptable.");

        using Fido2CredentialRecord? credentialRecord = registrationOutcome.CredentialRecord;
        Assert.IsNotNull(credentialRecord);
        Assert.AreEqual(0u, credentialRecord.SignCount);

        var assertionOptionsBuilder = new Fido2AssertionOptionsBuilder();
        PublicKeyCredentialRequestOptions requestOptions = await assertionOptionsBuilder.BuildAsync(
            rpId: RpId,
            pool: pool,
            allowedCredentials: null,
            userVerification: UserVerificationRequirement.Discouraged,
            cancellationToken: cancellationToken);

        byte[] getClientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(
            new ClientData(WellKnownClientDataTypes.Get, requestOptions.Challenge!, Origin));
        DigestValue getClientDataHash = Fido2ClientDataHash.Compute(getClientDataJson, pool);

        CtapGetAssertionRequest getAssertionRequest = CtapWave2CapstoneFixtures.BuildGetAssertionRequest(requestOptions, getClientDataHash);

        CtapGetAssertionResponse getAssertionResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, getAssertionRequest, CtapGetAssertionResponseCborReader.Read,
            pool, cancellationToken);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(getAssertionRequest);

        //Ownership of the parsed authenticator data, the response's credential identifier and user
        //handle, and the independently computed rpIdHash all transfer directly into the ceremony
        //input, which disposes every one of them.
        AuthenticatorData assertionAuthenticatorData = AuthenticatorDataReader.Read(
            getAssertionResponse.AuthData, CredentialPublicKeyCborReader.Read, pool);

        Assert.IsNotNull(getAssertionResponse.User, "The discoverable-credential path must return a user entity.");

        UserHandle responseUserHandle = getAssertionResponse.User!.Id;
        UserHandle storedUserHandle = UserHandle.Create(userIdBytes, pool);

        using AssertionCeremonyInput assertionCeremonyInput = new()
        {
            ClientData = ClientDataJsonReader.Read(getClientDataJson),
            AuthenticatorData = assertionAuthenticatorData,
            ExpectedChallenge = requestOptions.Challenge!,
            ExpectedOrigins = new HashSet<string> { Origin },
            ExpectedRpIdHash = CtapWave2CapstoneFixtures.ComputeExpectedRpIdHash(RpId, pool),
            UserVerification = UserVerificationRequirement.Discouraged,
            AllowedCredentialIds = null,
            CredentialId = getAssertionResponse.Credential.Id,
            StoredSignCount = credentialRecord.SignCount,
            StoredUvInitialized = credentialRecord.UvInitialized,
            ResponseUserHandle = responseUserHandle,
            StoredUserHandle = storedUserHandle
        };

        Fido2AssertionOutcome assertionOutcome = await Fido2AssertionVerifier.VerifyAsync(
            credentialRecord.PublicKey,
            getAssertionResponse.Signature,
            getAssertionResponse.AuthData,
            getClientDataJson,
            assertionCeremonyInput,
            correlationId: "ctap-wave2-capstone-assertion",
            pool,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch),
            cancellationToken: cancellationToken);

        Assert.IsTrue(assertionOutcome.SignatureValid, "The production Fido2AssertionVerifier must accept the CTAP-signed assertion.");
        Assert.IsTrue(assertionOutcome.IsAcceptable);
        Assert.AreEqual(1u, assertionAuthenticatorData.SignCount, "The signCount observed on the wire must be 1: exactly one successful assertion since registration.");
        Assert.IsGreaterThan(credentialRecord.SignCount, assertionAuthenticatorData.SignCount);

        bool independentlyVerified = VerifyAssertionSignatureIndependently(
            credentialRecord.PublicKey, getAssertionResponse.AuthData, getClientDataJson, getAssertionResponse.Signature, pool);
        Assert.IsTrue(independentlyVerified, "An independent ECDsa oracle must accept the same signature the shipped verifier accepted.");
    }


    /// <summary>
    /// A registration whose <c>attestationFormatsPreference</c> (0x0B) is absent mints a packed
    /// self-attestation statement — the authenticator's own choice per CTAP 2.3 section 6.1.2 step 17's
    /// first bullet — accepted by the SHIPPED <see cref="Fido2RegistrationVerifier"/> with
    /// <see cref="RegistrationCeremonyInput.AcceptSelfAttestation"/> left at its default, the first
    /// exercise of <see cref="PackedAttestation.VerifySelfAsync"/> against bytes that travelled over the
    /// real APDU transport rather than a hand-built statement.
    /// </summary>
    [TestMethod]
    public async Task PackedSelfAttestationRegistrationVerifiesOverRealApduTransport()
    {
        const string RpId = "wave3-packed.example";
        const string Origin = "https://wave3-packed.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("capstone-packed-authenticator");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken);

        byte[] userIdBytes = CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x90);
        UserHandle registrationUserId = UserHandle.Create(userIdBytes, pool);

        var registrationOptionsBuilder = new Fido2RegistrationOptionsBuilder();
        PublicKeyCredentialCreationOptions creationOptions = await registrationOptionsBuilder.BuildAsync(
            rpId: RpId,
            rpName: "Wave 3 Packed RP",
            userId: registrationUserId,
            userName: "packed-user",
            userDisplayName: "Packed Self-Attestation User",
            pool: pool,
            residentKey: ResidentKeyRequirement.Discouraged,
            requireResidentKey: false,
            cancellationToken: cancellationToken);

        byte[] createClientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(
            new ClientData(WellKnownClientDataTypes.Create, creationOptions.Challenge!, Origin));
        DigestValue createClientDataHash = Fido2ClientDataHash.Compute(createClientDataJson, pool);

        //attestationFormatsPreference stays absent: CTAP 2.3 section 6.1.2 step 17's first bullet makes
        //packed self-attestation this authenticator's own default choice.
        CtapMakeCredentialRequest makeCredentialRequest = CtapWave2CapstoneFixtures.BuildMakeCredentialRequest(
            creationOptions, createClientDataHash, pool);
        registrationUserId.Dispose();

        CtapMakeCredentialResponse makeCredentialResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, makeCredentialRequest, CtapMakeCredentialResponseCborReader.Read,
            pool, cancellationToken);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(makeCredentialRequest);

        Assert.AreEqual(WellKnownWebAuthnAttestationFormats.Packed, makeCredentialResponse.Fmt);

        TaggedMemory<byte> attestationObject = CtapAuthenticatorMakeCredentialClient.BuildAttestationObject(
            makeCredentialResponse, AttestationObjectCborWriter.Write);

        AttestationObjectParts attestationParts = AttestationObjectCborReader.Parse(attestationObject.Memory);

        AuthenticatorData registrationAuthenticatorData = AuthenticatorDataReader.Read(
            attestationParts.AuthenticatorData, CredentialPublicKeyCborReader.Read, pool);

        using RegistrationCeremonyInput registrationCeremonyInput = new()
        {
            ClientData = ClientDataJsonReader.Read(createClientDataJson),
            AuthenticatorData = registrationAuthenticatorData,
            ExpectedChallenge = creationOptions.Challenge!,
            ExpectedOrigins = new HashSet<string> { Origin },
            ExpectedRpIdHash = CtapWave2CapstoneFixtures.ComputeExpectedRpIdHash(RpId, pool),
            UserVerification = UserVerificationRequirement.Discouraged,
            AllowedAlgorithms = [WellKnownCoseAlgorithms.Es256]
        };

        SelectAttestationVerifierDelegate selectAttestationVerifier = Fido2AttestationSelectors.FromFormats(
            (WellKnownWebAuthnAttestationFormats.Packed, PackedAttestation.Build(
                PackedAttestationStatementCborReader.Parse,
                MicrosoftX509Functions.ValidateChainAsync,
                MicrosoftX509Functions.ReadCertificateProfile,
                MicrosoftX509Functions.ReadCertificateExtensionValue)));

        Fido2RegistrationOutcome registrationOutcome = await Fido2RegistrationVerifier.VerifyAsync(
            attestationParts.Format,
            attestationParts.AttestationStatement,
            attestationParts.AuthenticatorData,
            createClientDataJson,
            registrationCeremonyInput,
            selectAttestationVerifier,
            static (_, _) => ValueTask.FromResult(true),
            trustAnchors: [],
            validationTime: TestClock.CanonicalEpoch,
            correlationId: "ctap-wave3-capstone-packed-registration",
            pool,
            transports: ["nfc"],
            cancellationToken: cancellationToken);

        Assert.IsInstanceOfType<SelfAttestationResult>(registrationOutcome.AttestationResult);
        Assert.IsTrue(registrationOutcome.IsAcceptable, "A packed self-attestation registration must be acceptable with AcceptSelfAttestation left at its default.");

        using Fido2CredentialRecord? credentialRecord = registrationOutcome.CredentialRecord;
        Assert.IsNotNull(credentialRecord);

        PackedAttestationStatement statement = PackedAttestationStatementCborReader.Parse(attestationParts.AttestationStatement, pool);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, statement.Alg);
        Assert.IsNull(statement.X5c, "Self-attestation must omit x5c entirely on the wire.");

        bool independentlyVerified = VerifyAssertionSignatureIndependently(
            credentialRecord.PublicKey, attestationParts.AuthenticatorData, createClientDataJson, statement.Signature, pool);
        Assert.IsTrue(independentlyVerified, "An independent ECDsa oracle must accept the same self-attestation signature the shipped verifier accepted.");
    }


    /// <summary>
    /// Two resident credentials for the same relying party but different users produce a multi-account
    /// <c>authenticatorGetAssertion</c> response (<c>numberOfCredentials: 2</c>, the most recently minted
    /// credential, <c>user</c> carrying <c>id</c> only) followed by an <c>authenticatorGetNextAssertion</c>
    /// response for the older credential — both signatures accepted by the SHIPPED
    /// <see cref="Fido2AssertionVerifier"/> over the real APDU transport.
    /// </summary>
    [TestMethod]
    public async Task MultiAccountGetAssertionThenGetNextAssertionBothVerifyOverRealApduTransport()
    {
        const string RpId = "wave3-multi-account.example";
        const string Origin = "https://wave3-multi-account.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("capstone-multi-account-authenticator");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken);

        byte[] olderUserId = CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xB0);
        byte[] newerUserId = CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xB1);

        CtapWave2RegisteredCredential olderCredential = await RegisterResidentCredentialOverRealTransportAsync(harness, pool, RpId, olderUserId, cancellationToken);
        CtapWave2RegisteredCredential newerCredential = await RegisterResidentCredentialOverRealTransportAsync(harness, pool, RpId, newerUserId, cancellationToken);

        var assertionOptionsBuilder = new Fido2AssertionOptionsBuilder();
        PublicKeyCredentialRequestOptions requestOptions = await assertionOptionsBuilder.BuildAsync(
            rpId: RpId,
            pool: pool,
            allowedCredentials: null,
            userVerification: UserVerificationRequirement.Discouraged,
            cancellationToken: cancellationToken);

        byte[] getClientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(
            new ClientData(WellKnownClientDataTypes.Get, requestOptions.Challenge!, Origin));
        DigestValue getClientDataHash = Fido2ClientDataHash.Compute(getClientDataJson, pool);

        CtapGetAssertionRequest getAssertionRequest = CtapWave2CapstoneFixtures.BuildGetAssertionRequest(requestOptions, getClientDataHash);

        CtapGetAssertionResponse firstResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, getAssertionRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(getAssertionRequest);

        Assert.AreEqual(2, firstResponse.NumberOfCredentials);
        Assert.IsNull(firstResponse.UserSelected);
        Assert.IsNotNull(firstResponse.User);
        Assert.AreSequenceEqual(newerUserId, firstResponse.User!.Id.AsReadOnlySpan().ToArray());
        Assert.IsNull(firstResponse.User.Name);
        Assert.IsNull(firstResponse.User.DisplayName);

        await AssertShippedVerifierAcceptsAssertionAsync(
            newerCredential.PublicKey, firstResponse, getClientDataJson, requestOptions.Challenge!, RpId, Origin, newerUserId, pool, cancellationToken);

        CtapGetAssertionResponse nextResponse = await CtapAuthenticatorGetNextAssertionClient.GetNextAssertionAsync(
            harness.Transceive, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken);

        Assert.IsNull(nextResponse.NumberOfCredentials);
        Assert.IsNull(nextResponse.UserSelected);
        Assert.IsNotNull(nextResponse.User);
        Assert.AreSequenceEqual(olderUserId, nextResponse.User!.Id.AsReadOnlySpan().ToArray());
        Assert.IsNull(nextResponse.User.Name);
        Assert.IsNull(nextResponse.User.DisplayName);

        await AssertShippedVerifierAcceptsAssertionAsync(
            olderCredential.PublicKey, nextResponse, getClientDataJson, requestOptions.Challenge!, RpId, Origin, olderUserId, pool, cancellationToken);

        olderCredential.CredentialId.Dispose();
        newerCredential.CredentialId.Dispose();
    }


    /// <summary>
    /// Registers a resident credential for <paramref name="userId"/> at <paramref name="rpId"/> over
    /// <paramref name="harness"/>'s real APDU transport via <see cref="CtapAuthenticatorMakeCredentialClient"/>,
    /// returning the minted credential identifier and public key parsed from the wire response.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the credential ID carrier transfers to the returned CtapWave2RegisteredCredential, which the caller disposes.")]
    private static async Task<CtapWave2RegisteredCredential> RegisterResidentCredentialOverRealTransportAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, string rpId, byte[] userId, CancellationToken cancellationToken)
    {
        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: rpId, userId: userId, options: new CtapCommandOptions(ResidentKey: true));

        CtapMakeCredentialResponse response = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);
        CredentialId credentialId = CredentialId.Create(authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan(), pool);

        return new CtapWave2RegisteredCredential(credentialId, authenticatorData.AttestedCredentialData.CredentialPublicKey);
    }


    /// <summary>
    /// Builds an <see cref="AssertionCeremonyInput"/> for <paramref name="response"/> from wire bytes only
    /// (the RP's own known <paramref name="expectedUserId"/>, never the simulator's internal state) and
    /// asserts the SHIPPED <see cref="Fido2AssertionVerifier"/> accepts it — each credential's own first
    /// assertion since registration, so <see cref="AssertionCeremonyInput.StoredSignCount"/> is zero.
    /// </summary>
    private static async Task AssertShippedVerifierAcceptsAssertionAsync(
        CoseKey credentialPublicKey,
        CtapGetAssertionResponse response,
        byte[] clientDataJson,
        string challenge,
        string rpId,
        string origin,
        byte[] expectedUserId,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);
        UserHandle storedUserHandle = UserHandle.Create(expectedUserId, pool);

        using AssertionCeremonyInput ceremonyInput = new()
        {
            ClientData = ClientDataJsonReader.Read(clientDataJson),
            AuthenticatorData = authenticatorData,
            ExpectedChallenge = challenge,
            ExpectedOrigins = new HashSet<string> { origin },
            ExpectedRpIdHash = CtapWave2CapstoneFixtures.ComputeExpectedRpIdHash(rpId, pool),
            UserVerification = UserVerificationRequirement.Discouraged,
            AllowedCredentialIds = null,
            CredentialId = response.Credential.Id,
            StoredSignCount = 0,
            StoredUvInitialized = false,
            ResponseUserHandle = response.User!.Id,
            StoredUserHandle = storedUserHandle
        };

        Fido2AssertionOutcome outcome = await Fido2AssertionVerifier.VerifyAsync(
            credentialPublicKey,
            response.Signature,
            response.AuthData,
            clientDataJson,
            ceremonyInput,
            correlationId: "ctap-wave3-capstone-multi-account-assertion",
            pool,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch),
            cancellationToken: cancellationToken);

        Assert.IsTrue(outcome.SignatureValid, "The shipped Fido2AssertionVerifier must accept the CTAP-signed assertion.");
        Assert.IsTrue(outcome.IsAcceptable);
    }


    /// <summary>
    /// Verifies an assertion or packed self-attestation signature with the framework's own
    /// <see cref="ECDsa"/>, converting the stored ES256 COSE_Key to raw curve coordinates directly rather
    /// than through this library's own COSE-to-key conversion path exercised elsewhere — the sanctioned
    /// independent-oracle exception: a signature asserted outside the shipped verifier is cross-checked
    /// with a second, independently implemented verification primitive. Both signature kinds cover the
    /// identical <c>authenticatorData ‖ clientDataHash</c> message with the credential's own key
    /// (<see cref="Fido2CredentialSigner"/>'s own remarks document the shared signing operation), so one
    /// oracle serves both.
    /// </summary>
    private static bool VerifyAssertionSignatureIndependently(
        CoseKey credentialPublicKey, ReadOnlyMemory<byte> authenticatorData, byte[] clientDataJson, ReadOnlyMemory<byte> signature, MemoryPool<byte> pool)
    {
        using DigestValue clientDataHash = Fido2ClientDataHash.Compute(clientDataJson, pool);
        byte[] toBeSigned = new byte[authenticatorData.Length + clientDataHash.Length];
        authenticatorData.Span.CopyTo(toBeSigned);
        clientDataHash.AsReadOnlySpan().CopyTo(toBeSigned.AsSpan(authenticatorData.Length));

        using PublicKeyMemory publicKeyMemory = credentialPublicKey.ToPublicKeyMemory(pool);
        ReadOnlySpan<byte> compressed = publicKeyMemory.AsReadOnlySpan();
        byte[] y = EllipticCurveUtilities.Decompress(compressed, EllipticCurveTypes.P256);
        byte[] x = compressed[1..].ToArray();

        //Independent-oracle carve-out: mints the framework ECDsa verifier straight from the library's own
        //wire-exported COSE public key coordinates, never from freshly generated fixture material.
        using ECDsa key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });

        return key.VerifyData(toBeSigned, signature.Span, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }
}

using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;
using static Verifiable.Tests.TestInfrastructure.CtapWaveBioFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wavebio PKG-D real-wire capstones for <c>authenticatorBioEnrollment</c> (<c>0x09</c>) and the
/// built-in-UV cluster: five flows, each reconstructing every fact from wire bytes only, over the same
/// real, UNCHANGED APDU transport stack (<see cref="CtapWave2TransportHarness"/>)
/// <see cref="CtapAuthenticatorCredentialManagementFlowTests"/> uses. Every <c>pinUvAuthParam</c> is
/// computed with the real <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/> over wire-received
/// bytes, via <see cref="CtapWaveBioFixtures"/>'s R4 message-assembly helpers and
/// <see cref="CtapWave5bPinCryptoFixtures"/>'s key-agreement session. No assertion reads internal
/// simulator state.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorBioEnrollmentFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN every capstone establishes.</summary>
    private const string Pin = "1234";

    /// <summary>The single PIN/UV auth protocol every capstone drives.</summary>
    private static CtapPinUvAuthProtocolId ProtocolId => CtapPinUvAuthProtocolId.Two;

    /// <summary>The fixed <c>clientDataHash</c> bytes <see cref="BuildMakeCredentialRequest"/> always embeds — the mc verify message.</summary>
    private static byte[] McClientDataHash => BuildFixedBytes(32, 0x10);


    /// <summary>
    /// Capstone 1: the full <c>authenticatorBioEnrollment</c> lifecycle over the real APDU transport —
    /// <c>setPIN</c> → a PIN-path <c>be|mc</c> token → <c>enrollBegin</c> plus scripted-GOOD
    /// <c>enrollCaptureNextSample</c> calls to completion → a real <c>authenticatorGetInfo</c> flips
    /// <c>bioEnroll</c>/<c>uv</c> to true on the wire → <c>enumerateEnrollments</c>/<c>setFriendlyName</c>/
    /// <c>removeEnrollment</c> against REAL persisted values → the SAME token still succeeds at
    /// <c>authenticatorMakeCredential</c> afterward (row 6623, no re-issuance).
    /// </summary>
    [TestMethod]
    public async Task FullBioEnrollmentLifecycleOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CreateSimulator("wavebio-capstone-1");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        byte[] token = await IssuePinPathTokenAsync(
            harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Be | WellKnownCtapPinUvAuthTokenPermissions.Mc, DefaultRpId, cancellationToken)
            .ConfigureAwait(false);

        CtapGetInfoResponse infoBeforeEnrollment = await GetInfoAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(infoBeforeEnrollment.Options!.BioEnroll, "a fresh authenticator has zero provisioned enrollments.");
        Assert.IsFalse(infoBeforeEnrollment.Options!.Uv, "uv derives from the same source as bioEnroll.");

        byte[] templateId = await CompleteEnrollmentOverWireAsync(harness, pool, token, cancellationToken).ConfigureAwait(false);

        CtapGetInfoResponse infoAfterEnrollment = await GetInfoAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(infoAfterEnrollment.Options!.BioEnroll, "the completed enrollment must flip bioEnroll to true, observed on the wire.");
        Assert.IsTrue(infoAfterEnrollment.Options!.Uv, "uv must flip to true alongside bioEnroll, observed on the wire.");

        CtapBioEnrollmentResponse enumerated = await SendEnumerateEnrollmentsAsync(harness, pool, token, cancellationToken).ConfigureAwait(false);
        Assert.HasCount(1, enumerated.TemplateInfos!);
        Assert.IsTrue(templateId.AsSpan().SequenceEqual(enumerated.TemplateInfos![0].TemplateId.Span), "the enumerated templateId must equal enrollBegin's own minted id.");
        Assert.IsNull(enumerated.TemplateInfos[0].TemplateFriendlyName, "a freshly completed enrollment has no friendly name yet.");

        const string FriendlyName = "wavebio-capstone-1-finger";
        using(PooledMemory renameResponse = await SendSetFriendlyNameRawAsync(harness, pool, token, templateId, FriendlyName, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, renameResponse.AsReadOnlySpan()[0]);
        }

        CtapBioEnrollmentResponse enumeratedAfterRename = await SendEnumerateEnrollmentsAsync(harness, pool, token, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(FriendlyName, enumeratedAfterRename.TemplateInfos![0].TemplateFriendlyName, "the renamed friendly name must be visible on a real re-enumeration.");

        using(PooledMemory removeResponse = await SendRemoveEnrollmentRawAsync(harness, pool, token, templateId, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, removeResponse.AsReadOnlySpan()[0]);
        }

        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, ProtocolId, McClientDataHash, pool, cancellationToken).ConfigureAwait(false);
        CtapMakeCredentialRequest mcRequest = BuildMakeCredentialRequest(pool, pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)ProtocolId);
        using PooledMemory mcResponse = await SendMakeCredentialWireAsync(harness, mcRequest, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.Ok, mcResponse.AsReadOnlySpan()[0],
            "row 6623: the enrollment-completing be|mc token must still succeed at mc afterward, with no re-issuance, observed on the wire.");
    }


    /// <summary>
    /// Capstone 2: built-in-UV-minted tokens over the real APDU transport — <c>0x06</c> mints an
    /// <c>mc|ga</c> token via the simulated gesture and that token succeeds at
    /// <c>authenticatorMakeCredential</c> with the response's own <c>uv</c> bit set, decoded straight
    /// from wire <c>authData</c>; <c>0x06</c> with <c>be</c> (<c>uvBioEnroll</c> true) authorizes a
    /// SECOND, distinct enrollment off the first finger's own token; <c>0x06</c> with <c>acfg</c>
    /// answers <c>UNAUTHORIZED_PERMISSION</c> on the wire (0x06's own statement list, R5, never grants
    /// <c>acfg</c> since <c>uvAcfg</c> is permanently absent).
    /// </summary>
    [TestMethod]
    public async Task BuiltInUvMintedTokensOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CreateSimulator("wavebio-capstone-2");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        byte[] pinPathBeToken = await IssuePinPathTokenAsync(harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, cancellationToken).ConfigureAwait(false);
        byte[] firstTemplateId = await CompleteEnrollmentOverWireAsync(harness, pool, pinPathBeToken, cancellationToken).ConfigureAwait(false);

        byte[] uvMcGaToken = await IssueUvPathTokenAsync(
            harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga, DefaultRpId, cancellationToken)
            .ConfigureAwait(false);

        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(uvMcGaToken, ProtocolId, McClientDataHash, pool, cancellationToken).ConfigureAwait(false);
        CtapMakeCredentialRequest mcRequest = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0x70), pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)ProtocolId);
        using(PooledMemory mcResponse = await SendMakeCredentialWireAsync(harness, mcRequest, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, mcResponse.AsReadOnlySpan()[0], "a 0x06-minted mc token must succeed at authenticatorMakeCredential, on the wire.");

            CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(mcResponse.AsReadOnlyMemory()[1..]);
            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            Assert.IsTrue(authenticatorData.Flags.UserVerified, "the uv bit, decoded from real wire authData, must be set for a 0x06-minted token's mc call.");
        }

        byte[] uvBeToken = await IssueUvPathTokenAsync(harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, cancellationToken).ConfigureAwait(false);
        byte[] secondTemplateId = await CompleteEnrollmentOverWireAsync(harness, pool, uvBeToken, cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(
            firstTemplateId.AsSpan().SequenceEqual(secondTemplateId),
            "a second enrollment, authorized by a 0x06 token minted off the first finger, must mint a DISTINCT templateId.");

        byte uvAcfgStatus = await SendUvTokenRequestRawStatusAsync(
            harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.UnauthorizedPermission, uvAcfgStatus,
            "0x06's OWN statement list denies acfg unconditionally (uvAcfg stays permanently absent), on the wire.");
    }


    /// <summary>
    /// Capstone 3: <c>options.uv</c> built-in UV on <c>authenticatorMakeCredential</c>/
    /// <c>authenticatorGetAssertion</c> over the real APDU transport — <c>uv:true</c> against a
    /// fresh, zero-enrollment authenticator answers <c>CTAP2_ERR_INVALID_OPTION</c> (the "not yet
    /// configured" gate, distinct from 0x06's own <c>NotAllowed</c>); a level-3
    /// (<c>userVerificationRequired</c>) discoverable credential stays invisible to a UV-less
    /// discoverable-scan <c>ga</c>, then becomes visible through <c>options.uv = true</c> with NO
    /// <c>pinUvAuthToken</c> anywhere in the request.
    /// </summary>
    [TestMethod]
    public async Task MakeCredentialGetAssertionOptionsUvOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CreateSimulator("wavebio-capstone-3");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        CtapGetAssertionRequest zeroEnrollmentUvRequest = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserVerification: true));
        using(PooledMemory zeroEnrollmentUvResponse = await SendGetAssertionWireAsync(harness, zeroEnrollmentUvRequest, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(
                WellKnownCtapStatusCodes.InvalidOption, zeroEnrollmentUvResponse.AsReadOnlySpan()[0],
                "uv:true against a zero-enrollment (not yet configured) authenticator answers InvalidOption, on the wire.");
        }

        ReadOnlyMemory<byte> credProtectLevelThree = BuildMakeCredentialExtensionsInput(credProtect: 3);
        CtapMakeCredentialRequest registrationRequest = BuildMakeCredentialRequest(pool, userId: BuildFixedBytes(16, 0x80), options: new CtapCommandOptions(ResidentKey: true), extensions: credProtectLevelThree);
        using(PooledMemory registrationResponse = await SendMakeCredentialWireAsync(harness, registrationRequest, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, registrationResponse.AsReadOnlySpan()[0], "the level-3 discoverable credential must register on an unprotected, PIN-less authenticator.");
        }

        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        byte[] beToken = await IssuePinPathTokenAsync(harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, cancellationToken).ConfigureAwait(false);
        _ = await CompleteEnrollmentOverWireAsync(harness, pool, beToken, cancellationToken).ConfigureAwait(false);

        CtapGetAssertionRequest uvLessScan = BuildGetAssertionRequest(pool);
        using(PooledMemory uvLessResponse = await SendGetAssertionWireAsync(harness, uvLessScan, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(
                WellKnownCtapStatusCodes.NoCredentials, uvLessResponse.AsReadOnlySpan()[0],
                "a level-3 credProtect discoverable credential must stay invisible to a UV-less ga discoverable scan, on the wire.");
        }

        CtapGetAssertionRequest builtInUvScan = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserVerification: true));
        using PooledMemory builtInUvResponse = await SendGetAssertionWireAsync(harness, builtInUvScan, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.Ok, builtInUvResponse.AsReadOnlySpan()[0],
            "the SAME credential must become visible via options.uv = true, with no pinUvAuthToken in the request at all, on the wire.");

        CtapGetAssertionResponse decoded = CtapGetAssertionResponseCborReader.Read(builtInUvResponse.AsReadOnlyMemory()[1..], pool);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserVerified, "a successful built-in-UV ga call's own uv bit must be set, decoded from real wire authData.");
        decoded.Credential.Id.Dispose();
        decoded.User?.Id.Dispose();
    }


    /// <summary>
    /// Capstone 4: the <c>uvRetries</c> lockout arc over the real APDU transport — scripted
    /// <c>MatchFailure</c> gestures drain <c>uvRetries</c> to zero, with <c>getUVRetries</c> reporting
    /// the live decrement on the wire at every step; <c>0x06</c> then answers <c>UvBlocked</c>; mc/ga's
    /// own <c>options.uv</c> ladder answers <c>PuatRequired</c> (NOT <c>PinBlocked</c>, the documented
    /// unreachable arm); a correct clientPIN entry (a fresh <c>0x09</c> issuance) restores
    /// <c>uvRetries</c> to its maximum; separately, on an independent authenticator,
    /// <c>authenticatorReset</c> restores <c>uvRetries</c> AND clears every provisioned template — a
    /// real post-reset <c>authenticatorGetInfo</c> reports <c>bioEnroll:false</c>/<c>uv:false</c> and a
    /// real <c>0x06</c> call answers <c>NotAllowed</c>.
    /// </summary>
    [TestMethod]
    public async Task UvRetriesLockoutAndResetArcOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator lockoutSimulator = CreateSimulator("wavebio-capstone-4-lockout", simulateBuiltInUv: static () => CtapBuiltInUvAttemptOutcome.MatchFailure);
        using CtapWave2TransportHarness lockoutHarness = await CtapWave2TransportHarness.CreateAsync(lockoutSimulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(lockoutHarness, pool, cancellationToken).ConfigureAwait(false);
        byte[] beToken = await IssuePinPathTokenAsync(lockoutHarness, pool, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, cancellationToken).ConfigureAwait(false);
        _ = await CompleteEnrollmentOverWireAsync(lockoutHarness, pool, beToken, cancellationToken).ConfigureAwait(false);

        for(int call = 1; call < CtapAuthenticatorState.MaxUvRetries; call++)
        {
            byte status = await SendUvTokenRequestRawStatusAsync(lockoutHarness, pool, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(WellKnownCtapStatusCodes.UvInvalid, status, $"call {call}: uvRetries is still nonzero after this decrement.");
        }

        int uvRetriesBeforeFinalDecrement = await GetUvRetriesAsync(lockoutHarness, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1, uvRetriesBeforeFinalDecrement, "getUVRetries must report the live decrement on the wire after MaxUvRetries-1 MatchFailures.");

        byte finalDecrementStatus = await SendUvTokenRequestRawStatusAsync(lockoutHarness, pool, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.UvBlocked, finalDecrementStatus, "the decrement landing exactly on zero must answer UvBlocked, on the wire.");
        Assert.AreEqual(0, await GetUvRetriesAsync(lockoutHarness, pool, cancellationToken).ConfigureAwait(false));

        CtapGetAssertionRequest lockedOutUvScan = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserVerification: true));
        using(PooledMemory lockedOutUvResponse = await SendGetAssertionWireAsync(lockoutHarness, lockedOutUvScan, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(
                WellKnownCtapStatusCodes.PuatRequired, lockedOutUvResponse.AsReadOnlySpan()[0],
                "mc/ga's own options.uv ladder must answer PuatRequired (NOT PinBlocked, the documented unreachable arm) once uvRetries is exhausted, on the wire.");
        }

        _ = await IssuePinPathTokenAsync(lockoutHarness, pool, WellKnownCtapPinUvAuthTokenPermissions.Mc, DefaultRpId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            CtapAuthenticatorState.MaxUvRetries, await GetUvRetriesAsync(lockoutHarness, pool, cancellationToken).ConfigureAwait(false),
            "a correct clientPIN entry (0x09 issuance) must restore uvRetries to its maximum, observed on the wire.");

        using CtapAuthenticatorSimulator resetSimulator = CreateSimulator("wavebio-capstone-4-reset");
        using CtapWave2TransportHarness resetHarness = await CtapWave2TransportHarness.CreateAsync(resetSimulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(resetHarness, pool, cancellationToken).ConfigureAwait(false);
        byte[] resetBeToken = await IssuePinPathTokenAsync(resetHarness, pool, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, cancellationToken).ConfigureAwait(false);
        _ = await CompleteEnrollmentOverWireAsync(resetHarness, pool, resetBeToken, cancellationToken).ConfigureAwait(false);

        CtapGetInfoResponse infoBeforeReset = await GetInfoAsync(resetHarness, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(infoBeforeReset.Options!.BioEnroll, "the pre-reset authenticator must carry a completed enrollment.");

        using(PooledMemory resetResponse = await SendResetAsync(resetHarness, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        CtapGetInfoResponse infoAfterReset = await GetInfoAsync(resetHarness, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(infoAfterReset.Options!.BioEnroll, "authenticatorReset must clear every provisioned template, observed on a real post-reset getInfo.");
        Assert.IsFalse(infoAfterReset.Options!.Uv, "uv must revert to false alongside bioEnroll, observed on a real post-reset getInfo.");

        byte postResetUvStatus = await SendUvTokenRequestRawStatusAsync(resetHarness, pool, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, postResetUvStatus, "0x06 against the post-reset, zero-enrollment authenticator must answer NotAllowed, on the wire.");
    }


    /// <summary>
    /// Capstone 5: the token-free trio over the real APDU transport — <c>getModality</c>,
    /// <c>getFingerprintSensorInfo</c>, and <c>cancelCurrentEnrollment</c> all succeed with NO
    /// <c>pinUvAuthParam</c>, and no <c>authenticatorClientPIN</c> exchange occurs anywhere in the flow
    /// (no PIN is ever established on this authenticator).
    /// </summary>
    [TestMethod]
    public async Task TokenFreeTrioOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CreateSimulator("wavebio-capstone-5");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        var getModalityRequest = new CtapBioEnrollmentRequest(GetModality: true);
        using(PooledMemory getModalityResponse = await SendBioEnrollmentWireAsync(harness, getModalityRequest, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, getModalityResponse.AsReadOnlySpan()[0]);
            CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(getModalityResponse.AsReadOnlyMemory()[1..]);
            Assert.AreEqual(WellKnownCtapBioEnrollmentModalities.Fingerprint, decoded.Modality);
        }

        var sensorInfoRequest = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.GetFingerprintSensorInfo);
        using(PooledMemory sensorInfoResponse = await SendBioEnrollmentWireAsync(harness, sensorInfoRequest, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, sensorInfoResponse.AsReadOnlySpan()[0]);
            CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(sensorInfoResponse.AsReadOnlyMemory()[1..]);
            Assert.AreEqual(WellKnownCtapFingerprintKinds.Touch, decoded.FingerprintKind);
            Assert.AreEqual(CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll, decoded.MaxCaptureSamplesRequiredForEnroll);
            Assert.AreEqual(CtapAuthenticatorState.MaxTemplateFriendlyNameByteLength, decoded.MaxTemplateFriendlyName);
        }

        var cancelRequest = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.CancelCurrentEnrollment);
        using PooledMemory cancelResponse = await SendBioEnrollmentWireAsync(harness, cancelRequest, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1, cancelResponse.Length, "cancelCurrentEnrollment's success response carries no CBOR body.");
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, cancelResponse.AsReadOnlySpan()[0]);
    }


    /// <summary>Sends an <c>authenticatorGetInfo</c> request over <paramref name="harness"/>'s real transport and decodes the response.</summary>
    private static async Task<CtapGetInfoResponse> GetInfoAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await harness.Transceive(request, pool, cancellationToken).ConfigureAwait(false);

        return CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
    }


    /// <summary>Sends a bare <c>authenticatorReset</c> request over <paramref name="harness"/>'s real transport, returning the raw response envelope.</summary>
    private static ValueTask<PooledMemory> SendResetAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.Reset];

        return harness.Transceive(request, pool, cancellationToken);
    }


    /// <summary>Establishes <see cref="Pin"/> as the authenticator's PIN over <paramref name="harness"/>'s real transport.</summary>
    private static async Task EstablishPinAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(harness.Transceive, ProtocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(Pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)ProtocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c> (<c>0x09</c>)
    /// carrying <paramref name="permissions"/>, optionally bound to <paramref name="rpId"/>, decrypting
    /// it from wire bytes only, over <paramref name="harness"/>'s real transport.
    /// </summary>
    private static async Task<byte[]> IssuePinPathTokenAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, int permissions, string? rpId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(harness.Transceive, ProtocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(Pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)ProtocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingUvWithPermissions</c> (<c>0x06</c>)
    /// carrying <paramref name="permissions"/>, optionally bound to <paramref name="rpId"/>, over
    /// <paramref name="harness"/>'s real transport — the simulated built-in-UV gesture stands in for
    /// <c>pinHashEnc</c> (0x06's own request carries none).
    /// </summary>
    private static async Task<byte[]> IssueUvPathTokenAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, int permissions, string? rpId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(harness.Transceive, ProtocolId, pool, cancellationToken)
            .ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingUvWithPermissions,
            PinUvAuthProtocol: (int)ProtocolId, KeyAgreement: session.PlatformPublicKeyCose,
            Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends a <c>getPinUvAuthTokenUsingUvWithPermissions</c> (<c>0x06</c>) request over
    /// <paramref name="harness"/>'s real transport and returns the raw CTAP2 status byte, for scripted
    /// error paths (retry ladder, denied permissions, not-configured/not-allowed) that never decrypt a
    /// token.
    /// </summary>
    private static async Task<byte> SendUvTokenRequestRawStatusAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, int permissions, string? rpId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(harness.Transceive, ProtocolId, pool, cancellationToken)
            .ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingUvWithPermissions,
            PinUvAuthProtocol: (int)ProtocolId, KeyAgreement: session.PlatformPublicKeyCose,
            Permissions: permissions, RpId: rpId);
        TaggedMemory<byte> parameters = CtapClientPinRequestCborWriter.Write(request);
        byte[] envelope = new byte[parameters.Length + 1];
        envelope[0] = WellKnownCtapCommands.ClientPin;
        parameters.Span.CopyTo(envelope.AsSpan(1));

        using PooledMemory response = await harness.Transceive(envelope, pool, cancellationToken).ConfigureAwait(false);

        return response.AsReadOnlySpan()[0];
    }


    /// <summary>Reads the live <c>uvRetries</c> value via <c>getUVRetries</c> (<c>0x07</c>) over <paramref name="harness"/>'s real transport.</summary>
    private static async Task<int> GetUvRetriesAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetUvRetries);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        return response.UvRetries!.Value;
    }


    /// <summary>Encodes, sends, and returns the raw response envelope for an <c>authenticatorBioEnrollment</c> request over <paramref name="harness"/>'s real transport.</summary>
    private static ValueTask<PooledMemory> SendBioEnrollmentWireAsync(
        CtapWave2TransportHarness harness, CtapBioEnrollmentRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = BuildBioEnrollmentEnvelope(request);

        return harness.Transceive(envelope, pool, cancellationToken);
    }


    /// <summary>Computes a gated bioEnrollment subcommand's own <c>pinUvAuthParam</c> (bio scout Finding C: the TWO-byte <c>modality || subCommand [|| subCommandParams]</c> prefix).</summary>
    private static async Task<byte[]> ComputeGatedBioSignatureAsync(
        byte[] token, MemoryPool<byte> pool, int subCommand, ReadOnlyMemory<byte>? templateId, string? templateFriendlyName, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> subCommandParams = templateId is not null || templateFriendlyName is not null
            ? BuildSubCommandParams(templateId, templateFriendlyName)
            : ReadOnlyMemory<byte>.Empty;
        byte[] message = BuildMessage(WellKnownCtapBioEnrollmentModalities.Fingerprint, subCommand, subCommandParams);

        return await CtapWaveConfigFixtures.ComputeSignatureAsync(token, ProtocolId, message, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Sends a fully signed <c>enrollBegin</c> over <paramref name="harness"/>'s real transport, asserts <c>CTAP2_OK</c>, and returns the minted <c>templateId</c> bytes.</summary>
    private static async Task<byte[]> SendEnrollBeginAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, byte[] token, CancellationToken cancellationToken)
    {
        byte[] param = await ComputeGatedBioSignatureAsync(token, pool, WellKnownCtapBioEnrollmentSubCommands.EnrollBegin, null, null, cancellationToken).ConfigureAwait(false);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            PinUvAuthProtocol: (int)ProtocolId, PinUvAuthParam: param);

        using PooledMemory response = await SendBioEnrollmentWireAsync(harness, request, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        return CtapBioEnrollmentResponseCborReader.Read(response.AsReadOnlyMemory()[1..]).TemplateId!.Value.ToArray();
    }


    /// <summary>Sends a fully signed <c>enrollCaptureNextSample</c> for <paramref name="templateId"/> over <paramref name="harness"/>'s real transport, asserting <c>CTAP2_OK</c>.</summary>
    private static async Task SendEnrollCaptureNextSampleAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, byte[] token, byte[] templateId, CancellationToken cancellationToken)
    {
        byte[] param = await ComputeGatedBioSignatureAsync(token, pool, WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample, templateId, null, cancellationToken)
            .ConfigureAwait(false);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample,
            TemplateId: templateId, PinUvAuthProtocol: (int)ProtocolId, PinUvAuthParam: param);

        using PooledMemory response = await SendBioEnrollmentWireAsync(harness, request, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// Drives a complete enrollment lifecycle over <paramref name="harness"/>'s real transport — one
    /// <c>enrollBegin</c> plus enough <c>enrollCaptureNextSample</c> calls (the default always-GOOD
    /// simulated sensor) to reach <c>remainingSamples</c> zero — and returns the persisted template's
    /// identifier bytes.
    /// </summary>
    private static async Task<byte[]> CompleteEnrollmentOverWireAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, byte[] token, CancellationToken cancellationToken)
    {
        byte[] templateId = await SendEnrollBeginAsync(harness, pool, token, cancellationToken).ConfigureAwait(false);

        for(int sample = 1; sample < CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll; sample++)
        {
            await SendEnrollCaptureNextSampleAsync(harness, pool, token, templateId, cancellationToken).ConfigureAwait(false);
        }

        return templateId;
    }


    /// <summary>Sends a fully signed <c>enumerateEnrollments</c> over <paramref name="harness"/>'s real transport, asserts <c>CTAP2_OK</c>, and returns the decoded response.</summary>
    private static async Task<CtapBioEnrollmentResponse> SendEnumerateEnrollmentsAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, byte[] token, CancellationToken cancellationToken)
    {
        byte[] param = await ComputeGatedBioSignatureAsync(token, pool, WellKnownCtapBioEnrollmentSubCommands.EnumerateEnrollments, null, null, cancellationToken).ConfigureAwait(false);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnumerateEnrollments,
            PinUvAuthProtocol: (int)ProtocolId, PinUvAuthParam: param);

        using PooledMemory response = await SendBioEnrollmentWireAsync(harness, request, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        return CtapBioEnrollmentResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
    }


    /// <summary>Sends a fully signed <c>setFriendlyName</c> for <paramref name="templateId"/> over <paramref name="harness"/>'s real transport, returning the raw response envelope.</summary>
    private static async Task<PooledMemory> SendSetFriendlyNameRawAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, byte[] token, byte[] templateId, string friendlyName, CancellationToken cancellationToken)
    {
        byte[] param = await ComputeGatedBioSignatureAsync(token, pool, WellKnownCtapBioEnrollmentSubCommands.SetFriendlyName, templateId, friendlyName, cancellationToken)
            .ConfigureAwait(false);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.SetFriendlyName,
            TemplateId: templateId, TemplateFriendlyName: friendlyName, PinUvAuthProtocol: (int)ProtocolId, PinUvAuthParam: param);

        return await SendBioEnrollmentWireAsync(harness, request, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Sends a fully signed <c>removeEnrollment</c> for <paramref name="templateId"/> over <paramref name="harness"/>'s real transport, returning the raw response envelope.</summary>
    private static async Task<PooledMemory> SendRemoveEnrollmentRawAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, byte[] token, byte[] templateId, CancellationToken cancellationToken)
    {
        byte[] param = await ComputeGatedBioSignatureAsync(token, pool, WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment, templateId, null, cancellationToken).ConfigureAwait(false);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment,
            TemplateId: templateId, PinUvAuthProtocol: (int)ProtocolId, PinUvAuthParam: param);

        return await SendBioEnrollmentWireAsync(harness, request, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Encodes, sends, and disposes an <c>authenticatorMakeCredential</c> request over <paramref name="harness"/>'s real transport, returning the raw response envelope.</summary>
    private static async Task<PooledMemory> SendMakeCredentialWireAsync(
        CtapWave2TransportHarness harness, CtapMakeCredentialRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = CtapWave2RequestEnvelopes.BuildMakeCredentialEnvelope(request);
        DisposeMakeCredentialRequest(request);

        return await harness.Transceive(envelope, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Encodes, sends, and disposes an <c>authenticatorGetAssertion</c> request over <paramref name="harness"/>'s real transport, returning the raw response envelope.</summary>
    private static async Task<PooledMemory> SendGetAssertionWireAsync(
        CtapWave2TransportHarness harness, CtapGetAssertionRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = CtapWave2RequestEnvelopes.BuildGetAssertionEnvelope(request);
        DisposeGetAssertionRequest(request);

        return await harness.Transceive(envelope, pool, cancellationToken).ConfigureAwait(false);
    }
}

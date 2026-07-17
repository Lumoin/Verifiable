using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;
using static Verifiable.Tests.TestInfrastructure.CtapWaveBioFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wavebio PKG-B unit-test matrix for <c>authenticatorBioEnrollment</c> (<c>0x09</c>): the token-free
/// trio, the full preamble/verify/permission ladder for each of the five <c>be</c>-permission-gated
/// subcommands, the live fingerprint template store (capacity, capture-quality sequences, auto-cancel,
/// completion/persistence, rename, removal), the <c>bioEnroll</c>/<c>uv</c> getInfo tri-state flip, and
/// row 6623's token-survival guarantee. Driven in-process through
/// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>, mirroring
/// <see cref="CtapAuthenticatorCredentialManagementTests"/>'s conventions — platform-side
/// <c>pinUvAuthParam</c> computed the same way the wavecm/waveconfig fixtures compute credMgmt/acfg's own,
/// through <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/> over the actual token bytes. Every
/// assertion reads the response's own decoded wire bytes, never internal simulator state.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorBioEnrollmentTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN every token-issuing test establishes.</summary>
    private const string DefaultPin = "1234";


    /// <summary>
    /// <c>getModality: true</c> serves the bio-modality read IMMEDIATELY, with NO token and NO
    /// <c>subCommand</c> at all (CTAP 2.3 §6.7.2, snapshot lines 6626-6644): the response's own
    /// <c>modality</c> (0x01) field reports <c>fingerprint</c> (1).
    /// </summary>
    [TestMethod]
    public async Task GetModalityTrueReturnsFingerprintModalityTokenFree()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-getmodality");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(GetModality: true);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownCtapBioEnrollmentModalities.Fingerprint, decoded.Modality);
    }


    /// <summary>
    /// <c>getModality: true</c> WINS over an accompanying <c>subCommand</c> — a documented posture over
    /// the spec's own silence on the mixed-member case (bio scout trap 2/5): the modality read is still
    /// served, the <c>subCommand</c> is never dispatched.
    /// </summary>
    [TestMethod]
    public async Task GetModalityTrueWinsOverAccompanyingSubCommand()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-getmodality-wins");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint,
            SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            GetModality: true);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownCtapBioEnrollmentModalities.Fingerprint, decoded.Modality);
        Assert.IsNull(decoded.TemplateId, "enrollBegin must never dispatch when getModality:true is also present.");
    }


    /// <summary>
    /// A <c>getModality: false</c> request is treated as the member being absent, not an error — a
    /// documented posture over the spec's own silence (the platform's own send-value MUST, snapshot line
    /// 6417, binds only the SEND side): with no <c>subCommand</c> either, this resolves to
    /// <c>MissingParameter</c>, the same disposition as the member being omitted entirely.
    /// </summary>
    [TestMethod]
    public async Task GetModalityFalseWithNoSubCommandReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-getmodality-false");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(GetModality: false);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// Neither <c>getModality: true</c> nor a <c>subCommand</c> at all resolves to
    /// <c>MissingParameter</c> — a documented posture over spec silence (the general mandatory-params
    /// family disposition, since §6.7 itself names no top-level "nothing was requested" status).
    /// </summary>
    [TestMethod]
    public async Task NeitherGetModalityNorSubCommandReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-nothing-requested");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest();
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>getFingerprintSensorInfo</c> (subCommand <c>0x07</c>) is served with NO token at all (bio
    /// scout Finding 5/trap 7), reporting the fixed sensor statics: <c>fingerprintKind</c> = touch (1),
    /// <c>maxCaptureSamplesRequiredForEnroll</c> = 4, <c>maxTemplateFriendlyName</c> = 64.
    /// </summary>
    [TestMethod]
    public async Task GetFingerprintSensorInfoReturnsFixedStaticsTokenFree()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-sensor-info");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint,
            SubCommand: WellKnownCtapBioEnrollmentSubCommands.GetFingerprintSensorInfo);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(WellKnownCtapFingerprintKinds.Touch, decoded.FingerprintKind);
        Assert.AreEqual(CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll, decoded.MaxCaptureSamplesRequiredForEnroll);
        Assert.AreEqual(CtapAuthenticatorState.MaxTemplateFriendlyNameByteLength, decoded.MaxTemplateFriendlyName);
    }


    /// <summary>
    /// <c>cancelCurrentEnrollment</c> (subCommand <c>0x03</c>) is served with NO token at all and has
    /// NO error path whatsoever (snapshot line 6799): unconditionally <c>CTAP2_OK</c>, even with no
    /// enrollment in progress.
    /// </summary>
    [TestMethod]
    public async Task CancelCurrentEnrollmentWithNothingInProgressReturnsOkTokenFree()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-cancel-nothing");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint,
            SubCommand: WellKnownCtapBioEnrollmentSubCommands.CancelCurrentEnrollment);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(1, response.Length, "cancelCurrentEnrollment's success response carries no CBOR body.");
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>cancelCurrentEnrollment</c> discards an in-progress enrollment (R7): a subsequent
    /// <c>enrollCaptureNextSample</c> naming the cancelled enrollment's own <c>templateId</c> finds no
    /// matching in-progress sequence and answers <see cref="WellKnownCtapStatusCodes.InvalidOption"/>.
    /// </summary>
    [TestMethod]
    public async Task CancelCurrentEnrollmentDiscardsInProgressEnrollment()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-cancel-discards");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        byte[] templateId = await SendEnrollBeginAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        byte[] cancelParam = await ComputeGatedSignatureAsync(token, CtapPinUvAuthProtocolId.Two, pool, WellKnownCtapBioEnrollmentSubCommands.CancelCurrentEnrollment);
        var cancelRequest = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint,
            SubCommand: WellKnownCtapBioEnrollmentSubCommands.CancelCurrentEnrollment);
        using(PooledMemory cancelResponse = await SendBioEnrollmentAsync(simulator, cancelRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, cancelResponse.AsReadOnlySpan()[0]);
        }

        using PooledMemory captureResponse = await SendEnrollCaptureNextSampleRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two, templateId);
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, captureResponse.AsReadOnlySpan()[0]);
    }


    /// <summary>Every be-permission-gated subcommand answers <c>PuatRequired</c> with no <c>pinUvAuthParam</c> presented (CTAP 2.3 §6.7.4-§6.7.8's own shared step 1, R12).</summary>
    [TestMethod]
    [DataRow(WellKnownCtapBioEnrollmentSubCommandsEnrollBegin, DisplayName = "enrollBegin")]
    [DataRow(WellKnownCtapBioEnrollmentSubCommandsEnrollCaptureNextSample, DisplayName = "enrollCaptureNextSample")]
    [DataRow(WellKnownCtapBioEnrollmentSubCommandsEnumerateEnrollments, DisplayName = "enumerateEnrollments")]
    [DataRow(WellKnownCtapBioEnrollmentSubCommandsSetFriendlyName, DisplayName = "setFriendlyName")]
    [DataRow(WellKnownCtapBioEnrollmentSubCommandsRemoveEnrollment, DisplayName = "removeEnrollment")]
    public async Task GatedSubCommandWithoutTokenReturnsPuatRequired(int subCommand)
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator($"bio-gated-no-token-{subCommand:X2}");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: subCommand);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An unregistered <c>subCommand</c> value answers <c>InvalidSubcommand</c> — credMgmt's allow-list precedent (R12).</summary>
    [TestMethod]
    public async Task UnregisteredSubCommandReturnsInvalidSubcommand()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-unregistered-subcommand");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(SubCommand: 0x99);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSubcommand, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A freshly constructed authenticator's <c>authenticatorGetInfo</c> response advertises the
    /// wavebio getInfo surface (R2): <c>bioEnroll</c>/<c>uv</c> present-false (derived from
    /// <see cref="CtapAuthenticatorState.HasProvisionedBioEnrollments"/>, live-checked against the real,
    /// empty template store), <c>uvBioEnroll</c> present-true unconditionally, <c>preferredPlatformUvAttempts</c>
    /// (0x11) = 3, <c>uvModality</c> (0x12) = <c>USER_VERIFY_FINGERPRINT_INTERNAL</c> (0x00000002).
    /// </summary>
    [TestMethod]
    public async Task GetInfoAdvertisesWavebioSurfaceOnFreshAuthenticator()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-getinfo-surface");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await simulator.TransceiveAsync(request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapGetInfoResponse decoded = CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.IsNotNull(decoded.Options);
        Assert.IsFalse(decoded.Options!.BioEnroll, "a fresh authenticator has zero provisioned enrollments.");
        Assert.IsFalse(decoded.Options!.Uv, "uv derives from the same HasProvisionedBioEnrollments source as bioEnroll.");
        Assert.IsTrue(decoded.Options!.UvBioEnroll, "uvBioEnroll is a static build capability, always true.");
        Assert.AreEqual(CtapAuthenticatorState.PreferredPlatformUvAttempts, decoded.PreferredPlatformUvAttempts);
        Assert.AreEqual(CtapAuthenticatorState.UvModality, decoded.UvModality);
    }


    /// <summary><c>enrollBegin</c> with no <c>modality</c> answers <c>MissingParameter</c> (R12's shared mandatory-params check) — never reaches <c>verify()</c>, so no real token is needed.</summary>
    [TestMethod]
    public async Task EnrollBeginMissingModalityReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-enrollbegin-no-modality");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: new byte[32]);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enrollBegin</c> with a <c>modality</c> other than <c>fingerprint</c> answers <c>CTAP1_ERR_INVALID_PARAMETER</c> — a documented posture over spec silence (R12).</summary>
    [TestMethod]
    public async Task EnrollBeginUnsupportedModalityReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-enrollbegin-bad-modality");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            Modality: 0x02, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: new byte[32]);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enrollBegin</c> with no <c>pinUvAuthProtocol</c> answers <c>MissingParameter</c>, after the modality check passes.</summary>
    [TestMethod]
    public async Task EnrollBeginMissingProtocolReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-enrollbegin-no-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            PinUvAuthParam: new byte[32]);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enrollBegin</c> naming an unsupported <c>pinUvAuthProtocol</c> answers <c>CTAP1_ERR_INVALID_PARAMETER</c>.</summary>
    [TestMethod]
    public async Task EnrollBeginUnsupportedProtocolReturnsInvalidParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-enrollbegin-bad-protocol");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            PinUvAuthProtocol: 9, PinUvAuthParam: new byte[32]);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enrollCaptureNextSample</c> with no <c>templateId</c> answers <c>MissingParameter</c>.</summary>
    [TestMethod]
    public async Task EnrollCaptureNextSampleMissingTemplateIdReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-capturenext-no-templateid");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: new byte[32]);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>setFriendlyName</c> with a <c>templateId</c> but no <c>templateFriendlyName</c> answers <c>MissingParameter</c> — both are mandatory together.</summary>
    [TestMethod]
    public async Task SetFriendlyNameMissingTemplateFriendlyNameReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-setfriendlyname-no-name");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.SetFriendlyName,
            TemplateId: new byte[16], PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: new byte[32]);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>removeEnrollment</c> with no <c>templateId</c> answers <c>MissingParameter</c>.</summary>
    [TestMethod]
    public async Task RemoveEnrollmentMissingTemplateIdReturnsMissingParameter()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-remove-no-templateid");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: new byte[32]);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>setFriendlyName</c>'s friendly-name byte-length check runs BEFORE <c>verify()</c> (bio scout
    /// Finding 7): an oversized name is rejected with <see cref="WellKnownCtapStatusCodes.InvalidLength"/>
    /// even alongside a garbage <c>pinUvAuthParam</c> that would otherwise fail verification — no PIN or
    /// token is established at all, proving this path never reaches <c>verify()</c>.
    /// </summary>
    [TestMethod]
    public async Task SetFriendlyNameTooLongReturnsInvalidLengthBeforeVerify()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-setfriendlyname-too-long");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.SetFriendlyName,
            TemplateId: new byte[16], TemplateFriendlyName: new string('a', CtapAuthenticatorState.MaxTemplateFriendlyNameByteLength + 1),
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: new byte[32]);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidLength, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A signature that fails <c>verify()</c> against a real, established <c>be</c>-scoped token answers <c>PinAuthInvalid</c>.</summary>
    [TestMethod]
    public async Task EnrollBeginBadSignatureReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-enrollbegin-bad-signature");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        byte[] validParam = await ComputeGatedSignatureAsync(token, CtapPinUvAuthProtocolId.Two, pool, WellKnownCtapBioEnrollmentSubCommands.EnrollBegin);
        validParam[0] ^= 0xFF;

        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: validParam);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A correctly verified token that lacks the <c>be</c> permission bit still answers
    /// <c>PinAuthInvalid</c> (CTAP 2.3 §6.7.4 step 5) — the same wire code as a failed signature, since
    /// the spec names no finer-grained code for either failure.
    /// </summary>
    [TestMethod]
    public async Task EnrollBeginWithMcOnlyTokenReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-enrollbegin-mc-only-token");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);
        byte[] mcOnlyToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Mc, DefaultRpId, TestContext.CancellationToken);

        byte[] param = await ComputeGatedSignatureAsync(mcOnlyToken, CtapPinUvAuthProtocolId.Two, pool, WellKnownCtapBioEnrollmentSubCommands.EnrollBegin);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: param);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>enrollBegin</c> mints a fresh <c>templateId</c> and captures the first sample: with the
    /// default always-GOOD <see cref="SimulateFingerprintCaptureDelegate"/>, the response reports
    /// <c>lastEnrollSampleStatus</c> GOOD and <c>remainingSamples</c> = <see cref="CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll"/> − 1.
    /// </summary>
    [TestMethod]
    public async Task EnrollBeginMintsTemplateAndCapturesFirstGoodSample()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-enrollbegin-happy");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        byte[] param = await ComputeGatedSignatureAsync(token, CtapPinUvAuthProtocolId.Two, pool, WellKnownCtapBioEnrollmentSubCommands.EnrollBegin);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: param);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.IsNotNull(decoded.TemplateId);
        Assert.AreEqual(16, decoded.TemplateId!.Value.Length);
        Assert.AreEqual(WellKnownCtapLastEnrollSampleStatuses.Good, decoded.LastEnrollSampleStatus);
        Assert.AreEqual(CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll - 1, decoded.RemainingSamples);
    }


    /// <summary>
    /// A fresh <c>enrollBegin</c> auto-cancels any unfinished enrollment (CTAP 2.3 §6.7.4 step 7): the
    /// second call mints a DIFFERENT <c>templateId</c>, and the FIRST (now-discarded) enrollment's
    /// <c>templateId</c> can no longer be continued.
    /// </summary>
    [TestMethod]
    public async Task EnrollBeginAutoCancelsUnfinishedEnrollment()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-autocancel");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        byte[] firstTemplateId = await SendEnrollBeginAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);
        byte[] secondTemplateId = await SendEnrollBeginAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        Assert.IsFalse(firstTemplateId.AsSpan().SequenceEqual(secondTemplateId), "a fresh enrollBegin must mint a NEW template id, distinct from the auto-cancelled one.");

        using PooledMemory captureResponse = await SendEnrollCaptureNextSampleRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two, firstTemplateId);
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, captureResponse.AsReadOnlySpan()[0], "the auto-cancelled enrollment's own templateId must no longer be capturable.");
    }


    /// <summary><c>enrollCaptureNextSample</c> naming a <c>templateId</c> that does not match the in-progress enrollment answers <c>InvalidOption</c> — a documented posture over spec silence (bio scout trap 6).</summary>
    [TestMethod]
    public async Task EnrollCaptureNextSampleWithMismatchedTemplateIdReturnsInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-capturenext-mismatch");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);
        _ = await SendEnrollBeginAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        byte[] wrongTemplateId = new byte[16];
        using PooledMemory response = await SendEnrollCaptureNextSampleRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two, wrongTemplateId);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enrollCaptureNextSample</c> with no enrollment currently in progress answers <c>InvalidOption</c> (bio scout trap 6).</summary>
    [TestMethod]
    public async Task EnrollCaptureNextSampleWithNoEnrollmentInProgressReturnsInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-capturenext-nothing-in-progress");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        using PooledMemory response = await SendEnrollCaptureNextSampleRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two, new byte[16]);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <c>enrollCaptureNextSample</c> completes the enrollment once enough GOOD samples have been
    /// captured: <see cref="CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll"/> − 1 further
    /// captures after <c>enrollBegin</c>'s own first one bring <c>remainingSamples</c> to zero; the FINAL
    /// (and every continuation) response carries NO <c>templateId</c> (spec's own field list, snapshot
    /// lines 6777-6783).
    /// </summary>
    [TestMethod]
    public async Task EnrollCaptureNextSampleCompletesEnrollmentAfterEnoughGoodSamples()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-capturenext-completes");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        byte[] templateId = await SendEnrollBeginAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        int? remainingSamples = null;
        for(int sample = 1; sample < CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll; sample++)
        {
            using PooledMemory response = await SendEnrollCaptureNextSampleRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two, templateId);
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

            CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
            Assert.IsNull(decoded.TemplateId, "enrollCaptureNextSample's own response never carries templateId.");
            Assert.AreEqual(WellKnownCtapLastEnrollSampleStatuses.Good, decoded.LastEnrollSampleStatus);
            remainingSamples = decoded.RemainingSamples;
        }

        Assert.AreEqual(0, remainingSamples, "enough GOOD samples must bring remainingSamples to exactly zero.");

        using PooledMemory enumerateResponse = await SendEnumerateEnrollmentsRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, enumerateResponse.AsReadOnlySpan()[0], "the completed template must now be enumerable.");
    }


    /// <summary>
    /// A non-GOOD capture leaves <c>remainingSamples</c> UNCHANGED and is still reported inside a
    /// successful <c>CTAP2_OK</c> — bio scout Finding 9: capture-quality outcomes are response FIELD
    /// values, never protocol errors.
    /// </summary>
    [TestMethod]
    public async Task EnrollCaptureNextSamplePoorQualityLeavesRemainingSamplesUnchanged()
    {
        int[] scriptedStatuses =
        [
            WellKnownCtapLastEnrollSampleStatuses.Good,
            WellKnownCtapLastEnrollSampleStatuses.PoorQuality,
            WellKnownCtapLastEnrollSampleStatuses.Good
        ];
        int callIndex = 0;
        int SimulateCapture() => scriptedStatuses[callIndex++];

        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-capturenext-poor-quality", simulateFingerprintCapture: SimulateCapture);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        byte[] templateId = await SendEnrollBeginAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);
        int remainingAfterBegin = CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll - 1;

        using(PooledMemory poorResponse = await SendEnrollCaptureNextSampleRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two, templateId))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, poorResponse.AsReadOnlySpan()[0], "a poor-quality capture is still a successful CTAP2_OK response.");
            CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(poorResponse.AsReadOnlyMemory()[1..]);
            Assert.AreEqual(WellKnownCtapLastEnrollSampleStatuses.PoorQuality, decoded.LastEnrollSampleStatus);
            Assert.AreEqual(remainingAfterBegin, decoded.RemainingSamples, "a non-GOOD capture must not decrement remainingSamples.");
        }

        using(PooledMemory goodResponse = await SendEnrollCaptureNextSampleRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two, templateId))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, goodResponse.AsReadOnlySpan()[0]);
            CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(goodResponse.AsReadOnlyMemory()[1..]);
            Assert.AreEqual(remainingAfterBegin - 1, decoded.RemainingSamples, "a subsequent GOOD capture must resume decrementing from the unchanged count.");
        }
    }


    /// <summary><c>enrollBegin</c> answers <c>FpDatabaseFull</c> once <see cref="CtapAuthenticatorState.MaxEnrolledTemplatesCapacity"/> templates are already provisioned (CTAP 2.3 §6.7.4 step 6, snapshot line 6711).</summary>
    [TestMethod]
    public async Task EnrollBeginReturnsFpDatabaseFullWhenStoreAtCapacity()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-capacity");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        for(int i = 0; i < CtapAuthenticatorState.MaxEnrolledTemplatesCapacity; i++)
        {
            _ = await CompleteEnrollmentAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);
        }

        using PooledMemory response = await SendEnrollBeginRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        Assert.AreEqual(WellKnownCtapStatusCodes.FpDatabaseFull, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enumerateEnrollments</c> with zero provisioned templates answers <c>InvalidOption</c> — the spec's own exact code, not a "not found" invention (snapshot line 6836).</summary>
    [TestMethod]
    public async Task EnumerateEnrollmentsWithNoTemplatesReturnsInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-enumerate-empty");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        using PooledMemory response = await SendEnumerateEnrollmentsRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>enumerateEnrollments</c> reports every provisioned template's REAL persisted identifier and (initially null) friendly name.</summary>
    [TestMethod]
    public async Task EnumerateEnrollmentsReturnsRealPersistedTemplates()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-enumerate-real");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);
        byte[] completedTemplateId = await CompleteEnrollmentAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        using PooledMemory response = await SendEnumerateEnrollmentsRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        Assert.IsNotNull(decoded.TemplateInfos);
        Assert.HasCount(1, decoded.TemplateInfos!);
        Assert.IsTrue(decoded.TemplateInfos![0].TemplateId.Span.SequenceEqual(completedTemplateId));
        Assert.IsNull(decoded.TemplateInfos![0].TemplateFriendlyName, "friendly name is null until setFriendlyName assigns one.");
    }


    /// <summary><c>setFriendlyName</c> renames an existing template, verified through a real <c>enumerateEnrollments</c> round trip afterward.</summary>
    [TestMethod]
    public async Task SetFriendlyNameRenamesExistingTemplate()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-setfriendlyname-happy");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);
        byte[] templateId = await CompleteEnrollmentAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        const string friendlyName = "left thumb";
        byte[] param = await ComputeGatedSignatureAsync(token, CtapPinUvAuthProtocolId.Two, pool, WellKnownCtapBioEnrollmentSubCommands.SetFriendlyName, templateId, friendlyName);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.SetFriendlyName,
            TemplateId: templateId, TemplateFriendlyName: friendlyName, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: param);
        using(PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
            Assert.AreEqual(1, response.Length, "setFriendlyName's success response carries no CBOR body.");
        }

        using PooledMemory enumerateResponse = await SendEnumerateEnrollmentsRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);
        CtapBioEnrollmentResponse decoded = CtapBioEnrollmentResponseCborReader.Read(enumerateResponse.AsReadOnlyMemory()[1..]);
        Assert.AreEqual(friendlyName, decoded.TemplateInfos![0].TemplateFriendlyName);
    }


    /// <summary><c>setFriendlyName</c> naming an unknown <c>templateId</c> answers <c>InvalidOption</c> (snapshot line 6890).</summary>
    [TestMethod]
    public async Task SetFriendlyNameWithUnknownTemplateIdReturnsInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-setfriendlyname-unknown");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        byte[] unknownTemplateId = new byte[16];
        byte[] param = await ComputeGatedSignatureAsync(token, CtapPinUvAuthProtocolId.Two, pool, WellKnownCtapBioEnrollmentSubCommands.SetFriendlyName, unknownTemplateId, "ghost");
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.SetFriendlyName,
            TemplateId: unknownTemplateId, TemplateFriendlyName: "ghost", PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: param);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary><c>removeEnrollment</c> deletes an existing template, verified through a real subsequent <c>enumerateEnrollments</c> reporting no enrollments.</summary>
    [TestMethod]
    public async Task RemoveEnrollmentDeletesExistingTemplate()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-remove-happy");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);
        byte[] templateId = await CompleteEnrollmentAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        byte[] param = await ComputeGatedSignatureAsync(token, CtapPinUvAuthProtocolId.Two, pool, WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment, templateId);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment,
            TemplateId: templateId, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: param);
        using(PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
            Assert.AreEqual(1, response.Length, "removeEnrollment's success response carries no CBOR body.");
        }

        using PooledMemory enumerateResponse = await SendEnumerateEnrollmentsRawAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, enumerateResponse.AsReadOnlySpan()[0], "no enrollments remain once the only template is removed.");
    }


    /// <summary><c>removeEnrollment</c> naming an unknown <c>templateId</c> answers <c>InvalidOption</c> (snapshot line 6936).</summary>
    [TestMethod]
    public async Task RemoveEnrollmentWithUnknownTemplateIdReturnsInvalidOption()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-remove-unknown");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        byte[] unknownTemplateId = new byte[16];
        byte[] param = await ComputeGatedSignatureAsync(token, CtapPinUvAuthProtocolId.Two, pool, WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment, unknownTemplateId);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment,
            TemplateId: unknownTemplateId, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: param);
        using PooledMemory response = await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// R2's tri-state flip, proven from REAL <c>authenticatorGetInfo</c> bytes: <c>bioEnroll</c>/<c>uv</c>
    /// flip present-false → present-true once the FIRST enrollment completes, and flip back to
    /// present-false once the LAST template is removed.
    /// </summary>
    [TestMethod]
    public async Task EnrollmentTriStateFlipsBioEnrollAndUvOnRealGetInfoBytes()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-tristate-flip");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] token = await EstablishPinAndIssueBeTokenAsync(simulator, pool, CtapPinUvAuthProtocolId.Two);

        CtapGetInfoResponse beforeInfo = await CtapWaveConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsFalse(beforeInfo.Options!.BioEnroll);
        Assert.IsFalse(beforeInfo.Options!.Uv);

        byte[] templateId = await CompleteEnrollmentAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        CtapGetInfoResponse afterEnrollInfo = await CtapWaveConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(afterEnrollInfo.Options!.BioEnroll, "the first completed enrollment must flip bioEnroll to true.");
        Assert.IsTrue(afterEnrollInfo.Options!.Uv, "uv derives from the same single source as bioEnroll.");

        byte[] removeParam = await ComputeGatedSignatureAsync(token, CtapPinUvAuthProtocolId.Two, pool, WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment, templateId);
        var removeRequest = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment,
            TemplateId: templateId, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, PinUvAuthParam: removeParam);
        using(PooledMemory removeResponse = await SendBioEnrollmentAsync(simulator, removeRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, removeResponse.AsReadOnlySpan()[0]);
        }

        CtapGetInfoResponse afterRemoveInfo = await CtapWaveConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsFalse(afterRemoveInfo.Options!.BioEnroll, "removing the LAST template must flip bioEnroll back to false.");
        Assert.IsFalse(afterRemoveInfo.Options!.Uv);
    }


    /// <summary>
    /// Row 6623's SHOULD NOT (token survives enrollment completion): a single PIN-path token minted with
    /// <c>be | mc</c> permissions completes an enrollment and then still succeeds at
    /// <c>authenticatorMakeCredential</c>, with no re-issuance — bio enrollment tests no user presence,
    /// so the 5828 permission-stripping narrowing never fires.
    /// </summary>
    [TestMethod]
    public async Task TokenSurvivesEnrollmentCompletionAndSucceedsAtMakeCredentialAfterward()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("bio-6623-token-survival");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin, TestContext.CancellationToken);
        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, CtapPinUvAuthProtocolId.Two, DefaultPin,
            WellKnownCtapPinUvAuthTokenPermissions.Be | WellKnownCtapPinUvAuthTokenPermissions.Mc, DefaultRpId, TestContext.CancellationToken);

        _ = await CompleteEnrollmentAsync(simulator, pool, token, CtapPinUvAuthProtocolId.Two);

        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, McClientDataHash, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest mcRequest = BuildMakeCredentialRequest(pool, pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        using PooledMemory mcResponse = await SendMakeCredentialAsync(simulator, mcRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, mcResponse.AsReadOnlySpan()[0], "row 6623: the enrollment-completing token must still succeed at mc afterward, with no re-issuance.");
    }


    /// <summary>The fixed <c>clientDataHash</c> bytes <see cref="BuildMakeCredentialRequest"/> always embeds — the mc verify message, mirroring <see cref="CtapAuthenticatorPinUvAuthBindingTests"/>'s own constant.</summary>
    private static byte[] McClientDataHash => BuildFixedBytes(32, 0x10);


    /// <summary>Establishes <see cref="DefaultPin"/> and issues an unbound <c>be</c>-only-permissioned <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c> (0x09) — <c>be</c>'s own RP ID column is "Ignored", so no <c>rpId</c> is supplied.</summary>
    private async Task<byte[]> EstablishPinAndIssueBeTokenAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId)
    {
        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        return await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Be, rpId: null, TestContext.CancellationToken);
    }


    /// <summary>Computes a gated subcommand's own <c>pinUvAuthParam</c> (bio scout Finding C: the TWO-byte <c>modality || subCommand [|| subCommandParams]</c> prefix).</summary>
    private async Task<byte[]> ComputeGatedSignatureAsync(
        byte[] token, CtapPinUvAuthProtocolId protocolId, MemoryPool<byte> pool, int subCommand, ReadOnlyMemory<byte>? templateId = null, string? templateFriendlyName = null)
    {
        ReadOnlyMemory<byte> subCommandParams = templateId is not null || templateFriendlyName is not null
            ? BuildSubCommandParams(templateId, templateFriendlyName)
            : ReadOnlyMemory<byte>.Empty;
        byte[] message = BuildMessage(WellKnownCtapBioEnrollmentModalities.Fingerprint, subCommand, subCommandParams);

        return await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, TestContext.CancellationToken);
    }


    /// <summary>Sends a fully signed <c>enrollBegin</c> and returns the raw response envelope — the caller owns it and must dispose it.</summary>
    private async Task<PooledMemory> SendEnrollBeginRawAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, byte[] token, CtapPinUvAuthProtocolId protocolId)
    {
        byte[] param = await ComputeGatedSignatureAsync(token, protocolId, pool, WellKnownCtapBioEnrollmentSubCommands.EnrollBegin);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);

        return await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);
    }


    /// <summary>Sends a fully signed <c>enrollBegin</c>, asserts <c>CTAP2_OK</c>, and returns the minted <c>templateId</c> bytes.</summary>
    private async Task<byte[]> SendEnrollBeginAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, byte[] token, CtapPinUvAuthProtocolId protocolId)
    {
        using PooledMemory response = await SendEnrollBeginRawAsync(simulator, pool, token, protocolId);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        return CtapBioEnrollmentResponseCborReader.Read(response.AsReadOnlyMemory()[1..]).TemplateId!.Value.ToArray();
    }


    /// <summary>Sends a fully signed <c>enrollCaptureNextSample</c> for <paramref name="templateId"/> and returns the raw response envelope — the caller owns it and must dispose it.</summary>
    private async Task<PooledMemory> SendEnrollCaptureNextSampleRawAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, byte[] token, CtapPinUvAuthProtocolId protocolId, byte[] templateId)
    {
        byte[] param = await ComputeGatedSignatureAsync(token, protocolId, pool, WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample, templateId);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample,
            TemplateId: templateId, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);

        return await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);
    }


    /// <summary>Sends a fully signed <c>enumerateEnrollments</c> and returns the raw response envelope — the caller owns it and must dispose it.</summary>
    private async Task<PooledMemory> SendEnumerateEnrollmentsRawAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, byte[] token, CtapPinUvAuthProtocolId protocolId)
    {
        byte[] param = await ComputeGatedSignatureAsync(token, protocolId, pool, WellKnownCtapBioEnrollmentSubCommands.EnumerateEnrollments);
        var request = new CtapBioEnrollmentRequest(
            Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint, SubCommand: WellKnownCtapBioEnrollmentSubCommands.EnumerateEnrollments,
            PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);

        return await SendBioEnrollmentAsync(simulator, request, pool, TestContext.CancellationToken);
    }


    /// <summary>
    /// Drives a complete enrollment lifecycle — one <c>enrollBegin</c> plus enough <c>enrollCaptureNextSample</c>
    /// calls (the default always-GOOD simulated sensor) to reach <c>remainingSamples</c> zero — and returns
    /// the persisted template's identifier bytes.
    /// </summary>
    private async Task<byte[]> CompleteEnrollmentAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, byte[] token, CtapPinUvAuthProtocolId protocolId)
    {
        byte[] templateId = await SendEnrollBeginAsync(simulator, pool, token, protocolId);

        for(int sample = 1; sample < CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll; sample++)
        {
            using PooledMemory response = await SendEnrollCaptureNextSampleRawAsync(simulator, pool, token, protocolId, templateId);
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
        }

        return templateId;
    }


    /// <summary>The <c>enrollBegin</c> subCommand ID (<c>0x01</c>), used as a <c>DataRow</c> constant.</summary>
    private const int WellKnownCtapBioEnrollmentSubCommandsEnrollBegin = 0x01;

    /// <summary>The <c>enrollCaptureNextSample</c> subCommand ID (<c>0x02</c>), used as a <c>DataRow</c> constant.</summary>
    private const int WellKnownCtapBioEnrollmentSubCommandsEnrollCaptureNextSample = 0x02;

    /// <summary>The <c>enumerateEnrollments</c> subCommand ID (<c>0x04</c>), used as a <c>DataRow</c> constant.</summary>
    private const int WellKnownCtapBioEnrollmentSubCommandsEnumerateEnrollments = 0x04;

    /// <summary>The <c>setFriendlyName</c> subCommand ID (<c>0x05</c>), used as a <c>DataRow</c> constant.</summary>
    private const int WellKnownCtapBioEnrollmentSubCommandsSetFriendlyName = 0x05;

    /// <summary>The <c>removeEnrollment</c> subCommand ID (<c>0x06</c>), used as a <c>DataRow</c> constant.</summary>
    private const int WellKnownCtapBioEnrollmentSubCommandsRemoveEnrollment = 0x06;
}

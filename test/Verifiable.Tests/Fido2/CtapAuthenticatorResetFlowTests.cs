using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wavereset real-wire capstones for <c>authenticatorReset</c> (<c>0x07</c>): capstone A (the full
/// factory-reset lifecycle) and capstone B (the 10-second power-up window), both driven over the real,
/// unmodified APDU transport stack (<see cref="CtapWave2TransportHarness"/>), mirroring
/// <see cref="CtapAuthenticatorConfigFlowTests"/>'s composition. Every assertion reads a wire-visible
/// fact only -- response bytes, <see cref="CtapCommandException.StatusCode"/>, or a decoded
/// <c>authenticatorGetInfo</c> response -- never internal simulator state (<see cref="CtapAuthenticatorSimulator.PowerCycle"/>
/// is the one sanctioned exception: CTAP 2.3's own physical-replug seam, not a wire command, per R10).
/// Every <c>pinUvAuthParam</c> is computed with the real <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/>
/// over wire-received bytes, through <see cref="CtapWave5bPinCryptoFixtures"/>' session helpers.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorResetFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Capstone A: the full factory-reset lifecycle over real APDU. Captures the simulator's birth
    /// <c>authenticatorGetInfo</c> bytes, drives it through a PIN, two discoverable-credential
    /// registrations, a raised minimum PIN length with <c>forceChangePin</c>, <c>alwaysUv</c> enabled,
    /// and one wrong-PIN attempt (<c>pinRetries</c> observably dropping on the wire), then issues bare
    /// <c>authenticatorReset</c> (<c>0x07</c>) ON THE WIRE and proves every CTAP 2.3 §6.6 factory-default
    /// consequence from wire-visible facts alone: a status-only <c>CTAP2_OK</c> response frame; birth-byte
    /// <c>getInfo</c> equality (R8); <c>pinRetries</c> back at maximum; a regenerated
    /// <c>getKeyAgreement</c> key; a pre-reset credential unlocatable post-reset
    /// (<see cref="WellKnownCtapStatusCodes.NoCredentials"/>); a pre-reset <c>pinUvAuthToken</c> failing
    /// to authenticate a post-reset <c>mc</c> (<see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/>, line
    /// 6138); a fresh 4-code-point <c>setPIN</c> succeeding (minPINLength reverted); and a full
    /// <c>mc</c>/<c>ga</c> round trip succeeding factory-fresh.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The stale-token-on-<c>mc</c> proof needs the PIN re-established FIRST: this authenticator only
    /// enters its cryptographic <c>pinUvAuthParam</c> verification path when
    /// <c>CurrentStoredPin is not null</c> (<c>OnMakeCredentialRequested</c>'s own protected-branch gate)
    /// -- while unprotected, any presented <c>pinUvAuthParam</c>, stale or not, is ignored per the spec's
    /// own step-11 structure, so the wire proof would silently pass without ever exercising verification.
    /// This mirrors the in-process PKG-A unit test's own identical reordering necessity, not a departure
    /// from it.
    /// </para>
    /// <para>
    /// <c>setMinPINLength</c>'s own successful completion mints a fresh <c>pinUvAuthToken</c> for BOTH
    /// protocols (the fenced <c>CtapResetPinUvAuthTokensAction</c>/<c>ResetPinUvAuthTokensAsync</c>
    /// sibling's own step-7 side effect) and leaves <c>forcePINChange</c> pending, which blocks EVERY new
    /// token issuance until a compliant <c>changePIN</c> clears it -- so the combined
    /// <c>mc</c>|<c>ga</c>|<c>acfg</c> token this method later presents to <c>mc</c> after the reset is
    /// issued only once that recovery dance completes, mirroring
    /// <see cref="CtapAuthenticatorConfigFlowTests"/>'s own <c>setMinPINLength</c> capstone.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task FullFactoryResetLifecycleOverRealApduTransport()
    {
        const string RpId = "wavereset-capstone-a.example";
        const string Pin = "1234";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("wavereset-capstone-a");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        byte[] birthGetInfoBytes = await GetInfoBytesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness.Transceive, pool, protocolId, Pin, cancellationToken).ConfigureAwait(false);

        byte[] firstCredentialIdBytes = await RegisterDiscoverableCredentialAsync(
            harness.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xC0), cancellationToken)
            .ConfigureAwait(false);
        _ = await RegisterDiscoverableCredentialAsync(
            harness.Transceive, pool, protocolId, Pin, RpId, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xC1), cancellationToken)
            .ConfigureAwait(false);

        //A single acfg-permissioned token drives BOTH toggleAlwaysUv and setMinPINLength:
        //authenticatorConfig strips no permissions on success, so the SAME token survives both calls --
        //but setMinPINLength's own successful completion mints a fresh pinUvAuthToken for BOTH protocols
        //as its own step-7 side effect (the fenced CtapResetPinUvAuthTokensAction/ResetPinUvAuthTokensAsync
        //sibling), so this token itself does not survive PAST setMinPINLength.
        byte[] acfgToken = await IssueTokenAsync(
            harness.Transceive, pool, protocolId, Pin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, cancellationToken).ConfigureAwait(false);
        await SendToggleAlwaysUvAsync(harness.Transceive, pool, protocolId, acfgToken, cancellationToken).ConfigureAwait(false);
        await SendSetMinPinLengthAsync(harness.Transceive, pool, protocolId, acfgToken, newMinPinLength: 6, forceChangePin: true, cancellationToken)
            .ConfigureAwait(false);

        //forcePINChange is now pending, which blocks EVERY new token issuance (PinPolicyViolation) until
        //a compliant PIN change clears it -- the identical recovery dance
        //CtapAuthenticatorConfigFlowTests' own setMinPINLength capstone performs. The raised minimum (6)
        //is honored by the new PIN's own length.
        const string RaisedPin = "123456";
        await ChangePinAsync(harness.Transceive, pool, protocolId, Pin, RaisedPin, cancellationToken).ConfigureAwait(false);

        int retriesBeforeMismatch = await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(CtapAuthenticatorState.MaxPinRetries, retriesBeforeMismatch, "a compliant changePIN resets pinRetries to maximum.");

        await AttemptWrongPinAsync(harness.Transceive, pool, protocolId, cancellationToken).ConfigureAwait(false);

        int retriesAfterMismatch = await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(retriesBeforeMismatch - 1, retriesAfterMismatch, "a wrong-PIN attempt must drop pinRetries by one, observed on the wire.");

        CoseKey preResetKeyAgreement = await GetKeyAgreementAsync(harness.Transceive, protocolId, pool, cancellationToken).ConfigureAwait(false);

        //Issued LAST, once forcePINChange has cleared and nothing further consumes it before the reset
        //below: it remains "live" and byte-identical to what the post-reset stale-token proof needs.
        int mcGaAcfg = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga | WellKnownCtapPinUvAuthTokenPermissions.Acfg;
        byte[] preResetToken = await IssueTokenAsync(harness.Transceive, pool, protocolId, RaisedPin, mcGaAcfg, RpId, cancellationToken).ConfigureAwait(false);

        using(PooledMemory resetResponse = await SendResetAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(1, resetResponse.Length, "authenticatorReset's successful response frame carries a bare status byte only, no CBOR body.");
            Assert.AreEqual(
                WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0],
                "authenticatorReset must return CTAP2_OK on the wire once every condition is met.");
        }

        byte[] postResetGetInfoBytes = await GetInfoBytesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreSequenceEqual(birthGetInfoBytes, postResetGetInfoBytes, "post-reset getInfo bytes must be byte-identical to the birth capture (R8).");

        Assert.AreEqual(
            CtapAuthenticatorState.MaxPinRetries, await GetPinRetriesAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false),
            "pinRetries must revert to maximum after a successful reset, on the wire.");

        CoseKey postResetKeyAgreement = await GetKeyAgreementAsync(harness.Transceive, protocolId, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(
            preResetKeyAgreement.X!.Value.Span.SequenceEqual(postResetKeyAgreement.X!.Value.Span),
            "getKeyAgreement must return a different COSE key after a successful reset, proving key-agreement regeneration on the wire.");

        CtapGetAssertionRequest staleAllowListRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(firstCredentialIdBytes, pool) }]);
        CtapCommandException staleGaException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                harness.Transceive, CtapGetAssertionRequestCborWriter.Write, staleAllowListRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(staleAllowListRequest);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.NoCredentials, staleGaException.StatusCode, "a pre-reset credential must not be locatable after reset, on the wire.");

        await EstablishPinAsync(harness.Transceive, pool, protocolId, Pin, cancellationToken).ConfigureAwait(false);

        byte[] staleClientDataHashBytes = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x10);
        byte[] staleMcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(preResetToken, protocolId, staleClientDataHashBytes, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapMakeCredentialRequest staleMcRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: RpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF0), pinUvAuthParam: staleMcParam, pinUvAuthProtocol: (int)protocolId);
        CtapCommandException staleMcException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, staleMcRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(staleMcRequest);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.PinAuthInvalid, staleMcException.StatusCode,
            "a pre-reset pinUvAuthToken must fail to authenticate a post-reset mc call with PinAuthInvalid, on the wire (line 6138).");

        byte[] finalUserId = CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF1);
        CtapMakeCredentialRequest finalMcRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, rpId: RpId, userId: finalUserId);
        CtapMakeCredentialResponse finalMcResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, finalMcRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(finalMcRequest);

        byte[] finalCredentialIdBytes;
        using(AuthenticatorData finalAuthenticatorData = AuthenticatorDataReader.Read(finalMcResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            finalCredentialIdBytes = finalAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        CtapGetAssertionRequest finalGaRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(finalCredentialIdBytes, pool) }]);
        CtapGetAssertionResponse finalGaResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, finalGaRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(finalGaRequest);
        finalGaResponse.Credential.Id.Dispose();
        finalGaResponse.User?.Id.Dispose();
    }


    /// <summary>
    /// Capstone B: the 10-second power-up window over real APDU. A reset issued after the window has
    /// elapsed fails with <see cref="WellKnownCtapStatusCodes.NotAllowed"/> ON THE WIRE and leaves the
    /// credential store intact (a subsequent <c>ga</c> still locates the registered credential);
    /// <see cref="CtapAuthenticatorSimulator.PowerCycle"/> (the physical-replug seam, CTAP 2.3 §6.6 lines
    /// 6365-6366's own "powering up" framing) re-arms the window, so a reset issued immediately afterward
    /// succeeds; and a SUCCESSFUL reset does not itself re-arm the window -- a second reset issued once
    /// total elapsed time since the power cycle again exceeds 10 seconds fails the identical way.
    /// </summary>
    [TestMethod]
    public async Task PowerUpWindowGatesResetOverRealApduTransport()
    {
        const string RpId = "wavereset-capstone-b.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("wavereset-capstone-b", timeProvider: timeProvider);
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        byte[] userId = CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xB0);
        CtapMakeCredentialRequest registrationRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(pool, rpId: RpId, userId: userId);
        CtapMakeCredentialResponse registrationResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, registrationRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(registrationRequest);

        byte[] credentialIdBytes;
        using(AuthenticatorData registrationAuthenticatorData = AuthenticatorDataReader.Read(registrationResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            credentialIdBytes = registrationAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        timeProvider.Advance(TimeSpan.FromSeconds(11));

        using(PooledMemory tooLate = await SendResetAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(
                WellKnownCtapStatusCodes.NotAllowed, tooLate.AsReadOnlySpan()[0],
                "a reset issued after the 10-second power-up window must fail on the wire.");
        }

        CtapGetAssertionRequest survivingGaRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(credentialIdBytes, pool) }]);
        CtapGetAssertionResponse survivingGaResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, survivingGaRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(survivingGaRequest);
        survivingGaResponse.Credential.Id.Dispose();
        survivingGaResponse.User?.Id.Dispose();

        simulator.PowerCycle();

        using(PooledMemory afterPowerCycle = await SendResetAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(
                WellKnownCtapStatusCodes.Ok, afterPowerCycle.AsReadOnlySpan()[0],
                "a power cycle re-arms the 10-second power-up window, observed on the wire.");
        }

        timeProvider.Advance(TimeSpan.FromSeconds(11));

        using PooledMemory second = await SendResetAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.NotAllowed, second.AsReadOnlySpan()[0],
            "a successful reset must not restamp PoweredOnAt: the window here is measured from the power cycle, not from the reset that just succeeded.");
    }


    /// <summary>Sends a bare <c>authenticatorReset</c> request over <paramref name="transceive"/>, returning the raw response envelope.</summary>
    private static ValueTask<PooledMemory> SendResetAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.Reset];

        return transceive(request, pool, cancellationToken);
    }


    /// <summary>Sends a bare <c>authenticatorGetInfo</c> request over <paramref name="transceive"/> and returns the raw response bytes.</summary>
    private static async Task<byte[]> GetInfoBytesAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await transceive(request, pool, cancellationToken).ConfigureAwait(false);

        return response.AsReadOnlySpan().ToArray();
    }


    /// <summary>Establishes <paramref name="pin"/> as the authenticator's PIN over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task EstablishPinAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Changes the authenticator's PIN from <paramref name="oldPin"/> to <paramref name="newPin"/> via
    /// <c>changePIN</c> over <paramref name="transceive"/>'s real transport -- needs no existing
    /// <c>pinUvAuthToken</c>, only knowledge of the current PIN, so it remains available even while
    /// <c>forcePINChange</c> is pending (the one operation that clears it).
    /// </summary>
    private static async Task ChangePinAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string oldPin, string newPin,
        CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] pinUvAuthParam) =
            await session.BuildChangePinMessagesAsync(newPin, oldPin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc, PinHashEnc: pinHashEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a permissions-scoped <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c>
    /// (<c>0x09</c>) over <paramref name="transceive"/>'s real transport, decrypting it from wire bytes only.
    /// </summary>
    private static async Task<byte[]> IssueTokenAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, int permissions, string? rpId,
        CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers one discoverable (<c>rk</c>) credential for <paramref name="userId"/> under
    /// <paramref name="rpId"/>, driven by a freshly issued single-use <c>mc</c>-permissioned token over
    /// <paramref name="transceive"/>'s real transport: once a PIN is set, resident-credential creation
    /// requires a <c>pinUvAuthToken</c> regardless of <c>alwaysUv</c>, and a successful <c>mc</c> strips
    /// the token it consumes of every permission but <c>lbw</c>, so each registration needs its own token.
    /// </summary>
    private static async Task<byte[]> RegisterDiscoverableCredentialAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, string rpId, byte[] userId,
        CancellationToken cancellationToken)
    {
        byte[] token = await IssueTokenAsync(
            transceive, pool, protocolId, pin, WellKnownCtapPinUvAuthTokenPermissions.Mc, rpId, cancellationToken).ConfigureAwait(false);

        byte[] clientDataHashBytes = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x10);
        byte[] pinUvAuthParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, clientDataHashBytes, pool, cancellationToken)
            .ConfigureAwait(false);

        CtapMakeCredentialRequest request = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: rpId, userId: userId, options: new CtapCommandOptions(ResidentKey: true),
            pinUvAuthParam: pinUvAuthParam, pinUvAuthProtocol: (int)protocolId);
        CtapMakeCredentialResponse response = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(request);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);

        return authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Sends an <c>authenticatorConfig</c> request over <paramref name="transceive"/>'s real transport,
    /// throwing <see cref="CtapCommandException"/> for a non-success status -- reaching the caller's next
    /// line is itself the wire proof of <c>CTAP2_OK</c>.
    /// </summary>
    private static async Task SendAuthenticatorConfigAsync(
        Ctap2TransceiveDelegate transceive, CtapAuthenticatorConfigRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] envelope = CtapWaveConfigFixtures.BuildAuthenticatorConfigEnvelope(request);
        using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);

        byte statusCode = response.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(statusCode))
        {
            throw new CtapCommandException(statusCode);
        }
    }


    /// <summary>
    /// Sends <c>setMinPINLength</c> with an already-issued <paramref name="token"/> over
    /// <paramref name="transceive"/>'s real transport, computing the platform-side <c>pinUvAuthParam</c>
    /// over the SAME <c>subCommandParams</c> bytes the request will carry.
    /// </summary>
    private static async Task SendSetMinPinLengthAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, byte[] token, int newMinPinLength, bool forceChangePin,
        CancellationToken cancellationToken)
    {
        byte[] subCommandParams = CtapWaveConfigFixtures.BuildSubCommandParams(newMinPinLength: newMinPinLength, forceChangePin: forceChangePin);
        byte[] message = CtapWaveConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, subCommandParams);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken).ConfigureAwait(false);

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, NewMinPinLength: newMinPinLength, ForceChangePin: forceChangePin,
            PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);

        await SendAuthenticatorConfigAsync(transceive, request, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Sends <c>toggleAlwaysUv</c> with an already-issued <paramref name="token"/> over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task SendToggleAlwaysUvAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, byte[] token, CancellationToken cancellationToken)
    {
        byte[] message = CtapWaveConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken).ConfigureAwait(false);

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);

        await SendAuthenticatorConfigAsync(transceive, request, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reads the current <c>pinRetries</c> value via <c>getPINRetries</c> over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task<int> GetPinRetriesAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return response.PinRetries!.Value;
    }


    /// <summary>Reads a protocol's current key-agreement public key via <c>getKeyAgreement</c> over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task<CoseKey> GetKeyAgreementAsync(
        Ctap2TransceiveDelegate transceive, CtapPinUvAuthProtocolId protocolId, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)protocolId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return response.KeyAgreement!;
    }


    /// <summary>
    /// Attempts <c>getPinToken</c> with a deliberately wrong <c>pinHashEnc</c> over
    /// <paramref name="transceive"/>'s real transport, asserting the call fails -- the mismatch drops
    /// <c>pinRetries</c> by one regardless of the outcome status, the wire proof
    /// <see cref="GetPinRetriesAsync"/> reads before and after this call verifies.
    /// </summary>
    private static async Task AttemptWrongPinAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] wrongPinHashEnc = await session.BuildWrongPinHashEncAsync(cancellationToken).ConfigureAwait(false);
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);

        _ = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).AsTask());
    }
}

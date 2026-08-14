using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The real-wire capstones for <c>authenticatorConfig</c> (<c>0x0D</c>): the same real,
/// unmodified APDU transport stack (<see cref="CtapNfcTransportHarness"/>) the capstones in
/// <see cref="CtapAuthenticatorClientPinFlowTests"/> use, driving <c>toggleAlwaysUv</c>'s live mc/ga
/// gating and <c>setMinPINLength</c>'s <c>forcePINChange</c> gates end to end. Every assertion reads a
/// wire-visible fact only — <see cref="AuthenticatorDataReader"/> flags, <see cref="CtapCommandException.StatusCode"/>,
/// or a decoded <c>authenticatorGetInfo</c> response — never internal simulator state; every
/// <c>pinUvAuthParam</c> is computed with the real <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/>
/// over wire-received bytes, via <see cref="CtapConfigFixtures"/>' shared message-assembly helpers.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorConfigFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// The full <c>toggleAlwaysUv</c> lifecycle over the real APDU transport: an unprotected, tokenless
    /// enable flips <c>authenticatorGetInfo</c>'s <c>alwaysUv</c>/<c>makeCredUvNotRqd</c> bytes; once a
    /// PIN is set, a tokenless <c>authenticatorMakeCredential</c> now fails with <c>PuatRequired</c>
    /// (<c>0x36</c>) ON THE WIRE, while a silent (<c>up:false</c>) <c>authenticatorGetAssertion</c> still
    /// succeeds with <c>up=0</c> — the carve-out CTAP 2.3's own step 5 (line 3917) preserves; a
    /// permissions-scoped token carrying <c>mc|ga|acfg</c> then drives <c>toggleAlwaysUv</c>'s disable
    /// leg (message <c>32×0xff||0x0d||0x02</c>, <c>subCommandParams</c> elided) BEFORE that SAME token is
    /// ever used for <c>mc</c> — proving that <c>authenticatorConfig</c> does not strip a token's
    /// other permissions) the only way that is actually observable: if config stripped permissions the
    /// way a successful <c>mc</c>/<c>ga</c> does, the subsequent <c>mc</c> call below would fail. Closes
    /// with <c>authenticatorGetInfo</c> reverting and a final tokenless <c>mc</c> succeeding with
    /// <c>uv=0</c> again, exactly like before the toggle.
    /// </summary>
    [TestMethod]
    public async Task ToggleAlwaysUvLifecycleOverRealApduTransport()
    {
        const string RpId = "config-capstone-a.example";
        const string Pin = "1234";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("config-capstone-a");
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        //Setup, fully unprotected (no PIN, alwaysUv still off): mint a credential the up:false carve-out
        //leg below can silently locate once alwaysUv is live -- minting after alwaysUv is enabled is not
        //possible without a token (see the method's own remarks).
        byte[] presetupUserId = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0xC0);
        CtapMakeCredentialRequest presetupRequest = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(pool, rpId: RpId, userId: presetupUserId);
        CtapMakeCredentialResponse presetupResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, presetupRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(presetupRequest);
        byte[] presetupCredentialIdBytes;
        using(AuthenticatorData presetupAuthenticatorData = AuthenticatorDataReader.Read(presetupResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            presetupCredentialIdBytes = presetupAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        //Unprotected, alwaysUv currently false: the shared prologue's gate never applies at all (neither
        //protected nor alwaysUv) -- a completely tokenless enable.
        await CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
            harness.Transceive, CtapAuthenticatorConfigRequestCborWriter.Write,
            new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv), pool, cancellationToken)
            .ConfigureAwait(false);

        CtapGetInfoResponse infoAfterEnable = await GetInfoAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(infoAfterEnable.Options!.AlwaysUv!.Value, "toggleAlwaysUv's enable leg must flip alwaysUv to true on the wire.");
        Assert.IsFalse(infoAfterEnable.Options!.MakeCredUvNotRqd!.Value, "line 4951's MUST: alwaysUv:true forces makeCredUvNotRqd:false on the wire.");

        await EstablishPinAsync(harness.Transceive, pool, CtapPinUvAuthProtocolId.Two, Pin, cancellationToken).ConfigureAwait(false);

        //Protected + alwaysUv on + no token: mc's step 6 rejects, ON THE WIRE, before excludeList/rk are
        //ever consulted.
        byte[] tokenlessUserId = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0xC1);
        CtapMakeCredentialRequest tokenlessMcRequest = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(pool, rpId: RpId, userId: tokenlessUserId);
        CtapCommandException tokenlessMcException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, tokenlessMcRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, tokenlessMcException.StatusCode, "alwaysUv must force a pinUvAuthToken for mc, observed on the wire.");
        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(tokenlessMcRequest);

        //A silent (up:false) ga is NEVER subject to alwaysUv (the carve-out) -- it still succeeds, up=0.
        CtapGetAssertionRequest silentGaRequest = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(presetupCredentialIdBytes, pool) }],
            options: new CtapCommandOptions(UserPresence: false));
        CtapGetAssertionResponse silentGaResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, silentGaRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(silentGaRequest);
        using(AuthenticatorData silentGaAuthenticatorData = AuthenticatorDataReader.Read(silentGaResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsFalse(silentGaAuthenticatorData.Flags.UserPresent, "the up:false carve-out: alwaysUv must not force up/uv on a silent ga.");
            Assert.IsFalse(silentGaAuthenticatorData.Flags.UserVerified, "the up:false carve-out: alwaysUv must not force up/uv on a silent ga.");
        }
        silentGaResponse.Credential.Id.Dispose();
        silentGaResponse.User?.Id.Dispose();

        int mcGaAcfg = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga | WellKnownCtapPinUvAuthTokenPermissions.Acfg;
        byte[] token = await IssueTokenAsync(harness.Transceive, pool, CtapPinUvAuthProtocolId.Two, Pin, mcGaAcfg, RpId, cancellationToken).ConfigureAwait(false);

        //The SAME token drives toggleAlwaysUv's disable leg FIRST -- the message is exactly
        //32×0xff||0x0d||0x02 with subCommandParams elided, since toggleAlwaysUv takes no parameters.
        byte[] disableMessage = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] disableParam = await CtapConfigFixtures.ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, disableMessage, pool, cancellationToken)
            .ConfigureAwait(false);
        await CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
            harness.Transceive, CtapAuthenticatorConfigRequestCborWriter.Write,
            new CtapAuthenticatorConfigRequest(
                SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
                PinUvAuthParam: disableParam),
            pool, cancellationToken).ConfigureAwait(false);

        CtapGetInfoResponse infoAfterDisable = await GetInfoAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(infoAfterDisable.Options!.AlwaysUv!.Value, "toggleAlwaysUv's disable leg must flip alwaysUv back to false on the wire.");
        Assert.IsTrue(infoAfterDisable.Options!.MakeCredUvNotRqd!.Value, "disabling alwaysUv must restore makeCredUvNotRqd's default true on the wire.");

        //Wire-proven: the SAME token -- unstripped by the config call above -- still completes an
        //mc with its mc permission bit, uv=1.
        byte[] mcMessage = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x10);
        byte[] mcParam = await CtapConfigFixtures.ComputeSignatureAsync(token, CtapPinUvAuthProtocolId.Two, mcMessage, pool, cancellationToken).ConfigureAwait(false);
        byte[] postConfigUserId = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0xC2);
        CtapMakeCredentialRequest postConfigMcRequest = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(
            pool, rpId: RpId, userId: postConfigUserId, pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        CtapMakeCredentialResponse postConfigMcResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, postConfigMcRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(postConfigMcRequest);
        using(AuthenticatorData postConfigAuthenticatorData = AuthenticatorDataReader.Read(postConfigMcResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(
                postConfigAuthenticatorData.Flags.UserVerified,
                "a token used for authenticatorConfig must still authenticate a subsequent mc call with uv=1 -- no permission stripping.");
        }

        //Closing check: alwaysUv is off again, so a tokenless mc succeeds exactly like before the toggle.
        byte[] finalUserId = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0xC3);
        CtapMakeCredentialRequest finalMcRequest = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(pool, rpId: RpId, userId: finalUserId);
        CtapMakeCredentialResponse finalMcResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, finalMcRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(finalMcRequest);
        using(AuthenticatorData finalAuthenticatorData = AuthenticatorDataReader.Read(finalMcResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsFalse(finalAuthenticatorData.Flags.UserVerified, "once alwaysUv is disabled again, a tokenless mc must succeed with uv=0, as before the toggle.");
        }
    }


    /// <summary>
    /// The <c>setMinPINLength</c>/<c>forcePINChange</c> journey over the real APDU transport: an
    /// <c>acfg</c>-only token raises the minimum PIN length above the current 4-code-point PIN's own
    /// length, which auto-forces a PIN change (no <c>forceChangePin</c> parameter needed);
    /// while the force is pending, both token-issuing subcommands are denied with their OWN distinct
    /// status codes (<c>getPinUvAuthTokenUsingPinWithPermissions</c> → <c>PinPolicyViolation</c>,
    /// <c>getPinToken</c> → <c>PinInvalid</c>); a compliant <c>changePIN</c> clears the force and a fresh
    /// token then drives a successful <c>authenticatorGetAssertion</c> with <c>uv=1</c>. Negative legs:
    /// lowering the minimum is rejected, and <c>changePIN</c> to a PIN shorter than the now-raised minimum
    /// is rejected too.
    /// </summary>
    [TestMethod]
    public async Task SetMinPinLengthAndForcePinChangeJourneyOverRealApduTransport()
    {
        const string RpId = "config-capstone-b.example";
        const string InitialPin = "1234";
        const string RaisedPin = "123456";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("config-capstone-b");
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        //Setup, fully unprotected: mint a credential the closing ga leg (after the policy is raised) can
        //assert against.
        byte[] presetupUserId = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0xD0);
        CtapMakeCredentialRequest presetupRequest = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(pool, rpId: RpId, userId: presetupUserId);
        CtapMakeCredentialResponse presetupResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, presetupRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(presetupRequest);
        byte[] presetupCredentialIdBytes;
        using(AuthenticatorData presetupAuthenticatorData = AuthenticatorDataReader.Read(presetupResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            presetupCredentialIdBytes = presetupAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        await EstablishPinAsync(harness.Transceive, pool, CtapPinUvAuthProtocolId.Two, InitialPin, cancellationToken).ConfigureAwait(false);

        byte[] acfgToken = await IssueTokenAsync(
            harness.Transceive, pool, CtapPinUvAuthProtocolId.Two, InitialPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, cancellationToken)
            .ConfigureAwait(false);

        //The stored 4-code-point PIN is now shorter than the raised minimum, so this alone
        //forces a PIN change -- no forceChangePin parameter is presented.
        await SendSetMinPinLengthAsync(harness.Transceive, pool, CtapPinUvAuthProtocolId.Two, acfgToken, newMinPinLength: 6, cancellationToken)
            .ConfigureAwait(false);

        CtapGetInfoResponse infoAfterRaise = await GetInfoAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(6, infoAfterRaise.MinPinLength, "the raised minimum must be observable on the wire.");
        Assert.IsTrue(infoAfterRaise.ForcePinChange!.Value, "raising the minimum above the existing PIN's length must set forcePINChange on the wire.");

        //getPinUvAuthTokenUsingPinWithPermissions is denied while forcePINChange is pending: PinPolicyViolation.
        using CtapPlatformPinSession permissionsSession = await CtapPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        byte[] permissionsPinHashEnc = await permissionsSession.BuildPinHashEncAsync(InitialPin, cancellationToken).ConfigureAwait(false);
        var permissionsRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: permissionsSession.PlatformPublicKeyCose, PinHashEnc: permissionsPinHashEnc,
            Permissions: WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga, RpId: RpId);
        CtapCommandException permissionsException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                harness.Transceive, CtapClientPinRequestCborWriter.Write, permissionsRequest, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.PinPolicyViolation, permissionsException.StatusCode);

        //getPinToken is denied too, with its OWN back-compat status code: PinInvalid.
        using CtapPlatformPinSession legacySession = await CtapPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        byte[] legacyPinHashEnc = await legacySession.BuildPinHashEncAsync(InitialPin, cancellationToken).ConfigureAwait(false);
        var legacyRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: legacySession.PlatformPublicKeyCose, PinHashEnc: legacyPinHashEnc);
        CtapCommandException legacyException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                harness.Transceive, CtapClientPinRequestCborWriter.Write, legacyRequest, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, legacyException.StatusCode);

        //changePIN to a compliant 6-code-point PIN clears forcePINChange.
        using CtapPlatformPinSession changeSession = await CtapPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinHashEnc, byte[] changePinUvAuthParam) =
            await changeSession.BuildChangePinMessagesAsync(RaisedPin, InitialPin, cancellationToken).ConfigureAwait(false);
        var changePinRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: changeSession.PlatformPublicKeyCose, PinUvAuthParam: changePinUvAuthParam, NewPinEnc: newPinEnc, PinHashEnc: pinHashEnc);
        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, changePinRequest, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        CtapGetInfoResponse infoAfterChange = await GetInfoAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsFalse(infoAfterChange.ForcePinChange ?? false, "a compliant changePIN must clear forcePINChange on the wire.");
        Assert.AreEqual(6, infoAfterChange.MinPinLength, "changePIN must not alter the configured minimum.");

        //A fresh token is issuable again, and drives a successful ga with uv=1.
        byte[] gaToken = await IssueTokenAsync(
            harness.Transceive, pool, CtapPinUvAuthProtocolId.Two, RaisedPin, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpId, cancellationToken)
            .ConfigureAwait(false);
        byte[] gaMessage = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x20);
        byte[] gaParam = await CtapConfigFixtures.ComputeSignatureAsync(gaToken, CtapPinUvAuthProtocolId.Two, gaMessage, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapGetAssertionRequest gaRequest = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(presetupCredentialIdBytes, pool) }],
            pinUvAuthParam: gaParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        CtapGetAssertionResponse gaResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, gaRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(gaRequest);
        using(AuthenticatorData gaAuthenticatorData = AuthenticatorDataReader.Read(gaResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(gaAuthenticatorData.Flags.UserVerified, "a fresh token issued after the PIN change must drive a successful ga with uv=1.");
        }
        gaResponse.Credential.Id.Dispose();
        gaResponse.User?.Id.Dispose();

        //Negative legs, both driven by a fresh acfg token.
        byte[] negativeAcfgToken = await IssueTokenAsync(
            harness.Transceive, pool, CtapPinUvAuthProtocolId.Two, RaisedPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, cancellationToken)
            .ConfigureAwait(false);

        CtapCommandException lowerException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            SendSetMinPinLengthAsync(harness.Transceive, pool, CtapPinUvAuthProtocolId.Two, negativeAcfgToken, newMinPinLength: 5, cancellationToken));
        Assert.AreEqual(WellKnownCtapStatusCodes.PinPolicyViolation, lowerException.StatusCode, "lowering the minimum must be rejected.");

        using CtapPlatformPinSession shortChangeSession = await CtapPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        (byte[] shortNewPinEnc, byte[] shortPinHashEnc, byte[] shortPinUvAuthParam) =
            await shortChangeSession.BuildChangePinMessagesAsync("1234", RaisedPin, cancellationToken).ConfigureAwait(false);
        var shortChangeRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: shortChangeSession.PlatformPublicKeyCose, PinUvAuthParam: shortPinUvAuthParam, NewPinEnc: shortNewPinEnc, PinHashEnc: shortPinHashEnc);
        CtapCommandException shortChangeException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                harness.Transceive, CtapClientPinRequestCborWriter.Write, shortChangeRequest, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        Assert.AreEqual(
            WellKnownCtapStatusCodes.PinPolicyViolation, shortChangeException.StatusCode,
            "changePIN to a PIN shorter than the raised minimum must be rejected.");
    }


    /// <summary>Sends an <c>authenticatorGetInfo</c> request over <paramref name="transceive"/> and decodes the response.</summary>
    private static async Task<CtapGetInfoResponse> GetInfoAsync(Ctap2TransceiveDelegate transceive, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await transceive(request, pool, cancellationToken).ConfigureAwait(false);

        return CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
    }


    /// <summary>Establishes <paramref name="pin"/> as the authenticator's PIN over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task EstablishPinAsync(
        Ctap2TransceiveDelegate transceive, BaseMemoryPool pool, CtapPinUvAuthProtocolId protocolId, string pin, CancellationToken cancellationToken)
    {
        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a permissions-scoped <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c>
    /// (<c>0x09</c>) over <paramref name="transceive"/>'s real transport, decrypting it from wire bytes only.
    /// </summary>
    private static async Task<byte[]> IssueTokenAsync(
        Ctap2TransceiveDelegate transceive, BaseMemoryPool pool, CtapPinUvAuthProtocolId protocolId, string pin, int permissions, string? rpId,
        CancellationToken cancellationToken)
    {
        using CtapPlatformPinSession session = await CtapPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds and sends a <c>setMinPINLength</c> request over <paramref name="transceive"/>'s real
    /// transport, computing the platform-side <c>pinUvAuthParam</c> over the SAME <c>subCommandParams</c>
    /// bytes the request will carry.
    /// </summary>
    private static async Task SendSetMinPinLengthAsync(
        Ctap2TransceiveDelegate transceive, BaseMemoryPool pool, CtapPinUvAuthProtocolId protocolId, byte[] token, int? newMinPinLength,
        CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> subCommandParams = newMinPinLength is null
            ? ReadOnlyMemory<byte>.Empty
            : CtapConfigFixtures.BuildSubCommandParams(newMinPinLength);
        byte[] message = CtapConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, subCommandParams);
        byte[] param = await CtapConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken).ConfigureAwait(false);

        var request = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, NewMinPinLength: newMinPinLength,
            PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);

        await CtapAuthenticatorConfigClient.AuthenticatorConfigAsync(
            transceive, CtapAuthenticatorConfigRequestCborWriter.Write, request, pool, cancellationToken).ConfigureAwait(false);
    }
}

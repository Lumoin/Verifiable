using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wave-5a capstone firewalled flow test: the RP-side <see cref="CtapAuthenticatorClientPinClient"/>
/// drives a <see cref="CtapAuthenticatorSimulator"/>'s <c>getKeyAgreement</c> subcommand over the real,
/// unmodified <c>Verifiable.Apdu.ApduExecutor</c>/<c>Verifiable.Apdu.ApduDevice</c> stack via
/// <c>Verifiable.Apdu.Ctap.CtapNfcTransport</c> and <c>Verifiable.Apdu.Ctap.CtapNfcResponder</c>, then
/// the platform independently runs its own ECDH against the returned public key to derive a shared
/// secret — proving key agreement works end to end on the wire, mirroring the wave-2/3 capstone
/// composition (<see cref="CtapWave2TransportHarness"/>).
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorClientPinFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <c>getKeyAgreement</c> for PIN/UV auth protocol two reaches the simulator over the real APDU
    /// transport, returns a valid COSE_Key, and the platform's own freshly generated P-256 key can
    /// perform ECDH against it — the same production ECDH primitive
    /// (<see cref="MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async"/>) the authenticator
    /// itself is built on, run independently here as the platform side.
    /// </summary>
    [TestMethod]
    public async Task RpClientDrivesSimulatorOverRealApduTransportAndDerivesSharedSecret()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("clientpin-flow-authenticator");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, TestContext.CancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, TestContext.CancellationToken);

        CoseKey authenticatorKeyAgreementKey = response.KeyAgreement
            ?? throw new AssertFailedException("The getKeyAgreement response is missing the keyAgreement member.");
        Assert.AreEqual(CoseKeyTypes.Ec2, authenticatorKeyAgreementKey.Kty);
        Assert.AreEqual(-25, authenticatorKeyAgreementKey.Alg);
        Assert.AreEqual(CoseKeyCurves.P256, authenticatorKeyAgreementKey.Curve);

        //The platform side: an independent P-256 key pair, never seen by the authenticator, used only
        //to prove the wire-received public key is genuinely ECDH-viable.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> platformKeys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Exchange, pool);
        using PrivateKeyMemory platformPrivateKey = platformKeys.PrivateKey;
        using PublicKeyMemory platformPublicKey = platformKeys.PublicKey;

        using PublicKeyMemory authenticatorPublicKey = authenticatorKeyAgreementKey.ToPublicKeyMemory(pool);
        using SharedSecret sharedSecret = await platformPrivateKey.AgreementDecryptAsync(
            authenticatorPublicKey, MicrosoftKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async, pool, TestContext.CancellationToken);

        Assert.AreEqual(32, sharedSecret.Length, "ECDH over the wire-received key-agreement public key must derive a 32-byte P-256 shared secret.");
    }


    /// <summary>
    /// The wave-5b capstone firewalled flow test: a full platform journey — <c>getKeyAgreement</c> →
    /// <c>setPIN</c> → <c>authenticatorGetInfo</c> shows <c>clientPin: true</c> →
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> (<c>mc|ga</c>, bound to an <c>rpId</c>) →
    /// the client decrypts a 32-byte token; then a wrong-PIN <c>changePIN</c> leg (observes
    /// <c>PIN_INVALID</c> and a decremented <c>getPINRetries</c> count) followed by the right-PIN leg
    /// (succeeds) — all driven over the real, unmodified APDU transport stack, with every platform-side
    /// cryptographic step built from wire bytes only via <see cref="CtapWave5bPinCryptoFixtures"/>, never
    /// a back-channel read of the simulator's state. The first token is issued on PIN/UV auth protocol
    /// ONE and the <c>changePIN</c> runs entirely on protocol TWO; a subsequent protocol-ONE
    /// <c>getPinToken</c> decrypting to a different value is wire-level evidence consistent with
    /// <c>changePIN</c>'s cross-protocol <c>resetPinUvAuthToken()</c> (line 5714, "for all
    /// pinUvAuthProtocols"), though — because this test is firewalled to wire bytes only, with no
    /// internal-state access and no wave-c command yet wired to actually consume a <c>pinUvAuthToken</c>
    /// — it cannot by itself distinguish that reset from <c>getPinToken</c>'s own unconditional
    /// self-reminting on every call; the authoritative, non-tautological proof of <c>changePIN</c>'s
    /// system-wide invalidation is <see cref="CtapAuthenticatorChangePinTests.ChangePinSuccessInvalidatesTokensOnAllProtocols"/>,
    /// which reaches the authenticator's actual post-change token state and drives the in-use verify
    /// composition seam directly.
    /// </summary>
    [TestMethod]
    public async Task RpClientDrivesFullPinEstablishmentAndTokenIssuanceJourneyOverRealApduTransport()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave5AuthenticatorFixtures.CreateSimulator("clientpin-flow-capstone");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, TestContext.CancellationToken);

        //getKeyAgreement + setPIN.
        using CtapWave5bPlatformPinSession establishSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] setPinUvAuthParam) = await establishSession.BuildSetPinMessagesAsync("1234", TestContext.CancellationToken);
        CtapClientPinResponse setPinResponse = await SendClientPinAsync(harness.Transceive, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: establishSession.PlatformPublicKeyCose, PinUvAuthParam: setPinUvAuthParam, NewPinEnc: newPinEnc), pool);
        Assert.IsNull(setPinResponse.PinUvAuthToken);

        //authenticatorGetInfo now reports clientPin: true.
        CtapGetInfoResponse infoAfterSetPin = await GetInfoAsync(harness.Transceive, pool);
        Assert.IsTrue(infoAfterSetPin.Options!.ClientPin!.Value);

        //getPinUvAuthTokenUsingPinWithPermissions(mc|ga, rpId) on protocol ONE and decrypt the returned
        //token — deliberately the protocol the upcoming changePIN leg does NOT run on, so the later
        //re-fetch on this same protocol probes changePIN's cross-protocol reset rather than the
        //same-protocol churn a same-protocol re-fetch would also show on its own.
        using CtapWave5bPlatformPinSession tokenSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, TestContext.CancellationToken);
        byte[] tokenPinHashEnc = await tokenSession.BuildPinHashEncAsync("1234", TestContext.CancellationToken);
        int mcGa = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;
        CtapClientPinResponse tokenResponse = await SendClientPinAsync(harness.Transceive, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.One, KeyAgreement: tokenSession.PlatformPublicKeyCose,
            PinHashEnc: tokenPinHashEnc, Permissions: mcGa, RpId: "example.com"), pool);
        byte[] firstToken = await tokenSession.DecryptTokenAsync(tokenResponse.PinUvAuthToken!.Value, TestContext.CancellationToken);
        Assert.HasCount(32, firstToken);

        //changePIN with the WRONG current PIN: PIN_INVALID, and getPINRetries observes the decrement.
        using CtapWave5bPlatformPinSession wrongChangeSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] wrongNewPinEnc, byte[] wrongPinHashEnc, byte[] wrongPinUvAuthParam) =
            await wrongChangeSession.BuildChangePinMessagesAsync("5678", "0000", TestContext.CancellationToken);
        CtapCommandException wrongPinException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() => SendClientPinAsync(
            harness.Transceive,
            new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
                KeyAgreement: wrongChangeSession.PlatformPublicKeyCose, PinUvAuthParam: wrongPinUvAuthParam,
                NewPinEnc: wrongNewPinEnc, PinHashEnc: wrongPinHashEnc),
            pool));
        Assert.AreEqual(WellKnownCtapStatusCodes.PinInvalid, wrongPinException.StatusCode);

        CtapClientPinResponse retriesAfterWrongPin = await SendClientPinAsync(
            harness.Transceive, new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries), pool);
        Assert.AreEqual(7, retriesAfterWrongPin.PinRetries);

        //changePIN with the RIGHT current PIN: succeeds.
        using CtapWave5bPlatformPinSession rightChangeSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] rightNewPinEnc, byte[] rightPinHashEnc, byte[] rightPinUvAuthParam) =
            await rightChangeSession.BuildChangePinMessagesAsync("5678", "1234", TestContext.CancellationToken);
        CtapClientPinResponse changeResponse = await SendClientPinAsync(harness.Transceive, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.ChangePin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: rightChangeSession.PlatformPublicKeyCose, PinUvAuthParam: rightPinUvAuthParam,
            NewPinEnc: rightNewPinEnc, PinHashEnc: rightPinHashEnc), pool);
        Assert.IsNull(changeResponse.PinUvAuthToken);

        //Re-fetch on protocol ONE — the protocol the changePIN leg above never touched directly — and
        //decrypt: a genuinely different 32-byte value here is wire-level evidence consistent with
        //changePIN's cross-protocol resetPinUvAuthToken() (line 5714, "for all pinUvAuthProtocols"). This
        //firewalled journey cannot, on its own, rule out the value merely changing because getPinToken
        //always mints a fresh token on every call regardless of the intervening changePIN — see this
        //method's remarks for where the dispositive proof lives.
        using CtapWave5bPlatformPinSession freshTokenSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.One, pool, TestContext.CancellationToken);
        byte[] freshPinHashEnc = await freshTokenSession.BuildPinHashEncAsync("5678", TestContext.CancellationToken);
        CtapClientPinResponse freshTokenResponse = await SendClientPinAsync(harness.Transceive, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.One,
            KeyAgreement: freshTokenSession.PlatformPublicKeyCose, PinHashEnc: freshPinHashEnc), pool);
        byte[] secondToken = await freshTokenSession.DecryptTokenAsync(freshTokenResponse.PinUvAuthToken!.Value, TestContext.CancellationToken);

        Assert.HasCount(32, secondToken);
        Assert.AreNotSequenceEqual(firstToken, secondToken, "the token issued before changePIN must be invalidated by the PIN change.");
    }


    /// <summary>
    /// The wave-5c APDU flow capstone: a full journey mixing <c>authenticatorClientPIN</c> with the
    /// PIN/UV-protected <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> surface —
    /// <c>getKeyAgreement</c> → <c>setPIN</c> → <c>getPinUvAuthTokenUsingPinWithPermissions</c>
    /// (<c>mc|ga</c>, bound to an <c>rpId</c>) → the client decrypts the token and computes a
    /// <c>pinUvAuthParam</c> over the REAL wire → <c>authenticatorMakeCredential</c> succeeds with the
    /// response <c>authData</c> showing <c>uv=1</c>/<c>up=1</c> → a second <c>authenticatorMakeCredential</c>
    /// attempt over the SAME (now permission-stripped) token fails with <c>PinAuthInvalid</c> → a FRESH
    /// token bound to the same <c>rpId</c> drives a successful <c>authenticatorGetAssertion</c> with
    /// <c>uv=1</c> → a token bound to a DIFFERENT <c>rpId</c> fails an <c>authenticatorMakeCredential</c>
    /// attempt at the original <c>rpId</c> with <c>PinAuthInvalid</c>. Every status observed comes from
    /// <see cref="CtapCommandException.StatusCode"/>, never internal simulator state — the same firewalled
    /// discipline as <see cref="RpClientDrivesFullPinEstablishmentAndTokenIssuanceJourneyOverRealApduTransport"/>.
    /// </summary>
    [TestMethod]
    public async Task RpClientDrivesMakeCredentialAndGetAssertionWithPinUvAuthTokenOverRealApduTransport()
    {
        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("pinuv-mcga-capstone");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, TestContext.CancellationToken);

        const string boundRpId = "pinuv-mcga-capstone.example";
        const string otherRpId = "other-pinuv-mcga-capstone.example";
        byte[] mcMessage = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x10);
        byte[] gaMessage = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x20);

        using CtapWave5bPlatformPinSession establishSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, TestContext.CancellationToken);
        (byte[] newPinEnc, byte[] setPinUvAuthParam) = await establishSession.BuildSetPinMessagesAsync("1234", TestContext.CancellationToken);
        await SendClientPinAsync(harness.Transceive, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: establishSession.PlatformPublicKeyCose, PinUvAuthParam: setPinUvAuthParam, NewPinEnc: newPinEnc), pool);

        byte[] mcToken = await IssueTokenBoundToRpIdAsync(harness, pool, boundRpId, TestContext.CancellationToken);
        byte[] mcParam = await SignWithTokenAsync(mcToken, mcMessage, pool, TestContext.CancellationToken);

        CtapMakeCredentialRequest mcRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: boundRpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x60),
            pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        CtapMakeCredentialResponse mcResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, mcRequest, CtapMakeCredentialResponseCborReader.Read, pool, TestContext.CancellationToken);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(mcRequest);

        byte[] mintedCredentialIdBytes;
        using(AuthenticatorData mcAuthenticatorData = AuthenticatorDataReader.Read(mcResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(mcAuthenticatorData.Flags.UserVerified, "a successful pinUvAuthToken-backed authenticatorMakeCredential must report uv=1 on the wire.");
            Assert.IsTrue(mcAuthenticatorData.Flags.UserPresent, "a successful authenticatorMakeCredential must report up=1 on the wire.");
            mintedCredentialIdBytes = mcAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        //Token reuse: the successful mc call above stripped every permission but lbw from mcToken
        //(R6/line 5828), so a second authenticatorMakeCredential over the SAME token — even with a
        //freshly computed, otherwise-valid signature — must fail.
        byte[] reuseParam = await SignWithTokenAsync(mcToken, mcMessage, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest reuseRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: boundRpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x61),
            pinUvAuthParam: reuseParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        CtapCommandException reuseException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, reuseRequest, CtapMakeCredentialResponseCborReader.Read, pool, TestContext.CancellationToken).AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, reuseException.StatusCode, "a reused, permission-stripped token must fail with PinAuthInvalid.");
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(reuseRequest);

        //A fresh token bound to the SAME rpId drives a successful authenticatorGetAssertion.
        byte[] gaToken = await IssueTokenBoundToRpIdAsync(harness, pool, boundRpId, TestContext.CancellationToken);
        byte[] gaParam = await SignWithTokenAsync(gaToken, gaMessage, pool, TestContext.CancellationToken);
        CtapGetAssertionRequest gaRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: boundRpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(mintedCredentialIdBytes, pool) }],
            pinUvAuthParam: gaParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        CtapGetAssertionResponse gaResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, gaRequest, CtapGetAssertionResponseCborReader.Read, pool, TestContext.CancellationToken);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(gaRequest);
        try
        {
            using AuthenticatorData gaAuthenticatorData = AuthenticatorDataReader.Read(gaResponse.AuthData, CredentialPublicKeyCborReader.Read, pool);
            Assert.IsTrue(gaAuthenticatorData.Flags.UserVerified, "a successful pinUvAuthToken-backed authenticatorGetAssertion must report uv=1 on the wire.");
        }
        finally
        {
            gaResponse.Credential.Id.Dispose();
            gaResponse.User?.Id.Dispose();
        }

        //A fresh token bound to a DIFFERENT rpId must fail an authenticatorMakeCredential attempt at the
        //original boundRpId — the permissions-RP-ID binding CTAP2.3 line 5830-5834 describes.
        byte[] otherRpToken = await IssueTokenBoundToRpIdAsync(harness, pool, otherRpId, TestContext.CancellationToken);
        byte[] crossRpParam = await SignWithTokenAsync(otherRpToken, mcMessage, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest crossRpRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: boundRpId, userId: CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0x62),
            pinUvAuthParam: crossRpParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
        CtapCommandException crossRpException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, crossRpRequest, CtapMakeCredentialResponseCborReader.Read, pool, TestContext.CancellationToken).AsTask());
        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, crossRpException.StatusCode, "a token bound to a different rpId must fail authenticatorMakeCredential at the original rpId.");
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(crossRpRequest);
    }


    /// <summary>
    /// Establishes a fresh PIN/UV auth protocol TWO session over <paramref name="harness"/>'s real APDU
    /// transport and issues a <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c>
    /// (<c>0x09</c>) with <c>mc|ga</c> permissions bound to <paramref name="rpId"/>, decrypting it from
    /// wire bytes only.
    /// </summary>
    private static async Task<byte[]> IssueTokenBoundToRpIdAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, string rpId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync("1234", cancellationToken).ConfigureAwait(false);

        int mcGa = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;
        CtapClientPinResponse response = await SendClientPinAsync(harness.Transceive, new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: mcGa, RpId: rpId), pool);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Computes <c>authenticate(token, message)</c> under PIN/UV auth protocol TWO's own truncation rule — the platform-side computation <c>verify</c> checks a presented <c>pinUvAuthParam</c> against.</summary>
    private static async Task<byte[]> SignWithTokenAsync(byte[] token, byte[] message, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(CtapPinUvAuthProtocolId.Two);
        using IMemoryOwner<byte> signature = await protocol.AuthenticateAsync(token, message, pool, cancellationToken).ConfigureAwait(false);

        return signature.Memory.Span.ToArray();
    }


    /// <summary>Sends an <c>authenticatorClientPIN</c> request over <paramref name="transceive"/> and decodes the response.</summary>
    private static Task<CtapClientPinResponse> SendClientPinAsync(Ctap2TransceiveDelegate transceive, CtapClientPinRequest request, MemoryPool<byte> pool) =>
        CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, CancellationToken.None).AsTask();


    /// <summary>Sends an <c>authenticatorGetInfo</c> request over <paramref name="transceive"/> and decodes the response.</summary>
    private static async Task<CtapGetInfoResponse> GetInfoAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool)
    {
        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await transceive(request, pool, CancellationToken.None).ConfigureAwait(false);

        return CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
    }
}

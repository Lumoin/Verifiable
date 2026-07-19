using System;
using System.Buffers;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Capstone C: the wavecm real-Kestrel/real-APDU RP-HTTP ceremony proof that
/// <c>authenticatorCredentialManagement</c>'s <c>deleteCredential</c> has an RP-VISIBLE consequence --
/// composing <see cref="WebAuthnRelyingPartyCeremonySkin"/> exactly like
/// <see cref="WebAuthnRpHttpCeremonyAlwaysUvTests"/> does, registering a discoverable credential through
/// the real ceremony, proving one assertion succeeds, then deleting that credential over the wire via
/// <c>authenticatorCredentialManagement</c> and proving the subsequent assertion ceremony fails because
/// the authenticator itself refuses the <c>authenticatorGetAssertion</c> call with
/// <see cref="WellKnownCtapStatusCodes.NoCredentials"/> -- observed as
/// <see cref="CtapCommandException.StatusCode"/> on the exact call the ceremony's client-side leg makes.
/// The existing ceremony capstones in <see cref="WebAuthnRpHttpCeremonyTests"/>,
/// <see cref="WebAuthnRpHttpCeremonyRequiredUserVerificationTests"/>, and
/// <see cref="WebAuthnRpHttpCeremonyAlwaysUvTests"/> are untouched by this file and remain green.
/// </summary>
[TestClass]
internal sealed class WebAuthnRpHttpCeremonyCredentialManagementTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The relying party identifier this capstone's ceremonies are scoped to.</summary>
    private const string RpId = "webauthn-rp-http-cm.example";

    /// <summary>The relying party origin this capstone's ceremonies embed and expect.</summary>
    private const string Origin = "https://webauthn-rp-http-cm.example";

    /// <summary>The PIN established on the simulator this capstone drives.</summary>
    private const string Pin = "1234";

    /// <summary>The single PIN/UV auth protocol this capstone drives.</summary>
    private static CtapPinUvAuthProtocolId ProtocolId => CtapPinUvAuthProtocolId.Two;


    /// <summary>
    /// Registers a discoverable credential through the real RP ceremony, proves an assertion succeeds
    /// against it, then deletes it over the wire via <c>authenticatorCredentialManagement</c>'s
    /// <c>deleteCredential</c> subcommand -- proving the subsequent assertion ceremony can no longer
    /// complete: the authenticator itself refuses the client's <c>authenticatorGetAssertion</c> call with
    /// <see cref="WellKnownCtapStatusCodes.NoCredentials"/>, so no assertion result ever reaches the RP.
    /// </summary>
    [TestMethod]
    public async Task DeleteCredentialOverTheWireMakesSubsequentAssertionCeremonyFail()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        var skin = new WebAuthnRelyingPartyCeremonySkin(
            RpId, Origin, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF5), "wavecm-user", "Wavecm User", pool,
            residentKey: ResidentKeyRequirement.Required);
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(skin.HandleAsync, cancellationToken).ConfigureAwait(false);
        using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(host.Certificate, host.BaseAddress);

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("webauthn-rp-http-cm-authenticator");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);

        int mcGa = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;

        byte[] registrationToken = await IssueTokenAsync(harness, pool, mcGa, RpId, cancellationToken).ConfigureAwait(false);
        await RegisterOverRealTransportsWithTokenAsync(httpClient, harness, pool, registrationToken, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1, skin.AttestationResultRequestCount, "the RP must see exactly one attestation result request cross the socket.");
        Assert.IsNotNull(skin.StoredCredential, "a registration accepted by the RP must store a credential record.");
        byte[] storedCredentialIdBytes = skin.StoredCredential!.Id.AsReadOnlySpan().ToArray();

        byte[] preDeleteAssertionToken = await IssueTokenAsync(harness, pool, mcGa, RpId, cancellationToken).ConfigureAwait(false);
        await AssertOverRealTransportsWithTokenAsync(httpClient, harness, pool, preDeleteAssertionToken, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1, skin.AssertionResultRequestCount, "the pre-delete assertion ceremony must succeed through the RP.");

        byte[] cmToken = await IssueTokenAsync(harness, pool, WellKnownCtapPinUvAuthTokenPermissions.Cm, rpId: null, cancellationToken).ConfigureAwait(false);
        using(CredentialId deleteCarrier = CredentialId.Create(storedCredentialIdBytes, pool))
        {
            var deleteDescriptor = new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = deleteCarrier };
            byte[] subCommandParams = CtapWaveCmFixtures.BuildSubCommandParams(credentialId: deleteDescriptor);
            byte[] message = CtapWaveCmFixtures.BuildMessage(WellKnownCtapCredentialManagementSubCommands.DeleteCredential, subCommandParams);
            byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(cmToken, ProtocolId, message, pool, cancellationToken).ConfigureAwait(false);

            var deleteRequest = new CtapCredentialManagementRequest(
                SubCommand: WellKnownCtapCredentialManagementSubCommands.DeleteCredential, CredentialId: deleteDescriptor,
                PinUvAuthProtocol: (int)ProtocolId, PinUvAuthParam: param);
            byte[] deleteEnvelope = CtapWaveCmFixtures.BuildCredentialManagementEnvelope(deleteRequest);
            using PooledMemory deleteResponse = await harness.Transceive(deleteEnvelope, pool, cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, deleteResponse.AsReadOnlySpan()[0], "cm deleteCredential must succeed over the wire.");
        }

        byte[] postDeleteAssertionToken = await IssueTokenAsync(harness, pool, mcGa, RpId, cancellationToken).ConfigureAwait(false);

        using HttpResponseMessage optionsResponse = await PostAsync(httpClient, WebAuthnRelyingPartyCeremonySkin.AssertionOptionsPath, jsonBody: null, cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, optionsResponse.StatusCode);
        byte[] optionsBytes = await optionsResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        PublicKeyCredentialRequestOptions requestOptions = PublicKeyCredentialRequestOptionsJsonReader.Read(optionsBytes, pool);

        byte[] getClientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(new ClientData(WellKnownClientDataTypes.Get, requestOptions.Challenge!, Origin));
        DigestValue getClientDataHash = Fido2ClientDataHash.Compute(getClientDataJson, pool);
        byte[] gaParam = await SignWithTokenAsync(postDeleteAssertionToken, getClientDataHash.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        CtapGetAssertionRequest getAssertionRequest = CtapWave2CapstoneFixtures.BuildGetAssertionRequest(
            requestOptions, getClientDataHash, pinUvAuthParam: gaParam, pinUvAuthProtocol: (int)ProtocolId);

        CtapCommandException deletedAssertionException = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                harness.Transceive, CtapGetAssertionRequestCborWriter.Write, getAssertionRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
                .AsTask());
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(getAssertionRequest);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.NoCredentials, deletedAssertionException.StatusCode,
            "the authenticator must refuse the post-delete authenticatorGetAssertion call with NoCredentials, on the wire.");
        Assert.AreEqual(
            1, skin.AssertionResultRequestCount,
            "the RP must never receive a second assertion result request: the ceremony cannot produce one once the authenticator itself refuses.");
    }


    /// <summary>
    /// Drives one registration ceremony carrying a real <c>pinUvAuthParam</c> computed over
    /// <paramref name="token"/>: fetches <c>PublicKeyCredentialCreationOptionsJSON</c> over HTTP, runs
    /// <c>authenticatorMakeCredential</c> over the real APDU transport, and POSTs the resulting
    /// <c>RegistrationResponseJSON</c> envelope, asserting the RP accepted it.
    /// </summary>
    private static async Task RegisterOverRealTransportsWithTokenAsync(
        HttpClient httpClient, CtapWave2TransportHarness harness, MemoryPool<byte> pool, byte[] token, CancellationToken cancellationToken)
    {
        using HttpResponseMessage optionsResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AttestationOptionsPath, jsonBody: null, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, optionsResponse.StatusCode);
        byte[] optionsBytes = await optionsResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        PublicKeyCredentialCreationOptions creationOptions = PublicKeyCredentialCreationOptionsJsonReader.Read(optionsBytes, pool);

        byte[] createClientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(
            new ClientData(WellKnownClientDataTypes.Create, creationOptions.Challenge!, Origin));
        DigestValue createClientDataHash = Fido2ClientDataHash.Compute(createClientDataJson, pool);

        byte[] mcParam = await SignWithTokenAsync(token, createClientDataHash.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        CtapMakeCredentialRequest makeCredentialRequest = CtapWave2CapstoneFixtures.BuildMakeCredentialRequest(
            creationOptions, createClientDataHash, pool,
            attestationFormatsPreference: [WellKnownWebAuthnAttestationFormats.None],
            pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)ProtocolId);

        CtapMakeCredentialResponse makeCredentialResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, makeCredentialRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(makeCredentialRequest);

        TaggedMemory<byte> attestationObject = CtapAuthenticatorMakeCredentialClient.BuildAttestationObject(makeCredentialResponse, AttestationObjectCborWriter.Write);
        AttestationObjectParts attestationParts = AttestationObjectCborReader.Parse(attestationObject.Memory);
        using AuthenticatorData browserAuthenticatorData = AuthenticatorDataReader.Read(attestationParts.AuthenticatorData, CredentialPublicKeyCborReader.Read, pool);

        string registrationEnvelopeJson = WebAuthnRelyingPartyCeremonySkin.BuildRegistrationResponseJson(
            browserAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan(), createClientDataJson, attestationObject.Span);

        using HttpResponseMessage resultResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AttestationResultPath, registrationEnvelopeJson, cancellationToken).ConfigureAwait(false);
        string resultBody = await resultResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, resultResponse.StatusCode, $"Registration MUST be accepted. Body={resultBody}");
        Assert.Contains("\"verified\":true", resultBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// Drives one assertion ceremony carrying a real <c>pinUvAuthParam</c> computed over
    /// <paramref name="token"/>, mirroring <see cref="RegisterOverRealTransportsWithTokenAsync"/>'s
    /// shape for <c>authenticatorGetAssertion</c>, asserting the RP accepted the resulting assertion.
    /// </summary>
    private static async Task AssertOverRealTransportsWithTokenAsync(
        HttpClient httpClient, CtapWave2TransportHarness harness, MemoryPool<byte> pool, byte[] token, CancellationToken cancellationToken)
    {
        using HttpResponseMessage optionsResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AssertionOptionsPath, jsonBody: null, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, optionsResponse.StatusCode);
        byte[] optionsBytes = await optionsResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        PublicKeyCredentialRequestOptions requestOptions = PublicKeyCredentialRequestOptionsJsonReader.Read(optionsBytes, pool);

        byte[] getClientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(
            new ClientData(WellKnownClientDataTypes.Get, requestOptions.Challenge!, Origin));
        DigestValue getClientDataHash = Fido2ClientDataHash.Compute(getClientDataJson, pool);

        byte[] gaParam = await SignWithTokenAsync(token, getClientDataHash.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        CtapGetAssertionRequest getAssertionRequest = CtapWave2CapstoneFixtures.BuildGetAssertionRequest(
            requestOptions, getClientDataHash, pinUvAuthParam: gaParam, pinUvAuthProtocol: (int)ProtocolId);

        CtapGetAssertionResponse getAssertionResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, getAssertionRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(getAssertionRequest);

        bool hasUserHandle = getAssertionResponse.User is not null;
        string assertionEnvelopeJson = WebAuthnRelyingPartyCeremonySkin.BuildAssertionResponseJson(
            getAssertionResponse.Credential.Id.AsReadOnlySpan(),
            getClientDataJson,
            getAssertionResponse.AuthData.Span,
            getAssertionResponse.Signature.Span,
            hasUserHandle,
            hasUserHandle ? getAssertionResponse.User!.Id.AsReadOnlySpan() : default);
        getAssertionResponse.Credential.Id.Dispose();
        getAssertionResponse.User?.Id.Dispose();

        using HttpResponseMessage resultResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AssertionResultPath, assertionEnvelopeJson, cancellationToken).ConfigureAwait(false);
        string resultBody = await resultResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, resultResponse.StatusCode, $"Assertion MUST be accepted. Body={resultBody}");
        Assert.Contains("\"verified\":true", resultBody, StringComparison.Ordinal);
    }


    /// <summary>Establishes <see cref="Pin"/> on the simulator behind <paramref name="harness"/>'s real transport.</summary>
    private static async Task EstablishPinAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(harness.Transceive, ProtocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(Pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)ProtocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c> (<c>0x09</c>)
    /// carrying <paramref name="permissions"/>, optionally bound to <paramref name="rpId"/>, decrypting
    /// it from wire bytes only, over <paramref name="harness"/>'s real transport.
    /// </summary>
    private static async Task<byte[]> IssueTokenAsync(
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
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Computes <c>authenticate(token, message)</c> under <see cref="ProtocolId"/>'s own truncation rule -- the platform-side computation <c>verify</c> checks a presented <c>pinUvAuthParam</c> against.</summary>
    private static async Task<byte[]> SignWithTokenAsync(byte[] token, ReadOnlyMemory<byte> message, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(ProtocolId);
        using IMemoryOwner<byte> signature = await protocol.AuthenticateAsync(token, message, pool, cancellationToken).ConfigureAwait(false);

        return signature.Memory.Span.ToArray();
    }


    /// <summary>
    /// POSTs <paramref name="jsonBody"/> (or an empty body, when <see langword="null"/>) to
    /// <paramref name="path"/> via a genuine <see cref="HttpRequestMessage"/>/<see cref="HttpClient.SendAsync(HttpRequestMessage, CancellationToken)"/> call.
    /// </summary>
    private static async Task<HttpResponseMessage> PostAsync(HttpClient httpClient, string path, string? jsonBody, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(path, UriKind.Relative));
        if(jsonBody is not null)
        {
            request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        }

        return await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}

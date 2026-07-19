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
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wave-5c RP-HTTP ceremony capstone under <see cref="UserVerificationRequirement.Required"/>: the
/// same real-Kestrel/real-APDU composition <see cref="WebAuthnRpHttpCeremonyTests"/> establishes under
/// <see cref="UserVerificationRequirement.Discouraged"/>, extended with a PIN/UV auth token leg
/// (<c>setPIN</c> → <c>getPinUvAuthTokenUsingPinWithPermissions</c>) that feeds a computed
/// <c>pinUvAuthParam</c> into <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> over the
/// real APDU transport, proving the shipped <see cref="Fido2RegistrationVerifier"/>/
/// <see cref="Fido2AssertionVerifier"/> accept a <c>uv=1</c> ceremony under <c>Required</c> — observed by
/// re-parsing the EXACT bytes POSTed to the relying party, via the same shipped
/// <see cref="RegistrationResponseJsonReader"/>/<see cref="AuthenticationResponseJsonReader"/> the skin
/// itself uses — and reject a <c>uv=0</c> ceremony (no token presented) with
/// <see cref="WebAuthnRelyingPartyCeremonySkin"/>'s own <c>401</c> shape, for both registration and
/// assertion.
/// </summary>
[TestClass]
internal sealed class WebAuthnRpHttpCeremonyRequiredUserVerificationTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The relying party identifier the positive-leg capstone's ceremonies are scoped to.</summary>
    private const string RpId = "webauthn-rp-http-required.example";

    /// <summary>The relying party identifier the negative-leg capstone's ceremonies are scoped to.</summary>
    private const string NegativeRpId = "webauthn-rp-http-required-negative.example";

    /// <summary>The relying party origin every ceremony in this capstone embeds and expects.</summary>
    private const string Origin = "https://webauthn-rp-http-required.example";

    /// <summary>The PIN established on every simulator this capstone drives.</summary>
    private const string Pin = "1234";


    /// <summary>
    /// Registration then assertion, each carrying a real <c>pinUvAuthParam</c> computed over a
    /// <c>pinUvAuthToken</c> established and issued over the real APDU transport, both succeed against a
    /// relying party requiring <see cref="UserVerificationRequirement.Required"/> — and the posted
    /// <c>authenticatorData</c> bytes, re-parsed independently after the HTTP POST, show <c>uv=1</c> for
    /// both ceremonies.
    /// </summary>
    [TestMethod]
    public async Task RegistrationThenAssertionSucceedUnderRequiredUserVerificationWithPinUvAuthTokenAndObserveUvOneOnThePostedWireBytes()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        var skin = new WebAuthnRelyingPartyCeremonySkin(
            RpId, Origin, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF0), "erin", "Erin Example", pool,
            userVerification: UserVerificationRequirement.Required);
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(skin.HandleAsync, cancellationToken).ConfigureAwait(false);
        using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(host.Certificate, host.BaseAddress);

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("webauthn-rp-http-required-authenticator");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);

        byte[] registrationToken = await IssueTokenBoundToRpIdAsync(harness, pool, RpId, cancellationToken).ConfigureAwait(false);
        bool registrationUv = await RegisterOverRealTransportsWithTokenAsync(httpClient, harness, pool, registrationToken, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(registrationUv, "the registration ceremony's POSTed authenticatorData bytes must show uv=1 once re-parsed.");
        Assert.AreEqual(1, skin.AttestationResultRequestCount, "The RP MUST see exactly one attestation result request cross the socket.");
        Assert.IsNotNull(skin.StoredCredential, "A registration accepted under Required MUST store a credential record.");

        byte[] assertionToken = await IssueTokenBoundToRpIdAsync(harness, pool, RpId, cancellationToken).ConfigureAwait(false);
        bool assertionUv = await AssertOverRealTransportsWithTokenAsync(httpClient, harness, pool, assertionToken, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(assertionUv, "the assertion ceremony's POSTed authenticatorData bytes must show uv=1 once re-parsed.");
        Assert.AreEqual(1, skin.AssertionResultRequestCount, "The RP MUST see exactly one assertion result request cross the socket.");
    }


    /// <summary>
    /// A registration attempt carrying NO <c>pinUvAuthToken</c> (so the authenticator's response
    /// <c>authData</c> has <c>uv=0</c>) is rejected by a relying party requiring
    /// <see cref="UserVerificationRequirement.Required"/> with the skin's exact <c>401</c>
    /// <c>{"verified":false}</c> shape and stores no credential; an assertion attempt against an
    /// ALREADY-registered credential, likewise carrying no token, is rejected the same way.
    /// </summary>
    [TestMethod]
    public async Task RegistrationAndAssertionWithoutAPinUvAuthTokenFailWithTheSkinsUnauthorizedShapeUnderRequiredUserVerification()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        var skin = new WebAuthnRelyingPartyCeremonySkin(
            NegativeRpId, Origin, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF1), "frank", "Frank Example", pool,
            userVerification: UserVerificationRequirement.Required);
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(skin.HandleAsync, cancellationToken).ConfigureAwait(false);
        using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(host.Certificate, host.BaseAddress);

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("webauthn-rp-http-required-negative-authenticator");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        //No PIN has been established yet, so the authenticator is not protected: mc without a
        //pinUvAuthParam succeeds at the CTAP layer with uv=0 — the RP alone must reject it.
        using HttpResponseMessage registrationResponse = await RegisterOverRealTransportsWithoutTokenAsync(httpClient, harness, pool, cancellationToken).ConfigureAwait(false);
        string registrationBody = await registrationResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, registrationResponse.StatusCode, $"A uv=0 registration MUST be rejected under Required. Body={registrationBody}");
        Assert.Contains("\"verified\":false", registrationBody, StringComparison.Ordinal);
        Assert.IsNull(skin.StoredCredential, "A rejected registration MUST NOT store a credential.");

        //Register WITH a token so the negative assertion leg below has a real, stored credential to
        //target — the assertion leg's own uv=0 behavior is what is under test, not credential lookup.
        await EstablishPinAsync(harness, pool, cancellationToken).ConfigureAwait(false);
        byte[] registrationToken = await IssueTokenBoundToRpIdAsync(harness, pool, NegativeRpId, cancellationToken).ConfigureAwait(false);
        _ = await RegisterOverRealTransportsWithTokenAsync(httpClient, harness, pool, registrationToken, cancellationToken).ConfigureAwait(false);
        Assert.IsNotNull(skin.StoredCredential, "The token-bearing registration MUST have stored a credential.");

        //authenticatorGetAssertion has no makeCredUvNotRqd-shaped forced-rejection gate (CTAP 2.3
        //section 6.2.2 has no analog of mc's steps 7/8/10): even with the PIN now set, a ga call with no
        //pinUvAuthParam succeeds at the CTAP layer with uv=0 — again, the RP alone must reject it.
        using HttpResponseMessage assertionResponse = await AssertOverRealTransportsWithoutTokenAsync(httpClient, harness, pool, cancellationToken).ConfigureAwait(false);
        string assertionBody = await assertionResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, assertionResponse.StatusCode, $"A uv=0 assertion MUST be rejected under Required. Body={assertionBody}");
        Assert.Contains("\"verified\":false", assertionBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// Drives one registration ceremony carrying a real <c>pinUvAuthParam</c> computed over
    /// <paramref name="token"/>: fetches <c>PublicKeyCredentialCreationOptionsJSON</c> over HTTP, runs
    /// <c>authenticatorMakeCredential</c> over the real APDU transport, POSTs the resulting
    /// <c>RegistrationResponseJSON</c> envelope, asserts the RP accepted it, then re-parses the EXACT
    /// POSTed bytes with the shipped reader to report the observed <c>uv</c> bit.
    /// </summary>
    private static async Task<bool> RegisterOverRealTransportsWithTokenAsync(
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
            pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);

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
        Assert.AreEqual(HttpStatusCode.OK, resultResponse.StatusCode, $"Registration under Required with a token MUST be accepted. Body={resultBody}");
        Assert.Contains("\"verified\":true", resultBody, StringComparison.Ordinal);

        using WebAuthnRegistrationResponseEnvelope postedEnvelope = RegistrationResponseJsonReader.Read(Encoding.UTF8.GetBytes(registrationEnvelopeJson), pool);
        AttestationObjectParts postedAttestationParts = AttestationObjectCborReader.Parse(postedEnvelope.AttestationObject.AsReadOnlyMemory());
        using AuthenticatorData postedAuthenticatorData = AuthenticatorDataReader.Read(postedAttestationParts.AuthenticatorData, CredentialPublicKeyCborReader.Read, pool);

        return postedAuthenticatorData.Flags.UserVerified;
    }


    /// <summary>
    /// Drives one assertion ceremony carrying a real <c>pinUvAuthParam</c> computed over
    /// <paramref name="token"/>, mirroring <see cref="RegisterOverRealTransportsWithTokenAsync"/>'s
    /// shape for <c>authenticatorGetAssertion</c>.
    /// </summary>
    private static async Task<bool> AssertOverRealTransportsWithTokenAsync(
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
            requestOptions, getClientDataHash, pinUvAuthParam: gaParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);

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
        Assert.AreEqual(HttpStatusCode.OK, resultResponse.StatusCode, $"Assertion under Required with a token MUST be accepted. Body={resultBody}");
        Assert.Contains("\"verified\":true", resultBody, StringComparison.Ordinal);

        using WebAuthnAssertionResponseEnvelope postedEnvelope = AuthenticationResponseJsonReader.Read(Encoding.UTF8.GetBytes(assertionEnvelopeJson), pool);
        using AuthenticatorData postedAuthenticatorData = AuthenticatorDataReader.Read(postedEnvelope.AuthenticatorData.AsReadOnlyMemory(), CredentialPublicKeyCborReader.Read, pool);

        return postedAuthenticatorData.Flags.UserVerified;
    }


    /// <summary>
    /// Drives one registration ceremony with NO <c>pinUvAuthParam</c> at all, returning the raw HTTP
    /// response for the caller to assert the RP's rejection shape on.
    /// </summary>
    private static async Task<HttpResponseMessage> RegisterOverRealTransportsWithoutTokenAsync(
        HttpClient httpClient, CtapWave2TransportHarness harness, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using HttpResponseMessage optionsResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AttestationOptionsPath, jsonBody: null, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, optionsResponse.StatusCode);
        byte[] optionsBytes = await optionsResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        PublicKeyCredentialCreationOptions creationOptions = PublicKeyCredentialCreationOptionsJsonReader.Read(optionsBytes, pool);

        byte[] createClientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(
            new ClientData(WellKnownClientDataTypes.Create, creationOptions.Challenge!, Origin));
        DigestValue createClientDataHash = Fido2ClientDataHash.Compute(createClientDataJson, pool);

        CtapMakeCredentialRequest makeCredentialRequest = CtapWave2CapstoneFixtures.BuildMakeCredentialRequest(
            creationOptions, createClientDataHash, pool, attestationFormatsPreference: [WellKnownWebAuthnAttestationFormats.None]);

        CtapMakeCredentialResponse makeCredentialResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, makeCredentialRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(makeCredentialRequest);

        TaggedMemory<byte> attestationObject = CtapAuthenticatorMakeCredentialClient.BuildAttestationObject(makeCredentialResponse, AttestationObjectCborWriter.Write);
        AttestationObjectParts attestationParts = AttestationObjectCborReader.Parse(attestationObject.Memory);
        using AuthenticatorData browserAuthenticatorData = AuthenticatorDataReader.Read(attestationParts.AuthenticatorData, CredentialPublicKeyCborReader.Read, pool);

        string registrationEnvelopeJson = WebAuthnRelyingPartyCeremonySkin.BuildRegistrationResponseJson(
            browserAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan(), createClientDataJson, attestationObject.Span);

        return await PostAsync(httpClient, WebAuthnRelyingPartyCeremonySkin.AttestationResultPath, registrationEnvelopeJson, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives one assertion ceremony with NO <c>pinUvAuthParam</c> at all, returning the raw HTTP
    /// response for the caller to assert the RP's rejection shape on.
    /// </summary>
    private static async Task<HttpResponseMessage> AssertOverRealTransportsWithoutTokenAsync(
        HttpClient httpClient, CtapWave2TransportHarness harness, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using HttpResponseMessage optionsResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AssertionOptionsPath, jsonBody: null, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, optionsResponse.StatusCode);
        byte[] optionsBytes = await optionsResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        PublicKeyCredentialRequestOptions requestOptions = PublicKeyCredentialRequestOptionsJsonReader.Read(optionsBytes, pool);

        byte[] getClientDataJson = WebAuthnClientDataFixtures.BuildClientDataJson(
            new ClientData(WellKnownClientDataTypes.Get, requestOptions.Challenge!, Origin));
        DigestValue getClientDataHash = Fido2ClientDataHash.Compute(getClientDataJson, pool);

        CtapGetAssertionRequest getAssertionRequest = CtapWave2CapstoneFixtures.BuildGetAssertionRequest(requestOptions, getClientDataHash);

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

        return await PostAsync(httpClient, WebAuthnRelyingPartyCeremonySkin.AssertionResultPath, assertionEnvelopeJson, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Establishes a PIN on the simulator behind <paramref name="harness"/>'s real APDU transport, driven
    /// entirely over the wire via <see cref="CtapWave5bPinCryptoFixtures"/>.
    /// </summary>
    private static async Task EstablishPinAsync(CtapWave2TransportHarness harness, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(Pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c> (<c>0x09</c>)
    /// with <c>mc|ga</c> permissions bound to <paramref name="rpId"/>, decrypting it from wire bytes
    /// only, over <paramref name="harness"/>'s real APDU transport.
    /// </summary>
    private static async Task<byte[]> IssueTokenBoundToRpIdAsync(
        CtapWave2TransportHarness harness, MemoryPool<byte> pool, string rpId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            harness.Transceive, CtapPinUvAuthProtocolId.Two, pool, cancellationToken).ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(Pin, cancellationToken).ConfigureAwait(false);

        int mcGa = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: mcGa, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            harness.Transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Computes <c>authenticate(token, message)</c> under PIN/UV auth protocol TWO's own truncation rule — the platform-side computation <c>verify</c> checks a presented <c>pinUvAuthParam</c> against.</summary>
    private static async Task<byte[]> SignWithTokenAsync(byte[] token, ReadOnlyMemory<byte> message, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(CtapPinUvAuthProtocolId.Two);
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

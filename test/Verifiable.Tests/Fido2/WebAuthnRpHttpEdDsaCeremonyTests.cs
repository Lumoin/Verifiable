using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;
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
/// Real-wire capstone proving waveref ruling R-1 (the verification input's accepted algorithms are
/// DERIVED from the creation options they belong to, never independently hand-authored) together with
/// ruling R-2 (an authenticator that honours the relying party's stated EdDSA-first preference is
/// actually accepted, not silently rejected). Mirrors <see cref="WebAuthnRpHttpCeremonyTests"/>'s shape:
/// a CTAP authenticator simulator — here composed with <see cref="CtapCredentialSigningBackend.CreateEdDsaDefault"/>
/// rather than the ES256 default — driven over the REAL <see cref="Verifiable.Apdu.ApduExecutor"/>/
/// <see cref="Verifiable.Apdu.ApduDevice"/> transport, completes a registration then an authentication
/// ceremony against <see cref="WebAuthnRelyingPartyCeremonySkin"/> hosted on a genuine Kestrel loopback
/// listener and reached only by a real <see cref="HttpClient"/>.
/// </summary>
/// <remarks>
/// Before this wave, this exact round trip was structurally impossible to prove: the simulator shipped
/// only an ES256 credential backend (so it could never pick the EdDSA entry the RP's own builder
/// advertises first), and the RP skin hardcoded <c>AllowedAlgorithms = [ES256]</c> independently of what
/// it offered — the two facts observed together are exactly the defect this wave closes. This class
/// exercises both fixes through the same production code the HTTP/APDU capstone above already trusts,
/// never a shortcut construction of either side.
/// </remarks>
[TestClass]
internal sealed class WebAuthnRpHttpEdDsaCeremonyTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The relying party identifier this capstone's ceremonies are scoped to.</summary>
    private const string RpId = "webauthn-rp-http-eddsa.example";

    /// <summary>The relying party origin this capstone's ceremonies embed and expect.</summary>
    private const string Origin = "https://webauthn-rp-http-eddsa.example";


    /// <summary>
    /// The full journey over an EdDSA-only authenticator: the RP's own default options offer EdDSA first
    /// (unchanged production behaviour); the authenticator — which supports ONLY EdDSA, so it can never
    /// coincidentally satisfy a stale ES256-shaped expectation — mints an Ed25519 credential; and the RP's
    /// <see cref="RegistrationCeremonyInput.ExpectedPubKeyCredParams"/>-derived
    /// <see cref="RegistrationCeremonyInput.AllowedAlgorithms"/> accepts it. A subsequent assertion,
    /// signed with that same Ed25519 credential key, also verifies — proving the EdDSA signing path works
    /// end to end through the registered production seam, not merely that registration parsed the key.
    /// </summary>
    [TestMethod]
    public async Task EdDsaFirstOfferIsHonouredByAnEdDsaOnlyAuthenticatorAndAcceptedByTheDerivedAllowedAlgorithms()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        var skin = new WebAuthnRelyingPartyCeremonySkin(
            RpId, Origin, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xEA), "eve", "Eve Example", pool);
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(skin.HandleAsync, cancellationToken).ConfigureAwait(false);
        using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(host.Certificate, host.BaseAddress);

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulatorWithBackend(
            "webauthn-rp-http-eddsa-authenticator", CtapCredentialSigningBackend.CreateEdDsaDefault());
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        using HttpResponseMessage optionsResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AttestationOptionsPath, jsonBody: null, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, optionsResponse.StatusCode);
        byte[] optionsBytes = await optionsResponse.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        PublicKeyCredentialCreationOptions creationOptions = PublicKeyCredentialCreationOptionsJsonReader.Read(optionsBytes, pool);

        Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, creationOptions.PubKeyCredParams![0].Alg,
            "The relying party's own default MUST offer EdDSA first; this capstone is void if that ever regresses to something else.");

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

        Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, browserAuthenticatorData.AttestedCredentialData!.CredentialPublicKey.Alg,
            "The authenticator MUST have minted the first-preferred EdDSA entry from the offered pubKeyCredParams, not some other algorithm.");

        string registrationEnvelopeJson = WebAuthnRelyingPartyCeremonySkin.BuildRegistrationResponseJson(
            browserAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan(), createClientDataJson, attestationObject.Span);

        using HttpResponseMessage resultResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AttestationResultPath, registrationEnvelopeJson, cancellationToken).ConfigureAwait(false);
        string resultBody = await resultResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, resultResponse.StatusCode,
            $"An Ed25519 credential from an authenticator honouring the RP's own stated preference MUST be accepted — this is the exact case waveref R-1/R-2 fix. Body={resultBody}");
        Assert.Contains("\"verified\":true", resultBody, StringComparison.Ordinal);
        Assert.IsNotNull(skin.StoredCredential, "A successful registration MUST store a credential record.");
        Assert.AreEqual(WellKnownCoseAlgorithms.EdDsa, skin.StoredCredential!.PublicKey.Alg);

        await AssertOverRealTransportsAsync(httpClient, harness, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1, skin.AssertionResultRequestCount, "The RP MUST see exactly one assertion result request cross the socket.");
    }


    /// <summary>
    /// POSTs <paramref name="jsonBody"/> (or an empty body, when <see langword="null"/>) to
    /// <paramref name="path"/> via a genuine <see cref="HttpRequestMessage"/>/<see cref="HttpClient.SendAsync(HttpRequestMessage, CancellationToken)"/>
    /// call, mirroring <see cref="WebAuthnRpHttpCeremonyTests"/>'s own helper of the same shape.
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


    /// <summary>
    /// Drives one authentication ceremony against the just-registered Ed25519 credential: fetches
    /// <c>PublicKeyCredentialRequestOptionsJSON</c> over HTTP, runs <c>authenticatorGetAssertion</c> over
    /// the real APDU transport (which signs with the same Ed25519 credential key
    /// <see cref="Fido2CredentialSigner"/> minted), re-encodes the result as <c>AuthenticationResponseJSON</c>,
    /// and POSTs it back, asserting the RP accepts it — proving the EdDSA signing path works end to end
    /// through the registered production seam, not merely that registration parsed the public key.
    /// </summary>
    private static async Task AssertOverRealTransportsAsync(
        HttpClient httpClient, CtapWave2TransportHarness harness, BaseMemoryPool pool, CancellationToken cancellationToken)
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

        using HttpResponseMessage resultResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AssertionResultPath, assertionEnvelopeJson, cancellationToken).ConfigureAwait(false);
        string resultBody = await resultResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, resultResponse.StatusCode,
            $"An Ed25519-signed assertion MUST verify through the registered production signing/verification seam. Body={resultBody}");
        Assert.Contains("\"verified\":true", resultBody, StringComparison.Ordinal);
    }
}

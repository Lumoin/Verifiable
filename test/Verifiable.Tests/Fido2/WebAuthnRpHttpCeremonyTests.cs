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
/// Real-wire capstone for the WebAuthn RP wire surface (contract decision 3): a CTAP authenticator
/// simulator, driven over the REAL <see cref="Verifiable.Apdu.ApduExecutor"/>/<see cref="Verifiable.Apdu.ApduDevice"/>
/// transport (<see cref="CtapWave2TransportHarness"/>), completes a registration ceremony then an
/// authentication ceremony against <see cref="WebAuthnRelyingPartyCeremonySkin"/> hosted on a genuine
/// Kestrel loopback listener (<see cref="MinimalHttpHost"/>) and reached only by a real
/// <see cref="HttpClient"/>. Browser-glue in this class re-encodes the CTAP outputs into the W3C
/// WebAuthn Level 3 <c>RegistrationResponseJSON</c>/<c>AuthenticationResponseJSON</c> envelopes; the RP
/// side consumes ONLY bytes that crossed the HTTP wire (via the new
/// <see cref="RegistrationResponseJsonReader"/>/<see cref="AuthenticationResponseJsonReader"/>), and the
/// authenticator side consumes ONLY bytes that crossed the APDU wire.
/// </summary>
[TestClass]
internal sealed class WebAuthnRpHttpCeremonyTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The relying party identifier this capstone's ceremonies are scoped to.</summary>
    private const string RpId = "webauthn-rp-http.example";

    /// <summary>The relying party origin this capstone's ceremonies embed and expect.</summary>
    private const string Origin = "https://webauthn-rp-http.example";


    /// <summary>
    /// The full journey: registration then assertion, each ceremony's options fetched over HTTP, each
    /// authenticator operation carried out over the real APDU transport, and each result POSTed back
    /// over HTTP as the W3C JSON envelope — the RP accepts both.
    /// </summary>
    [TestMethod]
    public async Task RegistrationThenAssertionSucceedOverRealHttpAndApduTransports()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        var skin = new WebAuthnRelyingPartyCeremonySkin(
            RpId, Origin, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xE0), "alice", "Alice Example", pool);
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(skin.HandleAsync, cancellationToken).ConfigureAwait(false);
        using HttpClient httpClient = new() { BaseAddress = host.BaseAddress };

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("webauthn-rp-http-authenticator");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await RegisterOverRealTransportsAsync(httpClient, harness, pool, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1, skin.AttestationResultRequestCount, "The RP MUST see exactly one attestation result request cross the socket.");
        Assert.IsNotNull(skin.StoredCredential, "A successful registration MUST store a credential record.");
        uint registeredSignCount = skin.StoredCredential!.SignCount;

        await AssertOverRealTransportsAsync(httpClient, harness, pool, tamperSignature: false, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1, skin.AssertionResultRequestCount, "The RP MUST see exactly one assertion result request cross the socket.");
        Assert.IsGreaterThan(registeredSignCount, skin.StoredCredential!.SignCount, "A successful assertion MUST bump the stored sign count.");
    }


    /// <summary>
    /// A tampered assertion signature — one byte flipped after the authenticator signed it — fails
    /// verification with the RP skin's exact rejected shape (401, <c>{"verified":false}</c>), never a
    /// weaker or generic failure.
    /// </summary>
    [TestMethod]
    public async Task TamperedAssertionSignatureFailsVerificationWithExactShape()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        var skin = new WebAuthnRelyingPartyCeremonySkin(
            RpId, Origin, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xE1), "bob", "Bob Example", pool);
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(skin.HandleAsync, cancellationToken).ConfigureAwait(false);
        using HttpClient httpClient = new() { BaseAddress = host.BaseAddress };

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("webauthn-rp-http-tamper-authenticator");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await RegisterOverRealTransportsAsync(httpClient, harness, pool, cancellationToken).ConfigureAwait(false);

        using HttpResponseMessage response = await AssertOverRealTransportsAsync(httpClient, harness, pool, tamperSignature: true, cancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, $"A tampered signature MUST be rejected. Body={body}");
        Assert.Contains("\"verified\":false", body, StringComparison.Ordinal);
    }


    /// <summary>
    /// An <c>AuthenticationResponseJSON</c> body missing its required <c>response</c> member — an
    /// envelope-level negative at the HTTP boundary — is rejected with the RP skin's exact malformed
    /// shape (400, <c>error: "malformed envelope"</c>), never an unhandled server error.
    /// </summary>
    [TestMethod]
    public async Task MalformedEnvelopeAtAssertionResultReturnsExactBadRequestShape()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        var skin = new WebAuthnRelyingPartyCeremonySkin(
            RpId, Origin, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xE2), "carol", "Carol Example", pool);
        await using MinimalHttpHost host = await MinimalHttpHost.StartAsync(skin.HandleAsync, cancellationToken).ConfigureAwait(false);
        using HttpClient httpClient = new() { BaseAddress = host.BaseAddress };

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("webauthn-rp-http-malformed-authenticator");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await RegisterOverRealTransportsAsync(httpClient, harness, pool, cancellationToken).ConfigureAwait(false);

        using HttpResponseMessage optionsResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AssertionOptionsPath, jsonBody: null, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, optionsResponse.StatusCode);

        const string malformedEnvelope = """{"id":"AQIDBA","rawId":"AQIDBA","clientExtensionResults":{},"type":"public-key"}""";
        using HttpResponseMessage resultResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AssertionResultPath, malformedEnvelope, cancellationToken).ConfigureAwait(false);

        string body = await resultResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.BadRequest, resultResponse.StatusCode, $"A malformed envelope MUST be rejected. Body={body}");
        Assert.Contains("malformed envelope", body, StringComparison.Ordinal);
    }


    /// <summary>
    /// Once the Kestrel listener stops, the same request that succeeded moments earlier fails with a
    /// connection-level error rather than a protocol response — proof this capstone's ceremony is
    /// reachable only through the socket, not some in-process shortcut.
    /// </summary>
    [TestMethod]
    public async Task RequestFailsStructurallyOnceTheHostStops()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        var skin = new WebAuthnRelyingPartyCeremonySkin(
            RpId, Origin, CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xE3), "dave", "Dave Example", pool);

        Uri baseAddress;
        await using(MinimalHttpHost host = await MinimalHttpHost.StartAsync(skin.HandleAsync, cancellationToken).ConfigureAwait(false))
        {
            baseAddress = host.BaseAddress;
            using HttpClient warmupClient = new() { BaseAddress = baseAddress };
            using HttpResponseMessage warmup = await PostAsync(warmupClient, WebAuthnRelyingPartyCeremonySkin.AttestationOptionsPath, jsonBody: null, cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(HttpStatusCode.OK, warmup.StatusCode, "The endpoint MUST answer while the host is running.");
        }

        using HttpClient httpClient = new() { BaseAddress = baseAddress };
        await Assert.ThrowsExactlyAsync<HttpRequestException>(
            () => PostAsync(httpClient, WebAuthnRelyingPartyCeremonySkin.AttestationOptionsPath, jsonBody: null, cancellationToken));
    }


    /// <summary>
    /// POSTs <paramref name="jsonBody"/> (or an empty body, when <see langword="null"/>) to
    /// <paramref name="path"/> via a genuine <see cref="HttpRequestMessage"/>/<see cref="HttpClient.SendAsync(HttpRequestMessage, CancellationToken)"/>
    /// call — the <see cref="HttpRequestMessage"/>'s own disposal releases its <see cref="HttpContent"/>,
    /// so callers only need to dispose the returned response.
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
    /// Drives one full registration ceremony: fetches <c>PublicKeyCredentialCreationOptionsJSON</c> over
    /// HTTP, runs <c>authenticatorMakeCredential</c> over the real APDU transport, re-encodes the result
    /// as <c>RegistrationResponseJSON</c>, and POSTs it back, asserting the RP accepts it.
    /// </summary>
    private static async Task RegisterOverRealTransportsAsync(
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

        //Browser-glue: the client platform recovers the credential id from the authenticator's own
        //response (here via the shipped attestationObject/authenticatorData readers) to populate
        //PublicKeyCredential's id/rawId — the same recovery a real user agent performs before calling
        //toJSON(), never a test-only wire encoder.
        AttestationObjectParts attestationParts = AttestationObjectCborReader.Parse(attestationObject.Memory);
        using AuthenticatorData browserAuthenticatorData = AuthenticatorDataReader.Read(attestationParts.AuthenticatorData, CredentialPublicKeyCborReader.Read, pool);

        string registrationEnvelopeJson = WebAuthnRelyingPartyCeremonySkin.BuildRegistrationResponseJson(
            browserAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan(), createClientDataJson, attestationObject.Span);

        using HttpResponseMessage resultResponse = await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AttestationResultPath, registrationEnvelopeJson, cancellationToken).ConfigureAwait(false);
        string resultBody = await resultResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, resultResponse.StatusCode, $"Registration MUST be accepted over the real wire. Body={resultBody}");
        Assert.Contains("\"verified\":true", resultBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// Drives one authentication ceremony: fetches <c>PublicKeyCredentialRequestOptionsJSON</c> over
    /// HTTP, runs <c>authenticatorGetAssertion</c> over the real APDU transport, re-encodes the result as
    /// <c>AuthenticationResponseJSON</c> (optionally tampering the signature byte-for-byte), and POSTs it
    /// back, returning the raw HTTP response for the caller to assert on.
    /// </summary>
    private static async Task<HttpResponseMessage> AssertOverRealTransportsAsync(
        HttpClient httpClient, CtapWave2TransportHarness harness, MemoryPool<byte> pool, bool tamperSignature, CancellationToken cancellationToken)
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

        using IMemoryOwner<byte> signatureOwner = pool.Rent(getAssertionResponse.Signature.Length);
        Span<byte> signatureSpan = signatureOwner.Memory.Span[..getAssertionResponse.Signature.Length];
        getAssertionResponse.Signature.Span.CopyTo(signatureSpan);
        if(tamperSignature)
        {
            signatureSpan[^1] ^= 0xFF;
        }

        bool hasUserHandle = getAssertionResponse.User is not null;
        string assertionEnvelopeJson = WebAuthnRelyingPartyCeremonySkin.BuildAssertionResponseJson(
            getAssertionResponse.Credential.Id.AsReadOnlySpan(),
            getClientDataJson,
            getAssertionResponse.AuthData.Span,
            signatureSpan,
            hasUserHandle,
            hasUserHandle ? getAssertionResponse.User!.Id.AsReadOnlySpan() : default);

        return await PostAsync(
            httpClient, WebAuthnRelyingPartyCeremonySkin.AssertionResultPath, assertionEnvelopeJson, cancellationToken).ConfigureAwait(false);
    }
}

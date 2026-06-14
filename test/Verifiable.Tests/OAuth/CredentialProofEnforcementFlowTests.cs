using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vci.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The OPT-IN library-side Appendix F.4 proof enforcement at the §8 Credential Endpoint, driven
/// through the real dispatch pipeline. With the
/// <see cref="AuthorizationServerIntegration.ResolveCredentialProofExpectationAsync"/> seam wired,
/// the library validates the §8.2 <c>proofs.jwt</c> batch BEFORE the issuance seam: a good proof
/// issues, a bad-nonce proof yields the §8.3.1.2 <c>invalid_nonce</c> error before issuance. The
/// existing default-path Credential Endpoint tests (no expectation seam) stay green — proven there.
/// </summary>
[TestClass]
internal sealed class CredentialProofEnforcementFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://wallet.client.test";
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");
    private const string OfferSubject = "urn:uuid:end-user-42";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string CredentialNonce = "c-nonce-enforcement-42";
    private const string IssuedCredential = "issued-credential-opaque-42";

    private static readonly ImmutableHashSet<CapabilityIdentifier> CredentialCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);

    private static readonly System.Text.Json.JsonSerializerOptions JoseSerializationOptions =
        new(TestSetup.DefaultSerializationOptions)
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, JoseSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, JoseSerializationOptions);


    /// <summary>
    /// With the proof-expectation seam wired, a Credential Request carrying a production-minted
    /// proof bound to the resolved issuer <c>aud</c> and the expected <c>c_nonce</c> passes §F.4
    /// validation and issues.
    /// </summary>
    [TestMethod]
    public async Task GoodProofPassesLibraryValidationAndIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        WireProofExpectationSeam(host);
        bool seamIssued = WireIssuance(host);

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;
        string proof = await MintProofAsync(issuerAudience, CredentialNonce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAsync(host, material, proof).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(IssuedCredential,
            doc.RootElement.GetProperty("credentials")[0].GetProperty("credential").GetString());
    }


    /// <summary>
    /// §8.3.1.2: a proof echoing a stale <c>c_nonce</c> is rejected by the library with
    /// <c>invalid_nonce</c> BEFORE the issuance seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task BadNonceProofYieldsInvalidNonceBeforeTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        WireProofExpectationSeam(host);

        bool seamConsulted = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seamConsulted = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;
        string proof = await MintProofAsync(issuerAudience, "c-nonce-STALE").ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAsync(host, material, proof).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidNonce, response.Body);
        Assert.IsFalse(seamConsulted, "Library §F.4 enforcement must reject the bad nonce before the issuance seam.");
    }


    /// <summary>
    /// §8.3.1.2: a proof whose signature does not verify is rejected by the library with
    /// <c>invalid_proof</c> before the issuance seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task TamperedProofYieldsInvalidProofBeforeTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        WireProofExpectationSeam(host);

        bool seamConsulted = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seamConsulted = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;
        string proof = await MintProofAsync(issuerAudience, CredentialNonce).ConfigureAwait(false);

        int signatureStart = proof.LastIndexOf('.') + 1;
        int tamperIndex = signatureStart + (proof.Length - signatureStart) / 2;
        char tampered = proof[tamperIndex] == 'A' ? 'B' : 'A';
        string tamperedProof = string.Concat(
            proof.AsSpan(0, tamperIndex), tampered.ToString(), proof.AsSpan(tamperIndex + 1));

        ServerHttpResponse response = await DispatchAsync(host, material, tamperedProof).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
        Assert.IsFalse(seamConsulted, "Library §F.4 enforcement must reject the bad signature before the issuance seam.");
    }


    //Wires the opt-in §F.4 expectation seam: a fixed c_nonce, ES256-only, a 5-minute iat window.
    private static void WireProofExpectationSeam(TestHostShell host)
    {
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().ResolveCredentialProofExpectationAsync =
            (request, accessToken, registration, context, ct) =>
                ValueTask.FromResult<CredentialProofExpectation?>(new CredentialProofExpectation
                {
                    ExpectedNonce = CredentialNonce,
                    IsNonceRequired = true,
                    AcceptableProofSigningAlgorithms = [WellKnownJwaValues.Es256],
                    IatSkew = TimeSpan.FromMinutes(5),
                    IsProofRequired = true
                });
    }


    //Wires issuance to a simple issue; the bool flips when the seam runs (i.e. proof validation passed).
    private static bool WireIssuance(TestHostShell host)
    {
        bool issued = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                issued = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        return issued;
    }


    //Mints a §F.1 jwt proof with the production minter, bound to the given aud + nonce.
    private async Task<string> MintProofAsync(string audience, string nonce)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        return await Oid4VciProofIssuance.BuildJwtProofAsync(
            holderPrivate,
            holderPublic,
            audience,
            nonce,
            TimeProvider.GetUtcNow(),
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Mints the access token via the Pre-Authorized Code grant and dispatches a §8.2 Credential
    //Request carrying the proof to the Credential Endpoint.
    private async Task<ServerHttpResponse> DispatchAsync(
        TestHostShell host, VerifierKeyMaterial material, string proof)
    {
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, WellKnownScopes.OpenId));

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypePreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument tokenDoc = JsonDocument.Parse(tokenResponse.Body);
        string accessToken = tokenDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        string body = "{\"credential_configuration_id\":\"" + ConfigurationId
            + "\",\"proofs\":{\"jwt\":[\"" + proof + "\"]}}";

        RequestHeaders headers = new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = ["Bearer " + accessToken]
        });

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredential,
            "POST",
            new RequestFields(),
            headers,
            body,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}

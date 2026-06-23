using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end tests for the OpenID Federation 1.0 §12.2
/// <c>federation_registration_endpoint</c> (explicit client registration)
/// exposed by <see cref="FederationEndpoints"/>. The RP POSTs its signed
/// Entity Configuration; the OP returns a signed Explicit Registration
/// Response (<c>typ = explicit-registration-response+jwt</c>) with
/// <c>iss</c> = OP, <c>sub</c> = <c>aud</c> = RP, the selected
/// <c>trust_anchor</c>, and the registered client <c>metadata</c>. The
/// per-request result comes from the application's
/// <see cref="AuthorizationServerIntegration.ResolveExplicitRegistrationAsync"/>
/// delegate; the library passes the posted body through unparsed and only
/// builds and signs the response.
/// </summary>
[TestClass]
internal sealed class FederationRegistrationEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string OpEntityId = "https://op.example.com";
    private const string RpEntityId = "https://rp.example.com";
    private const string AnchorEntityId = "https://anchor.example.com";


    [TestMethod]
    public async Task RegistrationEndpointServesSignedExplicitRegistrationResponse()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> opFederationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial opKeys = RegisterOp(app, opFederationKeys);

        //Mint the RP's signed Entity Configuration — the body the RP POSTs.
        using Federation.FederationTestRingNode rpNode =
            Federation.FederationTestRing.CreateNode(new EntityIdentifier(RpEntityId));
        Federation.MintedStatement rpEc = await Federation.FederationTestRing.MintEntityConfigurationAsync(
            rpNode,
            TimeProvider.GetUtcNow(),
            TimeProvider.GetUtcNow().AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string rpEcJws = rpEc.CompactJws;

        string? observedBody = null;
        app.Server.OAuth().ResolveExplicitRegistrationAsync = (body, _, _, _) =>
        {
            observedBody = body;

            Dictionary<string, object> rpClientMetadata = new(StringComparer.Ordinal)
            {
                ["client_id"] = RpEntityId,
                ["client_name"] = "Registered RP",
            };
            Dictionary<string, object> metadata = new(StringComparer.Ordinal)
            {
                [WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value] = rpClientMetadata,
            };

            return ValueTask.FromResult<ExplicitRegistrationContribution?>(
                new ExplicitRegistrationContribution
                {
                    Subject = new Uri(RpEntityId),
                    Metadata = metadata,
                    TrustAnchor = new Uri(AnchorEntityId),
                });
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = opKeys.Registration.TenantId.Value;

        string compactResponse = await PostRegistrationAsync(host, segment, rpEcJws).ConfigureAwait(false);

        //The library handed the RP's posted Entity Configuration through verbatim.
        Assert.AreEqual(rpEcJws, observedBody,
            "The delegate must receive the exact posted Entity Configuration body.");

        Dictionary<string, object> header = DecodeSegment(compactResponse, 0);
        Assert.AreEqual(
            WellKnownFederationMediaTypes.ExplicitRegistrationResponseJwt,
            (string)header[WellKnownJoseHeaderNames.Typ],
            "The response must carry typ=explicit-registration-response+jwt per §12.2 / §15.8.");

        Dictionary<string, object> payload = DecodeSegment(compactResponse, 1);
        Assert.AreEqual(new Uri(OpEntityId).ToString(), (string)payload["iss"],
            "iss must be the OP's Entity Identifier.");
        Assert.AreEqual(new Uri(RpEntityId).ToString(), (string)payload["sub"],
            "sub must be the RP's Entity Identifier.");
        Assert.AreEqual(new Uri(RpEntityId).ToString(), (string)payload["aud"],
            "aud MUST be the RP's Entity Identifier per §3.1.5.");
        Assert.AreEqual(new Uri(AnchorEntityId).ToString(), (string)payload["trust_anchor"],
            "trust_anchor must be the OP-selected Trust Anchor.");

        IReadOnlyDictionary<string, object> metadata =
            (IReadOnlyDictionary<string, object>)payload["metadata"];
        IReadOnlyDictionary<string, object> rp =
            (IReadOnlyDictionary<string, object>)metadata[WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value];
        Assert.AreEqual("Registered RP", (string)rp["client_name"]);

        bool verified = await Jws.VerifyAsync(
            compactResponse,
            TestSetup.Base64UrlDecoder,
            Pool,
            opFederationKeys.PublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified,
            "The Explicit Registration Response must verify under the OP's federation signing key.");
    }


    [TestMethod]
    public async Task RegistrationEndpointReturns400WhenApplicationRefuses()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> opFederationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial opKeys = RegisterOp(app, opFederationKeys);

        app.Server.OAuth().ResolveExplicitRegistrationAsync =
            (_, _, _, _) => ValueTask.FromResult<ExplicitRegistrationContribution?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = opKeys.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_registration");
        using System.Net.Http.StringContent content = new(
            "eyJrp.entity.configuration", Encoding.UTF8, WellKnownMediaTypes.Application.EntityStatementJwt);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A refused registration (null contribution) yields HTTP 400.");
    }


    private static VerifierKeyMaterial RegisterOp(
        TestHostShell app,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> opFederationKeys)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.RegisterClientsExplicitly);

        return app.RegisterFederationCapableClient(
            clientId: OpEntityId,
            baseUri: new Uri(OpEntityId),
            federationEntityId: new Uri(OpEntityId),
            federationSigningKeyPair: opFederationKeys,
            baseCapabilities: capabilities);
    }


    private async ValueTask<string> PostRegistrationAsync(
        HostedAuthorizationServer host, string segment, string entityConfigurationJws)
    {
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_registration");
        using System.Net.Http.StringContent content = new(
            entityConfigurationJws, Encoding.UTF8, WellKnownMediaTypes.Application.EntityStatementJwt);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            $"POST federation_registration must return 200. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");

        string? actualContentType = response.Content.Headers.ContentType?.MediaType;
        Assert.AreEqual(WellKnownMediaTypes.Application.ExplicitRegistrationResponseJwt, actualContentType,
            $"The response must serve {WellKnownMediaTypes.Application.ExplicitRegistrationResponseJwt}.");

        return await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static Dictionary<string, object> DecodeSegment(string compactJws, int index)
    {
        string[] parts = compactJws.Split('.');
        Assert.HasCount(3, parts,
            "A registration response must be a JWS compact serialization with three segments.");

        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[index], Pool);

        return JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes.Memory.Span, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("JWS segment parsed to null.");
    }
}

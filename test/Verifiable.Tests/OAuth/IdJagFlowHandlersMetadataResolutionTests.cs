using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.IdJag;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Proves that <see cref="IdJagFlowHandlers.MintAsync"/> and <see cref="IdJagFlowHandlers.RedeemAsync"/>
/// map a non-<see cref="AuthorizationServerMetadataResolutionOutcome.Resolved"/>
/// <see cref="ResolveAuthorizationServerMetadataDelegate"/> answer to an
/// <see cref="OAuthAuthorizationServerMetadataUnresolved"/> failure, without throwing and without
/// sending a token request.
/// </summary>
[TestClass]
internal sealed class IdJagFlowHandlersMetadataResolutionTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private FillEntropyDelegate ClientEntropy { get; } = TestEntropy.NewCounterStream();

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// A mint call whose metadata resolution answers
    /// <see cref="AuthorizationServerMetadataResolutionOutcome.FetchFailed"/> returns
    /// <see cref="OAuthAuthorizationServerMetadataUnresolved"/> naming that outcome, and never reaches
    /// the token endpoint send.
    /// </summary>
    [TestMethod]
    public async Task MintAsyncReturnsUnresolvedFailureWhenMetadataFetchFails()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            AuthorizationServerMetadataResolutionOutcome.FetchFailed, "simulated transport failure");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory signingKey = keyMaterial.PrivateKey;
        IdJagMintOptions options = new()
        {
            Audience = "https://resource-as.example.com/",
            SubjectToken = "subject-token-opaque",
            SubjectTokenType = TokenType.IdToken,
            SigningKey = signingKey,
            SigningKeyId = "client-key-1",
            HeaderSerializer = HeaderSerializer,
            PayloadSerializer = PayloadSerializer
        };

        Result<TokenResponse, OAuthParseError> result = await IdJagFlowHandlers.MintAsync(
            options, infrastructure, registration, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        OAuthAuthorizationServerMetadataUnresolved failure =
            Assert.IsInstanceOfType<OAuthAuthorizationServerMetadataUnresolved>(result.Error);
        Assert.AreEqual(AuthorizationServerMetadataResolutionOutcome.FetchFailed, failure.Outcome);
    }


    /// <summary>
    /// A redeem call whose metadata resolution answers
    /// <see cref="AuthorizationServerMetadataResolutionOutcome.FetchFailed"/> returns
    /// <see cref="OAuthAuthorizationServerMetadataUnresolved"/> naming that outcome, and never reaches
    /// the token endpoint send.
    /// </summary>
    [TestMethod]
    public async Task RedeemAsyncReturnsUnresolvedFailureWhenMetadataFetchFails()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            AuthorizationServerMetadataResolutionOutcome.FetchFailed, "simulated transport failure");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory signingKey = keyMaterial.PrivateKey;
        IdJagRedeemOptions options = new()
        {
            Assertion = "id-jag-assertion-opaque",
            SigningKey = signingKey,
            SigningKeyId = "client-key-1",
            HeaderSerializer = HeaderSerializer,
            PayloadSerializer = PayloadSerializer
        };

        Result<TokenResponse, OAuthParseError> result = await IdJagFlowHandlers.RedeemAsync(
            options, infrastructure, registration, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        OAuthAuthorizationServerMetadataUnresolved failure =
            Assert.IsInstanceOfType<OAuthAuthorizationServerMetadataUnresolved>(result.Error);
        Assert.AreEqual(AuthorizationServerMetadataResolutionOutcome.FetchFailed, failure.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>-style
    /// SSRF hardening applies to the ID-JAG mint's token endpoint the same way it applies to
    /// AuthCode's PAR and token endpoints: it is read out of resolved authorization-server
    /// metadata, not chosen by this library, so a loopback IP literal is refused before the
    /// §4.3 form POST is ever sent.
    /// </summary>
    [TestMethod]
    public async Task MintAsyncRefusesLoopbackTokenEndpointBeforeAnyDial()
    {
        List<Uri> invocations = [];
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            AuthorizationServerMetadataResolutionOutcome.Resolved,
            defect: null,
            tokenEndpointOverride: new Uri("https://127.0.0.1/token"),
            sendFormPostInvocations: invocations);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory signingKey = keyMaterial.PrivateKey;
        IdJagMintOptions options = new()
        {
            Audience = "https://resource-as.example.com/",
            SubjectToken = "subject-token-opaque",
            SubjectTokenType = TokenType.IdToken,
            SigningKey = signingKey,
            SigningKeyId = "client-key-1",
            HeaderSerializer = HeaderSerializer,
            PayloadSerializer = PayloadSerializer
        };

        Result<TokenResponse, OAuthParseError> result = await IdJagFlowHandlers.MintAsync(
            options, infrastructure, registration, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        OAuthOutboundFetchPolicyDenied failure = Assert.IsInstanceOfType<OAuthOutboundFetchPolicyDenied>(result.Error);
        Assert.AreEqual(new Uri("https://127.0.0.1/token"), failure.Endpoint);
        Assert.IsEmpty(invocations, "The transport spy must record ZERO invocations when the policy denies the endpoint.");
    }


    /// <summary>
    /// The same SSRF hardening applies to the ID-JAG redeem's Resource Authorization Server token
    /// endpoint: a loopback IP literal is refused before the §4.4 form POST is ever sent.
    /// </summary>
    [TestMethod]
    public async Task RedeemAsyncRefusesLoopbackTokenEndpointBeforeAnyDial()
    {
        List<Uri> invocations = [];
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            AuthorizationServerMetadataResolutionOutcome.Resolved,
            defect: null,
            tokenEndpointOverride: new Uri("https://127.0.0.1/token"),
            sendFormPostInvocations: invocations);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory signingKey = keyMaterial.PrivateKey;
        IdJagRedeemOptions options = new()
        {
            Assertion = "id-jag-assertion-opaque",
            SigningKey = signingKey,
            SigningKeyId = "client-key-1",
            HeaderSerializer = HeaderSerializer,
            PayloadSerializer = PayloadSerializer
        };

        Result<TokenResponse, OAuthParseError> result = await IdJagFlowHandlers.RedeemAsync(
            options, infrastructure, registration, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        OAuthOutboundFetchPolicyDenied failure = Assert.IsInstanceOfType<OAuthOutboundFetchPolicyDenied>(result.Error);
        Assert.AreEqual(new Uri("https://127.0.0.1/token"), failure.Endpoint);
        Assert.IsEmpty(invocations, "The transport spy must record ZERO invocations when the policy denies the endpoint.");
    }


    private (OAuthClientInfrastructure Infrastructure, ClientRegistration Registration) CreateInfrastructureAndRegistration(
        AuthorizationServerMetadataResolutionOutcome outcome,
        string? defect,
        Uri? tokenEndpointOverride = null,
        List<Uri>? sendFormPostInvocations = null)
    {
        Uri issuerUri = new("https://as.example.com");
        Uri tokenEndpoint = tokenEndpointOverride ?? new Uri("https://as.example.com/token");

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, _, _, _, _) =>
            {
                sendFormPostInvocations?.Add(endpoint);
                throw new InvalidOperationException(
                    "Must not send a token request when metadata resolution fails or the outbound "
                    + "fetch policy denies the token endpoint.");
            },
            saveStateAsync: (_, _, _) => ValueTask.CompletedTask,
            loadStateAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            parseParResponseAsync: (response) =>
                throw new NotImplementedException("This test does not exercise PAR."),
            parseTokenResponseAsync: (response, receivedAt) =>
                throw new NotImplementedException("A failed metadata resolution must not reach the parser."),
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("This test does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
                ValueTask.FromResult(outcome == AuthorizationServerMetadataResolutionOutcome.Resolved
                    ? new AuthorizationServerMetadataResolution
                    {
                        Outcome = outcome,
                        Metadata = new AuthorizationServerMetadata
                        {
                            Issuer = issuerUri,
                            AuthorizationEndpoint = new Uri("https://as.example.com/authorize"),
                            TokenEndpoint = tokenEndpoint
                        }
                    }
                    : new AuthorizationServerMetadataResolution { Outcome = outcome, Defect = defect }),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: BaseMemoryPool.Shared,
            timeProvider: TimeProvider,
            fillEntropy: ClientEntropy,
            generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, ClientEntropy, BaseMemoryPool.Shared));

        ClientRegistration registration = new()
        {
            ClientId = new ClientId("https://machine.example.com"),
            AuthorizationServerIssuer = issuerUri,
            AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
            Profile = PolicyProfile.Haip10
        };

        return (infrastructure, registration);
    }
}

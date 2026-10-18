using Microsoft.Extensions.Time.Testing;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.IdJag;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The ID-JAG mint's client authentication by a client secret (<see cref="IdJagFlowHandlers.MintAsync"/>): a registration
/// naming <c>client_secret_post</c> presents its secret in the body and <c>client_secret_basic</c> in the Authorization header
/// field, each read from the registration composed for the one call and no assertion beside it; a secret method carrying no
/// secret and an assertion method handed no assertion inputs are refused before anything is sent; no <c>audience</c> is sent
/// where the options name none; and an answer of another <c>issued_token_type</c> than the ID-JAG's is refused.
/// </summary>
[TestClass]
internal sealed class IdJagMintClientAuthenticationTests
{
    /// <summary>The identity provider's issuer.</summary>
    private const string ProviderIssuer = "https://idp.example.com";

    /// <summary>The client's identifier at the provider.</summary>
    private const string ProviderClientId = "gateway-client-at-provider";

    /// <summary>The secret the provider issued the client, at least the length every record withholds.</summary>
    private const string ProviderSecret = "provider-issued-secret-0123456789";

    /// <summary>The test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fixed clock.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);


    /// <summary>A <c>client_secret_post</c> registration's mint carries the identifier and the secret in its body, and nothing in the Authorization field.</summary>
    [TestMethod]
    public async Task AClientSecretPostMintCarriesTheSecretInTheBody()
    {
        using var secret = new HeldSecret(ProviderSecret);
        var wire = new SentRequests();
        var infrastructure = CreateInfrastructure(wire, IdJagAnswer(WellKnownTokenTypeIdentifiers.IdJag));

        var minted = await IdJagFlowHandlers.MintAsync(
            MintOptions("https://resource-as.example.com"),
            infrastructure,
            Registration(ClientAuthenticationMethod.ClientSecretPost, secret.Material),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(minted.IsSuccess, $"The mint holds; refused by {minted.Error}.");
        var sent = Assert.ContainsSingle(wire.Requests);
        Assert.AreEqual(ProviderClientId, sent.Field(OAuthRequestParameterNames.ClientId));
        Assert.AreEqual(ProviderSecret, sent.Field(OAuthRequestParameterNames.ClientSecret));
        Assert.IsNull(sent.Field(OAuthRequestParameterNames.ClientAssertion));
        Assert.IsNull(sent.Authorization);
        Assert.AreEqual("https://resource-as.example.com", sent.Field(OAuthRequestParameterNames.Audience));
    }


    /// <summary>A <c>client_secret_basic</c> registration's mint carries the secret in HTTP Basic credentials, and neither secret nor assertion in the body.</summary>
    [TestMethod]
    public async Task AClientSecretBasicMintCarriesTheSecretInTheAuthorizationField()
    {
        using var secret = new HeldSecret(ProviderSecret);
        var wire = new SentRequests();
        var infrastructure = CreateInfrastructure(wire, IdJagAnswer(WellKnownTokenTypeIdentifiers.IdJag));

        var minted = await IdJagFlowHandlers.MintAsync(
            MintOptions("https://resource-as.example.com"),
            infrastructure,
            Registration(ClientAuthenticationMethod.ClientSecretBasic, secret.Material),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(minted.IsSuccess, $"The mint holds; refused by {minted.Error}.");
        var sent = Assert.ContainsSingle(wire.Requests);
        var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{Uri.EscapeDataString(ProviderClientId)}:{Uri.EscapeDataString(ProviderSecret)}"));
        Assert.AreEqual(expected, sent.Authorization);
        Assert.IsNull(sent.Field(OAuthRequestParameterNames.ClientSecret));
        Assert.IsNull(sent.Field(OAuthRequestParameterNames.ClientAssertion));
    }


    /// <summary>A mint whose options name no audience sends none, for a provider taking the audience from its own mapping.</summary>
    [TestMethod]
    public async Task AMintNamingNoAudienceSendsNone()
    {
        using var secret = new HeldSecret(ProviderSecret);
        var wire = new SentRequests();
        var infrastructure = CreateInfrastructure(wire, IdJagAnswer(WellKnownTokenTypeIdentifiers.IdJag));

        var minted = await IdJagFlowHandlers.MintAsync(
            MintOptions(audience: null),
            infrastructure,
            Registration(ClientAuthenticationMethod.ClientSecretPost, secret.Material),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(minted.IsSuccess, $"The mint holds; refused by {minted.Error}.");
        var sent = Assert.ContainsSingle(wire.Requests);
        Assert.IsFalse(sent.Names(OAuthRequestParameterNames.Audience), "No audience is sent where the options name none.");
        Assert.AreEqual("https://mcp.example.com/mcp", sent.Field(OAuthRequestParameterNames.Resource));
    }


    /// <summary>
    /// RFC 8693 §2.1: a mint naming an actor sends its <c>actor_token</c> with the <c>actor_token_type</c> "REQUIRED when the
    /// actor_token parameter is present", each once; a mint naming none sends neither.
    /// </summary>
    [TestMethod]
    public async Task AMintNamingAnActorSendsItsTokenWithItsTypeAndOneNamingNoneSendsNeither()
    {
        using var secret = new HeldSecret(ProviderSecret);
        var wire = new SentRequests();
        var infrastructure = CreateInfrastructure(wire, IdJagAnswer(WellKnownTokenTypeIdentifiers.IdJag));

        var minted = await IdJagFlowHandlers.MintAsync(
            MintOptions("https://resource-as.example.com") with { Actor = new IdJagMintActor { Token = "actor-jwt-of-the-client", Type = TokenType.Jwt } },
            infrastructure,
            Registration(ClientAuthenticationMethod.ClientSecretPost, secret.Material),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(minted.IsSuccess, $"The mint holds; refused by {minted.Error}.");
        var sent = Assert.ContainsSingle(wire.Requests);
        Assert.AreEqual("actor-jwt-of-the-client", sent.Field(OAuthRequestParameterNames.ActorToken), "The actor's token is sent.");
        Assert.AreEqual(WellKnownTokenTypeIdentifiers.Jwt, sent.Field(OAuthRequestParameterNames.ActorTokenType), "The actor's token is typed.");

        var unnamed = new SentRequests();
        _ = await IdJagFlowHandlers.MintAsync(
            MintOptions("https://resource-as.example.com"),
            CreateInfrastructure(unnamed, IdJagAnswer(WellKnownTokenTypeIdentifiers.IdJag)),
            Registration(ClientAuthenticationMethod.ClientSecretPost, secret.Material),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        var plain = Assert.ContainsSingle(unnamed.Requests);
        Assert.IsFalse(plain.Names(OAuthRequestParameterNames.ActorToken), "No actor token is sent where the options name no actor.");
        Assert.IsFalse(plain.Names(OAuthRequestParameterNames.ActorTokenType), "No actor token type is sent where the options name no actor.");
    }


    /// <summary>A secret method whose registration carries no secret is refused, typed, before anything is sent.</summary>
    [TestMethod]
    public async Task ASecretMethodCarryingNoSecretIsRefusedBeforeAnythingIsSent()
    {
        var wire = new SentRequests();
        var infrastructure = CreateInfrastructure(wire, IdJagAnswer(WellKnownTokenTypeIdentifiers.IdJag));

        var minted = await IdJagFlowHandlers.MintAsync(
            MintOptions("https://resource-as.example.com"),
            infrastructure,
            Registration(ClientAuthenticationMethod.ClientSecretPost, material: null),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        var refused = Assert.IsInstanceOfType<OAuthClientAuthenticationRefused>(minted.Error);
        Assert.AreEqual(ClientAuthenticationRefusalReason.ClientSecretNotCarried, refused.Reason);
        Assert.IsEmpty(wire.Requests);
    }


    /// <summary>An assertion method handed no assertion inputs is refused, typed, before anything is sent.</summary>
    [TestMethod]
    public async Task AnAssertionMethodHandedNoInputsIsRefusedBeforeAnythingIsSent()
    {
        using var secret = new HeldSecret(ProviderSecret);
        var wire = new SentRequests();
        var infrastructure = CreateInfrastructure(wire, IdJagAnswer(WellKnownTokenTypeIdentifiers.IdJag));

        var minted = await IdJagFlowHandlers.MintAsync(
            MintOptions("https://resource-as.example.com"),
            infrastructure,
            Registration(ClientAuthenticationMethod.PrivateKeyJwt, secret.Material),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        var refused = Assert.IsInstanceOfType<OAuthClientAuthenticationRefused>(minted.Error);
        Assert.AreEqual(ClientAuthenticationRefusalReason.AssertionInputsNotGiven, refused.Reason);
        Assert.IsEmpty(wire.Requests);
    }


    /// <summary>An answer naming another issued token type than the ID-JAG's is refused as the field it is.</summary>
    [TestMethod]
    public async Task AnAnswerOfAnotherIssuedTokenTypeIsRefused()
    {
        using var secret = new HeldSecret(ProviderSecret);
        var wire = new SentRequests();
        var infrastructure = CreateInfrastructure(wire, IdJagAnswer(WellKnownTokenTypeIdentifiers.AccessToken));

        var minted = await IdJagFlowHandlers.MintAsync(
            MintOptions("https://resource-as.example.com"),
            infrastructure,
            Registration(ClientAuthenticationMethod.ClientSecretPost, secret.Material),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        var refused = Assert.IsInstanceOfType<OAuthInvalidFieldValue>(minted.Error);
        Assert.AreEqual(OAuthRequestParameterNames.IssuedTokenType, refused.FieldName);
    }


    /// <summary>The mint's options: an ID Token subject, the MCP server's resource and the audience given.</summary>
    /// <param name="audience">The audience, or <see langword="null"/> for none.</param>
    /// <returns>The options.</returns>
    private static IdJagMintOptions MintOptions(string? audience) => new()
    {
        Audience = audience,
        SubjectToken = "subject-id-token",
        SubjectTokenType = TokenType.IdToken,
        ClientAssertion = null,
        Resource = ["https://mcp.example.com/mcp"],
        Scope = "tasks:read"
    };


    /// <summary>The registration at the provider under a method and the material composed for the call.</summary>
    /// <param name="method">The method.</param>
    /// <param name="material">The secret's material, or <see langword="null"/> for none.</param>
    /// <returns>The registration.</returns>
    private static ClientRegistration Registration(
        ClientAuthenticationMethod method, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>? material)
    {
        return new ClientRegistration
        {
            ClientId = new ClientId(ProviderClientId),
            AuthorizationServerIssuer = new Uri(ProviderIssuer),
            AuthenticationMethod = method,
            AuthenticationKeyMaterial = material
        };
    }


    /// <summary>A token exchange's answer naming the issued token type given.</summary>
    /// <param name="issuedTokenType">The issued token type.</param>
    /// <returns>The answer's body.</returns>
    private static string IdJagAnswer(string issuedTokenType) =>
        $$"""{"access_token":"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSJ9.c2lnbmF0dXJl","issued_token_type":"{{issuedTokenType}}","token_type":"N_A","expires_in":300}""";


    /// <summary>An infrastructure resolving the provider's metadata and answering every form post with the body given, recording each.</summary>
    /// <param name="wire">The record of the requests sent.</param>
    /// <param name="answer">The body every post is answered with.</param>
    /// <returns>The infrastructure.</returns>
    private OAuthClientInfrastructure CreateInfrastructure(SentRequests wire, string answer)
    {
        var issuer = new Uri(ProviderIssuer);
        var entropy = TestEntropy.NewCounterStream();

        return OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, fields, headers, context, cancellationToken) =>
            {
                wire.Requests.Add(new SentRequest(
                    [.. fields],
                    headers.Values.FirstOrDefault(static header => string.Equals(header.Key, "Authorization", StringComparison.OrdinalIgnoreCase)).Value));

                return ValueTask.FromResult(new HttpResponseData { StatusCode = 200, Body = answer });
            },
            saveStateAsync: (_, _, _) => ValueTask.CompletedTask,
            loadStateAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseRegistrationResponseAsync: (body, cancellationToken) =>
                throw new NotSupportedException("The mint reads no registration response."),
            resolveAuthorizationServerMetadataAsync: (requested, context, cancellationToken) =>
                ValueTask.FromResult<AuthorizationServerMetadataResolution>(new AuthorizationServerMetadataResolved
                {
                    MetadataLocation = WellKnownPaths.OAuthAuthorizationServer.ComputeUri(issuer.OriginalString),
                    Metadata = new AuthorizationServerMetadata
                    {
                        Issuer = issuer,
                        AuthorizationEndpoint = new Uri("https://idp.example.com/authorize"),
                        TokenEndpoint = new Uri("https://idp.example.com/token")
                    }
                }),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: BaseMemoryPool.Shared,
            timeProvider: TimeProvider,
            fillEntropy: entropy,
            generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, entropy, BaseMemoryPool.Shared));
    }


    /// <summary>The requests an infrastructure sent.</summary>
    private sealed class SentRequests
    {
        /// <summary>Each request, in the order sent.</summary>
        public List<SentRequest> Requests { get; } = [];
    }


    /// <summary>One request sent: its form fields and its Authorization field, where it carried one.</summary>
    /// <param name="Fields">The form fields.</param>
    /// <param name="Authorization">The Authorization field's value, or <see langword="null"/>.</param>
    private sealed record SentRequest(IReadOnlyList<KeyValuePair<string, string>> Fields, string? Authorization)
    {
        /// <summary>The first value of a field, or <see langword="null"/>.</summary>
        /// <param name="name">The field's name.</param>
        /// <returns>The value.</returns>
        public string? Field(string name) =>
            Fields.FirstOrDefault(field => string.Equals(field.Key, name, StringComparison.Ordinal)).Value;

        /// <summary>Whether the request names a field.</summary>
        /// <param name="name">The field's name.</param>
        /// <returns><see langword="true"/> when it does.</returns>
        public bool Names(string name) => Fields.Any(field => string.Equals(field.Key, name, StringComparison.Ordinal));
    }


    /// <summary>A client secret held as the key material a registration carries it in, both halves released with it.</summary>
    private sealed class HeldSecret : IDisposable
    {
        /// <summary>Holds a secret's UTF-8 octets in the private half; the public half is one octet no method reads.</summary>
        /// <param name="secret">The secret.</param>
        public HeldSecret(string secret)
        {
            var octets = Encoding.UTF8.GetBytes(secret);
            var owner = BaseMemoryPool.Shared.Rent(octets.Length);
            octets.CopyTo(owner.Memory.Span);
            UnreadHalf = new PublicKeyMemory(BaseMemoryPool.Shared.Rent(1), Tag.Empty);
            SecretHalf = new PrivateKeyMemory(owner, Tag.Empty);
            Material = new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(UnreadHalf, SecretHalf);
        }

        /// <summary>The key material.</summary>
        public PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Material { get; }

        /// <summary>The public half no method reads, owned here.</summary>
        private PublicKeyMemory UnreadHalf { get; }

        /// <summary>The private half carrying the secret's octets, owned here.</summary>
        private PrivateKeyMemory SecretHalf { get; }

        /// <summary>Releases both halves.</summary>
        public void Dispose()
        {
            UnreadHalf.Dispose();
            SecretHalf.Dispose();
        }
    }
}

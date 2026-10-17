using Microsoft.Extensions.Time.Testing;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
/// Every client flow that authenticates with a client assertion (RFC 7523 Section 2.2) forms its credential from the
/// registration's method and key material before anything is resolved or sent, and a credential the registration cannot
/// form is a typed refusal the flow's result carries: the authorization-code exchange, the refresh and the client
/// credentials grant carry it in <see cref="AuthCodeFlowEndpointResult.ClientAssertionCredentialRefusal"/>, and the
/// ID-JAG mint and redeem carry it as <see cref="OAuthClientAssertionRefused"/>. Each refusal is proven against a
/// transport that records every metadata resolution, flow-state read and request, and each flow's acceptance is proven
/// against the same transport by the assertion it sends verifying under the registration's own key or secret.
/// </summary>
[TestClass]
internal sealed class ClientAssertionCredentialFlowRefusalTests
{
    /// <summary>The client identifier every registration names.</summary>
    private const string ClientId = "https://machine.example.com";

    /// <summary>The key identifier a <c>private_key_jwt</c> assertion names when its options name one.</summary>
    private const string SigningKeyId = "client-key-1";

    /// <summary>A client secret of 64 octets, long enough for every HMAC algorithm of RFC 7518 Section 3.2.</summary>
    private const string LongClientSecret = "client-secret-the-authorization-server-issued-0123456789abcdefgh";

    /// <summary>A client secret of 16 octets, shorter than HMAC SHA-256's 32-octet output.</summary>
    private const string ShortClientSecret = "too-short-secret";

    /// <summary>The message the recording transport throws once a request reaches it.</summary>
    private const string TransportReachedMessage = "The request reached the token endpoint.";

    /// <summary>The code of <see cref="ApplicationDefinedMethod"/>, registered once for the process.</summary>
    private const int ApplicationDefinedMethodCode = 41_798;

    /// <summary>The authorization server every registration names.</summary>
    private static Uri Issuer { get; } = new("https://as.example.com");

    /// <summary>An application-defined client authentication method, which no assertion family classifies.</summary>
    private static ClientAuthenticationMethod ApplicationDefinedMethod { get; } = ClientAuthenticationMethod.Create(ApplicationDefinedMethodCode);

    /// <summary>The token endpoint the authorization server's metadata names.</summary>
    private static Uri TokenEndpoint { get; } = new("https://as.example.com/token");

    /// <summary>The pool every key and signature is rented from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>Serialises the client assertion's protected header.</summary>
    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    /// <summary>Serialises the client assertion's claims.</summary>
    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);

    /// <summary>The test context, carrying the token that cancels a test that outruns its run.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the infrastructure reads, held at the suite's canonical instant.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The entropy the infrastructure's identifiers are drawn from.</summary>
    private FillEntropyDelegate ClientEntropy { get; } = TestEntropy.NewCounterStream();


    /// <summary>
    /// A <c>private_key_jwt</c> registration whose assertion options name an empty or white-space key identifier names
    /// none: the authorization-code exchange answers the typed
    /// <see cref="ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier"/> refusal instead of throwing,
    /// before it resolves metadata, reads its flow state or sends anything.
    /// </summary>
    /// <param name="keyId">The key identifier naming none.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    public async Task AuthorizationCodeExchangeRefusesAKeyIdentifierNamingNoneBeforeSending(string keyId)
    {
        var observations = new FlowObservations();
        var client = new OAuthClient(CreateInfrastructure(observations));
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        var result = await client.AuthCode.ExchangeTokenAsync(
            RegistrationOf(ClientAuthenticationMethod.PrivateKeyJwt, keyMaterial), "flow-1", [], OptionsNaming(keyId),
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefusedBeforeAnything(result, ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier, observations);
    }


    /// <summary>
    /// The refresh of a <c>private_key_jwt</c> registration whose options name an empty or white-space key identifier
    /// answers the typed <see cref="ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier"/> refusal
    /// before it resolves metadata or sends anything.
    /// </summary>
    /// <param name="keyId">The key identifier naming none.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    public async Task RefreshRefusesAKeyIdentifierNamingNoneBeforeSending(string keyId)
    {
        var observations = new FlowObservations();
        var client = new OAuthClient(CreateInfrastructure(observations));
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        var result = await client.AuthCode.RefreshAsync(
            RegistrationOf(ClientAuthenticationMethod.PrivateKeyJwt, keyMaterial),
            new RefreshTokenRequest { ClientId = ClientId, RefreshToken = "refresh-token-opaque" },
            [],
            OptionsNaming(keyId),
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefusedBeforeAnything(result, ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier, observations);
    }


    /// <summary>
    /// The client credentials grant of a <c>private_key_jwt</c> registration whose options name an empty or white-space
    /// key identifier answers the typed <see cref="ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier"/>
    /// refusal before it resolves metadata or sends anything.
    /// </summary>
    /// <param name="keyId">The key identifier naming none.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    public async Task ClientCredentialsRefusesAKeyIdentifierNamingNoneBeforeSending(string keyId)
    {
        var observations = new FlowObservations();
        var client = new OAuthClient(CreateInfrastructure(observations));
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        var result = await client.ClientCredentials.RequestTokenAsync(
            RegistrationOf(ClientAuthenticationMethod.PrivateKeyJwt, keyMaterial), null, null, [], OptionsNaming(keyId),
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertRefusedBeforeAnything(result, ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier, observations);
    }


    /// <summary>
    /// The same client credentials grant under options naming the key identifier reaches the token endpoint, and the
    /// assertion it presents verifies under the registration's public key: the recording transport observes a request
    /// the refusals above never make.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsUnderANamedKeyIdentifierReachesTheTokenEndpoint()
    {
        var observations = new FlowObservations();
        var client = new OAuthClient(CreateInfrastructure(observations));
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        var reached = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await client.ClientCredentials.RequestTokenAsync(
                RegistrationOf(ClientAuthenticationMethod.PrivateKeyJwt, keyMaterial), null, null, [], OptionsNaming(SigningKeyId),
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(TransportReachedMessage, reached.Message);
        Assert.HasCount(1, observations.SentAssertions, "The grant sends one request carrying one client assertion.");

        var verified = await Jws.VerifyAsync(
            observations.SentAssertions[0], TestSetup.Base64UrlDecoder, Pool, publicKey, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified, "The assertion is signed under the registration's own key.");
    }


    /// <summary>
    /// An ID-JAG mint under a registration naming a method that presents no client assertion is refused, typed
    /// (<see cref="ClientAssertionCredentialRefusalReason.MethodPresentsNoAssertion"/>), before it resolves metadata or sends
    /// anything, although the registration carries a key the assertion could be signed with.
    /// </summary>
    [TestMethod]
    public async Task MintRefusesARegistrationWhoseMethodPresentsNoAssertion()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;
        var observations = new FlowObservations();

        var result = await MintAsync(
            RegistrationOf(ClientAuthenticationMethod.ClientSecretBasic, keyMaterial), OptionsNaming(SigningKeyId), observations)
            .ConfigureAwait(false);

        var refusal = AssertIdJagRefusedBeforeAnything(result, ClientAssertionCredentialRefusalReason.MethodPresentsNoAssertion, observations);
        Assert.AreEqual<ClientAuthenticationMethod?>(ClientAuthenticationMethod.ClientSecretBasic, refusal.Method, "The refusal names the registration's method.");
    }


    /// <summary>
    /// An ID-JAG redeem under a registration naming a method that presents no client assertion is refused, typed
    /// (<see cref="ClientAssertionCredentialRefusalReason.MethodPresentsNoAssertion"/>), before it resolves metadata or sends
    /// anything, although the registration carries a key the assertion could be signed with.
    /// </summary>
    [TestMethod]
    public async Task RedeemRefusesARegistrationWhoseMethodPresentsNoAssertion()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;
        var observations = new FlowObservations();

        var result = await RedeemAsync(
            RegistrationOf(ClientAuthenticationMethod.ClientSecretPost, keyMaterial), OptionsNaming(SigningKeyId), observations)
            .ConfigureAwait(false);

        var refusal = AssertIdJagRefusedBeforeAnything(result, ClientAssertionCredentialRefusalReason.MethodPresentsNoAssertion, observations);
        Assert.AreEqual<ClientAuthenticationMethod?>(ClientAuthenticationMethod.ClientSecretPost, refusal.Method, "The refusal names the registration's method.");
    }


    /// <summary>
    /// The methods no assertion family classifies, each a row of its own: <c>attest_jwt_client_auth</c>, <c>spiffe_jwt</c> and
    /// <see cref="ApplicationDefinedMethod"/>.
    /// </summary>
    /// <returns>The methods.</returns>
    private static IEnumerable<object[]> MethodsNoFamilyClassifies()
    {
        yield return [ClientAuthenticationMethod.AttestJwtClientAuth];
        yield return [ClientAuthenticationMethod.SpiffeJwt];
        yield return [ApplicationDefinedMethod];
    }


    /// <summary>
    /// An ID-JAG mint and redeem under a registration naming a method no assertion family classifies - attestation-based,
    /// SPIFFE, or one an application defined - are refused, typed
    /// (<see cref="ClientAssertionCredentialRefusalReason.MethodNotSupported"/>), before they resolve metadata or send anything:
    /// the refusal never records such a method as one known to present no assertion.
    /// </summary>
    /// <param name="method">The registration's method, one of <see cref="MethodsNoFamilyClassifies"/>.</param>
    [TestMethod]
    [DynamicData(nameof(MethodsNoFamilyClassifies))]
    public async Task MintAndRedeemRefuseARegistrationWhoseMethodNoFamilyClassifies(ClientAuthenticationMethod method)
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;
        var mintObservations = new FlowObservations();

        var minted = await MintAsync(RegistrationOf(method, keyMaterial), OptionsNaming(SigningKeyId), mintObservations)
            .ConfigureAwait(false);

        var mintRefusal = AssertIdJagRefusedBeforeAnything(minted, ClientAssertionCredentialRefusalReason.MethodNotSupported, mintObservations);
        Assert.AreEqual<ClientAuthenticationMethod?>(method, mintRefusal.Method, "The refusal names the registration's method.");

        var redeemObservations = new FlowObservations();

        var redeemed = await RedeemAsync(RegistrationOf(method, keyMaterial), OptionsNaming(SigningKeyId), redeemObservations)
            .ConfigureAwait(false);

        var redeemRefusal = AssertIdJagRefusedBeforeAnything(redeemed, ClientAssertionCredentialRefusalReason.MethodNotSupported, redeemObservations);
        Assert.AreEqual<ClientAuthenticationMethod?>(method, redeemRefusal.Method, "The refusal names the registration's method.");
        Assert.DoesNotContain("presents no client assertion", redeemRefusal.Describe(), "The description concludes nothing about an assertion.");
    }


    /// <summary>
    /// An ID-JAG mint under a <c>private_key_jwt</c> registration whose options name an empty or white-space key
    /// identifier is refused, typed (<see cref="ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier"/>),
    /// before it resolves metadata or sends anything.
    /// </summary>
    /// <param name="keyId">The key identifier naming none.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    public async Task MintRefusesAKeyIdentifierNamingNone(string keyId)
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;
        var observations = new FlowObservations();

        var result = await MintAsync(
            RegistrationOf(ClientAuthenticationMethod.PrivateKeyJwt, keyMaterial), OptionsNaming(keyId), observations)
            .ConfigureAwait(false);

        _ = AssertIdJagRefusedBeforeAnything(result, ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier, observations);
    }


    /// <summary>
    /// An ID-JAG redeem under a <c>private_key_jwt</c> registration whose options name an empty or white-space key
    /// identifier is refused, typed (<see cref="ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier"/>),
    /// before it resolves metadata or sends anything.
    /// </summary>
    /// <param name="keyId">The key identifier naming none.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    public async Task RedeemRefusesAKeyIdentifierNamingNone(string keyId)
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;
        var observations = new FlowObservations();

        var result = await RedeemAsync(
            RegistrationOf(ClientAuthenticationMethod.PrivateKeyJwt, keyMaterial), OptionsNaming(keyId), observations)
            .ConfigureAwait(false);

        _ = AssertIdJagRefusedBeforeAnything(result, ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier, observations);
    }


    /// <summary>
    /// An ID-JAG mint under a <c>client_secret_jwt</c> registration whose secret is shorter than HMAC SHA-256's output is
    /// refused, typed (<see cref="ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput"/>, RFC 7518
    /// Section 3.2), carrying the octets judged, before it resolves metadata or sends anything.
    /// </summary>
    [TestMethod]
    public async Task MintRefusesAClientSecretShorterThanTheMac()
    {
        var secretMaterial = SecretMaterialOf(ShortClientSecret);
        using var unusedPublicKey = secretMaterial.PublicKey;
        using var secret = secretMaterial.PrivateKey;
        var observations = new FlowObservations();

        var result = await MintAsync(
            RegistrationOf(ClientAuthenticationMethod.ClientSecretJwt, secretMaterial), OptionsNaming(null), observations)
            .ConfigureAwait(false);

        var refusal = AssertIdJagRefusedBeforeAnything(result, ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput, observations);
        Assert.AreEqual(ShortClientSecret.Length, refusal.SecretOctets, "The refusal carries the octets the secret holds.");
        Assert.AreEqual(HMACSHA256.HashSizeInBytes, refusal.RequiredOctets, "The refusal carries the octets HMAC SHA-256's output holds.");
    }


    /// <summary>
    /// An ID-JAG redeem under a <c>client_secret_jwt</c> registration whose secret is shorter than HMAC SHA-256's output is
    /// refused, typed (<see cref="ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput"/>), before it
    /// resolves metadata or sends anything.
    /// </summary>
    [TestMethod]
    public async Task RedeemRefusesAClientSecretShorterThanTheMac()
    {
        var secretMaterial = SecretMaterialOf(ShortClientSecret);
        using var unusedPublicKey = secretMaterial.PublicKey;
        using var secret = secretMaterial.PrivateKey;
        var observations = new FlowObservations();

        var result = await RedeemAsync(
            RegistrationOf(ClientAuthenticationMethod.ClientSecretJwt, secretMaterial), OptionsNaming(null), observations)
            .ConfigureAwait(false);

        _ = AssertIdJagRefusedBeforeAnything(result, ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput, observations);
    }


    /// <summary>
    /// An ID-JAG mint and redeem under a <c>private_key_jwt</c> registration carrying no authentication key material are
    /// refused, typed (<see cref="ClientAssertionCredentialRefusalReason.RegistrationCarriesNoKey"/>), before either resolves
    /// metadata or sends anything: no key handed beside the registration stands in for the registration's own.
    /// </summary>
    [TestMethod]
    public async Task MintAndRedeemRefuseARegistrationCarryingNoKey()
    {
        var registration = RegistrationOf(ClientAuthenticationMethod.PrivateKeyJwt, null);
        var mintObservations = new FlowObservations();
        var redeemObservations = new FlowObservations();

        var minted = await MintAsync(registration, OptionsNaming(SigningKeyId), mintObservations).ConfigureAwait(false);
        var redeemed = await RedeemAsync(registration, OptionsNaming(SigningKeyId), redeemObservations).ConfigureAwait(false);

        _ = AssertIdJagRefusedBeforeAnything(minted, ClientAssertionCredentialRefusalReason.RegistrationCarriesNoKey, mintObservations);
        _ = AssertIdJagRefusedBeforeAnything(redeemed, ClientAssertionCredentialRefusalReason.RegistrationCarriesNoKey, redeemObservations);
    }


    /// <summary>
    /// An ID-JAG mint and redeem under a <c>private_key_jwt</c> registration reach the token endpoint with an assertion
    /// that verifies under the registration's public key: the credential is the registration's.
    /// </summary>
    [TestMethod]
    public async Task MintAndRedeemPresentAnAssertionSignedUnderTheRegistrationsKey()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;
        var registration = RegistrationOf(ClientAuthenticationMethod.PrivateKeyJwt, keyMaterial);
        var observations = new FlowObservations();

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await MintAsync(registration, OptionsNaming(SigningKeyId), observations).ConfigureAwait(false)).ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await RedeemAsync(registration, OptionsNaming(SigningKeyId), observations).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.HasCount(2, observations.SentAssertions, "The mint and the redeem each send one client assertion.");

        foreach(var assertion in observations.SentAssertions)
        {
            var verified = await Jws.VerifyAsync(
                assertion, TestSetup.Base64UrlDecoder, Pool, publicKey, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(verified, "Each assertion is signed under the registration's own key.");
        }
    }


    /// <summary>
    /// An ID-JAG mint and redeem under a <c>client_secret_jwt</c> registration reach the token endpoint with an assertion
    /// whose <c>alg</c> is <c>HS256</c> and whose signature is the platform's own HMAC SHA-256 of its signing input under the
    /// registration's secret (OpenID Connect Core 1.0 Section 9).
    /// </summary>
    [TestMethod]
    public async Task MintAndRedeemPresentAnAssertionMacedUnderTheRegistrationsSecret()
    {
        var secretMaterial = SecretMaterialOf(LongClientSecret);
        using var unusedPublicKey = secretMaterial.PublicKey;
        using var secret = secretMaterial.PrivateKey;
        var registration = RegistrationOf(ClientAuthenticationMethod.ClientSecretJwt, secretMaterial);
        var observations = new FlowObservations();

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await MintAsync(registration, OptionsNaming(null), observations).ConfigureAwait(false)).ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await RedeemAsync(registration, OptionsNaming(null), observations).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.HasCount(2, observations.SentAssertions, "The mint and the redeem each send one client assertion.");

        foreach(var assertion in observations.SentAssertions)
        {
            var parts = assertion.Split('.');
            using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0]));
            var expected = HMACSHA256.HashData(Encoding.UTF8.GetBytes(LongClientSecret), Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"));

            Assert.AreEqual(WellKnownJwaValues.Hs256, header.RootElement.GetProperty(WellKnownJwkMemberNames.Alg).GetString());
            Assert.IsTrue(CryptographicOperations.FixedTimeEquals(expected, Base64Url.DecodeFromChars(parts[2])),
                "The assertion is MACed under the registration's own secret.");
        }
    }


    /// <summary>
    /// Asserts a token-endpoint flow answered the typed refusal of its credential, rendered from the refusal, and neither
    /// resolved metadata, read flow state nor sent a request.
    /// </summary>
    /// <param name="result">The flow's result.</param>
    /// <param name="reason">The rule the refusal names.</param>
    /// <param name="observations">What the flow did before it answered.</param>
    private static void AssertRefusedBeforeAnything(
        AuthCodeFlowEndpointResult result, ClientAssertionCredentialRefusalReason reason, FlowObservations observations)
    {
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome);
        Assert.IsNotNull(result.ClientAssertionCredentialRefusal, "The result carries the typed refusal.");
        Assert.AreEqual(reason, result.ClientAssertionCredentialRefusal.Reason);
        Assert.AreEqual(result.ClientAssertionCredentialRefusal.Describe(), result.ErrorDescription);
        Assert.AreEqual(AuthCodeFlowRefusalOrigin.ClientJudgement, result.RefusalOrigin, "A credential refused before anything was sent is the library's own judgement.");
        AssertNothingHappened(observations);
    }


    /// <summary>
    /// Asserts an ID-JAG flow answered <see cref="OAuthClientAssertionRefused"/> naming the rule, its summary rendered from
    /// the refusal, and neither resolved metadata nor sent a request.
    /// </summary>
    /// <param name="result">The flow's result.</param>
    /// <param name="reason">The rule the refusal names.</param>
    /// <param name="observations">What the flow did before it answered.</param>
    /// <returns>The refusal the result carries.</returns>
    private static ClientAssertionCredentialRefusal AssertIdJagRefusedBeforeAnything(
        Result<TokenResponse, OAuthParseError> result, ClientAssertionCredentialRefusalReason reason, FlowObservations observations)
    {
        Assert.IsFalse(result.IsSuccess, "A credential the registration cannot form is refused.");
        var refused = Assert.IsInstanceOfType<OAuthClientAssertionRefused>(result.Error);
        Assert.AreEqual(reason, refused.Refusal.Reason);
        Assert.AreEqual(refused.Refusal.Describe(), refused.Support.Summary);
        AssertNothingHappened(observations);

        return refused.Refusal;
    }


    /// <summary>Asserts the flow neither resolved metadata, read flow state nor sent a request.</summary>
    /// <param name="observations">What the flow did before it answered.</param>
    private static void AssertNothingHappened(FlowObservations observations)
    {
        Assert.AreEqual(0, observations.MetadataResolutions, "The refusal precedes the metadata resolution.");
        Assert.AreEqual(0, observations.StateReads, "The refusal precedes the flow state's read.");
        Assert.IsEmpty(observations.SentAssertions, "The refusal precedes any request.");
    }


    /// <summary>Mints an ID-JAG under the registration over the recording transport.</summary>
    /// <param name="registration">The registration naming the method and carrying the key.</param>
    /// <param name="clientAssertion">The client assertion's inputs.</param>
    /// <param name="observations">What the flow does.</param>
    /// <returns>The mint's result.</returns>
    private ValueTask<Result<TokenResponse, OAuthParseError>> MintAsync(
        ClientRegistration registration, ClientAssertionOptions clientAssertion, FlowObservations observations) =>
        new OAuthClient(CreateInfrastructure(observations)).IdJag.MintAsync(
            registration,
            new IdJagMintOptions
            {
                Audience = "https://resource-as.example.com/",
                SubjectToken = "subject-token-opaque",
                SubjectTokenType = TokenType.IdToken,
                ClientAssertion = clientAssertion
            },
            TestContext.CancellationToken);


    /// <summary>Redeems an ID-JAG under the registration over the recording transport.</summary>
    /// <param name="registration">The registration naming the method and carrying the key.</param>
    /// <param name="clientAssertion">The client assertion's inputs.</param>
    /// <param name="observations">What the flow does.</param>
    /// <returns>The redeem's result.</returns>
    private ValueTask<Result<TokenResponse, OAuthParseError>> RedeemAsync(
        ClientRegistration registration, ClientAssertionOptions clientAssertion, FlowObservations observations) =>
        new OAuthClient(CreateInfrastructure(observations)).IdJag.RedeemAsync(
            registration,
            new IdJagRedeemOptions
            {
                Assertion = "id-jag-assertion-opaque",
                ClientAssertion = clientAssertion
            },
            TestContext.CancellationToken);


    /// <summary>
    /// The client infrastructure over a transport that records every metadata resolution, flow-state read and request and
    /// throws once a request reaches it, so a flow that sends is observed and never answered.
    /// </summary>
    /// <param name="observations">The record the transport writes.</param>
    /// <returns>The infrastructure.</returns>
    private OAuthClientInfrastructure CreateInfrastructure(FlowObservations observations) =>
        OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, fields, headers, context, ct) =>
            {
                observations.SentAssertions.Add(fields.First(field => OAuthRequestParameterNames.IsClientAssertion(field.Key)).Value);

                throw new InvalidOperationException(TransportReachedMessage);
            },
            saveStateAsync: (state, context, ct) => ValueTask.CompletedTask,
            loadStateAsync: (flowId, context, ct) =>
            {
                observations.StateReads++;

                return ValueTask.FromResult<FlowState?>(null);
            },
            loadStateByRequestUriAsync: (requestUri, context, ct) => ValueTask.FromResult<FlowState?>(null),
            parseParResponseAsync: response => throw new NotImplementedException("No pushed request is answered."),
            parseTokenResponseAsync: (response, receivedAt) => throw new NotImplementedException("No token response is answered."),
            parseRegistrationResponseAsync: (body, ct) => throw new NotImplementedException("No registration is answered."),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
            {
                observations.MetadataResolutions++;

                return ValueTask.FromResult<AuthorizationServerMetadataResolution>(new AuthorizationServerMetadataResolved
                {
                    MetadataLocation = WellKnownPaths.OAuthAuthorizationServer.ComputeUri(Issuer.OriginalString),
                    Metadata = new AuthorizationServerMetadata
                    {
                        Issuer = Issuer,
                        AuthorizationEndpoint = new Uri("https://as.example.com/authorize"),
                        TokenEndpoint = TokenEndpoint
                    }
                });
            },
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: Pool,
            timeProvider: TimeProvider,
            fillEntropy: ClientEntropy,
            generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, ClientEntropy, Pool));


    /// <summary>A registration naming a method and carrying its key material, or none.</summary>
    /// <param name="method">The method.</param>
    /// <param name="keyMaterial">The key material, the private half the key or the secret; or <see langword="null"/> for none.</param>
    /// <returns>The registration.</returns>
    private static ClientRegistration RegistrationOf(
        ClientAuthenticationMethod method,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>? keyMaterial) =>
        new()
        {
            ClientId = new ClientId(ClientId),
            AuthorizationServerIssuer = Issuer,
            AuthenticationMethod = method,
            AuthenticationKeyMaterial = keyMaterial,
            Profile = PolicyProfile.Rfc6749WithPkce
        };


    /// <summary>Assertion options naming a key identifier, or none, under this class's serializers.</summary>
    /// <param name="keyId">The key identifier, or <see langword="null"/> for none.</param>
    /// <returns>The options.</returns>
    private static ClientAssertionOptions OptionsNaming(string? keyId) =>
        new()
        {
            SigningKeyId = keyId,
            HeaderSerializer = HeaderSerializer,
            PayloadSerializer = PayloadSerializer
        };


    /// <summary>
    /// A client secret's octets as the library carries one, untagged, paired with an unread public half, in pooled memory
    /// the caller disposes.
    /// </summary>
    /// <param name="secret">The secret.</param>
    /// <returns>The key material.</returns>
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> SecretMaterialOf(string secret)
    {
        var octets = Encoding.UTF8.GetBytes(secret);
        var owner = Pool.Rent(octets.Length);
        octets.CopyTo(owner.Memory.Span);

        //Both halves are handed on to the material alone; on any path that does not hand them on, they are disposed here.
        var privateKey = new PrivateKeyMemory(owner, Tag.Empty);
        var publicKey = new PublicKeyMemory(Pool.Rent(1), Tag.Empty);

        try
        {
            var material = new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKey, privateKey);
            publicKey = null;
            privateKey = null;

            return material;
        }
        finally
        {
            publicKey?.Dispose();
            privateKey?.Dispose();
        }
    }


    /// <summary>What a flow did before it answered: the metadata it resolved, the flow state it read and the requests it sent.</summary>
    private sealed class FlowObservations
    {
        /// <summary>How many times the flow resolved authorization server metadata.</summary>
        public int MetadataResolutions { get; set; }

        /// <summary>How many times the flow read its flow state.</summary>
        public int StateReads { get; set; }

        /// <summary>The client assertion each request the flow sent carried.</summary>
        public List<string> SentAssertions { get; } = [];
    }
}

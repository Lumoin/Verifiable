using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Json;

/// <summary>
/// Proves the published converter registration, <see cref="JsonSerializerOptionsVerifiableExtensions.ApplyVerifiableDefaults(JsonSerializerOptions, BaseMemoryPool, bool)"/>,
/// matches what this library actually declares: complete, pool-parameterized, faithful on the types it
/// owns, and compatible with the OAuth registration a caller adds alongside it.
/// </summary>
[TestClass]
internal sealed class VerifiableJsonDefaultsTests
{
    /// <summary>
    /// A converter this library declares in a <c>Verifiable.Json</c> namespace but the published
    /// registration omits is a silent defect for every consumer: invisible at compile time, at run
    /// time, and in this repository's own tests, until a caller's document happens to need exactly
    /// that converter. Every non-abstract, non-generic-definition <see cref="JsonConverter"/> the
    /// <c>Verifiable.Json</c> assembly declares must therefore be present, by exact runtime type, in
    /// what <see cref="JsonSerializerOptionsVerifiableExtensions.ApplyVerifiableDefaults(JsonSerializerOptions, BaseMemoryPool, bool)"/>
    /// registers.
    /// </summary>
    [TestMethod]
    public void EveryDeclaredConverterIsRegisteredByApplyVerifiableDefaults()
    {
        var declaredConverterTypes = typeof(JsonSerializerOptionsVerifiableExtensions).Assembly
            .GetTypes()
            .Where(type =>
                !type.IsAbstract
                && !type.IsGenericTypeDefinition
                && type.Namespace is not null
                && type.Namespace.StartsWith("Verifiable.Json", StringComparison.Ordinal)
                && typeof(JsonConverter).IsAssignableFrom(type))
            .ToList();

        var registeredConverterTypes = new JsonSerializerOptions()
            .ApplyVerifiableDefaults(BaseMemoryPool.Shared)
            .Converters
            .Select(converter => converter.GetType())
            .ToHashSet();

        var missing = declaredConverterTypes
            .Where(type => type.FullName is not null && !registeredConverterTypes.Contains(type))
            .Select(type => type.FullName)
            .ToList();

        Assert.IsEmpty(missing, $"ApplyVerifiableDefaults omits converters this library declares: {string.Join(", ", missing)}");
    }


    /// <summary>
    /// Options built by <see cref="JsonSerializerOptionsVerifiableExtensions.ApplyVerifiableDefaults(JsonSerializerOptions, BaseMemoryPool, bool)"/>
    /// accept <see cref="JsonSerializerOptions.MakeReadOnly()"/> from the caller immediately afterward:
    /// the registration sets <see cref="JsonSerializerOptions.TypeInfoResolver"/> itself, so freezing
    /// right after this call, rather than a process-wide default the caller could not vary its pool on,
    /// is a supported way to consume this method.
    /// </summary>
    [TestMethod]
    public void OptionsBuiltWithAPoolCanBeFrozenImmediatelyAfterRegistration()
    {
        var options = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);
        options.MakeReadOnly();

        Assert.IsTrue(options.IsReadOnly);
    }


    /// <summary>A did:key document with a scalar-string <c>@context</c>, the shape <c>DidDocumentConverter</c> and <c>JsonLdContextConverter</c> jointly handle.</summary>
    private const string DidDocumentFixtureJson =
        """
        {
          "@context": "https://www.w3.org/ns/did/v1",
          "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        }
        """;


    /// <summary>
    /// A DID document deserialized and re-serialized through options built by
    /// <see cref="JsonSerializerOptionsVerifiableExtensions.ApplyVerifiableDefaults(JsonSerializerOptions, BaseMemoryPool, bool)"/>
    /// reproduces the same JSON structure it was read from.
    /// </summary>
    [TestMethod]
    public void DidDocumentRoundTripsThroughPublishedDefaults()
    {
        var options = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);
        var (deserialized, reserialized) = JsonSerializationUtilities.PerformSerializationCycle<DidDocument>(DidDocumentFixtureJson, options);

        Assert.IsNotNull(deserialized);
        Assert.IsTrue(
            JsonSerializationUtilities.CompareJsonElements(DidDocumentFixtureJson, reserialized),
            $"DidDocument roundtrip through the published defaults changed structure. Reserialized: {reserialized}");
    }


    /// <summary>An unsecured credential whose <c>@context</c> mixes an IRI with an inline definition.</summary>
    private const string CredentialFixtureJson =
        """{"@context":["https://www.w3.org/ns/credentials/v2",{"@vocab":"https://example.com/"}],"type":["VerifiableCredential"],"issuer":"did:example:issuer","credentialSubject":{"id":"did:example:subject"}}""";


    /// <summary>
    /// A Verifiable Credential deserialized and re-serialized through options built by
    /// <see cref="JsonSerializerOptionsVerifiableExtensions.ApplyVerifiableDefaults(JsonSerializerOptions, BaseMemoryPool, bool)"/>
    /// reproduces the same JSON structure it was read from.
    /// </summary>
    [TestMethod]
    public void VerifiableCredentialRoundTripsThroughPublishedDefaults()
    {
        var options = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);
        var (deserialized, reserialized) = JsonSerializationUtilities.PerformSerializationCycle<VerifiableCredential>(CredentialFixtureJson, options);

        Assert.IsNotNull(deserialized);
        Assert.IsTrue(
            JsonSerializationUtilities.CompareJsonElements(CredentialFixtureJson, reserialized),
            $"VerifiableCredential roundtrip through the published defaults changed structure. Reserialized: {reserialized}");
    }


    /// <summary>Builds a single-key JWKS document with an EC public key, for the composition tests below.</summary>
    /// <returns>The JWKS document.</returns>
    private static JwksDocument CreateJwksFixture()
    {
        return new JwksDocument
        {
            Keys =
            [
                new JsonWebKey
                {
                    Kty = "EC",
                    Kid = "test-key-1",
                    Crv = "P-256",
                    X = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    Y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                }
            ]
        };
    }


    /// <summary>
    /// A JWKS document serializes its key array under the <c>keys</c> member
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">RFC 7517 §5</see> names — never under
    /// the declared CLR property name <c>Keys</c> — regardless of which registration builds the options or
    /// in which order: <see cref="JsonSerializerOptionsVerifiableExtensions.ApplyVerifiableDefaults(JsonSerializerOptions, BaseMemoryPool, bool)"/>
    /// alone, <see cref="JsonSerializerOptionsOAuthExtensions.ApplyOAuthDefaults(JsonSerializerOptions)"/>
    /// alone, Verifiable-then-OAuth, and OAuth-then-Verifiable. Each composition is read back with a plain
    /// <see cref="JsonDocument"/> reader, independent of either registration's typed model.
    /// </summary>
    [TestMethod]
    public void JwksDocumentSerializesIdenticallyUnderEveryCompositionOrder()
    {
        JwksDocument jwks = CreateJwksFixture();

        var verifiableOnly = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);
        var oauthOnly = new JsonSerializerOptions().ApplyOAuthDefaults();
        var verifiableThenOAuth = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared).ApplyOAuthDefaults();
        var oauthThenVerifiable = new JsonSerializerOptions().ApplyOAuthDefaults().ApplyVerifiableDefaults(BaseMemoryPool.Shared);

        AssertCarriesRfc7517KeysMember(JsonSerializerExtensions.Serialize(jwks, verifiableOnly), "Verifiable alone");
        AssertCarriesRfc7517KeysMember(JsonSerializerExtensions.Serialize(jwks, oauthOnly), "OAuth alone");
        AssertCarriesRfc7517KeysMember(JsonSerializerExtensions.Serialize(jwks, verifiableThenOAuth), "Verifiable-then-OAuth");
        AssertCarriesRfc7517KeysMember(JsonSerializerExtensions.Serialize(jwks, oauthThenVerifiable), "OAuth-then-Verifiable");
    }


    /// <summary>
    /// Asserts, with a plain <see cref="JsonDocument"/> reader independent of any typed model, that
    /// <paramref name="jwksJson"/> carries a top-level <c>keys</c> member and no top-level <c>Keys</c>
    /// member, per <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5">RFC 7517 §5</see>.
    /// </summary>
    /// <param name="jwksJson">The serialized JWKS document.</param>
    /// <param name="composition">The registration composition under test, folded into the failure message.</param>
    private static void AssertCarriesRfc7517KeysMember(string jwksJson, string composition)
    {
        using JsonDocument document = JsonDocument.Parse(jwksJson);

        Assert.IsTrue(document.RootElement.TryGetProperty("keys", out _), $"{composition}: JWKS is missing the RFC 7517 §5 'keys' member. JSON: {jwksJson}");
        Assert.IsFalse(document.RootElement.TryGetProperty("Keys", out _), $"{composition}: JWKS carries a 'Keys' member instead of the RFC 7517 §5 'keys' member. JSON: {jwksJson}");
    }


    /// <summary>
    /// <see cref="OidcDiscoveryDocument"/> serializes every declared member under its
    /// <see href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</see>
    /// / <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see> snake_case wire name when
    /// <see cref="JsonSerializerOptionsOAuthExtensions.ApplyOAuthDefaults(JsonSerializerOptions)"/> is the
    /// only registration applied, read with a plain <see cref="JsonDocument"/> reader.
    /// </summary>
    [TestMethod]
    public void OidcDiscoveryDocumentSerializesWithItsWireNamesUnderOAuthDefaultsAlone()
    {
        var document = new OidcDiscoveryDocument
        {
            Issuer = "https://issuer.example",
            AuthorizationEndpoint = new Uri("https://issuer.example/authorize"),
            TokenEndpoint = new Uri("https://issuer.example/token"),
            PushedAuthorizationRequestEndpoint = new Uri("https://issuer.example/par"),
            JwksUri = new Uri("https://issuer.example/jwks"),
            ResponseTypesSupported = ["code"],
            SubjectTypesSupported = ["public"],
            IdTokenSigningAlgValuesSupported = ["ES256"],
            CodeChallengeMethodsSupported = ["S256"],
            RequirePushedAuthorizationRequests = true,
            AuthorizationResponseIssParameterSupported = true,
            ClientIdMetadataDocumentSupported = true,
            DpopSigningAlgValuesSupported = ["ES256"]
        };

        string json = JsonSerializerExtensions.Serialize(document, new JsonSerializerOptions().ApplyOAuthDefaults());
        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement root = parsed.RootElement;

        string[] expectedWireNames =
        [
            "issuer", "authorization_endpoint", "token_endpoint",
            "pushed_authorization_request_endpoint", "jwks_uri",
            "response_types_supported", "subject_types_supported",
            "id_token_signing_alg_values_supported", "code_challenge_methods_supported",
            "require_pushed_authorization_requests", "authorization_response_iss_parameter_supported",
            "client_id_metadata_document_supported", "dpop_signing_alg_values_supported"
        ];

        foreach(string name in expectedWireNames)
        {
            Assert.IsTrue(root.TryGetProperty(name, out _), $"OidcDiscoveryDocument is missing the wire name '{name}'. JSON: {json}");
        }

        Assert.IsFalse(root.TryGetProperty("PushedAuthorizationRequestEndpoint", out _), $"OidcDiscoveryDocument carries a raw CLR member name instead of its wire name. JSON: {json}");
    }


    /// <summary>
    /// <see cref="ParServerResponse"/> serializes its members under the
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see> wire names
    /// <c>request_uri</c> and <c>expires_in</c> when
    /// <see cref="JsonSerializerOptionsOAuthExtensions.ApplyOAuthDefaults(JsonSerializerOptions)"/> is the
    /// only registration applied, read with a plain <see cref="JsonDocument"/> reader.
    /// </summary>
    [TestMethod]
    public void ParServerResponseSerializesWithRfc9126WireNamesUnderOAuthDefaultsAlone()
    {
        var response = new ParServerResponse
        {
            RequestUri = new Uri("urn:ietf:params:oauth:request_uri:example"),
            ExpiresIn = 60
        };

        string json = JsonSerializerExtensions.Serialize(response, new JsonSerializerOptions().ApplyOAuthDefaults());
        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement root = parsed.RootElement;

        Assert.IsTrue(root.TryGetProperty("request_uri", out _), $"ParServerResponse is missing the RFC 9126 §2.2 'request_uri' member. JSON: {json}");
        Assert.IsTrue(root.TryGetProperty("expires_in", out _), $"ParServerResponse is missing the RFC 9126 §2.2 'expires_in' member. JSON: {json}");
        Assert.IsFalse(root.TryGetProperty("RequestUri", out _), $"ParServerResponse carries the raw CLR member name 'RequestUri'. JSON: {json}");
        Assert.IsFalse(root.TryGetProperty("ExpiresIn", out _), $"ParServerResponse carries the raw CLR member name 'ExpiresIn'. JSON: {json}");
    }


    /// <summary>
    /// <see cref="TokenServerResponse"/> serializes its members under the
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see> wire names
    /// <c>access_token</c>, <c>token_type</c>, <c>expires_in</c>, and <c>refresh_token</c> when
    /// <see cref="JsonSerializerOptionsOAuthExtensions.ApplyOAuthDefaults(JsonSerializerOptions)"/> is the
    /// only registration applied, read with a plain <see cref="JsonDocument"/> reader.
    /// </summary>
    [TestMethod]
    public void TokenServerResponseSerializesWithRfc6749WireNamesUnderOAuthDefaultsAlone()
    {
        var response = new TokenServerResponse
        {
            AccessToken = "the-access-token",
            TokenType = "Bearer",
            ExpiresIn = 3600,
            RefreshToken = "the-refresh-token"
        };

        string json = JsonSerializerExtensions.Serialize(response, new JsonSerializerOptions().ApplyOAuthDefaults());
        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement root = parsed.RootElement;

        Assert.IsTrue(root.TryGetProperty("access_token", out _), $"TokenServerResponse is missing the RFC 6749 §5.1 'access_token' member. JSON: {json}");
        Assert.IsTrue(root.TryGetProperty("token_type", out _), $"TokenServerResponse is missing the RFC 6749 §5.1 'token_type' member. JSON: {json}");
        Assert.IsTrue(root.TryGetProperty("expires_in", out _), $"TokenServerResponse is missing the RFC 6749 §5.1 'expires_in' member. JSON: {json}");
        Assert.IsTrue(root.TryGetProperty("refresh_token", out _), $"TokenServerResponse is missing the RFC 6749 §5.1 'refresh_token' member. JSON: {json}");
        Assert.IsFalse(root.TryGetProperty("AccessToken", out _), $"TokenServerResponse carries the raw CLR member name 'AccessToken'. JSON: {json}");
    }


    /// <summary>
    /// <see cref="JsonSerializerOptionsOAuthExtensions.ApplyOAuthDefaults(JsonSerializerOptions)"/> refuses a
    /// <see cref="JsonSerializerOptions.PropertyNamingPolicy"/> it cannot guarantee an RFC-exact snake_case
    /// wire name from: only <see langword="null"/>, <see cref="JsonNamingPolicy.CamelCase"/>, and
    /// <see cref="JsonNamingPolicy.SnakeCaseLower"/> change solely case and word separators, so
    /// <see cref="JsonNamingPolicy.KebabCaseLower"/> throws <see cref="InvalidOperationException"/> rather
    /// than serialize <see cref="TokenServerResponse"/> under a wrong wire name.
    /// </summary>
    [TestMethod]
    public void ApplyOAuthDefaultsRejectsANamingPolicyItCannotConvertExactly()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.KebabCaseLower
        }.ApplyOAuthDefaults();

        var response = new TokenServerResponse
        {
            AccessToken = "the-access-token",
            TokenType = "Bearer",
            ExpiresIn = 3600
        };

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => JsonSerializerExtensions.Serialize(response, options));
    }


    /// <summary>Builds a signing JWK for <paramref name="publicKey"/> through the library's own converter, then layers <c>kid</c> and <c>use</c> on top.</summary>
    /// <param name="publicKey">The public key to project as a JWK.</param>
    /// <param name="kid">The key identifier to assign.</param>
    /// <returns>The built key.</returns>
    private static JsonWebKey BuildSigningJwk(PublicKeyMemory publicKey, string kid)
    {
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            publicKey.Tag.Get<CryptoAlgorithm>(),
            publicKey.Tag.Get<Purpose>(),
            publicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);
        jwk.Kid = kid;
        jwk.Use = WellKnownJwkValues.UseSig;

        return jwk;
    }


    /// <summary>
    /// Serializes and deserializes <paramref name="builtKey"/>, wrapped in a single-key
    /// <see cref="JwksDocument"/>, through every composition <see cref="JwksDocumentSerializesIdenticallyUnderEveryCompositionOrder"/>
    /// enumerates, and asserts THE RULE: the deserialized key's ten typed accessors return the built
    /// key's values, the deserialized key <see cref="JsonWebKey.Equals(JsonWebKey?)"/>s the built one,
    /// and the documents' key arrays are equal element by element.
    /// </summary>
    /// <param name="builtKey">The key built by the library's own converter.</param>
    private static void AssertKeyRoundTripsAcrossCompositions(JsonWebKey builtKey)
    {
        JwksDocument jwks = new() { Keys = [builtKey] };

        var verifiableOnly = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);
        var oauthOnly = new JsonSerializerOptions().ApplyOAuthDefaults();
        var verifiableThenOAuth = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared).ApplyOAuthDefaults();
        var oauthThenVerifiable = new JsonSerializerOptions().ApplyOAuthDefaults().ApplyVerifiableDefaults(BaseMemoryPool.Shared);

        AssertKeyRoundTrips(builtKey, jwks, verifiableOnly, "Verifiable alone");
        AssertKeyRoundTrips(builtKey, jwks, oauthOnly, "OAuth alone");
        AssertKeyRoundTrips(builtKey, jwks, verifiableThenOAuth, "Verifiable-then-OAuth");
        AssertKeyRoundTrips(builtKey, jwks, oauthThenVerifiable, "OAuth-then-Verifiable");
    }


    /// <summary>Asserts THE RULE for one composition: see <see cref="AssertKeyRoundTripsAcrossCompositions(JsonWebKey)"/>.</summary>
    /// <param name="builtKey">The key built by the library's own converter.</param>
    /// <param name="jwks">The single-key document wrapping <paramref name="builtKey"/>.</param>
    /// <param name="options">The composition under test.</param>
    /// <param name="composition">The composition's name, folded into every failure message.</param>
    private static void AssertKeyRoundTrips(JsonWebKey builtKey, JwksDocument jwks, JsonSerializerOptions options, string composition)
    {
        string json = JsonSerializerExtensions.Serialize(jwks, options);
        JwksDocument? roundTripped = JsonSerializerExtensions.Deserialize<JwksDocument>(json, options);

        Assert.IsNotNull(roundTripped, $"{composition}: JWKS failed to deserialize. JSON: {json}");
        Assert.HasCount(1, roundTripped.Keys, $"{composition}: JWKS key count changed. JSON: {json}");

        JsonWebKey roundTrippedKey = roundTripped.Keys[0];

        Assert.AreEqual(builtKey.Kty, roundTrippedKey.Kty, $"{composition}: kty mismatch. JSON: {json}");
        Assert.AreEqual(builtKey.Alg, roundTrippedKey.Alg, $"{composition}: alg mismatch. JSON: {json}");
        Assert.AreEqual(builtKey.Use, roundTrippedKey.Use, $"{composition}: use mismatch. JSON: {json}");
        Assert.AreEqual(builtKey.Kid, roundTrippedKey.Kid, $"{composition}: kid mismatch. JSON: {json}");
        Assert.AreEqual(builtKey.Crv, roundTrippedKey.Crv, $"{composition}: crv mismatch. JSON: {json}");
        Assert.AreEqual(builtKey.X, roundTrippedKey.X, $"{composition}: x mismatch. JSON: {json}");
        Assert.AreEqual(builtKey.Y, roundTrippedKey.Y, $"{composition}: y mismatch. JSON: {json}");
        Assert.AreEqual(builtKey.N, roundTrippedKey.N, $"{composition}: n mismatch. JSON: {json}");
        Assert.AreEqual(builtKey.E, roundTrippedKey.E, $"{composition}: e mismatch. JSON: {json}");
        Assert.AreEqual(builtKey.Pub, roundTrippedKey.Pub, $"{composition}: pub mismatch. JSON: {json}");
        Assert.AreEqual(builtKey, roundTrippedKey, $"{composition}: deserialized key does not equal the built key. JSON: {json}");
        Assert.AreEqual(jwks, roundTripped, $"{composition}: deserialized document does not equal the built document. JSON: {json}");
    }


    /// <summary>
    /// An EC P-256 public key built by <see cref="CryptoFormatConversions.DefaultAlgorithmToJwkConverter"/>
    /// deserializes to a key holding the same CLR values as the built key, in every composition.
    /// </summary>
    [TestMethod]
    public void DeserializedEcKeyMatchesBuiltKeyInEveryComposition()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        AssertKeyRoundTripsAcrossCompositions(BuildSigningJwk(publicKey, "ec-key-1"));
    }


    /// <summary>
    /// An RSA public key built by <see cref="CryptoFormatConversions.DefaultAlgorithmToJwkConverter"/>
    /// deserializes to a key holding the same CLR values as the built key, in every composition.
    /// </summary>
    [TestMethod]
    public void DeserializedRsaKeyMatchesBuiltKeyInEveryComposition()
    {
        var keyPair = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        AssertKeyRoundTripsAcrossCompositions(BuildSigningJwk(publicKey, "rsa-key-1"));
    }


    /// <summary>
    /// An Ed25519 (OKP) public key built by <see cref="CryptoFormatConversions.DefaultAlgorithmToJwkConverter"/>
    /// deserializes to a key holding the same CLR values as the built key, in every composition.
    /// </summary>
    [TestMethod]
    public void DeserializedOkpKeyMatchesBuiltKeyInEveryComposition()
    {
        var keyPair = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        AssertKeyRoundTripsAcrossCompositions(BuildSigningJwk(publicKey, "okp-key-1"));
    }


    /// <summary>
    /// A <c>kid</c> whose text is an ISO 8601 date, and one that is all digits, round-trip as the
    /// same <see cref="string"/> they were assigned — RFC 7517 §4.5 defines <c>kid</c> as an opaque
    /// string identifier, never a value subject to date or number sniffing.
    /// </summary>
    [TestMethod]
    public void KidTextThatLooksLikeADateOrAllDigitsRoundTripsAsThePlainString()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);

        JsonWebKey isoDateKeyBuilt = BuildSigningJwk(publicKey, "2026-09-19");
        JsonWebKey allDigitsKeyBuilt = BuildSigningJwk(publicKey, "20260919");

        JsonWebKey? isoDateKeyRoundTripped = JsonSerializerExtensions.Deserialize<JsonWebKey>(
            JsonSerializerExtensions.Serialize(isoDateKeyBuilt, options), options);
        JsonWebKey? allDigitsKeyRoundTripped = JsonSerializerExtensions.Deserialize<JsonWebKey>(
            JsonSerializerExtensions.Serialize(allDigitsKeyBuilt, options), options);

        Assert.AreEqual("2026-09-19", isoDateKeyRoundTripped?.Kid, "An ISO 8601 kid must round-trip as the same string, not a parsed date.");
        Assert.AreEqual("20260919", allDigitsKeyRoundTripped?.Kid, "An all-digit kid must round-trip as the same string, not a parsed date.");
    }


    /// <summary>
    /// A JWK object that repeats a member name is rejected with <see cref="JsonException"/>, per
    /// RFC 7517 §4: "The member names within a JWK MUST be unique; JWK parsers MUST either reject
    /// JWKs with duplicate member names or use a JSON parser that returns only the lexically last
    /// duplicate member name."
    /// </summary>
    [TestMethod]
    public void JsonWebKeyWithADuplicateMemberNameIsRejected()
    {
        var options = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);
        const string duplicateMemberJson = """{"kty":"EC","kty":"RSA"}""";

        _ = Assert.ThrowsExactly<JsonException>(() => JsonSerializerExtensions.Deserialize<JsonWebKey>(duplicateMemberJson, options));
    }


    /// <summary>
    /// The serialized bytes of <see cref="CreateJwksFixture"/> are unchanged by the registration of
    /// the <c>JsonWebKey</c> converter, in every composition: member names verbatim in insertion
    /// order, no member value the fixture carries is <see langword="null"/>, and the escaping is the
    /// same encoder the options already carried.
    /// </summary>
    [TestMethod]
    public void JwksFixtureSerializesToTheSameBytesTheTipProduces()
    {
        JwksDocument jwks = CreateJwksFixture();

        var verifiableOnly = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);
        var oauthOnly = new JsonSerializerOptions().ApplyOAuthDefaults();
        var verifiableThenOAuth = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared).ApplyOAuthDefaults();
        var oauthThenVerifiable = new JsonSerializerOptions().ApplyOAuthDefaults().ApplyVerifiableDefaults(BaseMemoryPool.Shared);

        const string expectedVerifiableOnly =
            """{"keys":[{"kty":"EC","kid":"test-key-1","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}""";
        const string expectedOauthOnly =
            """{"keys":[{"kty":"EC","kid":"test-key-1","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}""";

        Assert.AreEqual(expectedVerifiableOnly, JsonSerializerExtensions.Serialize(jwks, verifiableOnly), "Verifiable alone changed the pinned bytes.");
        Assert.AreEqual(expectedOauthOnly, JsonSerializerExtensions.Serialize(jwks, oauthOnly), "OAuth alone changed the pinned bytes.");
        Assert.AreEqual(expectedVerifiableOnly, JsonSerializerExtensions.Serialize(jwks, verifiableThenOAuth), "Verifiable-then-OAuth changed the pinned bytes.");
        Assert.AreEqual(expectedVerifiableOnly, JsonSerializerExtensions.Serialize(jwks, oauthThenVerifiable), "OAuth-then-Verifiable changed the pinned bytes.");
    }


    /// <summary>
    /// Non-string member shapes on read: <c>key_ops</c> and <c>x5c</c> arrays decode to
    /// <see cref="List{Object}"/> of <see cref="string"/>; <c>true</c>/<c>false</c> decode to
    /// <see cref="bool"/>; an integral number decodes to <see cref="long"/> and a fractional one to
    /// <see cref="decimal"/>; a nested object decodes to <see cref="Dictionary{String, Object}"/>; a
    /// <see langword="null"/> value decodes to <see langword="null"/>; and a member the library
    /// declares no typed accessor for is kept rather than dropped, per RFC 7517 §4: "Additional
    /// members can be present in the JWK; if not understood by implementations encountering them,
    /// they MUST be ignored."
    /// </summary>
    [TestMethod]
    public void NonStringMemberShapesDecodeToTheirDocumentedClrTypes()
    {
        const string json =
            """
            {
              "kty": "oct",
              "key_ops": ["sign", "verify"],
              "x5c": ["MIIB1234", "MIIC5678"],
              "ext": true,
              "count": 3,
              "ratio": 1.5,
              "nested": {"inner": "value"},
              "note": null,
              "x-vendor-extension": "kept"
            }
            """;

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);
        JsonWebKey? jwk = JsonSerializerExtensions.Deserialize<JsonWebKey>(json, options);

        Assert.IsNotNull(jwk);
        _ = Assert.IsInstanceOfType<List<object>>(jwk[WellKnownJwkMemberNames.KeyOps]);
        Assert.IsTrue(((List<object>)jwk[WellKnownJwkMemberNames.KeyOps]).All(item => item is string), "key_ops elements must be strings.");
        _ = Assert.IsInstanceOfType<List<object>>(jwk[WellKnownJwkMemberNames.X5c]);
        Assert.IsTrue(((List<object>)jwk[WellKnownJwkMemberNames.X5c]).All(item => item is string), "x5c elements must be strings.");
        _ = Assert.IsInstanceOfType<bool>(jwk["ext"]);
        Assert.IsTrue((bool)jwk["ext"]);
        _ = Assert.IsInstanceOfType<long>(jwk["count"]);
        Assert.AreEqual(3L, jwk["count"]);
        _ = Assert.IsInstanceOfType<decimal>(jwk["ratio"]);
        Assert.AreEqual(1.5m, jwk["ratio"]);
        _ = Assert.IsInstanceOfType<Dictionary<string, object>>(jwk["nested"]);
        Assert.IsNull(jwk["note"]);
        Assert.AreEqual("kept", jwk["x-vendor-extension"]);
    }


    /// <summary>
    /// A JSON array, string, or number where a JWK object is expected is a <see cref="JsonException"/>,
    /// and JSON <see langword="null"/> for a <see cref="JsonWebKey"/> reads as <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public void ANonObjectTokenForAJsonWebKeyIsRejectedAndNullReadsAsNull()
    {
        var options = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);

        _ = Assert.ThrowsExactly<JsonException>(() => JsonSerializerExtensions.Deserialize<JsonWebKey>("[]", options));
        _ = Assert.ThrowsExactly<JsonException>(() => JsonSerializerExtensions.Deserialize<JsonWebKey>("\"not-a-jwk\"", options));
        _ = Assert.ThrowsExactly<JsonException>(() => JsonSerializerExtensions.Deserialize<JsonWebKey>("42", options));

        Assert.IsNull(JsonSerializerExtensions.Deserialize<JsonWebKey>("null", options));
    }


    /// <summary>
    /// An additional JWK member whose value is a sequence writes the same JSON array whichever
    /// concrete list shape holds it: <see cref="string"/>[], <see cref="List{T}"/> of
    /// <see cref="string"/>, and <see cref="IReadOnlyList{T}"/> of <see cref="string"/> backed by an
    /// array write the identical bytes; a <see cref="List{T}"/> of <see cref="long"/> (the converter's
    /// only whole-number shape on both read and write) and a <see cref="List{T}"/> of
    /// <see cref="object"/> mixing a string and a nested
    /// dictionary each write as the JSON array of their own elements. RFC 7517 §4
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4">RFC 7517 §4</see>) lets an
    /// additional member's value take any JSON shape.
    /// </summary>
    [TestMethod]
    public void AdditionalMemberSequencesWriteIdenticalArraysAcrossListShapes()
    {
        var options = new JsonSerializerOptions().ApplyVerifiableDefaults(BaseMemoryPool.Shared);
        var jwk = new JsonWebKey
        {
            [WellKnownJwkMemberNames.Kty] = "oct"
        };
        string[] backingArray = ["a", "b"];
        jwk["x-string-array"] = backingArray;
        jwk["x-string-list"] = new List<string> { "a", "b" };
        jwk["x-string-readonly-list"] = Array.AsReadOnly(backingArray);
        jwk["x-long-list"] = new List<long> { 1L, 2L, 3L };
        jwk["x-mixed-list"] = new List<object> { "text", new Dictionary<string, object> { ["inner"] = "value" } };

        string json = JsonSerializerExtensions.Serialize(jwk, options);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        string stringArrayJson = root.GetProperty("x-string-array").GetRawText();
        string stringListJson = root.GetProperty("x-string-list").GetRawText();
        string stringReadOnlyListJson = root.GetProperty("x-string-readonly-list").GetRawText();

        Assert.AreEqual(/*lang=json,strict*/ """["a","b"]""", stringArrayJson);
        Assert.AreEqual(stringArrayJson, stringListJson);
        Assert.AreEqual(stringArrayJson, stringReadOnlyListJson);
        Assert.AreEqual(/*lang=json,strict*/ """[1,2,3]""", root.GetProperty("x-long-list").GetRawText());
        Assert.AreEqual(/*lang=json,strict*/ """["text",{"inner":"value"}]""", root.GetProperty("x-mixed-list").GetRawText());
    }
}

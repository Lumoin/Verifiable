using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the <c>private_key_jwt</c> client authentication assertion signer
/// (<see cref="ClientAssertionSigning"/>) per RFC 7523 §2.2/§3 — the confidential-client
/// authentication an ID-JAG client uses at the mint and redeem token endpoints (§9.1).
/// </summary>
[TestClass]
internal sealed class ClientAssertionSigningTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://client.example.com";
    private const string TokenEndpoint = "https://as.example.com/token";
    private const string SigningKeyId = "client-key-1";

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// RFC 7523 §3: the signed <c>client_assertion</c> carries <c>iss</c>==<c>sub</c>==client_id,
    /// <c>aud</c> the value the caller names (here a token endpoint URL), a single JSON string, a
    /// unique <c>jti</c>, and an <c>exp</c>; the protected header carries the <c>kid</c> the AS
    /// resolves the key by; and the signature verifies against the client's public key.
    /// </summary>
    [TestMethod]
    public async Task SignsVerifiablePrivateKeyJwtClientAssertion()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string assertion = await ClientAssertionSigning.SignAsync(
            ClientId,
            TokenEndpoint,
            jti: "assertion-jti-1",
            issuedAt: now,
            expiresAt: now.AddMinutes(5),
            privateKey,
            SigningKeyId,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The signature verifies against the client's public key (the key the AS resolves by kid).
        bool isValid = await Jws.VerifyAsync(
            assertion, TestSetup.Base64UrlDecoder, Pool, publicKey, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isValid, "the client_assertion signature must verify against the client key.");

        string[] parts = assertion.Split('.');
        Assert.HasCount(3, parts);

        //§3 claims.
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(parts[1], Pool);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);
        JsonElement claims = payload.RootElement;
        Assert.AreEqual(ClientId, claims.GetProperty(WellKnownJwtClaimNames.Iss).GetString());
        Assert.AreEqual(ClientId, claims.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
        Assert.AreEqual(TokenEndpoint, claims.GetProperty(WellKnownJwtClaimNames.Aud).GetString());
        Assert.AreEqual("assertion-jti-1", claims.GetProperty(WellKnownJwtClaimNames.Jti).GetString());
        Assert.IsTrue(claims.TryGetProperty(WellKnownJwtClaimNames.Exp, out _), "exp is REQUIRED.");
        Assert.IsTrue(claims.TryGetProperty(WellKnownJwtClaimNames.Iat, out _));

        //The header carries the kid.
        byte[] headerBytes = SecurityEventTestJson.DecodeSegment(parts[0], Pool);
        using JsonDocument header = JsonDocument.Parse(headerBytes);
        Assert.AreEqual(SigningKeyId, header.RootElement.GetProperty(WellKnownJwkMemberNames.Kid).GetString());
    }


    /// <summary>
    /// A pin on the thirteen-argument
    /// <see cref="ClientAssertionSigning.SignAsync(string,string,string,DateTimeOffset,DateTimeOffset,PrivateKeyMemory,string,string,JwtHeaderSerializer,JwtPayloadSerializer,EncodeDelegate,BaseMemoryPool,CancellationToken)"/>
    /// overload: per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">rfc7523bis-11
    /// Section 4</see>, client authentication JWTs "SHOULD be explicitly typed by using the typ header
    /// parameter value client-authentication+jwt", and the overload writes exactly the <c>typ</c> value
    /// its caller names, never a value it derives itself; <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC
    /// 7519 Section 4.1.3</see>'s single-string <c>aud</c> shape and the signature hold under either
    /// <c>typ</c>. Which <c>typ</c> a registration chooses is proven over the wire by
    /// <see cref="AuthCodeClientAuthenticationTests.CodeExchangeAssertionFollowsTheRegistrationsAudienceAndTypeAsync"/>.
    /// </summary>
    [TestMethod]
    [DataRow("JWT")]
    [DataRow("client-authentication+jwt")]
    public async Task TypeHeaderIsTheValueTheCallerNames(string type)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string assertion = await ClientAssertionSigning.SignAsync(
            ClientId,
            TokenEndpoint,
            jti: "typed-assertion-jti-1",
            issuedAt: now,
            expiresAt: now.AddMinutes(5),
            privateKey,
            SigningKeyId,
            type,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await Jws.VerifyAsync(
            assertion, TestSetup.Base64UrlDecoder, Pool, publicKey, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isValid, "the client_assertion signature must verify against the client key.");

        string[] parts = assertion.Split('.');
        Assert.HasCount(3, parts);

        byte[] headerBytes = SecurityEventTestJson.DecodeSegment(parts[0], Pool);
        using JsonDocument header = JsonDocument.Parse(headerBytes);
        Assert.AreEqual(type, header.RootElement.GetProperty(WellKnownJoseHeaderNames.Typ).GetString());

        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(parts[1], Pool);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);
        JsonElement audience = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud);
        Assert.AreEqual(JsonValueKind.String, audience.ValueKind);
        Assert.AreEqual(TokenEndpoint, audience.GetString());
    }


    /// <summary>
    /// <c>client_secret_jwt</c> (OpenID Connect Core 1.0 §9): "The HMAC (Hash-based Message Authentication Code) is
    /// calculated using the octets of the UTF-8 representation of the client_secret as the shared key." The assertion's
    /// one composition, handed the secret's key (<see cref="ClientAssertionCredential.OfClientSecret"/>), writes a MAC equal to the
    /// platform's own HMAC of the signing input under the secret, recomputed here independently of the library for each of
    /// RFC 7518 §3.2's three algorithms; the header names the algorithm and the type and no <c>kid</c>; and the claims are
    /// RFC 7523 §3's, as the <c>private_key_jwt</c> assertion carries them.
    /// </summary>
    [TestMethod]
    [DataRow("HS256")]
    [DataRow("HS384")]
    [DataRow("HS512")]
    public async Task SignsAClientSecretJwtAssertionWhoseMacIsTheSecretsHmacOfItsSigningInput(string algorithm)
    {
        var secretOctets = Encoding.UTF8.GetBytes(LongClientSecret);
        using var secret = SecretOf(secretOctets);

        var key = ClientAssertionCredential.OfClientSecret(secret, algorithm);
        Assert.IsTrue(key.IsSuccess, "A secret of 64 octets keys every HMAC algorithm of RFC 7518 Section 3.2.");

        var now = TimeProvider.GetUtcNow();
        var assertion = await ClientAssertionSigning.SignAsync(
            ClientId,
            TokenEndpoint,
            jti: "secret-assertion-jti-1",
            issuedAt: now,
            expiresAt: now.AddMinutes(1),
            key.Value,
            WellKnownMediaTypes.Jwt.ClientAuthenticationJwt,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        var parts = assertion.Split('.');
        Assert.HasCount(3, parts);

        var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        Assert.AreSequenceEqual(
            PlatformHmacOf(algorithm, secretOctets, signingInput),
            SecurityEventTestJson.DecodeSegment(parts[2], Pool),
            "The MAC is the secret's HMAC of the signing input.");

        using var header = JsonDocument.Parse(SecurityEventTestJson.DecodeSegment(parts[0], Pool));
        Assert.AreEqual(algorithm, header.RootElement.GetProperty(WellKnownJwkMemberNames.Alg).GetString());
        Assert.AreEqual(WellKnownMediaTypes.Jwt.ClientAuthenticationJwt, header.RootElement.GetProperty(WellKnownJoseHeaderNames.Typ).GetString());
        Assert.IsFalse(header.RootElement.TryGetProperty(WellKnownJwkMemberNames.Kid, out _), "No key identifier names a client secret.");
        Assert.HasCount(2, header.RootElement.EnumerateObject(), "The header names alg and typ alone.");

        using var payload = JsonDocument.Parse(SecurityEventTestJson.DecodeSegment(parts[1], Pool));
        var claims = payload.RootElement;
        Assert.AreEqual(ClientId, claims.GetProperty(WellKnownJwtClaimNames.Iss).GetString());
        Assert.AreEqual(ClientId, claims.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
        Assert.AreEqual(TokenEndpoint, claims.GetProperty(WellKnownJwtClaimNames.Aud).GetString());
        Assert.AreEqual("secret-assertion-jti-1", claims.GetProperty(WellKnownJwtClaimNames.Jti).GetString());
        Assert.AreEqual(now.ToUnixTimeSeconds(), claims.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64());
        Assert.AreEqual(now.AddMinutes(1).ToUnixTimeSeconds(), claims.GetProperty(WellKnownJwtClaimNames.Exp).GetInt64());
    }


    /// <summary>
    /// RFC 7518 §3.2: "A key of the same size as the hash output (for instance, 256 bits for "HS256") or larger MUST be used
    /// with this algorithm." A secret one octet shorter than the hash output is refused as the key is formed, a typed
    /// refusal carrying the algorithm, the octets the secret carries and the octets the algorithm needs, with nothing
    /// composed; one of exactly the hash output's length forms a key the composition MACs under.
    /// </summary>
    [TestMethod]
    [DataRow("HS256", 32)]
    [DataRow("HS384", 48)]
    [DataRow("HS512", 64)]
    public async Task AClientSecretShorterThanTheHashOutputIsRefused(string algorithm, int hashOutputLength)
    {
        using var shortSecret = SecretOf(Encoding.UTF8.GetBytes(new string('s', hashOutputLength - 1)));
        using var sufficientSecret = SecretOf(Encoding.UTF8.GetBytes(new string('s', hashOutputLength)));

        var refused = ClientAssertionCredential.OfClientSecret(shortSecret, algorithm);
        Assert.IsFalse(refused.IsSuccess, "A secret shorter than the hash output keys no assertion.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput, refused.Error.Reason);
        Assert.AreEqual(algorithm, refused.Error.Algorithm);
        Assert.AreEqual(hashOutputLength - 1, refused.Error.SecretOctets);
        Assert.AreEqual(hashOutputLength, refused.Error.RequiredOctets);

        var accepted = ClientAssertionCredential.OfClientSecret(sufficientSecret, algorithm);
        Assert.IsTrue(accepted.IsSuccess, "A secret of the hash output's length keys the assertion.");

        var assertion = await SignWithKeyAsync(accepted.Value, TimeProvider.GetUtcNow()).ConfigureAwait(false);
        Assert.HasCount(3, assertion.Split('.'));
    }


    /// <summary>
    /// A <c>client_secret_jwt</c> assertion is MACed under an HMAC algorithm of RFC 7518 §3.2 alone: a signature algorithm
    /// and <c>none</c> are refused as the key is formed, a typed refusal naming the algorithm, before anything is composed.
    /// </summary>
    /// <param name="algorithm">An algorithm none of the HMAC algorithms names.</param>
    [TestMethod]
    [DataRow("ES256")]
    [DataRow("RS256")]
    [DataRow("none")]
    public void AClientSecretAssertionUnderAnAlgorithmOtherThanAnHmacIsRefused(string algorithm)
    {
        using var secret = SecretOf(Encoding.UTF8.GetBytes(LongClientSecret));

        var refused = ClientAssertionCredential.OfClientSecret(secret, algorithm);

        Assert.IsFalse(refused.IsSuccess, "Only an HMAC algorithm keys a client secret assertion.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.AlgorithmIsNotAnHmac, refused.Error.Reason);
        Assert.AreEqual(algorithm, refused.Error.Algorithm);
    }


    /// <summary>
    /// The options of an assertion name the key identifier its key calls for: a <c>client_secret_jwt</c> registration's
    /// options naming a <c>kid</c> were composed for a signing key and are refused, typed, as the key is formed (OpenID
    /// Connect Core 1.0 §9: the secret is the client's own, which its identifier already names), and the same options
    /// naming none form a key whose header names no <c>kid</c>.
    /// </summary>
    [TestMethod]
    public void AClientSecretAssertionWhoseOptionsNameAKeyIdentifierIsRefused()
    {
        using var secret = SecretOf(Encoding.UTF8.GetBytes(LongClientSecret));
        using var unusedPublicKey = new PublicKeyMemory(Pool.Rent(1), Tag.Empty);
        var registration = RegistrationOf(ClientAuthenticationMethod.ClientSecretJwt, new(unusedPublicKey, secret));

        var refused = ClientAssertionCredential.Of(registration, OptionsNaming("a-key-identifier-no-secret-carries"));
        Assert.IsFalse(refused.IsSuccess, "Options naming a key identifier were composed for a signing key.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.ClientSecretNamesAKeyIdentifier, refused.Error.Reason);
        Assert.AreEqual(WellKnownJwaValues.Hs256, refused.Error.Algorithm);

        var accepted = ClientAssertionCredential.Of(registration, OptionsNaming(keyId: null));
        Assert.IsTrue(accepted.IsSuccess, "Options naming no key identifier form the secret's key.");
        Assert.IsNull(accepted.Value.KeyId);
        Assert.AreEqual(WellKnownJwaValues.Hs256, accepted.Value.Algorithm);
    }


    /// <summary>
    /// A <c>private_key_jwt</c> registration's options naming no <c>kid</c> are refused, typed, as the key is formed: the
    /// authorization server resolves the client's key by it (RFC 7515 §4.1.4); the same options naming one form a key whose
    /// header names it, under the algorithm the key's tag names.
    /// </summary>
    [TestMethod]
    public void APrivateKeyAssertionWhoseOptionsNameNoKeyIdentifierIsRefused()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;
        var registration = RegistrationOf(ClientAuthenticationMethod.PrivateKeyJwt, keyMaterial);

        var refused = ClientAssertionCredential.Of(registration, OptionsNaming(keyId: null));
        Assert.IsFalse(refused.IsSuccess, "A private key assertion names the key identifier the server resolves the key by.");
        Assert.AreEqual(ClientAssertionCredentialRefusalReason.PrivateKeyNamesNoKeyIdentifier, refused.Error.Reason);
        Assert.AreEqual(WellKnownJwaValues.Es256, refused.Error.Algorithm);

        var accepted = ClientAssertionCredential.Of(registration, OptionsNaming(SigningKeyId));
        Assert.IsTrue(accepted.IsSuccess, "Options naming the key identifier form the private key's key.");
        Assert.AreEqual(SigningKeyId, accepted.Value.KeyId);
        Assert.AreEqual(WellKnownJwaValues.Es256, accepted.Value.Algorithm);
    }


    /// <summary>A secret of 64 octets, long enough for every HMAC algorithm of RFC 7518 §3.2.</summary>
    private const string LongClientSecret = "client-secret-the-authorization-server-issued-0123456789abcdefgh";


    /// <summary>
    /// The platform's own HMAC of a signing input under the secret, for the three HMAC algorithms of RFC 7518 §3.2 alone.
    /// </summary>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <param name="secret">The secret's octets.</param>
    /// <param name="signingInput">The JWS signing input.</param>
    /// <returns>The MAC.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The algorithm is none of <c>HS256</c>, <c>HS384</c> and <c>HS512</c>.</exception>
    private static byte[] PlatformHmacOf(string algorithm, byte[] secret, byte[] signingInput) => algorithm switch
    {
        _ when WellKnownJwaValues.IsHs256(algorithm) => HMACSHA256.HashData(secret, signingInput),
        _ when WellKnownJwaValues.IsHs384(algorithm) => HMACSHA384.HashData(secret, signingInput),
        _ when WellKnownJwaValues.IsHs512(algorithm) => HMACSHA512.HashData(secret, signingInput),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Only the HMAC algorithms of RFC 7518 Section 3.2 MAC a client secret assertion.")
    };


    /// <summary>Composes one assertion under a key with this class's fixed claims.</summary>
    /// <param name="key">The key.</param>
    /// <param name="now">The instant the claims are computed from.</param>
    /// <returns>The compact assertion.</returns>
    private ValueTask<string> SignWithKeyAsync(ClientAssertionCredential key, DateTimeOffset now) =>
        ClientAssertionSigning.SignAsync(
            ClientId,
            TokenEndpoint,
            "secret-assertion-jti-2",
            now,
            now.AddMinutes(1),
            key,
            WellKnownJwkValues.TypeJwt,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken);


    /// <summary>A registration naming a method and carrying its key material, for forming a key from options.</summary>
    /// <param name="method">The method.</param>
    /// <param name="keyMaterial">The key material, the private half the key or the secret.</param>
    /// <returns>The registration.</returns>
    private static ClientRegistration RegistrationOf(
        ClientAuthenticationMethod method,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial) =>
        new()
        {
            ClientId = new ClientId(ClientId),
            AuthorizationServerIssuer = new Uri("https://as.example.com"),
            AuthenticationMethod = method,
            AuthenticationKeyMaterial = keyMaterial
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
    /// A client secret's octets as the library carries one, untagged - a shared secret is no asymmetric key - in pooled
    /// memory the returned key owns and its caller disposes.
    /// </summary>
    /// <param name="octets">The secret's octets.</param>
    /// <returns>The key holding a copy of the octets.</returns>
    private static PrivateKeyMemory SecretOf(byte[] octets)
    {
        var owner = Pool.Rent(octets.Length);
        octets.CopyTo(owner.Memory.Span);

        return new PrivateKeyMemory(owner, Tag.Empty);
    }


    /// <summary>
    /// RFC 7523
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">Section 3</see> item 3: "The JWT
    /// MUST contain an &quot;aud&quot; (audience) claim containing a value that identifies the authorization
    /// server as an intended audience." rfc7523bis-11
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">Section
    /// 4</see> item b replaces item 3 for client authentication: the &quot;aud&quot; claim value "MUST use
    /// the issuer identifier [RFC8414] of the authorization server as its sole value." A registration whose
    /// <see cref="ClientRegistration.ClientAssertionAudience"/> is unset names no such value, so
    /// <see cref="ClientTokenEndpointAuthentication.AttachClientAssertionAsync"/> refuses it as an
    /// argument error, an <see cref="ArgumentNullException"/> naming the audience member and not a
    /// <see cref="NullReferenceException"/> from reading it, and the form it was to extend carries no
    /// client authentication parameter afterwards.
    /// </summary>
    [TestMethod]
    public async Task UnsetAssertionAudienceIsRefusedAsAnArgumentAndAddsNothingToTheForm()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        (OAuthClient client, ClientRegistration registration, _) = app.CreateInProcessOAuthClientAndRegistration(
            material.Registration,
            "https://client.example.com/callback",
            material.Registration.IssuerUri!.ToString());
        ClientRegistration unsetAudience = registration with { ClientAssertionAudience = null! };

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        OutgoingFormFields form = new();
        ExchangeContext context = [];

        ArgumentNullException refusal = await Assert.ThrowsExactlyAsync<ArgumentNullException>(
            async () => await ClientTokenEndpointAuthentication.AttachClientAssertionAsync(
                form,
                unsetAudience,
                new Uri(TokenEndpoint),
                ClientAssertionCredential.OfPrivateKey(privateKey, SigningKeyId),
                HeaderSerializer,
                PayloadSerializer,
                TimeSpan.FromMinutes(5),
                client.Infrastructure,
                TimeProvider.GetUtcNow(),
                context,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.Contains(nameof(ClientRegistration.ClientAssertionAudience), refusal.ParamName ?? string.Empty,
            StringComparison.Ordinal, "The refusal must name the unset audience member.");
        Assert.AreEqual(0, form.Count, "A refused assertion must add no parameter to the form.");
    }
}

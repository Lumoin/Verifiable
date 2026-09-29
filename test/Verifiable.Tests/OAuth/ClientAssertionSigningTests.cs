using Microsoft.Extensions.Time.Testing;
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
                privateKey,
                SigningKeyId,
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

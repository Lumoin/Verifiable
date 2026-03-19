using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="ResolveIssuerDelegate"/> and <see cref="DefaultIssuerResolver"/>.
/// Covers the registration → context → throw fallback, application overrides, and
/// confirms that the discovery endpoint and access-token emission both route through
/// the resolver (the iss claim plus client_id are emitted as expected).
/// </summary>
/// <remarks>
/// The access-token shape tests exercise the JWT factories
/// (<see cref="JwtHeader.ForAccessToken"/> / <see cref="JwtPayload.ForAccessToken"/>)
/// composed with <see cref="JwtSigningExtensions.SignAsync"/> directly rather than
/// driving the full auth-code + PKCE + token-exchange flow. The wiring through
/// <c>AuthCodeEndpoints</c> and the producer pipeline is trivial to read in the
/// source; the behaviour worth asserting is that the signing primitive emits the
/// claims it is given.
/// </remarks>
[TestClass]
internal sealed class ResolveIssuerDelegateTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task DefaultIssuerResolverPrefersRegistrationIssuerUri()
    {
        Uri registrationUri = new("https://tenant-a.issuer.example");
        Uri contextUri = new("https://fallback.example");

        ClientRegistration registration = BuildRegistration(issuerUri: registrationUri);
        RequestContext context = new();
        context.SetIssuer(contextUri);

        Uri resolved = await DefaultIssuerResolver.ResolveAsync(
            registration, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(registrationUri, resolved,
            "DefaultIssuerResolver must prefer the registration's declared IssuerUri " +
            "over the context's request-scoped fallback.");
    }


    [TestMethod]
    public async Task DefaultIssuerResolverFallsBackToContextWhenRegistrationIssuerUriIsNull()
    {
        Uri contextUri = new("https://derived.example");

        ClientRegistration registration = BuildRegistration(issuerUri: null);
        RequestContext context = new();
        context.SetIssuer(contextUri);

        Uri resolved = await DefaultIssuerResolver.ResolveAsync(
            registration, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(contextUri, resolved,
            "DefaultIssuerResolver must fall back to context.Issuer when the " +
            "registration does not declare an IssuerUri.");
    }


    [TestMethod]
    public async Task DefaultIssuerResolverThrowsWhenBothAreUnset()
    {
        ClientRegistration registration = BuildRegistration(issuerUri: null);
        RequestContext context = new();

        InvalidOperationException thrown = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await DefaultIssuerResolver.ResolveAsync(
                registration, context, TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.Contains(nameof(ClientRegistration.IssuerUri), thrown.Message,
            "Exception message must identify IssuerUri as the missing declaration site.");
    }


    [TestMethod]
    public async Task ApplicationResolverOverridesDefault()
    {
        Uri registrationUri = new("https://declared.example");
        Uri overrideUri = new("https://policy-chosen.example");

        ClientRegistration registration = BuildRegistration(issuerUri: registrationUri);
        RequestContext context = new();

        ResolveIssuerDelegate customResolver = (_, _, _) =>
            ValueTask.FromResult(overrideUri);

        Uri resolved = await customResolver(
            registration, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(overrideUri, resolved,
            "An application-supplied resolver must replace the default entirely, " +
            "even when the registration declares a different IssuerUri.");
    }


    [TestMethod]
    public async Task DiscoveryEndpointUsesResolvedIssuerFromRegistration()
    {
        FakeTimeProvider timeProvider = new(DateTimeOffset.Parse(
            "2026-04-22T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

        using TestHostShell app = new(timeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(
            "verifier-client",
            new Uri("https://verifier.example"),
            ImmutableHashSet.Create(
                ServerCapabilityName.JwksEndpoint,
                ServerCapabilityName.DiscoveryEndpoint));

        string segment = keys.Registration.TenantId;

        //The registration declares IssuerUri as https://issuer.test/{segment} per
        //TestHostShell. The discovery endpoint must use that value, not any context
        //override, because the resolver prefers the registration.
        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(new Uri("https://wrong.context.example"));

        ServerHttpResponse response = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.DiscoveryEndpoint,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "Discovery endpoint must return HTTP 200.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        string? emittedIssuer = doc.RootElement.GetProperty("issuer").GetString();

        Assert.AreEqual($"https://issuer.test",
            emittedIssuer,
            "Discovery must emit the registration's IssuerUri authority, not the " +
            "context's fallback. GetLeftPart(UriPartial.Authority) strips the path.");
    }


    [TestMethod]
    public async Task AccessTokenSigningEmitsIssAndClientIdWhenSupplied()
    {
        string expectedIssuer = "https://issuer.test";
        string expectedClientId = "client-abc";
        string expectedSubject = "subject-xyz";
        string expectedJti = "jti-123";
        string expectedScope = "openid profile";

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using PrivateKeyMemory signingKey = keyPair.PrivateKey;

        DateTimeOffset now = DateTimeOffset.Parse(
            "2026-04-22T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        JwtHeader accessTokenHeader = JwtHeader.ForAccessToken(algorithm, "test-key");
        JwtPayload accessTokenPayload = JwtPayload.ForAccessToken(
            subject: expectedSubject,
            jti: expectedJti,
            scope: expectedScope,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            issuer: expectedIssuer,
            audience: null,
            clientId: expectedClientId);

        UnsignedJwt unsigned = new(accessTokenHeader, accessTokenPayload);

        EncodeDelegate encoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);

        using JwsMessage jws = await unsigned.SignAsync(
            privateKey: signingKey,
            headerSerializer: static headerDict => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)headerDict,
                TestSetup.DefaultSerializationOptions),
            payloadSerializer: static payloadDict => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payloadDict,
                TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: encoder,
            memoryPool: SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jwt = JwsSerialization.SerializeCompact(jws, encoder);

        keyPair.PublicKey.Dispose();

        (JsonDocument header, JsonDocument payload) = DecodeJwt(jwt);
        using(header)
        using(payload)
        {
            Assert.AreEqual("at+jwt", header.RootElement.GetProperty("typ").GetString(),
                "RFC 9068 requires typ=at+jwt on access tokens.");

            Assert.AreEqual(expectedIssuer, payload.RootElement.GetProperty("iss").GetString(),
                "iss claim must equal the issuer argument passed to SignAsync.");

            Assert.AreEqual(expectedClientId, payload.RootElement.GetProperty("client_id").GetString(),
                "client_id claim must equal the clientId argument passed to SignAsync.");

            Assert.AreEqual(expectedSubject, payload.RootElement.GetProperty("sub").GetString(),
                "sub claim must equal the subject argument.");

            Assert.AreEqual(expectedJti, payload.RootElement.GetProperty("jti").GetString(),
                "jti claim must equal the jti argument.");

            Assert.AreEqual(expectedScope, payload.RootElement.GetProperty("scope").GetString(),
                "scope claim must equal the scope argument.");
        }
    }


    [TestMethod]
    public async Task AccessTokenSigningOmitsIssAndClientIdWhenNotSupplied()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using PrivateKeyMemory signingKey = keyPair.PrivateKey;

        DateTimeOffset now = DateTimeOffset.Parse(
            "2026-04-22T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        JwtHeader accessTokenHeader = JwtHeader.ForAccessToken(algorithm, "test-key");
        JwtPayload accessTokenPayload = JwtPayload.ForAccessToken(
            subject: "subject-xyz",
            jti: "jti-123",
            scope: "openid",
            issuedAt: now,
            expiresAt: now.AddHours(1));

        UnsignedJwt unsigned = new(accessTokenHeader, accessTokenPayload);

        EncodeDelegate encoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);

        using JwsMessage jws = await unsigned.SignAsync(
            privateKey: signingKey,
            headerSerializer: static headerDict => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)headerDict,
                TestSetup.DefaultSerializationOptions),
            payloadSerializer: static payloadDict => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payloadDict,
                TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: encoder,
            memoryPool: SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jwt = JwsSerialization.SerializeCompact(jws, encoder);

        keyPair.PublicKey.Dispose();

        (JsonDocument header, JsonDocument payload) = DecodeJwt(jwt);
        using(header)
        using(payload)
        {
            //Sanity check: mechanical claims are always present.
            Assert.IsTrue(payload.RootElement.TryGetProperty("sub", out _),
                "sub must always be present.");
            Assert.IsTrue(payload.RootElement.TryGetProperty("jti", out _),
                "jti must always be present.");

            //When the caller passes no issuer/clientId the claim is absent (not
            //an empty string). This ensures applications that don't plumb them
            //don't produce RFC-9068-looking tokens with empty-string iss.
            Assert.IsFalse(payload.RootElement.TryGetProperty("iss", out _),
                "iss claim must be absent when issuer parameter was null.");
            Assert.IsFalse(payload.RootElement.TryGetProperty("client_id", out _),
                "client_id claim must be absent when clientId parameter was null.");
        }
    }


    private static ClientRegistration BuildRegistration(Uri? issuerUri) =>
        new()
        {
            ClientId = "test-client",
            TenantId = "test-segment",
            IssuerUri = issuerUri,
            AllowedCapabilities = ImmutableHashSet<ServerCapabilityName>.Empty,
            AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
            AllowedScopes = ImmutableHashSet<string>.Empty,
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty,
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty
        };


    //Decodes a compact JWS into (header, payload). No signature verification —
    //these tests assert claim shape, not cryptographic validity.
    private static (JsonDocument Header, JsonDocument Payload) DecodeJwt(string jwt)
    {
        string[] parts = jwt.Split('.');
        Assert.HasCount(3, parts, "Compact JWS must be header.payload.signature.");

        byte[] headerBytes = Base64UrlDecode(parts[0]);
        byte[] payloadBytes = Base64UrlDecode(parts[1]);

        return (JsonDocument.Parse(headerBytes), JsonDocument.Parse(payloadBytes));
    }


    private static byte[] Base64UrlDecode(string input)
    {
        string padded = input.Replace('-', '+').Replace('_', '/');
        switch(padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}

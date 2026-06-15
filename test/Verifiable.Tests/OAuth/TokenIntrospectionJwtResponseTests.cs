using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 9701 JWT introspection responses (FAPI 2.0 Message Signing §5.5), driven
/// through the real dispatch pipeline: a resource server that sends
/// <c>Accept: application/token-introspection+jwt</c> receives a signed JWT whose
/// <c>token_introspection</c> claim carries the RFC 7662 members, typed
/// <c>token-introspection+jwt</c> so it cannot be confused with an access token.
/// </summary>
[TestClass]
internal sealed class TokenIntrospectionJwtResponseTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://rs.introspection.client.test";

    private static readonly Uri ClientBaseUri = new("https://rs.introspection.client.test");

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly ImmutableHashSet<CapabilityIdentifier> IntrospectionCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthTokenIntrospection);


    [TestMethod]
    public async Task SignedResponseCarriesRfc7662MembersInsideTokenIntrospectionClaim()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterSigningCapableResourceServer(host);
        WireActiveToken(host);

        ServerHttpResponse response = await DispatchIntrospectionAsync(
            host, material, acceptJwt: true).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.TokenIntrospectionJwt, response.ContentType);

        //RFC 9701 §8.1: the typ header distinguishes the response from an access token.
        using JsonDocument header = ParseSegment(response.Body, segmentIndex: 0);
        Assert.AreEqual(WellKnownMediaTypes.Jwt.TokenIntrospectionJwt,
            header.RootElement.GetProperty(WellKnownJoseHeaderNames.Typ).GetString());
        Assert.AreEqual(WellKnownJwaValues.Es256,
            header.RootElement.GetProperty(WellKnownJwkMemberNames.Alg).GetString());

        //The signature verifies against the AS's published key.
        bool isSignatureValid = await Jws.VerifyAsync(
            response.Body, TestSetup.Base64UrlDecoder,
            static (ReadOnlySpan<byte> _) => (object?)null, Pool,
            material.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isSignatureValid);

        //RFC 9701 §5: iss/aud/iat at the top level; sub and exp deliberately absent;
        //the RFC 7662 members ride inside token_introspection.
        using JsonDocument payload = ParseSegment(response.Body, segmentIndex: 1);
        JsonElement root = payload.RootElement;
        Assert.AreEqual(material.Registration.IssuerUri!.OriginalString,
            root.GetProperty(WellKnownJwtClaimNames.Iss).GetString());
        Assert.AreEqual(ClientId, root.GetProperty(WellKnownJwtClaimNames.Aud).GetString());
        Assert.AreEqual(TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            root.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64());
        Assert.IsFalse(root.TryGetProperty(WellKnownJwtClaimNames.Sub, out _),
            "RFC 9701 §5: the top level SHOULD NOT carry sub.");
        Assert.IsFalse(root.TryGetProperty(WellKnownJwtClaimNames.Exp, out _),
            "RFC 9701 §5: the top level SHOULD NOT carry exp.");

        JsonElement introspection = root.GetProperty("token_introspection");
        Assert.IsTrue(introspection.GetProperty("active").GetBoolean());
        Assert.AreEqual("read write", introspection.GetProperty("scope").GetString());
        Assert.AreEqual("Z5O3upPC88QrAjx00dis", introspection.GetProperty("sub").GetString());
        Assert.AreEqual("token-jti-1", introspection.GetProperty("jti").GetString());
    }


    /// <summary>
    /// RFC 9396 §9.2 holds for the RFC 9701 signed JWT response too: the granted
    /// <c>authorization_details</c> ride inside the <c>token_introspection</c> claim, rendered as
    /// the §2 array structure — the same projection the plain JSON body emits, here through the
    /// wired JWT payload serializer.
    /// </summary>
    [TestMethod]
    public async Task SignedResponseCarriesAuthorizationDetailsInsideTheClaim()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterSigningCapableResourceServer(host);

        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().IntrospectTokenAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult
            {
                IsActive = true,
                Scope = "credential",
                AuthorizationDetails =
                [
                    new AuthorizationDetail
                    {
                        Type = "openid_credential",
                        ExtensionData = new Dictionary<string, string>(StringComparer.Ordinal)
                        {
                            ["credential_configuration_id"] = "\"UniversityDegree_dc_sd_jwt\"",
                            ["credential_identifiers"] = "[\"CivilEngineeringDegree-2026\"]"
                        }
                    }
                ]
            });

        ServerHttpResponse response = await DispatchIntrospectionAsync(
            host, material, acceptJwt: true).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument payload = ParseSegment(response.Body, segmentIndex: 1);
        JsonElement introspection = payload.RootElement.GetProperty("token_introspection");
        JsonElement details = introspection.GetProperty("authorization_details");

        Assert.AreEqual(JsonValueKind.Array, details.ValueKind);
        Assert.AreEqual(1, details.GetArrayLength());
        Assert.AreEqual("openid_credential", details[0].GetProperty("type").GetString());
        Assert.AreEqual("UniversityDegree_dc_sd_jwt",
            details[0].GetProperty("credential_configuration_id").GetString());
        Assert.AreEqual("CivilEngineeringDegree-2026",
            details[0].GetProperty("credential_identifiers")[0].GetString());
    }


    [TestMethod]
    public async Task InactiveTokenDisclosesOnlyActiveFalseInsideTheClaim()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterSigningCapableResourceServer(host);
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().IntrospectTokenAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult { IsActive = false });

        ServerHttpResponse response = await DispatchIntrospectionAsync(
            host, material, acceptJwt: true).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument payload = ParseSegment(response.Body, segmentIndex: 1);
        JsonElement introspection = payload.RootElement.GetProperty("token_introspection");

        Assert.IsFalse(introspection.GetProperty("active").GetBoolean());
        int memberCount = 0;
        foreach(JsonProperty _ in introspection.EnumerateObject())
        {
            memberCount++;
        }

        Assert.AreEqual(1, memberCount,
            "RFC 9701 §5: an inactive token must carry active=false and no other member.");
    }


    [TestMethod]
    public async Task JwtRequestWithoutSigningKeyIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        //A baseline registration WITHOUT an IntrospectionResponseSigning key.
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, IntrospectionCapabilities);
        WireActiveToken(host);

        ServerHttpResponse response = await DispatchIntrospectionAsync(
            host, material, acceptJwt: true).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body);
    }


    [TestMethod]
    public async Task PlainJsonRemainsTheDefaultWithoutTheAcceptHeader()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterSigningCapableResourceServer(host);
        WireActiveToken(host);

        ServerHttpResponse response = await DispatchIntrospectionAsync(
            host, material, acceptJwt: false).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.ContentType);

        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.IsTrue(document.RootElement.GetProperty("active").GetBoolean());
    }


    [TestMethod]
    public async Task DiscoveryAdvertisesIntrospectionSigningAlgsOnlyWithKey()
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthTokenIntrospection,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, capabilities);
        //The fail-closed candidate gate keeps the introspection endpoint off the chain
        //until its seams are wired; the chain presence is what the advertisement keys on.
        WireActiveToken(host);

        ServerHttpResponse unkeyed = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, unkeyed.StatusCode, unkeyed.Body);
        Assert.DoesNotContain(
            IntrospectionServerMetadataParameterNames.IntrospectionSigningAlgValuesSupported,
            unkeyed.Body,
            "Without a response-signing key the algorithms must not be advertised.");

        EnableIntrospectionSigning(host, material);

        ServerHttpResponse keyed = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, keyed.StatusCode, keyed.Body);
        Assert.Contains(
            IntrospectionServerMetadataParameterNames.IntrospectionSigningAlgValuesSupported,
            keyed.Body);
        Assert.Contains(WellKnownJwaValues.Es256, keyed.Body);
    }


    private static VerifierKeyMaterial RegisterSigningCapableResourceServer(TestHostShell host)
    {
        VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, IntrospectionCapabilities);
        EnableIntrospectionSigning(host, material);

        return material;
    }


    private static void EnableIntrospectionSigning(TestHostShell host, VerifierKeyMaterial material)
    {
        host.UpdateSigningKeys(
            material.Registration.TenantId.Value,
            material.Registration.SigningKeys.ToImmutableDictionary().Add(
                KeyUsageContext.IntrospectionResponseSigning,
                new SigningKeySet { Current = [material.SigningKeyId] }));
    }


    private static void WireActiveToken(TestHostShell host)
    {
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().IntrospectTokenAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult
            {
                IsActive = true,
                Scope = "read write",
                TokenType = "Bearer",
                Subject = "Z5O3upPC88QrAjx00dis",
                JwtId = "token-jti-1"
            });
    }


    private async ValueTask<ServerHttpResponse> DispatchIntrospectionAsync(
        TestHostShell host, VerifierKeyMaterial material, bool acceptJwt)
    {
        RequestHeaders headers = acceptJwt
            ? new RequestHeaders(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [WellKnownHttpHeaderNames.Accept] = [WellKnownMediaTypes.Application.TokenIntrospectionJwt]
            })
            : RequestHeaders.Empty;

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "access-token-to-inspect" },
            headers,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async ValueTask<ServerHttpResponse> DispatchDiscoveryAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static JsonDocument ParseSegment(string compactJwt, int segmentIndex)
    {
        string[] parts = compactJwt.Split('.');
        Assert.HasCount(3, parts);
        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[segmentIndex], Pool);
        string json = Encoding.UTF8.GetString(bytes.Memory.Span).TrimEnd('\0');

        return JsonDocument.Parse(json);
    }
}

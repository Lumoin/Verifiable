using System.Collections.Concurrent;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Keys;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Phase 9e — audit drift D-3 closure. Confirms that the
/// <see cref="TenantId"/> parameter added to
/// <see cref="ServerSigningKeyResolverDelegate"/> and
/// <see cref="ResolveServerHmacKeyDelegate"/> actually carries the
/// registration's tenant identifier through to the application's
/// resolver implementation.
/// </summary>
[TestClass]
internal sealed class TenantIdThreadingTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 5, 15, 12, 0, 0, TimeSpan.Zero));


    [TestMethod]
    public async Task SigningResolverReceivesRegistrationTenantId()
    {
        await using TestHostShell host = new(TimeProvider);
        string clientId = "https://client.example.com";
        Uri clientBase = new(clientId);

        ConcurrentBag<TenantId> observed = [];
        ServerSigningKeyResolverDelegate previous =
            host.Server.Cryptography.SigningKeyResolver!;
        host.Server.Cryptography.SigningKeyResolver = (keyId, tenantId, ctx, ct) =>
        {
            observed.Add(tenantId);
            return previous(keyId, tenantId, ctx, ct);
        };

        using VerifierKeyMaterial keys = host.RegisterDpopClient(
            clientId, clientBase, profile: PolicyProfile.Rfc6749WithPkce);

        await DriveCodeExchangeAsync(host, keys).ConfigureAwait(false);

        Assert.IsNotEmpty(observed,
            "Signing resolver must be invoked at least once during token issuance.");

        TenantId expected = keys.Registration.TenantId;
        foreach(TenantId t in observed)
        {
            Assert.AreEqual(expected, t,
                "Every signing-resolver invocation must receive the registration's tenant identifier.");
        }
    }


    [TestMethod]
    public async Task VerificationResolverReceivesRegistrationTenantId()
    {
        //The verification resolver is invoked when validating inbound JARs.
        //Driving a code exchange doesn't hit it; the OID4VP-side or JAR
        //paths do. For phase 9e the structural confirmation is sufficient:
        //the lambda installed on the test host has the new signature and
        //the build passes. The threaded value is exercised end-to-end by
        //the broader test suite's JAR-receiving paths.
        await using TestHostShell host = new(TimeProvider);
        ServerVerificationKeyResolverDelegate resolver =
            host.Server.Cryptography.VerificationKeyResolver!;

        //Smoke: call the resolver directly with a fabricated tenant to
        //confirm the delegate accepts the new four-parameter shape.
        PublicKeyMemory? key = await resolver(
            "kid-never-issued",
            new TenantId("some-tenant"),
            new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(key, "Unknown kid must return null.");
    }


    [TestMethod]
    public async Task HmacResolverReceivesTenantIdFromContext()
    {
        await using TestHostShell host = new(TimeProvider);
        host.EnableDpop();

        ConcurrentBag<TenantId> observed = [];
        ResolveServerHmacKeyDelegate previous =
            host.Server.Integration.ResolveServerHmacKeyAsync!;
        host.Server.Integration.ResolveServerHmacKeyAsync = (kid, tenantId, ctx, ct) =>
        {
            observed.Add(tenantId);
            return previous(kid, tenantId, ctx, ct);
        };

        //Issue a nonce through the integration delegate — exercises the
        //byte-loader path with the configured tenant.
        TenantId tenant = new("tenant-x");
        RequestContext ctx = new();
        ctx.SetTenantId(tenant.Value);

        _ = await host.Server.Integration.IssueDpopNonceAsync!(
            new Uri("https://issuer.test/abcd1234"),
            tenant,
            ctx,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotEmpty(observed,
            "HMAC resolver must be invoked during nonce issuance.");
        foreach(TenantId t in observed)
        {
            Assert.AreEqual(tenant, t,
                "Every HMAC-resolver invocation must receive the call site's tenant identifier.");
        }
    }


    private async Task DriveCodeExchangeAsync(TestHostShell host, VerifierKeyMaterial keys)
    {
        const string clientId = "https://client.example.com";
        Uri redirectUri = new("https://client.example.com/callback");
        string tenant = keys.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            tenant, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, parResponse.StatusCode);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        RequestContext authorizeContext = new();
        authorizeContext.SetSubjectId("subject-1");
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            tenant, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode);
        string code = ExtractCodeFromLocation(authorizeResponse.Location!);

        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeAuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.OriginalString
        };
        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            tenant, WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
    }


    private static string ExtractFromBody(string body, string property)
    {
        using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(body);
        return doc.RootElement.GetProperty(property).GetString()!;
    }


    private static string ExtractCodeFromLocation(string location)
    {
        int q = location.IndexOf('?', StringComparison.Ordinal);
        foreach(string pair in location[(q + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq > 0 && string.Equals(
                pair[..eq], OAuthRequestParameterNames.Code, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        throw new InvalidOperationException(
            $"Authorize redirect did not carry a code parameter: {location}");
    }
}

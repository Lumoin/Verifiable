using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Confirms that the
/// <see cref="TenantId"/> parameter of
/// <see cref="ServerSigningKeyResolverDelegate"/>,
/// <see cref="ServerVerificationKeyResolverDelegate"/> and
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


    /// <summary>
    /// Signing-key resolution receives the tenant identifier of the registration being served.
    /// <see href="../../../documents/AuthorizationServerDesign.md#middle-layer-cryptographic-primitive-delegates">Cryptographic delegates §3</see>.
    /// </summary>
    [TestMethod]
    public async Task SigningResolverReceivesRegistrationTenantId()
    {
        await using TestHostShell host = new(TimeProvider);
        string clientId = "https://client.example.com";
        Uri clientBase = new(clientId);

        ConcurrentBag<TenantId> observed = [];
        ServerSigningKeyResolverDelegate previous =
            host.Server.OAuth().Cryptography.SigningKeyResolver!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.Cryptography.SigningKeyResolver = (keyId, tenantId, ctx, ct) =>
            {
                observed.Add(tenantId);

                return previous(keyId, tenantId, ctx, ct);
            };
        }).ConfigureAwait(false);

        using VerifierKeyMaterial keys = await host.RegisterDpopClientAsync(
            clientId, clientBase, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        _ = await DriveCodeExchangeAsync(host, keys).ConfigureAwait(false);

        Assert.IsNotEmpty(observed,
            "Signing resolver must be invoked at least once during token issuance.");

        TenantId expected = keys.Registration.TenantId;
        foreach(TenantId t in observed)
        {
            Assert.AreEqual(expected, t,
                "Every signing-resolver invocation must receive the registration's tenant identifier.");
        }
    }


    /// <summary>
    /// A local contract of this library, labelled as such: the per-tenant key isolation
    /// <see cref="ServerVerificationKeyResolverDelegate"/> documents, "The tenantId parameter enables
    /// per-tenant key isolation". An access token issued to a registration and presented as a Bearer
    /// token at that registration's UserInfo endpoint over the wire is served 200, and every resolution
    /// of the token's key is scoped to the registration's own tenant.
    /// <see href="../../../documents/AuthorizationServerDesign.md#middle-layer-cryptographic-primitive-delegates">Cryptographic delegates §3</see>.
    /// </summary>
    [TestMethod]
    public async Task VerificationResolverReceivesRegistrationTenantId()
    {
        await using TestHostShell host = new(TimeProvider);
        string clientId = "https://client.example.com";
        Uri clientBase = new(clientId);
        _ = host.SeedTestSubject(subject: "subject-1");

        using VerifierKeyMaterial keys = await host.RegisterDpopClientAsync(
            clientId, clientBase, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        InProcessAuthCodeDriveResult drive = await DriveCodeExchangeAsync(host, keys).ConfigureAwait(false);
        using JsonDocument tokenBody = JsonDocument.Parse(drive.TokenResponse.Body);
        string accessToken = tokenBody.RootElement.GetProperty("access_token").GetString()!;

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri userInfoUrl = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.UserInfo, keys.Registration.TenantId.Value));
        using HttpRequestMessage request = new(HttpMethod.Post, userInfoUrl);
        _ = request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {accessToken}");

        hosted.VerificationKeyResolutions.Clear();
        using HttpResponseMessage response = await hosted.SharedHttpClient!.SendAsync(request, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);

        ImmutableArray<VerificationKeyResolution> resolutions = hosted.ResolutionsOf(keys.SigningKeyId);
        Assert.IsNotEmpty(resolutions, "UserInfo resolves the access token's key.");
        foreach(VerificationKeyResolution resolution in resolutions)
        {
            Assert.AreEqual(keys.Registration.TenantId, resolution.TenantId,
                "Every verification-resolver invocation must receive the registration's tenant identifier.");
        }
    }


    /// <summary>
    /// HMAC-key resolution receives the tenant identifier carried by the request context.
    /// <see href="../../../documents/AuthorizationServerDesign.md#middle-layer-cryptographic-primitive-delegates">Cryptographic delegates §3</see>.
    /// </summary>
    [TestMethod]
    public async Task HmacResolverReceivesTenantIdFromContext()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        ConcurrentBag<TenantId> observed = [];
        ResolveServerHmacKeyDelegate previous =
            host.Server.OAuth().ResolveServerHmacKeyAsync!;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveServerHmacKeyAsync = (kid, tenantId, ctx, ct) =>
            {
                observed.Add(tenantId);

                return previous(kid, tenantId, ctx, ct);
            };
        }).ConfigureAwait(false);

        //Issue a nonce through the integration delegate — exercises the
        //byte-loader path with the configured tenant.
        TenantId tenant = new("tenant-x");
        ExchangeContext ctx = [];
        ctx.SetTenantId(tenant.Value);
        ctx.SetServer(host.Server);

        _ = await host.Server.OAuth().IssueDpopNonceAsync!(
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


    /// <summary>
    /// Drives the authorization-code flow for <c>subject-1</c> with the <c>openid</c> scope through
    /// <paramref name="keys"/>'s registration, so the token endpoint signs an access token and an ID
    /// Token under the registration's keys.
    /// </summary>
    /// <param name="host">The host serving the flow.</param>
    /// <param name="keys">The registration the flow runs under.</param>
    /// <returns>The drive's result, whose token response carries the issued tokens.</returns>
    private async Task<InProcessAuthCodeDriveResult> DriveCodeExchangeAsync(TestHostShell host, VerifierKeyMaterial keys)
    {
        Uri redirectUri = new("https://client.example.com/callback");

        return await InProcessAuthCodeDriver.DriveAsync(
            host, keys, "subject-1", redirectUri,
            new InProcessAuthCodeDriveOptions { Scope = WellKnownScopes.OpenId },
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}

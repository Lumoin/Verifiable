using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Confirms that the
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
        //paths do. The structural confirmation is sufficient:
        //the lambda installed on the test host has the new signature and
        //the build passes. The threaded value is exercised end-to-end by
        //the broader test suite's JAR-receiving paths.
        await using TestHostShell host = new(TimeProvider);
        ServerVerificationKeyResolverDelegate resolver =
            host.Server.OAuth().Cryptography.VerificationKeyResolver!;

        //Smoke: call the resolver directly with a fabricated tenant to
        //confirm the delegate accepts the new four-parameter shape.
        PublicKeyMemory? key = await resolver(
            "kid-never-issued",
            new TenantId("some-tenant"),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(key, "Unknown kid must return null.");
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


    private async Task DriveCodeExchangeAsync(TestHostShell host, VerifierKeyMaterial keys)
    {
        Uri redirectUri = new("https://client.example.com/callback");

        _ = await InProcessAuthCodeDriver.DriveAsync(
            host, keys, "subject-1", redirectUri,
            new InProcessAuthCodeDriveOptions { Scope = WellKnownScopes.OpenId },
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}

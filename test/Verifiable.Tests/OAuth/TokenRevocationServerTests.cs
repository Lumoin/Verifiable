using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Server-side RFC 7009 token revocation, driven through the real dispatch
/// pipeline. The library owns the wire (client authentication, the empty-200
/// that never leaks token validity, the fail-closed candidate gate); the
/// application owns the revocation store behind <see cref="RevokeTokenDelegate"/>.
/// </summary>
[TestClass]
internal sealed class TokenRevocationServerTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The client identifier registered for the revocation tests.</summary>
    private const string ClientId = "https://revocation.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static readonly Uri ClientBaseUri = new("https://revocation.client.test");

    /// <summary>The single capability the revocation endpoint requires.</summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> RevocationCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthTokenRevocation);


    /// <summary>
    /// A wired revocation endpoint authenticates the client, relays the token
    /// and hint to the application seam, and answers RFC 7009 §2.2 with an empty
    /// 200 — the application's store records exactly what was presented.
    /// </summary>
    [TestMethod]
    public async Task RevocationEndpointAuthenticatesClientAndRelaysTokenToSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, RevocationCapabilities);

        List<(string Token, string? Hint, ClientRecord Client)> revoked = [];
        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.Integration.RevokeTokenAsync = (token, hint, registration, _, _) =>
        {
            revoked.Add((token, hint, registration));
            return ValueTask.CompletedTask;
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeRevoke,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.Token] = "access-token-to-kill",
                [OAuthRequestParameterNames.TokenTypeHint] = "access_token"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //RFC 7009 §2.2: 200 with an empty body.
        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(string.Empty, response.Body, "RFC 7009 §2.2 mandates an empty body.");

        Assert.HasCount(1, revoked, "The seam must be invoked exactly once.");
        Assert.AreEqual("access-token-to-kill", revoked[0].Token);
        Assert.AreEqual("access_token", revoked[0].Hint);
        Assert.AreEqual(material.Registration.ClientId, revoked[0].Client.ClientId,
            "Revocation must be scoped to the authenticated client.");
    }


    /// <summary>
    /// When client authentication fails the endpoint returns 401
    /// <c>invalid_client</c> and never reaches the revocation seam — a token is
    /// not revoked on an unauthenticated request (RFC 7009 §2.1).
    /// </summary>
    [TestMethod]
    public async Task RevocationEndpointRejectsUnauthenticatedClientWithoutTouchingTheStore()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, RevocationCapabilities);

        bool seamInvoked = false;
        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(false);
        host.Server.Integration.RevokeTokenAsync = (_, _, _, _, _) =>
        {
            seamInvoked = true;
            return ValueTask.CompletedTask;
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeRevoke,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "some-token" },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidClient, response.Body, StringComparison.Ordinal);
        Assert.IsFalse(seamInvoked, "A failed authentication must not revoke anything.");
    }


    /// <summary>
    /// Revocation is idempotent: presenting the same token twice answers 200
    /// both times (RFC 7009 §2.2 treats an already-revoked or unknown token as
    /// success), so a client may retry safely.
    /// </summary>
    [TestMethod]
    public async Task RevocationEndpointIsIdempotentAcrossRepeatedRequests()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, RevocationCapabilities);

        int seamCalls = 0;
        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.Integration.RevokeTokenAsync = (_, _, _, _, _) =>
        {
            seamCalls++;
            return ValueTask.CompletedTask;
        };

        RequestFields fields = new() { [OAuthRequestParameterNames.Token] = "repeated-token" };

        ServerHttpResponse first = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeRevoke,
            "POST", fields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        ServerHttpResponse second = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeRevoke,
            "POST", fields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, first.StatusCode, first.Body);
        Assert.AreEqual(200, second.StatusCode, second.Body);
        Assert.AreEqual(2, seamCalls, "Each request reaches the seam; the store dedupes, not the endpoint.");
    }


    /// <summary>
    /// Fail-closed: declaring the revocation capability without wiring the
    /// revocation seam leaves the endpoint absent from the chain, so a request
    /// to it returns 404 rather than silently no-op'ing.
    /// </summary>
    [TestMethod]
    public async Task RevocationEndpointAbsentWhenSeamUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, RevocationCapabilities);

        //Client authentication is wired but the revocation seam is not — the
        //candidate gate requires both, so the endpoint must not materialize.
        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeRevoke,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "some-token" },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unwired revocation seam must leave the endpoint absent (fail-closed).");
    }
}

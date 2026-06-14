using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Logout;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Server-side Global Token Revocation (draft-parecki-oauth-global-token-revocation),
/// driven through the real dispatch pipeline. The library owns the wire — client
/// authentication, body read, the §3 status-code mapping, and the fail-closed
/// candidate gate; the application owns the parse (the serialization firewall) and
/// the revoke-subject fan-out behind <see cref="RevokeSubjectTokensDelegate"/>. The
/// <c>sub_id</c> is the neutral <see cref="SubjectIdentifier"/> reused from the
/// Shared Signals subsystem. The parse seam here is supplied by the test, exactly
/// as the all-capabilities suite supplies the AuthZEN/SSF parse lambdas.
/// </summary>
[TestClass]
internal sealed class GlobalTokenRevocationServerTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The client identifier registered for the tests.</summary>
    private const string ClientId = "https://gtr.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static readonly Uri ClientBaseUri = new("https://gtr.client.test");

    /// <summary>The single capability the Global Token Revocation endpoint requires.</summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> GtrCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation);

    /// <summary>A representative iss_sub request body.</summary>
    private const string SubIdJson =
        /*lang=json,strict*/ "{\"sub_id\":{\"format\":\"iss_sub\",\"iss\":\"https://issuer.test\",\"sub\":\"subject-123\"}}";


    /// <summary>
    /// A wired endpoint authenticates the client, delivers the JSON body to the
    /// parse seam, relays the parsed Subject Identifier to the revoke-subject
    /// seam, and answers §3 with 204 when revocation is initiated.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationInitiatedReturns204AndRelaysSubject()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, GtrCapabilities);

        SubjectIdentifier? revokedSubject = null;
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);

        //Exercise the PRODUCTION JSON parser (Verifiable.Json) end-to-end — the
        //body's sub_id is parsed by the default parser, not a test lambda.
        host.Server.OAuth().UseDefaultGlobalTokenRevocationJsonParsing();
        host.Server.OAuth().RevokeSubjectTokensAsync = (subId, _, _, _) =>
        {
            revokedSubject = subId;
            return ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            SubIdJson,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(204, response.StatusCode, response.Body);
        Assert.AreEqual(string.Empty, response.Body);
        Assert.IsNotNull(revokedSubject);
        Assert.IsTrue(SubjectIdentifierFormats.IsIssuerSubject(revokedSubject.Format),
            "The default parser must project sub_id into the iss_sub format.");
        Assert.IsTrue(revokedSubject.IsValidForKnownFormat());
        Assert.AreEqual("https://issuer.test", revokedSubject.Members[SubjectIdentifierMemberNames.Iss]);
        Assert.AreEqual("subject-123", revokedSubject.Members[SubjectIdentifierMemberNames.Sub]);
    }


    /// <summary>
    /// §3.5: an unauthenticated request is rejected 401 <c>invalid_client</c>
    /// before the body is parsed or any token is revoked.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationRejectsUnauthenticatedClient()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, GtrCapabilities);

        bool parseInvoked = false;
        bool revokeInvoked = false;
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(false);
        host.Server.OAuth().ParseGlobalTokenRevocationRequestAsync = (_, _, _) =>
        {
            parseInvoked = true;
            return ValueTask.FromResult<GlobalTokenRevocationRequest?>(null);
        };
        host.Server.OAuth().RevokeSubjectTokensAsync = (_, _, _, _) =>
        {
            revokeInvoked = true;
            return ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            SubIdJson,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidClient, response.Body, StringComparison.Ordinal);
        Assert.IsFalse(parseInvoked, "Authentication must gate the body parse.");
        Assert.IsFalse(revokeInvoked, "A failed authentication must not revoke anything.");
    }


    /// <summary>
    /// §3 status-code mapping: the application-determined outcomes
    /// (<see cref="GlobalTokenRevocationOutcome.SubjectNotFound"/> /
    /// <see cref="GlobalTokenRevocationOutcome.Forbidden"/> /
    /// <see cref="GlobalTokenRevocationOutcome.Unprocessable"/>) map to 404 / 403 / 422.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationMapsOutcomesToStatusCodes()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, GtrCapabilities);

        GlobalTokenRevocationOutcome outcome = GlobalTokenRevocationOutcome.SubjectNotFound;
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().ParseGlobalTokenRevocationRequestAsync = static (_, _, _) =>
            ValueTask.FromResult<GlobalTokenRevocationRequest?>(new GlobalTokenRevocationRequest
            {
                SubId = SubjectIdentifier.Email("user@example.test")
            });
        host.Server.OAuth().RevokeSubjectTokensAsync = (_, _, _, _) => ValueTask.FromResult(outcome);

        async ValueTask<int> DispatchStatusAsync()
        {
            ServerHttpResponse response = await host.DispatchAtEndpointAsync(
                material.Registration.TenantId.Value,
                WellKnownEndpointNames.GlobalTokenRevocation,
                "POST",
                new RequestFields(),
                SubIdJson,
                new ExchangeContext(),
                TestContext.CancellationToken).ConfigureAwait(false);

            return response.StatusCode;
        }

        outcome = GlobalTokenRevocationOutcome.SubjectNotFound;
        Assert.AreEqual(404, await DispatchStatusAsync().ConfigureAwait(false));

        outcome = GlobalTokenRevocationOutcome.Forbidden;
        Assert.AreEqual(403, await DispatchStatusAsync().ConfigureAwait(false));

        outcome = GlobalTokenRevocationOutcome.Unprocessable;
        Assert.AreEqual(422, await DispatchStatusAsync().ConfigureAwait(false));
    }


    /// <summary>
    /// §3: a body that does not parse (the seam returns <see langword="null"/>)
    /// is a 400 <c>invalid_request</c> — the revoke seam is never reached.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationReturns400OnUnparseableBody()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, GtrCapabilities);

        bool revokeInvoked = false;
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().ParseGlobalTokenRevocationRequestAsync = static (_, _, _) =>
            ValueTask.FromResult<GlobalTokenRevocationRequest?>(null);
        host.Server.OAuth().RevokeSubjectTokensAsync = (_, _, _, _) =>
        {
            revokeInvoked = true;
            return ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            "not json",
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body, StringComparison.Ordinal);
        Assert.IsFalse(revokeInvoked);
    }


    /// <summary>
    /// §3: a parsed request whose <c>sub_id</c> is not a well-formed, known-format
    /// Subject Identifier is a 400 — the library validates the identifier before
    /// dropping out to the revoke seam.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationReturns400OnInvalidSubjectIdentifier()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, GtrCapabilities);

        bool revokeInvoked = false;
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);

        //An "email" format with no email member fails IsValidForKnownFormat().
        host.Server.OAuth().ParseGlobalTokenRevocationRequestAsync = static (_, _, _) =>
            ValueTask.FromResult<GlobalTokenRevocationRequest?>(new GlobalTokenRevocationRequest
            {
                SubId = new SubjectIdentifier
                {
                    Format = SubjectIdentifierFormats.Email,
                    Members = new Dictionary<string, object>(StringComparer.Ordinal)
                }
            });
        host.Server.OAuth().RevokeSubjectTokensAsync = (_, _, _, _) =>
        {
            revokeInvoked = true;
            return ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            SubIdJson,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsFalse(revokeInvoked, "An invalid sub_id must not reach the revoke seam.");
    }


    /// <summary>
    /// Fail-closed: declaring the capability without wiring the revoke-subject
    /// seam leaves the endpoint absent from the chain, so the request returns 404.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationEndpointAbsentWhenSeamUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, GtrCapabilities);

        //Client authentication and the parser are wired but the revoke-subject
        //seam is not — the gate requires all three, so the endpoint must not exist.
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.OAuth().ParseGlobalTokenRevocationRequestAsync = static (_, _, _) =>
            ValueTask.FromResult<GlobalTokenRevocationRequest?>(null);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            SubIdJson,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unwired revoke-subject seam must leave the endpoint absent (fail-closed).");
    }
}

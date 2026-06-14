using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Server;
using Verifiable.Tests.Federation;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end exemplar for OpenID Federation 1.0 §12.1 automatic client
/// registration wired into a real authorization flow. Proves the full path
/// the library intends for automatic registration:
/// </summary>
/// <list type="number">
///   <item><description>
///     An RP whose <c>client_id</c> is its Entity Identifier arrives with an
///     inline trust chain (here built in-process; on the wire it rides the
///     request object's <c>trust_chain</c> JOSE header).
///   </description></item>
///   <item><description>
///     The application runs <see cref="FederationAutomaticRegistration"/>,
///     PROJECTS the resolved effective metadata onto an ephemeral
///     <see cref="ClientRecord"/> (redirect URIs, scopes — tenant and
///     capabilities are the deployment's choice), and pre-sets it on the
///     <see cref="ExchangeContext"/>.
///   </description></item>
///   <item><description>
///     The dispatcher honours the pre-set <c>context.Registration</c>, so the
///     PAR endpoint runs against the federation-derived registration — a
///     redirect URI the RP declared in federation metadata is accepted, one it
///     did not is rejected.
///   </description></item>
/// </list>
/// <remarks>
/// This is an APPLICATION-COMPOSITION exemplar, not a library feature: the
/// library supplies the engine and honours a pre-set registration; the skin
/// owns recognising the federation <c>client_id</c>, running the engine, and
/// projecting the result (the <c>trust_chain</c> lives in the request object,
/// parsed after the dispatcher's early client-load step, so automatic
/// registration cannot be a <c>LoadClientRegistration</c> fallback).
/// </remarks>
[TestClass]
internal sealed class FederationAutomaticRegistrationFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly EntityTypeIdentifier RpType =
        WellKnownEntityTypeIdentifiers.OpenIdRelyingParty;

    private const string RpEntityId = "https://rp.example.com";
    private const string FederationRedirectUri = "https://rp.example.com/cb";


    [TestMethod]
    public async Task FederationDerivedRegistrationGovernsThePushedAuthorizationRequest()
    {
        await using TestHostShell host = new(TimeProvider);

        ClientRecord ephemeral = await ResolveAndProjectAsync(host).ConfigureAwait(false);

        //A PAR carrying the redirect_uri the RP declared in its federation
        //metadata is accepted — the federation-derived registration drives the
        //flow.
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = RpEntityId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = FederationRedirectUri,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
        };

        ExchangeContext context = new();
        context.SetRegistration(ephemeral);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            ephemeral.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode,
            $"A PAR under the federation-derived registration must succeed. Body: {response.Body}");
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal,
            $"PAR response must carry a request_uri. Got: {response.Body}");
    }


    [TestMethod]
    public async Task RedirectUriOutsideFederationMetadataIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);

        ClientRecord ephemeral = await ResolveAndProjectAsync(host).ConfigureAwait(false);

        //A redirect_uri the RP never declared in its federation metadata must
        //be refused — the AllowedRedirectUris came from the resolved chain.
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = RpEntityId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = "https://attacker.example.com/cb",
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
        };

        ExchangeContext context = new();
        context.SetRegistration(ephemeral);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            ephemeral.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(201, response.StatusCode,
            $"A redirect_uri outside the federation-derived AllowedRedirectUris must not succeed. Body: {response.Body}");
    }


    /// <summary>
    /// Resolves the RP via automatic registration over a real signed chain,
    /// then projects the effective metadata onto an ephemeral
    /// <see cref="ClientRecord"/> — the application-side step the skin owns.
    /// </summary>
    private async ValueTask<ClientRecord> ResolveAndProjectAsync(TestHostShell host)
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        //The RP declares its openid_relying_party metadata — redirect_uris and
        //scope the OP will register it with.
        Dictionary<string, object> rpMetadata = new(StringComparer.Ordinal)
        {
            ["redirect_uris"] = new List<object> { FederationRedirectUri },
            ["scope"] = WellKnownScopes.OpenId,
        };

        using FederationTestRingNode rpNode =
            FederationTestRing.CreateNode(new EntityIdentifier(RpEntityId));
        using FederationTestRingNode anchorNode =
            FederationTestRing.CreateNode(new EntityIdentifier("https://anchor.example.com"));

        MintedStatement rpEc = await FederationTestRing.MintEntityConfigurationAsync(
            rpNode, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [RpType.Value] = rpMetadata,
                },
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutRp = await FederationTestRing.MintSubordinateStatementAsync(
            anchorNode, rpNode, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchorNode, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        List<string> compactChain = [rpEc.CompactJws, anchorAboutRp.CompactJws, anchorEc.CompactJws];

        ValidateTrustChainAsyncDelegate validateChain = InlineTrustChainValidationDriver.Build(
            async (position, jws, ct) => position == 0
                ? await FederationTestRing.VerifyAsync(rpNode, jws, ct).ConfigureAwait(false)
                : await FederationTestRing.VerifyAsync(anchorNode, jws, ct).ConfigureAwait(false));

        FederationAutomaticRegistrationResult result = await FederationAutomaticRegistration.ResolveAsync(
            compactChain,
            new EntityIdentifier(RpEntityId),
            RpType,
            [anchorNode.Identifier],
            now,
            TimeSpan.FromMinutes(5),
            validateChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsRegistered,
            $"Automatic registration must admit the RP. Reason: {result.RejectionReason}");

        return ProjectToClientRecord(result);
    }


    /// <summary>
    /// Projects a <see cref="FederationAutomaticRegistrationResult"/> onto an
    /// ephemeral <see cref="ClientRecord"/>. redirect_uris and scopes come
    /// from the resolved federation metadata; tenant, capabilities, and
    /// lifetimes are the deployment's choice (here a fresh segment with the
    /// auth-code + PAR capabilities). The dispatcher honours this via a
    /// pre-set <c>context.Registration</c> — no prior <c>RegisterClient</c> is
    /// needed, which is exactly the point of automatic registration.
    /// </summary>
    private static ClientRecord ProjectToClientRecord(FederationAutomaticRegistrationResult result)
    {
        IReadOnlyDictionary<string, object> metadata = result.EffectiveMetadata!;

        ImmutableHashSet<Uri> redirectUris =
            [.. ((IEnumerable<object>)metadata["redirect_uris"]).Select(value => new Uri((string)value))];
        ImmutableHashSet<string> scopes =
            [.. ((string)metadata["scope"]).Split(' ', StringSplitOptions.RemoveEmptyEntries)];

        string segment = Guid.NewGuid().ToString("N")[..8];

        ClientRecord ephemeral = new()
        {
            ClientId = result.Subject.Value,
            TenantId = segment,
            IssuerUri = new Uri($"https://issuer.test/{segment}"),
            AllowedCapabilities = ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
            AllowedRedirectUris = redirectUris,
            AllowedScopes = scopes,
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty,
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
        };

        return ephemeral;
    }
}

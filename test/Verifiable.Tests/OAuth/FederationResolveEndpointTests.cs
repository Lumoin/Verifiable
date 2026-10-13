using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end tests for the OpenID Federation 1.0 §8.3
/// <c>federation_resolve_endpoint</c> exposed by <see cref="FederationEndpoints"/>.
/// The endpoint serves a signed Resolve Response JWT
/// (<c>typ = resolve-response+jwt</c>) carrying a subject's resolved
/// metadata, trust chain, and trust marks; the resolution itself comes from
/// the application's
/// <see cref="AuthorizationServerIntegration.ResolveSubjectTrustChainAsync"/>
/// delegate, while the library parses <c>sub</c> / <c>trust_anchor</c> / <c>entity_type</c>,
/// assembles the payload, and signs it with the resolver's federation key.
/// </summary>
[TestClass]
internal sealed class FederationResolveEndpointTests
{
    /// <summary>
    /// The test context; its cancellation token reaches every call of the rows that takes one.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The clock the host runs on, fixed at the canonical test epoch.
    /// </summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>
    /// The memory pool the rows decode and verify with.
    /// </summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// Signs the resolved entity metadata, trust chain and trust marks.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.2">Federation §8.3.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ResolveEndpointServesSignedResolveResponse()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        EntityIdentifier subject = new("https://leaf.example.com");
        EntityIdentifier anchor = new("https://anchor.example.com");

        EntityIdentifier? observedSubject = null;
        EntityIdentifier? observedAnchor = null;
        EntityTypeIdentifier? observedType = null;

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (sub, trustAnchor, entityTypeFilter, _, _, _) =>
                {
                    observedSubject = sub;
                    observedAnchor = trustAnchor;
                    observedType = entityTypeFilter;

                    Dictionary<string, object> rpMetadata = new(StringComparer.Ordinal)
                    {
                        ["client_name"] = "Leaf RP"
                    };
                    Dictionary<string, object> metadata = new(StringComparer.Ordinal)
                    {
                        [WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value] = rpMetadata
                    };

                    Dictionary<string, object> trustMark = new(StringComparer.Ordinal)
                    {
                        ["trust_mark_type"] = "https://anchor.example.com/marks/onboarded",
                        ["trust_mark"] = "eyJ0rust.mark.jwt"
                    };

                    return ValueTask.FromResult<FederationResolveOutcome?>(
                        FederationResolveOutcome.Resolved(new ResolveResponseContribution
                        {
                            Metadata = metadata,
                            TrustChain = ["eyJleaf.statement.jws", "eyJanchor.statement.jws"],
                            TrustMarks = [trustMark]
                        }));
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        string query =
            $"?sub={Uri.EscapeDataString(subject.Value)}"
            + $"&trust_anchor={Uri.EscapeDataString(anchor.Value)}"
            + "&entity_type=openid_relying_party";

        string compactResponse = await GetResolveAsync(
            host, $"/connect/{segment}/federation_resolve{query}").ConfigureAwait(false);

        //The library parsed and threaded all three request parameters.
        Assert.IsNotNull(observedSubject);
        Assert.AreEqual(subject.Value, observedSubject.Value.Value);
        Assert.IsNotNull(observedAnchor);
        Assert.AreEqual(anchor.Value, observedAnchor.Value.Value);
        Assert.IsNotNull(observedType);
        Assert.AreEqual(
            WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value, observedType.Value.Value);

        //The response is a three-segment JWS with the §8.3 explicit type.
        Dictionary<string, object> header = DecodeSegment(compactResponse, 0);
        Assert.AreEqual(
            WellKnownFederationMediaTypes.ResolveResponseJwt,
            (string)header[WellKnownJoseHeaderNames.Typ],
            "The Resolve Response must carry typ=resolve-response+jwt per §8.3.");

        Dictionary<string, object> payload = DecodeSegment(compactResponse, 1);
        Assert.AreEqual(resolverEntityId.ToString(), (string)payload["iss"],
            "iss must be the resolver's Entity Identifier.");
        Assert.AreEqual(subject.Value, (string)payload["sub"],
            "sub must be the resolved subject.");
        Assert.IsGreaterThan(
            Convert.ToInt64(payload["iat"], CultureInfo.InvariantCulture),
            Convert.ToInt64(payload["exp"], CultureInfo.InvariantCulture),
            "exp must be strictly after iat.");

        //Resolved metadata round-trips.
        IReadOnlyDictionary<string, object> metadata =
            (IReadOnlyDictionary<string, object>)payload["metadata"];
        IReadOnlyDictionary<string, object> rp =
            (IReadOnlyDictionary<string, object>)metadata[WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value];
        Assert.AreEqual("Leaf RP", (string)rp["client_name"]);

        //trust_chain and trust_marks are present in the form the application supplied.
        IReadOnlyList<object> chain = (IReadOnlyList<object>)payload["trust_chain"];
        Assert.HasCount(2, chain, "Both chain statements must be present.");
        Assert.AreEqual("eyJleaf.statement.jws", (string)chain[0]);
        Assert.AreEqual("eyJanchor.statement.jws", (string)chain[1]);

        IReadOnlyList<object> marks = (IReadOnlyList<object>)payload["trust_marks"];
        Assert.HasCount(1, marks);
        IReadOnlyDictionary<string, object> mark0 =
            (IReadOnlyDictionary<string, object>)marks[0];
        Assert.AreEqual(
            "https://anchor.example.com/marks/onboarded",
            (string)mark0["trust_mark_type"]);

        //The response verifies under the resolver's federation public key.
        bool isSignatureValid = await Jws.VerifyAsync(
            compactResponse,
            TestSetup.Base64UrlDecoder,
            Pool,
            federationKeys.PublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isSignatureValid,
            "The Resolve Response must verify under the resolver's federation signing key.");
    }


    /// <summary>
    /// The library's own rule for a lifetime it issues: the library writes a Resolve Response's <c>iat</c> and
    /// <c>exp</c> (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.2">OpenID Federation 1.0
    /// Section 8.3.2</see>) as whole-second NumericDates, and every lifetime the server's <see cref="TimingPolicy"/>
    /// holds is its whole seconds, so a <see cref="TimingPolicy.FederationEntityConfigurationLifetime"/> of 90.7
    /// seconds, with a resolution that states no expiry of its own, issues a Resolve Response, fetched over the real
    /// wire half a second past a whole second, whose <c>exp</c> is 90 seconds after its <c>iat</c>.
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task AResolveResponseUnderAFractionalLifetimeLivesItsWholeSecondsAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(
            app, new Uri("https://resolver.example.com"), federationKeys).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                static (sub, trustAnchor, entityTypeFilter, _, _, _) =>
                    ValueTask.FromResult<FederationResolveOutcome?>(
                        FederationResolveOutcome.Resolved(new ResolveResponseContribution
                        {
                            Metadata = RelyingPartyMetadata(),
                            TrustChain = ["eyJleaf.statement.jws", "eyJanchor.statement.jws"]
                        }));
            candidateIntegration.Timings = TimingPolicy.Default with
            {
                FederationEntityConfigurationLifetime = TimeSpan.FromTicks(907_000_000L)
            };
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        TimeProvider.Advance(TimeSpan.FromTicks(TimeSpan.TicksPerSecond / 2));
        string query =
            $"?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}";

        string compactResponse = await GetResolveAsync(
            host, $"/connect/{resolverKeys.Registration.TenantId.Value}/federation_resolve{query}").ConfigureAwait(false);
        Dictionary<string, object> payload = DecodeSegment(compactResponse, 1);

        Assert.AreEqual(
            90L,
            Convert.ToInt64(payload["exp"], CultureInfo.InvariantCulture)
                - Convert.ToInt64(payload["iat"], CultureInfo.InvariantCulture),
            compactResponse);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.2">OpenID Federation 1.0 Section
    /// 8.3.2</see>: the Resolve Response's <c>exp</c> "MUST be the minimum of the exp value of the Trust Chain from which
    /// the resolve response was derived, as well as any Trust Mark included in the response." The library's own rule for
    /// a lifetime it issues holds the time that minimum leaves after the response's issuance to at least one whole
    /// second, and never extends it. A resolution whose stated expiry lies half a second after a request fetched over
    /// the real wire half a second past a whole second leaves no such lifetime, so the request is refused 400
    /// <c>invalid_trust_chain</c> (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Section
    /// 8.9</see>: "The Trust Chain cannot be validated."); one whose stated expiry lies 90.2 or 90.7 seconds after it is
    /// served 200 with that expiry, in whole seconds (<see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC
    /// 7519 Section 2</see> NumericDate, floored), as its <c>exp</c>. At the half-second instant the 90.7-second
    /// remainder floors to a different whole second than the same instant plus 90 whole seconds does, so the row
    /// distinguishes the preserved expiry from a truncated remainder.
    /// </summary>
    /// <param name="remainingTicks">How far the resolution's stated expiry lies after the request, in ticks.</param>
    /// <param name="expectedStatusCode">The resolve endpoint's status code.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow(5_000_000L, 400)]
    [DataRow(902_000_000L, 200)]
    [DataRow(907_000_000L, 200)]
    public async Task AResolveResponseIsHeldToTheLifetimeItsResolutionLeavesAsync(long remainingTicks, int expectedStatusCode)
    {
        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(
            app, new Uri("https://resolver.example.com"), federationKeys).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        TimeProvider.Advance(TimeSpan.FromTicks(TimeSpan.TicksPerSecond / 2));
        DateTimeOffset resolutionExpiry = TimeProvider.GetUtcNow() + TimeSpan.FromTicks(remainingTicks);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (sub, trustAnchor, entityTypeFilter, _, _, _) =>
                    ValueTask.FromResult<FederationResolveOutcome?>(
                        FederationResolveOutcome.Resolved(new ResolveResponseContribution
                        {
                            Metadata = RelyingPartyMetadata(),
                            TrustChain = ["eyJleaf.statement.jws", "eyJanchor.statement.jws"],
                            ExpiresAt = resolutionExpiry
                        }));
        }).ConfigureAwait(false);
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{resolverKeys.Registration.TenantId.Value}/federation_resolve"
            + $"?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatusCode, (int)response.StatusCode, body);
        if(expectedStatusCode == 400)
        {
            Assert.Contains($"\"error\":\"{OAuthErrors.InvalidTrustChain}\"", body, StringComparison.Ordinal);

            return;
        }

        Dictionary<string, object> payload = DecodeSegment(body, 1);
        Assert.AreEqual(
            resolutionExpiry.ToUnixTimeSeconds(),
            Convert.ToInt64(payload["exp"], CultureInfo.InvariantCulture),
            body);
    }


    /// <summary>
    /// Returns invalid_subject when the application cannot resolve the requested entity.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>.
    /// </summary>
    [TestMethod]
    public async Task ResolveEndpointReturns404WhenSubjectUnresolvable()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) => ValueTask.FromResult<FederationResolveOutcome?>(null);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://unknown.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, (int)response.StatusCode,
            "A subject the resolver cannot resolve yields HTTP 404 per the null-contribution contract.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            "Federation §8.9: the error response must be an application/json object.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidSubject}\"", body, StringComparison.Ordinal,
            $"Federation §8.9: an unresolvable subject must carry the invalid_subject error code. Got: {body}");
    }


    /// <summary>
    /// Returns <c>invalid_trust_chain</c> with HTTP 400 when the resolver names that outcome.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>:
    /// "The Trust Chain cannot be validated. The HTTP response status code SHOULD be 400 (Bad Request)."
    /// </summary>
    [TestMethod]
    public async Task ResolveEndpointReturns400WithInvalidTrustChainWhenResolverNamesIt()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) => ValueTask.FromResult<FederationResolveOutcome?>(
                    FederationResolveOutcome.Failed(FederationResolveError.InvalidTrustChain));
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "Federation §8.9: invalid_trust_chain SHOULD be reported with HTTP 400.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidTrustChain}\"", body, StringComparison.Ordinal,
            $"The resolver named invalid_trust_chain; the wire body must carry that code, not invalid_subject. Got: {body}");
    }


    /// <summary>
    /// Returns <c>invalid_metadata</c> with HTTP 400 when the resolver names that outcome.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>:
    /// "Metadata or Metadata Policy values are invalid or conflict. The HTTP response status code
    /// SHOULD be 400 (Bad Request)."
    /// </summary>
    [TestMethod]
    public async Task ResolveEndpointReturns400WithInvalidMetadataWhenResolverNamesIt()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) => ValueTask.FromResult<FederationResolveOutcome?>(
                    FederationResolveOutcome.Failed(FederationResolveError.InvalidMetadata));
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "Federation §8.9: invalid_metadata SHOULD be reported with HTTP 400.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidMetadata}\"", body, StringComparison.Ordinal,
            $"The resolver named invalid_metadata; the wire body must carry that code, not invalid_subject. Got: {body}");
    }


    /// <summary>
    /// Returns <c>invalid_trust_anchor</c> with HTTP 404 when the resolver names that outcome.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>:
    /// "The Trust Anchor cannot be found or used. The HTTP response status code SHOULD be 404
    /// (Not Found)."
    /// </summary>
    [TestMethod]
    public async Task ResolveEndpointReturns404WithInvalidTrustAnchorWhenResolverNamesIt()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) => ValueTask.FromResult<FederationResolveOutcome?>(
                    FederationResolveOutcome.Failed(FederationResolveError.InvalidTrustAnchor));
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, (int)response.StatusCode,
            "Federation §8.9: invalid_trust_anchor SHOULD be reported with HTTP 404.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidTrustAnchor}\"", body, StringComparison.Ordinal,
            $"The resolver named invalid_trust_anchor; the wire body must carry that code, not invalid_subject. Got: {body}");
    }


    /// <summary>
    /// Returns <c>not_found</c> with HTTP 404 when the resolver names that outcome.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>:
    /// "The requested Entity Identifier cannot be found. The HTTP response status code SHOULD be
    /// 404 (Not Found)."
    /// </summary>
    [TestMethod]
    public async Task ResolveEndpointReturns404WithNotFoundWhenResolverNamesIt()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) => ValueTask.FromResult<FederationResolveOutcome?>(
                    FederationResolveOutcome.Failed(FederationResolveError.NotFound));
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, (int)response.StatusCode,
            "Federation §8.9: not_found SHOULD be reported with HTTP 404.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.NotFound}\"", body, StringComparison.Ordinal,
            $"The resolver named not_found; the wire body must carry that code, not invalid_subject. Got: {body}");
    }


    /// <summary>
    /// Rejects a resolution request missing its required subject before invoking the resolver.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation §8.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ResolveEndpointRejectsMissingSub()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        bool isDelegateInvoked = false;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) =>
                {
                    isDelegateInvoked = true;

                    return ValueTask.FromResult<FederationResolveOutcome?>(null);
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_resolve");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A resolve request with no sub is malformed (400), not a 404.");
        Assert.IsFalse(isDelegateInvoked,
            "The application delegate must not run for a request rejected at parameter validation.");
    }


    /// <summary>
    /// Rejects a resolution request missing its required <c>trust_anchor</c> before invoking the
    /// resolver, with a description naming the parameter.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "trust_anchor REQUIRED. The Trust Anchor that the resolve endpoint MUST use when resolving the
    /// metadata. The value is an Entity Identifier."
    /// </summary>
    [TestMethod]
    public async Task ResolveEndpointRejectsMissingAnchor()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        bool isDelegateInvoked = false;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) =>
                {
                    isDelegateInvoked = true;

                    return ValueTask.FromResult<FederationResolveOutcome?>(null);
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;

        //Section 8.3.1: trust_anchor is REQUIRED. A resolve request that names a subject but no
        //Trust Anchor is malformed (400), and the resolution delegate must not run.
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://leaf.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode,
            "A resolve request without the REQUIRED trust_anchor parameter is malformed (Federation section 8.3.1).");
        Assert.Contains("\"error\":\"invalid_request\"", body, StringComparison.Ordinal,
            $"A missing trust_anchor is an invalid_request. Got: {body}");
        Assert.Contains("trust_anchor", body, StringComparison.Ordinal,
            $"The description names the missing trust_anchor parameter. Got: {body}");
        Assert.IsFalse(isDelegateInvoked,
            "The resolution delegate must not run for a request rejected at parameter validation.");
    }


    /// <summary>
    /// Refuses a resolve request that names its Trust Anchor and its Entity Type by the names
    /// <c>anchor</c> and <c>type</c>: the endpoint reads <c>trust_anchor</c> and
    /// <c>entity_type</c> only, so the request carries no Trust Anchor and is answered 400
    /// <c>invalid_request</c> naming <c>trust_anchor</c> before the resolution delegate runs.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "trust_anchor REQUIRED. The Trust Anchor that the resolve endpoint MUST use when resolving the
    /// metadata. The value is an Entity Identifier."
    /// </summary>
    [TestMethod]
    public async Task ARequestNamingItsTrustAnchorByAnotherNameIsRefusedAsync()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        bool isDelegateInvoked = false;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) =>
                {
                    isDelegateInvoked = true;

                    return ValueTask.FromResult<FederationResolveOutcome?>(null);
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&anchor={Uri.EscapeDataString("https://anchor.example.com")}"
            + "&type=openid_relying_party");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode,
            $"A request naming its Trust Anchor anchor carries no trust_anchor and is malformed. Got: {body}");
        Assert.Contains("\"error\":\"invalid_request\"", body, StringComparison.Ordinal,
            $"A request without trust_anchor is an invalid_request. Got: {body}");
        Assert.Contains("trust_anchor", body, StringComparison.Ordinal,
            $"The description names the trust_anchor parameter the endpoint reads. Got: {body}");
        Assert.IsFalse(isDelegateInvoked,
            "The resolution delegate must not run for a request without trust_anchor.");
    }


    /// <summary>
    /// Refuses a <c>trust_anchor</c> whose value is not an Entity Identifier with 400
    /// <c>invalid_request</c> naming <c>trust_anchor</c>, before the resolution delegate runs.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "trust_anchor REQUIRED. The Trust Anchor that the resolve endpoint MUST use when resolving the
    /// metadata. The value is an Entity Identifier."
    /// </summary>
    [TestMethod]
    public async Task ATrustAnchorThatIsNotAnEntityIdentifierIsRefusedAsync()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        bool isDelegateInvoked = false;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) =>
                {
                    isDelegateInvoked = true;

                    return ValueTask.FromResult<FederationResolveOutcome?>(null);
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        //An Entity Identifier is an https URL; an http URL is not one.
        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("http://anchor.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode,
            $"A trust_anchor that is not an Entity Identifier is malformed. Got: {body}");
        Assert.Contains("\"error\":\"invalid_request\"", body, StringComparison.Ordinal,
            $"A malformed trust_anchor is an invalid_request. Got: {body}");
        Assert.Contains("trust_anchor parameter is not a valid Entity Identifier", body, StringComparison.Ordinal,
            $"The description names the trust_anchor parameter. Got: {body}");
        Assert.IsFalse(isDelegateInvoked,
            "The resolution delegate must not run for a malformed trust_anchor.");
    }


    /// <summary>
    /// Resolves against the first <c>trust_anchor</c> occurrence that carries a value when the
    /// parameter is sent several times; an occurrence without a value is omitted.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "The trust_anchor request parameter MAY occur multiple times, in which case, the resolver MAY
    /// return a successful resolve response using any of the Trust Anchor values provided."
    /// </summary>
    [TestMethod]
    public async Task TheFirstOfSeveralTrustAnchorsIsResolvedAgainstAsync()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        EntityIdentifier? observedAnchor = null;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, trustAnchor, _, _, _, _) =>
                {
                    observedAnchor = trustAnchor;

                    return ValueTask.FromResult<FederationResolveOutcome?>(
                        FederationResolveOutcome.Resolved(new ResolveResponseContribution
                        {
                            Metadata = RelyingPartyMetadata()
                        }));
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        string query =
            $"?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + "&trust_anchor="
            + $"&trust_anchor={Uri.EscapeDataString("https://first-anchor.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://second-anchor.example.com")}";

        _ = await GetResolveAsync(
            host, $"/connect/{segment}/federation_resolve{query}").ConfigureAwait(false);

        Assert.IsNotNull(observedAnchor,
            "The resolution delegate runs for a request that carries trust_anchor values.");
        Assert.AreEqual("https://first-anchor.example.com", observedAnchor.Value.Value,
            "The resolve endpoint resolves against the first trust_anchor occurrence that carries a value.");
    }


    /// <summary>
    /// Returns the metadata of each named Entity Type only when <c>entity_type</c> is sent several
    /// times: the resolution delegate receives no single filter, and the members of the other Entity
    /// Types it returns are left out of the response's <c>metadata</c>.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "The entity_type request parameter MAY occur multiple times, in which case, data for each Entity
    /// Type whose Entity Type Identifier is in an entity_type parameter value is returned."
    /// </summary>
    [TestMethod]
    public async Task SeveralEntityTypesReturnTheirMetadataOnlyAsync()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        bool isDelegateInvoked = false;
        EntityTypeIdentifier? observedType = null;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, entityTypeFilter, _, _, _) =>
                {
                    isDelegateInvoked = true;
                    observedType = entityTypeFilter;

                    return ValueTask.FromResult<FederationResolveOutcome?>(
                        FederationResolveOutcome.Resolved(new ResolveResponseContribution
                        {
                            Metadata = ThreeEntityTypesMetadata()
                        }));
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        string query =
            $"?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}"
            + "&entity_type=openid_relying_party"
            + "&entity_type=openid_provider";

        string compactResponse = await GetResolveAsync(
            host, $"/connect/{segment}/federation_resolve{query}").ConfigureAwait(false);

        Assert.IsTrue(isDelegateInvoked, "The resolution delegate runs for a well-formed request.");
        Assert.IsNull(observedType,
            "Several entity_type values are no single filter, so the resolution delegate receives none.");

        Dictionary<string, object> payload = DecodeSegment(compactResponse, 1);
        IReadOnlyDictionary<string, object> metadata =
            (IReadOnlyDictionary<string, object>)payload["metadata"];
        Assert.HasCount(2, metadata,
            "The metadata holds the members of the two named Entity Types only.");
        Assert.IsTrue(metadata.ContainsKey("openid_relying_party"),
            "The metadata holds the openid_relying_party member that was named.");
        Assert.IsTrue(metadata.ContainsKey("openid_provider"),
            "The metadata holds the openid_provider member that was named.");
        Assert.IsFalse(metadata.ContainsKey("federation_entity"),
            "The metadata leaves out the federation_entity member that was not named.");
    }


    /// <summary>
    /// Returns the metadata of the one named Entity Type only: the resolution delegate receives the
    /// Entity Type as its filter, and when it returns the members of other Entity Types as well, the
    /// response's <c>metadata</c> leaves them out.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "OPTIONAL. A specific Entity Type to resolve."
    /// </summary>
    [TestMethod]
    public async Task OneNamedEntityTypeReturnsItsMetadataOnlyAsync()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        EntityTypeIdentifier? observedType = null;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, entityTypeFilter, _, _, _) =>
                {
                    observedType = entityTypeFilter;

                    //The delegate leaves its filter unapplied and returns every Entity Type.
                    return ValueTask.FromResult<FederationResolveOutcome?>(
                        FederationResolveOutcome.Resolved(new ResolveResponseContribution
                        {
                            Metadata = ThreeEntityTypesMetadata()
                        }));
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        string query =
            $"?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}"
            + "&entity_type=openid_provider";

        string compactResponse = await GetResolveAsync(
            host, $"/connect/{segment}/federation_resolve{query}").ConfigureAwait(false);

        Assert.IsNotNull(observedType, "The one named Entity Type is the resolution delegate's filter.");
        Assert.AreEqual("openid_provider", observedType.Value.Value,
            "The resolution delegate receives the named Entity Type as its filter.");

        Dictionary<string, object> payload = DecodeSegment(compactResponse, 1);
        IReadOnlyDictionary<string, object> metadata =
            (IReadOnlyDictionary<string, object>)payload["metadata"];
        Assert.HasCount(1, metadata,
            "The metadata holds the member of the one named Entity Type only.");
        Assert.IsTrue(metadata.ContainsKey("openid_provider"),
            "The metadata holds the openid_provider member that was named.");
    }


    /// <summary>
    /// Reads an Entity Type sent twice as one named Entity Type: the resolution delegate receives it
    /// as its filter, and the response's <c>metadata</c> holds that Entity Type's member only.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "The entity_type request parameter MAY occur multiple times, in which case, data for each Entity
    /// Type whose Entity Type Identifier is in an entity_type parameter value is returned."
    /// </summary>
    [TestMethod]
    public async Task AnEntityTypeSentTwiceNamesOneEntityTypeAsync()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        EntityTypeIdentifier? observedType = null;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, entityTypeFilter, _, _, _) =>
                {
                    observedType = entityTypeFilter;

                    return ValueTask.FromResult<FederationResolveOutcome?>(
                        FederationResolveOutcome.Resolved(new ResolveResponseContribution
                        {
                            Metadata = ThreeEntityTypesMetadata()
                        }));
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        string query =
            $"?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}"
            + "&entity_type=openid_provider"
            + "&entity_type=openid_provider";

        string compactResponse = await GetResolveAsync(
            host, $"/connect/{segment}/federation_resolve{query}").ConfigureAwait(false);

        Assert.IsNotNull(observedType, "An Entity Type sent twice names one Entity Type, the delegate's filter.");
        Assert.AreEqual("openid_provider", observedType.Value.Value,
            "The resolution delegate receives the Entity Type sent twice as its filter.");

        Dictionary<string, object> payload = DecodeSegment(compactResponse, 1);
        IReadOnlyDictionary<string, object> metadata =
            (IReadOnlyDictionary<string, object>)payload["metadata"];
        Assert.HasCount(1, metadata,
            "The metadata holds the member of the one named Entity Type only.");
        Assert.IsTrue(metadata.ContainsKey("openid_provider"),
            "The metadata holds the openid_provider member that was named.");
    }


    /// <summary>
    /// Refuses a resolve request whose first <c>trust_anchor</c> occurrence is white space only with
    /// 400 <c>invalid_request</c> naming <c>trust_anchor</c>, before the resolution delegate runs: an
    /// occurrence of white space only carries a value, it is the first valued occurrence, and it is not
    /// an Entity Identifier.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "REQUIRED. The Trust Anchor that the resolve endpoint MUST use when resolving the metadata. The
    /// value is an Entity Identifier."
    /// </summary>
    [TestMethod]
    public async Task AWhiteSpaceTrustAnchorBeforeAValidOneIsRefusedAsync()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        bool isDelegateInvoked = false;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) =>
                {
                    isDelegateInvoked = true;

                    return ValueTask.FromResult<FederationResolveOutcome?>(
                        FederationResolveOutcome.Resolved(new ResolveResponseContribution
                        {
                            Metadata = RelyingPartyMetadata()
                        }));
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + "&trust_anchor=%20"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode,
            $"A first trust_anchor of white space only is not an Entity Identifier. Got: {body}");
        Assert.Contains("\"error\":\"invalid_request\"", body, StringComparison.Ordinal,
            $"A trust_anchor that is not an Entity Identifier is an invalid_request. Got: {body}");
        Assert.Contains("trust_anchor parameter is not a valid Entity Identifier", body, StringComparison.Ordinal,
            $"The description names the trust_anchor parameter. Got: {body}");
        Assert.IsFalse(isDelegateInvoked,
            "The resolution delegate must not run for a trust_anchor that is not an Entity Identifier.");
    }


    /// <summary>
    /// Refuses a resolve request whose <c>entity_type</c> is white space only with 400
    /// <c>invalid_request</c> naming <c>entity_type</c>, before the resolution delegate runs: an
    /// occurrence of white space only carries a value, and the value is not an Entity Type Identifier.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.1">Federation section 8.3.1</see>:
    /// "Its value is an Entity Type Identifier, as specified in Section 5.1."
    /// </summary>
    [TestMethod]
    public async Task AWhiteSpaceEntityTypeIsRefusedAsync()
    {
        await using TestHostShell app = new(TimeProvider);

        Uri resolverEntityId = new("https://resolver.example.com");
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial resolverKeys = await RegisterResolverAsync(app, resolverEntityId, federationKeys).ConfigureAwait(false);

        bool isDelegateInvoked = false;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectTrustChainAsync =
                (_, _, _, _, _, _) =>
                {
                    isDelegateInvoked = true;

                    return ValueTask.FromResult<FederationResolveOutcome?>(
                        FederationResolveOutcome.Resolved(new ResolveResponseContribution
                        {
                            Metadata = RelyingPartyMetadata()
                        }));
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = resolverKeys.Registration.TenantId.Value;
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_resolve?sub={Uri.EscapeDataString("https://leaf.example.com")}"
            + $"&trust_anchor={Uri.EscapeDataString("https://anchor.example.com")}"
            + "&entity_type=%20");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode,
            $"An entity_type of white space only is not an Entity Type Identifier. Got: {body}");
        Assert.Contains("\"error\":\"invalid_request\"", body, StringComparison.Ordinal,
            $"An entity_type that is not an Entity Type Identifier is an invalid_request. Got: {body}");
        Assert.Contains("entity_type parameter is not a valid Entity Type Identifier", body, StringComparison.Ordinal,
            $"The description names the entity_type parameter. Got: {body}");
        Assert.IsFalse(isDelegateInvoked,
            "The resolution delegate must not run for an entity_type that is not an Entity Type Identifier.");
    }


    /// <summary>
    /// The resolved metadata of a subject that is an OpenID Relying Party only, keyed by its
    /// Entity Type Identifier.
    /// </summary>
    /// <returns>The <c>metadata</c> object a resolution delegate returns.</returns>
    private static Dictionary<string, object> RelyingPartyMetadata() =>
        new(StringComparer.Ordinal)
        {
            ["openid_relying_party"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["client_name"] = "Leaf RP"
            }
        };


    /// <summary>
    /// The resolved metadata of a subject that is an OpenID Relying Party, an OpenID Provider and a
    /// Federation Entity, keyed by its three Entity Type Identifiers; the rows on the
    /// <c>entity_type</c> parameter return it from a resolution delegate that leaves its filter
    /// unapplied, so the response shows which members the endpoint keeps.
    /// </summary>
    /// <returns>The <c>metadata</c> object a resolution delegate returns.</returns>
    private static Dictionary<string, object> ThreeEntityTypesMetadata() =>
        new(StringComparer.Ordinal)
        {
            ["openid_relying_party"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["client_name"] = "Leaf RP"
            },
            ["openid_provider"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["issuer"] = "https://leaf.example.com"
            },
            ["federation_entity"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["organization_name"] = "Leaf Organization"
            }
        };


    /// <summary>
    /// Registers the resolver as a federation-capable client of <paramref name="app"/> that offers
    /// the resolve endpoint, its JWKS and its discovery document, signing with
    /// <paramref name="federationKeys"/>.
    /// </summary>
    /// <param name="app">The host the resolver is registered on.</param>
    /// <param name="resolverEntityId">The resolver's Entity Identifier, its client identifier and base URI.</param>
    /// <param name="federationKeys">The resolver's federation signing material.</param>
    /// <returns>The resolver's registration and signing material.</returns>
    private static async Task<VerifierKeyMaterial> RegisterResolverAsync(
        TestHostShell app,
        Uri resolverEntityId,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.ResolveTrustChain);

        return await app.RegisterFederationCapableClientAsync(
            clientId: resolverEntityId.ToString(),
            baseUri: resolverEntityId,
            federationEntityId: resolverEntityId,
            federationSigningKeyPair: federationKeys,
            baseCapabilities: capabilities).ConfigureAwait(false);
    }


    /// <summary>
    /// Sends a GET to the resolve endpoint over the loopback listener and returns the body, asserting
    /// a 200 answer that serves a Resolve Response.
    /// </summary>
    /// <param name="host">The hosted authorization server whose listener serves the request.</param>
    /// <param name="absolutePath">The path and query of the resolve request.</param>
    /// <returns>The compact Resolve Response JWT.</returns>
    private async ValueTask<string> GetResolveAsync(HostedAuthorizationServer host, string absolutePath)
    {
        Uri url = new(host.HttpBaseAddress!, absolutePath);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            $"GET {absolutePath} must return 200. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");

        string? actualContentType = response.Content.Headers.ContentType?.MediaType;
        Assert.AreEqual(WellKnownMediaTypes.Application.ResolveResponseJwt, actualContentType,
            $"GET {absolutePath} must serve {WellKnownMediaTypes.Application.ResolveResponseJwt}.");

        return await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Decodes one segment of a compact JWS into a dictionary of its members, asserting the
    /// three-segment shape.
    /// </summary>
    /// <param name="compactJws">The compact JWS.</param>
    /// <param name="index">The segment to decode: 0 the header, 1 the payload.</param>
    /// <returns>The segment's members.</returns>
    private static Dictionary<string, object> DecodeSegment(string compactJws, int index)
    {
        string[] parts = compactJws.Split('.');
        Assert.HasCount(3, parts,
            "A Resolve Response must be a JWS compact serialization with three segments.");

        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[index], Pool);

        //The test serialization options project JSON onto native CLR types —
        //strings, Int64, nested Dictionary<string, object>, List<object> —
        //so the claims read back in the shape the application supplied.
        return JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes.Memory.Span, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("JWS segment parsed to null.");
    }
}

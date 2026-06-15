using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core.SecurityEvents;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Ssf;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// HTTP wire tests for OAuth 2.0 Protected Resource Metadata (RFC 9728): the
/// document is served with <c>200 OK</c> and <c>application/json</c> (§3.2)
/// at the well-known URL formed by inserting the path suffix between the host
/// and the resource identifier's path (§3), carries the §2 parameter set with
/// zero-value parameters omitted, embeds the application-signed
/// <c>signed_metadata</c> JWT (§2.2), and survives the consumer's §3.3
/// resource-match validation by construction. The consumer side runs the
/// shipped strict parser from wire bytes alone.
/// </summary>
[TestClass]
internal sealed class ProtectedResourceMetadataTests
{
    private const string ClientId = "https://resource.example.com";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();


    [TestMethod]
    public async Task DocumentServesAtInsertedWellKnownLocationAndValidates()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = RegisterProtectedResource(app);

        app.Server.OAuth().ContributeProtectedResourceMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new ProtectedResourceMetadataContribution
            {
                AuthorizationServers = ["https://as.example.com"],
                ScopesSupported = [WellKnownScopes.SsfRead, WellKnownScopes.SsfManage],
                BearerMethodsSupported = [BearerMethodValues.Header],
                ResourceName = "Example Signals Transmitter",
                LocalizedParameters = new Dictionary<string, string>
                {
                    [$"{ProtectedResourceMetadataParameterNames.ResourceName}#fi"] = "Esimerkkilähetin"
                },
                DpopBoundAccessTokensRequired = true
            });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = resource.Registration.TenantId.Value;

        //The consumer flow: learn the resource identifier (here from the
        //co-located discovery document's issuer), form the metadata URL per
        //§3 by path insertion, fetch, parse strictly, and validate §3.3. The
        //identifier is the fixture's logical identity; the request rides its
        //§3 path on the test listener (the deployment's transport mapping).
        string issuer = await FetchIssuerAsync(host, segment).ConfigureAwait(false);
        Uri metadataUrl = WellKnownPaths.OAuthProtectedResource.ComputeUri(issuer);
        Assert.StartsWith("/.well-known/oauth-protected-resource/", metadataUrl.AbsolutePath,
            "§3: the suffix is inserted between host and path, not appended.");

        using HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(new Uri(host.HttpBaseAddress!, metadataUrl.AbsolutePath), TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType);

        ProtectedResourceMetadata? metadata =
            ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(body);
        Assert.IsNotNull(metadata);

        //§3.3: the resource value MUST be identical to the identifier the
        //metadata URL was derived from; a different identifier MUST fail.
        Assert.IsTrue(ProtectedResourceMetadataValidation.IsResourceMatch(metadata, issuer));
        Assert.IsFalse(ProtectedResourceMetadataValidation.IsResourceMatch(metadata, "https://attacker.example.com"));

        //§2 content: contributed values, the chain-derived jwks_uri, and the
        //§2.1 language-tagged variant.
        Assert.IsNotNull(metadata.ScopesSupported);
        Assert.Contains(WellKnownScopes.SsfManage, metadata.ScopesSupported!);
        Assert.IsNotNull(metadata.AuthorizationServers);
        Assert.AreEqual("https://as.example.com", metadata.AuthorizationServers![0]);
        Assert.IsNotNull(metadata.BearerMethodsSupported);
        Assert.IsTrue(BearerMethodValues.IsDefined(metadata.BearerMethodsSupported![0]));
        Assert.AreEqual("Example Signals Transmitter", metadata.ResourceName);
        Assert.IsTrue(metadata.DpopBoundAccessTokensRequired);
        Assert.IsNotNull(metadata.JwksUri, "jwks_uri is derived from the endpoint chain.");

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual("Esimerkkilähetin",
            doc.RootElement.GetProperty($"{ProtectedResourceMetadataParameterNames.ResourceName}#fi").GetString(),
            "§2.1: the language-tagged variant rides the document verbatim.");

        //§3.2: parameters with zero values are omitted from the response.
        Assert.IsFalse(doc.RootElement.TryGetProperty(
            ProtectedResourceMetadataParameterNames.ResourceTosUri, out _),
            "A parameter without a value must be omitted, not emitted as null.");
        Assert.IsFalse(doc.RootElement.TryGetProperty(
            ProtectedResourceMetadataParameterNames.SignedMetadata, out _),
            "signed_metadata is omitted when no signer seam is wired.");
    }


    [TestMethod]
    public async Task SignedMetadataEmbedsTheSignerOutputWithTheDocumentClaims()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = RegisterProtectedResource(app);

        app.Server.OAuth().ContributeProtectedResourceMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new ProtectedResourceMetadataContribution
            {
                ScopesSupported = [WellKnownScopes.SsfRead]
            });

        //Capture the claim set the library hands over and return a sentinel
        //JWS — the library's contract is "assemble the correct claims, embed
        //the returned JWT"; the key and algorithm are the application's.
        JwtPayload? signedClaims = null;
        app.Server.OAuth().SignProtectedResourceMetadataAsync = (claims, _, _, _) =>
        {
            signedClaims = claims;
            return ValueTask.FromResult<string?>("header.payload.signature");
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = resource.Registration.TenantId.Value;

        string issuer = await FetchIssuerAsync(host, segment).ConfigureAwait(false);
        Uri metadataUrl = WellKnownPaths.OAuthProtectedResource.ComputeUri(issuer);
        using HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(new Uri(host.HttpBaseAddress!, metadataUrl.AbsolutePath), TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        ProtectedResourceMetadata? metadata =
            ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(body);
        Assert.IsNotNull(metadata);
        Assert.AreEqual("header.payload.signature", metadata!.SignedMetadata,
            "The signer's JWT is embedded verbatim as signed_metadata.");

        //§2.2: the claim set mirrors the plain document and never contains a
        //signed_metadata claim itself.
        Assert.IsNotNull(signedClaims, "The signer must be invoked.");
        Assert.AreEqual(metadata.Resource,
            signedClaims![ProtectedResourceMetadataParameterNames.Resource],
            "The signed resource claim is byte-identical to the advertised value.");
        Assert.IsTrue(signedClaims.ContainsKey(ProtectedResourceMetadataParameterNames.ScopesSupported));
        Assert.IsFalse(signedClaims.ContainsKey(ProtectedResourceMetadataParameterNames.SignedMetadata),
            "§2.2: signed_metadata SHOULD NOT appear as a claim in the JWT.");
    }


    [TestMethod]
    public async Task FailsClosedWithoutTheCapability()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial bare = app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = bare.Registration.TenantId.Value;

        string issuer = await FetchIssuerAsync(host, segment).ConfigureAwait(false);
        Uri metadataUrl = WellKnownPaths.OAuthProtectedResource.ComputeUri(issuer);
        using HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(new Uri(host.HttpBaseAddress!, metadataUrl.AbsolutePath), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreNotEqual(200, (int)response.StatusCode,
            "Without the capability the metadata endpoint must not exist.");
    }


    [TestMethod]
    public async Task UnauthorizedResourceRequestAdvertisesMetadataAndCompletesDiscovery()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.SsfTransmitter,
                WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        //The SSF transmitter is the resource server: its stream endpoint
        //requires a bearer token, and its RFC 9728 document advertises the
        //SSF scopes — the CAEP interop scope-discovery story.
        app.Server.OAuth().UseDefaultSsfJsonParsing();
        app.Server.OAuth().CreateSsfStreamAsync = static (request, registration, context, ct) =>
            ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.Forbidden));
        app.Server.OAuth().AuthorizeSsfRequestAsync = static (request, requiredScope, registration, context, ct) =>
            ValueTask.FromResult(SsfRequestAuthorization.Unauthorized);
        app.Server.OAuth().ContributeProtectedResourceMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new ProtectedResourceMetadataContribution
            {
                ScopesSupported = [WellKnownScopes.SsfRead, WellKnownScopes.SsfManage]
            });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = resource.Registration.TenantId.Value;

        //Step 1 (§5, figure 1): the resource request without an access token.
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/stream");
        using StringContent createBody = new("""{"delivery":null}""", Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage denied = await host.SharedHttpClient!
            .PostAsync(streamUrl, createBody, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)denied.StatusCode);

        //Step 2: the 401 carries the WWW-Authenticate challenge with the
        //resource_metadata URL (§5.1).
        Assert.IsTrue(denied.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "The 401 must carry a WWW-Authenticate challenge.");
        string challenge = challenges!.Single();
        Assert.StartsWith(WellKnownAuthenticationSchemes.Bearer, challenge);

        string? metadataUrlValue = ProtectedResourceChallenge.TryReadResourceMetadata(challenge);
        Assert.IsNotNull(metadataUrlValue, $"The challenge must carry resource_metadata. Header: {challenge}");

        //The advertised URL is the §3 path-inserted location derived from the
        //same identity the document's resource value carries.
        string issuer = resource.Registration.IssuerUri!.OriginalString;
        Assert.AreEqual(
            WellKnownPaths.OAuthProtectedResource.ComputeUri(issuer).OriginalString,
            metadataUrlValue);

        //Steps 3–5: fetch the metadata (the deployment maps the logical host
        //to the test listener; the §3 path carries through), parse strictly,
        //and validate §3.3 against the identity the URL derives from.
        Uri advertised = new(metadataUrlValue!);
        using HttpResponseMessage metadataResponse = await host.SharedHttpClient!
            .GetAsync(new Uri(host.HttpBaseAddress!, advertised.AbsolutePath), TestContext.CancellationToken)
            .ConfigureAwait(false);
        string metadataBody = await metadataResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)metadataResponse.StatusCode, metadataBody);

        ProtectedResourceMetadata? metadata =
            ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(metadataBody);
        Assert.IsNotNull(metadata);
        Assert.IsTrue(ProtectedResourceMetadataValidation.IsResourceMatch(metadata, issuer));

        //The Receiver has now discovered the scopes to request from the
        //authorization server — the CAEP interop profile's conditional
        //"discover scopes via RFC 9728" is satisfiable end to end.
        Assert.Contains(WellKnownScopes.SsfManage, metadata!.ScopesSupported!);
    }


    [TestMethod]
    public async Task UnauthorizedRequestOmitsChallengeParameterWithoutTheMetadataCapability()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.SsfTransmitter,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        app.Server.OAuth().UseDefaultSsfJsonParsing();
        app.Server.OAuth().CreateSsfStreamAsync = static (request, registration, context, ct) =>
            ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.Forbidden));
        app.Server.OAuth().AuthorizeSsfRequestAsync = static (request, requiredScope, registration, context, ct) =>
            ValueTask.FromResult(SsfRequestAuthorization.Unauthorized);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = resource.Registration.TenantId.Value;

        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/stream");
        using StringContent createBody = new("""{"delivery":null}""", Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage denied = await host.SharedHttpClient!
            .PostAsync(streamUrl, createBody, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)denied.StatusCode);

        //Fail-closed advertising: without the metadata capability the URL
        //would 404, so the challenge parameter is not emitted.
        bool hasChallenge = denied.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? values);
        if(hasChallenge)
        {
            Assert.IsNull(ProtectedResourceChallenge.TryReadResourceMetadata(values!.Single()),
                "resource_metadata must not point at a document that is not served.");
        }
    }


    [TestMethod]
    public void ChallengeParsingFollowsTheAuthParamGrammar()
    {
        //Quoted string among other auth-params, any position (§5.1: MAY be
        //combined with other parameters).
        Assert.AreEqual("https://rs.example.com/.well-known/oauth-protected-resource",
            ProtectedResourceChallenge.TryReadResourceMetadata(
                "Bearer realm=\"api\", resource_metadata=\"https://rs.example.com/.well-known/oauth-protected-resource\", error=\"invalid_token\""));

        //Parameter names compare case-insensitively (RFC 9110 §11.2).
        Assert.AreEqual("https://rs.example.com/meta",
            ProtectedResourceChallenge.TryReadResourceMetadata("DPoP Resource_Metadata=\"https://rs.example.com/meta\""));

        //Token form (unquoted) is valid auth-param syntax.
        Assert.AreEqual("https://rs.example.com/meta",
            ProtectedResourceChallenge.TryReadResourceMetadata("Bearer resource_metadata=https://rs.example.com/meta"));

        //Quoted-pair unescaping.
        Assert.AreEqual("https://rs.example.com/a\"b",
            ProtectedResourceChallenge.TryReadResourceMetadata("Bearer resource_metadata=\"https://rs.example.com/a\\\"b\""));

        //A name that merely contains the parameter as a suffix is not it.
        Assert.IsNull(ProtectedResourceChallenge.TryReadResourceMetadata(
            "Bearer x_resource_metadata=\"https://attacker.example.com\""));

        //Absent and malformed shapes yield null, never a wrong value.
        Assert.IsNull(ProtectedResourceChallenge.TryReadResourceMetadata("Bearer realm=\"api\""));
        Assert.IsNull(ProtectedResourceChallenge.TryReadResourceMetadata(
            "Bearer resource_metadata=\"https://unterminated.example.com"));

        //The round trip with the builder.
        string built = ProtectedResourceChallenge.BuildChallenge(
            WellKnownAuthenticationSchemes.Bearer,
            new Uri("https://rs.example.com/.well-known/oauth-protected-resource/tenant-1"));
        Assert.AreEqual("https://rs.example.com/.well-known/oauth-protected-resource/tenant-1",
            ProtectedResourceChallenge.TryReadResourceMetadata(built));
    }


    [TestMethod]
    public void StrictParserRejectsStructuralFailures()
    {
        //§2: resource is REQUIRED.
        Assert.IsNull(ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata("{}"));

        //Not a JSON object.
        Assert.IsNull(ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata("[]"));
        Assert.IsNull(ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata("not json"));

        //A wrongly-typed known field fails the parse rather than being coerced.
        Assert.IsNull(ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(
            $$"""{"resource": "https://r.example.com", "{{ProtectedResourceMetadataParameterNames.ScopesSupported}}": "not-an-array"}"""));

        //Unknown parameters are ignored per §3.2.
        ProtectedResourceMetadata? metadata = ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(
            """{"resource": "https://r.example.com", "x-extension": {"nested": true}}""");
        Assert.IsNotNull(metadata);
        Assert.AreEqual("https://r.example.com", metadata!.Resource);
    }


    /// <summary>
    /// Registers a protected resource co-located with the server: the RFC 9728
    /// metadata capability plus discovery and JWKS so the consumer can learn
    /// the resource identifier and the document can advertise <c>jwks_uri</c>.
    /// </summary>
    private static VerifierKeyMaterial RegisterProtectedResource(TestHostShell app) =>
        app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));


    /// <summary>
    /// Learns the tenant's issuer identity from the co-located discovery
    /// document — the resource identifier the §3 metadata URL derives from.
    /// </summary>
    private async Task<string> FetchIssuerAsync(HostedAuthorizationServer host, string segment)
    {
        Uri discoveryUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/openid-configuration");
        using HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(discoveryUrl, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty("issuer").GetString()!;
    }
}

using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Ssf;
using Verifiable.Tests.TestInfrastructure;

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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);


    /// <summary>
    /// Checks that metadata at the path-inserted location matches the resource identifier determining that location.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 §3.3</see>.
    /// </summary>
    [TestMethod]
    public async Task DocumentServesAtInsertedWellKnownLocationAndValidates()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = await RegisterProtectedResourceAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeProtectedResourceMetadataAsync = static (_, _, _, _) =>
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
        }).ConfigureAwait(false);

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


    /// <summary>
    /// Checks that signed_metadata embeds the signer's output for the document claims without recursively including itself.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.2">RFC 9728 §2.2</see>.
    /// </summary>
    [TestMethod]
    public async Task SignedMetadataEmbedsTheSignerOutputWithTheDocumentClaims()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = await RegisterProtectedResourceAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeProtectedResourceMetadataAsync = static (_, _, _, _) =>
                ValueTask.FromResult(new ProtectedResourceMetadataContribution
                {
                    ScopesSupported = [WellKnownScopes.SsfRead]
                });
        }).ConfigureAwait(false);

        //Capture the claim set the library hands over and return a sentinel
        //JWS — the library's contract is "assemble the correct claims, embed
        //the returned JWT"; the key and algorithm are the application's.
        JwtPayload? signedClaims = null;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.SignProtectedResourceMetadataAsync = (claims, _, _, _) =>
            {
                signedClaims = claims;

                return ValueTask.FromResult<string?>("header.payload.signature");
            };
        }).ConfigureAwait(false);

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


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>: "The empty array [] can be
    /// used to indicate that no bearer methods are supported." and "dpop_bound_access_tokens_required OPTIONAL. Boolean
    /// value specifying whether the protected resource always requires the use of DPoP-bound access tokens [RFC9449].",
    /// with <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.2">Section 2.2</see>: "signed_metadata A JWT
    /// containing metadata parameters about the protected resource as claims." The issuer's document describes the
    /// resource the issuer identifies, which the requirement of the server's own resources does not govern. At a server
    /// whose resources require DPoP-bound access tokens, a resource contributing an empty
    /// <c>bearer_methods_supported</c> serves, over the wire, a document whose <c>signed_metadata</c> is the signer's
    /// JWT, and the claims handed to the signer carry <c>bearer_methods_supported</c> as the contributed empty list and
    /// no <c>dpop_bound_access_tokens_required</c>, the values the plain document carries.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task SignedMetadataCarriesTheContributedBearerMethodsUnderTheResourcesRequirementAsync()
    {
        JwtPayload? signedClaims = null;
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = await RegisterProtectedResourceAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeProtectedResourceMetadataAsync = (_, _, _, _) =>
                ValueTask.FromResult(new ProtectedResourceMetadataContribution { BearerMethodsSupported = [] });
        }).ConfigureAwait(false);
        await RequireDpopBoundAccessTokensAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.SignProtectedResourceMetadataAsync = (claims, _, _, _) =>
            {
                signedClaims = claims;

                return ValueTask.FromResult<string?>("header.payload.signature");
            };
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string issuer = await FetchIssuerAsync(host, resource.Registration.TenantId.Value).ConfigureAwait(false);
        Uri metadataUrl = WellKnownPaths.OAuthProtectedResource.ComputeUri(issuer);

        using HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(new Uri(host.HttpBaseAddress!, metadataUrl.AbsolutePath), TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.ConsumeHttpFaults(), "The document is served without a server fault.");
        Assert.AreEqual(200, (int)response.StatusCode, body);
        ProtectedResourceMetadata? metadata = ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(body);
        Assert.Contains("\"bearer_methods_supported\":[]", body, StringComparison.Ordinal, body);
        Assert.IsNotNull(metadata);
        Assert.AreEqual("header.payload.signature", metadata.SignedMetadata, "The signer's JWT is embedded verbatim as signed_metadata.");
        Assert.IsNotNull(signedClaims, "The signer must be invoked.");
        Assert.IsTrue(signedClaims.TryGetValue(ProtectedResourceMetadataParameterNames.BearerMethodsSupported, out object? bearerMethods),
            "The signed claims carry bearer_methods_supported.");
        Assert.IsEmpty(Assert.IsInstanceOfType<IReadOnlyList<string>>(bearerMethods), "The signed bearer_methods_supported is the empty list.");
        Assert.IsFalse(signedClaims.ContainsKey(ProtectedResourceMetadataParameterNames.DpopBoundAccessTokensRequired),
            "The signed claims carry no dpop_bound_access_tokens_required the contribution does not state.");
    }


    [TestMethod]
    public async Task FailsClosedWithoutTheCapability()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial bare = await app.RegisterClientAsync(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

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


    /// <summary>
    /// Checks that an authorization challenge supplies a metadata URL whose fetched document identifies the resource.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 §5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task UnauthorizedResourceRequestAdvertisesMetadataAndCompletesDiscovery()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = await app.RegisterClientAsync(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.SsfTransmitter,
                WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        //The SSF transmitter is the resource server: its stream endpoint
        //requires a bearer token, and its RFC 9728 document advertises the
        //SSF scopes — the CAEP interop scope-discovery story.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultSsfJsonParsing();


            candidateIntegration.CreateSsfStreamAsync = static (request, registration, receiver, context, ct) =>
                ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.Forbidden));

            candidateIntegration.AuthorizeSsfRequestAsync = static (evaluation, registration, context, ct) =>
                ValueTask.FromResult(SsfRequestDecision.Deny(SsfRequestDenialReason.AuthenticationRequired));

            candidateIntegration.ContributeProtectedResourceMetadataAsync = static (_, _, _, _) =>
                ValueTask.FromResult(new ProtectedResourceMetadataContribution
                {
                    ScopesSupported = [WellKnownScopes.SsfRead, WellKnownScopes.SsfManage]
                });
        }).ConfigureAwait(false);

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


    /// <summary>
    /// Checks that the application omits the metadata challenge parameter when its endpoint is disabled.
    /// <see href="../../../documents/AuthorizationServerDesign.md#22-endpoint-chain-stage">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task UnauthorizedRequestOmitsChallengeParameterWithoutTheMetadataCapability()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = await app.RegisterClientAsync(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.SsfTransmitter,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultSsfJsonParsing();


            candidateIntegration.CreateSsfStreamAsync = static (request, registration, receiver, context, ct) =>
                ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.Forbidden));

            candidateIntegration.AuthorizeSsfRequestAsync = static (evaluation, registration, context, ct) =>
                ValueTask.FromResult(SsfRequestDecision.Deny(SsfRequestDenialReason.AuthenticationRequired));
        }).ConfigureAwait(false);

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
        Assert.AreEqual("https://r.example.com", metadata.Resource);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 Section 8.1</see>: "JSON text exchanged
    /// between systems that are not part of a closed ecosystem MUST be encoded using UTF-8 [RFC3629]." The bytes of a JSON
    /// object naming its <c>resource</c> whose member <c>other</c>, one the reading does not know, holds the octet
    /// <c>0xFF</c>, which no UTF-8 sequence holds, are read by the bytes overload as no document.
    /// </summary>
    [TestMethod]
    public void StrictBytesParserReadsABodyThatIsNotUtf8AsNoDocument()
    {
        Assert.IsNull(ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(NotUtf8DocumentOf("https://x/r")));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>,
    /// <c>bearer_methods_supported</c>: "If this entry is omitted, no default bearer methods supported are implied,
    /// nor does its absence indicate that they are not supported." A resource whose contribution names no bearer
    /// method serves, over the wire, a document without the member, and the consumer's reading of the document
    /// holds no list for it: neither a default method nor an empty list standing for none.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ConsumerReadsAnOmittedBearerMethodsSupportedAsNoListAtAllAsync()
    {
        (string body, ProtectedResourceMetadata? metadata) = await FetchContributedDocumentAsync(new ProtectedResourceMetadataContribution
        {
            ScopesSupported = [WellKnownScopes.SsfRead]
        }).ConfigureAwait(false);

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsFalse(document.RootElement.TryGetProperty(ProtectedResourceMetadataParameterNames.BearerMethodsSupported, out _),
            "The served document omits bearer_methods_supported.");
        Assert.IsNotNull(metadata);
        Assert.IsNull(metadata.BearerMethodsSupported, "An omitted bearer_methods_supported implies no default and no empty list.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>, <c>bearer_methods_supported</c>:
    /// "The empty array [] can be used to indicate that no bearer methods are supported.", the named exception to
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">Section 3.2</see>'s "Parameters with zero values
    /// MUST be omitted from the response." A resource contributing an empty <c>bearer_methods_supported</c> list serves,
    /// over the wire, a document carrying <c>"bearer_methods_supported":[]</c>, and the consumer reads an empty list,
    /// not an omitted member.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DocumentPublishesAnEmptyBearerMethodsSupportedAsync()
    {
        (string body, ProtectedResourceMetadata? metadata) = await FetchContributedDocumentAsync(new ProtectedResourceMetadataContribution
        {
            BearerMethodsSupported = []
        }).ConfigureAwait(false);

        Assert.Contains("\"bearer_methods_supported\":[]", body, StringComparison.Ordinal, body);
        Assert.IsNotNull(metadata);
        Assert.IsNotNull(metadata.BearerMethodsSupported, "The consumer reads the empty list as stated, not as omitted.");
        Assert.IsEmpty(metadata.BearerMethodsSupported);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_signing_alg_values_supported OPTIONAL. JSON array containing a list of the JWS alg values (from the
    /// "JSON Web Signature and Encryption Algorithms" registry [IANA.JOSE]) supported by the resource server for
    /// validating Demonstrating Proof of Possession (DPoP) proof JWTs [RFC9449]." A resource contributing
    /// <c>ES256</c> and <c>EdDSA</c> serves, over the wire, a document whose
    /// <c>dpop_signing_alg_values_supported</c> is the JSON array <c>["ES256","EdDSA"]</c>, and the consumer reads
    /// the same two values in the same order.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DocumentPublishesTheDpopSigningAlgorithmsTheResourceSupportsAsync()
    {
        (string body, ProtectedResourceMetadata? metadata) = await FetchContributedDocumentAsync(new ProtectedResourceMetadataContribution
        {
            DpopSigningAlgValuesSupported = ContributedDpopAlgorithms
        }).ConfigureAwait(false);

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsTrue(document.RootElement.TryGetProperty(
            ProtectedResourceMetadataParameterNames.DpopSigningAlgValuesSupported, out JsonElement algorithms),
            "The served document carries dpop_signing_alg_values_supported.");
        Assert.AreEqual(JsonValueKind.Array, algorithms.ValueKind, "The member is a JSON array.");
        Assert.AreSequenceEqual(ContributedDpopAlgorithms, algorithms.EnumerateArray().Select(static value => value.GetString()).ToArray());
        Assert.IsNotNull(metadata);
        Assert.IsNotNull(metadata.DpopSigningAlgValuesSupported);
        Assert.AreSequenceEqual(ContributedDpopAlgorithms, metadata.DpopSigningAlgValuesSupported.ToArray());
    }


    /// <summary>The JWS algorithms the resource of <see cref="DocumentPublishesTheDpopSigningAlgorithmsTheResourceSupportsAsync"/> contributes, in order.</summary>
    private static string[] ContributedDpopAlgorithms { get; } = ["ES256", "EdDSA"];


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_signing_alg_values_supported OPTIONAL. JSON array containing a list of the JWS alg values (from the "JSON
    /// Web Signature and Encryption Algorithms" registry [IANA.JOSE]) supported by the resource server for validating
    /// Demonstrating Proof of Possession (DPoP) proof JWTs [RFC9449]." At a server that validates DPoP proofs, a resource
    /// whose contribution names no such list serves, over the wire, a document whose
    /// <c>dpop_signing_alg_values_supported</c> is exactly the list the server holds every proof to. The rows: the
    /// default list, <c>["ES256","ES384","ES512","ES256K","RS256","RS384","RS512","PS256","PS384","PS512","EdDSA","Ed25519"]</c>;
    /// the server's accepted list narrowed to <c>["ES384","EdDSA"]</c>.
    /// </summary>
    /// <param name="row">The server's accepted list: <see cref="DefaultAcceptedListRow"/> or <see cref="NarrowedAcceptedListRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(DefaultAcceptedListRow)]
    [DataRow(NarrowedAcceptedListRow)]
    public async Task DocumentPublishesTheDpopAlgorithmsTheServerAcceptsAsync(string row)
    {
        string[] expected = row switch
        {
            DefaultAcceptedListRow => ["ES256", "ES384", "ES512", "ES256K", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA", "Ed25519"],
            NarrowedAcceptedListRow => ["ES384", "EdDSA"],
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown accepted list row.")
        };

        (string body, ProtectedResourceMetadata? metadata) = await FetchContributedDocumentAsync(
            ProtectedResourceMetadataContribution.Empty,
            async app =>
            {
                _ = await app.EnableDpopAsync().ConfigureAwait(false);
                if(string.Equals(row, NarrowedAcceptedListRow, StringComparison.Ordinal))
                {
                    await app.AcceptDpopProofsUnderAsync(expected).ConfigureAwait(false);
                }
            }).ConfigureAwait(false);

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsTrue(document.RootElement.TryGetProperty(
            ProtectedResourceMetadataParameterNames.DpopSigningAlgValuesSupported, out JsonElement algorithms),
            "The served document carries dpop_signing_alg_values_supported.");
        Assert.AreSequenceEqual(expected, algorithms.EnumerateArray().Select(static value => value.GetString()).ToArray());
        Assert.IsNotNull(metadata);
    }


    /// <summary>
    /// The row whose server holds proofs to the default accepted list. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string DefaultAcceptedListRow = "default-accepted-list";

    /// <summary>
    /// The row whose server holds proofs to an accepted list narrowed to two names. A constant, not a property, because a
    /// DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string NarrowedAcceptedListRow = "narrowed-accepted-list";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>,
    /// <c>dpop_bound_access_tokens_required</c>: "Boolean value specifying whether the protected resource always
    /// requires the use of DPoP-bound access tokens [RFC9449]. If omitted, the default value is false." A resource
    /// whose contribution states nothing for the member serves, over the wire, a document without it, so a consumer
    /// applies the default false. The library's consumer side reads the document and substitutes no value for the
    /// omitted member: its reading holds no stated value, never a <see langword="true"/>, and no operation of the
    /// library applies the default itself, so the consumer half is that reading.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ConsumerReadsAnOmittedDpopBoundAccessTokensRequiredAsNoStatedValueAsync()
    {
        (string body, ProtectedResourceMetadata? metadata) = await FetchContributedDocumentAsync(new ProtectedResourceMetadataContribution
        {
            ScopesSupported = [WellKnownScopes.SsfRead]
        }).ConfigureAwait(false);

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsFalse(document.RootElement.TryGetProperty(ProtectedResourceMetadataParameterNames.DpopBoundAccessTokensRequired, out _),
            "The served document omits dpop_bound_access_tokens_required.");
        Assert.IsNotNull(metadata);
        Assert.IsNull(metadata.DpopBoundAccessTokensRequired, "The consumer reads no stated value and substitutes none.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_bound_access_tokens_required OPTIONAL. Boolean value specifying whether the protected resource always
    /// requires the use of DPoP-bound access tokens [RFC9449]. If omitted, the default value is false." The issuer's
    /// document describes the resource the issuer identifies, which the requirement of the server's own resources does not
    /// govern; those resources state it in their own documents. At a server whose resources require DPoP-bound access
    /// tokens, a resource whose contribution states neither member serves, over the wire, a document carrying neither
    /// <c>dpop_bound_access_tokens_required</c> nor <c>bearer_methods_supported</c>, and the consumer reads no stated value
    /// for either.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task IssuerDocumentStatesOnlyItsContributionUnderTheResourcesRequirementAsync()
    {
        (string body, ProtectedResourceMetadata? metadata) = await FetchContributedDocumentAsync(
            new ProtectedResourceMetadataContribution { ScopesSupported = [WellKnownScopes.SsfRead] },
            RequireDpopBoundAccessTokensAsync).ConfigureAwait(false);

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsFalse(document.RootElement.TryGetProperty(ProtectedResourceMetadataParameterNames.DpopBoundAccessTokensRequired, out _),
            "The issuer's document states no dpop_bound_access_tokens_required its contribution does not state.");
        Assert.IsFalse(document.RootElement.TryGetProperty(ProtectedResourceMetadataParameterNames.BearerMethodsSupported, out _),
            "The issuer's document states no bearer_methods_supported its contribution does not state.");
        Assert.IsNotNull(metadata);
        Assert.IsNull(metadata.DpopBoundAccessTokensRequired);
        Assert.IsNull(metadata.BearerMethodsSupported);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_bound_access_tokens_required OPTIONAL. Boolean value specifying whether the protected resource always
    /// requires the use of DPoP-bound access tokens [RFC9449]."; the issuer's document states what the resource the
    /// issuer identifies does, which the requirement of the server's own resources does not govern. At a server whose
    /// resources require DPoP-bound access tokens, the issuer's document is served over the wire 200 with the
    /// contribution's member as stated. The rows: a contribution stating <c>dpop_bound_access_tokens_required: false</c>,
    /// served as <c>"dpop_bound_access_tokens_required":false</c>; one naming the bearer method <c>header</c>, served as
    /// <c>"bearer_methods_supported":["header"]</c>.
    /// </summary>
    /// <param name="row">The contribution: <see cref="StatesNotRequiredRow"/> or <see cref="NamesABearerMethodRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(StatesNotRequiredRow)]
    [DataRow(NamesABearerMethodRow)]
    public async Task IssuerDocumentServesItsContributionUnderTheResourcesRequirementAsync(string row)
    {
        (ProtectedResourceMetadataContribution contribution, string member) = row switch
        {
            StatesNotRequiredRow => (new ProtectedResourceMetadataContribution { DpopBoundAccessTokensRequired = false },
                "\"dpop_bound_access_tokens_required\":false"),
            NamesABearerMethodRow => (new ProtectedResourceMetadataContribution { BearerMethodsSupported = [BearerMethodValues.Header] },
                "\"bearer_methods_supported\":[\"header\"]"),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown contribution row.")
        };

        (string body, ProtectedResourceMetadata? metadata) = await FetchContributedDocumentAsync(
            contribution, RequireDpopBoundAccessTokensAsync).ConfigureAwait(false);

        Assert.IsNotNull(metadata);
        Assert.Contains(member, body, StringComparison.Ordinal, body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>, <c>jwks_uri</c>: "URL of
    /// the protected resource's JSON Web Key (JWK) Set [JWK] document. ... This URL MUST use the https scheme." A host
    /// whose endpoint resolver answers the JWK Set's URL in the <c>http</c> scheme serves, over the wire, the issuer's
    /// document without a <c>jwks_uri</c> member.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DocumentOmitsAJwksUriThatIsNotHttpsAsync()
    {
        (string body, ProtectedResourceMetadata? metadata) = await FetchContributedDocumentAsync(
            ProtectedResourceMetadataContribution.Empty,
            static app => TestHostShell.AlterAsync(app.Server, static candidateIntegration =>
            {
                ResolveEndpointUriDelegate resolve = candidateIntegration.ResolveEndpointUriAsync!;
                candidateIntegration.ResolveEndpointUriAsync = async (endpointKey, registration, context, cancellationToken) =>
                {
                    Uri? resolved = await resolve(endpointKey, registration, context, cancellationToken).ConfigureAwait(false);

                    return (string.Equals(endpointKey, WellKnownEndpointNames.MetadataJwks, StringComparison.Ordinal), resolved) switch
                    {
                        (true, Uri url) => new Uri("http://" + url.Authority + url.AbsolutePath),
                        _ => resolved
                    };
                };
            })).ConfigureAwait(false);

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsFalse(document.RootElement.TryGetProperty(ProtectedResourceMetadataParameterNames.JwksUri, out _),
            "A jwks_uri that is not https is not written.");
        Assert.IsNotNull(metadata);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>,
    /// <c>resource_signing_alg_values_supported</c>: "No default algorithms are implied if this entry is omitted. The
    /// value none MUST NOT be used." and <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">Section
    /// 3.2</see>: "An error response uses the applicable HTTP status code value." A contribution naming <c>RS256</c> and
    /// <c>none</c> is the server's own wiring at fault: the fetch over the wire is answered 500 with
    /// <c>server_error</c> in the body and no document.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DocumentNamingNoneAmongTheResourceSigningAlgorithmsIsNotServedAsync()
    {
        (string body, _) = await FetchContributedDocumentAsync(
            new ProtectedResourceMetadataContribution { ResourceSigningAlgValuesSupported = ["RS256", "none"] },
            expectedStatusCode: 500).ConfigureAwait(false);

        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("server_error", document.RootElement.GetProperty("error").GetString(), body);
        Assert.IsFalse(document.RootElement.TryGetProperty(ProtectedResourceMetadataParameterNames.Resource, out _), "No document is served.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_signing_alg_values_supported OPTIONAL. JSON array containing a list of the JWS alg values ... supported by the
    /// resource server for validating Demonstrating Proof of Possession (DPoP) proof JWTs [RFC9449].", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.6">RFC 9449 Section 11.6</see>: "In particular, the
    /// algorithm none MUST NOT be allowed." and <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">Section
    /// 4.2</see>: "alg: An identifier for a JWS asymmetric digital signature algorithm". A server validating DPoP proofs
    /// whose host lists <c>ES256</c> and <c>HS256</c> for them serves, over the wire, the issuer's document whose
    /// <c>dpop_signing_alg_values_supported</c> is exactly <c>["ES256"]</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DocumentPublishesOnlyTheAsymmetricDpopAlgorithmsTheHostListsAsync()
    {
        (string body, _) = await FetchContributedDocumentAsync(
            ProtectedResourceMetadataContribution.Empty,
            static async app =>
            {
                _ = await app.EnableDpopAsync().ConfigureAwait(false);
                await app.AcceptDpopProofsUnderAsync(["ES256", "HS256"]).ConfigureAwait(false);
            }).ConfigureAwait(false);

        Assert.Contains("\"dpop_signing_alg_values_supported\":[\"ES256\"]", body, StringComparison.Ordinal, body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_signing_alg_values_supported OPTIONAL. JSON array containing a list of the JWS alg values ... supported by the
    /// resource server for validating Demonstrating Proof of Possession (DPoP) proof JWTs [RFC9449].", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2">RFC 9110 Section 5.6.2</see>: "token = 1*tchar".
    /// A host whose list for DPoP proofs holds a name that is no token beside <c>ES256</c> answers no list a proof can be
    /// validated under, the list a resource's challenges then name no <c>algs</c> for: a server validating DPoP proofs
    /// serves, over the wire, the issuer's document with no <c>dpop_signing_alg_values_supported</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DocumentOmitsTheDpopAlgorithmsWhereTheHostListsANameThatIsNoTokenAsync()
    {
        (string body, _) = await FetchContributedDocumentAsync(
            ProtectedResourceMetadataContribution.Empty,
            static async app =>
            {
                _ = await app.EnableDpopAsync().ConfigureAwait(false);
                await app.AcceptDpopProofsUnderAsync(["ES256", "ES 384"]).ConfigureAwait(false);
            }).ConfigureAwait(false);

        Assert.DoesNotContain(ProtectedResourceMetadataParameterNames.DpopSigningAlgValuesSupported, body, StringComparison.Ordinal, body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see>: "An error response uses
    /// the applicable HTTP status code value." The issuer's document names the issuer as its <c>resource</c>; a server
    /// that cannot resolve the issuer cannot compose it, a fault of the server's own wiring: the GET of the document over
    /// the wire is answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// captured server fault. The rows: the registration's issuer replaced by one the default issuer resolver refuses
    /// (<c>http</c> scheme); an application issuer resolver that answers nothing.
    /// </summary>
    /// <param name="row">Which part of the wiring fails: <see cref="IssuerUnresolvableRow"/> or <see cref="IssuerResolverAnswersNothingRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(IssuerUnresolvableRow)]
    [DataRow(IssuerResolverAnswersNothingRow)]
    public async Task IssuerDocumentWhereNoIssuerResolvesIsAServerErrorAsync(string row)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = await RegisterProtectedResourceAsync(app).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = resource.Registration.TenantId.Value;
        if(string.Equals(row, IssuerResolverAnswersNothingRow, StringComparison.Ordinal))
        {
            await TestHostShell.AlterAsync(app.Server, static candidateIntegration =>
                candidateIntegration.ResolveIssuerAsync = static (_, _, _) => ValueTask.FromResult<Uri?>(null)).ConfigureAwait(false);
        }
        else
        {
            ClientRecord replaced = host.Registrations[segment] with { IssuerUri = new Uri("http://issuer.test/" + segment) };
            host.Registrations[replaced.TenantId.Value] = replaced;
            host.Registrations[replaced.ClientId] = replaced;
        }

        using HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(
                new Uri(host.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.ProtectedResourceMetadata, segment)),
                TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.ConsumeHttpFaults(), "The fetch is answered without a server fault.");
        Assert.AreEqual(500, (int)response.StatusCode, body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", body);
    }


    /// <summary>
    /// The wiring row whose registration names an issuer the default resolver refuses. A constant, not a property,
    /// because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string IssuerUnresolvableRow = "issuer-unresolvable";

    /// <summary>
    /// The wiring row whose application issuer resolver answers nothing. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string IssuerResolverAnswersNothingRow = "issuer-resolver-answers-nothing";


    /// <summary>
    /// The row whose contribution states <c>dpop_bound_access_tokens_required: false</c>. A constant, not a property,
    /// because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string StatesNotRequiredRow = "states-not-required";

    /// <summary>
    /// The row whose contribution names the bearer method <c>header</c>. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    private const string NamesABearerMethodRow = "names-a-bearer-method";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see>: "Parameters with
    /// multiple values are represented as JSON arrays. Parameters with zero values MUST be omitted from the
    /// response." A resource contributing an empty list for <c>authorization_servers</c>, <c>scopes_supported</c>,
    /// <c>resource_signing_alg_values_supported</c>, <c>authorization_details_types_supported</c> and
    /// <c>dpop_signing_alg_values_supported</c> serves, over the wire, a document that carries none of the five.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DocumentOmitsEveryParameterWithZeroValuesAsync()
    {
        (string body, ProtectedResourceMetadata? metadata) = await FetchContributedDocumentAsync(new ProtectedResourceMetadataContribution
        {
            AuthorizationServers = [],
            ScopesSupported = [],
            ResourceSigningAlgValuesSupported = [],
            AuthorizationDetailsTypesSupported = [],
            DpopSigningAlgValuesSupported = []
        }).ConfigureAwait(false);

        Assert.IsNotNull(metadata);
        using JsonDocument document = JsonDocument.Parse(body);
        foreach(string name in (string[])[
            ProtectedResourceMetadataParameterNames.AuthorizationServers,
            ProtectedResourceMetadataParameterNames.ScopesSupported,
            ProtectedResourceMetadataParameterNames.ResourceSigningAlgValuesSupported,
            ProtectedResourceMetadataParameterNames.AuthorizationDetailsTypesSupported,
            ProtectedResourceMetadataParameterNames.DpopSigningAlgValuesSupported])
        {
            Assert.IsFalse(document.RootElement.TryGetProperty(name, out _), $"The parameter '{name}' with zero values is omitted.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "If the protected
    /// resource metadata was retrieved from a URL returned by the protected resource via the WWW-Authenticate
    /// resource_metadata parameter, then the resource value returned MUST be identical to the URL that the client used to
    /// make the request to the resource server.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.2">Section 5.2</see>: "If the client receives such a
    /// WWW-Authenticate response, it SHOULD retrieve the updated protected resource metadata and use the new metadata
    /// values obtained, after validating them as described in Section 3.3." A UserInfo request without credentials sent
    /// over the wire is answered with a challenge naming UserInfo's document; the resolution of that pointer for the URL
    /// the request was sent to fetches the document over the wire and answers it resolved: <c>resource</c> the request
    /// URL, <c>authorization_servers</c> the issuer alone, the twelve DPoP algorithms the server accepts. The rows: the
    /// server's resources not requiring DPoP-bound access tokens (no <c>dpop_bound_access_tokens_required</c>,
    /// <c>bearer_methods_supported</c> <c>["header"]</c>); requiring them (<c>true</c> and <c>[]</c>).
    /// </summary>
    /// <param name="row">The server's wiring: <see cref="ResolutionRequirementUnsetRow"/> or <see cref="ResolutionRequirementSetRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(ResolutionRequirementUnsetRow)]
    [DataRow(ResolutionRequirementSetRow)]
    public async Task ResolutionFromAChallengeReadsTheDocumentThatNamesTheRequestUrlAsync(string row)
    {
        bool isRequired = string.Equals(row, ResolutionRequirementSetRow, StringComparison.Ordinal);
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(app, requestUri, pointer).ConfigureAwait(false);

        ProtectedResourceMetadataResolved resolved = AssertResolutionCase<ProtectedResourceMetadataResolved>(resolution);
        Assert.AreEqual(requestUri.OriginalString, resolved.Metadata.Resource);
        Assert.AreEqual(pointer.OriginalString, resolved.MetadataLocation.OriginalString);
        Assert.AreSequenceEqual(new[] { IssuerOf(app, material) }, resolved.Metadata.AuthorizationServers!.ToArray());
        Assert.AreSequenceEqual(ResourceDpopProofs.AcceptedProofAlgorithms.Split(' '), resolved.Metadata.DpopSigningAlgValuesSupported!.ToArray());
        Assert.AreEqual<bool?>(isRequired ? true : null, resolved.Metadata.DpopBoundAccessTokensRequired);
        Assert.AreSequenceEqual(isRequired ? Array.Empty<string>() : [BearerMethodValues.Header], resolved.Metadata.BearerMethodsSupported!.ToArray());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "The resource value
    /// returned MUST be identical to the protected resource's resource identifier value into which the well-known URI path
    /// suffix was inserted to create the URL used to retrieve the metadata." and "the resource value returned MUST be
    /// identical to the URL that the client used to make the request to the resource server";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.3">Section 7.3</see>: "the client MUST ensure that the
    /// resource identifier URL it is using as the prefix for the metadata request exactly matches the value of the
    /// resource metadata parameter"; <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.7">Section 7.7</see>:
    /// "Clients SHOULD take appropriate precautions against SSRF attacks". UserInfo's challenge is read over the wire and
    /// its pointer replaced by one that is not the location formed from the request URL; the resolution answers that the
    /// pointer is not derived from the request, naming the request URL, the pointer and the location expected, and sends
    /// no request. The resolution runs under an outbound policy allowing the listener's host alone, so a request to any
    /// other host would be denied without leaving the machine. The rows: the pointer on another host; at another path;
    /// under another well-known suffix.
    /// </summary>
    /// <param name="row">The replaced pointer: <see cref="AnotherHostPointerRow"/>, <see cref="AnotherPathPointerRow"/> or <see cref="AnotherSuffixPointerRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(AnotherHostPointerRow)]
    [DataRow(AnotherPathPointerRow)]
    [DataRow(AnotherSuffixPointerRow)]
    public async Task ResolutionFromAChallengeRefusesAPointerNotDerivedFromTheRequestUrlAsync(string row)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);
        Uri replaced = new(row switch
        {
            AnotherHostPointerRow => $"https://resource.example.com/.well-known/oauth-protected-resource{requestUri.AbsolutePath}",
            AnotherPathPointerRow => pointer.OriginalString.Replace("/userinfo", "/credential", StringComparison.Ordinal),
            AnotherSuffixPointerRow => pointer.OriginalString.Replace(
                "/.well-known/oauth-protected-resource/", "/.well-known/oauth-authorization-server/", StringComparison.Ordinal),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown pointer row.")
        });
        using HttpClient client = SingleHopClientOf(app);
        (OutboundTransportDelegate transport, Func<IReadOnlyList<OutboundRequest>> requests) =
            RecordingOutboundTransport.WrapRequests(SingleHopTransportOf(client));

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(
            app,
            requestUri,
            replaced,
            transport,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy with { HostAllowList = [requestUri.Host] })).ConfigureAwait(false);

        ProtectedResourceMetadataPointerNotDerivedFromRequest notDerived =
            AssertResolutionCase<ProtectedResourceMetadataPointerNotDerivedFromRequest>(resolution);
        Assert.AreEqual(requestUri, notDerived.RequestUri);
        Assert.AreEqual(replaced, notDerived.Pointer);
        Assert.AreEqual(pointer.OriginalString, notDerived.ExpectedPointer.OriginalString);
        Assert.IsEmpty(requests(), "No request is sent to a pointer that is not derived from the request URL.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "the resource value
    /// returned MUST be identical to the URL that the client used to make the request to the resource server. If these
    /// values are not identical, the data contained in the response MUST NOT be used.", compared as
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-6">Section 6</see> states: "Comparisons between the two
    /// strings MUST be performed as a Unicode code-point-to-code-point equality comparison." UserInfo's document is served
    /// over the wire with its <c>resource</c> rewritten; the resolution answers the mismatch, naming the request URL, the
    /// published <c>resource</c> as served and the document's location, and no document. The rows: the issuer, another
    /// URL; the request URL with the first letter of UserInfo's path segment written <c>%75</c>, a spelling
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.2">RFC 3986 Section 6.2.2.2</see> holds equivalent
    /// ("These URIs should be normalized by decoding any percent-encoded octet that corresponds to an unreserved
    /// character") and a code-point comparison holds different.
    /// </summary>
    /// <param name="row">The served <c>resource</c>: <see cref="IssuerResourceRow"/> or <see cref="PercentEncodedResourceRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(IssuerResourceRow)]
    [DataRow(PercentEncodedResourceRow)]
    public async Task ResolutionFromAChallengeRefusesADocumentWhoseResourceIsNotTheRequestUrlAsync(string row)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);
        string published = row switch
        {
            IssuerResourceRow => IssuerOf(app, material),
            PercentEncodedResourceRow => requestUri.OriginalString.Replace("/userinfo", "/%75serinfo", StringComparison.Ordinal),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown resource row.")
        };
        List<(string Path, int StatusCode, string BodyBefore, string BodyAfter)> rewritten = app.RewriteAnswerBody(
            pointer.AbsolutePath, 1,
            body => body.Replace($"\"resource\":\"{requestUri.OriginalString}\"", $"\"resource\":\"{published}\"", StringComparison.Ordinal));

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(app, requestUri, pointer).ConfigureAwait(false);

        ProtectedResourceMetadataResourceMismatch mismatch = AssertResolutionCase<ProtectedResourceMetadataResourceMismatch>(resolution);
        Assert.AreEqual(requestUri, mismatch.RequestUri);
        Assert.AreEqual(published, mismatch.PublishedResource);
        Assert.AreEqual(pointer, mismatch.MetadataLocation);
        (_, _, string bodyBefore, string bodyAfter) = Assert.ContainsSingle(rewritten);
        Assert.AreNotEqual(bodyBefore, bodyAfter, "The served document names the rewritten resource.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see>: "Additional metadata
    /// parameters MAY be defined and used; any metadata parameters that are not understood MUST be ignored." UserInfo's
    /// document is served over the wire with a member the reading does not know, <c>"x_extension":{"a":1}</c>, added; the
    /// resolution answers the document resolved, its known members as served.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResolutionFromAChallengeIgnoresAMemberItDoesNotUnderstandAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);
        List<(string Path, int StatusCode, string BodyBefore, string BodyAfter)> rewritten = app.RewriteAnswerBody(
            pointer.AbsolutePath, 1, static body => "{\"x_extension\":{\"a\":1}," + body[1..]);

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(app, requestUri, pointer).ConfigureAwait(false);

        ProtectedResourceMetadataResolved resolved = AssertResolutionCase<ProtectedResourceMetadataResolved>(resolution);
        Assert.AreEqual(requestUri.OriginalString, resolved.Metadata.Resource);
        Assert.AreSequenceEqual(new[] { IssuerOf(app, material) }, resolved.Metadata.AuthorizationServers!.ToArray());
        Assert.AreSequenceEqual(new[] { WellKnownScopes.OpenId }, resolved.Metadata.ScopesSupported!.ToArray());
        Assert.StartsWith("{\"x_extension\":{\"a\":1},", Assert.ContainsSingle(rewritten).BodyAfter);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>: "A protected resource
    /// metadata document MUST be queried using an HTTP GET request at the previously specified URL." The resolution of
    /// UserInfo's pointer, read from its challenge over the wire, sends exactly one request through the transport, with
    /// the method <c>GET</c>, to the pointer.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResolutionFromAChallengeQueriesTheDocumentWithGetAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);
        using HttpClient client = SingleHopClientOf(app);
        (OutboundTransportDelegate transport, Func<IReadOnlyList<OutboundRequest>> requests) =
            RecordingOutboundTransport.WrapRequests(SingleHopTransportOf(client));

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(app, requestUri, pointer, transport).ConfigureAwait(false);

        OutboundRequest sent = Assert.ContainsSingle(requests(), "The document is queried with one request.");
        Assert.AreEqual(WellKnownHttpMethods.Get, sent.Method);
        Assert.AreEqual(pointer, sent.Target);
        _ = AssertResolutionCase<ProtectedResourceMetadataResolved>(resolution);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-7.7">RFC 9728 Section 7.7</see>: "Clients SHOULD take
    /// appropriate precautions against SSRF attacks, such as blocking requests to internal IP address ranges." The
    /// resolution of UserInfo's pointer, read from its challenge over the wire at the loopback listener, runs under the
    /// secure default outbound policy, which blocks loopback addresses: it answers the policy's denial of the pointer and
    /// the transport is never called.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResolutionFromAChallengeAnswersAPolicyDenialBeforeAnyRequestAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);
        using HttpClient client = SingleHopClientOf(app);
        (OutboundTransportDelegate transport, Func<IReadOnlyList<OutboundRequest>> requests) =
            RecordingOutboundTransport.WrapRequests(SingleHopTransportOf(client));

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(
            app, requestUri, pointer, transport, TestHostShell.ExchangeContextWith(OutboundFetchPolicy.SecureDefault)).ConfigureAwait(false);

        MetadataDocumentPolicyDenied denied = AssertResolutionCase<MetadataDocumentPolicyDenied>(resolution);
        Assert.AreEqual(pointer, denied.Target);
        Assert.IsEmpty(requests(), "The policy denies the pointer before the transport is called.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see>: "A successful response
    /// MUST use the 200 OK HTTP status code and return a JSON object using the application/json content type". UserInfo's
    /// document is served over the wire with its answer rewritten at the listener; the resolution answers the failure the
    /// answer is. The rows: the document answered with the status 404, a document not answered, with 404; the document
    /// answered with the content type <c>text/html</c>, an unsupported media type, with <c>text/html</c>.
    /// </summary>
    /// <param name="row">The rewritten answer: <see cref="AnsweredNotFoundRow"/> or <see cref="AnsweredAsHtmlRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(AnsweredNotFoundRow)]
    [DataRow(AnsweredAsHtmlRow)]
    public async Task ResolutionFromAChallengeAnswersADocumentThatIsNoJson200AsTheFailureItIsAsync(string row)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);
        string documentPath = pointer.AbsolutePath;
        app.Host("default").RewriteAnswer = (path, response) => string.Equals(path, documentPath, StringComparison.Ordinal)
            ? row switch
            {
                AnsweredNotFoundRow => response with { StatusCode = 404 },
                AnsweredAsHtmlRow => response with { ContentType = "text/html" },
                _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown answer row.")
            }
            : response;

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(app, requestUri, pointer).ConfigureAwait(false);

        Assert.AreEqual(
            row switch
            {
                AnsweredNotFoundRow => "NotAnswered 404",
                AnsweredAsHtmlRow => "UnsupportedMediaType text/html",
                _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown answer row.")
            },
            DescribeResolution(resolution));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2.2">RFC 9728 Section 2.2</see>: "Consumers of the
    /// metadata MAY ignore the signed metadata if they do not support this feature." UserInfo's document is served over
    /// the wire carrying <c>signed_metadata</c>, the server's signer answering <c>header.payload.signature</c>; the
    /// resolution answers the document resolved from its plain members, with the signed metadata carried as the string the
    /// document holds.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResolutionFromAChallengeCarriesTheSignedMetadataUnverifiedAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, static candidateIntegration =>
            candidateIntegration.SignProtectedResourceMetadataAsync = static (_, _, _, _) =>
                ValueTask.FromResult<string?>("header.payload.signature")).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(app, requestUri, pointer).ConfigureAwait(false);

        ProtectedResourceMetadataResolved resolved = AssertResolutionCase<ProtectedResourceMetadataResolved>(resolution);
        Assert.AreEqual(requestUri.OriginalString, resolved.Metadata.Resource);
        Assert.AreEqual("header.payload.signature", resolved.Metadata.SignedMetadata);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 Section 8.1</see>: "JSON text exchanged
    /// between systems that are not part of a closed ecosystem MUST be encoded using UTF-8 [RFC3629]."
    /// UserInfo's challenge is read over the wire, and its pointer is answered 200 <c>application/json</c> with a body
    /// naming the request URL as its <c>resource</c> whose member <c>other</c>, one the reading does not know, holds the
    /// octet <c>0xFF</c>, which no UTF-8 sequence holds; the resolution answers the body unreadable at the pointer. The
    /// document is answered by an injected transport because the listener's answer hooks carry a body as a string, which
    /// cannot hold an octet that is not UTF-8.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResolutionFromAChallengeAnswersABodyThatIsNotUtf8AsUnreadableAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);
        ScriptedOutboundTransport transport = new(new Dictionary<string, ScriptedOutboundResponse>(StringComparer.Ordinal)
        {
            [pointer.AbsoluteUri] = ScriptedOutboundResponse.WithBody(
                200,
                HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json)),
                new TaggedMemory<byte>(NotUtf8DocumentOf(requestUri.OriginalString), BufferTags.Json))
        });

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(app, requestUri, pointer, transport.Delegate).ConfigureAwait(false);

        ProtectedResourceMetadataUnreadable unreadable = AssertResolutionCase<ProtectedResourceMetadataUnreadable>(resolution);
        Assert.AreEqual(pointer.OriginalString, unreadable.MetadataLocation.OriginalString);
        Assert.AreEqual(pointer, Assert.ContainsSingle(transport.Calls, "The document is queried with one request.").Target);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see>: "A successful response
    /// MUST use the 200 OK HTTP status code and return a JSON object using the application/json content type".
    /// UserInfo's document is served over the wire with its body rewritten to <c>[]</c>, a JSON text that is not an
    /// object, its status and content type kept; the resolution answers the body unreadable at the pointer.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResolutionFromAChallengeAnswersAJsonTextThatIsNotAnObjectAsUnreadableAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);
        List<(string Path, int StatusCode, string BodyBefore, string BodyAfter)> rewritten = app.RewriteAnswerBody(
            pointer.AbsolutePath, 1, static _ => "[]");

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(app, requestUri, pointer).ConfigureAwait(false);

        ProtectedResourceMetadataUnreadable unreadable = AssertResolutionCase<ProtectedResourceMetadataUnreadable>(resolution);
        Assert.AreEqual(pointer.OriginalString, unreadable.MetadataLocation.OriginalString);
        Assert.AreEqual("[]", Assert.ContainsSingle(rewritten).BodyAfter);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>: "A protected resource
    /// metadata document MUST be queried using an HTTP GET request at the previously specified URL.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.4">RFC 9110 Section 15.4</see>: "If a Location header
    /// field (Section 10.2.2) is provided, the user agent MAY automatically redirect its request to the URI referenced by
    /// the Location field value". UserInfo's document location is answered over the wire with 302 and a
    /// <c>Location</c> naming UserInfo; under the loopback outbound policy, which follows no redirect, the resolution
    /// answers the redirect refused, with the status 302 and the <c>Location</c> as received.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResolutionFromAChallengeAnswersARedirectOfTheDocumentAsRefusedAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);
        string documentPath = pointer.AbsolutePath;
        string location = requestUri.OriginalString;
        app.Host("default").RewriteAnswer = (path, response) => string.Equals(path, documentPath, StringComparison.Ordinal)
            ? ServerHttpResponse.Redirect(location)
            : response;

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(app, requestUri, pointer).ConfigureAwait(false);

        MetadataDocumentRedirectRefused refused = AssertResolutionCase<MetadataDocumentRedirectRefused>(resolution);
        Assert.AreEqual(302, refused.StatusCode);
        Assert.AreEqual(location, refused.Location);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>: "A protected resource
    /// metadata document MUST be queried using an HTTP GET request at the previously specified URL."; RFC 9728 states no
    /// bound on the document's size, and the bound is the caller's byte cap. UserInfo's document, served over the wire
    /// without a <c>Content-Length</c> field, so its length is known only as it is read, is resolved under a cap of 64
    /// bytes, below its length; the guarded fetch stops at the first octet past the cap, and the resolution answers the
    /// document too large, with the cap, the 65 octets observed and that the length was observed.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResolutionFromAChallengeAnswersADocumentOverTheByteCapAsTooLargeAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (Uri requestUri, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(
            app, requestUri, pointer, maximumDocumentBytes: 64).ConfigureAwait(false);

        MetadataDocumentTooLarge tooLarge = AssertResolutionCase<MetadataDocumentTooLarge>(resolution);
        Assert.AreEqual(64L, tooLarge.Limit);
        Assert.AreEqual(65L, tooLarge.LengthSeen);
        Assert.AreEqual(OutboundResponseLengthKind.Observed, tooLarge.LengthKind);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>: "A protected resource
    /// metadata document MUST be queried using an HTTP GET request at the previously specified URL." The request URL names
    /// a loopback port that a socket holds bound and never listening on, so no listener can take it, and the pointer is
    /// the location formed from it; the GET finds no listener, the connection is refused, and the resolution answers the
    /// document unreachable with the transport's failure kind, <see cref="HttpRequestException"/>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResolutionFromAChallengeAnswersADocumentNoListenerServesAsUnreachableAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using Socket portHolder = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        portHolder.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        Uri requestUri = new($"https://127.0.0.1:{((IPEndPoint)portHolder.LocalEndPoint!).Port}/connect/no-listener/userinfo");
        Uri pointer = ResourceDpopProofs.ProtectedResourceDocumentUrlOf(requestUri);

        ProtectedResourceMetadataResolution resolution = await ResolveFromChallengeAsync(app, requestUri, pointer).ConfigureAwait(false);

        MetadataDocumentUnreachable unreachable = AssertResolutionCase<MetadataDocumentUnreachable>(resolution);
        Assert.AreEqual(typeof(HttpRequestException), unreachable.FailureKind);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>: "A protected resource
    /// metadata document MUST be queried using an HTTP GET request at the previously specified URL." UserInfo's
    /// challenge is read over the wire and its pointer, where a GET over a raw TLS connection is answered 200, is sent a
    /// POST over a raw TLS connection; the server serves no document to it and answers 404.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DocumentLocationAnswersAPostWithNotFoundAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterUserInfoResourceAsync(app, isRequired: false).ConfigureAwait(false);
        (_, Uri pointer) = await ReadUserInfoChallengePointerAsync(app, material).ConfigureAwait(false);
        HttpResponseData queried = await RawHttpsRequest.SendAsync(
            app, WellKnownHttpMethods.Get, pointer, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, queried.StatusCode, "A GET at the pointer is answered with the document.");

        HttpResponseData posted = await RawHttpsRequest.SendAsync(
            app, WellKnownHttpMethods.Post, pointer, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, posted.StatusCode, posted.Body);
    }


    /// <summary>
    /// Registers a protected resource, wires <paramref name="contribution"/> as its metadata contribution, runs
    /// <paramref name="arrange"/> on the server when given, starts the listener, and fetches the document over the wire
    /// at the location <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">RFC 9728 Section 3</see> derives
    /// from the resource identifier, asserting the host captured no server fault and then <paramref name="expectedStatusCode"/>.
    /// </summary>
    /// <param name="contribution">The resource's contribution to its document.</param>
    /// <param name="arrange">Further wiring of the server before the fetch, or <see langword="null"/> for none.</param>
    /// <param name="expectedStatusCode">The status the fetch is answered with.</param>
    /// <returns>
    /// The served body as received and the consumer's reading of it; the reading is <see langword="null"/> for an answer
    /// other than 200.
    /// </returns>
    private async Task<(string Body, ProtectedResourceMetadata? Metadata)> FetchContributedDocumentAsync(
        ProtectedResourceMetadataContribution contribution, Func<TestHostShell, Task>? arrange = null, int expectedStatusCode = 200)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial resource = await RegisterProtectedResourceAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeProtectedResourceMetadataAsync = (_, _, _, _) => ValueTask.FromResult(contribution);
        }).ConfigureAwait(false);
        if(arrange is not null)
        {
            await arrange(app).ConfigureAwait(false);
        }

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string issuer = await FetchIssuerAsync(host, resource.Registration.TenantId.Value).ConfigureAwait(false);
        Uri metadataUrl = WellKnownPaths.OAuthProtectedResource.ComputeUri(issuer);
        using HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(new Uri(host.HttpBaseAddress!, metadataUrl.AbsolutePath), TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(host.ConsumeHttpFaults(), "The fetch is answered without a server fault.");
        Assert.AreEqual(expectedStatusCode, (int)response.StatusCode, body);

        return (body, expectedStatusCode switch
        {
            200 => ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(body),
            _ => null
        });
    }


    /// <summary>
    /// Enables DPoP proof validation on the server and sets
    /// <see cref="AuthorizationServerIntegration.IsDpopBoundAccessTokenRequiredAtResources"/>, so its resources require
    /// DPoP-bound access tokens.
    /// </summary>
    /// <param name="app">The host.</param>
    /// <returns>A task that completes when the server is re-wired.</returns>
    private static async Task RequireDpopBoundAccessTokensAsync(TestHostShell app)
    {
        _ = await app.EnableDpopAsync().ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, static candidateIntegration =>
            candidateIntegration.IsDpopBoundAccessTokenRequiredAtResources = true).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers a protected resource co-located with the server: the RFC 9728
    /// metadata capability plus discovery and JWKS so the consumer can learn
    /// the resource identifier and the document can advertise <c>jwks_uri</c>.
    /// </summary>
    private static async Task<VerifierKeyMaterial> RegisterProtectedResourceAsync(TestHostShell app) =>
        await app.RegisterClientAsync(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);


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


    /// <summary>The resolution row whose server's resources do not require DPoP-bound access tokens.</summary>
    private const string ResolutionRequirementUnsetRow = "requirement-unset";

    /// <summary>The resolution row whose server's resources require DPoP-bound access tokens.</summary>
    private const string ResolutionRequirementSetRow = "requirement-set";

    /// <summary>The pointer row naming the document's path on another host.</summary>
    private const string AnotherHostPointerRow = "another-host";

    /// <summary>The pointer row naming the document of another path on the same host.</summary>
    private const string AnotherPathPointerRow = "another-path";

    /// <summary>The pointer row naming the request URL's path under another well-known suffix.</summary>
    private const string AnotherSuffixPointerRow = "another-suffix";

    /// <summary>The resource row whose document names the issuer as its <c>resource</c>.</summary>
    private const string IssuerResourceRow = "issuer";

    /// <summary>The resource row whose document names the request URL with one unreserved letter percent-encoded.</summary>
    private const string PercentEncodedResourceRow = "percent-encoded-letter";

    /// <summary>The answer row whose document is answered with the status 404.</summary>
    private const string AnsweredNotFoundRow = "answered-404";

    /// <summary>The answer row whose document is answered with the content type <c>text/html</c>.</summary>
    private const string AnsweredAsHtmlRow = "answered-text-html";

    /// <summary>The byte cap the resolution rows read a document under.</summary>
    private static long MaximumDocumentBytes { get; } = 64 * 1024;


    /// <summary>
    /// The bytes of <c>{"resource":"</c>, <paramref name="resource"/>, <c>","other":"</c>, the octet <c>0xFF</c> and
    /// <c>"}</c>: a JSON object in every byte but one, that octet, which no UTF-8 sequence holds, standing in the value of
    /// a member the reading does not know.
    /// </summary>
    /// <param name="resource">The <c>resource</c> value, ASCII with no character JSON escapes.</param>
    /// <returns>The bytes.</returns>
    private static byte[] NotUtf8DocumentOf(string resource) =>
        [.. Encoding.ASCII.GetBytes($"{{\"resource\":\"{resource}\",\"other\":\""), 0xFF, .. Encoding.ASCII.GetBytes("\"}")];


    /// <summary>
    /// The capabilities under which UserInfo answers a request without credentials with a challenge naming its protected
    /// resource metadata document, and serves that document: OpenID Connect UserInfo with discovery and the JWK Set, and
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> UserInfoDocumentCapabilities { get; } = ImmutableHashSet.Create(
        WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
        WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
        WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
        WellKnownCapabilityIdentifiers.OidcUserInfo,
        WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
        WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
        WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata);


    /// <summary>
    /// Registers a DPoP client under <see cref="UserInfoDocumentCapabilities"/> and enables DPoP proof validation on the
    /// server, with the resources requiring DPoP-bound access tokens when <paramref name="isRequired"/> is set.
    /// </summary>
    /// <param name="app">The host.</param>
    /// <param name="isRequired">Whether the server's resources require DPoP-bound access tokens.</param>
    /// <returns>The registration; the caller disposes it.</returns>
    private static async Task<VerifierKeyMaterial> RegisterUserInfoResourceAsync(TestHostShell app, bool isRequired)
    {
        VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), capabilities: UserInfoDocumentCapabilities).ConfigureAwait(false);
        if(isRequired)
        {
            await RequireDpopBoundAccessTokensAsync(app).ConfigureAwait(false);
        }
        else
        {
            _ = await app.EnableDpopAsync().ConfigureAwait(false);
        }

        return material;
    }


    /// <summary>
    /// Starts the listener, aligns <paramref name="material"/>'s registration to the listener's base address so the
    /// issuer and UserInfo's identifier name the URL a client sends its request to, sends a UserInfo request without
    /// credentials over a raw TLS connection, asserts the 401 answer, reads the <c>resource_metadata</c> pointer of its
    /// <c>DPoP</c> challenge as a client reads it (<see cref="DpopChallenge.TryRead"/> over every <c>WWW-Authenticate</c>
    /// field line), and asserts the pointer's text is, code point for code point, the test's own derivation of the
    /// document's URL from the request URL (<see cref="ResourceDpopProofs.ProtectedResourceDocumentUrlOf"/>).
    /// </summary>
    /// <param name="app">The host.</param>
    /// <param name="material">The registration whose UserInfo endpoint is addressed; its registration is replaced by the aligned one.</param>
    /// <returns>The URL the request was sent to and the pointer its challenge named.</returns>
    private async Task<(Uri RequestUri, Uri Pointer)> ReadUserInfoChallengePointerAsync(TestHostShell app, VerifierKeyMaterial material)
    {
        Uri requestUri = await RawAuthCodeWirePushers.ResolveUserInfoUriAsync(app, material, TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = app.AlignRegistrationToHostHttpBase("default", material.Registration);
        HttpResponseData challenged = await RawHttpsRequest.SendAsync(
            app, WellKnownHttpMethods.Post, requestUri, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, challenged.StatusCode, challenged.Body);
        IReadOnlyList<string> challengeLines = challenged.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate);
        Assert.IsTrue(DpopChallenge.TryRead(challengeLines, out DpopChallengeParameters parameters), string.Join(" | ", challengeLines));
        Assert.IsNotNull(parameters.ResourceMetadata, $"The challenge names UserInfo's document: {string.Join(" | ", challengeLines)}");
        Assert.AreEqual(
            ResourceDpopProofs.ProtectedResourceDocumentUrlOf(requestUri).OriginalString,
            parameters.ResourceMetadata.OriginalString,
            "The challenge's pointer is the document's URL formed from the request URL.");

        return (requestUri, parameters.ResourceMetadata);
    }


    /// <summary>
    /// Resolves <paramref name="pointer"/> for <paramref name="requestUri"/> under
    /// <see cref="WellKnownPaths.OAuthProtectedResource"/>, through <paramref name="transport"/> (by default the host's
    /// single-hop transport) under <paramref name="context"/> (by default the loopback outbound policy), with the JSON
    /// leaf's strict reading of the bytes and <see cref="MaximumDocumentBytes"/>.
    /// </summary>
    /// <param name="app">The host whose listener serves the document.</param>
    /// <param name="requestUri">The URL the challenged request was sent to.</param>
    /// <param name="pointer">The pointer resolved.</param>
    /// <param name="transport">The transport, or <see langword="null"/> for <see cref="SingleHopTransportOf"/>.</param>
    /// <param name="context">The context, or <see langword="null"/> for the loopback outbound policy.</param>
    /// <param name="maximumDocumentBytes">The byte cap, or <see langword="null"/> for <see cref="MaximumDocumentBytes"/>.</param>
    /// <returns>The resolution.</returns>
    private async Task<ProtectedResourceMetadataResolution> ResolveFromChallengeAsync(
        TestHostShell app,
        Uri requestUri,
        Uri pointer,
        OutboundTransportDelegate? transport = null,
        ExchangeContext? context = null,
        long? maximumDocumentBytes = null)
    {
        using HttpClient singleHopClient = SingleHopClientOf(app);

        return await ProtectedResourceMetadataDocuments.ResolveFromChallengeAsync(
            requestUri,
            pointer,
            WellKnownPaths.OAuthProtectedResource,
            context ?? TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            transport ?? SingleHopTransportOf(singleHopClient),
            ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata,
            maximumDocumentBytes ?? MaximumDocumentBytes,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A client of the default host's listener that pins the certificate the listener presents and follows no redirect
    /// (<see cref="LoopbackTls.CreateSingleHopPinnedHttpClient(System.Security.Cryptography.X509Certificates.X509Certificate2)"/>),
    /// so a 3xx reaches the guarded fetch, whose outbound policy is the one redirect authority.
    /// </summary>
    /// <param name="app">The host.</param>
    /// <returns>The client; the caller disposes it.</returns>
    private static HttpClient SingleHopClientOf(TestHostShell app) =>
        LoopbackTls.CreateSingleHopPinnedHttpClient(app.HostCertificate("default"));


    /// <summary>The single-hop transport over <paramref name="client"/>, a client of <see cref="SingleHopClientOf"/>.</summary>
    /// <param name="client">The single-hop client.</param>
    /// <returns>The transport.</returns>
    private static OutboundTransportDelegate SingleHopTransportOf(HttpClient client) =>
        GuardedHttpClientTransport.BuildSingleHopTransport(client);


    /// <summary>The issuer the host holds for <paramref name="material"/>'s registration, as written.</summary>
    /// <param name="app">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <returns>The issuer.</returns>
    private static string IssuerOf(TestHostShell app, VerifierKeyMaterial material) =>
        app.Host("default").Registrations[material.Registration.TenantId.Value].IssuerUri!.OriginalString;


    /// <summary>Asserts that <paramref name="resolution"/> holds the case <typeparamref name="T"/> and answers it.</summary>
    /// <typeparam name="T">The case type expected.</typeparam>
    /// <param name="resolution">The resolution.</param>
    /// <returns>The case.</returns>
    private static T AssertResolutionCase<T>(ProtectedResourceMetadataResolution resolution) where T : class =>
        Assert.IsInstanceOfType<T>(resolution.Value, $"Expected {typeof(T).Name}; got {DescribeResolution(resolution)}.");


    /// <summary>
    /// States a resolution for an assertion message: the case and its evidence, through a switch over every case of the
    /// union, so the description covers each case the resolution can answer.
    /// </summary>
    /// <param name="resolution">The resolution.</param>
    /// <returns>The statement.</returns>
    private static string DescribeResolution(ProtectedResourceMetadataResolution resolution) => resolution switch
    {
        ProtectedResourceMetadataResolved resolved => $"Resolved {resolved.Metadata.Resource}",
        ProtectedResourceMetadataPointerNotDerivedFromRequest notDerived => $"PointerNotDerivedFromRequest {notDerived.Pointer}",
        MetadataDocumentPolicyDenied denied => $"PolicyDenied {denied.Target}",
        MetadataDocumentUnreachable unreachable => $"Unreachable {unreachable.FailureKind.Name}",
        MetadataDocumentRedirectRefused refused => $"RedirectRefused {refused.StatusCode} {refused.Location}",
        MetadataDocumentTooLarge tooLarge => $"TooLarge {tooLarge.LengthSeen}",
        MetadataDocumentNotAnswered notAnswered => $"NotAnswered {notAnswered.StatusCode}",
        MetadataDocumentUnsupportedMediaType unsupported => $"UnsupportedMediaType {unsupported.ContentType}",
        ProtectedResourceMetadataUnreadable unreadable => $"Unreadable {unreadable.MetadataLocation}",
        ProtectedResourceMetadataResourceMismatch mismatch => $"ResourceMismatch {mismatch.PublishedResource}"
    };
}

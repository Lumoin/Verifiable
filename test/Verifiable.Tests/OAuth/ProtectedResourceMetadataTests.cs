using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
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
}

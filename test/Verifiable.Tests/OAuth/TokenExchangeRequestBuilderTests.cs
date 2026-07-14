using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit and real-wire tests for <see cref="TokenExchangeRequestBuilder"/> — the client side of an
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see> token-exchange
/// request. Covers: the minimal impersonation shape, the actor pairing invariant (<see cref="TokenExchangeActor"/>
/// makes "token without type" unconstructible), RFC 8707 §2 resource well-formedness including
/// multi-resource, the full RFC 8693 §3 token-type-URN vocabulary, and a round-trip of the builder's
/// output through the SHIPPED token-exchange authorization-server endpoint that
/// <see cref="TokenExchangeGrantTests"/> exercises via hand-built dictionaries.
/// </summary>
[TestClass]
internal sealed class TokenExchangeRequestBuilderTests
{
    private const string ClientId = "https://machine.example.com";
    private const string ClientSecret = "s3cret-of-the-machine";
    private const string SubjectTokenValue = "subject-token-opaque-blob";
    private const string ActorTokenValue = "actor-token-opaque-blob";
    private const string SubjectIdentity = "https://user.example/alice";
    private const string ActorIdentity = "https://svc.example/agent";
    private const string GrantedScope = "read";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);


    /// <summary>
    /// The minimal REQUIRED-only shape (RFC 8693 §2.1): <c>grant_type</c>, <c>subject_token</c>, and
    /// <c>subject_token_type</c>, and nothing else — no actor, requested-type, resource, audience, or
    /// scope field is emitted when the corresponding option is absent.
    /// </summary>
    [TestMethod]
    public void BuildWithSubjectTokenOnlyProducesTheMinimalImpersonationRequest()
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> result = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        });

        Assert.IsTrue(result.IsSuccess);
        OutgoingFormFields form = result.Value!;
        Assert.HasCount(3, form);
        Assert.AreEqual(WellKnownGrantTypes.TokenExchange, form[OAuthRequestParameterNames.GrantType]);
        Assert.AreEqual(SubjectTokenValue, form[OAuthRequestParameterNames.SubjectToken]);
        Assert.AreEqual(TokenTypeNames.GetName(TokenType.AccessToken), form[OAuthRequestParameterNames.SubjectTokenType]);
    }


    /// <summary>
    /// RFC 8693 §2.1: <c>actor_token_type</c> is REQUIRED whenever <c>actor_token</c> is present and
    /// MUST NOT be sent otherwise. <see cref="TokenExchangeActor"/> pairs both members as REQUIRED on
    /// one sub-object, so there is no way to construct a <see cref="TokenExchangeBuilderOptions"/> that
    /// carries a token without its type (a missing <see cref="TokenExchangeActor.TokenType"/> is a
    /// compiler error, and there is no actor-token-only property on <see cref="TokenExchangeBuilderOptions"/>
    /// to set in the first place). This test proves the runtime consequence for every token type in the
    /// vocabulary: whenever <see cref="TokenExchangeBuilderOptions.Actor"/> is supplied, the built form
    /// always carries both wire parameters together.
    /// </summary>
    [TestMethod]
    public void ActorPairingAlwaysEmitsBothWireParametersTogether()
    {
        foreach(TokenType actorTokenType in TokenType.TokenTypes)
        {
            Result<OutgoingFormFields, TokenRequestBuilderError> result = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
            {
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.AccessToken,
                Actor = new TokenExchangeActor { Token = ActorTokenValue, TokenType = actorTokenType }
            });

            Assert.IsTrue(result.IsSuccess);
            OutgoingFormFields form = result.Value!;
            Assert.IsTrue(form.ContainsKey(OAuthRequestParameterNames.ActorToken), $"actor_token missing for {actorTokenType}.");
            Assert.IsTrue(form.ContainsKey(OAuthRequestParameterNames.ActorTokenType), $"actor_token_type missing for {actorTokenType}.");
            Assert.AreEqual(ActorTokenValue, form[OAuthRequestParameterNames.ActorToken]);
            Assert.AreEqual(TokenTypeNames.GetName(actorTokenType), form[OAuthRequestParameterNames.ActorTokenType]);
        }
    }


    /// <summary>The impersonation converse of <see cref="ActorPairingAlwaysEmitsBothWireParametersTogether"/>: no <see cref="TokenExchangeBuilderOptions.Actor"/> emits NEITHER actor field, never one without the other.</summary>
    [TestMethod]
    public void NoActorEmitsNeitherActorFieldNorItsType()
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> result = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        });

        Assert.IsTrue(result.IsSuccess);
        OutgoingFormFields form = result.Value!;
        Assert.IsFalse(form.ContainsKey(OAuthRequestParameterNames.ActorToken));
        Assert.IsFalse(form.ContainsKey(OAuthRequestParameterNames.ActorTokenType));
    }


    /// <summary>
    /// RFC 8693 §2.1.1 / RFC 8707 §2: multiple valid <c>resource</c> values (an https URI, an http
    /// URI, and a urn) collapse into ONE space-delimited field — the same wire shape
    /// <c>IdJagFlowHandlers.MintAsync</c> already uses for the ID-JAG mint leg's resource parameter.
    /// </summary>
    [TestMethod]
    public void MultipleValidResourcesAreSpaceJoinedIntoOneField()
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> result = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Resource = ["https://rs1.example.com/api", "http://rs2.example.com/api", "urn:example:resource"]
        });

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(
            "https://rs1.example.com/api http://rs2.example.com/api urn:example:resource",
            result.Value![OAuthRequestParameterNames.Resource]);
    }


    /// <summary>RFC 8707 §2: <c>resource</c> "MUST NOT include a fragment component". A fragment is rejected with the exact <see cref="InvalidResourceParameter"/> the shipped authorization-server-side check reports for the same rule.</summary>
    [TestMethod]
    public void ResourceWithFragmentIsRejectedWithExactError()
    {
        const string invalidResource = "https://rs.example.com/api#fragment";

        Result<OutgoingFormFields, TokenRequestBuilderError> result = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Resource = [invalidResource]
        });

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(
            new InvalidResourceParameter(invalidResource, TokenExchangeRequestBuilder.InvalidResourceReason),
            result.Error);
    }


    /// <summary>
    /// RFC 8693 §2.1: a <c>resource</c> value "MAY include a query component" — only the scheme and
    /// fragment are checked by <c>IsValidResource</c>, so a query-bearing value is accepted, not
    /// rejected. This is also the RFC 8707 §2 SHOULD NOT ("It SHOULD NOT include a query
    /// component...") deliberately left unenforced: 8707's advisory text and 8693's explicit MAY are
    /// in tension for the same wire parameter, and enforcing 8707's SHOULD NOT would contradict
    /// 8693's MAY, so the builder favors permission. The query string is carried into the
    /// <c>resource</c> form field byte-for-byte.
    /// </summary>
    [TestMethod]
    public void ResourceWithQueryComponentIsAccepted()
    {
        const string resourceWithQuery = "https://rs.example.com/api?tenant=acme";

        Result<OutgoingFormFields, TokenRequestBuilderError> result = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Resource = [resourceWithQuery]
        });

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(resourceWithQuery, result.Value![OAuthRequestParameterNames.Resource]);
    }


    /// <summary>RFC 8707 §2 / RFC 3986 §4.3: <c>resource</c> "MUST be an absolute URI". A relative value is rejected with the exact error.</summary>
    [TestMethod]
    public void RelativeResourceIsRejectedWithExactError()
    {
        const string invalidResource = "/relative/path";

        Result<OutgoingFormFields, TokenRequestBuilderError> result = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Resource = [invalidResource]
        });

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(
            new InvalidResourceParameter(invalidResource, TokenExchangeRequestBuilder.InvalidResourceReason),
            result.Error);
    }


    /// <summary>Multi-resource: the SECOND of several resources being malformed still fails the whole build (fail-closed, not a partial/best-effort form), reporting exactly that entry.</summary>
    [TestMethod]
    public void OneInvalidResourceAmongSeveralFailsTheWholeBuild()
    {
        const string invalidResource = "ftp://rs.example.com/api";

        Result<OutgoingFormFields, TokenRequestBuilderError> result = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Resource = ["https://rs1.example.com/api", invalidResource]
        });

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(
            new InvalidResourceParameter(invalidResource, TokenExchangeRequestBuilder.InvalidResourceReason),
            result.Error);
    }


    /// <summary>Optional fields (<c>requested_token_type</c>, <c>audience</c>, <c>scope</c>) are emitted verbatim when supplied.</summary>
    [TestMethod]
    public void OptionalFieldsAreEmittedWhenSupplied()
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> result = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            RequestedTokenType = TokenType.AccessToken,
            Audience = "https://logical-service.example",
            Scope = GrantedScope
        });

        Assert.IsTrue(result.IsSuccess);
        OutgoingFormFields form = result.Value!;
        Assert.AreEqual(TokenTypeNames.GetName(TokenType.AccessToken), form[OAuthRequestParameterNames.RequestedTokenType]);
        Assert.AreEqual("https://logical-service.example", form[OAuthRequestParameterNames.Audience]);
        Assert.AreEqual(GrantedScope, form[OAuthRequestParameterNames.Scope]);
    }


    /// <summary>
    /// RFC 8693 §3 defines exactly six token-type identifier URIs. This pins each
    /// <see cref="WellKnownTokenTypeIdentifiers"/> member to the RFC text's own literal string, closing
    /// the "verify the full list against §3" contract item — nothing in the vocabulary is missing.
    /// </summary>
    [TestMethod]
    public void AllRfc8693Section3TokenTypeUrnsAreModeled()
    {
        Assert.AreEqual("urn:ietf:params:oauth:token-type:access_token", WellKnownTokenTypeIdentifiers.AccessToken);
        Assert.AreEqual("urn:ietf:params:oauth:token-type:refresh_token", WellKnownTokenTypeIdentifiers.RefreshToken);
        Assert.AreEqual("urn:ietf:params:oauth:token-type:id_token", WellKnownTokenTypeIdentifiers.IdToken);
        Assert.AreEqual("urn:ietf:params:oauth:token-type:saml1", WellKnownTokenTypeIdentifiers.Saml1);
        Assert.AreEqual("urn:ietf:params:oauth:token-type:saml2", WellKnownTokenTypeIdentifiers.Saml2);
        Assert.AreEqual("urn:ietf:params:oauth:token-type:jwt", WellKnownTokenTypeIdentifiers.Jwt);
    }


    /// <summary>
    /// End-to-end proof that <see cref="TokenExchangeRequestBuilder"/>'s output is not merely
    /// shape-correct in isolation but interoperates with the SHIPPED token-exchange endpoint: build an
    /// impersonation request, attach <c>client_secret_post</c> via
    /// <see cref="OutgoingFormFieldsClientAuthExtensions.WithClientSecretPost"/>, POST it over a real
    /// Kestrel-hosted wire, and confirm the AS issues a Bearer access token for the subject the
    /// validation seam returned — the same seams and assertions <see cref="TokenExchangeGrantTests.ImpersonationExchangeIssuesBearerAccessTokenOverHttpWire"/>
    /// exercises via a hand-built dictionary.
    /// </summary>
    [TestMethod]
    public async Task ImpersonationBuilderOutputRoundTripsThroughShippedEndpointOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireImpersonationSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        Result<OutgoingFormFields, TokenRequestBuilderError> built = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        });
        Assert.IsTrue(built.IsSuccess);
        OutgoingFormFields form = built.Value!.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, doc.RootElement.GetProperty("token_type").GetString());
        Assert.AreEqual(GrantedScope, doc.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString());
    }


    /// <summary>The delegation counterpart: the builder's <see cref="TokenExchangeBuilderOptions.Actor"/> carrier produces a request the shipped endpoint accepts and records in the issued token's <c>act</c> claim.</summary>
    [TestMethod]
    public async Task DelegationBuilderOutputRoundTripsThroughShippedEndpointOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    string.Equals(token, ActorTokenValue, StringComparison.Ordinal)
                        ? new ValidatedSecurityToken { Subject = ActorIdentity }
                        : new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization { Subject = subject.Subject, Scope = GrantedScope, IssuedTokenType = TokenType.AccessToken });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        Result<OutgoingFormFields, TokenRequestBuilderError> built = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = ActorTokenValue, TokenType = TokenType.AccessToken }
        });
        Assert.IsTrue(built.IsSuccess);
        OutgoingFormFields form = built.Value!.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        string[] segments = accessToken.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], BaseMemoryPool.Shared);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);
        Assert.AreEqual(ActorIdentity, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Act).GetProperty("sub").GetString());
    }


    /// <summary>Registers a confidential client allowed the <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> capability, with the signing keys the RFC 9068 access-token producer needs.</summary>
    private static VerifierKeyMaterial RegisterTokenExchangeClient(TestHostShell app) =>
        app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));


    /// <summary>Wires the <c>client_secret_post</c> (RFC 6749 §2.3.1) authentication seam that checks the request's <c>client_secret</c> form field against the fixture secret.</summary>
    private static void WireClientAuthentication(TestHostShell app) =>
        app.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));


    /// <summary>Wires client authentication plus a token-exchange validation and policy seam that accepts the fixture subject token and permits every exchange (RFC 8693 §1.1 impersonation).</summary>
    private static void WireImpersonationSeams(TestHostShell app)
    {
        WireClientAuthentication(app);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization { Subject = subject.Subject, Scope = GrantedScope, IssuedTokenType = TokenType.AccessToken });
    }


}

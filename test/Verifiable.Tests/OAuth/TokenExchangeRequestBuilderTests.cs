using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
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
        OutgoingFormFields form = result.Value;
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
            OutgoingFormFields form = result.Value;
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
        OutgoingFormFields form = result.Value;
        Assert.IsFalse(form.ContainsKey(OAuthRequestParameterNames.ActorToken));
        Assert.IsFalse(form.ContainsKey(OAuthRequestParameterNames.ActorTokenType));
    }


    /// <summary>
    /// RFC 8693 §2.1.1 / RFC 8707 §2: multiple valid <c>resource</c> values (an https URI, an http
    /// URI, and a urn) become that many REPEATED <c>resource</c> occurrences on the wire — the
    /// genuine RFC 8707 §2 multi-resource wire form (<see cref="OutgoingFormFields.Add"/>), never
    /// one occurrence carrying several space-joined URIs.
    /// </summary>
    [TestMethod]
    public void MultipleValidResourcesEmitRepeatedResourceOccurrences()
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> result = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Resource = ["https://rs1.example.com/api", "http://rs2.example.com/api", "urn:example:resource"]
        });

        Assert.IsTrue(result.IsSuccess);
        IReadOnlyList<string> resourceOccurrences = result.Value.GetValues(OAuthRequestParameterNames.Resource);
        Assert.HasCount(3, resourceOccurrences);
        Assert.AreEqual("https://rs1.example.com/api", resourceOccurrences[0]);
        Assert.AreEqual("http://rs2.example.com/api", resourceOccurrences[1]);
        Assert.AreEqual("urn:example:resource", resourceOccurrences[2]);
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
    /// RFC 8693 section 2.1: a <c>resource</c> value "MAY include a query component". The builder
    /// reads a value by the same absolute-URI grammar the token endpoint reads it by
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.3">RFC 3986 section 4.3</see>:
    /// <c>absolute-URI = scheme ":" hier-part [ "?" query ]</c>), which admits a query, so a
    /// query-bearing value is accepted, not rejected. This is also the RFC 8707 section 2 SHOULD NOT
    /// ("It SHOULD NOT include a query component") deliberately left unenforced: 8707's advisory
    /// text and 8693's explicit MAY are in tension for the same wire parameter, and enforcing 8707's
    /// SHOULD NOT would contradict 8693's MAY, so the builder favors permission. The query string is
    /// carried into the <c>resource</c> form field byte-for-byte.
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
        Assert.AreEqual(resourceWithQuery, result.Value[OAuthRequestParameterNames.Resource]);
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


    /// <summary>
    /// The SECOND of several resources being one the absolute-URI grammar refuses (a relative
    /// reference, which has no scheme) fails the whole build, reporting exactly that entry.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>: "Its value
    /// MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]." Refusing the whole build
    /// rather than sending the entries that pass is a rule of this library, not a specification clause.
    /// </summary>
    [TestMethod]
    public void OneInvalidResourceAmongSeveralFailsTheWholeBuild()
    {
        const string invalidResource = "rs.example.com/api";

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


    /// <summary>
    /// A <c>resource</c> value the absolute-URI grammar refuses is refused by the builder with the
    /// exact <see cref="InvalidResourceParameter"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>: "Its value
    /// MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]." Each value is refused by its
    /// own rule. <c>https://user@rs.example.com/api</c> carries a userinfo in an <c>https</c> URI;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 section 4.2.4</see>:
    /// "A sender MUST NOT generate the userinfo subcomponent (and its "@" delimiter) when an "http" or
    /// "https" URI reference is generated within a message as a target URI or field value."
    /// <c>https://rs.example.com/a b</c> carries a space, which no production of the path admits:
    /// <c>pchar = unreserved / pct-encoded / sub-delims / ":" / "@"</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>).
    /// <c>https:///api</c> has an empty host;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.2">RFC 9110 section 4.2.2</see>:
    /// "A sender MUST NOT generate an "https" URI with an empty host identifier."
    /// <c>https://rs.example.com/%GG</c> carries a percent sign that no triplet follows:
    /// <c>pct-encoded = "%" HEXDIG HEXDIG</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.1">RFC 3986 section 2.1</see>), and
    /// <c>G</c> is no <c>HEXDIG</c>. <c>:foo</c> has an empty scheme;
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">RFC 3986 section 3.1</see>:
    /// "Scheme names consist of a sequence of characters beginning with a letter and followed by any
    /// combination of letters, digits, plus ("+"), period ("."), or hyphen ("-")." An empty entry is
    /// refused too: the token endpoint reads it as omitted
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."),
    /// and the builder, which sends every entry it accepts, refuses it instead.
    /// </summary>
    /// <param name="invalidResource">The <c>resource</c> value the grammar refuses.</param>
    [TestMethod]
    [DataRow("https://user@rs.example.com/api")]
    [DataRow("https://rs.example.com/a b")]
    [DataRow("https:///api")]
    [DataRow("https://rs.example.com/%GG")]
    [DataRow(":foo")]
    [DataRow("")]
    public void AResourceTheGrammarRefusesIsRefusedByTheBuilder(string invalidResource)
    {
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
    /// The shipped token endpoint refuses a <c>resource</c> value the builder refuses, with an
    /// <c>error_description</c> equal to the text of
    /// <see cref="TokenExchangeRequestBuilder.InvalidResourceReason"/>. The endpoint's refusal follows
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 section 2.1</see>: "If the
    /// authorization server fails to parse the provided value(s) or does not consider the resource(s)
    /// acceptable, it should reject the request with an error response using the error code
    /// "invalid_target" as the value of the "error" parameter", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see> defines
    /// <c>invalid_target</c> as "The requested resource is invalid, missing, unknown, or malformed."
    /// That the builder and the endpoint answer with the same text is a rule of this library, not a
    /// clause of a specification. The form is hand-built, since the builder does not build it, and is
    /// posted with <c>client_secret_post</c> over the loopback listener.
    /// </summary>
    /// <param name="invalidResource">The <c>resource</c> value the builder refuses.</param>
    [TestMethod]
    [DataRow("https://user@rs.example.com/api")]
    [DataRow("https://rs.example.com/a b")]
    [DataRow("https:///api")]
    [DataRow("https://rs.example.com/%GG")]
    [DataRow(":foo")]
    public async Task TheServerRefusesWhatTheBuilderRefusesWithTheSameTextAsync(string invalidResource)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken),
            [OAuthRequestParameterNames.Resource] = invalidResource
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_target", doc.RootElement.GetProperty("error").GetString());
        Assert.AreEqual(TokenExchangeRequestBuilder.InvalidResourceReason, doc.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// A <c>resource</c> value of any scheme that the absolute-URI grammar reads as an absolute URI
    /// without a fragment (an <c>ftp</c> URL, a <c>urn</c>) travels through the builder and reaches the
    /// token endpoint as the one <c>resource</c> occurrence it was sent as. The <c>ftp</c> URL that
    /// carries a userinfo is admitted too, as the generic syntax of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1">RFC 3986 section 3.2.1</see>
    /// defines it, and is sent as written.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>: "Its value
    /// MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]." The request is built by
    /// <see cref="TokenExchangeRequestBuilder"/>, carries <c>client_secret_post</c>, and is posted over
    /// the loopback listener; the endpoint answers 200.
    /// </summary>
    /// <param name="resource">The <c>resource</c> value the builder is given.</param>
    [TestMethod]
    [DataRow("ftp://rs.example.com/api")]
    [DataRow("urn:example:resource")]
    [DataRow("ftp://user:secret@rs.example.com/api")]
    public async Task AResourceOfAnotherSchemeTravelsThroughTheBuilderAsync(string resource)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        List<RequestFields> receivedFields = [];
        await WireImpersonationSeamsAsync(app, receivedFields).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        Result<OutgoingFormFields, TokenRequestBuilderError> built = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Resource = [resource]
        });
        Assert.IsTrue(built.IsSuccess);
        OutgoingFormFields form = built.Value!.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        Assert.HasCount(1, receivedFields);
        Assert.AreSequenceEqual([resource], receivedFields[0].GetValues("resource"));
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
        OutgoingFormFields form = result.Value;
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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

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


    /// <summary>
    /// A <see cref="TokenExchangeBuilderOptions.Scope"/> of white space only holds no <c>scope-token</c>,
    /// so the request the builder produces carries no <c>scope</c> parameter.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 section 3.3</see> defines
    /// the value as <c>scope = scope-token *( SP scope-token )</c> with
    /// <c>scope-token = 1*( %x21 / %x23-5B / %x5D-7E )</c>, and neither a space (%x20) nor a tab (%x09)
    /// is in a <c>scope-token</c>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 section 3.2</see> says
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request." The
    /// impersonation request with <c>client_secret_post</c> is posted over the loopback listener to the
    /// shipped token endpoint, which answers 200, and the fields it received are exactly those of a
    /// request that names no scope.
    /// </summary>
    /// <param name="scope">The white-space-only <see cref="TokenExchangeBuilderOptions.Scope"/> the builder is given.</param>
    [TestMethod]
    [DataRow(" ")]
    [DataRow("\t")]
    public async Task AScopeOfWhiteSpaceOnlyIsSentAsNoScopeAsync(string scope)
    {
        await AssertNoScopeIsSentAsync(scope).ConfigureAwait(false);
    }


    /// <summary>
    /// A <see cref="TokenExchangeBuilderOptions.Scope"/> of one Unicode white space character that
    /// <see cref="char.IsWhiteSpace(char)"/> reads as white space, U+00A0 (NO-BREAK SPACE) or U+2003
    /// (EM SPACE), holds no <c>scope-token</c>, so the request the builder produces carries no
    /// <c>scope</c> parameter.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 section 3.3</see> defines
    /// <c>scope-token = 1*( %x21 / %x23-5B / %x5D-7E )</c>, which holds neither code point;
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 section 3.2</see> says
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request." The
    /// request is posted over the loopback listener to the shipped token endpoint, which answers 200,
    /// and the fields it received are exactly those of a request that names no scope.
    /// </summary>
    /// <param name="codePoint">The code point of the one character <see cref="TokenExchangeBuilderOptions.Scope"/> holds.</param>
    [TestMethod]
    [DataRow(0x00A0)]
    [DataRow(0x2003)]
    public async Task AScopeOfOneUnicodeWhiteSpaceCharacterIsSentAsNoScopeAsync(int codePoint)
    {
        await AssertNoScopeIsSentAsync(char.ConvertFromUtf32(codePoint)).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a token-exchange request whose <see cref="TokenExchangeBuilderOptions.Scope"/> is
    /// <paramref name="scope"/>, posts it with <c>client_secret_post</c> over the loopback listener
    /// to the shipped token endpoint, and asserts the endpoint answers 200 and received exactly the
    /// fields of a request that names no scope.
    /// </summary>
    /// <param name="scope">The white-space-only <see cref="TokenExchangeBuilderOptions.Scope"/> the builder is given.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertNoScopeIsSentAsync(string scope)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        List<RequestFields> receivedFields = [];
        await WireImpersonationSeamsAsync(app, receivedFields).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        Result<OutgoingFormFields, TokenRequestBuilderError> built = TokenExchangeRequestBuilder.Build(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Scope = scope
        });
        Assert.IsTrue(built.IsSuccess);
        OutgoingFormFields form = built.Value!.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        Assert.HasCount(1, receivedFields);
        Assert.AreSequenceEqual(
            ["client_id", "client_secret", "grant_type", "subject_token", "subject_token_type"],
            receivedFields[0].Keys.Order(StringComparer.Ordinal).ToArray());
    }


    /// <summary>The delegation counterpart: the builder's <see cref="TokenExchangeBuilderOptions.Actor"/> carrier produces a request the shipped endpoint accepts and records in the issued token's <c>act</c> claim.</summary>
    [TestMethod]
    public async Task DelegationBuilderOutputRoundTripsThroughShippedEndpointOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        string.Equals(token, ActorTokenValue, StringComparison.Ordinal)
                            ? new ValidatedSecurityToken { Subject = ActorIdentity }
                            : new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization { Subject = subject.Subject, Scope = GrantedScope, IssuedTokenType = TokenType.AccessToken });
        }).ConfigureAwait(false);

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
    private static async Task<VerifierKeyMaterial> RegisterTokenExchangeClientAsync(TestHostShell app) =>
        await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);


    /// <summary>
    /// Wires the <c>client_secret_post</c> (RFC 6749 section 2.3.1) authentication seam that checks the request's <c>client_secret</c> form field against the fixture secret.
    /// When <paramref name="receivedFields"/> is supplied, the installed seam appends the form fields of every request it receives to that list and then delegates to the check.
    /// </summary>
    /// <param name="app">The host shell whose server receives the seam.</param>
    /// <param name="receivedFields">The list that collects the form fields the token endpoint received, or <see langword="null"/> to collect nothing.</param>
    private static async Task WireClientAuthenticationAsync(TestHostShell app, List<RequestFields>? receivedFields = null)
    {
        static ValueTask<bool> checkSecret(RequestFields fields) =>
            ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
            {
                receivedFields?.Add(fields);

                return checkSecret(fields);
            };
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Wires client authentication plus a token-exchange validation and policy seam that accepts the fixture subject token and permits every exchange (RFC 8693 section 1.1 impersonation).
    /// </summary>
    /// <param name="app">The host shell whose server receives the seams.</param>
    /// <param name="receivedFields">The list that collects the form fields the token endpoint received, or <see langword="null"/> to collect nothing.</param>
    private static async Task WireImpersonationSeamsAsync(TestHostShell app, List<RequestFields>? receivedFields = null)
    {
        await WireClientAuthenticationAsync(app, receivedFields).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });


            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization { Subject = subject.Subject, Scope = GrantedScope, IssuedTokenType = TokenType.AccessToken });
        }).ConfigureAwait(false);
    }


}

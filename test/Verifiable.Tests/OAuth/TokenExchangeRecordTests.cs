using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.IdJag;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests of the Token Exchange records' text and of the arguments <see cref="IdJagMintRequestRule.Build"/> takes:
/// a record that carries a presented <c>subject_token</c> or <c>actor_token</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see>), or the ID-JAG a
/// client presents as its assertion, renders the request's shape as text and never the token, and the rule is
/// built only over a set that names audiences.
/// </summary>
[TestClass]
internal sealed class TokenExchangeRecordTests
{
    /// <summary>The presented subject token the records carry; no part of it may appear in their text.</summary>
    private static string SubjectTokenValue { get; } = "subject-token-presented-7f3a9c";

    /// <summary>The presented actor token the records carry; no part of it may appear in their text.</summary>
    private static string ActorTokenValue { get; } = "actor-token-presented-2d81e4";

    /// <summary>The presented ID-JAG the redeem record carries as its assertion; no part of it may appear in its text.</summary>
    private static string AssertionValue { get; } = "id-jag-assertion-presented-5b0c17";

    /// <summary>The <c>kid</c> of the client's signing material the ID-JAG client's records name.</summary>
    private static string SigningKeyIdValue { get; } = "kid-client-1";

    /// <summary>The audience the rule's rows build the rule over.</summary>
    private static string KnownAudience { get; } = "https://resource-authorization-server.example/";

    /// <summary>The audience the snapshot row writes into the source list after the rule is built.</summary>
    private static string LaterAudience { get; } = "https://later-resource-authorization-server.example/";

    /// <summary>The MSTest context whose cancellation token every await rides.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A <see cref="TokenExchangeRequest"/> carries the presented <c>subject_token</c> and <c>actor_token</c>
    /// unvalidated, and the application's request seam receives it; a rule of this library keeps both out of the
    /// record's text so a seam that logs the request writes neither. Its text is the request's shape:
    /// <c>TokenExchangeRequest { SubjectTokenType = urn:ietf:params:oauth:token-type:id_token, IsActorTokenPresent = True, ActorTokenType = urn:ietf:params:oauth:token-type:access_token, RequestedTokenType = urn:ietf:params:oauth:token-type:id-jag, ResourceCount = 1, AudienceCount = 1, IsScopePresent = True, IsAuthorizationDetailsPresent = False, GrantType = urn:ietf:params:oauth:grant-type:token-exchange }</c>.
    /// </summary>
    [TestMethod]
    public void ATokenExchangeRequestRendersNoPresentedTokenAsText()
    {
        TokenExchangeRequest request = new()
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.IdToken,
            ActorToken = ActorTokenValue,
            ActorTokenType = TokenType.AccessToken,
            RequestedTokenType = TokenType.IdJag,
            Resource = ["https://api.example/files"],
            Audience = [KnownAudience],
            Scope = "chat.read"
        };

        string text = request.ToString();

        Assert.DoesNotContain("subject-token-presented", text, StringComparison.Ordinal, text);
        Assert.DoesNotContain("actor-token-presented", text, StringComparison.Ordinal, text);
        Assert.AreEqual(
            "TokenExchangeRequest { SubjectTokenType = urn:ietf:params:oauth:token-type:id_token, IsActorTokenPresent = True, "
            + "ActorTokenType = urn:ietf:params:oauth:token-type:access_token, RequestedTokenType = urn:ietf:params:oauth:token-type:id-jag, "
            + "ResourceCount = 1, AudienceCount = 1, IsScopePresent = True, IsAuthorizationDetailsPresent = False, "
            + "GrantType = urn:ietf:params:oauth:grant-type:token-exchange }",
            text);
    }


    /// <summary>
    /// A <see cref="TokenExchangeActor"/> carries the <c>actor_token</c> a client presents
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see>); a rule of this
    /// library keeps it out of the record's text, which is
    /// <c>TokenExchangeActor { TokenType = urn:ietf:params:oauth:token-type:access_token, IsTokenPresent = True }</c>.
    /// </summary>
    [TestMethod]
    public void ATokenExchangeActorRendersNoPresentedTokenAsText()
    {
        TokenExchangeActor actor = new() { Token = ActorTokenValue, TokenType = TokenType.AccessToken };

        string text = actor.ToString();

        Assert.DoesNotContain("actor-token-presented", text, StringComparison.Ordinal, text);
        Assert.AreEqual(
            "TokenExchangeActor { TokenType = urn:ietf:params:oauth:token-type:access_token, IsTokenPresent = True }",
            text);
    }


    /// <summary>
    /// <see cref="TokenExchangeBuilderOptions"/> carries the <c>subject_token</c> and the <c>actor_token</c> a client
    /// presents (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see>); a rule
    /// of this library keeps both out of the record's text, which is
    /// <c>TokenExchangeBuilderOptions { SubjectTokenType = urn:ietf:params:oauth:token-type:access_token, IsActorPresent = True, ActorTokenType = urn:ietf:params:oauth:token-type:jwt, RequestedTokenType = , ResourceCount = 0, IsAudiencePresent = True, IsScopePresent = False }</c>.
    /// </summary>
    [TestMethod]
    public void TokenExchangeBuilderOptionsRenderNoPresentedTokenAsText()
    {
        TokenExchangeBuilderOptions options = new()
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = ActorTokenValue, TokenType = TokenType.Jwt },
            Audience = KnownAudience
        };

        string text = options.ToString();

        Assert.DoesNotContain("subject-token-presented", text, StringComparison.Ordinal, text);
        Assert.DoesNotContain("actor-token-presented", text, StringComparison.Ordinal, text);
        Assert.AreEqual(
            "TokenExchangeBuilderOptions { SubjectTokenType = urn:ietf:params:oauth:token-type:access_token, IsActorPresent = True, "
            + "ActorTokenType = urn:ietf:params:oauth:token-type:jwt, RequestedTokenType = , ResourceCount = 0, IsAudiencePresent = True, "
            + "IsScopePresent = False }",
            text);
    }


    /// <summary>
    /// A <see cref="TokenExchangeRequestRefusal"/> renders the refused parameter alone, as its debugger display
    /// does; its <see cref="TokenExchangeRequestRefusal.Description"/> is the application's text and stays out of the
    /// record's text, a rule of this library. The text is <c>TokenExchangeRequestRefusal { Parameter = scope }</c>.
    /// </summary>
    [TestMethod]
    public void ARefusalRendersItsParameterOnly()
    {
        TokenExchangeRequestRefusal refusal = new() { Parameter = "scope", Description = "Refused for the reason given." };

        string text = refusal.ToString();

        Assert.AreEqual("TokenExchangeRequestRefusal { Parameter = scope }", text);
    }


    /// <summary>
    /// <see cref="IdJagMintOptions"/> carries the <c>subject_token</c> a client presents to obtain an ID-JAG
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.3</see>:
    /// "subject_token: REQUIRED - Either the Identity Assertion (e.g. the OpenID Connect ID Token or SAML 2.0
    /// Assertion) for the target resource owner, or a Refresh Token previously issued by the IdP Authorization Server
    /// for that resource owner."); a rule of this library keeps it out of the record's text, which is
    /// <c>IdJagMintOptions { Audience = https://resource-authorization-server.example/, SubjectTokenType = urn:ietf:params:oauth:token-type:id_token, ResourceCount = 1, IsScopePresent = True, IsAuthorizationDetailsPresent = False, SigningKeyId = kid-client-1 }</c>.
    /// </summary>
    [TestMethod]
    public void IdJagMintOptionsRenderNoPresentedTokenAsText()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            IdJagMintOptions options = new()
            {
                Audience = KnownAudience,
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.IdToken,
                SigningKey = clientKeys.PrivateKey,
                SigningKeyId = SigningKeyIdValue,
                HeaderSerializer = static _ => [],
                PayloadSerializer = static _ => [],
                Resource = ["https://api.example/files"],
                Scope = "chat.read"
            };

            string text = options.ToString();

            Assert.DoesNotContain("subject-token-presented", text, StringComparison.Ordinal, text);
            Assert.AreEqual(
                "IdJagMintOptions { Audience = https://resource-authorization-server.example/, "
                + "SubjectTokenType = urn:ietf:params:oauth:token-type:id_token, ResourceCount = 1, IsScopePresent = True, "
                + "IsAuthorizationDetailsPresent = False, SigningKeyId = kid-client-1 }",
                text);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see cref="IdJagRedeemOptions"/> carries the ID-JAG a client presents as its assertion
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.4</see>:
    /// "assertion: REQUIRED - The Identity Assertion JWT Authorization Grant obtained in the previous token exchange
    /// step"); a rule of this library keeps it out of the record's text, which is
    /// <c>IdJagRedeemOptions { IsAssertionPresent = True, SigningKeyId = kid-client-1 }</c>.
    /// </summary>
    [TestMethod]
    public void IdJagRedeemOptionsRenderNoPresentedAssertionAsText()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            IdJagRedeemOptions options = new()
            {
                Assertion = AssertionValue,
                SigningKey = clientKeys.PrivateKey,
                SigningKeyId = SigningKeyIdValue,
                HeaderSerializer = static _ => [],
                PayloadSerializer = static _ => []
            };

            string text = options.ToString();

            Assert.DoesNotContain("assertion-presented", text, StringComparison.Ordinal, text);
            Assert.AreEqual("IdJagRedeemOptions { IsAssertionPresent = True, SigningKeyId = kid-client-1 }", text);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see cref="IdJagMintRequestRule.Build"/> refuses a <see langword="null"/> set of audiences with
    /// <see cref="ArgumentNullException"/>, a caller's own bad argument, a rule of this library.
    /// </summary>
    [TestMethod]
    public void BuildRefusesANullSetOfAudiences()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() => IdJagMintRequestRule.Build(null!));

        Assert.AreEqual("audiences", exception.ParamName);
    }


    /// <summary>
    /// <see cref="IdJagMintRequestRule.Build"/> refuses an empty set of audiences with
    /// <see cref="ArgumentException"/>: a rule over no Resource Authorization Server classifies no request, and the
    /// set has no mode that covers every audience, a rule of this library.
    /// </summary>
    [TestMethod]
    public void BuildRefusesAnEmptySetOfAudiences()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => IdJagMintRequestRule.Build([]));

        Assert.AreEqual("audiences", exception.ParamName);
    }


    /// <summary>
    /// <see cref="IdJagMintRequestRule.Build"/> refuses a set with a member that is <see langword="null"/>, empty or
    /// white space only with <see cref="ArgumentException"/>: the token endpoint drops an empty <c>audience</c> and
    /// refuses one of white space only before the rule runs, so such a member could match no request and the rule
    /// built over it would refuse nothing. Refusing the caller's own bad argument is a rule of this library.
    /// </summary>
    /// <param name="member">The member that names no audience.</param>
    [TestMethod]
    [DataRow(null, DisplayName = "a null member")]
    [DataRow("", DisplayName = "an empty member")]
    [DataRow(" ", DisplayName = "a member of one space")]
    public void BuildRefusesAMemberThatNamesNoAudience(string? member)
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => IdJagMintRequestRule.Build([KnownAudience, member!]));

        Assert.AreEqual("audiences", exception.ParamName);
    }


    /// <summary>
    /// <see cref="IdJagMintRequestRule.Build"/> copies the set it is given, a rule of this library: a change the
    /// caller makes to its own list after the rule is built changes no answer. The rule built over
    /// {<see cref="KnownAudience"/>} refuses an ID Token request naming that audience without
    /// <c>requested_token_type</c> after the caller has replaced it in its list with <see cref="LaterAudience"/>,
    /// and passes the same request naming <see cref="LaterAudience"/>.
    /// </summary>
    [TestMethod]
    public async Task TheRuleKeepsTheSetItWasBuiltOverAsync()
    {
        List<string> audiences = [KnownAudience];
        ValidateTokenExchangeRequestDelegate rule = IdJagMintRequestRule.Build(audiences);
        audiences[0] = LaterAudience;

        TokenExchangeRequestRefusal? knownAnswer = await rule(
            IdTokenRequestFor(KnownAudience), Registration, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        TokenExchangeRequestRefusal? laterAnswer = await rule(
            IdTokenRequestFor(LaterAudience), Registration, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(knownAnswer, "The audience the rule was built over must stay in its set.");
        Assert.AreEqual("requested_token_type", knownAnswer.Parameter);
        Assert.IsNull(laterAnswer, "An audience written into the caller's list after the rule was built must not join its set.");
    }


    /// <summary>The registration the rule's delegate is handed; the rule reads none of it.</summary>
    private static ClientRecord Registration { get; } = new()
    {
        ClientId = "https://machine.example.com",
        TenantId = "token-exchange-records",
        AllowedCapabilities = ImmutableHashSet<CapabilityIdentifier>.Empty,
        AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
        AllowedScopes = ImmutableHashSet<string>.Empty,
        TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
        SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
    };


    /// <summary>
    /// Builds a Token Exchange request of an ID Token subject that names <paramref name="audience"/> and states no
    /// <c>requested_token_type</c>.
    /// </summary>
    /// <param name="audience">The one <c>audience</c> the request names.</param>
    /// <returns>The request.</returns>
    private static TokenExchangeRequest IdTokenRequestFor(string audience) =>
        new()
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.IdToken,
            Audience = [audience]
        };
}

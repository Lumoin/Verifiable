using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit and real-wire tests for <see cref="JwtBearerRequestBuilder"/> — the client side of an
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.1">RFC 7523 §2.1</see> JWT Bearer
/// authorization-grant request. Covers: the minimal REQUIRED-only shape, the open
/// <see cref="JwtBearerBuilderOptions.AdditionalParameters"/> seam, reserved-name-collision rejection
/// with exact errors, and a round-trip of the builder's output through the SHIPPED jwt-bearer
/// authorization-server endpoint that <see cref="JwtBearerGrantTests"/> exercises via hand-built
/// dictionaries.
/// </summary>
[TestClass]
internal sealed class JwtBearerRequestBuilderTests
{
    private const string ClientId = "https://machine.example.com";
    private const string ClientSecret = "s3cret-of-the-machine";
    private const string AssertionValue = "eyJhbGciOiJFUzI1NiJ9.opaque-assertion-blob.signature";
    private const string AssertionSubject = "https://user.example/alice";
    private const string GrantedScope = "read";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);


    /// <summary>The minimal REQUIRED-only shape (RFC 7523 §2.1): <c>grant_type</c> and <c>assertion</c>, nothing else.</summary>
    [TestMethod]
    public void BuildWithAssertionOnlyProducesTheMinimalTwoFieldRequest()
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> result = JwtBearerRequestBuilder.Build(new JwtBearerBuilderOptions
        {
            Assertion = AssertionValue
        });

        Assert.IsTrue(result.IsSuccess);
        OutgoingFormFields form = result.Value;
        Assert.HasCount(2, form);
        Assert.AreEqual(WellKnownGrantTypes.JwtBearer, form[OAuthRequestParameterNames.GrantType]);
        Assert.AreEqual(AssertionValue, form[OAuthRequestParameterNames.Assertion]);
    }


    /// <summary>RFC 7523 §2.1: "the 'scope' parameter may be used ... to indicate the requested scope." Present when supplied.</summary>
    [TestMethod]
    public void ScopeIsIncludedWhenSupplied()
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> result = JwtBearerRequestBuilder.Build(new JwtBearerBuilderOptions
        {
            Assertion = AssertionValue,
            Scope = GrantedScope
        });

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(GrantedScope, result.Value[OAuthRequestParameterNames.Scope]);
    }


    /// <summary>
    /// The open <see cref="JwtBearerBuilderOptions.AdditionalParameters"/> seam merges a
    /// non-reserved, vendor-neutral parameter name straight onto the form — the substrate a
    /// deployment composes a vendor-specific token-request recipe from without the library ever
    /// naming that vendor anywhere in <c>src/**</c>.
    /// </summary>
    [TestMethod]
    public void AdditionalParameterMergesOntoTheFormFields()
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> result = JwtBearerRequestBuilder.Build(new JwtBearerBuilderOptions
        {
            Assertion = AssertionValue,
            AdditionalParameters = new Dictionary<string, string> { ["requested_actor_context"] = "billing-team" }
        });

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("billing-team", result.Value["requested_actor_context"]);
    }


    /// <summary>
    /// <see cref="JwtBearerRequestBuilder.ReservedParameterNames"/> is exactly the RFC 7523 §2.1 core
    /// set (<c>grant_type</c>, <c>assertion</c>, <c>scope</c>) plus the RFC 6749 §2.3.1 /
    /// RFC 7523 §2.2 client-authentication parameters (<c>client_id</c>, <c>client_secret</c>,
    /// <c>client_assertion</c>, <c>client_assertion_type</c>) — seven names, no more, no fewer.
    /// </summary>
    [TestMethod]
    public void ReservedParameterNamesCoverExactlyTheSetFromTheRfcTexts()
    {
        Assert.AreSequenceEqual(
            new[]
            {
                OAuthRequestParameterNames.GrantType,
                OAuthRequestParameterNames.Assertion,
                OAuthRequestParameterNames.Scope,
                OAuthRequestParameterNames.ClientId,
                OAuthRequestParameterNames.ClientSecret,
                OAuthRequestParameterNames.ClientAssertion,
                OAuthRequestParameterNames.ClientAssertionType
            },
            JwtBearerRequestBuilder.ReservedParameterNames.ToArray(),
            SequenceOrder.InAnyOrder);
    }


    /// <summary>
    /// An <see cref="JwtBearerBuilderOptions.AdditionalParameters"/> entry whose name collides with a
    /// reserved name is rejected via the exact <see cref="ReservedParameterNameCollision"/> — never
    /// silently merged over the core or client-authentication parameter it would otherwise corrupt.
    /// <c>[DataRow]</c> arguments must be compile-time constants, so the reserved names are literal
    /// wire strings here (the same values <see cref="OAuthRequestParameterNames"/> defines).
    /// </summary>
    [TestMethod]
    [DataRow("grant_type")]
    [DataRow("assertion")]
    [DataRow("scope")]
    [DataRow("client_id")]
    [DataRow("client_secret")]
    [DataRow("client_assertion")]
    [DataRow("client_assertion_type")]
    public void AdditionalParameterCollidingWithAReservedNameIsRejectedWithExactError(string reservedName)
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> result = JwtBearerRequestBuilder.Build(new JwtBearerBuilderOptions
        {
            Assertion = AssertionValue,
            AdditionalParameters = new Dictionary<string, string> { [reservedName] = "attacker-supplied-value" }
        });

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(new ReservedParameterNameCollision(reservedName), result.Error);
    }


    /// <summary>
    /// End-to-end proof that <see cref="JwtBearerRequestBuilder"/>'s output interoperates with the
    /// SHIPPED jwt-bearer endpoint: build a request, attach <c>client_secret_post</c> via
    /// <see cref="OutgoingFormFieldsClientAuthExtensions.WithClientSecretPost"/>, POST it over a real
    /// Kestrel-hosted wire, and confirm the AS issues a Bearer access token for the assertion's
    /// subject — the same seams and assertions <see cref="JwtBearerGrantTests.ValidAssertionIssuesBearerAccessTokenOverHttpWire"/>
    /// exercises via a hand-built dictionary.
    /// </summary>
    [TestMethod]
    public async Task BuilderOutputRoundTripsThroughShippedEndpointOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterJwtBearerClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await WireAcceptingValidatorAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        Result<OutgoingFormFields, TokenRequestBuilderError> built = JwtBearerRequestBuilder.Build(new JwtBearerBuilderOptions
        {
            Assertion = AssertionValue
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
    /// A <see cref="JwtBearerBuilderOptions.Scope"/> of white space only is omitted by this library's
    /// normalization at the builder, so the request the builder produces carries no <c>scope</c>
    /// parameter.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 section 3.3</see> defines
    /// the value as <c>scope = scope-token *( SP scope-token )</c> with
    /// <c>scope-token = 1*( %x21 / %x23-5B / %x5D-7E )</c>, and neither a space (%x20) nor a tab (%x09)
    /// is in a <c>scope-token</c>, so such a value holds no <c>scope-token</c>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 section 3.2</see>'s
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// governs an empty value only, not this one. The request with <c>client_secret_post</c> is
    /// posted over the loopback listener to the shipped token endpoint, which answers 200, and the
    /// fields it received are exactly those of a request that names no scope.
    /// </summary>
    /// <param name="scope">The white-space-only <see cref="JwtBearerBuilderOptions.Scope"/> the builder is given.</param>
    [TestMethod]
    [DataRow(" ")]
    [DataRow("\t")]
    public async Task AScopeOfWhiteSpaceOnlyIsSentAsNoScopeAsync(string scope)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterJwtBearerClientAsync(app).ConfigureAwait(false);
        List<RequestFields> receivedFields = [];
        await WireClientAuthenticationAsync(app, receivedFields).ConfigureAwait(false);
        await WireAcceptingValidatorAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        Result<OutgoingFormFields, TokenRequestBuilderError> built = JwtBearerRequestBuilder.Build(new JwtBearerBuilderOptions
        {
            Assertion = AssertionValue,
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
            ["assertion", "client_id", "client_secret", "grant_type"],
            receivedFields[0].Keys.Order(StringComparer.Ordinal).ToArray());
    }


    /// <summary>Registers a confidential client allowed the <see cref="WellKnownCapabilityIdentifiers.OAuthJwtBearer"/> capability, with the signing keys the RFC 9068 access-token producer needs.</summary>
    private static async Task<VerifierKeyMaterial> RegisterJwtBearerClientAsync(TestHostShell app) =>
        await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthJwtBearer,
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


    /// <summary>Wires an assertion-validation seam that accepts any assertion and returns the fixture subject and granted scope.</summary>
    private static async Task WireAcceptingValidatorAsync(TestHostShell app) =>
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                static (assertion, requestedScope, registration, context, ct) =>
                    ValueTask.FromResult<JwtBearerGrant?>(
                        new JwtBearerGrant { Subject = AssertionSubject, Scope = GrantedScope });
        }).ConfigureAwait(false);


}

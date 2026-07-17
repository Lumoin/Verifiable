using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Real-wire proof that <see cref="JwtBearerRequestBuilder"/>'s open
/// <see cref="JwtBearerBuilderOptions.AdditionalParameters"/> seam (RFC 7523 §2.1) composes with the
/// RFC 6749 §2.3.1 <c>client_secret_post</c> attach helper to build a vendor-specific delegation-flavored
/// token request without the library ever naming that vendor or parameter — the pattern several identity
/// providers' cross-service delegation flows use, for example Microsoft Entra ID's OAuth 2.0
/// On-Behalf-Of flow, which layers a <c>requested_token_use=on_behalf_of</c> parameter onto an otherwise
/// standard RFC 7523 jwt-bearer request. This is the composability proof for that shape of integration,
/// not a claim that the library implements an on-behalf-of feature: the vendor and parameter are named
/// only in this doc comment (the same test-side interop-citation convention
/// <see cref="IdJagGrantTests"/> uses for Okta/Auth0), never in <c>src/**</c>, and the test code below
/// uses only literal wire strings.
/// </summary>
[TestClass]
internal sealed class VendorParameterRecipeTests
{
    private const string ClientId = "https://machine.example.com";
    private const string ClientSecret = "s3cret-of-the-machine";
    private const string AssertionValue = "eyJhbGciOiJFUzI1NiJ9.opaque-assertion-blob.signature";
    private const string AssertionSubject = "https://user.example/alice";
    private const string GrantedScope = "read";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);


    /// <summary>
    /// The composed recipe over a real Kestrel-hosted wire: the builder's open seam carries the extra
    /// parameter into the form fields, <c>client_secret_post</c> attaches client authentication, and the
    /// authorization server's client-authentication seam — the one place the full posted field set is
    /// visible to the application — observes and requires the extra parameter's exact value before the
    /// grant issues a Bearer access token.
    /// </summary>
    [TestMethod]
    public async Task AdditionalParameterReachesTheAuthorizationServerOverHttpWireAndIsValidated()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterClient(app);
        WireClientAuthenticationRequiringAdditionalParameter(app);
        WireAcceptingAssertionValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        Result<OutgoingFormFields, TokenRequestBuilderError> built = JwtBearerRequestBuilder.Build(new JwtBearerBuilderOptions
        {
            Assertion = AssertionValue,
            AdditionalParameters = new Dictionary<string, string> { ["requested_token_use"] = "on_behalf_of" }
        });
        Assert.IsTrue(built.IsSuccess);
        OutgoingFormFields form = built.Value!.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, doc.RootElement.GetProperty("token_type").GetString());
    }


    /// <summary>
    /// The converse, proving the parameter genuinely travels the wire rather than being ignored: a
    /// request built WITHOUT the additional parameter authenticates with a correct <c>client_secret</c>
    /// but is still refused, because THIS deployment's client-authentication seam additionally requires
    /// it — a policy the application composed entirely above the generic seam, with no library change.
    /// </summary>
    [TestMethod]
    public async Task RequestWithoutTheAdditionalParameterFailsTheDeploymentSpecificAuthenticationCheck()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterClient(app);
        WireClientAuthenticationRequiringAdditionalParameter(app);
        WireAcceptingAssertionValidator(app);

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
        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidClient, body);
    }


    /// <summary>Registers the confidential client allowed the <see cref="WellKnownCapabilityIdentifiers.OAuthJwtBearer"/> capability.</summary>
    private static VerifierKeyMaterial RegisterClient(TestHostShell app) =>
        app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthJwtBearer,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));


    /// <summary>
    /// A deployment-specific <c>client_secret_post</c> (RFC 6749 §2.3.1) authentication seam that ALSO
    /// requires the additional form field the composability recipe adds — exactly where an application
    /// would implement its own vendor-flavored policy without any library change, since
    /// <see cref="ValidateClientCredentialsDelegate"/> receives the full posted field set.
    /// </summary>
    private static void WireClientAuthenticationRequiringAdditionalParameter(TestHostShell app) =>
        app.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal)
                && fields.TryGetValue("requested_token_use", out string? tokenUse)
                && string.Equals(tokenUse, "on_behalf_of", StringComparison.Ordinal));


    /// <summary>Wires an assertion-validation seam that accepts any assertion and returns the fixture subject and granted scope.</summary>
    private static void WireAcceptingAssertionValidator(TestHostShell app) =>
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            static (assertion, requestedScope, registration, context, ct) =>
                ValueTask.FromResult<JwtBearerGrant?>(
                    new JwtBearerGrant { Subject = AssertionSubject, Scope = GrantedScope });
}

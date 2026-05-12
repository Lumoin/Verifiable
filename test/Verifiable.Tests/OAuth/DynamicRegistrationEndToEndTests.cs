using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end test exercising dynamic client registration into an AuthCode
/// flow. The test gate for phase 4: when it passes, every type phases 1–3
/// introduced has been exercised in one continuous flow.
/// </summary>
[TestClass]
internal sealed class DynamicRegistrationEndToEndTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static readonly Uri DefaultRedirectUri = new("https://client.example.com/callback");


    [TestMethod]
    public async Task RegisterAsyncIssuesClientIdAndDrivesAuthCodeFlow()
    {
        using TestHostShell host = new(TimeProvider);

        OAuthClient client = host.CreateOAuthClientWithoutRegistration();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        ClientMetadata metadata = new()
        {
            ClientName = "phase-4-test-client",
            RedirectUris = [DefaultRedirectUri],
            TokenEndpointAuthMethod = ClientAuthenticationMethod.None,
            Scope = "openid"
        };

        RegisterClientOptions registerOptions = new()
        {
            RegistrationEndpoint = host.GlobalRegistrationEndpoint,
            AuthorizationServerIssuer = host.IssuerUri,
            Metadata = metadata,
            AuthenticationMethod = ClientAuthenticationMethod.None,
            SigningKeyMaterial = signingKey,
            Profile = PolicyProfile.Haip10
        };

        DynamicRegistrationResult result = await client.DynamicRegistration
            .RegisterAsync(registerOptions, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsNotNull(result.Registration.ClientId.Value,
            "AS-issued client_id must be non-null.");
        Assert.IsNotNull(result.Response.AccessToken,
            "AS must issue a registration_access_token alongside the client_id.");
        Assert.AreEqual(host.IssuerUri, result.Registration.AuthorizationServerIssuer,
            "Registration AS issuer must equal the host's issuer URI.");

        //Drive an AuthCode flow against the dynamically registered client.
        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            result.Registration,
            DefaultRedirectUri,
            OAuthFormEncodedFields.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR against dynamically registered client must succeed. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");
        Assert.IsNotNull(parResult.RedirectUri);
        Assert.Contains("request_uri", parResult.RedirectUri!.ToString(), StringComparison.Ordinal,
            "Authorize redirect URI must carry the PAR-issued request_uri.");
    }
}

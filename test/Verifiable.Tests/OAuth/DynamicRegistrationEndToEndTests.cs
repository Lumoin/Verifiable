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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static readonly Uri DefaultRedirectUri = new("https://client.example.com/callback");


    [TestMethod]
    public async Task RegisterAsyncIssuesClientIdAndDrivesAuthCodeFlow()
    {
        await using TestHostShell host = new(TimeProvider);

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


    [TestMethod]
    public async Task RegistrationLifecycleRegistersReadsUpdatesAndDeregisters()
    {
        await using TestHostShell host = new(TimeProvider);

        OAuthClient client = host.CreateOAuthClientWithoutRegistration();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        ClientMetadata initialMetadata = new()
        {
            ClientName = "phase-5-lifecycle-client",
            RedirectUris = [DefaultRedirectUri],
            TokenEndpointAuthMethod = ClientAuthenticationMethod.None,
            Scope = WellKnownScopes.OpenId
        };

        RegisterClientOptions registerOptions = new()
        {
            RegistrationEndpoint = host.GlobalRegistrationEndpoint,
            AuthorizationServerIssuer = host.IssuerUri,
            Metadata = initialMetadata,
            AuthenticationMethod = ClientAuthenticationMethod.None,
            SigningKeyMaterial = signingKey,
            Profile = PolicyProfile.Haip10
        };

        //Register.
        DynamicRegistrationResult registered = await client.DynamicRegistration
            .RegisterAsync(registerOptions, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsNotNull(registered.Registration.ClientId.Value);
        Assert.IsNotNull(registered.Registration.ManagementUri);
        Assert.IsNotNull(registered.Registration.AccessToken);

        //Read.
        ClientMetadata fetchedAfterRegister = await client.DynamicRegistration
            .ReadAsync(registered.Registration, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(initialMetadata.Scope, fetchedAfterRegister.Scope);
        Assert.HasCount(1, fetchedAfterRegister.RedirectUris,
            "Read must echo the single registered redirect_uri.");

        //Update.
        ClientMetadata updatedMetadata = initialMetadata with
        {
            ClientName = "phase-5-lifecycle-client-renamed",
            Scope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile}"
        };

        ClientMetadata appliedAfterUpdate = await client.DynamicRegistration
            .UpdateAsync(registered.Registration, updatedMetadata, TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Scope is a set on the wire per RFC 6749 §3.3 — order is not significant.
        //The server stores it as ImmutableHashSet and emits via deterministic
        //alphabetic sort, so the wire order is stable but caller code should
        //still treat scope as a set rather than relying on the ordering.
        HashSet<string> expectedScopes = [WellKnownScopes.OpenId, WellKnownScopes.Profile];
        HashSet<string> appliedScopes = SplitScope(appliedAfterUpdate.Scope);
        Assert.IsTrue(appliedScopes.SetEquals(expectedScopes),
            $"Update response must echo the new scope tokens; got '{appliedAfterUpdate.Scope}'.");

        //Read again — confirms the update persisted on the AS side.
        ClientMetadata fetchedAfterUpdate = await client.DynamicRegistration
            .ReadAsync(registered.Registration, TestContext.CancellationToken)
            .ConfigureAwait(false);

        HashSet<string> fetchedScopes = SplitScope(fetchedAfterUpdate.Scope);
        Assert.IsTrue(fetchedScopes.SetEquals(expectedScopes),
            $"Second read must reflect the updated scope tokens; got '{fetchedAfterUpdate.Scope}'.");

        //Deregister.
        await client.DynamicRegistration
            .DeregisterAsync(registered.Registration, TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Subsequent read must fail — the registration no longer exists.
        InvalidOperationException postDeleteRead = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await client.DynamicRegistration
                .ReadAsync(registered.Registration, TestContext.CancellationToken)
                .ConfigureAwait(false)).ConfigureAwait(false);

        Assert.Contains("RFC 7592 read failed", postDeleteRead.Message, StringComparison.Ordinal);
    }


    private static HashSet<string> SplitScope(string? scope) =>
        [.. (scope ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries)];
}

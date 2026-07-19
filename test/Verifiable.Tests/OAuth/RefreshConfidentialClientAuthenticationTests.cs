using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Mirrors <see cref="AuthCodeClientAuthenticationTests"/> for the REFRESH leg: the real
/// <see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, ExchangeContext, ClientAssertionOptions?, System.Threading.CancellationToken)"/>
/// attaches confidential-client authentication automatically per
/// <see cref="ClientRegistration.AuthenticationMethod"/>, over the real wire, for every declared
/// method — <c>client_secret_post</c>, <c>client_secret_basic</c>, and <c>private_key_jwt</c> — as
/// well as leaving a <see cref="ClientAuthenticationMethod.None"/> public client's refresh untouched.
/// Before this fix the refresh leg posted <see cref="Verifiable.OAuth.OutgoingHeaders.Empty"/>
/// regardless of the declared method, so a confidential client's refresh always 401'd
/// <c>invalid_client</c>; <see cref="ClientRecord.TokenEndpointAuthMethod"/> is set server-side so
/// the refresh fails closed (draft-ietf-oauth-client-id-metadata-document-02 §8.2, CIMD-049/050)
/// without the attached credential — a passing refresh therefore proves the client attached it, not
/// that the server never asked.
/// </summary>
[TestClass]
internal sealed class RefreshConfidentialClientAuthenticationTests
{
    /// <summary>MSTest's per-test context, supplying the cancellation token every wire call runs under.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the client share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://confidential-refresh.client.test";

    private const string SubjectId = "subject-confidential-refresh-01";

    private const string ClientSecret = "s3cret-of-the-confidential-refreshing-client";

    private static Uri ClientBaseUri { get; } = new(ClientId);

    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// <c>client_secret_post</c> (RFC 6749 §2.3.1): the real client attaches <c>client_id</c> +
    /// <c>client_secret</c> to the REFRESH request body — no explicit <see cref="ClientAssertionOptions"/>
    /// needed, driven through the plain <see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, System.Threading.CancellationToken)"/>
    /// path — and the server-side declared-method invariant requires it on the refresh leg too.
    /// </summary>
    [TestMethod]
    public async Task ClientSecretPostRefreshesOverRealWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
            DeclareServerSideAuthMethod(host, material, ClientAuthenticationMethod.ClientSecretPost);

            host.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
                AuthenticationKeyMaterial = secretMaterial
            };

            await DriveInitialIssuanceAndAssertRefreshSucceedsAsync(
                host, client, registration, clientFlowStore, material.Registration.TenantId.Value).ConfigureAwait(false);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <c>client_secret_basic</c> (RFC 6749 §2.3.1): the real client attaches an HTTP Basic
    /// <c>Authorization</c> header to the refresh POST — again through the plain <c>RefreshAsync</c>
    /// path, since this method needs no per-call <see cref="ClientAssertionOptions"/> either.
    /// </summary>
    [TestMethod]
    public async Task ClientSecretBasicRefreshesOverRealWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
            DeclareServerSideAuthMethod(host, material, ClientAuthenticationMethod.ClientSecretBasic);

            host.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(DecodeAndMatchBasicHeader(request, registration.ClientId, ClientSecret));

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretBasic,
                AuthenticationKeyMaterial = secretMaterial
            };

            await DriveInitialIssuanceAndAssertRefreshSucceedsAsync(
                host, client, registration, clientFlowStore, material.Registration.TenantId.Value).ConfigureAwait(false);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <c>private_key_jwt</c> (RFC 7523 §2.2): the real client signs and attaches a fresh
    /// <c>client_assertion</c> to the refresh POST from <see cref="TestKeyMaterialProvider"/>-generated
    /// P-256 key material, driven through <see cref="AuthCodeFlowDriver.DriveRefreshAsync"/>'s
    /// <see cref="ClientAssertionOptions"/> overload, verified server-side by the real
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?)"/>
    /// pipeline over a published <c>ClientJwks</c> — the same production shape
    /// <see cref="PrivateKeyJwtClientAuthenticationTests"/> exercises directly.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtRefreshesOverRealWire()
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

            //Start the listener before wiring the validator so the resolved token endpoint URL
            //(the client-signed aud, per RFC 7523 §3 item 3) is known.
            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            const string SigningKeyId = "confidential-refresh-client-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, SigningKeyId);
            DeclareServerSideAuthMethod(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt, clientJwks: jwksJson);

            host.Server.OAuth().ValidateClientCredentialsAsync =
                PrivateKeyJwtClientAuthentication.BuildValidator(
                    additionalAcceptedAudiences: [tokenEndpoint.OriginalString]);

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                AuthenticationKeyMaterial = clientKeys
            };

            ClientAssertionOptions assertionOptions = new()
            {
                SigningKeyId = SigningKeyId,
                HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
            };

            await DriveInitialIssuanceAndAssertRefreshSucceedsAsync(
                host, client, registration, clientFlowStore, segment,
                clientAssertionOptions: assertionOptions).ConfigureAwait(false);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A public client (<see cref="ClientAuthenticationMethod.None"/>, the default) attaches no
    /// credential at either leg and relies on PKCE alone (RFC 6749 §6, §3.2.1) — the refresh leg's
    /// new authentication attachment must not regress this baseline, unauthenticated case.
    /// </summary>
    [TestMethod]
    public async Task NoneAuthPublicClientStillRefreshesOverRealWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
        //TokenEndpointAuthMethod deliberately left unset (null) — a public client presents no
        //credential and the server does not require one.

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);
        //AuthenticationMethod deliberately left at its None default.

        await DriveInitialIssuanceAndAssertRefreshSucceedsAsync(
            host, client, registration, clientFlowStore, material.Registration.TenantId.Value).ConfigureAwait(false);
    }


    /// <summary>
    /// Pins that the positive tests above prove genuine authentication rather than a server that
    /// never checks: a declared confidential client whose refresh request carries no credential at
    /// all (the registration's <see cref="ClientRegistration.AuthenticationMethod"/> stays
    /// <see cref="ClientAuthenticationMethod.None"/> even though the server declared
    /// <c>client_secret_post</c>) still gets refused — the exact 401 <c>invalid_client</c> behavior
    /// this fix corrects FOR an attached credential, preserved for a MISSING one.
    /// </summary>
    [TestMethod]
    public async Task DeclaredConfidentialClientRefreshWithoutAttachedCredentialFailsClosed()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
            DeclareServerSideAuthMethod(host, material, ClientAuthenticationMethod.ClientSecretPost);

            host.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);

            //The AUTHENTICATED registration mints the initial tokens (the code-exchange leg is not
            //under test here and must succeed to obtain a refresh token to attempt refreshing with).
            ClientRegistration authenticated = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
                AuthenticationKeyMaterial = secretMaterial
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
                hosted, client, authenticated, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            string originalRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];

            //The refresh attempt itself uses the UNAUTHENTICATED registration — None stays the
            //client's declared method even though the server requires client_secret_post.
            RefreshTokenRequest refreshRequest = new()
            {
                ClientId = registration.ClientId.Value,
                RefreshToken = originalRefreshToken
            };
            AuthCodeFlowEndpointResult refreshResult = await client.AuthCode.RefreshAsync(
                registration, refreshRequest, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
                "A declared confidential client refreshing without an attached credential must not be issued new tokens.");
            Assert.AreEqual(OAuthErrors.InvalidClient, refreshResult.ErrorCode);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Drives PAR → authorize → callback → token over the real wire to obtain an initial refresh
    /// token, then refreshes through <see cref="AuthCodeFlowDriver.DriveRefreshAsync"/> — asserting
    /// both legs, including the refresh the confidential-auth attachment under test gates, succeeded
    /// and rotated in a fresh access token.
    /// </summary>
    private async Task DriveInitialIssuanceAndAssertRefreshSucceedsAsync(
        TestHostShell host,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string tenantSegment,
        ClientAssertionOptions? clientAssertionOptions = null)
    {
        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, tenantSegment, RedirectUri, SubjectId, browserClient,
            scope: WellKnownScopes.OpenId, clientAssertionOptions: clientAssertionOptions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string originalAccessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string originalRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];
        Assert.IsFalse(string.IsNullOrEmpty(originalRefreshToken), "The initial issuance must include a refresh_token.");

        RefreshTokenRequest refreshRequest = new()
        {
            ClientId = registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult refreshResult = await AuthCodeFlowDriver.DriveRefreshAsync(
            client, registration, refreshRequest, clientAssertionOptions, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string newAccessToken = (string)refreshResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.IsFalse(string.IsNullOrEmpty(newAccessToken), "The AS must mint a fresh access token on refresh.");
        Assert.AreNotEqual(originalAccessToken, newAccessToken,
            "Refresh must issue a fresh access token, not return the original.");
    }


    /// <summary>
    /// Re-registers the server-side <see cref="ClientRecord"/> with
    /// <see cref="ClientRecord.TokenEndpointAuthMethod"/> set to <paramref name="method"/> — the
    /// declared-client shape draft-ietf-oauth-client-id-metadata-document-02 §8.2 (CIMD-049/050) gates
    /// on, so a passing refresh proves the client attached the credential the server actually
    /// required. Uses the register-then-upgrade pattern the sibling grant suites use, because the
    /// routing dictionaries are host-internal.
    /// </summary>
    private static void DeclareServerSideAuthMethod(
        TestHostShell host, VerifierKeyMaterial material, ClientAuthenticationMethod method, string? clientJwks = null)
    {
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        ClientRecord previous = hosted.Registrations[segment];
        ClientRecord updated = previous with
        {
            TokenEndpointAuthMethod = method,
            ClientJwks = clientJwks
        };

        hosted.Registrations[segment] = updated;
        hosted.Registrations[updated.ClientId] = updated;
        hosted.Server.UpdateClient(previous, updated, new ExchangeContext());

        material.Registration = updated;
    }


    /// <summary>
    /// Wraps <paramref name="secret"/>'s UTF-8 bytes as a <see cref="PrivateKeyMemory"/> carrying no
    /// crypto tag (<see cref="Tag.Empty"/>) — a bare RFC 6749 §2.3.1 shared secret is not an
    /// asymmetric key, so none of the existing <see cref="CryptoTags"/> algorithm-specific entries
    /// apply. The paired <see cref="PublicKeyMemory"/> is never read (only
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>'s <c>PrivateKey</c> half is
    /// consulted for <c>client_secret_post</c>/<c>client_secret_basic</c>).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller, which disposes both halves via secretMaterial.PublicKey/PrivateKey.")]
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> BuildSecretKeyMaterial(string secret)
    {
        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
        IMemoryOwner<byte> secretOwner = Pool.Rent(secretBytes.Length);
        secretBytes.CopyTo(secretOwner.Memory.Span);
        PrivateKeyMemory privateKey = new(secretOwner, Tag.Empty);

        //Never read — client_secret_post/basic consult only the PrivateKey half — but a
        //PublicPrivateKeyMaterial pair requires one regardless.
        IMemoryOwner<byte> unusedPublicOwner = Pool.Rent(1);
        PublicKeyMemory publicKey = new(unusedPublicOwner, Tag.Empty);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKey, privateKey);
    }


    /// <summary>
    /// The test-side reverse of <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/>
    /// (RFC 6749 §2.3.1): base64-decode the <c>Authorization: Basic</c> header, split the pair on the
    /// first <c>:</c> (the join character the encoder never percent-encodes into either half), and
    /// reverse <c>application/x-www-form-urlencoded</c> on each half — <see cref="ClientId"/> contains
    /// <c>:</c> and <c>/</c>, both of which the encoder percent-escapes, so a naive raw comparison
    /// would never match.
    /// </summary>
    private static bool DecodeAndMatchBasicHeader(
        IncomingRequest? request, string expectedClientId, string expectedClientSecret)
    {
        if(request is null
            || !request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authorizationHeader)
            || authorizationHeader is null
            || !authorizationHeader.StartsWith("Basic ", StringComparison.Ordinal))
        {
            return false;
        }

        byte[] decoded = Convert.FromBase64String(authorizationHeader["Basic ".Length..]);
        string pair = Encoding.UTF8.GetString(decoded);
        int separatorIndex = pair.IndexOf(':', StringComparison.Ordinal);
        if(separatorIndex < 0)
        {
            return false;
        }

        string decodedClientId = FormUrlDecode(pair[..separatorIndex]);
        string decodedClientSecret = FormUrlDecode(pair[(separatorIndex + 1)..]);

        return string.Equals(decodedClientId, expectedClientId, StringComparison.Ordinal)
            && string.Equals(decodedClientSecret, expectedClientSecret, StringComparison.Ordinal);
    }


    /// <summary>Reverses <c>application/x-www-form-urlencoded</c> (RFC 6749 Appendix B): <c>+</c> becomes space, then <see cref="Uri.UnescapeDataString"/> resolves the remaining <c>%XX</c> triplets.</summary>
    private static string FormUrlDecode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));


    private static string BuildJwksJson(IReadOnlyDictionary<string, string> jwk, string kid)
    {
        StringBuilder sb = new();
        sb.Append('{').Append('"').Append(WellKnownJwkMemberNames.Keys).Append("\":[{");
        foreach(KeyValuePair<string, string> member in jwk)
        {
            sb.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append("\",");
        }

        sb.Append('"').Append(WellKnownJwkMemberNames.Kid).Append("\":\"").Append(kid).Append("\"}]}");

        return sb.ToString();
    }
}

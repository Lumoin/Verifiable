using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oidc;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Firewalled end-to-end scenario for the OIDC Core §3.1.3.7 checks
/// <see cref="Oidc10IdTokenValidator.ValidateAsync"/> enforces only when the caller opts in: the
/// <c>nonce</c> conditional-MUST and the untrusted-audience rejection MUST. Also proves that
/// <c>auth_time</c>/<c>acr</c>/<c>sid</c> are surfaced on every successful validation regardless of
/// whether the caller enforces them, so a caller that requested <c>acr_values</c>/<c>max_age</c> can
/// apply those §3.1.3.7 SHOULDs itself. Every id_token is minted through the REAL pipeline — a full
/// PAR → Authorize → Token exchange over the library's production issuance path; the relying party
/// reconstructs from the wire body alone and runs the full validation including the signature, the
/// same shape <see cref="AzpMultiAudienceScenarioTests"/> uses for the azp scenarios.
/// </summary>
[TestClass]
internal sealed class Oidc10IdTokenNonceAudienceScenarioTests
{
    private const string ClientId = "https://oidc-nonce-aud.client.test";
    private const string SubjectId = "subject-oidc-nonce-aud-1";
    private const string SecondAudience = "https://second-audience.example.com";
    private const string EstablishedAcr = "urn:example:acr:established-loa";
    private const string EstablishedSessionId = "session-oidc-nonce-aud-01";

    private static Uri ClientBaseUri { get; } = new(ClientId);
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");
    private static TimeSpan IatSkew { get; } = TimeSpan.FromSeconds(60);

    //Test-local claim id for the deployment contributor adding a second audience; the
    //WellKnownClaimIds registry holds the library-shipped ones.
    private static ClaimId SecondAudienceClaimId { get; } = ClaimId.Create(9110, "TestSecondAudience");

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);


    /// <summary>An id_token whose nonce equals the expected value validates, and the authentication-context claims arrive on the result.</summary>
    [TestMethod]
    public async Task MatchingNonceValidatesAndSurfacesAuthenticationContext()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //acr is emitted on the original-authentication id_token exclusively from the application's
        //OIDC-claims resolver (AcrAmrClaimContributor's documented behaviour); sid comes from the
        //authorize-time ExchangeContext stamp instead, wired below via SetSessionId.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveOidcClaimsAsync = (subject, grantedScope, tenantId, ctx, cancellationToken) =>
                ValueTask.FromResult<OidcClaims?>(new OidcClaims
                {
                    Subject = subject,
                    AuthContext = new AuthenticationContext { Acr = EstablishedAcr }
                });
        }).ConfigureAwait(false);

        const string RequestNonce = "nonce-match-01";
        string idToken = await DriveCodeExchangeForIdTokenAsync(
            host, material, nonce: RequestNonce, stampSessionId: true).ConfigureAwait(false);

        Oidc10IdTokenValidationResult result = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedNonce: RequestNonce, trustedAudiences: null).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess,
            $"An id_token whose nonce matches the expected nonce must validate; got {result.FailureReason}: {result.FailureDescription}");
        Assert.AreEqual(RequestNonce, result.Claims!.Nonce);
        Assert.IsNotNull(result.Claims.AuthTime, "auth_time must be surfaced — the AS always establishes it at authorize time.");
        Assert.AreEqual(EstablishedAcr, result.Claims.Acr);
        Assert.AreEqual(EstablishedSessionId, result.Claims.Sid);
    }


    /// <summary>An id_token whose nonce differs from the expected value is rejected with <see cref="JwsAccessTokenValidationFailureReason.NonceMismatch"/>.</summary>
    [TestMethod]
    public async Task MismatchedNonceIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string idToken = await DriveCodeExchangeForIdTokenAsync(
            host, material, nonce: "nonce-actual-01", stampSessionId: false).ConfigureAwait(false);

        Oidc10IdTokenValidationResult result = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedNonce: "nonce-expected-different-01", trustedAudiences: null).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.NonceMismatch, result.FailureReason,
            "A nonce that does not equal the expected value must be rejected (OIDC Core §3.1.3.7).");
    }


    /// <summary>An id_token carrying no nonce is rejected when a nonce is expected, but validates when the caller checks none.</summary>
    [TestMethod]
    public async Task AbsentNonceIsRejectedOnlyWhenExpected()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //No nonce sent in the authentication request — the id_token carries none.
        string idToken = await DriveCodeExchangeForIdTokenAsync(
            host, material, nonce: null, stampSessionId: false).ConfigureAwait(false);

        Oidc10IdTokenValidationResult enforced = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedNonce: "nonce-expected-01", trustedAudiences: null).ConfigureAwait(false);

        Assert.IsFalse(enforced.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.NonceMismatch, enforced.FailureReason,
            "An id_token with no nonce must be rejected when the relying party expects one (OIDC Core §3.1.3.7).");

        //A relying party that sent no nonce does not check it — the same wire token validates.
        Oidc10IdTokenValidationResult lenient = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedNonce: null, trustedAudiences: null).ConfigureAwait(false);

        Assert.IsTrue(lenient.IsSuccess,
            $"Without an expected nonce, nonce is surfaced but not enforced; got {lenient.FailureReason}: {lenient.FailureDescription}");
        Assert.IsNull(lenient.Claims!.Nonce);
    }


    /// <summary>
    /// A multi-audience id_token is rejected when the extra audience is outside the relying party's
    /// trust set, accepted when the relying party explicitly trusts it, and accepted when the relying
    /// party supplies no trust set at all (the MUST is opt-in).
    /// </summary>
    [TestMethod]
    public async Task UntrustedAudienceIsRejectedButAcceptedWhenTrustedOrUnchecked()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await ApplySecondAudienceContributorAsync(host).ConfigureAwait(false);

        string idToken = await DriveCodeExchangeForIdTokenAsync(
            host, material, nonce: null, stampSessionId: false).ConfigureAwait(false);

        //A relying party that trusts only the expected audience rejects the extra untrusted one.
        Oidc10IdTokenValidationResult untrusted = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedNonce: null, trustedAudiences: []).ConfigureAwait(false);

        Assert.IsFalse(untrusted.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.UntrustedAudience, untrusted.FailureReason,
            "An aud member outside the caller's trust set must be rejected (OIDC Core §3.1.3.7).");

        //A relying party that explicitly trusts the extra audience accepts the same wire token.
        Oidc10IdTokenValidationResult trusted = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedNonce: null, trustedAudiences: [SecondAudience]).ConfigureAwait(false);

        Assert.IsTrue(trusted.IsSuccess,
            $"An aud member inside the caller's trust set must validate; got {trusted.FailureReason}: {trusted.FailureDescription}");
        Assert.HasCount(2, trusted.Claims!.Audience);
        Assert.Contains(SecondAudience, trusted.Claims.Audience);

        //With no trust set supplied at all, the additional-audience MUST is not enforced.
        Oidc10IdTokenValidationResult noTrustSetSupplied = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedNonce: null, trustedAudiences: null).ConfigureAwait(false);

        Assert.IsTrue(noTrustSetSupplied.IsSuccess,
            $"Without a trusted-audience set, the additional-audience MUST is not enforced; got {noTrustSetSupplied.FailureReason}: {noTrustSetSupplied.FailureDescription}");
    }


    /// <summary>
    /// An id_token validated through <see cref="Oidc10IdTokenValidator.ValidateAsync"/> is rejected with
    /// <see cref="JwsAccessTokenValidationFailureReason.IssuerMismatch"/> when the relying party's
    /// expected issuer does not equal the token's <c>iss</c> — the same shared-core check
    /// <see cref="JwsAccessTokenValidatorTests.ValidatorRejectsIssuerMismatch"/> proves through the
    /// access-token entry point, exercised here through the id_token entry point instead.
    /// </summary>
    [TestMethod]
    public async Task IdTokenWithMismatchedIssuerIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string idToken = await DriveCodeExchangeForIdTokenAsync(
            host, material, nonce: null, stampSessionId: false).ConfigureAwait(false);

        Oidc10IdTokenValidationResult result = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedNonce: null, trustedAudiences: null,
            expectedIssuerOverride: "https://wrong-issuer.example.com").ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.IssuerMismatch, result.FailureReason,
            "An id_token whose iss does not equal the relying party's expected issuer must be rejected (OIDC Core §3.1.3.7).");
    }


    /// <summary>
    /// An id_token validated through <see cref="Oidc10IdTokenValidator.ValidateAsync"/> is rejected with
    /// <see cref="JwsAccessTokenValidationFailureReason.AudienceMismatch"/> when the relying party's
    /// <c>client_id</c> is not a member of the token's <c>aud</c> — the same shared-core check
    /// <see cref="JwsAccessTokenValidatorTests.ValidatorRejectsAudienceMismatch"/> proves through the
    /// access-token entry point, exercised here through the id_token entry point instead.
    /// </summary>
    [TestMethod]
    public async Task IdTokenWithMismatchedAudienceIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string idToken = await DriveCodeExchangeForIdTokenAsync(
            host, material, nonce: null, stampSessionId: false).ConfigureAwait(false);

        Oidc10IdTokenValidationResult result = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedNonce: null, trustedAudiences: null,
            expectedAudienceOverride: "https://unregistered-client.example.com").ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.AudienceMismatch, result.FailureReason,
            "An id_token whose aud does not contain the relying party's client_id must be rejected (OIDC Core §3.1.3.7).");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">OpenID Connect
    /// Core 1.0 §3.1.3.7</see>: "The Client MUST validate the signature of all other ID Tokens according
    /// to JWS [JWS] using the algorithm specified in the JWT alg Header Parameter. The Client MUST use
    /// the keys provided by the Issuer." An id_token the relying party receives in the token response
    /// over the real wire, re-signed under the issuer's key with a protected header whose <c>kid</c> is
    /// a single space, names no key the relying party can use: <see cref="Oidc10IdTokenValidator.ValidateAsync"/> rejects it with
    /// <see cref="JwsAccessTokenValidationFailureReason.InvalidHeader"/> and the description "JWS header
    /// is missing the kid member.", never an exception.
    /// </summary>
    [TestMethod]
    public async Task IdTokenWithWhitespaceKidIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (string idToken, string issuer) = await DriveCodeExchangeOverWireForIdTokenAsync(host, material).ConfigureAwait(false);
        string whitespaceKidIdToken = await CompactJwsResigning.ResignWithHeaderAsync(
            host, idToken, material.SigningKeyId, " ", "JWT").ConfigureAwait(false);

        Oidc10IdTokenValidationResult result = await ValidateAsRelyingPartyAsync(
            whitespaceKidIdToken, material, expectedNonce: null, trustedAudiences: null, expectedIssuerOverride: issuer)
            .ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.InvalidHeader, result.FailureReason);
        Assert.AreEqual("JWS header is missing the kid member.", result.FailureDescription);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">RFC 7519 §4.1.5</see>: "The
    /// "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for
    /// processing." An id_token the relying party receives in the token response over the real wire,
    /// re-signed under the issuer's key with an <c>nbf</c> no instant is represented for
    /// (253402300800, one second after 9999-12-31T23:59:59Z), names a time that cannot be checked:
    /// <see cref="Oidc10IdTokenValidator.ValidateAsync"/> rejects it with
    /// <see cref="JwsAccessTokenValidationFailureReason.Malformed"/>, never as an ID Token carrying no
    /// <c>nbf</c>.
    /// </summary>
    [TestMethod]
    public async Task IdTokenWithUnrepresentableNbfIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (string idToken, string issuer) = await DriveCodeExchangeOverWireForIdTokenAsync(host, material).ConfigureAwait(false);
        string farNotBeforeIdToken = await ResignIdTokenPayloadAsync(
            host, idToken, material.SigningKeyId, payload => payload["nbf"] = 253402300800L).ConfigureAwait(false);

        Oidc10IdTokenValidationResult result = await ValidateAsRelyingPartyAsync(
            farNotBeforeIdToken, material, expectedNonce: null, trustedAudiences: null, expectedIssuerOverride: issuer)
            .ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
        Assert.AreEqual("Access token nbf claim is not a NumericDate naming a representable instant.", result.FailureDescription);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0
    /// §2</see>: <c>auth_time</c>'s "value is a JSON number representing the number of seconds from
    /// 1970-01-01T00:00:00Z as measured in UTC until the date/time." An id_token the relying party receives
    /// in the token response over the real wire, re-signed under the issuer's key with an
    /// <c>auth_time</c> of 9223372036854775807, a value no instant is represented for, is rejected by
    /// <see cref="Oidc10IdTokenValidator.ValidateAsync"/> with
    /// <see cref="JwsAccessTokenValidationFailureReason.Malformed"/>, never surfaced as an absent
    /// <c>auth_time</c> a <c>max_age</c> check would misread.
    /// </summary>
    [TestMethod]
    public async Task IdTokenWithUnrepresentableAuthTimeIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (string idToken, string issuer) = await DriveCodeExchangeOverWireForIdTokenAsync(host, material).ConfigureAwait(false);
        string farAuthTimeIdToken = await ResignIdTokenPayloadAsync(
            host, idToken, material.SigningKeyId, payload => payload["auth_time"] = long.MaxValue).ConfigureAwait(false);

        Oidc10IdTokenValidationResult result = await ValidateAsRelyingPartyAsync(
            farAuthTimeIdToken, material, expectedNonce: null, trustedAudiences: null, expectedIssuerOverride: issuer)
            .ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
        Assert.AreEqual("ID Token auth_time claim is not a NumericDate naming a representable instant.", result.FailureDescription);
    }


    /// <summary>
    /// Drives PAR → Authorize → callback → Token over the host's loopback HTTPS listener through the
    /// library's own client with the <c>openid</c> scope, and returns the <c>id_token</c> of the token
    /// response together with the issuer the client registration names.
    /// </summary>
    /// <param name="host">The host whose listener serves the flow.</param>
    /// <param name="material">The registration the flow runs under.</param>
    /// <returns>The ID Token and the issuer it is expected from.</returns>
    private async Task<(string IdToken, string Issuer)> DriveCodeExchangeOverWireForIdTokenAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            host.Host("default"), client, registration, clientFlowStore, material.Registration.TenantId.Value,
            RedirectUri, SubjectId, browserClient, scope: WellKnownScopes.OpenId,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return ((string)drive.TokenResult.Body![OAuthRequestParameterNames.IdToken],
            registration.AuthorizationServerIssuer.OriginalString);
    }


    /// <summary>
    /// Re-signs an ID Token under <paramref name="keyId"/> with its payload rewritten by
    /// <paramref name="alterPayload"/>, through <see cref="CompactJwsResigning.ResignWithPayloadAsync"/>.
    /// </summary>
    /// <param name="host">The host holding the key's private half.</param>
    /// <param name="idToken">The issued ID Token.</param>
    /// <param name="keyId">The key the rebuilt token is signed under.</param>
    /// <param name="alterPayload">Rewrites the parsed payload.</param>
    /// <returns>The re-signed ID Token.</returns>
    private static async Task<string> ResignIdTokenPayloadAsync(
        TestHostShell host, string idToken, KeyId keyId, Action<JsonObject> alterPayload)
    {
        string[] parts = idToken.Split('.');
        using IMemoryOwner<byte> payloadOwner = TestSetup.Base64UrlDecoder(parts[1], BaseMemoryPool.Shared);
        JsonObject payload = JsonNode.Parse(payloadOwner.Memory.Span)!.AsObject();
        alterPayload(payload);

        return await CompactJwsResigning.ResignWithPayloadAsync(host, idToken, keyId, payload.ToJsonString())
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Replaces the host's claim issuer with the standard rules plus a deployment contributor that
    /// adds a second, application-chosen audience to the ID Token — the shape the untrusted-audience
    /// scenarios validate against.
    /// </summary>
    private async Task ApplySecondAudienceContributorAsync(TestHostShell host)
    {
        List<ClaimDelegate<ClaimContributionTarget>> rules = ContributionProfiles.StandardRules();
        rules.Add(new ClaimDelegate<ClaimContributionTarget>(
            new(ContributeSecondAudience), [SecondAudienceClaimId]));

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClaimIssuer = new ClaimIssuer<ClaimContributionTarget>(
                WellKnownAssessorIds.ClaimContributors, rules, TimeProvider);
        }).ConfigureAwait(false);
    }


    private static ValueTask<List<Claim>> ContributeSecondAudience(
        ClaimContributionTarget target, CancellationToken cancellationToken)
    {
        if(target is not IdTokenTarget)
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(SecondAudienceClaimId, ClaimOutcome.NotApplicable)]);
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            new Claim(SecondAudienceClaimId, ClaimOutcome.Success,
                new ClaimContributionContext(WellKnownJwtClaimNames.Aud, new[] { ClientId, SecondAudience }),
                Claim.NoSubClaims)
        ]);
    }


    /// <summary>
    /// Drives the full PAR → Authorize → Token exchange with the <c>openid</c> scope, optionally
    /// carrying <paramref name="nonce"/> on the authentication request and optionally stamping the
    /// authorize-time <c>sid</c> via <paramref name="stampSessionId"/>, and returns the <c>id_token</c>
    /// from the wire body.
    /// </summary>
    private async Task<string> DriveCodeExchangeForIdTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string? nonce, bool stampSessionId)
    {
        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions
            {
                Scope = WellKnownScopes.OpenId,
                Nonce = nonce,
                SessionId = stampSessionId ? EstablishedSessionId : null
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        return ExtractFromBody(result.TokenResponse.Body, "id_token");
    }


    /// <summary>
    /// The relying party's validation from wire bytes only: full signature verification plus the
    /// §3.1.3.7 issuer/audience checks, with the caller-supplied nonce and trusted-audience
    /// expectations under test. The verification key resolves by the token's kid, the way a
    /// deployment resolves against the fetched JWKS.
    /// </summary>
    private async Task<Oidc10IdTokenValidationResult> ValidateAsRelyingPartyAsync(
        string idToken,
        VerifierKeyMaterial material,
        string? expectedNonce,
        IReadOnlyCollection<string>? trustedAudiences,
        string? expectedIssuerOverride = null,
        string? expectedAudienceOverride = null)
    {
        ValueTask<PublicKeyMemory?> resolveKey(KeyId kid, TenantId tenant, ExchangeContext ctx, CancellationToken ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, material.SigningKeyId.Value, StringComparison.Ordinal)
                    ? material.SigningPublicKey : null);

        return await Oidc10IdTokenValidator.ValidateAsync(
            idToken,
            expectedIssuerOverride ?? material.Registration.IssuerUri!.OriginalString,
            expectedAudienceOverride ?? ClientId,
            resolveKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            tenantId: default,
            [],
            expectedAuthorizedParty: null,
            expectedNonce,
            trustedAudiences,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(property).GetString()!;
    }


}

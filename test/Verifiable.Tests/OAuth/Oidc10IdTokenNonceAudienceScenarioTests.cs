using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
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

    private static readonly Uri ClientBaseUri = new(ClientId);
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");
    private static readonly TimeSpan IatSkew = TimeSpan.FromSeconds(60);

    //Test-local claim id for the deployment contributor adding a second audience; the
    //WellKnownClaimIds registry holds the library-shipped ones.
    private static readonly ClaimId SecondAudienceClaimId = ClaimId.Create(9110, "TestSecondAudience");

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);


    /// <summary>An id_token whose nonce equals the expected value validates, and the authentication-context claims arrive on the result.</summary>
    [TestMethod]
    public async Task MatchingNonceValidatesAndSurfacesAuthenticationContext()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        //acr is emitted on the original-authentication id_token exclusively from the application's
        //OIDC-claims resolver (AcrAmrClaimContributor's documented behaviour); sid comes from the
        //authorize-time ExchangeContext stamp instead, wired below via SetSessionId.
        host.Server.OAuth().ResolveOidcClaimsAsync = (subject, grantedScope, tenantId, ctx, cancellationToken) =>
            ValueTask.FromResult<OidcClaims?>(new OidcClaims
            {
                Subject = subject,
                AuthContext = new AuthenticationContext { Acr = EstablishedAcr }
            });

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ApplySecondAudienceContributor(host);

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
    /// Replaces the host's claim issuer with the standard rules plus a deployment contributor that
    /// adds a second, application-chosen audience to the ID Token — the shape the untrusted-audience
    /// scenarios validate against.
    /// </summary>
    private void ApplySecondAudienceContributor(TestHostShell host)
    {
        List<ClaimDelegate<ClaimContributionTarget>> rules = ContributionProfiles.StandardRules();
        rules.Add(new ClaimDelegate<ClaimContributionTarget>(
            new(ContributeSecondAudience), [SecondAudienceClaimId]));

        host.Server.OAuth().ClaimIssuer = new ClaimIssuer<ClaimContributionTarget>(
            WellKnownAssessorIds.ClaimContributors, rules, TimeProvider);
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
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        if(nonce is not null)
        {
            parFields[WellKnownJwtClaimNames.Nonce] = nonce;
        }

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, WellKnownHttpMethods.Post,
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body!, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        if(stampSessionId)
        {
            authorizeContext.SetSessionId(EstablishedSessionId);
        }

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode);
        string code = ExtractCode(authorizeResponse.Location!);

        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, WellKnownHttpMethods.Post,
            tokenFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        return ExtractFromBody(tokenResponse.Body!, "id_token");
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
        ServerVerificationKeyResolverDelegate resolveKey = (kid, tenant, ctx, ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, material.SigningKeyId.Value, StringComparison.Ordinal)
                    ? material.SigningPublicKey : null);

        return await Oidc10IdTokenValidator.ValidateAsync(
            idToken,
            expectedIssuerOverride ?? material.Registration.IssuerUri!.OriginalString,
            expectedAudienceOverride ?? ClientId,
            resolveKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            tenantId: default,
            new ExchangeContext(),
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


    private static string ExtractCode(string location)
    {
        Uri uri = new(location);
        string query = uri.Query.TrimStart('?');
        foreach(string pair in query.Split('&'))
        {
            string[] parts = pair.Split('=', 2);
            if(parts.Length == 2 && parts[0] == "code")
            {
                return Uri.UnescapeDataString(parts[1]);
            }
        }

        throw new InvalidOperationException($"No code in redirect: {location}");
    }
}

using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Firewalled end-to-end scenario for the OIDC Core §3.1.3.7 multi-audience
/// rules (ID Token validation steps 3–5): an ID Token with multiple audiences
/// SHOULD carry an <c>azp</c> claim, and when <c>azp</c> is present the
/// relying party SHOULD verify it equals its own <c>client_id</c>. The issuer
/// side mints through the REAL pipeline — the OIDC ID Token producer plus a
/// deployment claim contributor adding the second audience and <c>azp</c> —
/// over the full PAR → Authorize → Token exchange; the relying party
/// reconstructs from the wire body alone and runs the full validation
/// including the signature.
/// </summary>
/// <remarks>
/// <para>
/// The §3.1.3.7 azp rules are SHOULDs, so enforcement is opt-in by design:
/// the relying party passes its <c>client_id</c> as the expected authorized
/// party and the validator then enforces both "multi-audience ⇒ azp present"
/// and "azp = client_id"; with no expectation supplied, <c>azp</c> is
/// surfaced but not enforced. Which audiences are acceptable stays
/// application policy. This is the first of the conditional-requirement
/// scenario catalogue: spec rules whose MUST/SHOULD depends on token shape,
/// each pinned by a firewalled end-to-end test.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AzpMultiAudienceScenarioTests
{
    private const string ClientId = "https://client.example.com";
    private const string SubjectId = "subject-azp-1";
    private const string SecondAudience = "https://api.partner.example.com";

    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");
    private static TimeSpan IatSkew { get; } = TimeSpan.FromSeconds(60);

    //Test-local claim ids for the deployment contributor; the WellKnownClaimIds
    //registry holds the library-shipped ones.
    private static ClaimId MultiAudienceClaimId { get; } = ClaimId.Create(9100, "TestMultiAudience");
    private static ClaimId AuthorizedPartyClaimId { get; } = ClaimId.Create(9101, "TestAuthorizedParty");

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 5, 12, 0, 0, TimeSpan.Zero));


    [TestMethod]
    public async Task MultiAudienceIdTokenWithAzpValidatesEndToEnd()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //A conformant issuer: when minting for a second audience it adds azp
        //alongside (§3.1.3.7 rule 4's expectation on the token shape).
        await ApplyIdTokenContributorAsync(host, ContributeMultiAudienceWithAzp).ConfigureAwait(false);

        string idToken = await DriveCodeExchangeForIdTokenAsync(host, material).ConfigureAwait(false);

        //The relying party validates from wire bytes only, supplying its own
        //client_id as the expected authorized party (rule 5).
        Oidc10IdTokenValidationResult result = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedAuthorizedParty: ClientId).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess,
            $"A multi-audience ID Token carrying azp = client_id must validate; got {result.FailureReason}: {result.FailureDescription}");
        Assert.AreEqual(ClientId, result.Claims!.AuthorizedParty);
        Assert.HasCount(2, result.Claims.Audience);
        Assert.Contains(SecondAudience, result.Claims.Audience);

        //The same wire token presented to a DIFFERENT relying party fails
        //rule 5 — azp names the party the token was issued to, not them.
        Oidc10IdTokenValidationResult otherParty = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedAuthorizedParty: "https://other-client.example.com").ConfigureAwait(false);

        Assert.IsFalse(otherParty.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.AuthorizedPartyMismatch, otherParty.FailureReason,
            "azp not equal to the relying party's client_id must be rejected (OIDC Core §3.1.3.7).");
    }


    [TestMethod]
    public async Task MultiAudienceIdTokenWithoutAzpIsRejectedWhenEnforced()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //A non-conformant issuer: multiple audiences but no azp.
        await ApplyIdTokenContributorAsync(host, ContributeMultiAudienceWithoutAzp).ConfigureAwait(false);

        string idToken = await DriveCodeExchangeForIdTokenAsync(host, material).ConfigureAwait(false);

        //An enforcing relying party rejects the shape (rule 4)…
        Oidc10IdTokenValidationResult enforced = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedAuthorizedParty: ClientId).ConfigureAwait(false);

        Assert.IsFalse(enforced.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.AuthorizedPartyMissing, enforced.FailureReason,
            "Multiple audiences without azp must be rejected when the relying party enforces §3.1.3.7.");

        //…and a non-enforcing one accepts it — the rules are SHOULDs, so
        //enforcement is the relying party's opt-in, not a hard issuance gate.
        Oidc10IdTokenValidationResult lenient = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedAuthorizedParty: null).ConfigureAwait(false);

        Assert.IsTrue(lenient.IsSuccess,
            $"Without an expected authorized party azp is surfaced, not enforced; got {lenient.FailureReason}: {lenient.FailureDescription}");
        Assert.IsNull(lenient.Claims!.AuthorizedParty);
    }


    [TestMethod]
    public async Task SingleAudienceIdTokenNeedsNoAzpEvenWhenEnforced()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //The stock pipeline: single audience (the client), no azp — the
        //ordinary OIDC shape needs no authorized-party claim (§3.1.3.7
        //rule 4 conditions on MULTIPLE audiences).
        string idToken = await DriveCodeExchangeForIdTokenAsync(host, material).ConfigureAwait(false);

        Oidc10IdTokenValidationResult result = await ValidateAsRelyingPartyAsync(
            idToken, material, expectedAuthorizedParty: ClientId).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess,
            $"A single-audience ID Token without azp must validate even for an enforcing relying party; got {result.FailureReason}: {result.FailureDescription}");
        Assert.IsNull(result.Claims!.AuthorizedParty);
    }


    /// <summary>
    /// Replaces the host's claim issuer with the standard rules plus the
    /// supplied deployment contributor — the documented extension point for
    /// deployment-specific token shaping.
    /// </summary>
    private async Task ApplyIdTokenContributorAsync(
        TestHostShell host,
        Func<ClaimContributionTarget, CancellationToken, ValueTask<List<Claim>>> contributor)
    {
        List<ClaimDelegate<ClaimContributionTarget>> rules = ContributionProfiles.StandardRules();
        rules.Add(new ClaimDelegate<ClaimContributionTarget>(
            new(contributor), [MultiAudienceClaimId, AuthorizedPartyClaimId]));

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClaimIssuer = new ClaimIssuer<ClaimContributionTarget>(
                WellKnownAssessorIds.ClaimContributors, rules, TimeProvider);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// The conformant deployment contributor: the ID Token gains a second
    /// audience and the azp claim naming the requesting client.
    /// </summary>
    private static ValueTask<List<Claim>> ContributeMultiAudienceWithAzp(
        ClaimContributionTarget target, CancellationToken cancellationToken)
    {
        if(target is not IdTokenTarget)
        {
            return ValueTask.FromResult<List<Claim>>(
            [
                new Claim(MultiAudienceClaimId, ClaimOutcome.NotApplicable),
                new Claim(AuthorizedPartyClaimId, ClaimOutcome.NotApplicable)
            ]);
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            new Claim(MultiAudienceClaimId, ClaimOutcome.Success,
                new ClaimContributionContext(WellKnownJwtClaimNames.Aud, new[] { ClientId, SecondAudience }),
                Claim.NoSubClaims),
            new Claim(AuthorizedPartyClaimId, ClaimOutcome.Success,
                new ClaimContributionContext(WellKnownJwtClaimNames.Azp, ClientId),
                Claim.NoSubClaims)
        ]);
    }


    /// <summary>
    /// The non-conformant deployment contributor: multiple audiences with no
    /// azp — the shape §3.1.3.7 rule 4 tells the relying party to reject.
    /// </summary>
    private static ValueTask<List<Claim>> ContributeMultiAudienceWithoutAzp(
        ClaimContributionTarget target, CancellationToken cancellationToken)
    {
        if(target is not IdTokenTarget)
        {
            return ValueTask.FromResult<List<Claim>>(
                [new Claim(MultiAudienceClaimId, ClaimOutcome.NotApplicable)]);
        }

        return ValueTask.FromResult<List<Claim>>(
        [
            new Claim(MultiAudienceClaimId, ClaimOutcome.Success,
                new ClaimContributionContext(WellKnownJwtClaimNames.Aud, new[] { ClientId, SecondAudience }),
                Claim.NoSubClaims)
        ]);
    }


    /// <summary>
    /// Drives the full PAR → Authorize → Token exchange with the
    /// <c>openid</c> scope and returns the <c>id_token</c> from the wire body.
    /// </summary>
    private async Task<string> DriveCodeExchangeForIdTokenAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions { Scope = WellKnownScopes.OpenId },
            TestContext.CancellationToken).ConfigureAwait(false);

        return ExtractFromBody(result.TokenResponse.Body, "id_token");
    }


    /// <summary>
    /// The relying party's validation from wire bytes only: full signature
    /// verification plus the §3.1.3.7 issuer/audience/azp checks. The
    /// verification key resolves by the token's kid, the way a deployment
    /// resolves against the fetched JWKS.
    /// </summary>
    private async Task<Oidc10IdTokenValidationResult> ValidateAsRelyingPartyAsync(
        string idToken, VerifierKeyMaterial material, string? expectedAuthorizedParty)
    {
        ValueTask<PublicKeyMemory?> resolveKey(KeyId kid, TenantId tenant, ExchangeContext ctx, CancellationToken ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, material.SigningKeyId.Value, StringComparison.Ordinal)
                    ? material.SigningPublicKey : null);

        return await Oidc10IdTokenValidator.ValidateAsync(
            idToken,
            material.Registration.IssuerUri!.OriginalString,
            ClientId,
resolveKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            tenantId: default,
            [],
            expectedAuthorizedParty,
            expectedNonce: null,
            trustedAudiences: null,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(property).GetString()!;
    }


}

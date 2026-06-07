using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Dcql;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Full-flow integration test for an SD-CWT (<c>dc+sd-cwt</c>) OID4VP presentation
/// against a pinned-key verifier registration — the SD-CWT counterpart of
/// <see cref="Oid4VpMdocFlowIntegrationTests"/>. Drives the verifier through its
/// real PDA pipeline (PAR → JAR served → encrypted direct_post →
/// PresentationVerified) and the executor's <c>dc+sd-cwt</c> dispatch branch,
/// which runs the holder-binding (Key Binding Token) and issuer verifications
/// through the
/// <see cref="Verifiable.OAuth.Validation.ValidationProfiles.Haip10SdCwtRules"/>
/// ClaimIssuer.
/// </summary>
/// <remarks>
/// The host, verification seams, SD-CWT issuance, DCQL query, presentation
/// drop-out (the Core disclosure engine + KBT signing), and the verified-claims
/// assertion all come from the shared <see cref="SdCwtVpFixture"/>, which the
/// scheme × format matrix (<see cref="Oid4VpSchemeFormatMatrixTests"/>) also
/// drives against every client-id scheme. This test pins the remaining axis the
/// matrix does not: a <see cref="TestHostShell.RegisterClient"/> verifier (the
/// <see cref="PolicyProfile.Oid4VpVerifier"/> registration path) resolved via the
/// pinned-key resolver rather than a client-id scheme. The drop-out selects the
/// minimal set the query asks for (given + family, withholding email), so the
/// assertion also covers withholding. Unlike mdoc, SD-CWT needs no <c>apu</c> /
/// SessionTranscript — the holder binding rides entirely in the KBT. Firewalled:
/// only the compact JAR (in) and compact JWE (out) cross the party boundary.
/// </remarks>
[TestClass]
internal sealed class Oid4VpSdCwtFlowIntegrationTests
{
    public required TestContext TestContext { get; set; }

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2026, 5, 26, 12, 0, 0, TimeSpan.Zero));

    private const string VerifierClientId = "https://verifier.example.com";
    private static readonly Uri VerifierBaseUri = new("https://verifier.example.com");

    private static readonly ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    [TestMethod]
    public async Task CrossDeviceSdCwtFlowReachesPresentationVerified()
    {
        //The fixture builds the host wired with the dc+sd-cwt verification seams,
        //issues the SD-CWT (holder COSE_Key in cnf), and hands back the DCQL query,
        //the KBT-signing presentation drop-out, and the verified-claims assertion
        //(which also asserts the withheld email never surfaces).
        await using FormatRun run = await SdCwtVpFixture.Format.StartAsync(
            TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        TestHostShell app = run.App;

        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        //Step 1: Verifier PAR with the dc+sd-cwt DCQL query.
        TransactionNonce nonce = new("nonce-sd-cwt-flow-01");
        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys, nonce, run.Query, TestContext.CancellationToken).ConfigureAwait(false);

        //Step 2: JAR served — advances the verifier PDA to VerifierJarServed and hands
        //the wallet the compact JAR it will verify and present against.
        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        //Step 3: The real wallet client (pinned-key resolver) verifies the JAR, runs
        //the DCQL engine + KBT signing behind the fixture's presentation drop-out,
        //encrypts the response, and POSTs it — driving the verifier to
        //PresentationVerified.
        (OAuthClient oauthClient, _, _) = app.CreateInProcessOAuthClientAndRegistration(
            verifierKeys.Registration,
            "https://wallet.example.com/cb",
            verifierKeys.Registration.IssuerUri!.ToString());

        Oid4VpWalletClient walletClient = new(
            oauthClient.Infrastructure,
            TestHostShell.BuildSlimOid4VpWalletConfiguration(
                run.Produce,
                TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey)));

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-sdcwt-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "The cross-device SD-CWT presentation must reach the ResponseSent wallet terminal.");

        run.AssertClaims((PresentationVerifiedState)app.GetFlowState(parHandle).State);
    }


    [TestMethod]
    public async Task SdCwtFlowFromTrustedAuthorityReachesPresentationVerified()
    {
        //OID4VP 1.0 §6.1.1.3: the DCQL query pins the acceptable issuer via a
        //trusted_authorities (openid_federation) constraint. The SD-CWT's iss matches,
        //so the verifier's fail-closed DcqlEvaluator check passes for the dc+sd-cwt format.
        await using FormatRun run = await SdCwtVpFixture.Format.StartAsync(
            TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);

        OAuthFlowState state = await DriveFlowAsync(
            run,
            SdCwtVpFixture.BuildSdCwtTrustedAuthoritiesPreparedQuery(SdCwtVpFixture.IssuerId))
            .ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(state,
            "An SD-CWT whose issuer is in trusted_authorities must verify.");
    }


    [TestMethod]
    public async Task SdCwtFlowFromUntrustedAuthorityDoesNotVerify()
    {
        //The trusted_authorities list names only a stranger, so the SD-CWT's issuer is
        //not trusted. The wallet's adapter does not enforce trusted_authorities (it
        //presents normally) — a clean verifier-side rejection for the dc+sd-cwt format.
        await using FormatRun run = await SdCwtVpFixture.Format.StartAsync(
            TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);

        OAuthFlowState state = await DriveFlowAsync(
            run,
            SdCwtVpFixture.BuildSdCwtTrustedAuthoritiesPreparedQuery("https://stranger.example.com"))
            .ConfigureAwait(false);

        Assert.IsNotInstanceOfType<PresentationVerifiedState>(state,
            "An SD-CWT whose issuer is not in trusted_authorities must NOT verify.");
    }


    /// <summary>
    /// Drives the verifier through PAR → JAR → encrypted direct_post for the supplied DCQL
    /// query and returns the verifier's terminal flow state. A verifier rejection surfaces as
    /// a non-200 direct_post (the wallet client throws), which is swallowed so the caller can
    /// assert on the flow state either way.
    /// </summary>
    private async Task<OAuthFlowState> DriveFlowAsync(FormatRun run, PreparedDcqlQuery query)
    {
        TestHostShell app = run.App;
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        TransactionNonce nonce = new($"nonce-sd-cwt-ta-{Guid.NewGuid():N}");
        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys, nonce, query, TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        (OAuthClient oauthClient, _, _) = app.CreateInProcessOAuthClientAndRegistration(
            verifierKeys.Registration,
            "https://wallet.example.com/cb",
            verifierKeys.Registration.IssuerUri!.ToString());

        Oid4VpWalletClient walletClient = new(
            oauthClient.Infrastructure,
            TestHostShell.BuildSlimOid4VpWalletConfiguration(
                run.Produce,
                TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey)));

        try
        {
            _ = await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                    FlowId = $"wallet-sdcwt-ta-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //Verifier rejected the presentation (non-200 direct_post).
        }

        return app.GetFlowState(parHandle).State;
    }
}

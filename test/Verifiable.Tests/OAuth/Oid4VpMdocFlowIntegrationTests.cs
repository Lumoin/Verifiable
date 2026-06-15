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
/// Full-flow integration test for an ISO mdoc (<c>mso_mdoc</c>) OID4VP
/// presentation against a pinned-key verifier registration — the mdoc
/// counterpart of the SD-JWT <see cref="Oid4VpFlowIntegrationTests"/> cross-device
/// flow. Drives the verifier through its real PDA pipeline (PAR → JAR served →
/// encrypted direct_post → PresentationVerified) and the executor's
/// <c>mso_mdoc</c> dispatch branch.
/// </summary>
/// <remarks>
/// <para>
/// The host, verification seams, mdoc issuance, DCQL query, presentation drop-out
/// (the Core DCQL engine + device signing over the OID4VP SessionTranscript), and
/// the verified-claims assertion all come from the shared
/// <see cref="MdocVpFixture"/>, which the scheme × format matrix
/// (<see cref="Oid4VpSchemeFormatMatrixTests"/>) also drives against every
/// client-id scheme. This test pins the remaining axis the matrix does not: a
/// <see cref="TestHostShell.RegisterClient"/> verifier (the
/// <see cref="PolicyProfile.Oid4VpVerifier"/> registration path) resolved via the
/// pinned-key resolver rather than a client-id scheme.
/// </para>
/// <para>
/// This remains a firewalled flow: the only values crossing the party boundary
/// are the wire artifacts (the compact JAR into the wallet, the compact JWE back
/// out). The verifier reconstructs the SessionTranscript from its own
/// <c>client_id</c>/<c>response_uri</c>/<c>nonce</c> plus the <c>apu</c> nonce,
/// verifies the issuer-auth signature, the MSO digest binding, and the device
/// signature, then surfaces the result through the
/// <see cref="Verifiable.OAuth.Validation.ValidationProfiles.Haip10MdocRules"/>
/// ClaimIssuer — the same pipeline the SD-JWT path runs.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Oid4VpMdocFlowIntegrationTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string VerifierClientId = "https://verifier.example.com";
    private static readonly Uri VerifierBaseUri = new("https://verifier.example.com");

    private static readonly ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    [TestMethod]
    public async Task CrossDeviceMdocFlowReachesPresentationVerified()
    {
        //The fixture builds the host wired with the mso_mdoc verification seams,
        //issues the PID mdoc, and hands back the DCQL query, the device-signing
        //presentation drop-out, and the verified-claims assertion.
        await using FormatRun run = await MdocVpFixture.Format.StartAsync(
            TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        TestHostShell app = run.App;

        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        //Step 1: Verifier PAR with the mso_mdoc DCQL query — seeds the flow with the
        //credential query whose Format routes to both the wallet's mdoc provider and
        //the executor's mdoc branch.
        TransactionNonce nonce = new("nonce-mdoc-flow-01");
        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys, nonce, run.Query, TestContext.CancellationToken).ConfigureAwait(false);

        //Step 2: JAR served — advances the verifier PDA to VerifierJarServed and hands
        //the wallet the compact JAR it will verify and present against.
        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        //Step 3: The real wallet client (pinned-key resolver) verifies the JAR, runs
        //the DCQL engine + device-signing behind the fixture's presentation drop-out,
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
                FlowId = $"wallet-mdoc-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "The cross-device mdoc presentation must reach the ResponseSent wallet terminal.");

        run.AssertClaims((PresentationVerifiedState)app.GetFlowState(parHandle).State);
    }


    [TestMethod]
    public async Task MdocFlowFromTrustedAuthorityReachesPresentationVerified()
    {
        //OID4VP 1.0 §6.1.1.1: the DCQL query pins the acceptable issuer via a
        //trusted_authorities (aki) constraint matching the IssuerAuth leaf certificate's
        //AuthorityKeyIdentifier. The IACA-rooted run carries a real x5chain, so the verifier
        //extracts that AKI and its fail-closed DcqlEvaluator check passes for the mdoc format.
        //The clock sits inside the certificate validity window so chain validation succeeds.
        FakeTimeProvider tp = new(new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero));
        (FormatRun run, string authorityKeyIdentifier) = await MdocVpFixture.StartWithIacaChainAsync(
            tp, TestContext.CancellationToken).ConfigureAwait(false);

        await using(run)
        {
            FlowState state = await DriveFlowAsync(
                run, MdocVpFixture.BuildMdocTrustedAuthoritiesPreparedQuery(authorityKeyIdentifier))
                .ConfigureAwait(false);

            Assert.IsInstanceOfType<PresentationVerifiedState>(state,
                "An mdoc whose leaf AuthorityKeyIdentifier is in trusted_authorities must verify.");
        }
    }


    [TestMethod]
    public async Task MdocFlowFromUntrustedAuthorityDoesNotVerify()
    {
        //The trusted_authorities list names only a stranger AKI, so the mdoc's leaf authority
        //is not trusted. The wallet's mdoc adapter does not enforce trusted_authorities (it
        //presents normally) — a clean verifier-side rejection for the mso_mdoc format.
        FakeTimeProvider tp = new(new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero));
        (FormatRun run, _) = await MdocVpFixture.StartWithIacaChainAsync(
            tp, TestContext.CancellationToken).ConfigureAwait(false);

        await using(run)
        {
            //"stranger-aki" base64url-encoded — a value no certificate in the chain bears.
            FlowState state = await DriveFlowAsync(
                run, MdocVpFixture.BuildMdocTrustedAuthoritiesPreparedQuery("c3RyYW5nZXItYWtp"))
                .ConfigureAwait(false);

            Assert.IsNotInstanceOfType<PresentationVerifiedState>(state,
                "An mdoc whose leaf AuthorityKeyIdentifier is not in trusted_authorities must NOT verify.");
        }
    }


    /// <summary>
    /// Drives the verifier through PAR → JAR → encrypted direct_post for the supplied DCQL
    /// query and returns the verifier's terminal flow state. A verifier rejection surfaces as
    /// a non-200 direct_post (the wallet client throws), which is swallowed so the caller can
    /// assert on the flow state either way.
    /// </summary>
    private async Task<FlowState> DriveFlowAsync(FormatRun run, PreparedDcqlQuery query)
    {
        TestHostShell app = run.App;
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        TransactionNonce nonce = new($"nonce-mdoc-ta-{Guid.NewGuid():N}");
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
                    FlowId = $"wallet-mdoc-ta-{Guid.NewGuid():N}"
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

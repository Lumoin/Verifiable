using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using System.Text;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Server;
using Verifiable.Tests.Federation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end tests for <see cref="Oid4VpWalletClient"/>. Each test
/// drives the full presentation flow through the in-process Verifier exposed by
/// <see cref="TestHostShell"/>: PAR, JAR fetch, wallet-side presentation, and
/// the encrypted direct_post.jwt POST.
/// </summary>
[TestClass]
internal sealed class Oid4VpWalletClientTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private const string VerifierClientId = "https://verifier.example.com";
    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    private const string IssuerId = SdJwtVpFixture.IssuerId;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    [TestMethod]
    public async Task PresentsValidVpTokenForSimpleSdJwtVcRequest()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        (Uri requestUri, string parHandle, string compactJar) = await IssueJarAsync(
            app, verifierKeys).ConfigureAwait(false);

        Oid4VpWalletClient walletClient = BuildWalletClient(
            app, verifierKeys, serializedSdJwt, holderKey);

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result.PostedResponseArtifact);
        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState);
        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "Verifier PDA must reach PresentationVerified after the wallet POSTs the encrypted response.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 8.2</see>: "Additional response parameters MAY be
    /// defined and used. The Wallet MUST ignore any unrecognized parameters." A canned transport
    /// answers the <c>direct_post</c> POST with a 200 JSON object carrying <c>redirect_uri</c>
    /// alongside two members no OID4VP response ever defines; <see cref="Oid4VpWalletClient"/>
    /// never decodes the response body at all — it reads only the HTTP status code — so the
    /// presentation completes identically to a recognized-members-only 200, proving the MUST by
    /// construction rather than a member-by-member allowlist.
    /// </summary>
    [TestMethod]
    public async Task IgnoresUnrecognizedDirectPostResponseMembersPerSection82()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        (Uri requestUri, string _, string compactJar) = await IssueJarAsync(
            app, verifierKeys).ConfigureAwait(false);

        //The direct_post POST is the wallet client's only outbound call in this flow (PAR/JAR are
        //driven server-side by the test host, never through this OAuthClientInfrastructure), so the
        //decorator answers every call with the canned 200 rather than conditioning on the endpoint.
        (OAuthClient oauthClient, _, _) = app.CreateInProcessOAuthClientAndRegistration(
            verifierKeys.Registration,
            "https://client.example.com/callback",
            verifierKeys.Registration.IssuerUri!.ToString(),
            decorateSendFormPostAsync: _ => (_, _, _, _, _) =>
                ValueTask.FromResult(new HttpResponseData
                {
                    StatusCode = 200,
                    Body = """{"redirect_uri":"https://rp.example/done","response_code":"abc","x-future":1}""",
                    Headers = ResponseHeaders.Empty
                }));

        ProduceVpTokenPresentationsDelegate produce =
            TestHostShell.BuildSdJwtProduceDelegate(serializedSdJwt, holderKey);

        Oid4VpWalletClient walletClient = new(
            oauthClient.Infrastructure,
            TestHostShell.BuildSlimOid4VpWalletConfiguration(
                produce,
                TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey)));

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-must-ignore-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result.PostedResponseArtifact);
        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "OID4VP 1.0 §8.2: unrecognized response members (response_code, x-future) must not fail the presentation.");
    }


    [TestMethod]
    public async Task RejectsJarWhoseClientIdDoesNotMatchExpectedVerifier()
    {
        //Mix-up defence: the wallet pinned one Verifier identity out-of-band
        //(ExpectedVerifierClientId) but the JAR — though validly signed and
        //resolved by the pinned key — carries a DIFFERENT client_id. Resolving
        //the signing key proves the request is signed by a key bound to the
        //asserted identity, NOT that the asserted identity is the one the wallet
        //meant to answer. The wallet MUST refuse fail-closed before producing any
        //presentation or POSTing a response, so the Verifier never verifies.
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        (Uri requestUri, string parHandle, string compactJar) = await IssueJarAsync(
            app, verifierKeys).ConfigureAwait(false);

        Oid4VpWalletClient walletClient = BuildWalletClient(
            app, verifierKeys, serializedSdJwt, holderKey);

        //The JAR's client_id is VerifierClientId; the wallet pinned someone else.
        const string PinnedButWrongVerifier = "https://attacker.example.com";

        InvalidOperationException ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = PinnedButWrongVerifier,
                    FlowId = $"wallet-mixup-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.Contains("does not match", ex.Message, StringComparison.Ordinal);
        Assert.Contains(PinnedButWrongVerifier, ex.Message, StringComparison.Ordinal);
        Assert.Contains(VerifierClientId, ex.Message, StringComparison.Ordinal);

        Assert.IsNotInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "The wallet must refuse the mismatched client_id before POSTing, so the Verifier never verifies.");
    }


    [TestMethod]
    public async Task PresentJarAsyncRoundTripsThroughExistingVerifier()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        (Uri requestUri, string parHandle, string compactJar) = await IssueJarAsync(
            app, verifierKeys).ConfigureAwait(false);

        Oid4VpWalletClient walletClient = BuildWalletClient(
            app, verifierKeys, serializedSdJwt, holderKey);

        _ = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-roundtrip-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Credentials.ContainsKey(new CredentialQueryId("pid")),
            "Verifier must surface the wallet's presentation under the 'pid' credential query identifier.");
        Assert.IsNotNull(verified.Credentials[new CredentialQueryId("pid")]);
    }


    [TestMethod]
    public async Task PresentJarAsyncSurfacesCancellation()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        (Uri requestUri, string _, string compactJar) = await IssueJarAsync(
            app, verifierKeys).ConfigureAwait(false);

        Oid4VpWalletClient walletClient = BuildWalletClient(
            app, verifierKeys, serializedSdJwt, holderKey);

        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            _ = await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                },
                cts.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task VerifierRejectsPresentationMissingARequestedClaim()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        //The verifier asks for phone_number, which this PID does not carry, so the
        //wallet's minimal disclosure cannot include it. The verifier's
        //DCQL-satisfaction check (CheckDcqlSatisfaction) must reject the
        //presentation even though every signature/sd_hash axis is valid.
        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce($"nonce-unsat-{Guid.NewGuid():N}"),
            CreateQueryRequestingAbsentClaim(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        Oid4VpWalletClient walletClient = BuildWalletClient(app, verifierKeys, serializedSdJwt, holderKey);

        try
        {
            _ = await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //The verifier rejected the unsatisfying presentation; its direct_post
            //response is non-200, which the wallet client surfaces as this exception.
        }

        Assert.IsNotInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "The verifier must NOT reach PresentationVerified when the presentation omits a DCQL-requested claim.");
    }


    [TestMethod]
    public async Task VerifierRejectsOverDisclosingPresentationByDefault()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        //The query asks only for family_name; the issued PID also carries
        //given_name. A reveal-all wallet discloses both, over-disclosing
        //given_name. With the verifier profile's default enforcement the
        //CheckNoOverDisclosure rule must reject — even though signatures, sd_hash,
        //and DCQL-satisfaction all pass.
        (Uri requestUri, string parHandle, string compactJar) = await IssueJarAsync(
            app, verifierKeys).ConfigureAwait(false);

        Oid4VpWalletClient walletClient = BuildWalletClient(
            app, verifierKeys, serializedSdJwt, holderKey, revealAll: true);

        try
        {
            _ = await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //Verifier rejected the over-disclosing presentation (non-200 direct_post).
        }

        Assert.IsNotInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "The verifier must NOT reach PresentationVerified for an over-disclosing presentation under default enforcement.");
    }


    [TestMethod]
    public async Task VerifierRejectsSecondPresentationReusingDisclosureSalts()
    {
        //A verifier wired with a salt-reuse store. Presenting the SAME credential twice replays the
        //issuer's disclosure salts (the holder does not re-salt on presentation), so the second
        //presentation must be rejected by CheckSaltReuse — the OID4VP mirror of DPoP-JTI replay.
        var store = new InMemoryCommitmentStore();
        CommitmentReuseDetectionSeam saltReuseSeam = new(
            SHA256.HashData, HashOutputByteLength: 32, Sha256CommitmentTag, store.IsSeen, store.Record);

        await using TestHostShell app = new(TimeProvider, saltReuseSeam: saltReuseSeam);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        //First presentation: salts are new, so it verifies and seeds the store.
        (Uri firstUri, string firstHandle, string firstJar) = await IssueJarAsync(app, verifierKeys).ConfigureAwait(false);
        Oid4VpWalletClient firstClient = BuildWalletClient(app, verifierKeys, serializedSdJwt, holderKey);
        _ = await firstClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = firstJar,
                RequestUri = firstUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-first-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(firstHandle).State,
            "The first presentation of fresh salts must verify and record them.");

        //Second presentation of the same credential reuses the same disclosure salts.
        (Uri secondUri, string secondHandle, string secondJar) = await IssueJarAsync(app, verifierKeys).ConfigureAwait(false);
        Oid4VpWalletClient secondClient = BuildWalletClient(app, verifierKeys, serializedSdJwt, holderKey);
        try
        {
            _ = await secondClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = secondJar,
                    RequestUri = secondUri,
                    ExpectedVerifierClientId = VerifierClientId,
                        FlowId = $"wallet-second-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //Verifier rejected the salt-reusing presentation (non-200 direct_post).
        }

        Assert.IsNotInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(secondHandle).State,
            "The second presentation reuses the disclosure salts and must NOT reach PresentationVerified.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">
    /// OID4VP 1.0 §6.1.1.3</see>'s <c>openid_federation</c> match requires "a valid trust path,
    /// including the given Entity Identifier"; the wallet resolves the issuer's evidence through
    /// <see cref="FederationTrustPathEvidence.ResolveAsync"/> against a real minted federation chain
    /// from the credential's issuer entity to a familiar anchor, so the issuer's own Entity
    /// Identifier is a subject on a validated path and the query's <c>trusted_authorities</c> value
    /// (the issuer's own identifier) matches it.
    /// </summary>
    [TestMethod]
    public async Task VerifierAcceptsPresentationWhenIssuerIsOnAValidatedFederationTrustPath()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        EntityIdentifier issuerEntity = new(IssuerId);
        EntityIdentifier familiarAnchor = new("https://anchor.example.com");
        ResolveTrustedAuthorityEvidenceDelegate resolveTrustedAuthorityEvidence =
            await BuildFederationTrustedAuthorityResolverAsync(
                issuerEntity, familiarAnchor, now, TestContext.CancellationToken).ConfigureAwait(false);

        await using TestHostShell app = new(TimeProvider, resolveTrustedAuthorityEvidence: resolveTrustedAuthorityEvidence);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        (Uri requestUri, string parHandle, string compactJar) = await IssueJarAsync(
            app, verifierKeys, DcqlFixtures.PidFamilyNameTrustedAuthoritiesPrepared(IssuerId))
            .ConfigureAwait(false);

        Oid4VpWalletClient walletClient = BuildWalletClient(app, verifierKeys, serializedSdJwt, holderKey);
        _ = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-ta-accept-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "The issuer's Entity Identifier is a subject on a validated OpenID Federation trust path to a familiar anchor, so the trusted_authorities constraint naming that identifier is satisfied.");
    }


    /// <summary>
    /// The DCQL query's <c>trusted_authorities</c> names only a stranger identifier that is not a
    /// subject on the issuer's validated federation trust path
    /// (<see cref="FederationTrustPathEvidence.ResolveAsync"/> resolves the SAME real chain as
    /// <see cref="VerifierAcceptsPresentationWhenIssuerIsOnAValidatedFederationTrustPath"/>). The
    /// wallet's own adapter does not enforce <c>trusted_authorities</c> (it presents normally), so
    /// this is a clean verifier-side rejection: <see cref="Verifiable.Core.Dcql.DcqlEvaluator"/>
    /// finds no entry matching and the flow must NOT verify.
    /// </summary>
    [TestMethod]
    public async Task VerifierRejectsPresentationFromUntrustedAuthority()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        EntityIdentifier issuerEntity = new(IssuerId);
        EntityIdentifier familiarAnchor = new("https://anchor.example.com");
        ResolveTrustedAuthorityEvidenceDelegate resolveTrustedAuthorityEvidence =
            await BuildFederationTrustedAuthorityResolverAsync(
                issuerEntity, familiarAnchor, now, TestContext.CancellationToken).ConfigureAwait(false);

        await using TestHostShell app = new(TimeProvider, resolveTrustedAuthorityEvidence: resolveTrustedAuthorityEvidence);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        (Uri requestUri, string parHandle, string compactJar) = await IssueJarAsync(
            app, verifierKeys,
            DcqlFixtures.PidFamilyNameTrustedAuthoritiesPrepared("https://stranger.example.com"))
            .ConfigureAwait(false);

        Oid4VpWalletClient walletClient = BuildWalletClient(app, verifierKeys, serializedSdJwt, holderKey);
        try
        {
            _ = await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                    FlowId = $"wallet-ta-reject-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //Verifier rejected the untrusted-authority presentation (non-200 direct_post).
        }

        Assert.IsNotInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "A stranger identifier absent from the issuer's validated trust path must NOT verify.");
    }


    /// <summary>
    /// Mints a real two-node OpenID Federation trust chain (<paramref name="issuerEntity"/> as the
    /// subject, <paramref name="familiarAnchor"/> as the Trust Anchor) via <see cref="FederationTestRing"/>,
    /// wires the corresponding fetch delegates in-memory (no network I/O), and returns a
    /// <see cref="ResolveTrustedAuthorityEvidenceDelegate"/> composed through
    /// <see cref="TrustedAuthorityEvidenceResolution.Build"/> whose <c>openid_federation</c> arm
    /// resolves through <see cref="FederationTrustPathEvidence.ResolveAsync"/> against that chain and
    /// <paramref name="familiarAnchor"/> as the wallet's only familiar anchor. The <c>aki</c>/<c>etsi_tl</c>
    /// arms are wired but never exercised (no certificate chain is presented in these tests).
    /// </summary>
    /// <param name="issuerEntity">The credential issuer's Entity Identifier — the chain's subject.</param>
    /// <param name="familiarAnchor">The wallet's familiar Trust Anchor — the chain's terminus.</param>
    /// <param name="now">The instant the minted statements are issued at and validated against.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The composed resolver.</returns>
    private static async Task<ResolveTrustedAuthorityEvidenceDelegate> BuildFederationTrustedAuthorityResolverAsync(
        EntityIdentifier issuerEntity,
        EntityIdentifier familiarAnchor,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        const string AnchorFetchEndpoint = "https://anchor.example.com/federation/fetch";

        using FederationTestRingNode issuerNode = FederationTestRing.CreateNode(issuerEntity);
        using FederationTestRingNode anchorNode = FederationTestRing.CreateNode(familiarAnchor);

        MintedStatement issuerEc = await FederationTestRing.MintEntityConfigurationAsync(
            issuerNode, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.AuthorityHints] = new List<object> { familiarAnchor.Value }
            },
            cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchorNode, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [WellKnownEntityTypeIdentifiers.FederationEntity.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [FederationMetadataParameterNames.FetchEndpoint] = AnchorFetchEndpoint
                    }
                }
            },
            cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutIssuer = await FederationTestRing.MintSubordinateStatementAsync(
            anchorNode, issuerNode, now, now.AddHours(1), cancellationToken: cancellationToken).ConfigureAwait(false);

        Dictionary<string, string> configByEntity = new(StringComparer.Ordinal)
        {
            [issuerEntity.Value] = issuerEc.CompactJws,
            [familiarAnchor.Value] = anchorEc.CompactJws
        };

        FetchEntityConfigurationDelegate fetchConfiguration = (entity, context, ct) =>
            ValueTask.FromResult(configByEntity.TryGetValue(entity.Value, out string? jws)
                ? FederationHttpClientTransport.TryParseFetchedStatement(jws)
                : null);

        FetchEntityStatementDelegate fetchSubordinate = (subject, fetchEndpoint, context, ct) =>
            ValueTask.FromResult(
                string.Equals(fetchEndpoint.ToString(), AnchorFetchEndpoint, StringComparison.Ordinal)
                    && string.Equals(subject.Value, issuerEntity.Value, StringComparison.Ordinal)
                    ? FederationHttpClientTransport.TryParseFetchedStatement(anchorAboutIssuer.CompactJws)
                    : null);

        ValidateTrustChainAsyncDelegate validate = TrustChainValidation.BuildInlineValidator(
            HeaderDeserializer, PayloadDeserializer, TestSetup.Base64UrlDecoder,
            FederationKeyResolver.BuildInChainResolver(TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared));

        return TrustedAuthorityEvidenceResolution.Build(
            MicrosoftX509Functions.GetAuthorityKeyIdentifier,
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName,
            heldTrustedLists: [],
            resolveFederationTrustPath: (issuer, ct) => FederationTrustPathEvidence.ResolveAsync(
                issuer,
                [familiarAnchor],
                fetchConfiguration,
                fetchSubordinate,
                validate,
                new ExchangeContext(),
                maxChainLength: 5,
                validationTime: now,
                clockSkew: TimeSpan.FromMinutes(5),
                BaseMemoryPool.Shared,
                ct));
    }


    /// <summary>Deserializes a compact JWS header segment for <see cref="TrustChainValidation.BuildInlineValidator"/>.</summary>
    private static JwtHeaderDeserializer HeaderDeserializer { get; } = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Header JSON parsed to null.");

    /// <summary>Deserializes a compact JWS payload segment for <see cref="TrustChainValidation.BuildInlineValidator"/>.</summary>
    private static JwtPayloadDeserializer PayloadDeserializer { get; } = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Payload JSON parsed to null.");


    [TestMethod]
    public async Task VerifierAcceptsPresentationMatchingClaimValueConstraint()
    {
        //The DCQL query constrains family_name to its actual issued value. The
        //minimal-disclosure wallet discloses given_name + family_name (both asked),
        //the verifier's value-constraint check passes, and the flow verifies.
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        (Uri requestUri, string parHandle, string compactJar) = await IssueJarAsync(
            app, verifierKeys, DcqlFixtures.PidFamilyNameValueConstraintPrepared("Mustermann"))
            .ConfigureAwait(false);

        Oid4VpWalletClient walletClient = BuildWalletClient(app, verifierKeys, serializedSdJwt, holderKey);
        _ = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-val-accept-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "A disclosed claim value that matches the DCQL values constraint must verify.");
    }


    [TestMethod]
    public async Task VerifierRejectsPresentationFailingClaimValueConstraint()
    {
        //The DCQL query demands a family_name the PID does not carry. A reveal-all
        //wallet still discloses the real family_name (and given_name, also asked, so
        //over-disclosure is not the trigger), forcing the verifier's value-constraint
        //branch: the disclosed "Mustermann" is not the demanded value, so it must NOT verify.
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        (Uri requestUri, string parHandle, string compactJar) = await IssueJarAsync(
            app, verifierKeys, DcqlFixtures.PidFamilyNameValueConstraintPrepared("Schmidt"))
            .ConfigureAwait(false);

        Oid4VpWalletClient walletClient = BuildWalletClient(
            app, verifierKeys, serializedSdJwt, holderKey, revealAll: true);
        try
        {
            _ = await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                    FlowId = $"wallet-val-reject-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //Verifier rejected the value-mismatching presentation (non-200 direct_post).
        }

        Assert.IsNotInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "A disclosed claim value outside the DCQL values constraint must NOT verify.");
    }


    private async ValueTask<(Uri RequestUri, string ParHandle, string CompactJar)> IssueJarAsync(
        TestHostShell app,
        VerifierKeyMaterial verifierKeys,
        PreparedDcqlQuery? query = null)
    {
        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce($"nonce-walletclient-{Guid.NewGuid():N}"),
            query ?? CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        return (requestUri, parHandle, compactJar);
    }


    private static Oid4VpWalletClient BuildWalletClient(
        TestHostShell app,
        VerifierKeyMaterial verifierKeys,
        string storedSdJwt,
        PrivateKeyMemory holderKey,
        bool revealAll = false)
    {
        (OAuthClient oauthClient, _, _) = app.CreateInProcessOAuthClientAndRegistration(
            verifierKeys.Registration,
            "https://client.example.com/callback",
            verifierKeys.Registration.IssuerUri!.ToString());

        ProduceVpTokenPresentationsDelegate produce = revealAll
            ? TestHostShell.BuildSdJwtProduceDelegateRevealingAll(storedSdJwt, holderKey)
            : TestHostShell.BuildSdJwtProduceDelegate(storedSdJwt, holderKey);

        return new Oid4VpWalletClient(
            oauthClient.Infrastructure,
            TestHostShell.BuildSlimOid4VpWalletConfiguration(
                produce,
                TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey)));
    }


    private static PreparedDcqlQuery CreatePreparedQuery() =>
        DcqlFixtures.PidFamilyNamePrepared();


    private static Tag Sha256CommitmentTag { get; } = Tag.Create(HashAlgorithmName.SHA256);


    /// <summary>
    /// A verifier-side salt-reuse store: a process-local set keyed by commitment bytes, shared across
    /// the two presentations in the reuse test. Wired as method groups, so only the per-call commitment
    /// is threaded by the library.
    /// </summary>
    private sealed class InMemoryCommitmentStore
    {
        private HashSet<string> Seen { get; } = new(StringComparer.Ordinal);

        public ValueTask<bool> IsSeen(DigestValue commitment, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Seen.Contains(Convert.ToHexString(commitment.AsReadOnlySpan())));

        public ValueTask Record(DigestValue commitment, CancellationToken cancellationToken)
        {
            Seen.Add(Convert.ToHexString(commitment.AsReadOnlySpan()));

            return ValueTask.CompletedTask;
        }
    }


    //A dc+sd-jwt query (under the same "pid" credential query id) requesting a
    //claim the issued PID does not carry — drives the DCQL-satisfaction failure.
    private static PreparedDcqlQuery CreateQueryRequestingAbsentClaim() =>
        DcqlPreparer.Prepare(new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = DcqlCredentialFormats.SdJwt,
                    Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                    Claims = [ClaimsQuery.ForPath([EudiPid.SdJwt.PhoneNumber])]
                }
            ]
        });


    //The PID SD-JWT issuance lives in the shared SdJwtVpFixture, the single source
    //the scheme × format matrix also issues through.
    private ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)> IssuePidCredentialAsync(
        CancellationToken cancellationToken) =>
        SdJwtVpFixture.IssuePidCredentialAsync(TimeProvider, cancellationToken);
}

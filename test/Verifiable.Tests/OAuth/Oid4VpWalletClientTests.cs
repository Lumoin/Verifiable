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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string VerifierClientId = "https://verifier.example.com";
    private static readonly Uri VerifierBaseUri = new("https://verifier.example.com");

    private const string IssuerId = SdJwtVpFixture.IssuerId;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities =
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
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verifier must surface the wallet's presentation under the 'pid' credential query identifier.");
        Assert.IsNotNull(verified.Claims["pid"]);
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


    [TestMethod]
    public async Task VerifierAcceptsPresentationFromTrustedAuthority()
    {
        //OID4VP 1.0 §6.1.1.3: the DCQL query pins the acceptable issuer via a
        //trusted_authorities (openid_federation) constraint. The PID is issued
        //under exactly that issuer, so the verifier's fail-closed DcqlEvaluator
        //check passes and the flow reaches PresentationVerified.
        await using TestHostShell app = new(TimeProvider);
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
            "A credential from a trusted authority must verify.");
    }


    [TestMethod]
    public async Task VerifierRejectsPresentationFromUntrustedAuthority()
    {
        //The DCQL query's trusted_authorities lists only a stranger, so the PID's
        //issuer is NOT trusted. The wallet's own adapter does not enforce
        //trusted_authorities (it presents normally), so this is a clean verifier-side
        //rejection: DcqlEvaluator fails the issuer check and the flow must NOT verify.
        await using TestHostShell app = new(TimeProvider);
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
            "A credential whose issuer is not in trusted_authorities must NOT verify.");
    }


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


    private static readonly Tag Sha256CommitmentTag = new(new Dictionary<Type, object>
    {
        [typeof(HashAlgorithmName)] = HashAlgorithmName.SHA256
    });


    /// <summary>
    /// A verifier-side salt-reuse store: a process-local set keyed by commitment bytes, shared across
    /// the two presentations in the reuse test. Wired as method groups, so only the per-call commitment
    /// is threaded by the library.
    /// </summary>
    private sealed class InMemoryCommitmentStore
    {
        private readonly HashSet<string> seen = new(StringComparer.Ordinal);

        public ValueTask<bool> IsSeen(DigestValue commitment, CancellationToken cancellationToken) =>
            ValueTask.FromResult(seen.Contains(Convert.ToHexString(commitment.AsReadOnlySpan())));

        public ValueTask Record(DigestValue commitment, CancellationToken cancellationToken)
        {
            seen.Add(Convert.ToHexString(commitment.AsReadOnlySpan()));

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

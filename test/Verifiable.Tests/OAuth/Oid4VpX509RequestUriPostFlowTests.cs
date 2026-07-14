using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The interop scenario that motivated the neutral-context / resolution-by-scheme
/// epic (the iDAKTO sandbox shape), proven end-to-end over real HTTP in one test:
/// an <c>x509_san_dns</c> verifier + OID4VP 1.0 §5.10 <c>request_uri_method=post</c>
/// + a JWE-wrapped JAR. The wallet POSTs its <c>wallet_metadata</c> JWKS to the
/// <c>request_uri</c> over a real Kestrel listener, receives the encrypted JAR,
/// decrypts it, resolves the verifier's signing key from the <c>x5c</c> in the
/// decrypted JAR header (NOT a pinned key) against trust anchors carried on the
/// <see cref="ExchangeContext"/>, verifies, presents, and POSTs the encrypted
/// <c>vp_token</c> — driving the verifier to <see cref="PresentationVerifiedState"/>.
/// </summary>
/// <remarks>
/// The matrix (<see cref="Oid4VpSchemeFormatMatrixTests"/>) covers x509 resolution
/// over the in-process transport, and <see cref="Oid4VpFlowIntegrationTests"/>
/// covers §5.10 POST + encrypted JAR with the <c>redirect_uri</c> prefix; this test
/// is the one that drives all three axes together over the wire. The x509 scheme
/// material is the shared <see cref="Oid4VpSchemeFixtures.X509"/>; the credential is
/// the shared <see cref="SdJwtVpFixture"/> PID — the only new wiring is the
/// HTTP-backed wallet built with the scheme resolver
/// (<see cref="TestHostShell.CreateHttpBackedOid4VpWalletClientAsync(VerifierKeyMaterial, ProduceVpTokenPresentationsDelegate, ResolveClientIdSigningKeyAsyncDelegate, System.Threading.CancellationToken)"/>).
/// </remarks>
[TestClass]
internal sealed class Oid4VpX509RequestUriPostFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static readonly Uri VerifierBaseUri = new("https://verifier.example.com");

    private static readonly ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    [TestMethod]
    public async Task X509SignedJarOverRequestUriPostWithEncryptedJarReachesPresentationVerified()
    {
        await using TestHostShell app = new(TimeProvider);

        //x509 scheme material: leaf-cert JAR-signing key, x5c JOSE header, the
        //x509_san_dns resolver, and the CA trust anchors the wallet evaluates the
        //chain against — all from the shared scheme fixture.
        using SchemeMaterial scheme = await Oid4VpSchemeFixtures.X509.CreateAsync(
            TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);

        //Register the verifier so the AS signs its JAR with the leaf cert key.
        using VerifierKeyMaterial verifierKeys = app.RegisterJarSigningClient(
            scheme.ClientId, VerifierBaseUri, scheme.JarSigningKeyPair, Oid4VpCapabilities);

        //Issue the SD-JWT PID the wallet will present, and register issuer trust.
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await SdJwtVpFixture.IssuePidCredentialAsync(
                TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(SdJwtVpFixture.IssuerId, issuerKey);

        //HTTP-backed wallet wired with the x509 resolver (no pinned key) and the
        //SD-JWT presentation drop-out.
        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys,
            TestHostShell.BuildSdJwtProduceDelegate(serializedSdJwt, holderKey),
            scheme.Resolver,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Wallet's ECDH-ES exchange keypair: the public side goes into
        //wallet_metadata.jwks on the §5.10 POST; the private side decrypts the
        //JWE-wrapped JAR.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> walletExchangeKeys =
            BouncyCastleKeyMaterialCreator.CreateP256ExchangeKeys(BaseMemoryPool.Shared);
        using PublicKeyMemory walletEncPublic = walletExchangeKeys.PublicKey;
        using PrivateKeyMemory walletEncPrivate = walletExchangeKeys.PrivateKey;

        //PAR in-process, injecting the x5c header into the JAR the AS will later
        //sign and JWE-wrap on the §5.10 POST path (the header rides the persisted
        //flow state, so it survives into the POST-served JAR).
        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-x509-post-01"),
            DcqlFixtures.PidFamilyNamePrepared(),
            transactionData: null,
            jarAdditionalHeaderClaims: scheme.JarHeader,
            TestContext.CancellationToken).ConfigureAwait(false);

        //CompactJar is null — the wallet client drives the §5.10 POST itself:
        //POSTs wallet_metadata + wallet_nonce, gets the encrypted JAR, decrypts it,
        //resolves the leaf key from the decrypted x5c against the context anchors,
        //verifies, presents, and POSTs the encrypted response.
        ExchangeContext exchangeContext = new();
        scheme.PlaceTrustMaterial(exchangeContext);

        //The wallet's sends route through the guarded chokepoint; the test
        //deployment's listener is loopback http, so the policy is relaxed for
        //exactly that — the deployment's explicit per-call choice.
        exchangeContext.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = null,
                RequestUri = requestUri,
                ExpectedVerifierClientId = scheme.ClientId,
                WalletExchangePublicKey = walletEncPublic,
                WalletExchangePrivateKey = walletEncPrivate,
                FlowId = $"wallet-x509-post-{Guid.NewGuid():N}"
            },
            exchangeContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            "Wallet PDA must reach ResponseSent after resolving the x509 leaf key from the " +
            "decrypted JAR's x5c over the §5.10 POST round-trip.");

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.Claims.ContainsKey("pid"),
            "Verifier must reach PresentationVerified for the x509 + request_uri_method=post + " +
            "encrypted-JAR flow driven entirely over HTTP.");
    }
}

using System.Collections.Immutable;
using System.Reflection;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.JCose;
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
/// A single data-driven matrix that drives every client-id scheme against every
/// credential format end-to-end through the real <see cref="Oid4VpWalletClient"/>.
/// Each matrix row is data carrying delegates — a <see cref="SchemeFixture"/>
/// (the per-scheme JAR-signing key, JAR header, key resolver, and trust material
/// the application places on the <see cref="ExchangeContext"/>) crossed with a
/// <see cref="FormatFixture"/> (the per-format host, issued credential, DCQL
/// query, presentation drop-out, and claim assertion). One shared
/// <see cref="RunAsync"/> driver runs every cell.
/// </summary>
/// <remarks>
/// The wallet-client pipeline is format-agnostic (fetch → resolve-by-scheme →
/// drop out to <see cref="Oid4VpWalletConfiguration.ProduceVpTokenPresentations"/>
/// → encrypt/POST), so the scheme axis and the format axis are independent: the
/// scheme determines only how the wallet resolves the JAR-signing key; the format
/// determines only what the presentation drop-out produces. Every cell must reach
/// the verifier's <see cref="PresentationVerifiedState"/> — a failing cell is a
/// real coupling between the two axes, not an expected gap.
/// </remarks>
[TestClass]
internal sealed class Oid4VpSchemeFormatMatrixTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static readonly Uri VerifierBaseUri = new("https://verifier.example.com");

    private static readonly ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    //The four client-id schemes the wallet resolves the JAR-signing key under,
    //drawn from the shared Oid4VpSchemeFixtures.
    private static IEnumerable<SchemeFixture> Schemes =>
        [Oid4VpSchemeFixtures.X509, Oid4VpSchemeFixtures.X509Hash,
         Oid4VpSchemeFixtures.VerifierAttestation,
         Oid4VpSchemeFixtures.OpenIdFederation, Oid4VpSchemeFixtures.DecentralizedIdentifier];

    //Each credential format is a sibling shared fixture; the matrix is format-blind.
    private static IEnumerable<FormatFixture> Formats =>
        [SdJwtVpFixture.Format, MdocVpFixture.Format, SdCwtVpFixture.Format];


    /// <summary>The scheme × format cross product; each row carries the two fixture objects.</summary>
    public static IEnumerable<object[]> Matrix =>
        from scheme in Schemes
        from format in Formats
        select new object[] { scheme, format };


    public static string MatrixDisplayName(MethodInfo _, object[] data) =>
        $"{((SchemeFixture)data[0]).Name} × {((FormatFixture)data[1]).Name}";


    [TestMethod]
    [DynamicData(nameof(Matrix), DynamicDataDisplayName = nameof(MatrixDisplayName))]
    public async Task SchemeFormatReachesPresentationVerified(SchemeFixture scheme, FormatFixture format) =>
        await RunAsync(scheme, format, TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// The one shared driver: build the format's host + credential, register the
    /// verifier so the AS signs its JAR with the scheme's key, issue and serve the
    /// JAR carrying the scheme's header material, then drive the real wallet client
    /// — which resolves the JAR-signing key by scheme off the
    /// <see cref="ExchangeContext"/>, runs the format's presentation drop-out,
    /// encrypts the response, and POSTs it. Every cell must reach the verifier's
    /// <see cref="PresentationVerifiedState"/>.
    /// </summary>
    private static async Task RunAsync(
        SchemeFixture scheme, FormatFixture format, FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        await using FormatRun run = await format.StartAsync(tp, cancellationToken).ConfigureAwait(false);
        TestHostShell app = run.App;

        using SchemeMaterial schemeMaterial = await scheme.CreateAsync(tp, cancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial verifierKeys = app.RegisterJarSigningClient(
            schemeMaterial.ClientId, VerifierBaseUri, schemeMaterial.JarSigningKeyPair, Oid4VpCapabilities);

        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce($"nonce-{Guid.NewGuid():N}"),
            run.Query,
            transactionData: null,
            jarAdditionalHeaderClaims: schemeMaterial.JarHeader,
            cancellationToken).ConfigureAwait(false);
        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, cancellationToken).ConfigureAwait(false);

        //Wallet client wired ONLY with the scheme resolver — no pinned key.
        (OAuthClient oauthClient, _, _) = app.CreateInProcessOAuthClientAndRegistration(
            verifierKeys.Registration,
            "https://wallet.example.com/cb",
            verifierKeys.Registration.IssuerUri!.ToString());

        Oid4VpWalletClient walletClient = new(
            oauthClient.Infrastructure,
            TestHostShell.BuildSlimOid4VpWalletConfiguration(run.Produce, schemeMaterial.Resolver));

        ExchangeContext exchangeContext = new();
        schemeMaterial.PlaceTrustMaterial(exchangeContext);

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = schemeMaterial.ClientId,
                FlowId = $"wallet-{Guid.NewGuid():N}"
            },
            exchangeContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState,
            $"Wallet client must reach ResponseSent after resolving the '{schemeMaterial.ClientId}' JAR key.");

        PresentationVerifiedState verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        run.AssertClaims(verified);
    }
}


/// <summary>
/// A credential format as data: its display name plus a factory that starts a
/// per-run <see cref="FormatRun"/> — building the format's host (with whatever
/// verification seams it needs), issuing and registering trust for one
/// credential, and wiring the presentation drop-out and the verified-claims
/// assertion.
/// </summary>
internal sealed record FormatFixture(
    string Name,
    Func<FakeTimeProvider, CancellationToken, ValueTask<FormatRun>> StartAsync);


/// <summary>
/// Everything one matrix cell needs from the format side, owned for the duration
/// of the run. Disposing releases the credential material and the host.
/// </summary>
/// <remarks>
/// Host construction and credential issuance are fused into one step because some
/// formats (mdoc, SD-CWT) bind the issuer key into the host's verification seams
/// at construction time, so the issuer key must exist before the host is built.
/// </remarks>
internal sealed class FormatRun: IAsyncDisposable
{
    public required TestHostShell App { get; init; }

    public required PreparedDcqlQuery Query { get; init; }

    public required ProduceVpTokenPresentationsDelegate Produce { get; init; }

    public required Action<PresentationVerifiedState> AssertClaims { get; init; }

    /// <summary>Credential / key material the format allocated (holder + issuer keys, stored credential).</summary>
    public IReadOnlyList<IDisposable> Owned { get; init; } = [];

    public async ValueTask DisposeAsync()
    {
        foreach(IDisposable owned in Owned)
        {
            owned.Dispose();
        }

        await App.DisposeAsync().ConfigureAwait(false);
    }
}

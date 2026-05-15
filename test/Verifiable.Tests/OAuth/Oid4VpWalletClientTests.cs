using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using System.Text;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end tests for <see cref="Oid4VpWalletClient{TCredential}"/>. Each test
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

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static readonly ImmutableHashSet<ServerCapabilityName> Oid4VpCapabilities =
        ImmutableHashSet.Create(
            ServerCapabilityName.VerifiablePresentation,
            ServerCapabilityName.JwksEndpoint,
            ServerCapabilityName.DiscoveryEndpoint);


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

        Oid4VpWalletClient<SdJwtVcCredential> walletClient = BuildWalletClient(
            app, verifierKeys, new SdJwtVcCredential(serializedSdJwt));

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions<SdJwtVcCredential>
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                VerifierSigningPublicKey = verifierKeys.SigningPublicKey,
                HolderKey = holderKey,
                FlowId = $"wallet-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result.EncryptedJweResponse);
        Assert.IsInstanceOfType<ResponseSent>(result.TerminalState);
        Assert.IsInstanceOfType<PresentationVerifiedState>(
            app.GetFlowState(parHandle).State,
            "Verifier PDA must reach PresentationVerified after the wallet POSTs the encrypted response.");
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

        Oid4VpWalletClient<SdJwtVcCredential> walletClient = BuildWalletClient(
            app, verifierKeys, new SdJwtVcCredential(serializedSdJwt));

        _ = await walletClient.PresentJarAsync(
            new PresentJarOptions<SdJwtVcCredential>
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                VerifierSigningPublicKey = verifierKeys.SigningPublicKey,
                HolderKey = holderKey,
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

        Oid4VpWalletClient<SdJwtVcCredential> walletClient = BuildWalletClient(
            app, verifierKeys, new SdJwtVcCredential(serializedSdJwt));

        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            _ = await walletClient.PresentJarAsync(
                new PresentJarOptions<SdJwtVcCredential>
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                    VerifierSigningPublicKey = verifierKeys.SigningPublicKey,
                    HolderKey = holderKey
                },
                cts.Token).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    private async ValueTask<(Uri RequestUri, string ParHandle, string CompactJar)> IssueJarAsync(
        TestHostShell app,
        VerifierKeyMaterial verifierKeys)
    {
        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce($"nonce-walletclient-{Guid.NewGuid():N}"),
            CreatePreparedQuery(),
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        return (requestUri, parHandle, compactJar);
    }


    private static Oid4VpWalletClient<SdJwtVcCredential> BuildWalletClient(
        TestHostShell app,
        VerifierKeyMaterial verifierKeys,
        SdJwtVcCredential storedCredential)
    {
        (OAuthClient oauthClient, _, _) = app.CreateInProcessOAuthClientAndRegistration(
            verifierKeys.Registration,
            "https://client.example.com/callback",
            verifierKeys.Registration.IssuerUri!.ToString());

        Oid4VpWalletConfiguration<SdJwtVcCredential> walletConfig = new()
        {
            ResolveCandidateCredentials = (_, _) =>
                ValueTask.FromResult<IReadOnlyList<SdJwtVcCredential>>([storedCredential]),
            Base64UrlDecoder = TestSetup.Base64UrlDecoder,
            JwtHeaderSerializer = header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions),
            JwtPayloadSerializer = payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions),
            JarHeaderDeserializer = bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            JarPayloadDeserializer = bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            DcqlQueryDeserializer = json => JsonSerializer.Deserialize<DcqlQuery>(
                json, TestSetup.DefaultSerializationOptions)!,
            ClientMetadataDeserializer = json => JsonSerializer.Deserialize<VerifierClientMetadata>(
                json, TestSetup.DefaultSerializationOptions)!,
            TagToEpkCrvConverter = CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            KeyAgreementEncrypt = BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            KeyDerivation = ConcatKdf.DefaultKeyDerivationDelegate,
            AeadEncrypt = BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            ParseSdJwt = sdJwt => SdJwtSerializer.ParseToken(
                sdJwt, TestSetup.Base64UrlDecoder, Pool, TestSalts.TestSaltTag),
            SerializeSdJwt = token => SdJwtSerializer.SerializeToken(token, TestSetup.Base64UrlEncoder),
            ComputeSdJwtHashInput = token => SdJwtSerializer.GetSdJwtForHashing(token, TestSetup.Base64UrlEncoder),
            MemoryPool = Pool
        };

        return new Oid4VpWalletClient<SdJwtVcCredential>(oauthClient.Infrastructure, walletConfig);
    }


    private static PreparedDcqlQuery CreatePreparedQuery() =>
        DcqlPreparer.Prepare(new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                    Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }]
                }
            ]
        });


    private async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)> IssuePidCredentialAsync(
        CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;

        Dictionary<string, object> holderJwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublicKey.Tag.Get<CryptoAlgorithm>(),
            holderPublicKey.Tag.Get<Purpose>(),
            holderPublicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: IssuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: TimeProvider.GetUtcNow(),
            holderConfirmation: holderJwk,
            claims:
            [
                new(EudiPid.SdJwt.GivenName, "Erika"),
                new(EudiPid.SdJwt.FamilyName, "Mustermann")
            ]);

        byte[] payloadBytes = JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);

        HashSet<CredentialPath> disclosablePaths =
        [
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
        ];

        SdTokenResult result = await payload.IssueSdJwtAsync(
            disclosablePaths, TestSalts.DefaultGenerator(),
            issuerPrivateKey, IssuerKeyId, Pool,
            TestSetup.DefaultSerializationOptions,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }
}

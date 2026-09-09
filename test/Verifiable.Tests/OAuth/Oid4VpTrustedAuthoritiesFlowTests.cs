using Microsoft.Extensions.Time.Testing;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Federation;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
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
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.Tests.Federation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end flow tests for the DCQL <c>trusted_authorities</c> types of
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
/// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see> over the real OID4VP wire (PAR → JAR
/// → encrypted <c>direct_post</c>): the <c>aki</c> type for a <c>dc+sd-jwt</c> credential whose issuer
/// JWS carries an <c>x5c</c> certificate chain, and the privacy guarantee of
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">
/// Section 15.10</see> for the <c>openid_federation</c> type. The mdoc <c>aki</c> twin lives in
/// <see cref="Oid4VpMdocFlowIntegrationTests"/> (its IssuerAuth carries the x5chain natively) and the
/// <c>openid_federation</c> accept/reject pair in <see cref="Oid4VpWalletClientTests"/>; this class
/// covers the SD-JWT chain arm those two do not, and the zero-fetch privacy invariant.
/// </summary>
[TestClass]
internal sealed class Oid4VpTrustedAuthoritiesFlowTests
{
    /// <summary>The MSTest context, providing the per-test cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fixed clock every flow in this class runs against.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The verifier's OAuth client identifier.</summary>
    private const string VerifierClientId = "https://verifier.example.com";

    /// <summary>The verifier's base URI.</summary>
    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    /// <summary>The identifier the PID is issued under and registered as a trusted issuer key.</summary>
    private const string IssuerId = "https://issuer.example.com";

    /// <summary>The issuer JWS <c>kid</c> the SD-JWT is signed under.</summary>
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    /// <summary>The shared, explicitly-passed test memory pool.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The verifier capabilities every host in this class registers its client with.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
    /// OID4VP 1.0, Section 6.1.1.1</see>: "The raw byte representation of this element MUST match with
    /// the AuthorityKeyIdentifier element of an X.509 certificate in the certificate chain present in
    /// the Credential (e.g., in the header of an mdoc or SD-JWT)." A <c>dc+sd-jwt</c> credential whose
    /// issuer JWS carries the minted chain in its <c>x5c</c> header, queried with the leaf's
    /// AuthorityKeyIdentifier (the leaf's issuer certificate's SubjectKeyIdentifier per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2">RFC 5280, Section 4.2.1.2</see>),
    /// reaches <see cref="PresentationVerifiedState"/>. The AKI value is computed from the minted
    /// intermediate certificate's SubjectKeyIdentifier, never read back through the AuthorityKeyIdentifier
    /// delegate under test.
    /// </summary>
    /// <param name="backendName">The X.509 backend the verifier reads the chain through.</param>
    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task SdJwtFlowWhoseChainLeafAuthorityIsTrustedReachesPresentationVerified(string backendName)
    {
        X509Backend backend = ResolveBackend(backendName);
        using X509ChainTestRingChain chain = X509ChainTestRing.BuildThreeLevelChain("issuer.example.com", TimeProvider);

        //The leaf's AuthorityKeyIdentifier is, by RFC 5280 §4.2.1.2, its issuer's (the intermediate's)
        //SubjectKeyIdentifier — the trusted authority the query pins for the accept case.
        string leafAuthorityKeyIdentifier = ComputeSubjectKeyIdentifierBase64Url(
            backend.ReadSubjectKeyIdentifier, chain.Intermediate.Certificate.RawData);

        FlowState state = await RunSdJwtAkiFlowAsync(
            backend, chain, BuildSdJwtAkiQuery(leafAuthorityKeyIdentifier)).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(state,
            "Section 6.1.1.1: a chain certificate's AuthorityKeyIdentifier named in trusted_authorities (aki) must reach PresentationVerified.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OID4VP 1.0, Section 6.1</see>: "Every Credential returned by the Wallet SHOULD match at least one
    /// of the conditions present in the corresponding trusted_authorities array if present." The DCQL
    /// query names only a stranger AuthorityKeyIdentifier that no certificate in the credential's chain
    /// bears, so the verifier's disclosure assessment — the consistency check on
    /// <see cref="VpTokenParsed.TrustedAuthorityEvidence"/> — refuses the presentation, and the flow does
    /// NOT reach <see cref="PresentationVerifiedState"/>.
    /// </summary>
    /// <param name="backendName">The X.509 backend the verifier reads the chain through.</param>
    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task SdJwtFlowWhoseChainAuthorityIsAStrangerDoesNotVerify(string backendName)
    {
        X509Backend backend = ResolveBackend(backendName);
        using X509ChainTestRingChain chain = X509ChainTestRing.BuildThreeLevelChain("issuer.example.com", TimeProvider);

        //"c3RyYW5nZXItYWtp" is base64url for "stranger-aki" — a value no chain certificate bears.
        FlowState state = await RunSdJwtAkiFlowAsync(
            backend, chain, BuildSdJwtAkiQuery("c3RyYW5nZXItYWtp")).ConfigureAwait(false);

        Assert.IsNotInstanceOfType<PresentationVerifiedState>(state,
            "Section 6.1: a credential whose chain matches no trusted_authorities (aki) entry must NOT reach PresentationVerified.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
    /// OID4VP 1.0, Section 6.1.1.1</see>: "The raw byte representation of this element MUST match with the
    /// AuthorityKeyIdentifier element of an X.509 certificate in the certificate chain" — "the chain can
    /// consist of a single certificate and the Credential can include the entire X.509 chain or parts of
    /// it." The query names the intermediate's own AuthorityKeyIdentifier (the root certificate's
    /// SubjectKeyIdentifier), which matches through the INTERMEDIATE certificate carried in the
    /// three-level chain, not the leaf — proving the match ranges over every chain certificate.
    /// </summary>
    /// <param name="backendName">The X.509 backend the verifier reads the chain through.</param>
    [TestMethod]
    [DataRow("Microsoft")]
    [DataRow("BouncyCastle")]
    public async Task SdJwtFlowAcceptsAnIntermediateCertificatesAuthorityKeyIdentifier(string backendName)
    {
        X509Backend backend = ResolveBackend(backendName);
        using X509ChainTestRingChain chain = X509ChainTestRing.BuildThreeLevelChain("issuer.example.com", TimeProvider);

        //The intermediate's AuthorityKeyIdentifier is, by RFC 5280 §4.2.1.2, its issuer's (the root's)
        //SubjectKeyIdentifier — a value that matches through the intermediate certificate in the chain,
        //not the leaf.
        string intermediateAuthorityKeyIdentifier = ComputeSubjectKeyIdentifierBase64Url(
            backend.ReadSubjectKeyIdentifier, chain.Root.Certificate.RawData);

        FlowState state = await RunSdJwtAkiFlowAsync(
            backend, chain, BuildSdJwtAkiQuery(intermediateAuthorityKeyIdentifier)).ConfigureAwait(false);

        Assert.IsInstanceOfType<PresentationVerifiedState>(state,
            "Section 6.1.1.1: an intermediate certificate's AuthorityKeyIdentifier in the chain must satisfy the aki constraint.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">
    /// OID4VP 1.0, Section 15.10</see>: "Wallets SHOULD NOT access URLs included in a request from the
    /// Verifier if those URLs are unfamiliar or hosted by untrusted third parties. Privacy risks can be
    /// reduced if such URLs are treated purely as identifiers and not actually retrieved by the Wallet
    /// upon receiving the request." With the resolver's familiar-anchor set emptied, the issuer's
    /// <c>openid_federation</c> identifier resolves to no validated trust path, so the accept case turns
    /// into a withhold — and, structurally, the federation fetch delegates are never invoked, so no
    /// request-named identifier is ever dereferenced.
    /// </summary>
    [TestMethod]
    public async Task FederationFlowWithNoFamiliarAnchorWithholdsWithoutDereferencingAnyIdentifier()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        EntityIdentifier issuerEntity = new(IssuerId);
        EntityIdentifier candidateAnchor = new("https://anchor.example.com");
        FetchInvocationCounter fetchCounter = new();

        //The resolver is built over a genuinely capable federation chain and fetch delegates, but the
        //wallet/verifier holds NO familiar anchor, so FederationTrustPathEvidence.ResolveAsync iterates
        //an empty anchor set: the fetch delegates are wired yet never called.
        ResolveTrustedAuthorityEvidenceDelegate resolveTrustedAuthorityEvidence =
            await BuildCountingFederationResolverAsync(
                issuerEntity, candidateAnchor, familiarTrustAnchors: [], now, fetchCounter,
                TestContext.CancellationToken).ConfigureAwait(false);

        await using TestHostShell app = new(TimeProvider, resolveTrustedAuthorityEvidence: resolveTrustedAuthorityEvidence);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await SdJwtVpFixture.IssuePidCredentialAsync(TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        FlowState state = await DriveSdJwtFlowAsync(
            app, verifierKeys, serializedSdJwt, holderKey,
            DcqlFixtures.PidFamilyNameTrustedAuthoritiesPrepared(IssuerId)).ConfigureAwait(false);

        Assert.IsNotInstanceOfType<PresentationVerifiedState>(state,
            "Section 15.10: with no familiar anchor the issuer's identifier is on no validated path, so the accept case must withhold.");
        Assert.AreEqual(0, fetchCounter.EntityConfigurationFetches,
            "Section 15.10: no Entity Configuration is fetched — the request's identifiers are treated purely as identifiers.");
        Assert.AreEqual(0, fetchCounter.SubordinateStatementFetches,
            "Section 15.10: no Subordinate Statement is fetched — the request's identifiers are never dereferenced.");
    }


    /// <summary>
    /// Drives a <c>dc+sd-jwt</c> credential whose issuer JWS carries <paramref name="chain"/> in its
    /// <c>x5c</c> header through the full OID4VP wire against a verifier wired to read the chain through
    /// <paramref name="backend"/>, and returns the verifier's terminal flow state.
    /// </summary>
    /// <param name="backend">The X.509 backend the verifier parses and reads the chain through.</param>
    /// <param name="chain">The minted certificate chain embedded as the issuer JWS <c>x5c</c> evidence.</param>
    /// <param name="query">The prepared DCQL query carrying the <c>trusted_authorities</c> (aki) constraint.</param>
    /// <returns>The verifier's terminal flow state.</returns>
    private async Task<FlowState> RunSdJwtAkiFlowAsync(
        X509Backend backend, X509ChainTestRingChain chain, PreparedDcqlQuery query)
    {
        ResolveTrustedAuthorityEvidenceDelegate resolveTrustedAuthorityEvidence =
            TrustedAuthorityEvidenceResolution.Build(
                backend.ExtractAuthorityKeyIdentifier,
                backend.ReadSubjectKeyIdentifier,
                backend.ReadSubjectName,
                heldTrustedLists: [],
                resolveFederationTrustPath: null);

        await using TestHostShell app = new(
            TimeProvider, parseX5c: backend.ParseX5c, resolveTrustedAuthorityEvidence: resolveTrustedAuthorityEvidence);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialWithX5cAsync(
                chain.X5cValues, TestContext.CancellationToken).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        return await DriveSdJwtFlowAsync(app, verifierKeys, serializedSdJwt, holderKey, query).ConfigureAwait(false);
    }


    /// <summary>
    /// Runs the PAR → JAR → encrypted <c>direct_post</c> wire for <paramref name="query"/> and returns
    /// the verifier's terminal flow state. A verifier rejection surfaces as a non-200 <c>direct_post</c>
    /// (the wallet client throws <see cref="InvalidOperationException"/>), swallowed so the caller can
    /// assert on the flow state either way.
    /// </summary>
    /// <param name="app">The in-process verifier host shell.</param>
    /// <param name="verifierKeys">The registered verifier's key material.</param>
    /// <param name="serializedSdJwt">The stored SD-JWT the wallet presents.</param>
    /// <param name="holderKey">The holder's key-binding private key.</param>
    /// <param name="query">The prepared DCQL query.</param>
    /// <returns>The verifier's terminal flow state.</returns>
    private async Task<FlowState> DriveSdJwtFlowAsync(
        TestHostShell app,
        VerifierKeyMaterial verifierKeys,
        string serializedSdJwt,
        PrivateKeyMemory holderKey,
        PreparedDcqlQuery query)
    {
        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce($"nonce-ta-{Guid.NewGuid():N}"),
            query,
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
                    FlowId = $"wallet-ta-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //A verifier refusal (a credential matching no trusted_authorities entry) is a non-200
            //direct_post; the flow state carries the outcome the assertion inspects.
        }

        return app.GetFlowState(parHandle).State;
    }


    /// <summary>
    /// Builds an <see cref="Oid4VpWalletClient"/> over the in-process verifier that presents
    /// <paramref name="storedSdJwt"/> with minimal disclosure and the holder's key binding.
    /// </summary>
    /// <param name="app">The in-process verifier host shell.</param>
    /// <param name="verifierKeys">The registered verifier's key material.</param>
    /// <param name="storedSdJwt">The stored SD-JWT the wallet presents.</param>
    /// <param name="holderKey">The holder's key-binding private key.</param>
    /// <returns>The wallet client.</returns>
    private static Oid4VpWalletClient BuildWalletClient(
        TestHostShell app,
        VerifierKeyMaterial verifierKeys,
        string storedSdJwt,
        PrivateKeyMemory holderKey)
    {
        (OAuthClient oauthClient, _, _) = app.CreateInProcessOAuthClientAndRegistration(
            verifierKeys.Registration,
            "https://client.example.com/callback",
            verifierKeys.Registration.IssuerUri!.ToString());

        return new Oid4VpWalletClient(
            oauthClient.Infrastructure,
            TestHostShell.BuildSlimOid4VpWalletConfiguration(
                TestHostShell.BuildSdJwtProduceDelegate(storedSdJwt, holderKey),
                TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey)));
    }


    /// <summary>
    /// Builds a prepared <c>dc+sd-jwt</c> DCQL query for <c>family_name</c> carrying a
    /// <c>trusted_authorities</c> constraint of type <c>aki</c> naming
    /// <paramref name="authorityKeyIdentifiers"/> (each base64url), per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
    /// OID4VP 1.0, Section 6.1.1.1</see>.
    /// </summary>
    /// <param name="authorityKeyIdentifiers">The accepted AuthorityKeyIdentifiers (base64url).</param>
    /// <returns>The prepared query.</returns>
    private static PreparedDcqlQuery BuildSdJwtAkiQuery(params string[] authorityKeyIdentifiers)
    {
        DcqlQuery query = new()
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                    Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                    TrustedAuthorities =
                    [
                        new TrustedAuthoritiesQuery
                        {
                            Type = DcqlTrustedAuthorityTypes.Aki,
                            Values = authorityKeyIdentifiers
                        }
                    ],
                    Claims =
                    [
                        new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(EudiPid.SdJwt.FamilyName) }
                    ]
                }
            ]
        };

        return DcqlPreparer.Prepare(query);
    }


    /// <summary>
    /// Issues an EUDI PID SD-JWT VC (P-256 issuer signature, Ed25519 holder key in <c>cnf</c>) whose
    /// issuer JWS protected header carries <paramref name="x5c"/> as the RFC 7515 §4.1.6 certificate
    /// chain — the <c>aki</c> evidence Section 6.1.1.1 reads. The issuer signature is verified against
    /// the registered issuer key (the trust framework's out-of-band <c>iss</c> resolution); the chain in
    /// the header is the credential's certificate-chain evidence, exactly the separation
    /// <see cref="SdJwtVpTokenVerification"/> draws between key resolution and trust-authority evidence.
    /// </summary>
    /// <param name="x5c">The base64-DER certificate chain (leaf first) to embed in the issuer JWS header.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The serialized SD-JWT, the holder's private key, and the issuer's public key; the caller owns the two keys.</returns>
    private ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)> IssuePidCredentialWithX5cAsync(
        IReadOnlyList<string> x5c, CancellationToken cancellationToken) =>
        IssuePidCredentialWithX5cCoreAsync(TimeProvider, [.. x5c], cancellationToken);


    /// <summary>
    /// The parameter-taking body of <see cref="IssuePidCredentialWithX5cAsync"/>.
    /// </summary>
    /// <param name="tp">The clock the credential is issued against.</param>
    /// <param name="x5c">The base64-DER certificate chain (leaf first) to embed.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The serialized SD-JWT and the holder/issuer key material.</returns>
    private static async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)> IssuePidCredentialWithX5cCoreAsync(
        FakeTimeProvider tp, string[] x5c, CancellationToken cancellationToken)
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
            issuedAt: tp.GetUtcNow(),
            holderConfirmation: holderJwk,
            claims:
            [
                new(EudiPid.SdJwt.GivenName, "Erika"),
                new(EudiPid.SdJwt.FamilyName, "Mustermann")
            ]);

        HashSet<CredentialPath> disclosablePaths =
        [
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
        ];

        byte[] payloadBytes = JsonSerializerExtensions.SerializeToUtf8Bytes(
            payload, TestSetup.DefaultSerializationOptions);

        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(
            issuerPrivateKey.Tag.Get<CryptoAlgorithm>(), issuerPrivateKey.Tag.Get<Purpose>());

        (SdTokenResult result, _) = await SdIssuance.IssueVerboseAsync(
            payloadBytes,
            disclosablePaths,
            SdJwtPipeline.Redact,
            BuildX5cIssuerSign(x5c),
            TestSalts.DefaultGenerator(),
            issuerPrivateKey,
            IssuerKeyId,
            Pool,
            signingDelegate,
            hashAlgorithm: null,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }


    /// <summary>
    /// Builds a <see cref="SignPayloadDelegate"/> that signs the redacted SD-JWT payload as a compact
    /// JWS whose protected header carries the <c>x5c</c> certificate chain
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6">RFC 7515, Section 4.1.6</see>)
    /// alongside <c>alg</c>, <c>typ</c> and <c>kid</c> — the header shape
    /// <see cref="SdJwtIssuerHeader.TryReadX5c"/> reads on the verifier side.
    /// </summary>
    /// <param name="x5c">The base64-DER certificate chain (leaf first) to place in the header.</param>
    /// <returns>The signing delegate.</returns>
    private static SignPayloadDelegate BuildX5cIssuerSign(string[] x5c)
    {
        return async (signingDelegate, redactedPayload, hashAlgorithm, mediaType, privateKey, keyId, memoryPool, cancellationToken) =>
        {
            string resolvedMediaType = string.IsNullOrEmpty(mediaType)
                ? WellKnownMediaTypes.Jwt.SdJwt
                : mediaType;

            string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

            JwtHeader header = new()
            {
                [WellKnownJwkMemberNames.Alg] = algorithm,
                [WellKnownJoseHeaderNames.Typ] = resolvedMediaType,
                [WellKnownJwkMemberNames.Kid] = keyId,
                [WellKnownJwkMemberNames.X5c] = x5c
            };

            byte[] headerBytes = JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);
            EncodeDelegate encoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);

            string headerSegment = encoder(headerBytes);
            string payloadSegment = encoder(redactedPayload.Span);

            int signingInputLength = headerSegment.Length + 1 + payloadSegment.Length;
            using IMemoryOwner<byte> signingInputOwner = memoryPool.Rent(signingInputLength);
            Memory<byte> signingInputMemory = signingInputOwner.Memory[..signingInputLength];

            int written = Encoding.ASCII.GetBytes(headerSegment, signingInputMemory.Span);
            signingInputMemory.Span[written] = (byte)'.';
            written += 1;
            _ = Encoding.ASCII.GetBytes(payloadSegment, signingInputMemory.Span[written..]);

            (Signature signature, CryptoEvent? cryptoEvent) = await signingDelegate(
                privateKey.AsReadOnlyMemory(),
                signingInputMemory,
                memoryPool,
                context: null,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            if(cryptoEvent is not null)
            {
                CryptographicKeyEvents.DefaultSink(cryptoEvent);
            }

            string signatureSegment = encoder(signature.AsReadOnlyMemory().Span);
            string compactJws = $"{headerSegment}.{payloadSegment}.{signatureSegment}";

            return Encoding.UTF8.GetBytes(compactJws);
        };
    }


    /// <summary>
    /// Computes the base64url AuthorityKeyIdentifier a <c>trusted_authorities</c> (aki) entry pins for a
    /// certificate whose issuer is <paramref name="issuerCertificateDer"/>: the issuer certificate's
    /// SubjectKeyIdentifier bytes, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2">RFC 5280, Section 4.2.1.2</see>,
    /// which by Section 4.2.1.1 the subject certificate carries as its AuthorityKeyIdentifier
    /// <c>keyIdentifier</c>. Read through the SubjectKeyIdentifier backend delegate, never the
    /// AuthorityKeyIdentifier delegate the flow puts under test.
    /// </summary>
    /// <param name="readSubjectKeyIdentifier">The backend SubjectKeyIdentifier reader.</param>
    /// <param name="issuerCertificateDer">The issuer certificate's DER bytes.</param>
    /// <returns>The canonical unpadded base64url of the issuer's SubjectKeyIdentifier.</returns>
    private static string ComputeSubjectKeyIdentifierBase64Url(
        ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier, byte[] issuerCertificateDer)
    {
        using PkiCertificateMemory issuerCertificate = CopyToPkiCertificate(issuerCertificateDer);

        return new AuthorityKeyIdentifier(readSubjectKeyIdentifier(issuerCertificate)).ToBase64Url();
    }


    /// <summary>Copies DER certificate bytes into a pooled <see cref="PkiCertificateMemory"/>.</summary>
    /// <param name="derBytes">The certificate's DER bytes.</param>
    /// <returns>The pooled certificate carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory CopyToPkiCertificate(byte[] derBytes)
    {
        IMemoryOwner<byte> owner = Pool.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Mints a two-node OpenID Federation trust chain (<paramref name="issuerEntity"/> subordinate to
    /// <paramref name="candidateAnchor"/>) via <see cref="FederationTestRing"/>, wires in-memory fetch
    /// delegates that increment <paramref name="fetchCounter"/> on every call, and composes a
    /// <see cref="ResolveTrustedAuthorityEvidenceDelegate"/> whose <c>openid_federation</c> arm resolves
    /// through <see cref="FederationTrustPathEvidence.ResolveAsync"/> against
    /// <paramref name="familiarTrustAnchors"/>. Passing an empty <paramref name="familiarTrustAnchors"/>
    /// leaves the fetch delegates wired but never invoked — the structural expression of
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">
    /// OID4VP 1.0, Section 15.10</see>.
    /// </summary>
    /// <param name="issuerEntity">The credential issuer's Entity Identifier — the chain's subject.</param>
    /// <param name="candidateAnchor">The Trust Anchor the chain is minted toward.</param>
    /// <param name="familiarTrustAnchors">The anchors the resolver actually validates against.</param>
    /// <param name="now">The instant the statements are issued and validated at.</param>
    /// <param name="fetchCounter">The counter the fetch delegates increment.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The composed resolver.</returns>
    private static async Task<ResolveTrustedAuthorityEvidenceDelegate> BuildCountingFederationResolverAsync(
        EntityIdentifier issuerEntity,
        EntityIdentifier candidateAnchor,
        IReadOnlyCollection<EntityIdentifier> familiarTrustAnchors,
        DateTimeOffset now,
        FetchInvocationCounter fetchCounter,
        CancellationToken cancellationToken)
    {
        const string AnchorFetchEndpoint = "https://anchor.example.com/federation/fetch";

        using FederationTestRingNode issuerNode = FederationTestRing.CreateNode(issuerEntity);
        using FederationTestRingNode anchorNode = FederationTestRing.CreateNode(candidateAnchor);

        MintedStatement issuerEntityConfiguration = await FederationTestRing.MintEntityConfigurationAsync(
            issuerNode, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.AuthorityHints] = new List<object> { candidateAnchor.Value }
            },
            cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement anchorEntityConfiguration = await FederationTestRing.MintEntityConfigurationAsync(
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

        Dictionary<string, string> configurationByEntity = new(StringComparer.Ordinal)
        {
            [issuerEntity.Value] = issuerEntityConfiguration.CompactJws,
            [candidateAnchor.Value] = anchorEntityConfiguration.CompactJws
        };

        FetchEntityConfigurationDelegate fetchConfiguration = (entity, context, ct) =>
        {
            fetchCounter.EntityConfigurationFetches++;

            return ValueTask.FromResult(configurationByEntity.TryGetValue(entity.Value, out string? jws)
                ? FederationHttpClientTransport.TryParseFetchedStatement(jws)
                : null);
        };

        FetchEntityStatementDelegate fetchSubordinate = (subject, fetchEndpoint, context, ct) =>
        {
            fetchCounter.SubordinateStatementFetches++;

            return ValueTask.FromResult(
                string.Equals(fetchEndpoint.ToString(), AnchorFetchEndpoint, StringComparison.Ordinal)
                    && string.Equals(subject.Value, issuerEntity.Value, StringComparison.Ordinal)
                    ? FederationHttpClientTransport.TryParseFetchedStatement(anchorAboutIssuer.CompactJws)
                    : null);
        };

        ValidateTrustChainAsyncDelegate validate = TrustChainValidation.BuildInlineValidator(
            HeaderDeserializer, PayloadDeserializer, TestSetup.Base64UrlDecoder,
            FederationKeyResolver.BuildInChainResolver(TestSetup.Base64UrlDecoder, Pool));

        return TrustedAuthorityEvidenceResolution.Build(
            MicrosoftX509Functions.GetAuthorityKeyIdentifier,
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName,
            heldTrustedLists: [],
            resolveFederationTrustPath: (issuer, ct) => FederationTrustPathEvidence.ResolveAsync(
                issuer,
                familiarTrustAnchors,
                fetchConfiguration,
                fetchSubordinate,
                validate,
                new ExchangeContext(),
                maxChainLength: 5,
                validationTime: now,
                clockSkew: TimeSpan.FromMinutes(5),
                Pool,
                ct));
    }


    /// <summary>Deserializes a compact JWS header segment for <see cref="TrustChainValidation.BuildInlineValidator"/>.</summary>
    private static JwtHeaderDeserializer HeaderDeserializer { get; } = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Header JSON parsed to null.");

    /// <summary>Deserializes a compact JWS payload segment for <see cref="TrustChainValidation.BuildInlineValidator"/>.</summary>
    private static JwtPayloadDeserializer PayloadDeserializer { get; } = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Payload JSON parsed to null.");


    /// <summary>
    /// The X.509 backend delegate set a flow reads the credential's certificate chain through — run once
    /// per backend so the trust-evidence arm proves out on both <see cref="MicrosoftX509Functions"/> and
    /// <see cref="BouncyCastleX509Functions"/>.
    /// </summary>
    /// <param name="ParseX5c">Parses the JOSE <c>x5c</c> header into certificates.</param>
    /// <param name="ExtractAuthorityKeyIdentifier">Reads a certificate's AuthorityKeyIdentifier — the delegate under test.</param>
    /// <param name="ReadSubjectKeyIdentifier">Reads a certificate's SubjectKeyIdentifier.</param>
    /// <param name="ReadSubjectName">Renders a certificate's Subject as an RFC 4514 string.</param>
    private readonly record struct X509Backend(
        ParseX5cDelegate ParseX5c,
        ExtractAuthorityKeyIdentifierDelegate ExtractAuthorityKeyIdentifier,
        ReadCertificateSubjectKeyIdentifierDelegate ReadSubjectKeyIdentifier,
        ReadCertificateSubjectNameDelegate ReadSubjectName);


    /// <summary>Resolves the named X.509 backend's delegate set.</summary>
    /// <param name="backendName">The backend name, <c>"Microsoft"</c> or <c>"BouncyCastle"</c>.</param>
    /// <returns>The backend delegate set.</returns>
    private static X509Backend ResolveBackend(string backendName) => backendName switch
    {
        "Microsoft" => new X509Backend(
            MicrosoftX509Functions.ParseX5c,
            MicrosoftX509Functions.GetAuthorityKeyIdentifier,
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName),
        "BouncyCastle" => new X509Backend(
            BouncyCastleX509Functions.ParseX5c,
            BouncyCastleX509Functions.GetAuthorityKeyIdentifier,
            BouncyCastleX509Functions.GetSubjectKeyIdentifier,
            BouncyCastleX509Functions.GetSubjectName),
        _ => throw new ArgumentOutOfRangeException(nameof(backendName), backendName, "Unknown X.509 backend.")
    };


    /// <summary>
    /// A mutable tally of the OpenID Federation fetch delegates' invocations, shared into a resolver's
    /// closures so a test can assert zero fetches for the Section 15.10 privacy invariant.
    /// </summary>
    private sealed class FetchInvocationCounter
    {
        /// <summary>The number of Entity Configuration fetches.</summary>
        public int EntityConfigurationFetches { get; set; }

        /// <summary>The number of Subordinate Statement fetches.</summary>
        public int SubordinateStatementFetches { get; set; }
    }
}

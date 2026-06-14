using System.Buffers;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="CompositeClientIdSigningKeyResolver"/> demonstrating
/// the unified delegate dispatches correctly across the prefixes the
/// library ships handler factories for: <c>x509_san_dns:</c> and
/// <c>openid_federation:</c>. Each test mints a real JAR via the
/// appropriate test ring and exercises the full composite path.
/// </summary>
[TestClass]
internal sealed class CompositeClientIdSigningKeyResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer JwtPayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);

    private const string VerifierClientId = "https://verifier.example.com";


    [TestMethod]
    public async Task CompositeDispatchesOpenIdFederationPrefix()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        //Build a federation chain.
        using Federation.FederationTestRingNode verifierNode =
            Federation.FederationTestRing.CreateNode(new EntityIdentifier(VerifierClientId));
        using Federation.FederationTestRingNode anchorNode =
            Federation.FederationTestRing.CreateNode(new EntityIdentifier("https://anchor.example.com"));
        Federation.MintedChain mintedChain =
            await Federation.FederationTestRing.BuildDirectChainAsync(
                verifierNode, anchorNode, now, now.AddHours(1),
                TestContext.CancellationToken).ConfigureAwait(false);

        //Compose a JAR.
        string clientIdWithPrefix = $"{WellKnownClientIdPrefixes.OpenIdFederation}:{VerifierClientId}";
        string compactJar = await BuildFederationBoundJarAsync(
            verifierNode, clientIdWithPrefix, mintedChain.CompactJwsByPosition, now,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Compose a composite resolver with only the openid_federation handler.
        ValidateTrustChainAsyncDelegate validateChain =
            Federation.InlineTrustChainValidationDriver.Build(
                async (position, jws, ct) => position switch
                {
                    0 => await Federation.FederationTestRing.VerifyAsync(verifierNode, jws, ct).ConfigureAwait(false),
                    _ => await Federation.FederationTestRing.VerifyAsync(anchorNode, jws, ct).ConfigureAwait(false),
                });

        ResolveClientIdSigningKeyAsyncDelegate composite = CompositeClientIdSigningKeyResolver.Build(
            new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>
            {
                [WellKnownClientIdPrefixes.OpenIdFederation] =
                    CompositeClientIdSigningKeyResolver.BuildOpenIdFederationHandler(
                        TimeSpan.FromMinutes(5),
                        validateChain,
                        Decoder,
                        Pool),
            });

        UnverifiedJwtHeader jarHeader = ParseHeader(compactJar);
        ExchangeContext context = new();
        context.SetOpenIdFederationTrustAnchors([anchorNode.Identifier]);
        context.SetValidationTime(now);
        using PublicKeyMemory key = await composite(
            context, clientIdWithPrefix, jarHeader, TestContext.CancellationToken).ConfigureAwait(false);

        //The resolved key must verify the JAR.
        bool isVerified = await Jws.VerifyAsync(
            compactJar, Decoder,
            static (ReadOnlySpan<byte> _) => (object?)null,
            Pool, key, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isVerified, "Resolved Federation-bound key must verify the JAR.");
    }


    [TestMethod]
    public async Task CompositeDispatchesX509SanDnsPrefix()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateP256ChainMaterial(TimeProvider);

        string clientIdWithPrefix = $"{WellKnownClientIdPrefixes.X509SanDns}:{chain.DnsName}";
        string leafBase64 = Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlyMemory().ToArray());
        string caBase64 = Convert.ToBase64String(chain.CaDerBytes.AsReadOnlyMemory().ToArray());
        string[] x5cValues = [leafBase64, caBase64];

        IReadOnlyList<PkiCertificateMemory> trustAnchors =
            MicrosoftX509Functions.ParseX5c([caBase64], Pool);
        try
        {
            VerifierClientMetadata clientMetadata =
                HaipProfile.CreateVerifierClientMetadata(clientIdWithPrefix,
                    /*lang=json,strict*/ "{\"keys\":[]}");

            AuthorizationRequestObject requestObject =
                HaipProfile.CreateAuthorizationRequestObject(
                    clientId: clientIdWithPrefix,
                    responseUri: new Uri("https://verifier.example.com/cb"),
                    nonce: "nonce-composite-x509",
                    dcqlQuery: BuildPidDcqlQuery(),
                    clientMetadata: clientMetadata,
                    state: "state-composite-x509",
                    iat: now,
                    nbf: now,
                    exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

            using SignedJar signedJar = await requestObject.SignJarAsync(
                signingKey: chain.LeafSigningKey,
                headerSerializer: JwtHeaderSerializer,
                payloadSerializer: JwtPayloadSerializer,
                dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
                clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
                base64UrlEncoder: Encoder,
                memoryPool: Pool,
                additionalHeaderClaims: new Dictionary<string, object>
                {
                    [WellKnownJwkMemberNames.X5c] = x5cValues,
                },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            string compactJar = JwsSerialization.SerializeCompact(signedJar.Message, Encoder);

            ResolveClientIdSigningKeyAsyncDelegate composite = CompositeClientIdSigningKeyResolver.Build(
                new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>
                {
                    [WellKnownClientIdPrefixes.X509SanDns] =
                        CompositeClientIdSigningKeyResolver.BuildX509SanDnsHandler(
                            MicrosoftX509Functions.ParseX5c,
                            MicrosoftX509Functions.ValidateChainAsync,
                            MicrosoftX509Functions.VerifyDnsSan,
                            Pool),
                });

            UnverifiedJwtHeader jarHeader = ParseHeader(compactJar);
            ExchangeContext context = new();
            context.SetX509TrustAnchors(trustAnchors);
            context.SetValidationTime(now);
            using PublicKeyMemory key = await composite(
                context, clientIdWithPrefix, jarHeader, TestContext.CancellationToken).ConfigureAwait(false);

            bool isVerified = await Jws.VerifyAsync(
                compactJar, Decoder,
                static (ReadOnlySpan<byte> _) => (object?)null,
                Pool, key, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isVerified, "Resolved X.509-bound key must verify the JAR.");
        }
        finally
        {
            foreach(PkiCertificateMemory anchor in trustAnchors)
            {
                anchor.Dispose();
            }
        }
    }


    [TestMethod]
    public async Task CompositeDispatchesVerifierAttestationPrefix()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        //Trust anchor + verifier signing keys via the project's test key-material
        //facility (fresh keypairs for the wrong-key negative).
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> trustAnchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory trustAnchorPublicKey = trustAnchorKeys.PublicKey;
        using PrivateKeyMemory trustAnchorPrivateKey = trustAnchorKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierSigningKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory verifierSigningPublicKey = verifierSigningKeys.PublicKey;
        using PrivateKeyMemory verifierSigningPrivateKey = verifierSigningKeys.PrivateKey;

        string clientIdWithPrefix = $"{WellKnownClientIdPrefixes.VerifierAttestation}:{VerifierClientId}";
        string clientIdWithoutPrefix = WellKnownClientIdPrefixes.StripPrefix(clientIdWithPrefix);

        //Trust anchor signs an attestation about the verifier with cnf = verifier signing key.
        string attestationCompactJwt = await VerifierAttestationIssuer.BuildAsync(
            issuer: "https://trust-anchor.example.com",
            subject: clientIdWithoutPrefix,
            verifierSigningPublicKey: verifierSigningPublicKey,
            trustAnchorPrivateKey: trustAnchorPrivateKey,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            headerSerializer: JwtHeaderSerializer,
            payloadSerializer: JwtPayloadSerializer,
            base64UrlEncoder: Encoder,
            jwkConverter: static key => CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
                key.Tag.Get<CryptoAlgorithm>(),
                key.Tag.Get<Purpose>(),
                key.AsReadOnlySpan(),
                TestSetup.Base64UrlEncoder),
            pool: Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(clientIdWithPrefix, /*lang=json,strict*/ "{\"keys\":[]}");

        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: clientIdWithPrefix,
                responseUri: new Uri("https://verifier.example.com/cb"),
                nonce: "nonce-composite-att",
                dcqlQuery: BuildPidDcqlQuery(),
                clientMetadata: clientMetadata,
                state: "state-composite-att",
                iat: now,
                nbf: now,
                exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

        using SignedJar signedJar = await requestObject.SignJarAsync(
            signingKey: verifierSigningPrivateKey,
            headerSerializer: JwtHeaderSerializer,
            payloadSerializer: JwtPayloadSerializer,
            dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: Encoder,
            memoryPool: Pool,
            additionalHeaderClaims: new Dictionary<string, object>
            {
                [WellKnownJoseHeaderNames.Jwt] = attestationCompactJwt,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = JwsSerialization.SerializeCompact(signedJar.Message, Encoder);

        //Compose a composite resolver with only the verifier_attestation handler.
        ResolveClientIdSigningKeyAsyncDelegate composite = CompositeClientIdSigningKeyResolver.Build(
            new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>
            {
                [WellKnownClientIdPrefixes.VerifierAttestation] =
                    CompositeClientIdSigningKeyResolver.BuildVerifierAttestationHandler(
                        Decoder,
                        bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                            bytes, TestSetup.DefaultSerializationOptions)!,
                        bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                            bytes, TestSetup.DefaultSerializationOptions)!,
                        Pool),
            });

        UnverifiedJwtHeader jarHeader = ParseHeader(compactJar);
        ExchangeContext context = new();
        context.SetVerifierAttestationTrustAnchorKey(trustAnchorPublicKey);
        context.SetValidationTime(now);
        using PublicKeyMemory key = await composite(
            context, clientIdWithPrefix, jarHeader, TestContext.CancellationToken).ConfigureAwait(false);

        bool isVerified = await Jws.VerifyAsync(
            compactJar, Decoder,
            static (ReadOnlySpan<byte> _) => (object?)null,
            Pool, key, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isVerified, "Resolved verifier-attestation key must verify the JAR.");
    }


    [TestMethod]
    public async Task CompositeRejectsUnknownPrefix()
    {
        ResolveClientIdSigningKeyAsyncDelegate composite = CompositeClientIdSigningKeyResolver.Build(
            new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>
            {
                [WellKnownClientIdPrefixes.OpenIdFederation] =
                    (ctx, id, hdr, ct) => throw new InvalidOperationException(
                        "Should not be reached — different prefix in test."),
            });

        UnverifiedJwtHeader emptyHeader = new();
        await Assert.ThrowsExactlyAsync<SecurityException>(
            async () => await composite(
                new ExchangeContext(),
                "x509_san_dns:verifier.example.com",
                emptyHeader,
                TestContext.CancellationToken).ConfigureAwait(false));
    }


    [TestMethod]
    public async Task CompositeRejectsClientIdWithoutPrefix()
    {
        ResolveClientIdSigningKeyAsyncDelegate composite = CompositeClientIdSigningKeyResolver.Build(
            new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>());

        UnverifiedJwtHeader emptyHeader = new();
        await Assert.ThrowsExactlyAsync<SecurityException>(
            async () => await composite(
                new ExchangeContext(),
                "verifier.example.com",  //no prefix
                emptyHeader,
                TestContext.CancellationToken).ConfigureAwait(false));
    }


    private static UnverifiedJwtHeader ParseHeader(string compactJar)
    {
        using UnverifiedJwsMessage unverified = JwsParsing.ParseCompact(
            compactJar,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            Pool);
        //The header dictionary survives Dispose because UnverifiedJwtHeader holds
        //its own dictionary; the wrapper around it doesn't depend on the JWS message.
        return new UnverifiedJwtHeader(unverified.Signatures[0].ProtectedHeader);
    }


    private static async Task<string> BuildFederationBoundJarAsync(
        Federation.FederationTestRingNode verifierNode,
        string clientIdWithPrefix,
        IReadOnlyList<string> trustChainCompactJws,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        System.Security.Cryptography.ECParameters ecParameters =
            verifierNode.SigningKey.ExportParameters(includePrivateParameters: true);
        IMemoryOwner<byte> privateOwner = Pool.Rent(ecParameters.D!.Length);
        ecParameters.D.CopyTo(privateOwner.Memory.Span);
        using PrivateKeyMemory verifierPrivateKey = new(privateOwner, CryptoTags.P256PrivateKey);

        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(clientIdWithPrefix,
                /*lang=json,strict*/ "{\"keys\":[]}");

        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: clientIdWithPrefix,
                responseUri: new Uri("https://verifier.example.com/cb"),
                nonce: "nonce-composite-fed",
                dcqlQuery: BuildPidDcqlQuery(),
                clientMetadata: clientMetadata,
                state: "state-composite-fed",
                iat: now,
                nbf: now,
                exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

        List<object> chainHeader = [.. trustChainCompactJws];

        using SignedJar signedJar = await requestObject.SignJarAsync(
            signingKey: verifierPrivateKey,
            headerSerializer: JwtHeaderSerializer,
            payloadSerializer: JwtPayloadSerializer,
            dcqlQuerySerializer: q => JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
            clientMetadataSerializer: m => JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: Encoder,
            memoryPool: Pool,
            additionalHeaderClaims: new Dictionary<string, object>
            {
                [WellKnownFederationClaimNames.TrustChain] = chainHeader,
            },
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(signedJar.Message, Encoder);
    }


    private static DcqlQuery BuildPidDcqlQuery() =>
        new()
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                    Claims =
                    [
                        ClaimsQuery.ForPath(["given_name"]),
                        ClaimsQuery.ForPath(["family_name"])
                    ]
                }
            ]
        };
}

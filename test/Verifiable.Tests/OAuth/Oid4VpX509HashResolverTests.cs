using System.Buffers;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the <c>x509_hash:</c> Verifier-key resolution path per OID4VP 1.0 §5.9.3
/// (the <c>client_id</c> is the base64url SHA-256 hash of the DER-encoded leaf
/// certificate carried in <c>x5c</c>) and the additional HAIP 1.0 §5.2 constraints
/// for a signed request: the request-signing certificate MUST NOT be self-signed,
/// and the trust anchor MUST NOT appear in <c>x5c</c>.
/// </summary>
/// <remarks>
/// Each gate is isolated: the resolver checks self-signed first, then trust-anchor
/// exclusion, then chain validity, then the hash binding — so each negative test
/// drives exactly the gate it names while the others pass. As with
/// <see cref="Oid4VpX509SanDnsResolverTests"/>, one stateless resolver reads the
/// trust anchors per-call from the <see cref="ExchangeContext"/>, never captured.
/// </remarks>
[TestClass]
internal sealed class Oid4VpX509HashResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider Time { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer JwtPayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task ResolvedKeyVerifiesTheJar()
    {
        DateTimeOffset now = Time.GetUtcNow();

        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("hash-verifier.example.com", Time);

        string clientId = $"{WellKnownClientIdPrefixes.X509Hash}:{LeafHash(chain)}";
        string compactJar = await BuildX509HashJarAsync(chain.LeafSigningKey, clientId, LeafX5c(chain), now).ConfigureAwait(false);
        UnverifiedJwtHeader jarHeader = ParseHeader(compactJar);

        ResolveClientIdSigningKeyAsyncDelegate resolver = BuildX509HashComposite();
        IReadOnlyList<PkiCertificateMemory> anchors = ParseAnchor(chain);
        try
        {
            ExchangeContext context = new();
            context.SetX509TrustAnchors(anchors);
            context.SetValidationTime(now);

            using PublicKeyMemory key = await resolver(
                context, clientId, jarHeader, TestContext.CancellationToken).ConfigureAwait(false);

            bool verified = await Jws.VerifyAsync(
                compactJar, Decoder,
                static (ReadOnlySpan<byte> _) => (object?)null,
                Pool, key, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(verified,
                "The key resolved from the x5c leaf bound by hash must verify the JAR it signed.");
        }
        finally
        {
            DisposeAll(anchors);
        }
    }


    [TestMethod]
    public async Task WrongCertificateHashIsRejected()
    {
        DateTimeOffset now = Time.GetUtcNow();

        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("real.example.com", Time);

        //The JAR is correctly signed and chains to the trusted anchor, but the
        //client_id asserts a hash the leaf certificate does not produce. The hash
        //binding is the whole point of the prefix, so this must fail (OID4VP §5.9.3).
        string spoofedClientId =
            $"{WellKnownClientIdPrefixes.X509Hash}:{TestSetup.Base64UrlEncoder(SHA256.HashData("not-the-leaf"u8))}";
        string compactJar = await BuildX509HashJarAsync(chain.LeafSigningKey, spoofedClientId, LeafX5c(chain), now).ConfigureAwait(false);
        UnverifiedJwtHeader jarHeader = ParseHeader(compactJar);

        ResolveClientIdSigningKeyAsyncDelegate resolver = BuildX509HashComposite();
        IReadOnlyList<PkiCertificateMemory> anchors = ParseAnchor(chain);
        try
        {
            ExchangeContext context = new();
            context.SetX509TrustAnchors(anchors);
            context.SetValidationTime(now);

            await Assert.ThrowsExactlyAsync<SecurityException>(
                async () => await resolver(
                    context, spoofedClientId, jarHeader, TestContext.CancellationToken).ConfigureAwait(false));
        }
        finally
        {
            DisposeAll(anchors);
        }
    }


    [TestMethod]
    public async Task TrustAnchorPresentInX5cIsRejected()
    {
        DateTimeOffset now = Time.GetUtcNow();

        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("anchor-in-x5c.example.com", Time);

        //HAIP 1.0 §5.2: the trust anchor MUST NOT be carried in x5c. Here the chain
        //is otherwise valid and the hash matches the leaf, but the CA (the anchor)
        //is included as the second x5c entry — that alone must be rejected.
        string clientId = $"{WellKnownClientIdPrefixes.X509Hash}:{LeafHash(chain)}";
        string leafBase64 = Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlyMemory().ToArray());
        string caBase64 = Convert.ToBase64String(chain.CaDerBytes.AsReadOnlyMemory().ToArray());
        string compactJar = await BuildX509HashJarAsync(chain.LeafSigningKey, clientId, [leafBase64, caBase64], now).ConfigureAwait(false);
        UnverifiedJwtHeader jarHeader = ParseHeader(compactJar);

        ResolveClientIdSigningKeyAsyncDelegate resolver = BuildX509HashComposite();
        IReadOnlyList<PkiCertificateMemory> anchors = ParseAnchor(chain);
        try
        {
            ExchangeContext context = new();
            context.SetX509TrustAnchors(anchors);
            context.SetValidationTime(now);

            await Assert.ThrowsExactlyAsync<SecurityException>(
                async () => await resolver(
                    context, clientId, jarHeader, TestContext.CancellationToken).ConfigureAwait(false));
        }
        finally
        {
            DisposeAll(anchors);
        }
    }


    [TestMethod]
    public async Task SelfSignedSigningCertificateIsRejected()
    {
        DateTimeOffset now = Time.GetUtcNow();

        //The self-signed certificate used as the request signer is the (self-signed)
        //CA of one chain; the trust anchor on the context is a DIFFERENT chain's CA,
        //so the anchor-exclusion gate passes and the self-signed gate is what fires
        //(HAIP 1.0 §5.2). Resolution rejects before any signature verification.
        using CertificateChainMaterial signer =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("self-signed.example.com", Time);
        using CertificateChainMaterial anchorChain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("anchor.example.com", Time);

        string selfSignedBase64 = Convert.ToBase64String(signer.CaDerBytes.AsReadOnlyMemory().ToArray());
        string clientId = $"{WellKnownClientIdPrefixes.X509Hash}:" +
            $"{TestSetup.Base64UrlEncoder(SHA256.HashData(signer.CaDerBytes.AsReadOnlyMemory().Span))}";
        UnverifiedJwtHeader jarHeader = new()
        {
            [WellKnownJwkMemberNames.X5c] = new[] { selfSignedBase64 }
        };

        ResolveClientIdSigningKeyAsyncDelegate resolver = BuildX509HashComposite();
        IReadOnlyList<PkiCertificateMemory> anchors = ParseAnchor(anchorChain);
        try
        {
            ExchangeContext context = new();
            context.SetX509TrustAnchors(anchors);
            context.SetValidationTime(now);

            await Assert.ThrowsExactlyAsync<SecurityException>(
                async () => await resolver(
                    context, clientId, jarHeader, TestContext.CancellationToken).ConfigureAwait(false));
        }
        finally
        {
            DisposeAll(anchors);
        }
    }


    [TestMethod]
    public async Task ChainWithIntermediateValidatesWhenTrustAnchorExcludedFromX5c()
    {
        DateTimeOffset now = Time.GetUtcNow();

        //The realistic HAIP deployment shape: a three-level chain (Root → Intermediate
        //→ Leaf) where x5c carries the leaf AND the intermediate, but NOT the root —
        //the root is the trust anchor, supplied out-of-band (HAIP 1.0 §5.2). This proves
        //the anchor-exclusion gate rejects only the anchor itself, not legitimate
        //intermediates, and that chain validation traverses the intermediate.
        using X509ChainTestRingChain chain =
            X509ChainTestRing.BuildThreeLevelChain("intermediate-verifier.example.com", Time);

        string leafBase64 = Convert.ToBase64String(chain.Leaf.Certificate.RawData);
        string intermediateBase64 = Convert.ToBase64String(chain.Intermediate.Certificate.RawData);
        string[] x5c = [leafBase64, intermediateBase64];

        string leafHash = TestSetup.Base64UrlEncoder(SHA256.HashData(chain.Leaf.Certificate.RawData));
        string clientId = $"{WellKnownClientIdPrefixes.X509Hash}:{leafHash}";

        using PrivateKeyMemory leafKey = RingLeafSigningKey(chain.Leaf);
        string compactJar = await BuildX509HashJarAsync(leafKey, clientId, x5c, now).ConfigureAwait(false);
        UnverifiedJwtHeader jarHeader = ParseHeader(compactJar);

        ResolveClientIdSigningKeyAsyncDelegate resolver = BuildX509HashComposite();
        //The trust anchor is the root alone — it is NOT present in x5c.
        IReadOnlyList<PkiCertificateMemory> anchors =
            MicrosoftX509Functions.ParseX5c(chain.RootX5c, Pool);
        try
        {
            ExchangeContext context = new();
            context.SetX509TrustAnchors(anchors);
            context.SetValidationTime(now);

            using PublicKeyMemory key = await resolver(
                context, clientId, jarHeader, TestContext.CancellationToken).ConfigureAwait(false);

            bool verified = await Jws.VerifyAsync(
                compactJar, Decoder,
                static (ReadOnlySpan<byte> _) => (object?)null,
                Pool, key, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(verified,
                "A leaf chaining through an intermediate to the out-of-band root anchor must resolve " +
                "and verify, with the anchor excluded from x5c (HAIP 1.0 §5.2).");
        }
        finally
        {
            DisposeAll(anchors);
        }
    }


    [TestMethod]
    public async Task MissingTrustAnchorsOnContextFailsClosed()
    {
        DateTimeOffset now = Time.GetUtcNow();

        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("verifier.example.com", Time);

        string clientId = $"{WellKnownClientIdPrefixes.X509Hash}:{LeafHash(chain)}";
        string compactJar = await BuildX509HashJarAsync(chain.LeafSigningKey, clientId, LeafX5c(chain), now).ConfigureAwait(false);
        UnverifiedJwtHeader jarHeader = ParseHeader(compactJar);

        ResolveClientIdSigningKeyAsyncDelegate resolver = BuildX509HashComposite();

        //An application that forgot to place the tenant's trust anchors on the
        //context must NOT silently resolve — the handler fails closed.
        ExchangeContext context = new();
        context.SetValidationTime(now);

        await Assert.ThrowsExactlyAsync<SecurityException>(
            async () => await resolver(
                context, clientId, jarHeader, TestContext.CancellationToken).ConfigureAwait(false));
    }


    //One stateless composite resolver: the x509_hash handler captures only the
    //deployment-stable cert/hash/encoder delegates and the pool — never trust anchors.
    private static ResolveClientIdSigningKeyAsyncDelegate BuildX509HashComposite() =>
        CompositeClientIdSigningKeyResolver.Build(
            new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>
            {
                [WellKnownClientIdPrefixes.X509Hash] =
                    CompositeClientIdSigningKeyResolver.BuildX509HashHandler(
                        MicrosoftX509Functions.ParseX5c,
                        MicrosoftX509Functions.ValidateChainAsync,
                        MicrosoftX509Functions.IsSelfSigned,
                        SHA256.HashData,
                        TestSetup.Base64UrlEncoder,
                        Pool),
            });


    private static string LeafHash(CertificateChainMaterial chain) =>
        TestSetup.Base64UrlEncoder(SHA256.HashData(chain.LeafDerBytes.AsReadOnlyMemory().Span));


    private static string[] LeafX5c(CertificateChainMaterial chain) =>
        [Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlyMemory().ToArray())];


    //Materialises the ring leaf's ECDsa private key as a pooled PrivateKeyMemory
    //(the bare P-256 D scalar the library's signing functions expect), so a JAR can
    //be signed under the leaf whose public key the resolver extracts from x5c.
    private static PrivateKeyMemory RingLeafSigningKey(X509ChainTestRingNode leaf)
    {
        byte[] d = leaf.SigningKey.ExportParameters(includePrivateParameters: true).D!;
        IMemoryOwner<byte> owner = Pool.Rent(d.Length);
        d.CopyTo(owner.Memory.Span);

        return new PrivateKeyMemory(owner, CryptoTags.P256PrivateKey);
    }


    //Mints a JAR signed by the supplied leaf key, carrying the given x5c values in
    //the JOSE header. Callers control x5c composition so each test drives the gate
    //it names (leaf alone, leaf+anchor, leaf+intermediate, ...).
    private async Task<string> BuildX509HashJarAsync(
        PrivateKeyMemory signingKey,
        string clientIdWithPrefix,
        string[] x5cValues,
        DateTimeOffset now)
    {
        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(clientIdWithPrefix, "{\"keys\":[]}");

        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: clientIdWithPrefix,
                responseUri: new Uri("https://verifier.example.com/cb"),
                nonce: "nonce-x509-hash-resolver",
                dcqlQuery: BuildPidDcqlQuery(),
                clientMetadata: clientMetadata,
                state: "state-x509-hash-resolver",
                iat: now,
                nbf: now,
                exp: now + TimingPolicy.Default.Oid4VpRequestObjectLifetime);

        using SignedJar signedJar = await requestObject.SignJarAsync(
            signingKey: signingKey,
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

        return JwsSerialization.SerializeCompact(signedJar.Message, Encoder);
    }


    private static IReadOnlyList<PkiCertificateMemory> ParseAnchor(CertificateChainMaterial chain) =>
        MicrosoftX509Functions.ParseX5c(
            [Convert.ToBase64String(chain.CaDerBytes.AsReadOnlyMemory().ToArray())], Pool);


    private static void DisposeAll(IReadOnlyList<PkiCertificateMemory> anchors)
    {
        foreach(PkiCertificateMemory anchor in anchors)
        {
            anchor.Dispose();
        }
    }


    private static UnverifiedJwtHeader ParseHeader(string compactJar)
    {
        using UnverifiedJwsMessage unverified = JwsParsing.ParseCompact(
            compactJar,
            Decoder,
            bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)!,
            Pool);

        return new UnverifiedJwtHeader(unverified.Signatures[0].ProtectedHeader);
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

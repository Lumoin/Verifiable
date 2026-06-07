using System.Buffers;
using System.Security;
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

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests the <c>x509_san_dns:</c> Verifier-key resolution path that unblocks
/// integration against external OID4VP sandboxes (for example the French
/// iDAKTO playground): the wallet resolves the JAR signing key from the
/// <c>x5c</c> chain bound to the leaf's DNS SAN, evaluating it against the
/// current tenant's trust anchors carried on the threaded
/// <see cref="ExchangeContext"/> rather than a captured/pinned key.
/// </summary>
/// <remarks>
/// These exercise the architectural heart of the neutral-context change: a
/// single <em>stateless</em> <see cref="ResolveClientIdSigningKeyAsyncDelegate"/>
/// serves every tenant because the per-operation context — not a closure —
/// supplies the trust material. That is what makes the recursive multi-tenant
/// SaaS shape work, and it is verified directly below.
/// </remarks>
[TestClass]
internal sealed class Oid4VpX509SanDnsResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider Time { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;
    private static EncodeDelegate Encoder => TestSetup.Base64UrlEncoder;
    private static DecodeDelegate Decoder => TestSetup.Base64UrlDecoder;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer JwtPayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task OneStatelessResolverServesTwoTenantsViaContext()
    {
        DateTimeOffset now = Time.GetUtcNow();

        using CertificateChainMaterial tenantA =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("tenant-a.example.com", Time);
        using CertificateChainMaterial tenantB =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("tenant-b.example.com", Time);

        string clientIdA = $"{WellKnownClientIdPrefixes.X509SanDns}:{tenantA.DnsName}";
        string compactJarA = await BuildX509JarAsync(tenantA, clientIdA, now).ConfigureAwait(false);
        UnverifiedJwtHeader jarHeaderA = ParseHeader(compactJarA);

        //One resolver instance, registered once, with NO captured trust anchors.
        ResolveClientIdSigningKeyAsyncDelegate resolver = BuildX509Composite();

        IReadOnlyList<PkiCertificateMemory> anchorsA = ParseAnchor(tenantA);
        IReadOnlyList<PkiCertificateMemory> anchorsB = ParseAnchor(tenantB);
        try
        {
            //Tenant A's operation carries tenant A's anchors on the context — the
            //same stateless resolver resolves and the key verifies A's JAR.
            ExchangeContext contextA = new();
            contextA.SetX509TrustAnchors(anchorsA);
            contextA.SetValidationTime(now);

            using(PublicKeyMemory keyForA = await resolver(
                contextA, clientIdA, jarHeaderA, TestContext.CancellationToken).ConfigureAwait(false))
            {
                bool verified = await Jws.VerifyAsync(
                    compactJarA, Decoder,
                    static (ReadOnlySpan<byte> _) => (object?)null,
                    Pool, keyForA, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(verified,
                    "The key resolved against tenant A's context must verify tenant A's JAR.");
            }

            //The very same resolver, handed tenant B's anchors on the context,
            //cannot validate tenant A's chain — proving the trust material is read
            //per-call from the context, never captured. No cross-tenant leakage.
            ExchangeContext contextB = new();
            contextB.SetX509TrustAnchors(anchorsB);
            contextB.SetValidationTime(now);

            await Assert.ThrowsExactlyAsync<SecurityException>(
                async () => await resolver(
                    contextB, clientIdA, jarHeaderA, TestContext.CancellationToken).ConfigureAwait(false));
        }
        finally
        {
            DisposeAll(anchorsA);
            DisposeAll(anchorsB);
        }
    }


    [TestMethod]
    public async Task X509SanMismatchIsRejected()
    {
        DateTimeOffset now = Time.GetUtcNow();

        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("real.example.com", Time);

        //The JAR is correctly signed and chains to a trusted anchor, but the
        //client_id asserts a DNS name the leaf certificate's SAN does not carry.
        //The DNS-SAN binding is the whole point of the prefix, so this must fail.
        string spoofedClientId = $"{WellKnownClientIdPrefixes.X509SanDns}:attacker.example.com";
        string compactJar = await BuildX509JarAsync(chain, spoofedClientId, now).ConfigureAwait(false);
        UnverifiedJwtHeader jarHeader = ParseHeader(compactJar);

        ResolveClientIdSigningKeyAsyncDelegate resolver = BuildX509Composite();
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
    public async Task MissingTrustAnchorsOnContextFailsClosed()
    {
        DateTimeOffset now = Time.GetUtcNow();

        using CertificateChainMaterial chain =
            TestCertificateChainProvider.CreateFreshP256ChainMaterial("verifier.example.com", Time);

        string clientId = $"{WellKnownClientIdPrefixes.X509SanDns}:{chain.DnsName}";
        string compactJar = await BuildX509JarAsync(chain, clientId, now).ConfigureAwait(false);
        UnverifiedJwtHeader jarHeader = ParseHeader(compactJar);

        ResolveClientIdSigningKeyAsyncDelegate resolver = BuildX509Composite();

        //An application that forgot to place the tenant's trust anchors on the
        //context must NOT silently resolve — the handler fails closed.
        ExchangeContext context = new();
        context.SetValidationTime(now);

        await Assert.ThrowsExactlyAsync<SecurityException>(
            async () => await resolver(
                context, clientId, jarHeader, TestContext.CancellationToken).ConfigureAwait(false));
    }


    //One stateless composite resolver: the x509_san_dns handler captures only the
    //deployment-stable cert algorithm delegates and the pool — never trust anchors.
    private static ResolveClientIdSigningKeyAsyncDelegate BuildX509Composite() =>
        CompositeClientIdSigningKeyResolver.Build(
            new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>
            {
                [WellKnownClientIdPrefixes.X509SanDns] =
                    CompositeClientIdSigningKeyResolver.BuildX509SanDnsHandler(
                        MicrosoftX509Functions.ParseX5c,
                        MicrosoftX509Functions.ValidateChainAsync,
                        MicrosoftX509Functions.VerifyDnsSan,
                        Pool),
            });


    //Mints a JAR signed by the chain's leaf key, carrying the [leaf, ca] x5c
    //chain in the JOSE header, exactly as an x509_san_dns: Verifier would serve it.
    private async Task<string> BuildX509JarAsync(
        CertificateChainMaterial chain,
        string clientIdWithPrefix,
        DateTimeOffset now)
    {
        string leafBase64 = Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlyMemory().ToArray());
        string caBase64 = Convert.ToBase64String(chain.CaDerBytes.AsReadOnlyMemory().ToArray());
        string[] x5cValues = [leafBase64, caBase64];

        VerifierClientMetadata clientMetadata =
            HaipProfile.CreateVerifierClientMetadata(clientIdWithPrefix, /*lang=json,strict*/ "{\"keys\":[]}");

        AuthorizationRequestObject requestObject =
            HaipProfile.CreateAuthorizationRequestObject(
                clientId: clientIdWithPrefix,
                responseUri: new Uri("https://verifier.example.com/cb"),
                nonce: "nonce-x509-resolver",
                dcqlQuery: BuildPidDcqlQuery(),
                clientMetadata: clientMetadata,
                state: "state-x509-resolver",
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

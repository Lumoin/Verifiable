using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.Tests.Federation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The four OID4VP <c>client_id</c> schemes expressed as shared
/// <see cref="SchemeFixture"/> data: each mints the per-run
/// <see cref="SchemeMaterial"/> (the verifier's JAR-signing key, the JAR header
/// carrying the scheme's material, the per-prefix key resolver, and the trust
/// material the application places on the <see cref="ExchangeContext"/>). The
/// single source shared by the scheme × format matrix
/// (<see cref="Oid4VpSchemeFormatMatrixTests"/>) and any other flow that drives a
/// scheme-signed JAR (e.g. the x509 + <c>request_uri_method=post</c> HTTP e2e).
/// </summary>
internal static class Oid4VpSchemeFixtures
{
    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static readonly JwtHeaderSerializer JwtHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer JwtPayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>x509_san_dns: the AS signs the JAR with the leaf cert key, advertised in the x5c header.</summary>
    public static SchemeFixture X509 => new("x509_san_dns", CreateX509SchemeAsync);

    /// <summary>x509_hash: the client_id is the base64url SHA-256 hash of the leaf cert; x5c carries the leaf only (HAIP 1.0 §5.2 excludes the trust anchor).</summary>
    public static SchemeFixture X509Hash => new("x509_hash", CreateX509HashSchemeAsync);

    /// <summary>verifier_attestation: a trust-anchor-issued attestation binds the verifier's JAR-signing key in its cnf.</summary>
    public static SchemeFixture VerifierAttestation => new("verifier_attestation", CreateVerifierAttestationSchemeAsync);

    /// <summary>openid_federation: the JAR carries a trust chain whose chain[0].jwks holds the JAR-signing key.</summary>
    public static SchemeFixture OpenIdFederation => new("openid_federation", CreateOpenIdFederationSchemeAsync);

    /// <summary>decentralized_identifier: the JAR's kid is a did:key verification-method URL the wallet dereferences.</summary>
    public static SchemeFixture DecentralizedIdentifier => new("decentralized_identifier", CreateDecentralizedIdentifierSchemeAsync);


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of verifierSigningKeys transfers to RegisterJarSigningClient, which disposes it when the TestHostShell host is disposed.")]
    private static async ValueTask<SchemeMaterial> CreateVerifierAttestationSchemeAsync(
        FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        DateTimeOffset now = tp.GetUtcNow();

        string clientIdWithoutPrefix = "https://attested-verifier.example.com";
        string clientIdWithPrefix = $"{WellKnownClientIdPrefixes.VerifierAttestation}:{clientIdWithoutPrefix}";

        //Trust anchor that issues the attestation; the wallet validates the
        //attestation against its public key, read off the ExchangeContext.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> trustAnchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicKeyMemory trustAnchorPublicKey = trustAnchorKeys.PublicKey;
        using PrivateKeyMemory trustAnchorPrivateKey = trustAnchorKeys.PrivateKey;

        //The verifier's JAR-signing key, bound into the attestation's cnf.
        //Ownership transfers to the host via RegisterJarSigningClient.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierSigningKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        string attestationJwt = await VerifierAttestationIssuer.BuildAsync(
            issuer: "https://trust-anchor.example.com",
            subject: clientIdWithoutPrefix,
            verifierSigningPublicKey: verifierSigningKeys.PublicKey,
            trustAnchorPrivateKey: trustAnchorPrivateKey,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            headerSerializer: JwtHeaderSerializer,
            payloadSerializer: JwtPayloadSerializer,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            jwkConverter: static key => CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
                key.Tag.Get<CryptoAlgorithm>(), key.Tag.Get<Purpose>(),
                key.AsReadOnlySpan(), TestSetup.Base64UrlEncoder),
            pool: Pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        JwtHeader jarHeader = new() { [WellKnownJoseHeaderNames.Jwt] = attestationJwt };
        ResolveClientIdSigningKeyAsyncDelegate resolver = CompositeClientIdSigningKeyResolver.Build(
            new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>
            {
                [WellKnownClientIdPrefixes.VerifierAttestation] =
                    CompositeClientIdSigningKeyResolver.BuildVerifierAttestationHandler(
                        TestSetup.Base64UrlDecoder,
                        bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                            bytes, TestSetup.DefaultSerializationOptions)!,
                        bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                            bytes, TestSetup.DefaultSerializationOptions)!,
                        Pool),
            });

        return new SchemeMaterial
        {
            ClientId = clientIdWithPrefix,
            JarSigningKeyPair = verifierSigningKeys,
            JarHeader = jarHeader,
            Resolver = resolver,
            PlaceTrustMaterial = context => context.SetVerifierAttestationTrustAnchorKey(trustAnchorPublicKey),
            Owned = [trustAnchorPublicKey]
        };
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of vmKeys (the verification-method key pair) transfers to RegisterJarSigningClient, which disposes it when the TestHostShell host is disposed.")]
    private static async ValueTask<SchemeMaterial> CreateDecentralizedIdentifierSchemeAsync(
        FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        //The verification-method key pair. The did:key is derived from its public
        //side; the AS signs the JAR with its private side. Ownership transfers to
        //the host via RegisterJarSigningClient.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> vmKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Verifiable.Core.Model.Did.DidDocument didDocument =
            await new Verifiable.Core.Model.Did.KeyDidBuilder().BuildAsync(
                vmKeys.PublicKey,
                Verifiable.Core.Model.Did.CryptographicSuites.MultikeyVerificationMethodTypeInfo.Instance,
                includeDefaultContext: false,
                cancellationToken).ConfigureAwait(false);

        string didKeyId = didDocument.Id!.ToString()!;
        string verificationMethodId = didDocument.VerificationMethod![0].Id!;
        string clientIdWithPrefix = $"{WellKnownClientIdPrefixes.DecentralizedIdentifier}:{didKeyId}";

        Verifiable.Core.Resolvers.DidResolver didResolver = new(
            Verifiable.Core.Resolvers.DidMethodSelectors.FromResolvers(
                (Verifiable.Core.Model.Did.Methods.WellKnownDidMethodPrefixes.KeyDidMethodPrefix,
                 Verifiable.Core.Resolvers.KeyDidResolver.Build(Pool))));

        //The kid carries the absolute verification-method DID URL the JAR was
        //signed under; the handler dereferences it and checks it shares the
        //client_id's base DID.
        JwtHeader jarHeader = new() { [WellKnownJwkMemberNames.Kid] = verificationMethodId };
        ResolveClientIdSigningKeyAsyncDelegate resolver = CompositeClientIdSigningKeyResolver.Build(
            new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>
            {
                [WellKnownClientIdPrefixes.DecentralizedIdentifier] =
                    CompositeClientIdSigningKeyResolver.BuildDecentralizedIdentifierHandler(didResolver, Pool),
            });

        return new SchemeMaterial
        {
            ClientId = clientIdWithPrefix,
            JarSigningKeyPair = vmKeys,
            JarHeader = jarHeader,
            Resolver = resolver,
            PlaceTrustMaterial = static _ => { },
            Owned = []
        };
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of verifierSigningKeys transfers to RegisterJarSigningClient, which disposes it when the TestHostShell host is disposed.")]
    private static async ValueTask<SchemeMaterial> CreateOpenIdFederationSchemeAsync(
        FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        DateTimeOffset now = tp.GetUtcNow();

        string verifierEntityId = "https://federated-verifier.example.com";
        string anchorEntityId = "https://federation-anchor.example.com";
        string clientIdWithPrefix = $"{WellKnownClientIdPrefixes.OpenIdFederation}:{verifierEntityId}";

        //The verifier's JAR-signing key. CreateNodeFromKey publishes its public
        //side in the chain's chain[0].jwks, so the wallet's chain-validation
        //resolver yields the same key the AS signs the JAR with. Ownership of
        //the pair transfers to the host via RegisterJarSigningClient.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierSigningKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        FederationTestRingNode verifierNode = FederationTestRing.CreateNodeFromKey(
            new EntityIdentifier(verifierEntityId), verifierSigningKeys.PrivateKey);
        FederationTestRingNode anchorNode = FederationTestRing.CreateNode(new EntityIdentifier(anchorEntityId));

        MintedChain mintedChain = await FederationTestRing.BuildDirectChainAsync(
            verifierNode, anchorNode, now, now.AddHours(1), cancellationToken).ConfigureAwait(false);

        ValidateTrustChainAsyncDelegate validateChain = InlineTrustChainValidationDriver.Build(
            async (position, jws, ct) => position switch
            {
                0 => await FederationTestRing.VerifyAsync(verifierNode, jws, ct).ConfigureAwait(false),
                _ => await FederationTestRing.VerifyAsync(anchorNode, jws, ct).ConfigureAwait(false),
            });

        JwtHeader jarHeader = new()
        {
            [WellKnownFederationClaimNames.TrustChain] = new List<object>(mintedChain.CompactJwsByPosition),
        };
        ResolveClientIdSigningKeyAsyncDelegate resolver = CompositeClientIdSigningKeyResolver.Build(
            new Dictionary<ClientIdPrefix, ResolveClientIdSigningKeyAsyncDelegate>
            {
                [WellKnownClientIdPrefixes.OpenIdFederation] =
                    CompositeClientIdSigningKeyResolver.BuildOpenIdFederationHandler(
                        TimeSpan.FromMinutes(5), validateChain, TestSetup.Base64UrlDecoder, Pool),
            });

        return new SchemeMaterial
        {
            ClientId = clientIdWithPrefix,
            JarSigningKeyPair = verifierSigningKeys,
            JarHeader = jarHeader,
            Resolver = resolver,
            PlaceTrustMaterial = context => context.SetOpenIdFederationTrustAnchors([anchorNode.Identifier]),
            Owned = [verifierNode, anchorNode]
        };
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the leaf public key (from ValidateChain) and the copied leaf private key transfers to RegisterJarSigningClient, which disposes both when the TestHostShell host is disposed.")]
    private static async ValueTask<SchemeMaterial> CreateX509SchemeAsync(
        FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        DateTimeOffset now = tp.GetUtcNow();

        //An x509_san_dns: verifier. The AS signs its JAR with the leaf
        //certificate's key and advertises the chain in the x5c JOSE header; the
        //wallet must resolve that leaf key from x5c — NOT from a pinned key.
        CertificateChainMaterial chain = TestCertificateChainProvider.CreateP256ChainMaterial(tp);
        string clientIdWithPrefix = $"{WellKnownClientIdPrefixes.X509SanDns}:{chain.DnsName}";
        string leafBase64 = Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlyMemory().ToArray());
        string caBase64 = Convert.ToBase64String(chain.CaDerBytes.AsReadOnlyMemory().ToArray());
        string[] x5cValues = [leafBase64, caBase64];

        //CA trust anchors the WALLET evaluates the chain against, placed on the
        //per-operation ExchangeContext — read per-call by the stateless resolver,
        //never captured.
        IReadOnlyList<PkiCertificateMemory> walletTrustAnchors =
            MicrosoftX509Functions.ParseX5c([caBase64], Pool);

        //The AS's JAR-signing key IS the leaf key. ValidateChain yields the leaf
        //public key; the leaf private key is copied so the host and the chain
        //material own independent buffers. Ownership of both transfers to the host
        //via RegisterJarSigningClient.
        IReadOnlyList<PkiCertificateMemory> registrationChain =
            MicrosoftX509Functions.ParseX5c(x5cValues, Pool);
        PublicKeyMemory leafPublic;
        try
        {
            leafPublic = await MicrosoftX509Functions.ValidateChainAsync(
                registrationChain, walletTrustAnchors, now, Pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach(PkiCertificateMemory cert in registrationChain)
            {
                cert.Dispose();
            }
        }

        JwtHeader jarHeader = new() { [WellKnownJwkMemberNames.X5c] = x5cValues };
        ResolveClientIdSigningKeyAsyncDelegate resolver =
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

        SchemeMaterial material = new()
        {
            ClientId = clientIdWithPrefix,
            JarSigningKeyPair = new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(
                leafPublic, CopyPrivateKey(chain.LeafSigningKey)),
            JarHeader = jarHeader,
            Resolver = resolver,
            PlaceTrustMaterial = context => context.SetX509TrustAnchors(walletTrustAnchors),
            //The trust anchors must outlive PresentJarAsync (the resolver reads them
            //per call); the chain material owns the DER buffers the x5c was built from.
            Owned = [.. walletTrustAnchors, chain]
        };

        return material;
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the leaf public key (from ValidateChain) and the copied leaf private key transfers to RegisterJarSigningClient, which disposes both when the TestHostShell host is disposed.")]
    private static async ValueTask<SchemeMaterial> CreateX509HashSchemeAsync(
        FakeTimeProvider tp, CancellationToken cancellationToken)
    {
        DateTimeOffset now = tp.GetUtcNow();

        //An x509_hash: verifier. The client_id is the base64url-encoded SHA-256 hash
        //of the DER-encoded leaf certificate; the AS signs its JAR with the leaf key.
        //Per HAIP 1.0 §5.2 the trust anchor MUST NOT be carried in x5c, so x5c holds
        //the leaf alone and the CA is supplied to the wallet via the ExchangeContext.
        CertificateChainMaterial chain = TestCertificateChainProvider.CreateP256ChainMaterial(tp);
        string leafBase64 = Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlyMemory().ToArray());
        string caBase64 = Convert.ToBase64String(chain.CaDerBytes.AsReadOnlyMemory().ToArray());
        string leafHash = TestSetup.Base64UrlEncoder(SHA256.HashData(chain.LeafDerBytes.AsReadOnlyMemory().Span));
        string clientIdWithPrefix = $"{WellKnownClientIdPrefixes.X509Hash}:{leafHash}";
        string[] x5cValues = [leafBase64];

        //CA trust anchors the WALLET evaluates the chain against, placed on the
        //per-operation ExchangeContext — read per-call by the stateless resolver.
        IReadOnlyList<PkiCertificateMemory> walletTrustAnchors =
            MicrosoftX509Functions.ParseX5c([caBase64], Pool);

        //The AS's JAR-signing key IS the leaf key. ValidateChain yields the leaf
        //public key; the leaf private key is copied so the host and the chain
        //material own independent buffers. Ownership of both transfers to the host.
        IReadOnlyList<PkiCertificateMemory> registrationChain =
            MicrosoftX509Functions.ParseX5c(x5cValues, Pool);
        PublicKeyMemory leafPublic;
        try
        {
            leafPublic = await MicrosoftX509Functions.ValidateChainAsync(
                registrationChain, walletTrustAnchors, now, Pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach(PkiCertificateMemory cert in registrationChain)
            {
                cert.Dispose();
            }
        }

        JwtHeader jarHeader = new() { [WellKnownJwkMemberNames.X5c] = x5cValues };
        ResolveClientIdSigningKeyAsyncDelegate resolver =
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

        SchemeMaterial material = new()
        {
            ClientId = clientIdWithPrefix,
            JarSigningKeyPair = new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(
                leafPublic, CopyPrivateKey(chain.LeafSigningKey)),
            JarHeader = jarHeader,
            Resolver = resolver,
            PlaceTrustMaterial = context => context.SetX509TrustAnchors(walletTrustAnchors),
            Owned = [.. walletTrustAnchors, chain]
        };

        return material;
    }


    private static PrivateKeyMemory CopyPrivateKey(PrivateKeyMemory source)
    {
        ReadOnlySpan<byte> bytes = source.AsReadOnlySpan();
        IMemoryOwner<byte> owner = Pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PrivateKeyMemory(owner, source.Tag);
    }
}


/// <summary>
/// A client-id scheme as data: its display name plus a factory that mints the
/// per-run <see cref="SchemeMaterial"/> (JAR-signing key, JAR header, key
/// resolver, and the trust material the application places on the context). The
/// factory is async because attestation/federation mint JWTs/chains.
/// </summary>
internal sealed record SchemeFixture(
    string Name,
    Func<FakeTimeProvider, CancellationToken, ValueTask<SchemeMaterial>> CreateAsync);


/// <summary>
/// The per-run material a scheme produces. <see cref="Dispose"/> disposes
/// <see cref="Owned"/> only — the <see cref="JarSigningKeyPair"/> is owned by the
/// host (ownership transfers to <c>RegisterJarSigningClient</c>).
/// </summary>
internal sealed class SchemeMaterial: IDisposable
{
    public required string ClientId { get; init; }

    public required PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> JarSigningKeyPair { get; init; }

    public required JwtHeader JarHeader { get; init; }

    public required ResolveClientIdSigningKeyAsyncDelegate Resolver { get; init; }

    public required Action<ExchangeContext> PlaceTrustMaterial { get; init; }

    /// <summary>Trust anchors / certificates / federation nodes the scheme allocated.</summary>
    public IReadOnlyList<IDisposable> Owned { get; init; } = [];

    public void Dispose()
    {
        foreach(IDisposable owned in Owned)
        {
            owned.Dispose();
        }
    }
}

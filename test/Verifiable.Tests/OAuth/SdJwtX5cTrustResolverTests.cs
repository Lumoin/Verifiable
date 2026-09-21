using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="SdJwtX5cTrustResolver.ResolveAsync"/> — the Inline X.509 Certificates mechanism of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#section-2.5">SD-JWT
/// VC draft-19, Section 2.5</see>: "the recipient uses the public key from the end-entity
/// certificate of the certificates from that x5c parameter and validates the X.509 certificate chain
/// accordingly."
/// </summary>
[TestClass]
internal sealed class SdJwtX5cTrustResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider Time { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>A chain to a configured trust anchor yields the leaf certificate's public key.</summary>
    [TestMethod]
    public async Task ChainToConfiguredAnchorYieldsLeafKey()
    {
        DateTimeOffset now = Time.GetUtcNow();
        using CertificateChainMaterial chain = TestCertificateChainProvider.CreateP256ChainMaterial(Time);
        using PkiCertificateMemory trustAnchor = CopyAnchor(chain);

        IReadOnlyList<string> x5c =
        [
            Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlySpan()),
            Convert.ToBase64String(chain.CaDerBytes.AsReadOnlySpan())
        ];

        using PublicKeyMemory? resolved = await SdJwtX5cTrustResolver.ResolveAsync(
            x5c,
            MicrosoftX509Functions.ParseX5c,
            MicrosoftX509Functions.ValidateChainAsync,
            [trustAnchor],
            now,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(resolved, "A chain reaching a configured trust anchor must yield the leaf key.");
    }


    /// <summary>A chain to no configured trust anchor yields <see langword="null"/>.</summary>
    [TestMethod]
    public async Task ChainToNoAnchorYieldsNull()
    {
        DateTimeOffset now = Time.GetUtcNow();
        using CertificateChainMaterial chain = TestCertificateChainProvider.CreateP256ChainMaterial(Time);
        using CertificateChainMaterial otherChain = TestCertificateChainProvider.CreateFreshP256ChainMaterial(
            "other.example.com", Time);
        using PkiCertificateMemory unrelatedAnchor = CopyAnchor(otherChain);

        IReadOnlyList<string> x5c =
        [
            Convert.ToBase64String(chain.LeafDerBytes.AsReadOnlySpan()),
            Convert.ToBase64String(chain.CaDerBytes.AsReadOnlySpan())
        ];

        PublicKeyMemory? resolved = await SdJwtX5cTrustResolver.ResolveAsync(
            x5c,
            MicrosoftX509Functions.ParseX5c,
            MicrosoftX509Functions.ValidateChainAsync,
            [unrelatedAnchor],
            now,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(resolved, "A chain reaching none of the configured trust anchors must yield null.");
    }


    /// <summary>An empty <c>x5c</c> chain yields <see langword="null"/> without dialling the chain validator.</summary>
    [TestMethod]
    public async Task EmptyX5cYieldsNull()
    {
        DateTimeOffset now = Time.GetUtcNow();
        using CertificateChainMaterial chain = TestCertificateChainProvider.CreateP256ChainMaterial(Time);
        using PkiCertificateMemory trustAnchor = CopyAnchor(chain);

        PublicKeyMemory? resolved = await SdJwtX5cTrustResolver.ResolveAsync(
            [],
            MicrosoftX509Functions.ParseX5c,
            MicrosoftX509Functions.ValidateChainAsync,
            [trustAnchor],
            now,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(resolved, "An empty x5c chain must yield null.");
    }


    //A trust anchor the resolver's own validator can build against, copied from the chain's CA DER
    //bytes rather than passing chain.CaDerBytes itself — the same instance must not be both the
    //chain's own material (disposed with the chain) and a caller-owned trust anchor (disposed
    //separately by the test).
    private static PkiCertificateMemory CopyAnchor(CertificateChainMaterial chain)
    {
        IReadOnlyList<PkiCertificateMemory> anchors = MicrosoftX509Functions.ParseX5c(
            [Convert.ToBase64String(chain.CaDerBytes.AsReadOnlySpan())], Pool);

        return anchors[0];
    }
}

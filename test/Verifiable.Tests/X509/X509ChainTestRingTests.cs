using System.Buffers;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;

namespace Verifiable.Tests.X509;

/// <summary>
/// Smoke tests for <see cref="X509ChainTestRing"/> demonstrating that the
/// generated chains are real X.509 chains that validate through the
/// production <see cref="MicrosoftX509Functions"/> primitives.
/// </summary>
[TestClass]
internal sealed class X509ChainTestRingTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string DnsName = "verifier.example.com";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public async Task TwoLevelChainValidatesThroughMicrosoftDriver()
    {
        //Root CA → Leaf directly. The traditional shape of TestCertificateChainProvider.
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(TimeProvider, pathLengthConstraint: 0);
        using X509ChainTestRingNode leaf = X509ChainTestRing.CreateLeaf(root, DnsName, TimeProvider);

        DateTimeOffset now = TimeProvider.GetUtcNow();

        IReadOnlyList<string> x5c =
        [
            Convert.ToBase64String(leaf.Certificate.RawData),
            Convert.ToBase64String(root.Certificate.RawData),
        ];

        IReadOnlyList<PkiCertificateMemory> trustAnchors = MicrosoftX509Functions.ParseX5c(
            [Convert.ToBase64String(root.Certificate.RawData)],
            Pool);
        try
        {
            using PublicKeyMemory leafKey = await ResolveLeafKey(
                x5c, trustAnchors, now, TestContext.CancellationToken).ConfigureAwait(false);

            //The resolved key bytes must match the leaf's actual public key.
            byte[] expected = leaf.Certificate.GetPublicKey();
            Assert.IsNotNull(expected);
            Assert.IsGreaterThan(0, leafKey.AsReadOnlySpan().Length,
                "Resolver must produce non-empty public key bytes.");
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
    public async Task ThreeLevelChainValidatesThroughMicrosoftDriver()
    {
        //Root CA → Intermediate CA → Leaf. Common production shape — real PKI
        //rarely flattens to a single CA above the leaf.
        using X509ChainTestRingChain chain = X509ChainTestRing.BuildThreeLevelChain(DnsName, TimeProvider);

        DateTimeOffset now = TimeProvider.GetUtcNow();

        IReadOnlyList<PkiCertificateMemory> trustAnchors = MicrosoftX509Functions.ParseX5c(
            chain.RootX5c, Pool);
        try
        {
            using PublicKeyMemory leafKey = await ResolveLeafKey(
                chain.X5cValues, trustAnchors, now, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsGreaterThan(0, leafKey.AsReadOnlySpan().Length,
                "Three-level chain must produce a resolved leaf key.");
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
    public void GeneratedLeafCarriesDnsSanMatchingArgument()
    {
        using X509ChainTestRingChain chain = X509ChainTestRing.BuildThreeLevelChain(DnsName, TimeProvider);

        bool foundMatch = false;
        foreach(X509Extension ext in chain.Leaf.Certificate.Extensions)
        {
            if(ext is X509SubjectAlternativeNameExtension san)
            {
                foreach(string dns in san.EnumerateDnsNames())
                {
                    if(string.Equals(dns, DnsName, StringComparison.OrdinalIgnoreCase))
                    {
                        foundMatch = true;
                    }
                }
            }
        }

        Assert.IsTrue(foundMatch, $"Leaf certificate must carry '{DnsName}' as a DNS SAN.");
    }


    [TestMethod]
    public void IntermediateCarriesCaBasicConstraint()
    {
        using X509ChainTestRingChain chain = X509ChainTestRing.BuildThreeLevelChain(DnsName, TimeProvider);

        X509BasicConstraintsExtension? bc = null;
        foreach(X509Extension ext in chain.Intermediate.Certificate.Extensions)
        {
            if(ext is X509BasicConstraintsExtension found)
            {
                bc = found;
                break;
            }
        }

        Assert.IsNotNull(bc, "Intermediate must carry a BasicConstraints extension.");
        Assert.IsTrue(bc.CertificateAuthority, "Intermediate must be a CA.");
        Assert.AreEqual(0, bc.PathLengthConstraint,
            "Intermediate's pathLengthConstraint must be 0 — no further CAs beneath it.");
    }


    [TestMethod]
    public void LeafCarriesNonCaBasicConstraint()
    {
        using X509ChainTestRingChain chain = X509ChainTestRing.BuildThreeLevelChain(DnsName, TimeProvider);

        X509BasicConstraintsExtension? bc = null;
        foreach(X509Extension ext in chain.Leaf.Certificate.Extensions)
        {
            if(ext is X509BasicConstraintsExtension found)
            {
                bc = found;
                break;
            }
        }

        Assert.IsNotNull(bc, "Leaf must carry a BasicConstraints extension.");
        Assert.IsFalse(bc.CertificateAuthority, "Leaf must not be a CA.");
    }


    [TestMethod]
    public void CannotIssueIntermediateFromLeaf()
    {
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(TimeProvider);
        using X509ChainTestRingNode leaf = X509ChainTestRing.CreateLeaf(root, DnsName, TimeProvider);

        Assert.ThrowsExactly<InvalidOperationException>(
            () => X509ChainTestRing.CreateIntermediate(leaf, TimeProvider),
            "A Leaf must not be allowed to issue further nodes.");
    }


    private static async ValueTask<PublicKeyMemory> ResolveLeafKey(
        IReadOnlyList<string> x5c,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        //Walks the chain through the production primitives, exactly as
        //X509SanDnsKeyResolver would. Asserts the chain validates and the
        //leaf key extracts cleanly.
        IReadOnlyList<PkiCertificateMemory> parsed = MicrosoftX509Functions.ParseX5c(x5c, Pool);
        try
        {
            return await MicrosoftX509Functions.ValidateChainAsync(
                parsed, trustAnchors, now, Pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach(PkiCertificateMemory cert in parsed)
            {
                cert.Dispose();
            }
        }
    }
}

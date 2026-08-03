using System;
using System.Buffers;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="CertificateValidityPeriod.TryRead"/>: the CB-6.3-d certificate-window
/// fact a signing certificate's own DER encoding states, read over the shared internal
/// <see cref="ManagedCertificate"/> parse rather than a platform X.509 type. Certificates are minted with
/// <see cref="X509ChainTestRing"/>, so the expected <c>notBefore</c>/<c>notAfter</c> are fixed by construction.
/// </summary>
[TestClass]
internal sealed class CertificateValidityPeriodTests
{
    /// <summary>The minted validity start, chosen at whole-second precision so the DER round-trip is exact.</summary>
    private static DateTimeOffset NotBefore { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The minted validity end, chosen at whole-second precision so the DER round-trip is exact.</summary>
    private static DateTimeOffset NotAfter { get; } = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);


    /// <summary>A certificate minted with an explicit validity window reads back the exact same <c>notBefore</c>/<c>notAfter</c> instants.</summary>
    [TestMethod]
    public void ReadsTheExactMintedValidityPeriod()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using PkiCertificateMemory certificate = OcspTestFixtures.ToCertificateCarrier(root.Certificate);

        bool wasRead = CertificateValidityPeriod.TryRead(certificate, out CertificateValidityPeriod? validityPeriod);

        Assert.IsTrue(wasRead, "A well-formed minted certificate must read.");
        Assert.IsNotNull(validityPeriod, "TryRead must populate the out parameter when it answers true.");
        Assert.AreEqual(NotBefore, validityPeriod.NotBefore, "notBefore must be the exact instant the certificate was minted with.");
        Assert.AreEqual(NotAfter, validityPeriod.NotAfter, "notAfter must be the exact instant the certificate was minted with.");
    }


    /// <summary>Garbage bytes, and a well-formed certificate followed by trailing data, both fail closed rather than throwing.</summary>
    [TestMethod]
    public void FailsClosedOnMalformedDer()
    {
        IMemoryOwner<byte> garbageOwner = BaseMemoryPool.Shared.Rent(3);
        ReadOnlySpan<byte> garbageBytes = [0x01, 0x02, 0x03];
        garbageBytes.CopyTo(garbageOwner.Memory.Span);
        using var garbage = new PkiCertificateMemory(garbageOwner, PkiCertificateTags.X509Certificate);

        bool wasRead = CertificateValidityPeriod.TryRead(garbage, out CertificateValidityPeriod? validityPeriod);

        Assert.IsFalse(wasRead, "Garbage bytes must fail closed, not throw.");
        Assert.IsNull(validityPeriod, "A failed read must not populate the out parameter.");

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        byte[] certificateDer = root.Certificate.RawData;
        IMemoryOwner<byte> trailingOwner = BaseMemoryPool.Shared.Rent(certificateDer.Length + 1);
        certificateDer.CopyTo(trailingOwner.Memory.Span);
        trailingOwner.Memory.Span[certificateDer.Length] = 0x00;
        using var trailing = new PkiCertificateMemory(trailingOwner, PkiCertificateTags.X509Certificate);

        bool wasTrailingRead = CertificateValidityPeriod.TryRead(trailing, out CertificateValidityPeriod? trailingValidityPeriod);

        Assert.IsFalse(wasTrailingRead, "Trailing data after the Certificate sequence must fail closed, not throw.");
        Assert.IsNull(trailingValidityPeriod, "A failed read must not populate the out parameter.");
    }


    /// <summary>A carrier holding something other than an X.509 certificate is a composition error, rejected before any parsing.</summary>
    [TestMethod]
    public void RejectsANonCertificateCarrier()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(root.Certificate.RawDataMemory.Length);
        root.Certificate.RawDataMemory.Span.CopyTo(owner.Memory.Span);
        using var mistagged = new PkiCertificateMemory(owner, PkiCertificateTags.X509Crl);

        Assert.ThrowsExactly<ArgumentException>(
            () => CertificateValidityPeriod.TryRead(mistagged, out _),
            "A CRL-tagged carrier must be rejected before any parsing.");
    }


    /// <summary>A <see langword="null"/> carrier is a composition error, not a malformed-input case.</summary>
    [TestMethod]
    public void RejectsANullCertificate()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => CertificateValidityPeriod.TryRead(null!, out _));
    }
}

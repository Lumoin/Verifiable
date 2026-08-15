using System;
using System.Buffers;
using System.Formats.Asn1;
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
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-6.3-d.
    /// </remarks>
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


    /// <summary>
    /// The verify-pass exploit this regresses: <c>issuer</c> read via <c>ReadEncodedValue</c> accepted ANY
    /// single TLV, so a NULL where RFC 5280 §4.1.2.4 requires a SEQUENCE-shaped <c>Name</c>
    /// (<c>RDNSequence</c>) parsed clean. <see cref="ManagedCertificate.Parse"/> now peeks the tag first and
    /// <see cref="CertificateValidityPeriod.TryRead"/> fails closed over it.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-6.3-d.
    /// </remarks>
    [TestMethod]
    public void RejectsAnIssuerThatIsNotASequence()
    {
        using PkiCertificateMemory pseudoCertificate = BuildCertificateWithNullIssuer();

        Assert.ThrowsExactly<AsnContentException>(() => ManagedCertificate.Parse(pseudoCertificate.AsReadOnlyMemory()));

        bool wasRead = CertificateValidityPeriod.TryRead(pseudoCertificate, out CertificateValidityPeriod? validityPeriod);

        Assert.IsFalse(wasRead, "A NULL-TLV issuer is not an RDNSequence and must fail closed, not be accepted as a Name.");
        Assert.IsNull(validityPeriod, "A failed read must not populate the out parameter.");
    }


    /// <summary>
    /// The verify-pass exploit this regresses: the <c>[0]</c> EXPLICIT version wrapper's contents were consumed
    /// unvalidated, so a NULL in place of the RFC 5280 §4.1.2.1 <c>Version::= INTEGER</c> parsed clean. <see
    /// cref="ManagedCertificate.Parse"/> now requires exactly one INTEGER inside the wrapper and <see
    /// cref="CertificateValidityPeriod.TryRead"/> fails closed over it.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-6.3-d.
    /// </remarks>
    [TestMethod]
    public void RejectsAVersionWrapperThatIsNotAnInteger()
    {
        using PkiCertificateMemory pseudoCertificate = BuildCertificateWithNonIntegerVersion();

        Assert.ThrowsExactly<AsnContentException>(() => ManagedCertificate.Parse(pseudoCertificate.AsReadOnlyMemory()));

        bool wasRead = CertificateValidityPeriod.TryRead(pseudoCertificate, out CertificateValidityPeriod? validityPeriod);

        Assert.IsFalse(wasRead, "A NULL inside the [0] version wrapper is not an INTEGER and must fail closed.");
        Assert.IsNull(validityPeriod, "A failed read must not populate the out parameter.");
    }


    /// <summary>
    /// The verify-pass exploit this regresses: the <c>tbsCertificate.signature</c> <c>AlgorithmIdentifier</c>
    /// SEQUENCE's contents were never read, so an empty SEQUENCE (no OBJECT IDENTIFIER at all, RFC 5280
    /// §4.1.2.3/§4.1.1.2) parsed clean. <see cref="ManagedCertificate.Parse"/> now reads the leading OBJECT
    /// IDENTIFIER and <see cref="CertificateValidityPeriod.TryRead"/> fails closed over its absence.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-6.3-d.
    /// </remarks>
    [TestMethod]
    public void RejectsASignatureAlgorithmIdentifierWithoutAnObjectIdentifier()
    {
        using PkiCertificateMemory pseudoCertificate = BuildCertificateWithSignatureAlgorithmMissingObjectIdentifier();

        Assert.ThrowsExactly<AsnContentException>(() => ManagedCertificate.Parse(pseudoCertificate.AsReadOnlyMemory()));

        bool wasRead = CertificateValidityPeriod.TryRead(pseudoCertificate, out CertificateValidityPeriod? validityPeriod);

        Assert.IsFalse(wasRead, "An empty tbsCertificate.signature AlgorithmIdentifier carries no OBJECT IDENTIFIER and must fail closed.");
        Assert.IsNull(validityPeriod, "A failed read must not populate the out parameter.");
    }


    /// <summary>
    /// Assembles a structurally pseudo, otherwise well-formed X.509 certificate whose <c>issuer</c> field is a
    /// NULL TLV rather than a SEQUENCE (RFC 5280 §4.1.2.4) — the one shape difference from a well-formed
    /// certificate, mirroring <c>OcspTestFixtures.BuildSyntheticCertificateWithRawExtensions</c>'s
    /// stand-in-field shape for every OTHER field.
    /// </summary>
    /// <returns>The pooled certificate carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory BuildCertificateWithNullIssuer()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                        //Certificate.
        {
            using(writer.PushSequence())                                    //tbsCertificate.
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteInteger(2);                                 //version v3.
                }

                writer.WriteInteger(1);                                     //serialNumber stand-in.
                using(writer.PushSequence())                                //signature AlgorithmIdentifier stand-in.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                }

                writer.WriteNull();                                         //issuer -- NOT a SEQUENCE.
                using(writer.PushSequence())                                //validity.
                {
                    writer.WriteUtcTime(NotBefore);
                    writer.WriteUtcTime(NotAfter);
                }

                using(writer.PushSequence())                                //subject -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //subjectPublicKeyInfo stand-in, never reached.
                {
                }
            }

            using(writer.PushSequence())                                    //signatureAlgorithm stand-in.
            {
                writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            writer.WriteBitString([]);                                      //signatureValue stand-in.
        }

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        _ = writer.Encode(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Assembles a structurally pseudo, otherwise well-formed X.509 certificate whose <c>[0]</c> EXPLICIT
    /// version wrapper contains a NULL rather than an INTEGER (RFC 5280 §4.1.2.1) — the one shape difference
    /// from a well-formed certificate.
    /// </summary>
    /// <returns>The pooled certificate carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory BuildCertificateWithNonIntegerVersion()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                        //Certificate.
        {
            using(writer.PushSequence())                                    //tbsCertificate.
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteNull();                                     //NOT an INTEGER.
                }

                writer.WriteInteger(1);                                     //serialNumber stand-in.
                using(writer.PushSequence())                                //signature AlgorithmIdentifier stand-in.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                }

                using(writer.PushSequence())                                //issuer -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //validity.
                {
                    writer.WriteUtcTime(NotBefore);
                    writer.WriteUtcTime(NotAfter);
                }

                using(writer.PushSequence())                                //subject -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //subjectPublicKeyInfo stand-in, never reached.
                {
                }
            }

            using(writer.PushSequence())                                    //signatureAlgorithm stand-in.
            {
                writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            writer.WriteBitString([]);                                      //signatureValue stand-in.
        }

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        _ = writer.Encode(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Assembles a structurally pseudo, otherwise well-formed X.509 certificate whose
    /// <c>tbsCertificate.signature</c> <c>AlgorithmIdentifier</c> SEQUENCE is empty, carrying no OBJECT
    /// IDENTIFIER at all (RFC 5280 §4.1.2.3/§4.1.1.2) — the one shape difference from a well-formed certificate.
    /// </summary>
    /// <returns>The pooled certificate carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory BuildCertificateWithSignatureAlgorithmMissingObjectIdentifier()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                        //Certificate.
        {
            using(writer.PushSequence())                                    //tbsCertificate.
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteInteger(2);                                 //version v3.
                }

                writer.WriteInteger(1);                                     //serialNumber stand-in.
                using(writer.PushSequence())                                //signature AlgorithmIdentifier -- deliberately empty, no OID.
                {
                }

                using(writer.PushSequence())                                //issuer -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //validity.
                {
                    writer.WriteUtcTime(NotBefore);
                    writer.WriteUtcTime(NotAfter);
                }

                using(writer.PushSequence())                                //subject -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //subjectPublicKeyInfo stand-in, never reached.
                {
                }
            }

            using(writer.PushSequence())                                    //signatureAlgorithm stand-in.
            {
                writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            writer.WriteBitString([]);                                      //signatureValue stand-in.
        }

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        _ = writer.Encode(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}

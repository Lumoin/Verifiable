using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Defense-in-depth: proves <see cref="PAdESLifecycleValidation"/>'s own mint
/// helper -- <see cref="BoundProvenance.TryBindByCertificateDigestAsync"/> plus
/// <see cref="Verified{T}.TryCreateBound"/> -- refuses a fabricated identity binding, at the KERNEL granularity
/// a real TOTAL-PASSED <see cref="SignatureValidationOutcome"/> can never exercise: step 2)'s own
/// signing-certificate identification already refuses a mismatched certificate/reference pair before the
/// pipeline could ever reach TOTAL-PASSED, so the e2e capstone alone cannot prove this gate.
/// </summary>
[TestClass]
internal sealed class PAdESLifecycleMintDisciplineTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Bind-to-X / verify-under-Y: the cryptographic verification ran under certificate A, but the
    /// signature's own signer reference names certificate B's digest. The bind must refuse, never mint against
    /// the certificate crypto actually ran under while the reference names something else.
    /// </summary>
    [TestMethod]
    public async Task TryBindByCertificateDigestAsyncRefusesWhenTheSignerReferenceNamesADifferentCertificate()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode rootA = X509ChainTestRing.CreateRootCa(timeProvider, subjectCn: "Verifiable Test Root CA A");
        using X509ChainTestRingNode rootB = X509ChainTestRing.CreateRootCa(timeProvider, subjectCn: "Verifiable Test Root CA B");
        using PkiCertificateMemory certificateA = ToCarrier(rootA.Certificate.RawData);
        using PkiCertificateMemory certificateB = ToCarrier(rootB.Certificate.RawData);

        var verification = new SignatureCryptographicVerification
        {
            Outcome = SignatureCryptographicOutcome.Verified,
            SigningCertificate = certificateA
        };

        SigningCertificateReference mismatchedReference = await BuildSignerReferenceAsync(certificateB, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            BoundProvenance? bound = await BoundProvenance.TryBindByCertificateDigestAsync(
                [mismatchedReference], verification, new object(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNull(bound, "Verified-under-A, signed-reference-names-B must refuse -- the bind-to-X/verify-under-Y hazard PAdES's mint helper closes.");
        }
        finally
        {
            mismatchedReference.CertificateDigest?.Dispose();
        }
    }


    /// <summary>
    /// The mirror positive: a matching signer reference binds with <see cref="ResolutionSource.CertificateDigest"/>,
    /// and the resulting <see cref="BoundProvenance"/> mints a <see cref="Verified{PAdESVerifiedSignatureFacts}"/>
    /// only for the EXACT facts instance it was established for -- a different instance refuses, proving PAdES's
    /// mint helper cannot fabricate a binding across subjects.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each certificate copy's ownership transfers into the PAdESVerifiedSignatureFacts " +
            "constructed immediately after it -- the facts/differentFacts instances own and dispose their own " +
            "copies via PAdESVerifiedSignatureFacts.Dispose, guaranteed here by this method's own using declarations.")]
    public async Task TryBindByCertificateDigestAsyncBindsOnMatchAndTheMintRefusesADifferentFactsInstance()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
        using PkiCertificateMemory certificate = ToCarrier(root.Certificate.RawData);

        var verification = new SignatureCryptographicVerification
        {
            Outcome = SignatureCryptographicOutcome.Verified,
            SigningCertificate = certificate
        };

        SigningCertificateReference matchingReference = await BuildSignerReferenceAsync(certificate, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            PkiCertificateMemory factsCertificate = ToCarrier(root.Certificate.RawData);
            using var facts = new PAdESVerifiedSignatureFacts(PAdESReachedLevel.BT, factsCertificate);
            BoundProvenance? provenance = await BoundProvenance.TryBindByCertificateDigestAsync(
                [matchingReference], verification, facts, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNotNull(provenance);
            Assert.AreEqual(ResolutionSource.CertificateDigest, provenance!.Source);

            PkiCertificateMemory differentFactsCertificate = ToCarrier(root.Certificate.RawData);
            using var differentFacts = new PAdESVerifiedSignatureFacts(PAdESReachedLevel.BT, differentFactsCertificate);
            Verified<PAdESVerifiedSignatureFacts>? mintedForDifferentSubject = Verified<PAdESVerifiedSignatureFacts>.TryCreateBound(differentFacts, provenance);
            Assert.IsNull(mintedForDifferentSubject, "A provenance established for one facts instance must never mint for a different one.");

            Verified<PAdESVerifiedSignatureFacts>? minted = Verified<PAdESVerifiedSignatureFacts>.TryCreateBound(facts, provenance);
            Assert.IsNotNull(minted);
            Assert.IsTrue(minted!.Value.IsIdentityBound);
        }
        finally
        {
            matchingReference.CertificateDigest?.Dispose();
        }
    }


    /// <summary>Builds a signer reference naming <paramref name="certificate"/>'s own digest, computed through the project's own digest provider.</summary>
    private static async Task<SigningCertificateReference> BuildSignerReferenceAsync(PkiCertificateMemory certificate, CancellationToken cancellationToken)
    {
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            certificate.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

        return new SigningCertificateReference
        {
            DigestAlgorithm = AlgorithmIdentifier.Sha256,
            CertificateDigest = digest,
            IsSignerReference = true
        };
    }


    private static PkiCertificateMemory ToCarrier(byte[] derBytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}

using System;
using System.Buffers;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Builds a <see cref="SigningCertificateReference"/> from a certificate-thumbprint digest — the shape every
/// format's signing-certificate-identification header parameter reduces to once decoded: CAdES's ESS signing
/// certificate attribute, XAdES's <c>CertDigest</c>, JAdES's <c>x5t#S256</c>/<c>x5t#o</c>/<c>sigX5ts</c>, and
/// CB-AdES's <c>x5t</c>/<c>x5ts</c> all name a certificate by (digest bytes, digest algorithm). Shared here so
/// JAdES and CB-AdES feed <see cref="SignatureFacts.SigningCertificateReferences"/> from the SAME implementation
/// (reuse over reinvention) rather than each re-deriving the copy-and-tag recipe
/// <see cref="Pki.CAdESSignatureFacts.ReadEssCertificateReferences"/> and <see cref="XAdESSignatureFacts.BuildFacts"/>
/// already ship, one per family.
/// </summary>
public static class SigningCertificateReferenceBuilder
{
    /// <summary>
    /// Builds a <see cref="SigningCertificateReference"/> by copying <paramref name="digest"/>'s bytes into a
    /// fresh, caller-owned <see cref="DigestValue"/> under the algorithm <paramref name="digest"/>'s own <see
    /// cref="Tag"/> names (<see cref="PkiDigestAlgorithm.FromDigest"/>) — never aliasing <paramref name="digest"/>
    /// itself, so the returned reference's own <see cref="SigningCertificateReference.CertificateDigest"/> disposes
    /// independently of whatever owns <paramref name="digest"/> (the "copy bytes into fresh, this-instance-owned
    /// pool memory" discipline <see cref="JAdESSignatureFacts.BuildFacts"/>/<see cref="CBAdESSignatureFacts.BuildFacts"/>
    /// already hold every other carrier to).
    /// </summary>
    /// <param name="digest">The thumbprint digest, tagged with its own resolvable hash algorithm.</param>
    /// <param name="isSignerReference">Whether this reference names the signer's own certificate directly.</param>
    /// <param name="pool">The memory pool the copied digest is rented from.</param>
    /// <returns>
    /// The reference, or <see langword="null"/> when <paramref name="digest"/>'s own tag names no algorithm this
    /// library resolves (<see cref="PkiDigestAlgorithm.FromDigest"/>) — a reference with no resolvable digest
    /// algorithm can never be checked, so it is refused rather than carried forward unusable.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="digest"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static SigningCertificateReference? TryBuildFromDigest(DigestValue digest, bool isSignerReference, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(digest);
        ArgumentNullException.ThrowIfNull(pool);

        if(PkiDigestAlgorithm.FromDigest(digest) is not PkiDigestAlgorithm algorithm)
        {
            return null;
        }

        IMemoryOwner<byte> owner = pool.Rent(digest.Length);
        try
        {
            digest.AsReadOnlySpan().CopyTo(owner.Memory.Span);

            return new SigningCertificateReference
            {
                DigestAlgorithm = algorithm.Identifier,
                CertificateDigest = new DigestValue(owner, algorithm.DigestTag),
                IsSignerReference = isSignerReference
            };
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }
}

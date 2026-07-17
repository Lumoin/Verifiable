using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// The verification result for an attestation statement whose signature verified against an
/// X.509 certificate path: Basic, Attestation CA, or Anonymization CA attestation.
/// </summary>
/// <param name="Type">
/// The certified-path attestation type, or <see cref="AttestationType.Unknown"/> when the
/// verification procedure cannot itself distinguish which of the certificate-path types applies
/// without externally supplied authenticator metadata (see <see cref="AttestationType"/>).
/// </param>
/// <param name="TrustPath">
/// The certificate chain the attestation signature verified against, leaf first. These
/// <see cref="PkiCertificateMemory"/> instances are referenced by this result, not owned by
/// it — ownership remains with whichever component parsed the attestation statement and
/// constructed the chain (typically the caller of the <see cref="AttestationVerifyDelegate"/>
/// that produced this result). This record does not dispose them; the owner must.
/// </param>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2: Packed Attestation Statement Format.</see>
/// The verification procedure's <c>x5c</c>-present branch: "If successful, return
/// implementation-specific values representing attestation type Basic, AttCA or uncertainty,
/// and attestation trust path x5c."
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record CertifiedAttestationResult(AttestationType Type, IReadOnlyList<PkiCertificateMemory> TrustPath): AttestationResult
{
    /// <summary>
    /// Determines whether this result and <paramref name="other"/> report the same attestation
    /// type and trust path. The compiler-synthesized record equality would compare
    /// <see cref="TrustPath"/> by reference, which would report two independently-parsed results
    /// carrying byte-identical certificate chains as unequal — for example the same trust path
    /// reconstructed from wire bytes on two separate verification runs; this override compares
    /// <see cref="TrustPath"/> element-wise instead, relying on <see cref="PkiCertificateMemory"/>'s
    /// own content equality.
    /// </summary>
    /// <param name="other">The other result to compare against.</param>
    /// <returns>
    /// <see langword="true"/> when <see cref="Type"/> matches and <see cref="TrustPath"/> is
    /// element-wise equal, in order; otherwise <see langword="false"/>.
    /// </returns>
    public bool Equals(CertifiedAttestationResult? other) =>
        other is not null
        && Type == other.Type
        && TrustPath.SequenceEqual(other.TrustPath);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(CertifiedAttestationResult?)"/> —
    /// combining <see cref="Type"/> with each <see cref="TrustPath"/> entry's own hash code in
    /// order — so two value-equal results never disagree in a hash-based collection.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Type);
        foreach(PkiCertificateMemory certificate in TrustPath)
        {
            hash.Add(certificate);
        }

        return hash.ToHashCode();
    }


    /// <summary>
    /// A debugger-friendly summary of the attestation type and trust path length.
    /// </summary>
    private string DebuggerDisplay => $"CertifiedAttestationResult(Type={Type}, TrustPath={TrustPath.Count})";
}

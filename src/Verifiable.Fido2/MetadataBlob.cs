using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// A verified FIDO Metadata Service BLOB: the compact-JWS envelope plus its typed payload.
/// </summary>
/// <param name="Algorithm">
/// The JWT Header <c>alg</c> value, per
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob">FIDO
/// Metadata Service v3.1, section 3.1.7: Metadata BLOB</see>. Already checked against
/// <see cref="MetadataBlobVerification"/>'s supported-algorithm allowlist.
/// </param>
/// <param name="X5c">
/// The JWT Header <c>x5c</c> certificate chain, leaf first, per RFC 7515 §4.1.6 — the BLOB signing
/// certificate chain, already validated against the caller's trust anchors. Owned by this instance.
/// </param>
/// <param name="SigningInput">
/// The exact bytes the JWS signature covers: <c>EncodedJWTHeader || "." || EncodedMetadataBLOBPayload</c>,
/// per the same section's <c>tbsPayload</c> definition. Aliases the buffer supplied to the
/// <see cref="ParseMetadataBlobDelegate"/> that produced the <see cref="UnverifiedMetadataBlob"/>
/// this instance was projected from (wrap, don't copy) — it remains valid only as long as that
/// buffer does.
/// </param>
/// <param name="Signature">
/// The decoded JWS signature bytes (the third compact-serialization segment, base64url-decoded),
/// already checked against <see cref="SigningInput"/> and the leaf certificate's public key. ES256
/// signatures are already the fixed-width IEEE P1363 encoding per RFC 7518 §3.4 — no DER unwrap is
/// applied, unlike the WebAuthn attestation/assertion signature wire format.
/// </param>
/// <param name="Payload">
/// The typed, verified <c>MetadataBLOBPayload</c>. Owned by this instance.
/// </param>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html#sctn-mds-blob">FIDO
/// Metadata Service v3.1, section 3.1.7: Metadata BLOB.</see>
/// <para>
/// The trust position is <em>verified BLOB</em>: constructed only by
/// <see cref="UnverifiedMetadataBlob.ToVerified"/>, itself called only once
/// <see cref="MetadataBlobVerification"/>'s full processing-rules procedure — algorithm allowlist,
/// chain validation, signature verification, serial-number monotonicity, and <c>nextUpdate</c>
/// staleness — has passed. A function expecting this type cannot be miscalled with an
/// <see cref="UnverifiedMetadataBlob"/> whose signature was never checked; the distinction is
/// enforced by the compiler, not by caller discipline.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns <see cref="X5c"/> and <see cref="Payload"/> and
/// disposes both; it does not own the buffer <see cref="SigningInput"/> aliases. A
/// <see cref="VerifiedMetadataBlobResult"/> hands this instance to the caller, who disposes it once
/// no longer needed.
/// </para>
/// </remarks>
[DebuggerDisplay("MetadataBlob(Algorithm={Algorithm,nq}, X5c={X5c.Count}, No={Payload.No})")]
public sealed record MetadataBlob(
    string Algorithm,
    IReadOnlyList<PkiCertificateMemory> X5c,
    ReadOnlyMemory<byte> SigningInput,
    ReadOnlyMemory<byte> Signature,
    MetadataBlobPayload Payload): IDisposable
{
    /// <summary>
    /// Determines whether this BLOB and <paramref name="other"/> report the same content. The
    /// compiler-synthesized record equality would compare <see cref="X5c"/> and the
    /// <see cref="ReadOnlyMemory{T}"/> members by reference/identity; this override compares each
    /// by value instead.
    /// </summary>
    /// <param name="other">The other BLOB to compare against.</param>
    /// <returns><see langword="true"/> when every member matches by value.</returns>
    public bool Equals(MetadataBlob? other) =>
        other is not null
        && Algorithm == other.Algorithm
        && X5c.SequenceEqual(other.X5c)
        && SigningInput.Span.SequenceEqual(other.SigningInput.Span)
        && Signature.Span.SequenceEqual(other.Signature.Span)
        && Payload.Equals(other.Payload);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(MetadataBlob?)"/>.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Algorithm, StringComparer.Ordinal);
        foreach(PkiCertificateMemory certificate in X5c)
        {
            hash.Add(certificate);
        }

        hash.AddBytes(SigningInput.Span);
        hash.AddBytes(Signature.Span);
        hash.Add(Payload);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Releases <see cref="X5c"/> and <see cref="Payload"/>. Does not release the buffer
    /// <see cref="SigningInput"/> aliases — see the type-level ownership remarks.
    /// </summary>
    public void Dispose()
    {
        foreach(PkiCertificateMemory certificate in X5c)
        {
            certificate.Dispose();
        }

        Payload.Dispose();
    }
}

using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// The decoded fields of a <c>packed</c> attestation statement (<c>attStmt</c>).
/// </summary>
/// <param name="Alg">
/// The COSEAlgorithmIdentifier of the algorithm used to generate <see cref="Signature"/> (the
/// CBOR <c>alg</c> member).
/// </param>
/// <param name="Signature">The attestation signature bytes (the CBOR <c>sig</c> member).</param>
/// <param name="X5c">
/// The attestation certificate followed by its certificate chain, if any — leaf first, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication
/// Level 3, section 8.2: Packed Attestation Statement Format</see> ("The attestation certificate
/// attestnCert MUST be the first element in the array."). <see langword="null"/> when the CBOR
/// <c>attStmt</c> omits the <c>x5c</c> member, meaning self attestation is in use.
/// </param>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2: Packed Attestation Statement Format.</see>
/// </remarks>
[DebuggerDisplay("PackedAttestationStatement(Alg={Alg}, Signature={Signature.Length} bytes, X5c={X5c?.Count ?? 0})")]
public sealed record PackedAttestationStatement(int Alg, ReadOnlyMemory<byte> Signature, IReadOnlyList<PkiCertificateMemory>? X5c)
{
    /// <summary>
    /// Determines whether this statement and <paramref name="other"/> report the same content. The
    /// compiler-synthesized record equality would compare <see cref="Signature"/> and <see cref="X5c"/>
    /// by reference — two independently parsed statements decoded from byte-identical wire bytes would
    /// report as unequal; this override compares <see cref="Signature"/> by sequence and <see cref="X5c"/>
    /// element-wise instead, relying on <see cref="PkiCertificateMemory"/>'s own content equality. A
    /// <see langword="null"/> <see cref="X5c"/> (self attestation) equals only another <see langword="null"/>
    /// <see cref="X5c"/>, never an empty list.
    /// </summary>
    /// <param name="other">The other statement to compare against.</param>
    /// <returns>
    /// <see langword="true"/> when <see cref="Alg"/> matches, <see cref="Signature"/> is byte-equal, and
    /// <see cref="X5c"/> is either both <see langword="null"/> or element-wise equal, in order; otherwise
    /// <see langword="false"/>.
    /// </returns>
    public bool Equals(PackedAttestationStatement? other) =>
        other is not null
        && Alg == other.Alg
        && Signature.Span.SequenceEqual(other.Signature.Span)
        && (X5c is null ? other.X5c is null : other.X5c is not null && X5c.SequenceEqual(other.X5c));


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(PackedAttestationStatement?)"/> —
    /// combining <see cref="Alg"/>, <see cref="Signature"/>'s bytes, and each <see cref="X5c"/> entry's
    /// own hash code in order — so two value-equal statements never disagree in a hash-based collection.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Alg);
        hash.AddBytes(Signature.Span);
        if(X5c is not null)
        {
            foreach(PkiCertificateMemory certificate in X5c)
            {
                hash.Add(certificate);
            }
        }

        return hash.ToHashCode();
    }
}


/// <summary>
/// Decodes a <c>packed</c> attestation statement's raw CBOR bytes into a
/// <see cref="PackedAttestationStatement"/>.
/// </summary>
/// <param name="attestationStatement">The raw <c>attStmt</c> CBOR bytes.</param>
/// <param name="pool">
/// The memory pool the decoded <see cref="PackedAttestationStatement.X5c"/> entries' certificate
/// carriers allocate from.
/// </param>
/// <returns>The decoded statement.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping this library
/// serialization-agnostic — mirrors <see cref="ReadCredentialPublicKeyDelegate"/>.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// Thrown when <paramref name="attestationStatement"/> is not valid CBOR conforming to the
/// packed attestation statement syntax defined in
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2</see>.
/// </exception>
public delegate PackedAttestationStatement ParsePackedAttestationStatementDelegate(ReadOnlyMemory<byte> attestationStatement, MemoryPool<byte> pool);

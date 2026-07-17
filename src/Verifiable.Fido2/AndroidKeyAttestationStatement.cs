using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// The decoded fields of an <c>android-key</c> attestation statement (<c>attStmt</c>).
/// </summary>
/// <param name="Alg">
/// The COSEAlgorithmIdentifier of the algorithm used to generate <see cref="Signature"/> (the
/// CBOR <c>alg</c> member).
/// </param>
/// <param name="Signature">The attestation signature bytes (the CBOR <c>sig</c> member).</param>
/// <param name="X5c">
/// The attestation certificate (<c>credCert</c>) followed by its certificate chain, leaf first, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication
/// Level 3, section 8.4: Android Key Attestation Statement Format</see>'s CDDL
/// (<c>x5c: [ credCert: bytes, * (caCert: bytes) ]</c>). Unlike
/// <see cref="PackedAttestationStatement.X5c"/>, this member is MANDATORY, never
/// <see langword="null"/> — the <c>android-key</c> format has no self-attestation branch, so
/// <c>x5c</c> is always present on the wire. A decoded, present-but-empty array is still possible
/// (a non-conforming <c>attStmt</c>); <see cref="AndroidKeyAttestation"/>'s verification procedure,
/// not the codec, rejects that case.
/// </param>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication Level 3, section 8.4: Android Key Attestation Statement Format.</see>
/// </remarks>
[DebuggerDisplay("AndroidKeyAttestationStatement(Alg={Alg}, Signature={Signature.Length} bytes, X5c={X5c.Count})")]
public sealed record AndroidKeyAttestationStatement(int Alg, ReadOnlyMemory<byte> Signature, IReadOnlyList<PkiCertificateMemory> X5c)
{
    /// <summary>
    /// Determines whether this statement and <paramref name="other"/> report the same content. The
    /// compiler-synthesized record equality would compare <see cref="Signature"/> and <see cref="X5c"/>
    /// by reference — two independently parsed statements decoded from byte-identical wire bytes would
    /// report as unequal; this override compares <see cref="Signature"/> by sequence and <see cref="X5c"/>
    /// element-wise instead, relying on <see cref="PkiCertificateMemory"/>'s own content equality.
    /// </summary>
    /// <param name="other">The other statement to compare against.</param>
    /// <returns>
    /// <see langword="true"/> when <see cref="Alg"/> matches, <see cref="Signature"/> is byte-equal, and
    /// <see cref="X5c"/> is element-wise equal, in order; otherwise <see langword="false"/>.
    /// </returns>
    public bool Equals(AndroidKeyAttestationStatement? other) =>
        other is not null
        && Alg == other.Alg
        && Signature.Span.SequenceEqual(other.Signature.Span)
        && X5c.SequenceEqual(other.X5c);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(AndroidKeyAttestationStatement?)"/> —
    /// combining <see cref="Alg"/>, <see cref="Signature"/>'s bytes, and each <see cref="X5c"/> entry's
    /// own hash code in order — so two value-equal statements never disagree in a hash-based collection.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Alg);
        hash.AddBytes(Signature.Span);
        foreach(PkiCertificateMemory certificate in X5c)
        {
            hash.Add(certificate);
        }

        return hash.ToHashCode();
    }
}


/// <summary>
/// Decodes an <c>android-key</c> attestation statement's raw CBOR bytes into an
/// <see cref="AndroidKeyAttestationStatement"/>.
/// </summary>
/// <param name="attestationStatement">The raw <c>attStmt</c> CBOR bytes.</param>
/// <param name="pool">
/// The memory pool the decoded <see cref="AndroidKeyAttestationStatement.X5c"/> entries' certificate
/// carriers allocate from.
/// </param>
/// <returns>The decoded statement.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping this library
/// serialization-agnostic — mirrors <see cref="ParsePackedAttestationStatementDelegate"/>.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// Thrown when <paramref name="attestationStatement"/> is not valid CBOR conforming to the
/// android-key attestation statement syntax defined in
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication Level 3, section 8.4</see>.
/// </exception>
public delegate AndroidKeyAttestationStatement ParseAndroidKeyAttestationStatementDelegate(ReadOnlyMemory<byte> attestationStatement, MemoryPool<byte> pool);

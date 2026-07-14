using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// The decoded fields of a <c>fido-u2f</c> attestation statement (<c>attStmt</c>).
/// </summary>
/// <param name="Signature">The attestation signature bytes (the CBOR <c>sig</c> member).</param>
/// <param name="X5c">
/// The single-element attestation certificate array (the CBOR <c>x5c</c> member), per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication
/// Level 3, section 8.6: FIDO U2F Attestation Statement Format</see>'s CDDL
/// (<c>x5c: [ attestnCert: bytes ]</c>) — unlike <see cref="PackedAttestationStatement.X5c"/>, this
/// member is MANDATORY and carries exactly one certificate, never a chain and never absent; a parse
/// delegate implementation MUST reject any other element count.
/// </param>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication
/// Level 3, section 8.6: FIDO U2F Attestation Statement Format</see>. Unlike <c>packed</c>'s
/// <c>attStmt</c>, this format's CDDL carries no <c>alg</c> member — the format is implicitly bound
/// to ES256 by its (authenticator-side) Signing procedure text rather than a wire field.
/// </remarks>
[DebuggerDisplay("FidoU2fAttestationStatement(Signature={Signature.Length} bytes, X5c={X5c.Count})")]
public sealed record FidoU2fAttestationStatement(ReadOnlyMemory<byte> Signature, IReadOnlyList<PkiCertificateMemory> X5c)
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
    /// <see langword="true"/> when <see cref="Signature"/> is byte-equal and <see cref="X5c"/> is
    /// element-wise equal, in order; otherwise <see langword="false"/>.
    /// </returns>
    public bool Equals(FidoU2fAttestationStatement? other) =>
        other is not null
        && Signature.Span.SequenceEqual(other.Signature.Span)
        && X5c.SequenceEqual(other.X5c);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(FidoU2fAttestationStatement?)"/> —
    /// combining <see cref="Signature"/>'s bytes and each <see cref="X5c"/> entry's own hash code in
    /// order — so two value-equal statements never disagree in a hash-based collection.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.AddBytes(Signature.Span);
        foreach(PkiCertificateMemory certificate in X5c)
        {
            hash.Add(certificate);
        }

        return hash.ToHashCode();
    }
}


/// <summary>
/// Decodes a <c>fido-u2f</c> attestation statement's raw CBOR bytes into a
/// <see cref="FidoU2fAttestationStatement"/>.
/// </summary>
/// <param name="attestationStatement">The raw <c>attStmt</c> CBOR bytes.</param>
/// <param name="pool">
/// The memory pool the decoded <see cref="FidoU2fAttestationStatement.X5c"/> entry's certificate
/// carrier allocates from.
/// </param>
/// <returns>The decoded statement.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping this library
/// serialization-agnostic — mirrors <see cref="ParsePackedAttestationStatementDelegate"/>.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// Thrown when <paramref name="attestationStatement"/> is not valid CBOR conforming to the
/// fido-u2f attestation statement syntax defined in
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication Level 3, section 8.6</see>,
/// including when <c>x5c</c> does not carry exactly one element.
/// </exception>
public delegate FidoU2fAttestationStatement ParseFidoU2fAttestationStatementDelegate(ReadOnlyMemory<byte> attestationStatement, MemoryPool<byte> pool);

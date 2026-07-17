using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2;

/// <summary>
/// The decoded fields of a <c>tpm</c> attestation statement (<c>attStmt</c>).
/// </summary>
/// <param name="Alg">
/// The COSEAlgorithmIdentifier of the algorithm used to generate <see cref="Signature"/> (the
/// CBOR <c>alg</c> member).
/// </param>
/// <param name="Signature">
/// The attestation signature bytes (the CBOR <c>sig</c> member) — a marshaled TPMT_SIGNATURE
/// structure, per <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web
/// Authentication Level 3, section 8.3: TPM Attestation Statement Format</see>, "in the form of a
/// TPMT_SIGNATURE structure as specified in [TPMv2-Part2] section 11.3.4."
/// </param>
/// <param name="CertInfo">
/// The <c>certInfo</c> bytes — a marshaled TPMS_ATTEST structure (<see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">section
/// 8.3</see>, "as specified in [TPMv2-Part2] section 10.12.8") over which <see cref="Signature"/>
/// was computed.
/// </param>
/// <param name="PubArea">
/// The <c>pubArea</c> bytes — a marshaled TPMT_PUBLIC structure (section 8.3, "see [TPMv2-Part2]
/// section 12.2.4") representing the credential public key. Per section 8.3's signing-procedure
/// note, this is the TPMT_PUBLIC content alone, with any TPM2B_PUBLIC length prefix already
/// stripped.
/// </param>
/// <param name="X5c">
/// The AIK certificate (<c>aikCert</c>) followed by its certificate chain, leaf first, per
/// section 8.3's CDDL (<c>x5c: [ aikCert: bytes, * (caCert: bytes) ]</c>). Unlike
/// <see cref="PackedAttestationStatement.X5c"/>, this member is MANDATORY, never
/// <see langword="null"/> — the <c>tpm</c> format has no self-attestation branch, so <c>x5c</c> is
/// always present on the wire. A decoded, present-but-empty array is still possible (a
/// non-conforming <c>attStmt</c>); <see cref="TpmAttestation"/>'s verification procedure, not the
/// codec, rejects that case.
/// </param>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level 3, section 8.3: TPM Attestation Statement Format.</see>
/// </remarks>
[DebuggerDisplay("TpmAttestationStatement(Alg={Alg}, Signature={Signature.Length} bytes, CertInfo={CertInfo.Length} bytes, PubArea={PubArea.Length} bytes, X5c={X5c.Count})")]
public sealed record TpmAttestationStatement(
    int Alg,
    ReadOnlyMemory<byte> Signature,
    ReadOnlyMemory<byte> CertInfo,
    ReadOnlyMemory<byte> PubArea,
    IReadOnlyList<PkiCertificateMemory> X5c)
{
    /// <summary>
    /// Determines whether this statement and <paramref name="other"/> report the same content. The
    /// compiler-synthesized record equality would compare <see cref="Signature"/>,
    /// <see cref="CertInfo"/>, <see cref="PubArea"/>, and <see cref="X5c"/> by reference — two
    /// independently parsed statements decoded from byte-identical wire bytes would report as
    /// unequal; this override compares the byte members by sequence and <see cref="X5c"/>
    /// element-wise instead, relying on <see cref="PkiCertificateMemory"/>'s own content equality.
    /// </summary>
    /// <param name="other">The other statement to compare against.</param>
    /// <returns>
    /// <see langword="true"/> when <see cref="Alg"/> matches, <see cref="Signature"/>,
    /// <see cref="CertInfo"/>, and <see cref="PubArea"/> are byte-equal, and <see cref="X5c"/> is
    /// element-wise equal, in order; otherwise <see langword="false"/>.
    /// </returns>
    public bool Equals(TpmAttestationStatement? other) =>
        other is not null
        && Alg == other.Alg
        && Signature.Span.SequenceEqual(other.Signature.Span)
        && CertInfo.Span.SequenceEqual(other.CertInfo.Span)
        && PubArea.Span.SequenceEqual(other.PubArea.Span)
        && X5c.SequenceEqual(other.X5c);


    /// <summary>
    /// Computes a hash code consistent with <see cref="Equals(TpmAttestationStatement?)"/> —
    /// combining <see cref="Alg"/>, the three byte members' content, and each <see cref="X5c"/>
    /// entry's own hash code in order — so two value-equal statements never disagree in a
    /// hash-based collection.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(Alg);
        hash.AddBytes(Signature.Span);
        hash.AddBytes(CertInfo.Span);
        hash.AddBytes(PubArea.Span);
        foreach(PkiCertificateMemory certificate in X5c)
        {
            hash.Add(certificate);
        }

        return hash.ToHashCode();
    }
}


/// <summary>
/// Decodes a <c>tpm</c> attestation statement's raw CBOR bytes into a
/// <see cref="TpmAttestationStatement"/>.
/// </summary>
/// <param name="attestationStatement">The raw <c>attStmt</c> CBOR bytes.</param>
/// <param name="pool">
/// The memory pool the decoded <see cref="TpmAttestationStatement.X5c"/> entries' certificate
/// carriers allocate from.
/// </param>
/// <returns>The decoded statement.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping this library
/// serialization-agnostic — mirrors <see cref="ParsePackedAttestationStatementDelegate"/>.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// Thrown when <paramref name="attestationStatement"/> is not valid CBOR conforming to the
/// tpm attestation statement syntax defined in
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level 3, section 8.3</see>.
/// </exception>
public delegate TpmAttestationStatement ParseTpmAttestationStatementDelegate(ReadOnlyMemory<byte> attestationStatement, MemoryPool<byte> pool);

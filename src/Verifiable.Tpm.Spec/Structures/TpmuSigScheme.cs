using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Union of signature scheme parameters (TPMU_SIG_SCHEME), selected by the enclosing scheme algorithm.
/// </summary>
/// <remarks>
/// <para>
/// Every non-anonymous signing scheme (<c>RSASSA</c>, <c>RSAPSS</c>, <c>ECDSA</c>, <c>SM2</c>,
/// <c>ECSCHNORR</c>) carries just a hash algorithm — <c>TPMS_SCHEME_HASH</c>, Part 2 Table 173. The anonymous
/// <c>ECDAA</c> scheme additionally carries a commit counter — <c>TPMS_SCHEME_ECDAA</c>, Part 2 Table 174.
/// The HMAC scheme's <c>TPMS_SCHEME_HMAC</c> (Table 176) is the same shape as <c>TPMS_SCHEME_HASH</c>, so it
/// shares this type's hash-only member.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.2.1.4, Table 182.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmuSigScheme
{
    /// <summary>
    /// Gets the hash algorithm every member carries.
    /// </summary>
    public TpmiAlgHash HashAlg { get; }

    /// <summary>
    /// Gets the ECDAA commit counter, present only when this member is the <c>TPMS_SCHEME_ECDAA</c> shape;
    /// otherwise <see langword="null"/>.
    /// </summary>
    public ushort? Count { get; }

    /// <summary>
    /// Initializes a signature scheme union member.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <param name="count">The ECDAA commit counter, or <see langword="null"/> for a hash-only member.</param>
    private TpmuSigScheme(TpmiAlgHash hashAlg, ushort? count)
    {
        HashAlg = hashAlg;
        Count = count;
    }

    /// <summary>
    /// Gets whether this member is the anonymous <c>TPMS_SCHEME_ECDAA</c> shape.
    /// </summary>
    public bool IsEcdaa => Count.HasValue;

    /// <summary>
    /// Creates a hash-only member (<c>TPMS_SCHEME_HASH</c> / <c>TPMS_SCHEME_HMAC</c>), the shape every
    /// non-anonymous signing scheme uses.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <returns>The created member.</returns>
    public static TpmuSigScheme CreateHash(TpmiAlgHash hashAlg) => new(hashAlg, null);

    /// <summary>
    /// Creates the anonymous ECDAA member (<c>TPMS_SCHEME_ECDAA</c>).
    /// </summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <param name="count">The counter value used between <c>TPM2_Commit()</c> and the sign operation.</param>
    /// <returns>The created member.</returns>
    public static TpmuSigScheme CreateEcdaa(TpmiAlgHash hashAlg, ushort count) => new(hashAlg, count);

    /// <summary>
    /// Gets the serialized size of this member.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + (Count.HasValue ? sizeof(ushort) : 0);

    /// <summary>
    /// Writes this member to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        HashAlg.WriteTo(ref writer);

        if(Count.HasValue)
        {
            writer.WriteUInt16(Count.Value);
        }
    }

    /// <summary>
    /// Parses a signature scheme union member, using the enclosing scheme selector to choose its shape.
    /// </summary>
    /// <param name="scheme">The scheme selector from the enclosing <see cref="TpmtSigScheme"/>.</param>
    /// <param name="reader">The reader positioned at the member's <c>hashAlg</c> field.</param>
    /// <returns>The parsed member.</returns>
    /// <exception cref="InvalidOperationException">The scheme's <c>hashAlg</c> is not a hash algorithm (<c>TPM_RC_HASH</c>).</exception>
    public static TpmuSigScheme Parse(TpmAlgIdConstants scheme, ref TpmReader reader)
    {
        TpmiAlgHash hashAlg = TpmiAlgHash.Parse(ref reader);

        if(scheme == TpmAlgIdConstants.TPM_ALG_ECDAA)
        {
            ushort count = reader.ReadUInt16();

            return CreateEcdaa(hashAlg, count);
        }

        return CreateHash(hashAlg);
    }

    private string DebuggerDisplay => IsEcdaa
        ? $"TPMU_SIG_SCHEME(ECDAA, {HashAlg.Value}, count={Count})"
        : $"TPMU_SIG_SCHEME({HashAlg.Value})";
}

using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Parameters for a keyed-hash object (TPMS_KEYEDHASH_PARMS).
/// </summary>
/// <remarks>
/// <para>
/// A keyed-hash object is either an HMAC key, an XOR-obfuscation key, or a sealed data object. The scheme
/// selects which: <see cref="Hmac"/> and <see cref="Xor"/> build the two key shapes, and <see cref="SealedData"/>
/// (scheme <c>TPM_ALG_NULL</c>) carries no scheme detail at all. Support for <c>TPM_ALG_NULL</c> on an HMAC key
/// whose public area has the <c>sign</c> attribute SET was deprecated in version 185 (Part 2, Table 227's note).
/// </para>
/// <para>
/// <b>Wire format:</b> TPMT_KEYEDHASH_SCHEME scheme = scheme selector (TPMI_ALG_KEYEDHASH_SCHEME, UINT16),
/// followed by the TPMU_SCHEME_KEYEDHASH details the selector chooses: nothing for <c>TPM_ALG_NULL</c>; a hash
/// algorithm (TPMI_ALG_HASH, UINT16) for <c>TPM_ALG_HMAC</c> (TPMS_SCHEME_HMAC, Table 176); a hash algorithm then
/// a key-derivation function (TPMI_ALG_KDF, UINT16) for <c>TPM_ALG_XOR</c> (TPMS_SCHEME_XOR, Table 177).
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.1.23, Table 179 (TPMT_KEYEDHASH_SCHEME) and
/// Section 12.2.3.3, Table 227 (TPMS_KEYEDHASH_PARMS).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsKeyedHashParms
{
    /// <summary>
    /// Gets the keyed-hash scheme (TPM_ALG_HMAC, TPM_ALG_XOR, or TPM_ALG_NULL).
    /// </summary>
    public TpmAlgIdConstants Scheme { get; init; }

    /// <summary>
    /// Gets the hash algorithm for the scheme; meaningful only when <see cref="Scheme"/> is not TPM_ALG_NULL.
    /// </summary>
    public TpmAlgIdConstants HashAlg { get; init; }

    /// <summary>
    /// Gets the key-derivation function for the XOR scheme (TPMS_SCHEME_XOR's <c>kdf</c>); meaningful only when
    /// <see cref="Scheme"/> is TPM_ALG_XOR.
    /// </summary>
    public TpmAlgIdConstants Kdf { get; init; }

    /// <summary>
    /// Gets whether this is the null scheme (a sealed data object rather than an HMAC/XOR key).
    /// </summary>
    public bool IsNull => Scheme == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Gets whether this is an HMAC key scheme.
    /// </summary>
    public bool IsHmac => Scheme == TpmAlgIdConstants.TPM_ALG_HMAC;

    /// <summary>
    /// Gets whether this is an XOR-obfuscation key scheme.
    /// </summary>
    public bool IsXor => Scheme == TpmAlgIdConstants.TPM_ALG_XOR;

    /// <summary>
    /// Gets the null-scheme parameters used for a sealed data object.
    /// </summary>
    public static TpmsKeyedHashParms SealedData => new() { Scheme = TpmAlgIdConstants.TPM_ALG_NULL };

    /// <summary>
    /// Creates the HMAC scheme parameters (TPMS_SCHEME_HMAC): an HMAC key signs and verifies with
    /// <paramref name="hashAlg"/>.
    /// </summary>
    /// <param name="hashAlg">The HMAC hash algorithm.</param>
    /// <returns>The HMAC scheme parameters.</returns>
    public static TpmsKeyedHashParms Hmac(TpmAlgIdConstants hashAlg) => new()
    {
        Scheme = TpmAlgIdConstants.TPM_ALG_HMAC,
        HashAlg = hashAlg
    };

    /// <summary>
    /// Creates the XOR-obfuscation scheme parameters (TPMS_SCHEME_XOR): the obfuscation mask is derived with
    /// <paramref name="kdf"/> over <paramref name="hashAlg"/>.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm the key-derivation function digests with.</param>
    /// <param name="kdf">The key-derivation function that produces the obfuscation mask.</param>
    /// <returns>The XOR scheme parameters.</returns>
    public static TpmsKeyedHashParms Xor(TpmAlgIdConstants hashAlg, TpmAlgIdConstants kdf) => new()
    {
        Scheme = TpmAlgIdConstants.TPM_ALG_XOR,
        HashAlg = hashAlg,
        Kdf = kdf
    };

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => Scheme switch
    {
        TpmAlgIdConstants.TPM_ALG_NULL => sizeof(ushort),
        TpmAlgIdConstants.TPM_ALG_XOR => sizeof(ushort) + sizeof(ushort) + sizeof(ushort),
        _ => sizeof(ushort) + sizeof(ushort)
    };

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)Scheme);

        if(IsNull)
        {
            return;
        }

        writer.WriteUInt16((ushort)HashAlg);

        if(IsXor)
        {
            writer.WriteUInt16((ushort)Kdf);
        }
    }

    /// <summary>
    /// Parses a keyed-hash parameters structure from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed parameters.</returns>
    /// <exception cref="InvalidOperationException">
    /// <c>scheme</c> is not one of the values TPMI_ALG_KEYEDHASH_SCHEME admits — TPM_ALG_HMAC, TPM_ALG_XOR, or
    /// TPM_ALG_NULL (Table 175's <c>#TPM_RC_VALUE</c>); or, for the HMAC and XOR arms, <c>hashAlg</c> is neither
    /// a TCG-defined hash algorithm nor TPM_ALG_NULL (Table 77's <c>#TPM_RC_HASH</c>, via
    /// <see cref="TpmiAlgHash.Parse"/>) — the parse admits the NULL hash structurally so that the object's
    /// validating command answers Table 177's <c>TPM_RC_HASH</c> itself, where a parse-time refusal would reach
    /// the wire through the parser's single <c>TPM_RC_SIZE</c> channel; or, for the XOR arm, <c>kdf</c> is not
    /// one of the key-derivation functions TPMI_ALG_KDF admits (Table 82's <c>#TPM_RC_KDF</c>; TPM_ALG_NULL is
    /// admitted, Table 177's <c>TPMI_ALG_KDF+</c>).
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">Too few octets remain for the scheme selector or the details the selector chooses.</exception>
    public static TpmsKeyedHashParms Parse(ref TpmReader reader)
    {
        var scheme = (TpmAlgIdConstants)reader.ReadUInt16();
        if(scheme == TpmAlgIdConstants.TPM_ALG_NULL)
        {
            return new TpmsKeyedHashParms { Scheme = scheme };
        }

        if(scheme != TpmAlgIdConstants.TPM_ALG_HMAC && scheme != TpmAlgIdConstants.TPM_ALG_XOR)
        {
            throw new InvalidOperationException($"Invalid keyed-hash scheme 0x{(ushort)scheme:X4}. Expected TPM_ALG_HMAC, TPM_ALG_XOR, or TPM_ALG_NULL.");
        }

        TpmiAlgHash hashAlg = TpmiAlgHash.Parse(ref reader, isNullAdmitted: true);
        if(scheme == TpmAlgIdConstants.TPM_ALG_XOR)
        {
            TpmiAlgKdf kdf = TpmiAlgKdf.Parse(ref reader, isNullAdmitted: true);

            return new TpmsKeyedHashParms { Scheme = scheme, HashAlg = hashAlg.Value, Kdf = kdf.Value };
        }

        return new TpmsKeyedHashParms { Scheme = scheme, HashAlg = hashAlg.Value };
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => Scheme switch
    {
        TpmAlgIdConstants.TPM_ALG_NULL => "TPMS_KEYEDHASH_PARMS(NULL)",
        TpmAlgIdConstants.TPM_ALG_XOR => $"TPMS_KEYEDHASH_PARMS(XOR, {HashAlg}, {Kdf})",
        _ => $"TPMS_KEYEDHASH_PARMS({Scheme}, {HashAlg})"
    };
}

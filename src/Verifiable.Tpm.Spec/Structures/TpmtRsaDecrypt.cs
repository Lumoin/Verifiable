using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// RSA decryption scheme selection (TPMT_RSA_DECRYPT) — the padding scheme <c>TPM2_RSA_Encrypt()</c> and
/// <c>TPM2_RSA_Decrypt()</c> carry as <c>inScheme</c>, and the shape of a <c>TPMS_RSA_PARMS.scheme</c> when
/// that scheme is a decryption scheme.
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_RSA_DECRYPT scheme;              // Scheme selector (or TPM_ALG_NULL).
///     TPMU_RSA_SCHEME details;                  // rsaes: TPMS_EMPTY; oaep: TPMS_SCHEME_HASH.
/// } TPMT_RSA_DECRYPT;
/// </code>
/// <para>
/// Table 190's <c>TPMU_RSA_SCHEME</c> restricts <c>details</c> to exactly two non-NULL shapes for this
/// selector: <c>rsaes</c> carries nothing, <c>oaep</c> carries a single hash algorithm. That two-member
/// algebra is the same one <see cref="TpmtRsaScheme"/> already special-cases with a flat <see cref="HashAlg"/>
/// field rather than a nested union, so this type mirrors it: <see cref="Scheme"/> plus a
/// <see cref="HashAlg"/> that is meaningful only when <see cref="Scheme"/> selects OAEP.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.2.4.5, Table 193; the <c>details</c> shapes are
/// clause 11.2.4.2, Table 190 (<c>rsaes: TPMS_EMPTY</c>, <c>oaep: TPMS_SCHEME_HASH</c>).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtRsaDecrypt
{
    /// <summary>
    /// Gets the scheme selector.
    /// </summary>
    public TpmiAlgRsaDecrypt Scheme { get; init; }

    /// <summary>
    /// Gets the hash algorithm for the scheme.
    /// </summary>
    /// <remarks>
    /// Meaningful only when <see cref="Scheme"/> selects <c>TPM_ALG_OAEP</c> — Table 190's <c>rsaes</c> member
    /// is <c>TPMS_EMPTY</c> and carries no hash.
    /// </remarks>
    public TpmAlgIdConstants HashAlg { get; init; }

    /// <summary>
    /// Gets whether this is a null scheme.
    /// </summary>
    public bool IsNull => Scheme.IsNull;

    /// <summary>
    /// Gets a null RSA decryption scheme.
    /// </summary>
    public static TpmtRsaDecrypt Null => new() { Scheme = TpmiAlgRsaDecrypt.FromValue(TpmAlgIdConstants.TPM_ALG_NULL) };

    /// <summary>
    /// Gets an RSAES (PKCS#1 v1.5 encryption) scheme.
    /// </summary>
    /// <remarks>
    /// RSAES has no hash algorithm parameter (Table 190's <c>rsaes: TPMS_EMPTY</c>).
    /// </remarks>
    public static TpmtRsaDecrypt RsaEs => new() { Scheme = TpmiAlgRsaDecrypt.FromValue(TpmAlgIdConstants.TPM_ALG_RSAES) };

    /// <summary>
    /// Creates an OAEP encryption scheme.
    /// </summary>
    /// <param name="hashAlg">The OAEP hash algorithm.</param>
    /// <returns>The RSA decryption scheme.</returns>
    public static TpmtRsaDecrypt Oaep(TpmAlgIdConstants hashAlg) => new()
    {
        Scheme = TpmiAlgRsaDecrypt.FromValue(TpmAlgIdConstants.TPM_ALG_OAEP),
        HashAlg = hashAlg
    };

    /// <summary>
    /// Gets the serialized size of this structure: 2 octets for a NULL or RSAES selector (no
    /// <c>details</c>), 4 octets for OAEP (selector plus its hash algorithm).
    /// </summary>
    public int SerializedSize => Scheme.Value == TpmAlgIdConstants.TPM_ALG_OAEP
        ? sizeof(ushort) + sizeof(ushort)
        : sizeof(ushort);

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        Scheme.WriteTo(ref writer);

        if(Scheme.Value == TpmAlgIdConstants.TPM_ALG_OAEP)
        {
            writer.WriteUInt16((ushort)HashAlg);
        }
    }

    /// <summary>
    /// Parses an RSA decryption scheme from a TPM reader as one compound step, for a caller that does not need
    /// to distinguish a bad selector from a bad hash algorithm (for example a round-trip test).
    /// </summary>
    /// <remarks>
    /// Table 192's selector failure is <c>TPM_RC_VALUE</c> and Table 173/77's OAEP hash failure is
    /// <c>TPM_RC_HASH</c> — two different response codes reached through the same <see cref="InvalidOperationException"/>
    /// type. The in-house simulator's own <c>TPM2_RSA_Encrypt()</c>/<c>TPM2_RSA_Decrypt()</c> parsers do not
    /// call this method: they read <see cref="TpmiAlgRsaDecrypt.Parse"/> and, for OAEP,
    /// <see cref="TpmiAlgHash.Parse(ref TpmReader, bool)"/> as two separate steps under their own catch blocks,
    /// so the two codes stay distinguishable at the wire boundary.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted for the selector.</param>
    /// <returns>The parsed RSA decryption scheme.</returns>
    /// <exception cref="InvalidOperationException">The selector is not admitted (<c>TPM_RC_VALUE</c>), or the OAEP hash algorithm is not admitted (<c>TPM_RC_HASH</c>).</exception>
    public static TpmtRsaDecrypt Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        TpmiAlgRsaDecrypt scheme = TpmiAlgRsaDecrypt.Parse(ref reader, isNullAdmitted);

        if(scheme.Value != TpmAlgIdConstants.TPM_ALG_OAEP)
        {
            return new TpmtRsaDecrypt { Scheme = scheme };
        }

        TpmiAlgHash hashAlg = TpmiAlgHash.Parse(ref reader, isNullAdmitted: false);

        return new TpmtRsaDecrypt { Scheme = scheme, HashAlg = hashAlg.Value };
    }

    /// <summary>
    /// Converts this decryption scheme to the flat <see cref="TpmtRsaScheme"/> shape a <see cref="TpmsRsaParms.Scheme"/>
    /// carries, so Table 42's "be the same as scheme" compare (selector and hash both) is one equality against
    /// the key's own scheme.
    /// </summary>
    /// <returns>The equivalent <see cref="TpmtRsaScheme"/>.</returns>
    public TpmtRsaScheme ToRsaScheme() => new()
    {
        Scheme = Scheme.Value,
        HashAlg = HashAlg
    };

    /// <summary>
    /// Converts a key's own <see cref="TpmtRsaScheme"/> to this decryption-scheme shape.
    /// </summary>
    /// <remarks>
    /// A <paramref name="scheme"/> whose selector is outside Table 192's set (<c>TPM_ALG_RSASSA</c> or
    /// <c>TPM_ALG_RSAPSS</c>, a signing scheme) has no <see cref="TpmiAlgRsaDecrypt"/> counterpart and throws —
    /// this conversion is meant only for a key scheme already judged admitted for decryption by Table 42's own
    /// selection logic before the call, never for an arbitrary signing-scheme value.
    /// </remarks>
    /// <param name="scheme">The key's own RSA scheme.</param>
    /// <returns>The equivalent RSA decryption scheme.</returns>
    /// <exception cref="InvalidOperationException"><paramref name="scheme"/>'s selector is not RSAES, OAEP, or NULL.</exception>
    public static TpmtRsaDecrypt FromRsaScheme(TpmtRsaScheme scheme)
    {
        if(!TpmiAlgRsaDecrypt.IsRsaDecryptScheme(scheme.Scheme, isNullAdmitted: true))
        {
            throw new InvalidOperationException($"'{scheme.Scheme}' is not a decryption scheme (TPM_ALG_RSAES, TPM_ALG_OAEP, or TPM_ALG_NULL).");
        }

        return new TpmtRsaDecrypt
        {
            Scheme = TpmiAlgRsaDecrypt.FromValue(scheme.Scheme),
            HashAlg = scheme.HashAlg
        };
    }

    /// <summary>
    /// The debugger's one-line rendering.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            if(IsNull)
            {
                return "TPMT_RSA_DECRYPT(NULL)";
            }

            if(Scheme.Value == TpmAlgIdConstants.TPM_ALG_RSAES)
            {
                return "TPMT_RSA_DECRYPT(RSAES)";
            }

            return $"TPMT_RSA_DECRYPT({Scheme.Value}, {HashAlg})";
        }
    }
}

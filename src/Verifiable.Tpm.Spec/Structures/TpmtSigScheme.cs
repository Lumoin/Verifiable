using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// An algorithm-agile signing scheme (TPMT_SIG_SCHEME): the scheme selector followed by the
/// <see cref="TpmuSigScheme"/> parameters it selects.
/// </summary>
/// <remarks>
/// <para>
/// Appears in an object's public area and in commands where the signing scheme is variable (for example
/// <c>TPMS_RSA_PARMS.scheme</c>, <c>TPMS_ECC_PARMS.scheme</c>). A <c>TPM_ALG_NULL</c> scheme selects no
/// parameters at all.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     +TPMI_ALG_SIG_SCHEME scheme;              // Scheme selector.
///     TPMU_SIG_SCHEME      details;              // The scheme parameters scheme selects; absent for NULL.
/// } TPMT_SIG_SCHEME;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.2.1.5, Table 180.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtSigScheme
{
    private static TpmtSigScheme NullInstance { get; } = new(TpmiAlgSigScheme.FromValue(TpmAlgIdConstants.TPM_ALG_NULL), null);

    /// <summary>
    /// Gets the scheme selector.
    /// </summary>
    public TpmiAlgSigScheme Scheme { get; }

    /// <summary>
    /// Gets the scheme parameters, or <see langword="null"/> when <see cref="Scheme"/> is <c>TPM_ALG_NULL</c>.
    /// </summary>
    public TpmuSigScheme? Details { get; }

    /// <summary>
    /// Initializes an algorithm-agile signing scheme.
    /// </summary>
    /// <param name="scheme">The scheme selector.</param>
    /// <param name="details">The scheme parameters, or <see langword="null"/> for the NULL scheme.</param>
    private TpmtSigScheme(TpmiAlgSigScheme scheme, TpmuSigScheme? details)
    {
        Scheme = scheme;
        Details = details;
    }

    /// <summary>
    /// Gets the NULL signing scheme (<c>scheme == TPM_ALG_NULL</c>, no parameters).
    /// </summary>
    public static TpmtSigScheme Null => NullInstance;

    /// <summary>
    /// Gets whether this is the NULL signing scheme.
    /// </summary>
    public bool IsNull => Scheme.IsNull;

    /// <summary>
    /// Creates a hash-only signing scheme — every non-anonymous scheme: <c>RSASSA</c>, <c>RSAPSS</c>,
    /// <c>ECDSA</c>, <c>SM2</c>, <c>ECSCHNORR</c>, or <c>HMAC</c>.
    /// </summary>
    /// <param name="scheme">The scheme selector.</param>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <returns>The created scheme.</returns>
    /// <exception cref="ArgumentException"><paramref name="scheme"/> is not an admitted, non-anonymous signing scheme.</exception>
    public static TpmtSigScheme Create(TpmAlgIdConstants scheme, TpmiAlgHash hashAlg)
    {
        if(scheme == TpmAlgIdConstants.TPM_ALG_ECDAA || !TpmiAlgSigScheme.IsSigScheme(scheme))
        {
            throw new ArgumentException($"'{scheme}' is not an admitted hash-only signing scheme.", nameof(scheme));
        }

        return new TpmtSigScheme(TpmiAlgSigScheme.FromValue(scheme), TpmuSigScheme.CreateHash(hashAlg));
    }

    /// <summary>
    /// Creates the anonymous ECDAA signing scheme.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <param name="count">The counter value used between <c>TPM2_Commit()</c> and the sign operation.</param>
    /// <returns>The created scheme.</returns>
    public static TpmtSigScheme CreateEcdaa(TpmiAlgHash hashAlg, ushort count)
    {
        return new TpmtSigScheme(TpmiAlgSigScheme.FromValue(TpmAlgIdConstants.TPM_ALG_ECDAA), TpmuSigScheme.CreateEcdaa(hashAlg, count));
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + (Details?.SerializedSize ?? 0);

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <exception cref="InvalidOperationException">
    /// <see cref="Scheme"/> is <c>TPM_ALG_ERROR</c> — the default-constructed value, never a valid scheme
    /// selector (<c>TPM_RC_SCHEME</c>).
    /// </exception>
    public void WriteTo(ref TpmWriter writer)
    {
        if(Scheme.Value == TpmAlgIdConstants.TPM_ALG_ERROR)
        {
            throw new InvalidOperationException("Cannot write a default-constructed TPMT_SIG_SCHEME: 'scheme' is TPM_ALG_ERROR, not an admitted signing scheme.");
        }

        Scheme.WriteTo(ref writer);

        if(Details.HasValue)
        {
            TpmuSigScheme details = Details.Value;
            details.WriteTo(ref writer);
        }
    }

    /// <summary>
    /// Parses an algorithm-agile signing scheme from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at <c>scheme</c>.</param>
    /// <param name="isNullAdmitted">Whether <c>scheme</c> may be <c>TPM_ALG_NULL</c>.</param>
    /// <returns>The parsed scheme.</returns>
    /// <exception cref="InvalidOperationException"><c>scheme</c> is not an admitted signing scheme (<c>TPM_RC_SCHEME</c>).</exception>
    public static TpmtSigScheme Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        TpmiAlgSigScheme scheme = TpmiAlgSigScheme.Parse(ref reader, isNullAdmitted);

        if(scheme.IsNull)
        {
            return Null;
        }

        TpmuSigScheme details = TpmuSigScheme.Parse(scheme.Value, ref reader);

        return new TpmtSigScheme(scheme, details);
    }

    private string DebuggerDisplay => IsNull ? "TPMT_SIG_SCHEME(NULL)" : $"TPMT_SIG_SCHEME({Scheme.Value})";
}

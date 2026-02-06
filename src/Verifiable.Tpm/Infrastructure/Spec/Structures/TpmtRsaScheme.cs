using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// RSA scheme definition (TPMT_RSA_SCHEME).
/// </summary>
/// <remarks>
/// <para>
/// This structure defines the signing or encryption scheme for an RSA key.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_RSA_SCHEME scheme;              // Scheme selector (or TPM_ALG_NULL).
///     TPMU_ASYM_SCHEME details;                // Scheme parameters (if scheme != NULL).
/// } TPMT_RSA_SCHEME;
/// </code>
/// <para>
/// When scheme is TPM_ALG_NULL, details is not present on the wire.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.2.4.2.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtRsaScheme
{
    /// <summary>
    /// Gets the scheme algorithm.
    /// </summary>
    /// <remarks>
    /// For signing: TPM_ALG_RSASSA, TPM_ALG_RSAPSS.
    /// For encryption: TPM_ALG_RSAES, TPM_ALG_OAEP.
    /// TPM_ALG_NULL for unrestricted keys or storage keys.
    /// </remarks>
    public TpmAlgIdConstants Scheme { get; init; }

    /// <summary>
    /// Gets the hash algorithm for the scheme.
    /// </summary>
    /// <remarks>
    /// Only meaningful when Scheme is not TPM_ALG_NULL and not TPM_ALG_RSAES.
    /// </remarks>
    public TpmAlgIdConstants HashAlg { get; init; }

    /// <summary>
    /// Gets whether this is a null scheme.
    /// </summary>
    public bool IsNull => Scheme == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Gets a null RSA scheme.
    /// </summary>
    public static TpmtRsaScheme Null => new() { Scheme = TpmAlgIdConstants.TPM_ALG_NULL };

    /// <summary>
    /// Creates an RSASSA (PKCS#1 v1.5) signing scheme.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <returns>The RSA scheme.</returns>
    public static TpmtRsaScheme Rsassa(TpmAlgIdConstants hashAlg) => new()
    {
        Scheme = TpmAlgIdConstants.TPM_ALG_RSASSA,
        HashAlg = hashAlg
    };

    /// <summary>
    /// Creates an RSAPSS signing scheme.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <returns>The RSA scheme.</returns>
    public static TpmtRsaScheme RsaPss(TpmAlgIdConstants hashAlg) => new()
    {
        Scheme = TpmAlgIdConstants.TPM_ALG_RSAPSS,
        HashAlg = hashAlg
    };

    /// <summary>
    /// Creates an OAEP encryption scheme.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <returns>The RSA scheme.</returns>
    public static TpmtRsaScheme Oaep(TpmAlgIdConstants hashAlg) => new()
    {
        Scheme = TpmAlgIdConstants.TPM_ALG_OAEP,
        HashAlg = hashAlg
    };

    /// <summary>
    /// Gets an RSAES (PKCS#1 v1.5 encryption) scheme.
    /// </summary>
    /// <remarks>
    /// RSAES has no hash algorithm parameter.
    /// </remarks>
    public static TpmtRsaScheme RsaEs => new()
    {
        Scheme = TpmAlgIdConstants.TPM_ALG_RSAES
    };

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize
    {
        get
        {
            if(IsNull)
            {
                return sizeof(ushort); // scheme only
            }

            // RSAES has no hash parameter.
            if(Scheme == TpmAlgIdConstants.TPM_ALG_RSAES)
            {
                return sizeof(ushort); // scheme only
            }

            return sizeof(ushort) + sizeof(ushort); // scheme + hashAlg
        }
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)Scheme);

        if(!IsNull && Scheme != TpmAlgIdConstants.TPM_ALG_RSAES)
        {
            writer.WriteUInt16((ushort)HashAlg);
        }
    }

    /// <summary>
    /// Parses an RSA scheme from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed RSA scheme.</returns>
    public static TpmtRsaScheme Parse(ref TpmReader reader)
    {
        var scheme = (TpmAlgIdConstants)reader.ReadUInt16();

        if(scheme == TpmAlgIdConstants.TPM_ALG_NULL)
        {
            return Null;
        }

        // RSAES has no hash parameter.
        if(scheme == TpmAlgIdConstants.TPM_ALG_RSAES)
        {
            return RsaEs;
        }

        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        return new TpmtRsaScheme
        {
            Scheme = scheme,
            HashAlg = hashAlg
        };
    }

    private string DebuggerDisplay
    {
        get
        {
            if(IsNull)
            {
                return "TPMT_RSA_SCHEME(NULL)";
            }

            if(Scheme == TpmAlgIdConstants.TPM_ALG_RSAES)
            {
                return "TPMT_RSA_SCHEME(RSAES)";
            }

            return $"TPMT_RSA_SCHEME({Scheme}, {HashAlg})";
        }
    }
}
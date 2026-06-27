using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Union of signature values (TPMU_SIGNATURE), selected by the signing algorithm.
/// </summary>
/// <remarks>
/// <para>
/// The active member is chosen by the <c>sigAlg</c> selector of the enclosing TPMT_SIGNATURE. Each
/// member carries the hash algorithm used followed by the scheme-specific signature value.
/// </para>
/// <para>
/// <b>Union members:</b>
/// </para>
/// <list type="bullet">
///   <item><description>TPM_ALG_ECDSA: TPMS_SIGNATURE_ECDSA (hash + signatureR + signatureS), Part 2, Section 11.3.4.</description></item>
///   <item><description>TPM_ALG_RSASSA / TPM_ALG_RSAPSS: TPMS_SIGNATURE_RSA (hash + sig), Part 2, Section 11.3.2.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.3.5, Table 195 (TPMU_SIGNATURE).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmuSignature: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the signing algorithm selector (for example TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).
    /// </summary>
    public TpmAlgIdConstants Type { get; }

    /// <summary>
    /// Gets the hash algorithm reported inside the signature member.
    /// </summary>
    public TpmAlgIdConstants HashAlgorithm { get; }

    /// <summary>
    /// Gets the r component of an ECDSA signature, when <see cref="Type"/> is TPM_ALG_ECDSA; otherwise <see langword="null"/>.
    /// </summary>
    public Tpm2bEccParameter? SignatureR { get; }

    /// <summary>
    /// Gets the s component of an ECDSA signature, when <see cref="Type"/> is TPM_ALG_ECDSA; otherwise <see langword="null"/>.
    /// </summary>
    public Tpm2bEccParameter? SignatureS { get; }

    /// <summary>
    /// Gets the RSA signature buffer, when <see cref="Type"/> is TPM_ALG_RSASSA or TPM_ALG_RSAPSS; otherwise <see cref="Tpm2bPublicKeyRsa.Empty"/>.
    /// </summary>
    public Tpm2bPublicKeyRsa RsaSignature { get; }

    /// <summary>
    /// Initializes an ECDSA signature member.
    /// </summary>
    private TpmuSignature(TpmAlgIdConstants type, TpmAlgIdConstants hashAlgorithm, Tpm2bEccParameter signatureR, Tpm2bEccParameter signatureS)
    {
        Type = type;
        HashAlgorithm = hashAlgorithm;
        SignatureR = signatureR;
        SignatureS = signatureS;
        RsaSignature = Tpm2bPublicKeyRsa.Empty;
    }

    /// <summary>
    /// Initializes an RSA signature member.
    /// </summary>
    private TpmuSignature(TpmAlgIdConstants type, TpmAlgIdConstants hashAlgorithm, Tpm2bPublicKeyRsa rsaSignature)
    {
        Type = type;
        HashAlgorithm = hashAlgorithm;
        RsaSignature = rsaSignature;
        SignatureR = null;
        SignatureS = null;
    }

    /// <summary>
    /// Parses a signature union from a TPM reader using the supplied algorithm selector.
    /// </summary>
    /// <param name="sigAlg">The signing algorithm selector from the enclosing TPMT_SIGNATURE.</param>
    /// <param name="reader">The reader positioned at the start of the signature member (its hash field).</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed signature union.</returns>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="sigAlg"/> is not a supported signing algorithm.</exception>
    public static TpmuSignature Parse(TpmAlgIdConstants sigAlg, ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        return sigAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_ECDSA => ParseEcdsa(sigAlg, hashAlg, ref reader, pool),
            TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS => ParseRsa(sigAlg, hashAlg, ref reader, pool),
            _ => throw new NotSupportedException($"Signing algorithm '{sigAlg}' is not supported for parsing.")
        };

        static TpmuSignature ParseEcdsa(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ref TpmReader reader, MemoryPool<byte> pool)
        {
            Tpm2bEccParameter r = Tpm2bEccParameter.Parse(ref reader, pool);
            Tpm2bEccParameter s = Tpm2bEccParameter.Parse(ref reader, pool);

            return new TpmuSignature(sigAlg, hashAlg, r, s);
        }

        static TpmuSignature ParseRsa(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ref TpmReader reader, MemoryPool<byte> pool)
        {
            Tpm2bPublicKeyRsa rsa = Tpm2bPublicKeyRsa.Parse(ref reader, pool);

            return new TpmuSignature(sigAlg, hashAlg, rsa);
        }
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            SignatureR?.Dispose();
            SignatureS?.Dispose();
            RsaSignature.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => Type switch
    {
        TpmAlgIdConstants.TPM_ALG_ECDSA => $"TPMU_SIGNATURE(ECDSA, {HashAlgorithm}, R={SignatureR?.Length ?? 0} bytes, S={SignatureS?.Length ?? 0} bytes)",
        TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS => $"TPMU_SIGNATURE({Type}, {HashAlgorithm}, {RsaSignature.Size} bytes)",
        _ => $"TPMU_SIGNATURE({Type})"
    };
}

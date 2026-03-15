using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_Sign command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 20.2):
/// </para>
/// <list type="bullet">
///   <item><description>signature (TPMT_SIGNATURE): sigAlg (2 bytes) + TPMS_SIGNATURE_ECDSA.</description></item>
/// </list>
/// <para>
/// TPMS_SIGNATURE_ECDSA structure (TPM 2.0 Part 2, Section 11.3.4):
/// </para>
/// <list type="bullet">
///   <item><description>hash (TPMI_ALG_HASH): The hash algorithm used.</description></item>
///   <item><description>signatureR (TPM2B_ECC_PARAMETER): The r component.</description></item>
///   <item><description>signatureS (TPM2B_ECC_PARAMETER): The s component.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SignResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the signing algorithm reported by the TPM.
    /// </summary>
    public TpmAlgIdConstants SignatureAlgorithm { get; }

    /// <summary>
    /// Gets the hash algorithm reported by the TPM.
    /// </summary>
    public TpmAlgIdConstants HashAlgorithm { get; }

    /// <summary>
    /// Gets the r component of the ECDSA signature.
    /// </summary>
    public Tpm2bEccParameter SignatureR { get; }

    /// <summary>
    /// Gets the s component of the ECDSA signature.
    /// </summary>
    public Tpm2bEccParameter SignatureS { get; }

    private SignResponse(
        TpmAlgIdConstants signatureAlgorithm,
        TpmAlgIdConstants hashAlgorithm,
        Tpm2bEccParameter signatureR,
        Tpm2bEccParameter signatureS)
    {
        SignatureAlgorithm = signatureAlgorithm;
        HashAlgorithm = hashAlgorithm;
        SignatureR = signatureR;
        SignatureS = signatureS;
    }

    /// <summary>
    /// Parses a TPM2_Sign response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed sign response.</returns>
    public static SignResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        Tpm2bEccParameter r = Tpm2bEccParameter.Parse(ref reader, pool);
        Tpm2bEccParameter s = Tpm2bEccParameter.Parse(ref reader, pool);
        return new SignResponse(sigAlg, hashAlg, r, s);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            SignatureR.Dispose();
            SignatureS.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"SignResponse({SignatureAlgorithm}, R={SignatureR.Length} bytes, S={SignatureS.Length} bytes)";
}

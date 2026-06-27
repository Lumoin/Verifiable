using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_Quote command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 18.4):
/// </para>
/// <list type="bullet">
///   <item><description>quoted (TPM2B_ATTEST): the signed attestation (a marshaled TPMS_ATTEST). The signature is over its raw bytes.</description></item>
///   <item><description>signature (TPMT_SIGNATURE): sigAlg (TPMI_ALG_SIG_SCHEME, 2 bytes) selecting a <see cref="TpmuSignature"/> member.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class QuoteResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the signed attestation. Verify the signature over <see cref="Tpm2bAttest.GetRawBytes"/>.
    /// </summary>
    public Tpm2bAttest Quoted { get; }

    /// <summary>
    /// Gets the signing algorithm reported by the TPM (the TPMU_SIGNATURE selector).
    /// </summary>
    public TpmAlgIdConstants SignatureAlgorithm { get; }

    /// <summary>
    /// Gets the parsed signature value.
    /// </summary>
    public TpmuSignature Signature { get; }

    /// <summary>
    /// Gets the hash algorithm reported by the TPM inside the signature.
    /// </summary>
    public TpmAlgIdConstants HashAlgorithm => Signature.HashAlgorithm;

    private QuoteResponse(Tpm2bAttest quoted, TpmAlgIdConstants signatureAlgorithm, TpmuSignature signature)
    {
        Quoted = quoted;
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
    }

    /// <summary>
    /// Parses a TPM2_Quote response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed quote response.</returns>
    public static QuoteResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bAttest quoted = Tpm2bAttest.Parse(ref reader, pool);
        var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        TpmuSignature signature = TpmuSignature.Parse(sigAlg, ref reader, pool);

        return new QuoteResponse(quoted, sigAlg, signature);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Quoted.Dispose();
            Signature.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"QuoteResponse({Quoted}, {SignatureAlgorithm}, {Signature})";
}

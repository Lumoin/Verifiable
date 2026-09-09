using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_VerifySignature command.
/// </summary>
/// <remarks>
/// Response structure (TPM 2.0 Library Part 3, clause 20.2, Table 117): a single TPMT_TK_VERIFIED validation
/// ticket — unlike every attest-producing command (TPM2_Certify, TPM2_Quote, and friends), there is no
/// TPM2B_ATTEST, no TPMU_ATTEST union, and no TPMT_SIGNATURE in the response.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class VerifySignatureResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the validation ticket proving the TPM verified the signature.
    /// </summary>
    public TpmtTkVerified Validation { get; }

    private VerifySignatureResponse(TpmtTkVerified validation)
    {
        Validation = validation;
    }

    /// <summary>
    /// Parses a TPM2_VerifySignature response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed verify-signature response.</returns>
    /// <exception cref="InvalidOperationException">The ticket's tag is not <c>TPM_ST_VERIFIED</c> — this command's response table fixes it, even though <see cref="TpmtTkVerified.Parse"/> itself admits all three Table 112 tags (TPM 2.0 Library Part 3, clause 20.2.2).</exception>
    public static VerifySignatureResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        TpmtTkVerified validation = TpmtTkVerified.Parse(ref reader, pool);

        if(validation.Tag != TpmStConstants.TPM_ST_VERIFIED)
        {
            validation.Dispose();

            throw new InvalidOperationException(
                $"TPM2_VerifySignature() response ticket must be tagged TPM_ST_VERIFIED, got {validation.Tag} (TPM 2.0 Library Part 3, clause 20.2.2, Table 117).");
        }

        return new VerifySignatureResponse(validation);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Validation.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"VerifySignatureResponse(Hierarchy={Validation.Hierarchy}, {(Validation.IsNull ? "NULL" : $"{Validation.Hmac.Length} bytes")})";
}

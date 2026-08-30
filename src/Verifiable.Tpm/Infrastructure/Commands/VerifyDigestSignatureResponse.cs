using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_VerifyDigestSignature command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 20.4, Table 121): a single TPMT_TK_VERIFIED validation
/// ticket, tagged TPM_ST_DIGEST_VERIFIED (TPM 2.0 Library Part 2, clause 10.6.5, Table 112) — unlike
/// <see cref="VerifySignatureResponse"/>'s TPM_ST_VERIFIED ticket, this ticket's <see cref="TpmtTkVerified.Metadata"/>
/// carries the scheme hash algorithm that was verified (Table 111's <c>digestVerified</c> arm). If the key is in
/// the NULL hierarchy, the ticket is the NULL tuple for this tag — hierarchy TPM_RH_NULL, empty hmac, metadata
/// still the scheme's hash algorithm (Table 111's arm admits no NULL selector).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class VerifyDigestSignatureResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the validation ticket proving the TPM verified the signature.
    /// </summary>
    public TpmtTkVerified Validation { get; }

    private VerifyDigestSignatureResponse(TpmtTkVerified validation)
    {
        Validation = validation;
    }

    /// <summary>
    /// Parses a TPM2_VerifyDigestSignature response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed verify-digest-signature response.</returns>
    /// <exception cref="InvalidOperationException">The ticket's tag is not <c>TPM_ST_DIGEST_VERIFIED</c> — Table 121 fixes it ("tag will be TPM_ST_DIGEST_VERIFIED"), even though <see cref="TpmtTkVerified.Parse"/> itself admits all three Table 112 tags.</exception>
    public static VerifyDigestSignatureResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        TpmtTkVerified validation = TpmtTkVerified.Parse(ref reader, pool);

        if(validation.Tag != TpmStConstants.TPM_ST_DIGEST_VERIFIED)
        {
            validation.Dispose();

            throw new InvalidOperationException(
                $"TPM2_VerifyDigestSignature() response ticket must be tagged TPM_ST_DIGEST_VERIFIED, got {validation.Tag} (TPM 2.0 Library Part 3, clause 20.4, Table 121).");
        }

        return new VerifyDigestSignatureResponse(validation);
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

    /// <summary>The debugger's one-line rendering: the ticket's hierarchy and either "NULL" or its HMAC's octet count, never the HMAC octets themselves.</summary>
    private string DebuggerDisplay => $"VerifyDigestSignatureResponse(Hierarchy={Validation.Hierarchy}, {(Validation.IsNull ? "NULL" : $"{Validation.Hmac.Length} bytes")})";
}

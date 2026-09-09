using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_VerifySequenceComplete command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 20.3, Table 119): a single TPMT_TK_VERIFIED validation
/// ticket, tagged TPM_ST_MESSAGE_VERIFIED (TPM 2.0 Library Part 2, clause 10.6.5, Table 112) — the third
/// member of the validation-ticket family alongside <see cref="VerifySignatureResponse"/>'s TPM_ST_VERIFIED
/// ticket and <see cref="VerifyDigestSignatureResponse"/>'s TPM_ST_DIGEST_VERIFIED ticket. Unlike the
/// digest-verified ticket, this ticket's <see cref="TpmtTkVerified.Metadata"/> records no hash algorithm
/// (Table 111's <c>messageVerified</c> arm is <c>TPMS_EMPTY</c>): the equation binds the message itself, not
/// a digest of it. If the key is in the NULL hierarchy, the ticket is the NULL tuple for this tag —
/// hierarchy TPM_RH_NULL, empty hmac. On success the sequence context named by the request's
/// <c>sequenceHandle</c> is flushed from the TPM ({F}, TPM 2.0 Library Part 1, clause 29.4.6).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class VerifySequenceCompleteResponse: IDisposable, ITpmWireType
{
    /// <summary>Whether <see cref="Dispose"/> has already released <see cref="Validation"/>.</summary>
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the validation ticket proving the TPM verified the signature against the sequence's message.
    /// </summary>
    public TpmtTkVerified Validation { get; }

    /// <summary>
    /// Initializes a new instance with the specified validation ticket.
    /// </summary>
    /// <param name="validation">The validation ticket proving the TPM verified the signature against the sequence's message.</param>
    private VerifySequenceCompleteResponse(TpmtTkVerified validation)
    {
        Validation = validation;
    }

    /// <summary>
    /// Parses a TPM2_VerifySequenceComplete response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed verify-sequence-complete response.</returns>
    /// <exception cref="InvalidOperationException">The ticket's tag is not <c>TPM_ST_MESSAGE_VERIFIED</c> — Table 119 fixes it ("tag will be TPM_ST_MESSAGE_VERIFIED"), even though <see cref="TpmtTkVerified.Parse"/> itself admits all three Table 112 tags.</exception>
    public static VerifySequenceCompleteResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        TpmtTkVerified validation = TpmtTkVerified.Parse(ref reader, pool);

        if(validation.Tag != TpmStConstants.TPM_ST_MESSAGE_VERIFIED)
        {
            validation.Dispose();

            throw new InvalidOperationException(
                $"TPM2_VerifySequenceComplete() response ticket must be tagged TPM_ST_MESSAGE_VERIFIED, got {validation.Tag} (TPM 2.0 Library Part 3, clause 20.3, Table 119).");
        }

        return new VerifySequenceCompleteResponse(validation);
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
    private string DebuggerDisplay => $"VerifySequenceCompleteResponse(Hierarchy={Validation.Hierarchy}, {(Validation.IsNull ? "NULL" : $"{Validation.Hmac.Length} bytes")})";
}

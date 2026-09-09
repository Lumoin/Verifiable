using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response to the TPM2_SequenceComplete command: the completed sequence's digest or HMAC and the
/// <c>TPMT_TK_HASHCHECK</c> ticket that says whether the digest may be signed with a restricted key (TPM 2.0
/// Library Part 3, clause 17.8, Table 94).
/// </summary>
/// <remarks>
/// <see cref="Validation"/> is the NULL Ticket (hierarchy <c>TPM_RH_NULL</c>, empty digest) when the caller
/// asked for none (<c>hierarchy</c> = <c>TPM_RH_NULL</c>), when the sequence's first block was not safe to sign
/// (it began with <c>TPM_GENERATED_VALUE</c>, or held fewer than four octets), or when the sequence is an
/// HMAC sequence. A non-NULL ticket is consumed verbatim by <c>SignDigestInput.CreateForRestrictedKey</c>
/// (clause 20.7). Both carriers are owned by this response and released by <see cref="Dispose"/>.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SequenceCompleteResponse: IDisposable, ITpmWireType
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <summary>The digest or HMAC of the whole sequence (<c>result</c>, TPM2B_DIGEST).</summary>
    public Tpm2bDigest Result { get; }

    /// <summary>The hash-check ticket over <see cref="Result"/> (<c>validation</c>, TPMT_TK_HASHCHECK).</summary>
    public TpmtTkHashcheck Validation { get; }

    /// <summary>Initializes the response over its two owned carriers.</summary>
    /// <param name="result">The owned digest carrier.</param>
    /// <param name="validation">The owned ticket.</param>
    private SequenceCompleteResponse(Tpm2bDigest result, TpmtTkHashcheck validation)
    {
        Result = result;
        Validation = validation;
    }

    /// <summary>
    /// Parses the Table 94 response parameters: <c>result</c> (TPM2B_DIGEST) then <c>validation</c>
    /// (TPMT_TK_HASHCHECK).
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameter area.</param>
    /// <param name="pool">The memory pool the carriers are rented from.</param>
    /// <returns>The parsed response; the caller owns it.</returns>
    public static SequenceCompleteResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bDigest result = Tpm2bDigest.Parse(ref reader, pool);
        try
        {
            TpmtTkHashcheck validation = TpmtTkHashcheck.Parse(ref reader, pool);

            return new SequenceCompleteResponse(result, validation);
        }
        catch
        {
            //A truncated or malformed ticket must not orphan the digest rental already taken.
            result.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Result.Dispose();
            Validation.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"SequenceCompleteResponse(Result={Result.Size} bytes, Validation={(Validation.IsNull ? "NULL" : "present")})";
}

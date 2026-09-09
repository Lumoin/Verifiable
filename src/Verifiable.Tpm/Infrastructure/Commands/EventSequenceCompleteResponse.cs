using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response to the TPM2_EventSequenceComplete command: the tagged digests of the whole event, one per
/// implemented hash algorithm (TPM 2.0 Library Part 3, clause 17.9, Table 96).
/// </summary>
/// <remarks>
/// "Unlike TPM2_PCR_Event(), a digest is always returned for each implemented hash algorithm. There is no
/// option to only return digests for which pcrHandle is allocated" (clause 17.9.1). The list is owned by this
/// response and released by <see cref="Dispose"/>.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EventSequenceCompleteResponse: IDisposable, ITpmWireType
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <summary>The tagged digests computed for the PCR (<c>results</c>, TPML_DIGEST_VALUES).</summary>
    public TpmlDigestValues Results { get; }

    /// <summary>Initializes the response over its owned digest list.</summary>
    /// <param name="results">The owned digest list.</param>
    private EventSequenceCompleteResponse(TpmlDigestValues results)
    {
        Results = results;
    }

    /// <summary>
    /// Parses the Table 96 response parameter: <c>results</c> (TPML_DIGEST_VALUES).
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameter area.</param>
    /// <param name="pool">The memory pool the digest carriers are rented from.</param>
    /// <returns>The parsed response; the caller owns it.</returns>
    public static EventSequenceCompleteResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        TpmlDigestValues results = TpmlDigestValues.Parse(ref reader, pool);

        return new EventSequenceCompleteResponse(results);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Results.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"EventSequenceCompleteResponse(Results={Results.Count})";
}

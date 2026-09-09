using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response to the TPM2_PCR_Event command: the tagged digests of the event data, one per bank the TPM hashed
/// it under (TPM 2.0 Library Part 3, clause 22.3, Table 133).
/// </summary>
/// <remarks>
/// "On successful command completion, digests will contain the list of tagged digests of eventData that was
/// computed in preparation for extending the data into the PCR" (clause 22.3.1). The list is owned by this
/// response and released by <see cref="Dispose"/>.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PcrEventResponse: IDisposable, ITpmWireType
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <summary>The tagged digests of the event data (<c>digests</c>, TPML_DIGEST_VALUES).</summary>
    public TpmlDigestValues Digests { get; }

    /// <summary>Initializes the response over its owned digest list.</summary>
    /// <param name="digests">The owned digest list.</param>
    private PcrEventResponse(TpmlDigestValues digests)
    {
        Digests = digests;
    }

    /// <summary>
    /// Parses the Table 133 response parameter: <c>digests</c> (TPML_DIGEST_VALUES).
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameter area.</param>
    /// <param name="pool">The memory pool the digest carriers are rented from.</param>
    /// <returns>The parsed response; the caller owns it.</returns>
    public static PcrEventResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        TpmlDigestValues digests = TpmlDigestValues.Parse(ref reader, pool);

        return new PcrEventResponse(digests);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Digests.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"PcrEventResponse(Digests={Digests.Count})";
}

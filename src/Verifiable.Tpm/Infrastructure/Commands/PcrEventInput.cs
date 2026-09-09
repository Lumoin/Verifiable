using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PCR_Event command (CC = TPM_CC_PCR_Event, 0x0000013C).
/// </summary>
/// <remarks>
/// <para>
/// Has the TPM hash <see cref="EventData"/> under the algorithm of every bank in which the register
/// <see cref="PcrHandle"/> names is allocated, return the tagged digests, and — unless <c>pcrHandle</c> is
/// <c>TPM_RH_NULL</c> — extend the register with each bank's digest exactly as <c>TPM2_PCR_Extend()</c> would
/// (TPM 2.0 Library Part 3, clause 22.3.1). "A TPM shall support an eventData.size of zero through 1,024
/// inclusive"; an empty event still hashes and extends. Events larger than the buffer use the sequence commands
/// and <c>TPM2_EventSequenceComplete()</c> instead (Part 1, clause 14.4).
/// </para>
/// <para>
/// <see cref="PcrHandle"/> carries Auth Index 1 with Auth Role USER (Part 3, Table 132): the PCR's EmptyAuth on a PC
/// Client TPM (PTP 1.07, clause 4.7, item 5), exempt from dictionary-attack protection (Part 1, clause 14.7).
/// The register's attributes may forbid the extend at the command's locality (<c>TPM_RC_LOCALITY</c>).
/// </para>
/// <para>
/// Wire layout (Table 132): handle area <c>@pcrHandle</c> (TPMI_DH_PCR+); parameter <c>eventData</c>
/// (TPM2B_EVENT), the first parameter and a TPM2B, so encryptable. The command is <c>{NV}</c>.
/// </para>
/// <para>
/// See TPM 2.0 Library Part 3, clause 22.3, Table 132 - TPM2_PCR_Event.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PcrEventInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PCR_Event;

    /// <inheritdoc/>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// The register to extend (<c>pcrHandle</c>, TPMI_DH_PCR+), or <c>TPM_RH_NULL</c> to only compute the
    /// digests.
    /// </summary>
    public TpmiDhPcr PcrHandle { get; }

    /// <summary>
    /// The event to record (<c>eventData</c>, TPM2B_EVENT); owned by this input and released by
    /// <see cref="Dispose"/>.
    /// </summary>
    public Tpm2bEvent EventData { get; }

    /// <summary>
    /// Creates an input recording <paramref name="eventData"/> into <paramref name="pcrHandle"/>.
    /// </summary>
    /// <param name="pcrHandle">The register to extend, or <c>TPM_RH_NULL</c>.</param>
    /// <param name="eventData">The event octets, at most <see cref="Tpm2bEvent.MaxSize"/>.</param>
    /// <param name="pool">The memory pool the event carrier is rented from.</param>
    /// <returns>The command input.</returns>
    /// <exception cref="ArgumentException"><paramref name="eventData"/> is longer than <see cref="Tpm2bEvent.MaxSize"/>.</exception>
    public static PcrEventInput Create(TpmiDhPcr pcrHandle, ReadOnlySpan<byte> eventData, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bEvent carrier = Tpm2bEvent.Create(eventData, pool);

        return new PcrEventInput(pcrHandle, carrier);
    }

    /// <summary>
    /// Initializes the input over an owned event carrier.
    /// </summary>
    /// <param name="pcrHandle">The register to extend.</param>
    /// <param name="eventData">The owned event carrier.</param>
    private PcrEventInput(TpmiDhPcr pcrHandle, Tpm2bEvent eventData)
    {
        PcrHandle = pcrHandle;
        EventData = eventData;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +             //pcrHandle (TPMI_DH_PCR+).
               EventData.SerializedSize;  //eventData (TPM2B_EVENT).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        PcrHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        EventData.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            EventData.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"PcrEventInput(PcrHandle=0x{PcrHandle.Value:X8}, EventData={EventData.Length} bytes)";
}

using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Load command - loads an object created by TPM2_Create into a transient slot.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_Load presents a parent-wrapped private blob and its public area to the parent that produced them;
/// the TPM unwraps the sensitive area into a transient object and returns a handle plus the object Name.
/// The transient object is released with <c>TPM2_FlushContext()</c> (or on the next TPM Reset); the TPM
/// holds nothing durable.
/// </para>
/// <para>
/// <b>Command structure:</b>
/// </para>
/// <code>
/// TPMI_ST_COMMAND_TAG  tag             TPM_ST_SESSIONS
/// UINT32               commandSize
/// TPM_CC               commandCode     TPM_CC_Load
/// TPMI_DH_OBJECT       @parentHandle   Loaded parent (storage) key (requires authorization)
/// TPM2B_PRIVATE        inPrivate       The parent-wrapped private blob
/// TPM2B_PUBLIC         inPublic        The public area
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 3, Section 12.2 (Table 22).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class LoadInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Load;

    /// <summary>
    /// Gets the handle of the loaded parent that wrapped the object (Auth Index 1, Auth Role USER).
    /// </summary>
    public uint ParentHandle { get; }

    /// <summary>
    /// Gets the parent-wrapped private blob to load (the <c>outPrivate</c> of a prior TPM2_Create).
    /// </summary>
    public Tpm2bPrivate InPrivate { get; }

    /// <summary>
    /// Gets the public area of the object to load.
    /// </summary>
    public Tpm2bPublic InPublic { get; }

    /// <summary>
    /// Initializes a new Load input.
    /// </summary>
    /// <param name="parentHandle">The loaded parent key handle.</param>
    /// <param name="inPrivate">The parent-wrapped private blob; disposed with this instance.</param>
    /// <param name="inPublic">The public area; disposed with this instance.</param>
    public LoadInput(uint parentHandle, Tpm2bPrivate inPrivate, Tpm2bPublic inPublic)
    {
        ArgumentNullException.ThrowIfNull(inPrivate);
        ArgumentNullException.ThrowIfNull(inPublic);

        ParentHandle = parentHandle;
        InPrivate = inPrivate;
        InPublic = inPublic;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return sizeof(uint)                  //parentHandle.
            + InPrivate.SerializedSize
            + InPublic.GetSerializedSize();
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt32(ParentHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        InPrivate.WriteTo(ref writer);
        InPublic.WriteTo(ref writer);
    }

    /// <summary>
    /// Releases resources owned by this input.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            InPrivate.Dispose();
            InPublic.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"LoadInput(parent=0x{ParentHandle:X8}, private={InPrivate.Length} bytes)";
}

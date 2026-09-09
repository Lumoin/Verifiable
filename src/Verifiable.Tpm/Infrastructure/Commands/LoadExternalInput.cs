using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_LoadExternal command - loads a public area alone, or a public area with an unencrypted
/// sensitive area, as a Temporary Object not associated with a Storage Parent's wrap.
/// </summary>
/// <remarks>
/// <para>
/// Unlike TPM2_Load, TPM2_LoadExternal carries no command handle at all: the object arrives already in the
/// clear (no parent-wrapped private blob to unwrap), and the caller names the hierarchy the object joins as a
/// parameter, not a handle. If both the public and sensitive portions are supplied, the hierarchy is required to
/// be TPM_RH_NULL (TPM 2.0 Library Part 3, clause 12.3.1). The loaded object is a Temporary Object, released
/// with <c>TPM2_FlushContext()</c> (or the next TPM Reset); the TPM holds nothing durable.
/// </para>
/// <para>
/// <b>Command structure:</b>
/// </para>
/// <code>
/// TPMI_ST_COMMAND_TAG  tag             TPM_ST_NO_SESSIONS, or TPM_ST_SESSIONS over the zero-handle table
/// UINT32               commandSize
/// TPM_CC               commandCode     TPM_CC_LoadExternal
/// TPM2B_SENSITIVE      inPrivate       The sensitive area, or size zero for a public-only load
/// TPM2B_PUBLIC+        inPublic        The public area (nameAlg = TPM_ALG_NULL admitted)
/// TPMI_RH_HIERARCHY    hierarchy       The hierarchy the object is associated with
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 3, clause 12.3 (Table 22).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class LoadExternalInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already released the owned public and sensitive areas.</summary>
    private bool disposed;

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_LoadExternal;

    /// <summary>
    /// Gets the sensitive area to load, or <see langword="null"/> for the public-only form.
    /// </summary>
    public TpmtSensitive? InPrivate { get; }

    /// <summary>
    /// Gets the public area to load.
    /// </summary>
    public Tpm2bPublic InPublic { get; }

    /// <summary>
    /// Gets the hierarchy the object is associated with (<c>TPM_RH_NULL</c> required when <see cref="InPrivate"/>
    /// is not <see langword="null"/>).
    /// </summary>
    public TpmiRhHierarchy Hierarchy { get; }

    /// <summary>
    /// Initializes a new LoadExternal input.
    /// </summary>
    /// <param name="inPrivate">The sensitive area, or <see langword="null"/> for a public-only load; disposed with this instance.</param>
    /// <param name="inPublic">The public area; disposed with this instance.</param>
    /// <param name="hierarchy">The hierarchy the object is associated with.</param>
    public LoadExternalInput(TpmtSensitive? inPrivate, Tpm2bPublic inPublic, TpmiRhHierarchy hierarchy)
    {
        ArgumentNullException.ThrowIfNull(inPublic);

        InPrivate = inPrivate;
        InPublic = inPublic;
        Hierarchy = hierarchy;
    }

    /// <summary>
    /// Creates a public-only LoadExternal input — <c>inPrivate</c> frames as the empty (size-zero) buffer.
    /// </summary>
    /// <param name="inPublic">The public area; disposed with the returned instance.</param>
    /// <param name="hierarchy">The hierarchy the object is associated with.</param>
    /// <returns>The public-only input.</returns>
    public static LoadExternalInput PublicOnly(Tpm2bPublic inPublic, TpmiRhHierarchy hierarchy) =>
        new(null, inPublic, hierarchy);

    /// <inheritdoc/>
    /// <remarks>
    /// <c>inPrivate</c> (<c>TPM2B_SENSITIVE</c>) is the command's first parameter and is a sized buffer, so it is
    /// eligible for session-based decrypt parameter encryption (TPM 2.0 Library Part 1, clause 18.1;
    /// Part 3, clause 12.3, Table 22's zero-handle session table).
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //inPrivate: a UINT16 size prefix (0 for a public-only load) plus the marshaled TPMT_SENSITIVE when present.
        int inPrivateSize = sizeof(ushort) + (InPrivate?.SerializedSize ?? 0);

        return inPrivateSize
            + InPublic.GetSerializedSize()
            + sizeof(uint); //hierarchy.
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //TPM2_LoadExternal() carries no command handle at all — hierarchy travels as a parameter.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(InPrivate is null)
        {
            writer.WriteUInt16(0);
        }
        else
        {
            writer.WriteUInt16((ushort)InPrivate.SerializedSize);
            InPrivate.WriteTo(ref writer);
        }

        InPublic.WriteTo(ref writer);
        writer.WriteUInt32(Hierarchy.Value);
    }

    /// <summary>
    /// Releases resources owned by this input.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            InPrivate?.Dispose();
            InPublic.Dispose();
            disposed = true;
        }
    }

    /// <summary>The debugger text this type's <see cref="DebuggerDisplayAttribute"/> names: the form and the hierarchy.</summary>
    private string DebuggerDisplay => $"LoadExternalInput(private={(InPrivate is null ? "none" : "present")}, hierarchy=0x{Hierarchy.Value:X8})";
}

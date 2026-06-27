using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Create command - creates an ordinary object under a loaded parent.
/// </summary>
/// <remarks>
/// <para>
/// Unlike <c>TPM2_CreatePrimary()</c>, which derives a key deterministically from a hierarchy seed,
/// <c>TPM2_Create()</c> creates a fresh object under a loaded parent (a restricted storage key) and
/// returns it as an opaque, parent-wrapped private blob (<c>outPrivate</c>) plus its public area. The
/// TPM stores nothing: the caller persists the blob and reloads it with <c>TPM2_Load()</c> per use. This
/// is the path for minting many distinct, non-extractable per-key objects without consuming scarce TPM
/// storage.
/// </para>
/// <para>
/// <b>Command structure:</b>
/// </para>
/// <code>
/// TPMI_ST_COMMAND_TAG    tag             TPM_ST_SESSIONS
/// UINT32                 commandSize
/// TPM_CC                 commandCode     TPM_CC_Create
/// TPMI_DH_OBJECT         @parentHandle   Loaded parent (storage) key (requires authorization)
/// TPM2B_SENSITIVE_CREATE inSensitive     Sensitive data (userAuth, data)
/// TPM2B_PUBLIC           inPublic        Public template
/// TPM2B_DATA             outsideInfo     External data for creation linkage
/// TPML_PCR_SELECTION     creationPCR     PCRs to include in creation data
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 3, Section 12.1 (Table 19).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CreateInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Create;

    /// <summary>
    /// Gets the handle of the loaded parent under which the object is created.
    /// </summary>
    /// <remarks>
    /// The parent must be a loaded restricted storage key (Auth Index 1, Auth Role USER). It is a
    /// transient or persistent object handle, not a hierarchy handle.
    /// </remarks>
    public uint ParentHandle { get; }

    /// <summary>
    /// Gets the sensitive data for object creation (the new object's authValue and any seed data).
    /// </summary>
    public Tpm2bSensitiveCreate InSensitive { get; }

    /// <summary>
    /// Gets the public template for the object.
    /// </summary>
    public Tpm2bPublic InPublic { get; }

    /// <summary>
    /// Gets the external data to include in creation data.
    /// </summary>
    public Tpm2bData OutsideInfo { get; }

    /// <summary>
    /// Gets the PCR selection for creation data.
    /// </summary>
    public TpmlPcrSelection CreationPcr { get; }

    /// <summary>
    /// Initializes a new Create input.
    /// </summary>
    /// <param name="parentHandle">The loaded parent key handle.</param>
    /// <param name="inSensitive">The sensitive data; disposed with this instance.</param>
    /// <param name="inPublic">The public template; disposed with this instance.</param>
    /// <param name="outsideInfo">External linkage data; disposed with this instance.</param>
    /// <param name="creationPcr">PCR selection; disposed with this instance.</param>
    public CreateInput(
        uint parentHandle,
        Tpm2bSensitiveCreate inSensitive,
        Tpm2bPublic inPublic,
        Tpm2bData outsideInfo,
        TpmlPcrSelection creationPcr)
    {
        ArgumentNullException.ThrowIfNull(inSensitive);
        ArgumentNullException.ThrowIfNull(inPublic);
        ArgumentNullException.ThrowIfNull(outsideInfo);
        ArgumentNullException.ThrowIfNull(creationPcr);

        ParentHandle = parentHandle;
        InSensitive = inSensitive;
        InPublic = inPublic;
        OutsideInfo = outsideInfo;
        CreationPcr = creationPcr;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return sizeof(uint)                  //parentHandle.
            + InSensitive.SerializedSize
            + InPublic.GetSerializedSize()
            + OutsideInfo.SerializedSize
            + CreationPcr.GetSerializedSize();
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

        InSensitive.WriteTo(ref writer);
        InPublic.WriteTo(ref writer);
        OutsideInfo.WriteTo(ref writer);
        CreationPcr.WriteTo(ref writer);
    }

    /// <summary>
    /// Creates a <see cref="CreateInput"/> for an ECC signing child key under a loaded storage parent.
    /// </summary>
    /// <param name="parentHandle">The loaded storage-parent handle.</param>
    /// <param name="password">Optional authValue for the new key (<see langword="null"/> for none).</param>
    /// <param name="curve">The ECC curve.</param>
    /// <param name="scheme">The signing scheme.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    public static CreateInput ForEccSigningChild(
        uint parentHandle,
        string? password,
        TpmEccCurveConstants curve,
        TpmtEccScheme scheme,
        MemoryPool<byte> pool)
    {
        TpmaObject objectAttributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT;

        Tpm2bSensitiveCreate inSensitive = string.IsNullOrEmpty(password)
            ? Tpm2bSensitiveCreate.CreateEmpty(pool)
            : Tpm2bSensitiveCreate.WithPassword(password, pool);

        Tpm2bPublic inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            objectAttributes,
            curve,
            scheme);

        return new CreateInput(parentHandle, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
    }

    /// <summary>
    /// Releases resources owned by this input.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            InSensitive.Dispose();
            InPublic.Dispose();
            OutsideInfo.Dispose();
            CreationPcr.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"CreateInput(parent=0x{ParentHandle:X8}, {InPublic.PublicArea.Type})";
}

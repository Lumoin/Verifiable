using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Spec.Commands;

/// <summary>
/// TPM2_CreatePrimary command.
/// </summary>
/// <remarks>
/// <para>
/// This command creates a primary key in a hierarchy. The key is derived from the
/// hierarchy's primary seed and the template parameters - calling with identical
/// parameters always produces the same key.
/// </para>
/// <para>
/// <b>Command structure:</b>
/// </para>
/// <code>
/// TPMI_ST_COMMAND_TAG    tag             TPM_ST_SESSIONS
/// UINT32                 commandSize
/// TPM_CC                 commandCode     TPM_CC_CreatePrimary
/// TPMI_RH_HIERARCHY      @primaryHandle  Hierarchy handle (requires authorization)
/// TPM2B_SENSITIVE_CREATE inSensitive     Sensitive data (userAuth, data)
/// TPM2B_PUBLIC           inPublic        Public template
/// TPM2B_DATA             outsideInfo     External data for creation linkage
/// TPML_PCR_SELECTION     creationPCR     PCRs to include in creation data
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 3, Section 24.1, Table 174.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2CreatePrimaryCommand: IDisposable
{
    /// <summary>
    /// Command code for TPM2_CreatePrimary.
    /// </summary>
    public const TpmCcConstants CommandCode = TpmCcConstants.TPM_CC_CreatePrimary;

    private bool disposed;

    /// <summary>
    /// Gets the hierarchy in which to create the primary key.
    /// </summary>
    /// <remarks>
    /// Valid values: TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_NULL.
    /// This handle requires authorization (Auth Index 1, Auth Role USER).
    /// </remarks>
    public TpmRh PrimaryHandle { get; }

    /// <summary>
    /// Gets the sensitive data for key creation.
    /// </summary>
    /// <remarks>
    /// Contains userAuth (password for the new key) and optional data
    /// (symmetric key material or seed for derivation).
    /// </remarks>
    public Tpm2bSensitiveCreate InSensitive { get; }

    /// <summary>
    /// Gets the public template for the key.
    /// </summary>
    /// <remarks>
    /// Defines the key type, algorithm, attributes, and policy.
    /// For primary keys, the unique field should be empty (TPM generates it).
    /// </remarks>
    public Tpm2bPublic InPublic { get; }

    /// <summary>
    /// Gets the external data to include in creation data.
    /// </summary>
    /// <remarks>
    /// Provides permanent, verifiable linkage between this object and
    /// some external owner data. Can be empty.
    /// </remarks>
    public Tpm2bData OutsideInfo { get; }

    /// <summary>
    /// Gets the PCR selection for creation data.
    /// </summary>
    /// <remarks>
    /// PCR values to include in the creation data. The TPM captures
    /// current PCR values at creation time.
    /// </remarks>
    public TpmlPcrSelection CreationPcr { get; }

    /// <summary>
    /// Initializes a new CreatePrimary command.
    /// </summary>
    /// <param name="primaryHandle">The hierarchy handle.</param>
    /// <param name="inSensitive">The sensitive data.</param>
    /// <param name="inPublic">The public template.</param>
    /// <param name="outsideInfo">External linkage data.</param>
    /// <param name="creationPcr">PCR selection.</param>
    public Tpm2CreatePrimaryCommand(
        TpmRh primaryHandle,
        Tpm2bSensitiveCreate inSensitive,
        Tpm2bPublic inPublic,
        Tpm2bData outsideInfo,
        TpmlPcrSelection creationPcr)
    {
        PrimaryHandle = primaryHandle;
        InSensitive = inSensitive;
        InPublic = inPublic;
        OutsideInfo = outsideInfo;
        CreationPcr = creationPcr;
    }

    /// <summary>
    /// Gets the size of the command parameters (excluding header and auth).
    /// </summary>
    public int GetParametersSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return InSensitive.SerializedSize +
               InPublic.GetSerializedSize() +
               OutsideInfo.SerializedSize +
               CreationPcr.GetSerializedSize();
    }

    /// <summary>
    /// Writes the command parameters to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <remarks>
    /// This writes only the parameters portion. The command header and
    /// authorization area must be written separately.
    /// </remarks>
    public void WriteParametersTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        InSensitive.WriteTo(ref writer);
        InPublic.WriteTo(ref writer);
        OutsideInfo.WriteTo(ref writer);
        CreationPcr.WriteTo(ref writer);
    }

    /// <summary>
    /// Releases resources owned by this command.
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

    private string DebuggerDisplay => $"TPM2_CreatePrimary({PrimaryHandle}, {InPublic.PublicArea.Type})";
}
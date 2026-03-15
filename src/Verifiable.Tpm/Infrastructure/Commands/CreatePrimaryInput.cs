using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_CreatePrimary command.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_CreatePrimary creates a primary key in a hierarchy. The key is derived
/// deterministically from the hierarchy's primary seed and the template parameters.
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
public sealed class CreatePrimaryInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_CreatePrimary;

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
    public Tpm2bSensitiveCreate InSensitive { get; }

    /// <summary>
    /// Gets the public template for the key.
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
    /// Initializes a new CreatePrimary input.
    /// </summary>
    /// <param name="primaryHandle">The hierarchy handle.</param>
    /// <param name="inSensitive">The sensitive data.</param>
    /// <param name="inPublic">The public template.</param>
    /// <param name="outsideInfo">External linkage data.</param>
    /// <param name="creationPcr">PCR selection.</param>
    public CreatePrimaryInput(
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

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return sizeof(uint) + // primaryHandle
               InSensitive.SerializedSize +
               InPublic.GetSerializedSize() +
               OutsideInfo.SerializedSize +
               CreationPcr.GetSerializedSize();
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt32((uint)PrimaryHandle);
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
    /// Creates a CreatePrimary input for an ECC signing key.
    /// </summary>
    /// <param name="hierarchy">The hierarchy (typically TPM_RH_OWNER or TPM_RH_ENDORSEMENT).</param>
    /// <param name="password">Optional password for the key (null for no password).</param>
    /// <param name="curve">The ECC curve.</param>
    /// <param name="scheme">The signing scheme.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    public static CreatePrimaryInput ForEccSigningKey(
        TpmRh hierarchy,
        string? password,
        TpmEccCurveConstants curve,
        TpmtEccScheme scheme,
        MemoryPool<byte> pool)
    {
        var objectAttributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT;

        var inSensitive = string.IsNullOrEmpty(password)
            ? Tpm2bSensitiveCreate.CreateEmpty(pool)
            : Tpm2bSensitiveCreate.WithPassword(password, pool);

        var inPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            objectAttributes,
            curve,
            scheme);

        var outsideInfo = Tpm2bData.Empty;
        var creationPcr = TpmlPcrSelection.Empty;

        return new CreatePrimaryInput(hierarchy, inSensitive, inPublic, outsideInfo, creationPcr);
    }

    /// <summary>
    /// Creates a CreatePrimary input for an RSA signing key.
    /// </summary>
    /// <param name="hierarchy">The hierarchy (typically TPM_RH_OWNER or TPM_RH_ENDORSEMENT).</param>
    /// <param name="password">Optional password for the key (null for no password).</param>
    /// <param name="keyBits">Key size in bits (typically 2048).</param>
    /// <param name="scheme">The signing scheme.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The command input.</returns>
    public static CreatePrimaryInput ForRsaSigningKey(
        TpmRh hierarchy,
        string? password,
        ushort keyBits,
        TpmtRsaScheme scheme,
        MemoryPool<byte> pool)
    {
        var objectAttributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT;

        var inSensitive = string.IsNullOrEmpty(password)
            ? Tpm2bSensitiveCreate.CreateEmpty(pool)
            : Tpm2bSensitiveCreate.WithPassword(password, pool);

        var inPublic = Tpm2bPublic.CreateRsaSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            objectAttributes,
            keyBits,
            scheme);

        var outsideInfo = Tpm2bData.Empty;
        var creationPcr = TpmlPcrSelection.Empty;

        return new CreatePrimaryInput(hierarchy, inSensitive, inPublic, outsideInfo, creationPcr);
    }


    /// <summary>
    /// Creates a <see cref="CreatePrimaryInput"/> for generating an ECC ECDH key agreement key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Creates a key suitable for use as the SECDSA blinding key aU held by the WSCA.
    /// The key uses a null scheme with the DECRYPT attribute, producing a raw EC point
    /// when TPM2_ECDH_ZGen is called.
    /// </para>
    /// <para>
    /// Key differences from <see cref="ForEccSigningKey"/>:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>Object attributes include <see cref="TpmaObject.DECRYPT"/> instead of <see cref="TpmaObject.SIGN_ENCRYPT"/>.</description></item>
    ///   <item><description>Scheme is TPM_ALG_NULL — unrestricted decryption key per TPM 2.0 Part 2, Section 12.2.3.5.</description></item>
    ///   <item><description>KDF is TPM_ALG_NULL — raw point output required for SECDSA protocol math.</description></item>
    /// </list>
    /// </remarks>
    /// <param name="hierarchy">The hierarchy under which to create the primary key.</param>
    /// <param name="authPassword">The authorization password, or <see langword="null"/> for no password.</param>
    /// <param name="curve">The ECC curve. Use <see cref="TpmEccCurveConstants.TPM_ECC_NIST_P256"/> for SECDSA.</param>
    /// <param name="pool">The memory pool for password buffer allocation.</param>
    /// <returns>A <see cref="CreatePrimaryInput"/> configured for ECDH key agreement.</returns>
    public static CreatePrimaryInput ForEccKeyAgreementKey(
        TpmRh hierarchy,
        string? authPassword,
        TpmEccCurveConstants curve,
        MemoryPool<byte> pool)
    {
        var inSensitive = string.IsNullOrEmpty(authPassword)
            ? Tpm2bSensitiveCreate.CreateEmpty(pool)
            : Tpm2bSensitiveCreate.WithPassword(authPassword, pool);

        var inPublic = Tpm2bPublic.CreateEccKeyAgreementTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            curve);

        return new CreatePrimaryInput(hierarchy, inSensitive, inPublic, Tpm2bData.Empty, TpmlPcrSelection.Empty);
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

    private string DebuggerDisplay => $"CreatePrimaryInput({PrimaryHandle}, {InPublic.PublicArea.Type})";
}

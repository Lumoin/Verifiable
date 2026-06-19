using System;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_DefineSpace - reserves space for an NV Index with the given public area and
/// authorization value.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> @authHandle (TPMI_RH_PROVISION) - <c>TPM_RH_OWNER</c> or
/// <c>TPM_RH_PLATFORM</c>; authorized with USER role (1 handle).
/// </para>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>auth (TPM2B_AUTH) - the authorization value for the new Index.</description></item>
///   <item><description>publicInfo (TPM2B_NV_PUBLIC) - the public parameters of the NV area.</description></item>
/// </list>
/// <para>
/// This command is authorized, so it is sent with <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library Part 3,
/// Section 31.3 (Table 228). The instance does not own <paramref name="auth"/> / <paramref name="publicInfo"/>
/// caller-supplied buffers beyond the disposal it performs.
/// </para>
/// </remarks>
public sealed class NvDefineSpaceInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    /// <summary>Gets the provisioning hierarchy that authorizes the definition.</summary>
    public TpmRh AuthHandle { get; }

    /// <summary>Gets the authorization value assigned to the new NV Index.</summary>
    public Tpm2bAuth Auth { get; }

    /// <summary>Gets the public area of the NV Index to define.</summary>
    public TpmsNvPublic PublicInfo { get; }

    /// <summary>
    /// Initializes a new define-space input.
    /// </summary>
    /// <param name="authHandle">The provisioning hierarchy (owner or platform).</param>
    /// <param name="auth">The new Index's authorization value; disposed with this instance.</param>
    /// <param name="publicInfo">The NV public area; disposed with this instance.</param>
    public NvDefineSpaceInput(TpmRh authHandle, Tpm2bAuth auth, TpmsNvPublic publicInfo)
    {
        ArgumentNullException.ThrowIfNull(auth);
        ArgumentNullException.ThrowIfNull(publicInfo);

        AuthHandle = authHandle;
        Auth = auth;
        PublicInfo = publicInfo;
    }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_DefineSpace;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)                                  //authHandle.
        + Auth.SerializedSize                         //auth (TPM2B_AUTH).
        + sizeof(ushort) + PublicInfo.SerializedSize; //publicInfo (TPM2B_NV_PUBLIC = size prefix + TPMS_NV_PUBLIC).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)AuthHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        Auth.WriteTo(ref writer);

        //publicInfo is wrapped in a TPM2B_NV_PUBLIC: a UINT16 size prefix around the TPMS_NV_PUBLIC.
        writer.WriteUInt16((ushort)PublicInfo.SerializedSize);
        PublicInfo.WriteTo(ref writer);
    }

    /// <summary>
    /// Releases the authorization value and public area.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Auth.Dispose();
            PublicInfo.Dispose();
            disposed = true;
        }
    }
}

using System;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_ChangeAuth - atomically replaces the authorization value (authValue) of an NV Index.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (1 handle):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@nvIndex (TPMI_RH_NV_INDEX) - the NV Index whose authValue is replaced; Auth Index: 1,
///   Auth Role: ADMIN. Unlike every other sessioned NV command, the Index itself is the sole authorized
///   handle - there is no separate provisioning <c>@authHandle</c>.</description></item>
/// </list>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>newAuth (TPM2B_AUTH) - the replacement authorization value; the command's only
///   parameter, and therefore also its first.</description></item>
/// </list>
/// <para>
/// ADMIN role on an NV Index has no authValue fallback: this command requires that a policy session be used
/// for authorization of <c>nvIndex</c>, with the policy session's <c>commandCode</c> set to
/// <c>TPM_CC_NV_ChangeAuth</c> (TPM 2.0 Library Part 1, Section 17.2; Section 35.2.3). A password or HMAC
/// session on <c>nvIndex</c> can never authorize this command. This command is authorized, so it is sent with
/// <c>TPM_ST_SESSIONS</c>. Rotation never perturbs the Index's Name (authValue is outside TPMS_NV_PUBLIC). See
/// TPM 2.0 Library Part 3, Section 31.15 (Table 252/253).
/// </para>
/// </remarks>
public sealed class NvChangeAuthInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    /// <summary>Gets the handle of the NV Index whose authorization value is replaced.</summary>
    public uint NvIndex { get; }

    /// <summary>Gets the replacement authorization value.</summary>
    public Tpm2bAuth NewAuth { get; }

    /// <summary>
    /// Initializes a new change-auth input.
    /// </summary>
    /// <param name="nvIndex">The NV Index to rotate.</param>
    /// <param name="newAuth">The replacement authorization value; disposed with this instance.</param>
    public NvChangeAuthInput(uint nvIndex, Tpm2bAuth newAuth)
    {
        ArgumentNullException.ThrowIfNull(newAuth);

        NvIndex = nvIndex;
        NewAuth = newAuth;
    }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_ChangeAuth;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>newAuth</c> is the command's sole parameter, so it is trivially the first sized parameter and is
    /// eligible for session-based parameter encryption (TPM 2.0 Library Part 1, Section 19.1). This is the
    /// highest-value confidentiality target in the whole NV command family: unlike a one-time definition
    /// value, <c>newAuth</c> is a secret that may be rotated repeatedly over the Index's lifetime.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)               //nvIndex.
        + NewAuth.SerializedSize;  //newAuth (TPM2B_AUTH).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(NvIndex);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        NewAuth.WriteTo(ref writer);
    }

    /// <summary>
    /// Releases the replacement authorization value.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            NewAuth.Dispose();
            disposed = true;
        }
    }
}

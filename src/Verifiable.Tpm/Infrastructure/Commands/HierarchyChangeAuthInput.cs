using System;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_HierarchyChangeAuth - replaces the authorization value of a hierarchy or the lockout entity,
/// authorized by the current value of that same authorization.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (1 handle):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@authHandle (TPMI_RH_HIERARCHY_AUTH) - <c>TPM_RH_LOCKOUT</c>, <c>TPM_RH_ENDORSEMENT</c>,
///   <c>TPM_RH_OWNER</c>, or <c>TPM_RH_PLATFORM</c>; Auth Index: 1, Auth Role: USER. Selects which of
///   lockoutAuth/endorsementAuth/ownerAuth/platformAuth is replaced.</description></item>
/// </list>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>newAuth (TPM2B_AUTH) - the replacement authorization value; the command's only
///   parameter, and therefore also its first.</description></item>
/// </list>
/// <para>
/// The replacement value is bounded by the digest size of the hash algorithm used for context integrity, not by
/// a per-hierarchy nameAlg (hierarchies have none) - TPM 2.0 Library Part 1, Section 17.6.4.2. The response HMAC
/// keys on <c>newAuth</c>, not the pre-change auth (TPM 2.0 Library Part 3, Section 24.8.1's closing sentence),
/// mirroring TPM2_NV_ChangeAuth's own response-HMAC swap. This command is authorized, so it is sent with
/// <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library Part 3, Section 24.8 (Table 188/189).
/// </para>
/// </remarks>
public sealed class HierarchyChangeAuthInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    /// <summary>Gets the hierarchy (or lockout) handle whose authorization value is replaced.</summary>
    public TpmRh AuthHandle { get; }

    /// <summary>Gets the replacement authorization value.</summary>
    public Tpm2bAuth NewAuth { get; }

    /// <summary>
    /// Initializes a new hierarchy change-auth input.
    /// </summary>
    /// <param name="authHandle">The hierarchy or lockout handle to rotate.</param>
    /// <param name="newAuth">The replacement authorization value; disposed with this instance.</param>
    public HierarchyChangeAuthInput(TpmRh authHandle, Tpm2bAuth newAuth)
    {
        ArgumentNullException.ThrowIfNull(newAuth);

        AuthHandle = authHandle;
        NewAuth = newAuth;
    }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_HierarchyChangeAuth;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>newAuth</c> is the command's sole parameter, so it is trivially the first sized parameter and is
    /// eligible for session-based parameter encryption (TPM 2.0 Library Part 1, Section 19.1). A separate
    /// decrypt session is the intended path for this value, mirroring the pinned-secret rotation shape already
    /// used for NV authValue rotation.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)               //authHandle.
        + NewAuth.SerializedSize;  //newAuth (TPM2B_AUTH).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)AuthHandle);
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

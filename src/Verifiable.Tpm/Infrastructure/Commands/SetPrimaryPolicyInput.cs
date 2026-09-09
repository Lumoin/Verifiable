using System;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_SetPrimaryPolicy command (TPM 2.0 Library Part 3, clause 24.3). Sets the authorization
/// policy digest (and its hash algorithm) associated with a hierarchy or the lockout entity.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> <c>@authHandle</c> (<c>TPMI_RH_HIERARCHY_POLICY</c>) - <c>TPM_RH_LOCKOUT</c>,
/// <c>TPM_RH_ENDORSEMENT</c>, <c>TPM_RH_OWNER</c>, or <c>TPM_RH_PLATFORM</c>; authorized with USER role (1
/// handle). This is the only one of the five hierarchy commands' handle-interface types that also admits
/// <c>TPMI_RH_ACT</c>, which this codebase does not model. The caller supplies the authorizing session
/// separately (via <c>TpmCommandExecutor</c>'s session list); this type carries only the handle and the new
/// policy.
/// </para>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description><c>authPolicy</c> (TPM2B_DIGEST) - the new authorization policy digest, or the Empty
///   Buffer to disable policy-based authorization for the target.</description></item>
///   <item><description><c>hashAlg</c> (TPMI_ALG_HASH+) - the hash algorithm <c>authPolicy</c> was computed
///   with; <c>TPM_ALG_NULL</c> if and only if <c>authPolicy</c> is the Empty Buffer.</description></item>
/// </list>
/// <para>
/// If the enable associated with <c>authHandle</c> is not SET, the TPM returns <c>TPM_RC_HIERARCHY</c>; if
/// <c>hashAlg</c> is not <c>TPM_ALG_NULL</c> and <c>authPolicy</c>'s size does not match that algorithm's digest
/// size, the TPM returns <c>TPM_RC_SIZE</c> (TPM 2.0 Library Part 3, clause 24.3.1). This command is
/// authorized, so it is sent with <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library Part 3, clause 24.3 (Table
/// 195/196).
/// </para>
/// </remarks>
public sealed class SetPrimaryPolicyInput: ITpmCommandInput, IDisposable
{
    private bool disposed;

    /// <summary>Gets the hierarchy (or lockout) handle whose policy is replaced.</summary>
    public TpmRh AuthHandle { get; }

    /// <summary>Gets the new authorization policy digest, or the Empty Buffer to disable policy authorization.</summary>
    public Tpm2bDigest AuthPolicy { get; }

    /// <summary>Gets the hash algorithm <see cref="AuthPolicy"/> was computed with.</summary>
    public TpmAlgIdConstants HashAlg { get; }

    /// <summary>
    /// Initializes a new set-primary-policy input.
    /// </summary>
    /// <param name="authHandle">The hierarchy or lockout handle whose policy is replaced.</param>
    /// <param name="authPolicy">The new policy digest; disposed with this instance.</param>
    /// <param name="hashAlg">The hash algorithm <paramref name="authPolicy"/> was computed with.</param>
    public SetPrimaryPolicyInput(TpmRh authHandle, Tpm2bDigest authPolicy, TpmAlgIdConstants hashAlg)
    {
        ArgumentNullException.ThrowIfNull(authPolicy);

        AuthHandle = authHandle;
        AuthPolicy = authPolicy;
        HashAlg = hashAlg;
    }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_SetPrimaryPolicy;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)                  //authHandle.
        + AuthPolicy.SerializedSize   //authPolicy (TPM2B_DIGEST).
        + sizeof(ushort);             //hashAlg (TPMI_ALG_HASH+).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)AuthHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        AuthPolicy.WriteTo(ref writer);
        writer.WriteUInt16((ushort)HashAlg);
    }

    /// <summary>
    /// Releases the policy digest.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            AuthPolicy.Dispose();
            disposed = true;
        }
    }
}

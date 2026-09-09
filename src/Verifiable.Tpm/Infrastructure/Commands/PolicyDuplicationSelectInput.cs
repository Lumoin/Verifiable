using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyDuplicationSelect command (CC = 0x00000188).
/// </summary>
/// <remarks>
/// <para>
/// Qualifies a duplication to a selected new parent — and, when <see cref="IsObjectIncluded"/> is SET, to a
/// selected object as well: the session's nameHash becomes <c>H(objectName.name || newParentName.name)</c>, its
/// commandCode becomes <c>TPM_CC_Duplicate</c>, and its policyDigest is updated as
/// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyDuplicationSelect || [objectName.name ||] newParentName.name || includeObject)</c>
/// (TPM 2.0 Library Part 3, clause 23.15); see <see cref="TpmPolicyDigest.ExtendForDuplicationSelect"/>. The object Name
/// is normally unknowable when the object's own policy is written (the Name covers the policy), so
/// <see cref="IsObjectIncluded"/> is CLEAR unless the assertion is approved through TPM2_PolicyAuthorize by an
/// authority that knows both Names. The TPM refuses the assertion with TPM_RC_CPHASH when the session's shared
/// cpHash slot is already occupied and with TPM_RC_COMMAND_CODE when its commandCode is already set.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 23.15, Table 168):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>objectName (TPM2B_NAME): The Name of the object to be duplicated.</description></item>
///   <item><description>newParentName (TPM2B_NAME): The Name of the new parent.</description></item>
///   <item><description>includeObject (TPMI_YES_NO): Whether objectName is included in the policyDigest.</description></item>
/// </list>
/// </remarks>
/// <param name="PolicySession">The policy session handle.</param>
/// <param name="ObjectName">The Name of the object to be duplicated, at most <see cref="Tpm2bName.MaxSize"/> octets. The caller owns the underlying memory.</param>
/// <param name="NewParentName">The Name of the new parent, at most <see cref="Tpm2bName.MaxSize"/> octets. The caller owns the underlying memory.</param>
/// <param name="IsObjectIncluded">Whether <paramref name="ObjectName"/> is folded into the policyDigest (YES), binding the policy to this object and new parent as a pair rather than to the new parent alone (NO).</param>
/// <exception cref="ArgumentException"><paramref name="ObjectName"/> or <paramref name="NewParentName"/> is longer than <see cref="Tpm2bName.MaxSize"/>.</exception>
[DebuggerDisplay("PolicyDuplicationSelectInput(Session=0x{PolicySession,h}, IncludeObject={IsObjectIncluded})")]
public readonly record struct PolicyDuplicationSelectInput(uint PolicySession, ReadOnlyMemory<byte> ObjectName, ReadOnlyMemory<byte> NewParentName, bool IsObjectIncluded): ITpmCommandInput
{
    /// <summary>
    /// Gets the Name of the object to be duplicated, bounded at construction by <see cref="Tpm2bName.MaxSize"/>.
    /// </summary>
    public ReadOnlyMemory<byte> ObjectName
    {
        get => field;
        init => field = EnsureWithinNameBound(value);
    } = EnsureWithinNameBound(ObjectName);

    /// <summary>
    /// Gets the Name of the new parent, bounded at construction by <see cref="Tpm2bName.MaxSize"/>.
    /// </summary>
    public ReadOnlyMemory<byte> NewParentName
    {
        get => field;
        init => field = EnsureWithinNameBound(value);
    } = EnsureWithinNameBound(NewParentName);

    /// <summary>
    /// Refuses a Name the <c>TPM2B_NAME</c> wire type cannot carry (TPM 2.0 Library Part 2, clause 10.4.3, Table 105:
    /// <c>name[size]{:sizeof(TPMU_NAME)}</c>), so the caller learns it at construction rather than from the TPM's
    /// <c>TPM_RC_SIZE</c> after a round trip.
    /// </summary>
    /// <param name="candidate">The Name offered by the caller.</param>
    /// <returns><paramref name="candidate"/> when it is within the bound.</returns>
    /// <exception cref="ArgumentException"><paramref name="candidate"/> is longer than <see cref="Tpm2bName.MaxSize"/>.</exception>
    private static ReadOnlyMemory<byte> EnsureWithinNameBound(ReadOnlyMemory<byte> candidate)
    {
        if(candidate.Length > Tpm2bName.MaxSize)
        {
            throw new ArgumentException($"Name too large. Maximum is {Tpm2bName.MaxSize} bytes.", nameof(candidate));
        }

        return candidate;
    }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyDuplicationSelect;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>policySession</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 23.15.2, Table 168) — the
    /// first session in an authorization area over this command is a companion, never an authorizer, so a
    /// decrypt or encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0
    /// Library Part 1, clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)                                //policySession (handle area).
        + sizeof(ushort) + ObjectName.Length        //objectName (TPM2B_NAME).
        + sizeof(ushort) + NewParentName.Length     //newParentName (TPM2B_NAME).
        + sizeof(byte);                             //includeObject (TPMI_YES_NO).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteTpm2b(ObjectName.Span);
        writer.WriteTpm2b(NewParentName.Span);
        writer.WriteByte(IsObjectIncluded ? (byte)1 : (byte)0);
    }
}

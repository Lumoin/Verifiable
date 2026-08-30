using System;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Duplicate command (CC = 0x0000014B).
/// </summary>
/// <remarks>
/// <para>
/// Exports a loaded, duplicable object (its public area's <c>fixedParent</c> CLEAR) from under its current
/// parent so <c>TPM2_Import</c> can bring it in under a new one — the key-migration and backup path of the
/// Protected Storage hierarchy (TPM 2.0 Part 1, Clause 20; Part 3, Section 13.1).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 13.1):
/// </para>
/// <list type="bullet">
///   <item><description>objectHandle (TPMI_DH_OBJECT): the loaded object to duplicate. Requires DUP-role authorization — a policy session whose <c>commandCode</c> is latched to <c>TPM_CC_Duplicate</c>.</description></item>
///   <item><description>newParentHandle (TPMI_DH_OBJECT+): the new parent (its public area suffices on a real TPM), or <c>TPM_RH_NULL</c> for no new parent. No authorization.</description></item>
///   <item><description>encryptionKeyIn (TPM2B_DATA): the optional inner-wrapper key; shall be the Empty Buffer when <c>symmetricAlg</c> is <c>TPM_ALG_NULL</c>.</description></item>
///   <item><description>symmetricAlg (TPMT_SYM_DEF_OBJECT+): the inner-wrapper algorithm, or <c>TPM_ALG_NULL</c> for no inner wrapper.</description></item>
/// </list>
/// <para>
/// This input frames the no-inner-wrapper form — an empty <c>encryptionKeyIn</c> and
/// <c>symmetricAlg = TPM_ALG_NULL</c> — so the duplicate's protection is the identity-based outer wrapper to
/// the new parent alone. The executor is given one authorization session in handle order: the object's
/// DUP-role policy session.
/// </para>
/// </remarks>
public sealed class DuplicateInput: ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Duplicate;

    /// <summary>
    /// Gets the handle of the loaded object being duplicated.
    /// </summary>
    public TpmiDhObject ObjectHandle { get; }

    /// <summary>
    /// Gets the handle of the new parent, or the <c>TPM_RH_NULL</c> value for no new parent.
    /// </summary>
    public TpmiDhObject NewParentHandle { get; }

    /// <summary>
    /// Initializes a TPM2_Duplicate input framing the no-inner-wrapper form.
    /// </summary>
    /// <param name="objectHandle">The loaded object being duplicated.</param>
    /// <param name="newParentHandle">The new parent's handle, or the <c>TPM_RH_NULL</c> value.</param>
    public DuplicateInput(uint objectHandle, uint newParentHandle)
    {
        ObjectHandle = TpmiDhObject.FromValue(objectHandle);
        NewParentHandle = TpmiDhObject.FromValue(newParentHandle);
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return (2 * sizeof(uint)) +                 //objectHandle + newParentHandle.
               sizeof(ushort) +                     //encryptionKeyIn (empty TPM2B_DATA).
               sizeof(ushort);                      //symmetricAlg (TPM_ALG_NULL selector alone).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        ObjectHandle.WriteTo(ref writer);
        NewParentHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //encryptionKeyIn: the Empty Buffer the TPM_ALG_NULL form requires; symmetricAlg: the bare NULL
        //selector, which a TPMT_SYM_DEF_OBJECT carries with no keyBits or mode fields after it.
        writer.WriteUInt16(0);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_NULL);
    }
}

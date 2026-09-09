using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_ObjectChangeAuth command (TPM 2.0 Library Part 3, clause 12.8, Table 32): a new
/// authorization value for a loaded object, answered as a freshly wrapped private area under the object's
/// parent for a later <c>TPM2_Load()</c>. The TPM-resident object itself is unchanged ("This command does not
/// change the authorization of the TPM-resident object on which it operates", clause 12.8.1).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>objectHandle (TPMI_DH_OBJECT) - the loaded object whose authorization value is replaced. ADMIN-role authorization: a password or HMAC session while the object's <c>adminWithPolicy</c> attribute is CLEAR; a policy session latched to <c>TPM_CC_ObjectChangeAuth</c> otherwise (Part 3, clause 5.6, check 5.1; Part 1, clause 16.2).</description></item>
///   <item><description>parentHandle (TPMI_DH_OBJECT) - the object's parent, whose Qualified Name the TPM chains the object's from and compares to the retained one (<c>TPM_RC_TYPE</c> on mismatch). No authorization.</description></item>
/// </list>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>newAuth (TPM2B_AUTH) - the replacement authorization value; once trailing zeros are stripped, no wider than the digest of the object's Name algorithm (<c>TPM_RC_SIZE</c>).</description></item>
/// </list>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 12.8 (Tables 32 and 33).
/// </para>
/// </remarks>
/// <param name="ObjectHandle">The loaded object whose authorization value is replaced.</param>
/// <param name="ParentHandle">The object's parent.</param>
/// <param name="NewAuth">
/// The replacement authorization value. BORROWS the caller's carrier: this type neither owns nor disposes it —
/// the caller retains ownership across the call, the non-owning contract <see cref="StirRandomInput"/> keeps
/// for its own sized parameter.
/// </param>
public readonly record struct ObjectChangeAuthInput(TpmiDhObject ObjectHandle, TpmiDhObject ParentHandle, Tpm2bAuth NewAuth): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_ObjectChangeAuth;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>newAuth</c> is a sized buffer and is the command's first (and only) parameter, so it is eligible for
    /// session-based parameter encryption (TPM 2.0 Library Part 1, clause 18.1) — the value most worth
    /// protecting in flight, since it is the object's next authorization secret.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <inheritdoc/>
    public int GetSerializedSize() => (2 * sizeof(uint)) + NewAuth.SerializedSize;

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        ObjectHandle.WriteTo(ref writer);
        ParentHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        NewAuth.WriteTo(ref writer);
    }
}

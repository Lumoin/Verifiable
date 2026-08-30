using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyNameHash command (CC = 0x00000170).
/// </summary>
/// <remarks>
/// <para>
/// Authorizes a policy session only for the command whose target entity's Name(s) hash to
/// <see cref="NameHash"/>. The session's policyDigest is updated as
/// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyNameHash || nameHash)</c> (TPM 2.0 Part 3, Section
/// 23.14); see <see cref="TpmPolicyDigest.ExtendForNameHash"/>. TPM2_PolicyNameHash and TPM2_PolicyCpHash are
/// mutually exclusive within one session (TPM_RC_CPHASH if both are attempted), because the command's cpHash
/// already covers the handle Names TPM2_PolicyNameHash would otherwise bind.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.14, Table 166):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>nameHash (TPM2B_DIGEST): The digest of the concatenated Names the policy binds to.</description></item>
/// </list>
/// </remarks>
/// <param name="PolicySession">The policy session handle.</param>
/// <param name="NameHash">The digest of the concatenated target Names, at most <see cref="Tpm2bDigest.MaxSize"/> octets. The caller owns the underlying memory.</param>
/// <exception cref="ArgumentException"><paramref name="NameHash"/> is longer than <see cref="Tpm2bDigest.MaxSize"/>.</exception>
[DebuggerDisplay("PolicyNameHashInput(Session=0x{PolicySession,h})")]
public readonly record struct PolicyNameHashInput(uint PolicySession, ReadOnlyMemory<byte> NameHash): ITpmCommandInput
{
    /// <summary>
    /// Gets the digest of the concatenated target Names, bounded at construction by
    /// <see cref="Tpm2bDigest.MaxSize"/>.
    /// </summary>
    public ReadOnlyMemory<byte> NameHash
    {
        get => field;
        init => field = EnsureWithinDigestBound(value);
    } = EnsureWithinDigestBound(NameHash);

    /// <summary>
    /// Refuses a digest the <c>TPM2B_DIGEST</c> wire type cannot carry, so the caller learns it at construction
    /// rather than from the TPM's <c>TPM_RC_SIZE</c> after a round trip.
    /// </summary>
    /// <param name="candidate">The digest offered by the caller.</param>
    /// <returns><paramref name="candidate"/> when it is within the bound.</returns>
    /// <exception cref="ArgumentException"><paramref name="candidate"/> is longer than <see cref="Tpm2bDigest.MaxSize"/>.</exception>
    private static ReadOnlyMemory<byte> EnsureWithinDigestBound(ReadOnlyMemory<byte> candidate)
    {
        if(candidate.Length > Tpm2bDigest.MaxSize)
        {
            throw new ArgumentException($"Digest too large. Maximum is {Tpm2bDigest.MaxSize} bytes.", nameof(candidate));
        }

        return candidate;
    }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyNameHash;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)                         //policySession (handle area).
        + sizeof(ushort) + NameHash.Length;  //nameHash (TPM2B_DIGEST).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteTpm2b(NameHash.Span);
    }
}

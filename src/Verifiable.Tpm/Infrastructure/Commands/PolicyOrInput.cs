using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyOR command (CC = 0x00000171).
/// </summary>
/// <remarks>
/// <para>
/// Authorizes a policy session if its current policyDigest matches any digest in <see cref="BranchDigests"/>,
/// then collapses the session to a single OR digest:
/// <c>policyDigest = H(0...0 || TPM_CC_PolicyOR || pHashList)</c>, where <c>pHashList</c> is the concatenation of
/// the branch digests' bytes. The result depends only on the branch set, not on which branch matched, so a
/// caller can predict it from the branches alone (see <see cref="TpmPolicyDigest.ExtendForOr"/>). On a trial
/// session the match check is skipped and the digest is set unconditionally.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.6):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>pHashList (TPML_DIGEST): The allowed branch policy digests.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PolicyOrInput: ITpmCommandInput
{
    private readonly IReadOnlyList<ReadOnlyMemory<byte>> branchDigests;

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyOR;

    /// <summary>
    /// Gets the policy session handle the assertion is applied to.
    /// </summary>
    public uint PolicySession { get; }

    /// <summary>
    /// Gets the allowed branch policy digests (the OR alternatives).
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> BranchDigests => branchDigests;

    /// <summary>
    /// Creates a TPM2_PolicyOR input. The branch digests are public policy-digest values; the instance references
    /// the supplied memory and does not copy or own it.
    /// </summary>
    /// <param name="policySession">The policy session handle.</param>
    /// <param name="branchDigests">The allowed branch policy digests.</param>
    public PolicyOrInput(uint policySession, IReadOnlyList<ReadOnlyMemory<byte>> branchDigests)
    {
        ArgumentNullException.ThrowIfNull(branchDigests);
        PolicySession = policySession;
        this.branchDigests = branchDigests;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        int size = sizeof(uint) +   //policySession (handle area)
                   sizeof(uint);    //pHashList count (UINT32)

        for(int i = 0; i < branchDigests.Count; i++)
        {
            size += sizeof(ushort) + branchDigests[i].Length;   //each digest as TPM2B_DIGEST.
        }

        return size;
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)branchDigests.Count);
        for(int i = 0; i < branchDigests.Count; i++)
        {
            writer.WriteTpm2b(branchDigests[i].Span);
        }
    }

    private string DebuggerDisplay => $"PolicyOrInput(Session=0x{PolicySession:X8}, {branchDigests.Count} branch(es))";
}

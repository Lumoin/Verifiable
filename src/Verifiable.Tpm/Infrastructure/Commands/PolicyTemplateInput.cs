using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyTemplate command (CC = 0x00000190).
/// </summary>
/// <remarks>
/// <para>
/// Authorizes a policy session only for a TPM2_CreatePrimary, TPM2_Create, or TPM2_CreateLoaded whose
/// templateHash (the digest of the object's TPMT_PUBLIC template) equals <see cref="TemplateHash"/>. The
/// session's policyDigest is updated as
/// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyTemplate || templateHash)</c> (TPM 2.0 Library Part 3, clause
/// 23.21); see <see cref="TpmPolicyDigest.ExtendForTemplate"/>. On a trial session the comparison is skipped and
/// only the digest is updated.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 23.21, Table 180):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>templateHash (TPM2B_DIGEST): The digest of the object template the policy binds to.</description></item>
/// </list>
/// </remarks>
/// <param name="PolicySession">The policy session handle.</param>
/// <param name="TemplateHash">The digest of the bound object template, at most <see cref="Tpm2bDigest.MaxSize"/> octets. The caller owns the underlying memory.</param>
/// <exception cref="ArgumentException"><paramref name="TemplateHash"/> is longer than <see cref="Tpm2bDigest.MaxSize"/>.</exception>
[DebuggerDisplay("PolicyTemplateInput(Session=0x{PolicySession,h})")]
public readonly record struct PolicyTemplateInput(uint PolicySession, ReadOnlyMemory<byte> TemplateHash): ITpmCommandInput
{
    /// <summary>
    /// Gets the digest of the bound object template, bounded at construction by
    /// <see cref="Tpm2bDigest.MaxSize"/>.
    /// </summary>
    public ReadOnlyMemory<byte> TemplateHash
    {
        get => field;
        init => field = EnsureWithinDigestBound(value);
    } = EnsureWithinDigestBound(TemplateHash);

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
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyTemplate;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>policySession</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 23.21.2, Table 180) — the
    /// first session in an authorization area over this command is a companion, never an authorizer, so a
    /// decrypt or encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0
    /// Library Part 1, clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)                             //policySession (handle area).
        + sizeof(ushort) + TemplateHash.Length;  //templateHash (TPM2B_DIGEST).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteTpm2b(TemplateHash.Span);
    }
}

using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyCpHash command (CC = 0x0000016E).
/// </summary>
/// <remarks>
/// <para>
/// Authorizes a policy session only for the command whose parameters hash to <see cref="CpHashA"/>. The
/// session's policyDigest is updated as
/// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyCpHash || cpHashA)</c> (TPM 2.0 Part 3, Section 23.13);
/// see <see cref="TpmPolicyDigest.ExtendForCpHash"/>. The TPM requires <see cref="CpHashA"/>'s size to equal the
/// session's digest size (TPM_RC_SIZE otherwise) and refuses a second, differently-valued call for the same
/// session (TPM_RC_CPHASH) — a policy binds to at most one cpHash.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 23.13, Table 164):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>cpHashA (TPM2B_DIGEST): The command parameter digest the policy binds to.</description></item>
/// </list>
/// </remarks>
/// <param name="PolicySession">The policy session handle.</param>
/// <param name="CpHashA">The command parameter digest, at most <see cref="Tpm2bDigest.MaxSize"/> octets. The caller owns the underlying memory.</param>
/// <exception cref="ArgumentException"><paramref name="CpHashA"/> is longer than <see cref="Tpm2bDigest.MaxSize"/>.</exception>
[DebuggerDisplay("PolicyCpHashInput(Session=0x{PolicySession,h})")]
public readonly record struct PolicyCpHashInput(uint PolicySession, ReadOnlyMemory<byte> CpHashA): ITpmCommandInput
{
    /// <summary>
    /// Gets the command parameter digest the policy binds to, bounded at construction by
    /// <see cref="Tpm2bDigest.MaxSize"/>.
    /// </summary>
    public ReadOnlyMemory<byte> CpHashA
    {
        get => field;
        init => field = EnsureWithinDigestBound(value);
    } = EnsureWithinDigestBound(CpHashA);

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
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyCpHash;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)                        //policySession (handle area).
        + sizeof(ushort) + CpHashA.Length;  //cpHashA (TPM2B_DIGEST).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteTpm2b(CpHashA.Span);
    }
}

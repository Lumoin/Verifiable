using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PolicyParameters command (CC = 0x0000019C).
/// </summary>
/// <remarks>
/// <para>
/// Binds a policy session to a specific command and its parameters, but not to specific objects: at use the TPM
/// compares <see cref="ParametersHash"/> against <c>H(commandCode || parameters)</c> of the authorized command
/// with the handle Names skipped. The session's policyDigest is updated as
/// <c>policyDigest = H(policyDigestold || TPM_CC_PolicyParameters || pHash)</c> (TPM 2.0 Library Part 3, clause
/// 23.24); see <see cref="TpmPolicyDigest.ExtendForParameters"/>. TPM2_PolicyParameters shares the session's one
/// cpHash slot with TPM2_PolicyCpHash, TPM2_PolicyNameHash and TPM2_PolicyTemplate, so only one of them can be
/// asserted per session (TPM_RC_CPHASH otherwise).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 23.24, Table 187):
/// </para>
/// <list type="bullet">
///   <item><description>policySession (TPMI_SH_POLICY): The policy session handle (command handle, no authorization).</description></item>
///   <item><description>pHash (TPM2B_DIGEST): The parameter digest added to the policy.</description></item>
/// </list>
/// </remarks>
/// <param name="PolicySession">The policy session handle.</param>
/// <param name="ParametersHash">The digest of the command code and parameters the policy binds to, at most <see cref="Tpm2bDigest.MaxSize"/> octets. The caller owns the underlying memory.</param>
/// <exception cref="ArgumentException"><paramref name="ParametersHash"/> is longer than <see cref="Tpm2bDigest.MaxSize"/>.</exception>
[DebuggerDisplay("PolicyParametersInput(Session=0x{PolicySession,h})")]
public readonly record struct PolicyParametersInput(uint PolicySession, ReadOnlyMemory<byte> ParametersHash): ITpmCommandInput
{
    /// <summary>
    /// Gets the digest of the command code and parameters the policy binds to, bounded at construction by
    /// <see cref="Tpm2bDigest.MaxSize"/>.
    /// </summary>
    public ReadOnlyMemory<byte> ParametersHash
    {
        get => field;
        init => field = EnsureWithinDigestBound(value);
    } = EnsureWithinDigestBound(ParametersHash);

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
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PolicyParameters;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>policySession</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 23.24.2, Table 187) — the
    /// first session in an authorization area over this command is a companion, never an authorizer, so a
    /// decrypt or encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0
    /// Library Part 1, clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint)                               //policySession (handle area).
        + sizeof(ushort) + ParametersHash.Length;  //pHash (TPM2B_DIGEST).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(PolicySession);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteTpm2b(ParametersHash.Span);
    }
}

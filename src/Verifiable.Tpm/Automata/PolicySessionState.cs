using System;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a started policy (enhanced authorization) session: the policy hash algorithm, the
/// trial flag, and the accumulated policyDigest a sequence of <c>TPM2_Policy*()</c> assertions drives (TPM 2.0
/// Library Part 1, clause 19.7). It is the smallest session model the policy command family needs — a session
/// begins with an all-zero policyDigest of the hash width, and each assertion extends it toward the value an
/// object's <c>authPolicy</c> would be set to.
/// </summary>
/// <remarks>
/// <para>
/// Like <see cref="TransientKeyState"/> and <see cref="NvIndexState"/>, the accumulated digest is held as a plain
/// <see cref="ReadOnlyMemory{T}"/>: it is durable model state owned by the live automaton for the lifetime of the
/// session (until <c>TPM2_FlushContext()</c> releases it), not hot wire-path memory. A value is only ever replaced
/// wholesale by the next assertion, never mutated in place.
/// </para>
/// <para>
/// A trial session (<see cref="IsTrial"/>) accumulates the same policyDigest a real policy session would but does
/// not authorize any command; the difference surfaces only in assertions whose real-session form performs a live
/// check the trial form skips (for example the <c>TPM2_PolicyOR()</c> branch match).
/// </para>
/// </remarks>
/// <param name="Handle">The session handle assigned at <c>TPM2_StartAuthSession()</c> (most-significant octet <c>TPM_HT_POLICY_SESSION</c>, TPM 2.0 Library Part 2, clause 7.2).</param>
/// <param name="PolicyHash">The session's policy hash algorithm (the <c>authHash</c> supplied at start), whose digest width the policyDigest carries.</param>
/// <param name="IsTrial">Whether this is a trial session (started with <c>TPM_SE_TRIAL</c>): it computes the policyDigest but authorizes nothing.</param>
/// <param name="PolicyDigest">The accumulated policyDigest, starting at all-zeros of the hash width and extended by each assertion.</param>
public sealed record PolicySessionState(
    uint Handle,
    TpmAlgIdConstants PolicyHash,
    bool IsTrial,
    ReadOnlyMemory<byte> PolicyDigest);

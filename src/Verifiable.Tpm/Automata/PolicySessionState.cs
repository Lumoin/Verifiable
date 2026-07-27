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
/// <param name="NonceTpm">
/// The session's retained nonceTPM (<see cref="PolicyHash"/>'s digest width), drawn from the TPM's RNG when the
/// session started (TPM 2.0 Library Part 3, clause 11.1) and framed verbatim in the <c>TPM2_StartAuthSession()</c>
/// response. <c>TPM2_PolicySigned()</c>'s <c>aHash</c> binds to this exact value (Part 3, Section 23.3), so it
/// must be the real per-session nonce, not a placeholder.
/// </param>
/// <param name="CpHash">
/// The command-parameter digest this session has been bound to, or empty when unlatched. Part 3, Section 23.2.4:
/// once a policy assertion (for example <c>TPM2_PolicySigned()</c>) sets this to a non-empty value, it is
/// immutable for the life of the session (first-writer-wins) — a later assertion proposing a different, non-empty
/// value is rejected rather than silently replacing it.
/// </param>
/// <param name="StartTime">
/// A snapshot of the simulator's <c>Time</c> (TPM 2.0 Library Part 1, clause 36.2) taken when the session
/// started, used as the base for a session-relative <c>expiration</c> deadline (Part 3, Section 23.2.2). There is
/// deliberately no separate "time epoch" field: a TPM Reset invalidates every policy session outright (this
/// simulator clears <see cref="TpmSimulatorState.PolicySessions"/> on <c>OnStartup</c>'s Reset branch), so a
/// session whose <see cref="StartTime"/> predates a Reset can never still be resolvable when a later command
/// consults it — the epoch-mismatch branch a real TPM's free-running oscillator needs is structurally
/// unreachable for an in-process simulator with no real timer discontinuity to detect.
/// </param>
public sealed record PolicySessionState(
    uint Handle,
    TpmAlgIdConstants PolicyHash,
    bool IsTrial,
    ReadOnlyMemory<byte> PolicyDigest,
    ReadOnlyMemory<byte> NonceTpm,
    ReadOnlyMemory<byte> CpHash,
    ulong StartTime);

using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a started policy (enhanced authorization) session: the policy hash algorithm, the
/// trial flag, and the accumulated policyDigest a sequence of <c>TPM2_Policy*()</c> assertions drives (TPM 2.0
/// Library Part 1, clause 16.7). It is the smallest session model the policy command family needs — a session
/// begins with an all-zero policyDigest of the hash width, and each assertion extends it toward the value an
/// object's <c>authPolicy</c> would be set to.
/// </summary>
/// <remarks>
/// <para>
/// The session key is held in a pooled, zero-on-dispose sensitive carrier (<see cref="SymmetricKeyMemory"/>),
/// fixed at <c>TPM2_StartAuthSession()</c> for the session's whole life; this record is the carrier's single
/// owner, and everything downstream reads it through non-owning <see cref="ReadOnlyMemory{T}"/> views. The
/// nonceTPM is the structure Part 2, clause 10.3.4, Table 92 names — <c>TPM2B_NONCE</c>, the declared type of
/// <c>TPMS_AUTH_RESPONSE.nonce</c> (clause 10.12.3, Table 157) — so it rides in a <see cref="Tpm2bNonce"/>
/// carrier this record likewise owns, replaced wholesale by <see cref="WithNonceTpm(Tpm2bNonce)"/> once per
/// command response. The accumulated policyDigest and the latched cpHash are both the structure Part 2, clause
/// 10.3.2, Table 90 names — <c>TPM2B_DIGEST</c> — so each rides in a <see cref="Tpm2bDigest"/> carrier this
/// record owns as well, replaced wholesale by <see cref="WithPolicyDigest(Tpm2bDigest)"/> and
/// <see cref="WithCpHash(Tpm2bDigest)"/> and never mutated in place. Before the first assertion, and again
/// after the context reset, the policyDigest is the shared dispose-immune
/// <see cref="Tpm2bDigest.Zero(TpmiAlgHash)"/> of the session hash's width.
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
/// <param name="PolicyDigest">
/// The accumulated policyDigest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90) in an
/// owned pooled carrier: the shared <see cref="Tpm2bDigest.Zero(TpmiAlgHash)"/> of <see cref="PolicyHash"/>'s
/// width before the first assertion, then a freshly rented carrier per extension, installed through
/// <see cref="WithPolicyDigest(Tpm2bDigest)"/>, which releases the superseded one as the replacement lands.
/// This record owns the carrier; the response framing and the pending-verification queue read it as a borrow
/// and never dispose it.
/// </param>
/// <param name="NonceTpm">
/// The session's retained nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92, of
/// <see cref="PolicyHash"/>'s digest width) in an owned pooled carrier: drawn from the TPM's RNG when the session
/// started (Part 3, clause 11.1) and framed verbatim in the <c>TPM2_StartAuthSession()</c> response, then rolled
/// to a fresh value on each command response (Part 1, clause 16.6.5) through <see cref="WithNonceTpm(Tpm2bNonce)"/>,
/// which releases the superseded carrier as the replacement lands. <c>TPM2_PolicySigned()</c>'s <c>aHash</c>
/// binds to this exact value (Part 3, clause 23.3), so it must be the real per-session nonce, not a
/// placeholder. This record owns the carrier; the pending-verification queue and the response-framing records
/// read it as a borrow and never dispose it.
/// </param>
/// <param name="CpHash">
/// The command-parameter digest this session has been bound to (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2,
/// clause 10.3.2, Table 90) in an owned pooled carrier, or the dispose-immune
/// <see cref="Tpm2bDigest.Empty"/> sentinel when unlatched. Part 3, clause 23.2.4: once a policy assertion (for
/// example <c>TPM2_PolicySigned()</c>) sets this to a non-empty value, it is immutable for the life of the
/// session (first-writer-wins) — a later assertion proposing a different, non-empty value is rejected rather
/// than silently replacing it. The latching assertion TRANSFERS its own carrier here through
/// <see cref="WithCpHash(Tpm2bDigest)"/>; an assertion that re-proposes the same value has its carrier released
/// by the arm that accepted it.
/// </param>
/// <param name="StartTime">
/// A snapshot of the simulator's <c>Time</c> (TPM 2.0 Library Part 1, clause 33.2) taken when the session
/// started, used as the base for a session-relative <c>expiration</c> deadline (Part 3, clause 23.2.2). There is
/// deliberately no separate "time epoch" field: a TPM Reset invalidates every policy session outright (this
/// simulator clears <see cref="TpmSimulatorState.PolicySessions"/> on <c>OnStartup</c>'s Reset branch), so a
/// session whose <see cref="StartTime"/> predates a Reset can never still be resolvable when a later command
/// consults it — the epoch-mismatch branch a real TPM's free-running oscillator needs is structurally
/// unreachable for an in-process simulator with no real timer discontinuity to detect.
/// </param>
/// <param name="Timeout">
/// The session's own tracked deadline (<c>policySession-&gt;timeout</c>, Part 3, clause 23.2.4), or zero when
/// unset. <c>TPM2_PolicySigned()</c>, <c>TPM2_PolicySecret()</c>, and <c>TPM2_PolicyTicket()</c> each update this
/// with the smaller of the existing value and their own computed deadline — never a larger one, and never on a
/// zero deadline (the trial-session and no-expiration folds) — mirroring <c>PolicyContextUpdate</c>'s
/// "<c>if(session-&gt;timeout == 0 || session-&gt;timeout &gt; policyTimeout) session-&gt;timeout =
/// policyTimeout</c>" rule exactly. This value is tracked but not yet consulted anywhere to answer
/// <c>TPM_RC_EXPIRED</c> at authorization time — the companion half of the same normative rule, which is
/// not modelled here.
/// </param>
/// <param name="SessionKey">
/// The session key, derived identically to <see cref="HmacSessionState.SessionKey"/> by the same
/// <c>TPM2_StartAuthSession()</c> bind/salt ladder regardless of session type (Part 3, clause 11.1.1: "For all
/// session types, this command will cause initialization of the sessionKey"): <c>KDFa</c>-derived (Part 1,
/// clause 16.6.10 equation 20 / clause 16.6.12 equation 25) when the session is bound and/or salted, or the
/// shared Empty-Buffer carrier <see cref="TpmSimulatorState.EmptySessionKey"/> when it is neither (clause 16.6.9
/// — no KDFa runs at all); this record owns the carrier. Unlike an HMAC session, a POLICY
/// session never applies the bind-entity-omission optimization (Part 3, clause 11.1.1's own "the session is not
/// bound") — whether this key's bind-entity authValue is layered on top of it for a given command's authHMAC is
/// decided solely by <see cref="IsAuthValueNeeded"/>/<see cref="IsPasswordNeeded"/> (equations 26/27, Part 1
/// clause 16.6.12), never by binding.
/// </param>
/// <param name="Symmetric">
/// The symmetric definition negotiated at <c>TPM2_StartAuthSession()</c> (Part 3, clause 11.1: the command's
/// own <c>symmetric</c> parameter), XOR obfuscation or AES-CFB, which keys parameter encryption when this
/// session sits at a decrypt or encrypt companion slot — TPM 2.0 Library Part 1, clause 15.6.1, Table 12
/// footnote [2]: "a policy authorization session can also be used for encryption and decryption." A policy
/// session negotiates this term exactly as an HMAC session does (TPM 2.0 Library Part 3, clause 11.1.1 makes
/// no session-type distinction for the negotiation), so it is retained here rather than discarded once the
/// session starts.
/// </param>
/// <param name="IsAuthValueNeeded">
/// SET by <c>TPM2_PolicyAuthValue()</c>; CLEAR by default, by <c>TPM2_PolicyPassword()</c>, and once this
/// session has been successfully used to authorize a command (TPM 2.0 Library Part 1, clause 16.7.8; Part 3,
/// clause 23.2.4). When SET, a command this session authorizes folds the authorized entity's authValue into
/// the authHMAC key alongside <see cref="SessionKey"/> (equation 26, Part 1 clause 16.6.12); when CLEAR, the key
/// is <see cref="SessionKey"/> alone (equation 27). CLEAR also by <c>TPM2_PolicyPassword()</c> (Part 1, clause
/// 16.7.8's "It will also be CLEAR by TPM2_PolicyPassword()") and by <c>TPM2_PolicyRestart()</c> as part of a
/// full context reset (Part 3, clause 11.2).
/// </param>
/// <param name="IsPasswordNeeded">
/// SET by <c>TPM2_PolicyPassword()</c>; CLEAR by default, by <c>TPM2_PolicyAuthValue()</c>, and by
/// <c>TPM2_PolicyRestart()</c> (TPM 2.0 Library Part 1, clause 16.7.8; Part 3, clause 23.18). When SET, a
/// command this session authorizes proves the authorized entity's authValue by presenting it in the clear in
/// the session's <c>hmac</c> field — "the comparison of hmac to authValue is performed as if the authorization
/// is a password" (clause 23.18) — and the response carries an empty <c>hmac</c> (Part 1, clause 16.6.16).
/// The mutual exclusion with <see cref="IsAuthValueNeeded"/> is symmetric: whichever of the two ran last
/// determines the presentation format the session then requires.
/// </param>
/// <param name="CommandCode">
/// The command code <c>TPM2_PolicyCommandCode()</c> restricted this session to (Part 3, clause 23.11) — or
/// <c>TPM_CC_Duplicate</c> once <c>TPM2_PolicyDuplicationSelect()</c> has run (clause 23.15) — or
/// <see langword="null"/> while no such assertion has been made. A later assertion that would set it to a
/// different value is refused (Part 1, clause 16.7.8). The restriction is carried in
/// <see cref="PolicyDigest"/> as well — the digest fold is what a USER-role entity's authPolicy match enforces
/// implicitly — but an ADMIN-role authorization additionally consults this field directly, because Part 1,
/// clause 16.2's ADMIN Note requires BOTH conditions independently ("an authPolicy is satisfied when
/// policySession→policyDigest matches the value of the authPolicy value of the object AND
/// policySession→commandCode matches commandCode for the authorized command"). A session that never asserted a
/// command code therefore fails an ADMIN-role check outright rather than being decided by the digest alone,
/// and a session that asserted the wrong one is distinguishable from a session that asserted none.
/// Cleared alongside the rest of the policy context when the session is successfully used to authorize a
/// command (Part 3, clause 23.2.4) or by <c>TPM2_PolicyRestart()</c> (clause 11.2).
/// </param>
/// <param name="CpHashKind">
/// Which deferred assertion occupies the shared <see cref="CpHash"/> slot (TPM 2.0 Library Part 1, Table 8): a
/// command-parameter digest (<c>TPM2_PolicyCpHash()</c> or the cpHashA a <c>TPM2_PolicySigned()</c>/
/// <c>TPM2_PolicySecret()</c>/<c>TPM2_PolicyTicket()</c> authorization bound), a Name digest
/// (<c>TPM2_PolicyNameHash()</c>, or the one <c>TPM2_PolicyDuplicationSelect()</c> computes), a command-code-and-
/// parameters digest (<c>TPM2_PolicyParameters()</c>), or a template digest (<c>TPM2_PolicyTemplate()</c>). The kind decides what
/// <see cref="CpHash"/> is compared against at use and which later assertions may re-propose the slot; its
/// default <see cref="TpmPolicyCpHashKind.None"/> is the unlatched slot. Cleared by the after-use reset (Part 3,
/// clause 23.2.4) and <c>TPM2_PolicyRestart()</c>.
/// </param>
/// <param name="CommandLocality">
/// The marshaled <c>TPMA_LOCALITY</c> octet the session is restricted to (TPM 2.0 Library Part 3, clause 23.8;
/// Part 2, clause 8.5, Table 39), the logical AND of every <c>TPM2_PolicyLocality()</c> the policy asserted, or
/// zero for the initial "any locality" state. At use, a restricted session authorizes only when the command's
/// locality is enabled here — this simulator receives every command at locality 0. Cleared by the after-use
/// reset and <c>TPM2_PolicyRestart()</c>.
/// </param>
/// <param name="IsNvWrittenChecked">
/// Whether <c>TPM2_PolicyNvWritten()</c> has recorded a deferred check on the authorized NV Index's
/// <c>TPMA_NV_WRITTEN</c> attribute (TPM 2.0 Library Part 1, clause 16.7.8; Part 3, clause 23.20). When SET, the
/// authorized command must reference an NV Index whose written state equals <see cref="IsNvWrittenRequired"/>.
/// Cleared by the after-use reset and <c>TPM2_PolicyRestart()</c>.
/// </param>
/// <param name="IsNvWrittenRequired">
/// The <c>TPMA_NV_WRITTEN</c> value the check demands — SET (the Index must have been written) or CLEAR (it must
/// not) — meaningful only while <see cref="IsNvWrittenChecked"/> is SET (Part 1, clause 16.7.8).
/// </param>
/// <param name="IsBoundEntityDaProtected">
/// Whether the entity named by <c>bind</c> at <c>TPM2_StartAuthSession()</c> receives dictionary-attack
/// protection, captured once when the session started — TPM 2.0 Library Part 1, clause 16.6.10: "The noDA
/// attribute of the bind entity is recorded in the session context." A policy session records this even though
/// it records no bound-entity Name, because the two serve different mechanisms: the Name serves the
/// bind-omission optimization a policy session never applies (Part 3, clause 11.1.1's own "the session is not
/// bound"), while this flag serves dictionary-attack accounting, which Part 1, clause 16.8.7 states for a session
/// without qualifying it by session type. A policy session's <see cref="SessionKey"/> folds the bind entity's
/// authValue through the same KDFa an HMAC session's does (clause 11.1.1: "For all session types, this command
/// will cause initialization of the sessionKey"), so a failed use of it is evidence against that authValue in
/// exactly the sense clause 16.8.1 means by "the authValue parameter in the computation of sessionKey for a
/// bound session" being one of the three ways an authValue is used, all of which "receive DA protection". Part 4
/// likewise sets its <c>isDaBound</c> session attribute for every session type.
/// </param>
/// <param name="IsBoundToLockout">
/// Whether the bind entity is <c>TPM_RH_LOCKOUT</c>, whose authValue is the one permanent-entity authValue that
/// is dictionary-attack protected (TPM 2.0 Library Part 1, clause 16.8.1: "lockoutAuth is DA protected even
/// though it is a permanent entity"). Never set without <see cref="IsBoundEntityDaProtected"/> also being set,
/// matching Part 4's derivation of <c>isLockoutBound</c> from <c>isDaBound</c>. A failed use of a session whose
/// key folded lockoutAuth takes the one-strike discipline of clause 16.8.5 rather than the ordinary failure
/// counter, whichever entity the policy went on to authorize.
/// </param>
public sealed record PolicySessionState(
    TpmiShPolicy Handle,
    TpmiAlgHash PolicyHash,
    bool IsTrial,
    Tpm2bDigest PolicyDigest,
    Tpm2bNonce NonceTpm,
    Tpm2bDigest CpHash,
    ulong StartTime,
    SymmetricKeyMemory SessionKey,
    TpmtSymDef Symmetric,
    ulong Timeout = 0ul,
    bool IsAuthValueNeeded = false,
    bool IsPasswordNeeded = false,
    TpmCcConstants? CommandCode = null,
    bool IsBoundEntityDaProtected = false,
    bool IsBoundToLockout = false,
    TpmPolicyCpHashKind CpHashKind = TpmPolicyCpHashKind.None,
    byte CommandLocality = 0,
    bool IsNvWrittenChecked = false,
    bool IsNvWrittenRequired = false): IDisposable, IAuthSessionState
{
    /// <summary>
    /// The <see cref="IAuthSessionState"/> reading of this session's handle, widened from
    /// <see cref="TpmiShPolicy"/> to the generic <see cref="TpmHandle"/> shape the interface exposes.
    /// </summary>
    TpmHandle IAuthSessionState.Handle => Handle;

    /// <summary>
    /// The <see cref="IAuthSessionState"/> reading of this session's hash algorithm, which a policy session
    /// carries as <see cref="PolicyHash"/> rather than under the HMAC-side name.
    /// </summary>
    TpmiAlgHash IAuthSessionState.SessionAlg => PolicyHash;

    /// <summary>
    /// Returns a copy of this session carrying <paramref name="rolledNonceTpm"/> as its nonceTPM, releasing the
    /// superseded carrier as the replacement lands — the roll a command response performs exactly once (TPM 2.0
    /// Library Part 1, clause 16.6.5). The dispose-immune shared empty carrier is safe to supersede.
    /// </summary>
    /// <param name="rolledNonceTpm">The freshly generated nonceTPM in an owned carrier; ownership transfers to the returned session.</param>
    /// <returns>The session with its nonceTPM rolled.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of rolledNonceTpm transfers to the returned PolicySessionState's NonceTpm, which the record's Dispose or the next roll releases; the outgoing carrier is disposed here before the with-copy replaces it.")]
    public PolicySessionState WithNonceTpm(Tpm2bNonce rolledNonceTpm)
    {
        NonceTpm.Dispose();

        return this with { NonceTpm = rolledNonceTpm };
    }

    /// <summary>
    /// Returns a copy of this session carrying <paramref name="extendedPolicyDigest"/> as its accumulated
    /// policyDigest, releasing the superseded carrier as the replacement lands — the wholesale replacement each
    /// policy assertion performs (TPM 2.0 Library Part 1, clause 16.7). The shared Zero Digest a session starts
    /// from is dispose-immune, so the very first assertion supersedes it safely.
    /// </summary>
    /// <param name="extendedPolicyDigest">The freshly extended policyDigest in an owned carrier; ownership transfers to the returned session.</param>
    /// <returns>The session with its policyDigest advanced.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of extendedPolicyDigest transfers to the returned PolicySessionState's PolicyDigest, which the record's Dispose or the next assertion releases; the outgoing carrier is disposed here before the with-copy replaces it.")]
    public PolicySessionState WithPolicyDigest(Tpm2bDigest extendedPolicyDigest)
    {
        PolicyDigest.Dispose();

        return this with { PolicyDigest = extendedPolicyDigest };
    }

    /// <summary>
    /// Returns a copy of this session carrying <paramref name="latchedCpHash"/> as its cpHash, releasing the
    /// superseded carrier as the replacement lands — the first-writer-wins latch of TPM 2.0 Library Part 3,
    /// clause 23.2.4 and the unlatching half of the same clause's context reset. The dispose-immune empty
    /// carrier an unlatched session holds is safe to supersede.
    /// </summary>
    /// <param name="latchedCpHash">The cpHash in an owned carrier, or the empty sentinel to unlatch; ownership transfers to the returned session.</param>
    /// <param name="kind">The kind the slot takes — <see cref="TpmPolicyCpHashKind.None"/> when unlatching, otherwise the assertion that latched it.</param>
    /// <returns>The session with its cpHash replaced.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of latchedCpHash transfers to the returned PolicySessionState's CpHash, which the record's Dispose or the context reset releases; the outgoing carrier is disposed here before the with-copy replaces it.")]
    public PolicySessionState WithCpHash(Tpm2bDigest latchedCpHash, TpmPolicyCpHashKind kind)
    {
        CpHash.Dispose();

        return this with { CpHash = latchedCpHash, CpHashKind = kind };
    }

    /// <summary>
    /// Releases the session's owned <see cref="SessionKey"/>, <see cref="NonceTpm"/>,
    /// <see cref="PolicyDigest"/>, and <see cref="CpHash"/> carriers. Called when the session leaves the
    /// automaton's dictionary for good (<c>TPM2_FlushContext()</c>, any <c>TPM2_Startup()</c>'s session flush,
    /// simulator teardown); the shared Empty-Buffer key, the shared empty nonce, the shared Zero Digest, and the
    /// shared empty cpHash are all dispose-immune, so the walk is safe for an unbound, unsalted session that
    /// never asserted anything.
    /// </summary>
    public void Dispose()
    {
        SessionKey.Dispose();
        NonceTpm.Dispose();
        PolicyDigest.Dispose();
        CpHash.Dispose();
    }

    /// <summary>
    /// Value equality with OWNERSHIP identity for the owned carriers: two sessions are equal only when
    /// they share the same <see cref="SessionKey"/>, <see cref="NonceTpm"/>, <see cref="PolicyDigest"/>, and
    /// <see cref="CpHash"/> instances — reference
    /// comparison preserves the object-identity semantics plain memory fields have and never reads
    /// carrier content, so a superseded or disposed snapshot cannot throw here (see
    /// <see cref="NvIndexState.Equals(NvIndexState)"/> for the shared rationale).
    /// </summary>
    /// <param name="other">The session to compare against.</param>
    /// <returns><see langword="true"/> when every field matches and the carriers are the same instances.</returns>
    public bool Equals(PolicySessionState? other) =>
        other is not null
        && Handle == other.Handle
        && PolicyHash == other.PolicyHash
        && IsTrial == other.IsTrial
        && ReferenceEquals(PolicyDigest, other.PolicyDigest)
        && ReferenceEquals(NonceTpm, other.NonceTpm)
        && ReferenceEquals(CpHash, other.CpHash)
        && StartTime == other.StartTime
        && ReferenceEquals(SessionKey, other.SessionKey)
        && Symmetric.Equals(other.Symmetric)
        && Timeout == other.Timeout
        && IsAuthValueNeeded == other.IsAuthValueNeeded
        && IsPasswordNeeded == other.IsPasswordNeeded
        && CommandCode == other.CommandCode
        && IsBoundEntityDaProtected == other.IsBoundEntityDaProtected
        && IsBoundToLockout == other.IsBoundToLockout
        && CpHashKind == other.CpHashKind
        && CommandLocality == other.CommandLocality
        && IsNvWrittenChecked == other.IsNvWrittenChecked
        && IsNvWrittenRequired == other.IsNvWrittenRequired;

    /// <summary>
    /// Hashes the session's immutable identity fields, consistent with
    /// <see cref="Equals(PolicySessionState)"/> without ever reading carrier content.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() => HashCode.Combine(Handle, PolicyHash, IsTrial, StartTime, IsBoundEntityDaProtected, IsBoundToLockout);
}

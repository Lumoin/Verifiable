using System;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The in-flight audit of one command: the cpHash the audit-claiming session's command HMAC was verified over, the
/// session's pre-command audit digest, and the first-use/exclusivity facts <see cref="OnCommandHmacVerified"/>
/// already has once every session in the command's authorization area has verified (TPM 2.0 Library Part 1, clause
/// 17.1: "For all commands using a session tagged as audit (including the initial use), if the command completes
/// successfully, the cpHash and the rpHash are Extended to the audit session digest."). Carried transiently on
/// <see cref="TpmSimulatorState.PendingAudit"/> — never serialized, released by the command's completing
/// transition whether the command succeeds or fails (clause 17.5).
/// </summary>
/// <param name="Session">The audit-claiming session's handle.</param>
/// <param name="SessionIndex">The session's zero-based position in the command's authorization area, for the format-one session-index encoding a later refusal might still need.</param>
/// <param name="CommandAttributes">The session's command-side <c>TPMA_SESSION</c> octet, the source of the response octet the framing effect rewrites (<c>auditReset</c> forced CLEAR, <c>auditExclusive</c> set to the end-of-command exclusive status; TPM 2.0 Library Part 2, clause 8.4, Table 38).</param>
/// <param name="SessionAlg">The session hash algorithm the audit digest extends under.</param>
/// <param name="CpHash">
/// The command parameter hash the session's command HMAC was verified over — the wire parameter area, the
/// ciphertext when a decrypt session protected the first parameter (Part 1, clause 17.1, NOTE) — retained by
/// <see cref="TpmSimulator"/>'s command-HMAC-verification effect instead of being released with the rest of that
/// verification's scratch. OWNED: released by <see cref="Dispose"/> once the framing effect has folded it into
/// the new digest, or immediately on a refusal that never reaches framing.
/// </param>
/// <param name="CurrentDigest">
/// The session's <see cref="HmacSessionState.AuditDigest"/> as it stood when the command HMAC verified — BORROWED
/// from the live session record and never disposed here; the framing effect reads it as the fold's left-hand term
/// when <see cref="IsFirstUseOrReset"/> is <see langword="false"/>.
/// </param>
/// <param name="IsFirstUseOrReset">
/// Whether the fold's left-hand term is the Zero Digest of <see cref="SessionAlg"/>'s width rather than
/// <see cref="CurrentDigest"/> — set when the session has never completed a command as an audit session
/// (<c>!session.IsAudit</c>) or when this command's <c>auditReset</c> bit is SET (Part 4's
/// <c>UpdateAuditSessionStatus</c>: <c>isAudit == CLEAR || auditReset</c> re-initializes the digest before
/// extending it).
/// </param>
/// <param name="IsExclusiveAtEnd">
/// Whether the session holds the TPM-wide exclusive-audit-session status once this command completes — TPM 2.0
/// Library Part 1, clause 17.2: "A session becomes the current exclusive audit session when it is first used as
/// an audit session, regardless of the setting of auditReset. It can also become the current exclusive audit
/// session if the auditReset attribute of the session is SET in the command." <see cref="IsFirstUseOrReset"/> is
/// therefore sufficient on its own for that half; otherwise the session keeps exclusivity only when it already
/// held it (<c>state.ExclusiveAuditSession == Session</c>). Evaluated once the session's command HMAC has
/// verified — "Evaluation of the exclusive status is done at the start of the command" (Table 15, the
/// <c>auditExclusive</c> row) — because nothing runs between the verification and the framing that could change
/// the exclusive-session tracking for THIS command.
/// </param>
public sealed record TpmPendingAudit(
    TpmiShHmac Session,
    int SessionIndex,
    TpmaSession CommandAttributes,
    TpmiAlgHash SessionAlg,
    Tpm2bDigest CpHash,
    Tpm2bDigest CurrentDigest,
    bool IsFirstUseOrReset,
    bool IsExclusiveAtEnd): IDisposable
{
    /// <summary>
    /// Releases the OWNED <see cref="CpHash"/> carrier. <see cref="CurrentDigest"/> is BORROWED and is never
    /// touched here — it remains owned by the live <see cref="HmacSessionState"/> until that record's own
    /// <c>WithAudit</c> supersedes it.
    /// </summary>
    public void Dispose()
    {
        CpHash.Dispose();
    }
}

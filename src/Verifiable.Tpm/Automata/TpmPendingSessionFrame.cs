using System;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The response framing already built for a no-authorization command's authorization area, stamped on
/// <see cref="TpmSimulatorState.PendingSessionFrame"/> while the command's own inner transition runs to produce
/// its plain, unauthorized-form terminal intent (TPM 2.0 Library Part 1, clause 15.6.1) — transient, in-flight
/// command state, mirroring <see cref="TpmPendingAudit"/>'s shape: never serialized, and always
/// <see langword="null"/> between commands.
/// </summary>
/// <remarks>
/// Stamped by <c>CompleteNoAuthOverSessions</c> once every session in the wrapper's authorization area has
/// verified, immediately before it re-dispatches the wrapped command's own inner request
/// (<see cref="TpmNoAuthOverSessionsRequested.Inner"/>) through <c>DispatchCommand</c>. Consumed by
/// <c>ApplyPendingSessionFrame</c> the moment that inner dispatch's own effect/feedback loop produces a fresh
/// terminal <see cref="TpmResponseIntent"/>: on <c>TPM_RC_SUCCESS</c> the frame and the plain intent are handed
/// to a declared <see cref="TpmFrameNoAuthSessionsAction"/>, which serializes the plain intent and wraps it in
/// this framing; on any other code <see cref="Dispose"/> releases the frame and the inner's own bare,
/// <c>TPM_ST_NO_SESSIONS</c> response stands unchanged (TPM 2.0 Library Part 3, clause 5.9: "If that code is not
/// TPM_RC_SUCCESS, the post processing code will not update any session or audit data and will return a
/// 10-octet response packet.").
/// </remarks>
/// <param name="Framing">The command code and every companion slot's response-entry material, in command-session order — built exactly as <c>CompleteNoAuthOverSessions</c> builds every other command's framing, over the wrapper's whole authorization area.</param>
/// <param name="ResponseCarriesHandle">Whether the framed response carries a 4-octet response handle ahead of parameterSize (<c>TPMA_CC.R_HANDLE</c>, TPM 2.0 Library Part 2, clause 8.9, Table 43; TPM 2.0 Library Part 3, clause 4.3) — set for the commands whose response returns a handle (<c>TPM2_HashSequenceStart()</c>, <c>TPM2_SignSequenceStart()</c>, <c>TPM2_VerifySequenceStart()</c>, <c>TPM2_LoadExternal()</c>), clear for every other command the framing serves.</param>
public sealed record TpmPendingSessionFrame(TpmOverSessionsFraming Framing, bool ResponseCarriesHandle): IDisposable
{
    /// <summary>
    /// Releases every companion slot's caller-nonce carrier (<see cref="TpmResponseSession.NonceCaller"/>) —
    /// the same release <see cref="TpmSimulator"/>'s <c>ReleaseResponseSessionNonces</c> applies to every other
    /// command's response-session entries, applied here directly since this type is declared in
    /// <see cref="Automata"/> rather than beside that helper. Each entry's session key and negotiated symmetric
    /// definition are BORROWED from the durable session record and need no release; a real slot's supplied hmac
    /// was already released by <see cref="TpmAuthorizationArea.ReleaseCredentials"/> before this frame was
    /// built, and a password slot never reaches a companion frame at all (Part 1, clause 15.6.4's password rule
    /// refuses it before framing is ever stamped). Called only when the wrapped command's inner transition never
    /// reaches a <c>TPM_RC_SUCCESS</c> terminal intent — a fault unwinding the effect loop, or a bare failure the
    /// inner command's own tail answers.
    /// </summary>
    public void Dispose()
    {
        foreach(TpmResponseSession session in Framing.Sessions)
        {
            session.NonceCaller.Dispose();
        }
    }
}

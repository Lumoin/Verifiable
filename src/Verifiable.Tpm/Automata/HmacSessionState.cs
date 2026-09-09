using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of a started bound, unsalted HMAC session with parameter encryption: the session hash
/// algorithm, the negotiated symmetric definition, the derived session key, the current nonceTPM, and the audit
/// digest the session accumulates once it is first used for audit (TPM 2.0 Library Part 1, clauses 16.6, 17.1
/// and 18). It is the smallest session model the encrypt-attributed command path needs — the session key drives
/// both the response HMAC and the parameter-encryption mask/keystream, and the nonceTPM rolls once per command.
/// </summary>
/// <remarks>
/// <para>
/// The session key, bound-entity value, and audit digest are held in pooled, zero-on-dispose sensitive carriers
/// (<see cref="SymmetricKeyMemory"/>, <see cref="SessionBoundEntity"/>, <see cref="Tpm2bDigest"/>): durable model
/// state owned by the live automaton for the lifetime of the session (until <c>TPM2_FlushContext()</c> releases
/// it), the first two fixed at <c>TPM2_StartAuthSession()</c> and never replaced, the audit digest replaced
/// wholesale by <see cref="WithAudit(Tpm2bDigest)"/> once per audited command. This record is the carriers'
/// single owner — everything downstream (verification queues, response-framing records, actions) reads them
/// through non-owning <see cref="ReadOnlyMemory{T}"/> views and never disposes them. The nonceTPM is the
/// structure Part 2, clause 10.3.4, Table 92 names — <c>TPM2B_NONCE</c>, the declared type of
/// <c>TPMS_AUTH_COMMAND.nonce</c> and <c>TPMS_AUTH_RESPONSE.nonce</c> (clauses 10.12.2 and 10.12.3, Tables 153
/// and 154) — so it rides in a <see cref="Tpm2bNonce"/> carrier this record likewise owns, replaced wholesale by
/// <see cref="WithNonceTpm(Tpm2bNonce)"/> once per command response.
/// </para>
/// <para>
/// Only bind entities whose authorization value is empty are modelled (the objects it creates carry empty auth),
/// so <c>sessionValue = sessionKey ‖ authValue</c> (Part 1, clause 18.1) reduces to the session key alone, which
/// is what both the response HMAC and the parameter encryption key on.
/// </para>
/// </remarks>
/// <param name="Handle">The session handle assigned at <c>TPM2_StartAuthSession()</c> (most-significant octet <c>TPM_HT_HMAC_SESSION</c>, TPM 2.0 Library Part 2, clause 7.2).</param>
/// <param name="SessionAlg">The session hash algorithm (the <c>authHash</c> supplied at start), which drives the KDFa derivations, the response HMAC width, and the nonce width.</param>
/// <param name="Symmetric">The symmetric definition negotiated at start (XOR obfuscation or AES-CFB), which keys parameter encryption of the first response parameter.</param>
/// <param name="SessionKey">The session key, used as the HMAC key and the parameter-encryption key seed: <c>KDFa</c>-derived (Part 1, clause 16.6.10 equation 20) when bound and/or salted, or the shared Empty-Buffer carrier <see cref="TpmSimulatorState.EmptySessionKey"/> when neither (clause 16.6.9). This record owns the carrier.</param>
/// <param name="NonceTpm">The current nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) in an owned pooled carrier: seeded by the initial value returned at start and rolled to a fresh value on each command response (Part 1, clause 16.6.5) through <see cref="WithNonceTpm(Tpm2bNonce)"/>, which releases the superseded carrier as the replacement lands. This record owns the carrier; the pending-verification queue, the response-framing records, and the response intents read it as a borrow and never dispose it.</param>
/// <param name="BoundEntity">
/// The bound-entity value captured once at <c>TPM2_StartAuthSession()</c> (<see cref="SessionBoundEntity.Unbound"/>
/// for <c>bind == TPM_RH_NULL</c>): the bind entity's Name in this model's recorded bind form — a permanent
/// handle's or NV Index's 4-octet big-endian handle value, an object's own retained
/// <see cref="TransientKeyState.Name"/> — with the entity's stripped authValue XORed into the tail (Part 4,
/// <c>SessionComputeBoundEntity()</c>; Part 1, clause 16.6.10). A command-HMAC verification omits the bound
/// entity's authValue from the HMAC key precisely when the entity being authorized NOW recomputes to this same
/// value (equations 21/22) — binding already proved knowledge of the authValue once via the session-key KDFa, so
/// re-including it is redundant — and because the authValue is folded in, a rotation of the entity's authValue or
/// a same-Name squatter ends the binding structurally. This record owns the carrier.
/// </param>
/// <param name="IsBoundEntityDaProtected">
/// Whether the entity this session is bound to receives dictionary-attack protection, captured once at
/// <c>TPM2_StartAuthSession()</c> alongside <see cref="BoundEntity"/> — TPM 2.0 Library Part 1, clause
/// 16.6.10: "The noDA attribute of the bind entity is recorded in the session context." It is <see langword="false"/>
/// for an unbound session and for a session bound to a permanent entity other than <c>TPM_RH_LOCKOUT</c>
/// (clause 16.8.7: "If a session is bound to a permanent entity other than TPM_RH_LOCKOUT, then the session is
/// not bound to an entity that has DA protection"). While it is set, a failed use of this session charges the
/// authorization failure counter and is refused outright in Lockout mode whatever the DA state of the entity the
/// session authorizes, because clause 16.8.7 makes the charge an OR: "the authorization failure counter
/// (failedTries) is incremented if either the entity being authorized is subject to DA protection or if the
/// session is bound to an entity that has DA protection." Part 4 records the identical state as the
/// <c>isDaBound</c> session attribute, computed once when the session is created.
/// </param>
/// <param name="IsBoundToLockout">
/// Whether the bind entity is <c>TPM_RH_LOCKOUT</c> — the sole permanent entity whose authValue is
/// dictionary-attack protected (TPM 2.0 Library Part 1, clause 16.8.1: "lockoutAuth is DA protected even though
/// it is a permanent entity"). It is never set without <see cref="IsBoundEntityDaProtected"/> also being set,
/// matching Part 4's own <c>isLockoutBound</c> derivation from <c>isDaBound</c>. A failed use of such a session
/// takes the one-strike lockoutAuth discipline (clause 16.8.5: an authorization failure associated with
/// lockoutAuth enters the special lockout state "regardless of the setting of failedTries and maxTries") rather
/// than the ordinary counter, because the session key genuinely folded lockoutAuth through the bind KDFa.
/// </param>
/// <param name="IsAudit">
/// Whether this session has completed at least one command with the <c>audit</c> attribute SET (Part 4's
/// <c>isAudit</c>). It starts <see langword="false"/> and is latched permanently <see langword="true"/> by
/// <see cref="WithAudit(Tpm2bDigest)"/> on the first successful command that uses the session for audit — TPM
/// 2.0 Library Part 3, clause 18.5.1, NOTE: "A session does not become an audit session until the successful
/// completion of the command in which the session is first used as an audit session."
/// </param>
/// <param name="AuditDigest">
/// The session's audit digest (TPM 2.0 Library Part 1, clause 17.1, equation 30). OWNED: <see cref="Tpm2bDigest.Empty"/>
/// until <see cref="IsAudit"/> first becomes <see langword="true"/>, then the Zero Digest of the session hash
/// algorithm's width (clause 17.1: "The initialization value is a Zero Digest with the number of octets
/// determined by the hash algorithm of the session"), extended thereafter by <c>H(old ‖ cpHash ‖ rpHash)</c> on
/// every successful audited command. Clause 17.1's NOTE: audit within an encrypted session records the
/// encrypted cpHash and/or rpHash.
/// </param>
public sealed record HmacSessionState(
    TpmiShHmac Handle,
    TpmiAlgHash SessionAlg,
    TpmtSymDef Symmetric,
    SymmetricKeyMemory SessionKey,
    Tpm2bNonce NonceTpm,
    SessionBoundEntity BoundEntity,
    Tpm2bDigest AuditDigest,
    bool IsBoundEntityDaProtected = false,
    bool IsBoundToLockout = false,
    bool IsAudit = false): IDisposable, IAuthSessionState
{
    /// <summary>
    /// The <see cref="IAuthSessionState"/> reading of this session's handle, widened from
    /// <see cref="TpmiShHmac"/> to the generic <see cref="TpmHandle"/> shape the interface exposes.
    /// </summary>
    TpmHandle IAuthSessionState.Handle => Handle;

    /// <summary>
    /// Returns a copy of this session carrying <paramref name="rolledNonceTpm"/> as its nonceTPM, releasing the
    /// superseded carrier as the replacement lands — the roll a command response performs exactly once (TPM 2.0
    /// Library Part 1, clause 16.6.5). The dispose-immune shared empty carrier is safe to supersede.
    /// </summary>
    /// <param name="rolledNonceTpm">The freshly generated nonceTPM in an owned carrier; ownership transfers to the returned session.</param>
    /// <returns>The session with its nonceTPM rolled.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of rolledNonceTpm transfers to the returned HmacSessionState's NonceTpm, which the record's Dispose or the next roll releases; the outgoing carrier is disposed here before the with-copy replaces it.")]
    public HmacSessionState WithNonceTpm(Tpm2bNonce rolledNonceTpm)
    {
        NonceTpm.Dispose();

        return this with { NonceTpm = rolledNonceTpm };
    }

    /// <summary>
    /// Returns a copy of this session marked as an audit session, carrying <paramref name="newDigest"/> as its
    /// audit digest and its bind value lost — TPM 2.0 Library Part 1, clause 17.1: "If the session was bound
    /// when created (see Clause 16.6.10 and Clause 16.6.12), the bind value is lost and any further use of the
    /// session for authorization will require that the authValue be used in the HMAC." Part 4's
    /// <c>InitAuditSession()</c> clears <c>isBound</c> alone, so <see cref="IsBoundEntityDaProtected"/> and
    /// <see cref="IsBoundToLockout"/> are left as they were. Releases the superseded <see cref="AuditDigest"/>
    /// (the dispose-immune <see cref="Tpm2bDigest.Empty"/> and <see cref="Tpm2bDigest.Zero(TpmiAlgHash)"/> widths
    /// are safe to supersede unconditionally) and the superseded <see cref="BoundEntity"/>, unless it is already
    /// <see cref="SessionBoundEntity.Unbound"/>.
    /// </summary>
    /// <param name="newDigest">The audit digest to install; ownership transfers to the returned session.</param>
    /// <returns>The session marked as an audit session, unbound, carrying <paramref name="newDigest"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of newDigest transfers to the returned HmacSessionState's AuditDigest, which the record's Dispose or the next WithAudit call releases; the superseded AuditDigest and BoundEntity are disposed here before the with-copy replaces them.")]
    public HmacSessionState WithAudit(Tpm2bDigest newDigest)
    {
        AuditDigest.Dispose();

        if(!ReferenceEquals(BoundEntity, SessionBoundEntity.Unbound))
        {
            BoundEntity.Dispose();
        }

        return this with { IsAudit = true, AuditDigest = newDigest, BoundEntity = SessionBoundEntity.Unbound };
    }

    /// <summary>
    /// Releases the session's owned <see cref="SessionKey"/>, <see cref="NonceTpm"/>, <see cref="BoundEntity"/>
    /// and <see cref="AuditDigest"/> carriers.
    /// Called when the session leaves the automaton's dictionary for good (<c>TPM2_FlushContext()</c>,
    /// any <c>TPM2_Startup()</c>'s session flush, simulator teardown); the shared Empty-Buffer key, the shared
    /// empty nonce, <see cref="SessionBoundEntity.Unbound"/> and the shared Empty/Zero digest widths are
    /// dispose-immune, so the walk is safe for an unbound, unsalted, non-audit session.
    /// </summary>
    public void Dispose()
    {
        SessionKey.Dispose();
        NonceTpm.Dispose();
        BoundEntity.Dispose();
        AuditDigest.Dispose();
    }

    /// <summary>
    /// Value equality with OWNERSHIP identity for the owned carriers: two sessions are equal only when
    /// they share the same <see cref="SessionKey"/>, <see cref="NonceTpm"/>, <see cref="BoundEntity"/> and
    /// <see cref="AuditDigest"/> instances — reference
    /// comparison preserves the object-identity semantics plain memory fields have and never reads
    /// carrier content, so a superseded or disposed snapshot cannot throw here (see
    /// <see cref="NvIndexState.Equals(NvIndexState)"/> for the shared rationale).
    /// </summary>
    /// <param name="other">The session to compare against.</param>
    /// <returns><see langword="true"/> when every field matches and the carriers are the same instances.</returns>
    public bool Equals(HmacSessionState? other) =>
        other is not null
        && Handle == other.Handle
        && SessionAlg == other.SessionAlg
        && Symmetric.Equals(other.Symmetric)
        && ReferenceEquals(SessionKey, other.SessionKey)
        && ReferenceEquals(NonceTpm, other.NonceTpm)
        && ReferenceEquals(BoundEntity, other.BoundEntity)
        && IsBoundEntityDaProtected == other.IsBoundEntityDaProtected
        && IsBoundToLockout == other.IsBoundToLockout
        && IsAudit == other.IsAudit
        && ReferenceEquals(AuditDigest, other.AuditDigest);

    /// <summary>
    /// Hashes the session's immutable identity fields, consistent with
    /// <see cref="Equals(HmacSessionState)"/> without ever reading carrier content.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() => HashCode.Combine(Handle, SessionAlg, IsBoundEntityDaProtected, IsBoundToLockout, IsAudit);
}

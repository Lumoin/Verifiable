using System;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// One session's material for a pending command-HMAC verification (TPM 2.0 Library Part 1, clause 16.6; Part 3,
/// clause 5.6): the resolved session's key/nonce, the entity authValue (if any) and dictionary-attack-protection
/// flag for this authorization, the two nonce-binding fold terms (Part 1, clause 16.6.3.4 — only ever non-empty
/// for the first session in a command's authorization area), and the supplied <c>hmac</c> to compare against. Carried
/// by <see cref="TpmVerifyCommandHmacAction"/> and its continuation <see cref="TpmCommandHmacVerified"/> so the
/// shared verification mechanism threads through a command's session queue one session at a time.
/// </summary>
/// <param name="SessionHandle">The HMAC session handle being verified.</param>
/// <param name="SessionIndex">
/// The zero-based position of this session within the command's authorization area — the session-index term of
/// the format-one response-code encoding (TPM 2.0 Library Part 2, clause 6.6.2) and the input to
/// <see cref="TpmLifecycleTransitions"/>'s session-index-encoded rejection helpers.
/// </param>
/// <param name="SessionAlg">The session hash algorithm driving the HMAC computation.</param>
/// <param name="SessionKey">The session's KDFa-derived session key — a borrowed reference to the carrier the durable session record owns; the verification effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="AuthValue">
/// The authorization value folded into the HMAC key alongside <see cref="SessionKey"/> (TPM 2.0 Library Part 1,
/// clause 16.6.10 equation 21) — a borrowed reference to the carrier the durable state owns; the verification
/// effect reads its trailing-zero-stripped view at the HMAC primitive and never disposes it. The shared empty
/// carrier when this session authorizes no entity, or when the bind-omission applies (the session's bound
/// entity Name equals the entity being authorized now, equation 22).
/// </param>
/// <param name="IsDaProtected">
/// Whether the entity this session authorizes is dictionary-attack protected (<see langword="false"/> when the
/// session authorizes no entity) — decides whether a mismatch increments <c>FailedTries</c> (<c>TPM_RC_AUTH_FAIL</c>)
/// or leaves it untouched (<c>TPM_RC_BAD_AUTH</c>), TPM 2.0 Library Part 3, clause 5.6.
/// </param>
/// <param name="NonceCaller">
/// This command's caller nonce for the session (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4,
/// Table 92) — the cpHash-verification nonceNewer. A BORROWED reference to the carrier the request record
/// owns; the verification effect reads it at the HMAC primitive and never disposes it, and the request outlives
/// the whole verification queue, so the same borrow is safe across the re-thread that verifies each remaining
/// session in turn.
/// </param>
/// <param name="NonceTpm">The session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) — the PRE-roll value the caller saw (the cpHash-verification nonceOlder); the roll to a fresh value happens only after verification succeeds. A borrowed reference to the carrier the durable session record owns; the verification effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="FoldedNonceDecrypt">
/// The nonceTPM of the OTHER session in the command that carries the <c>decrypt</c> attribute — equation 17's
/// <c>{‖ nonceTPMdecrypt}</c> term (TPM 2.0 Library Part 1, clauses 16.6.3.4 and 16.6.5): non-empty only when
/// <see cref="SessionIndex"/> is zero and this session itself authorizes an entity; the shared empty carrier for
/// every other session and for a decrypt session that IS this session (its own nonceTPM already counts once as
/// <see cref="NonceTpm"/>, so folding it again would be redundant, not additive). A borrowed reference to the
/// carrier the durable session record owns; the verification effect never disposes it.
/// </param>
/// <param name="FoldedNonceEncrypt">
/// The nonceTPM of the OTHER session in the command that carries the <c>encrypt</c> attribute — equation 17's
/// <c>{‖ nonceTPMencrypt}</c> term, folded AFTER <see cref="FoldedNonceDecrypt"/> in that equation's own order.
/// The shared empty carrier on the same conditions, and additionally when the encrypting session IS the
/// decrypting one: "If the same session (not the first session) is used for decrypt and encrypt, its nonceTPM is
/// only used once" (Part 1, clause 16.6.5). The two terms are carried as a PAIR rather than pre-concatenated
/// because a pure transition holds no memory pool; the verification effect, which already assembles its HMAC
/// message in pooled scratch, concatenates them there. A borrowed reference to the carrier the durable session
/// record owns; the verification effect never disposes it.
/// </param>
/// <param name="SessionAttributes">This session's command session-attributes octet.</param>
/// <param name="SuppliedHmac">
/// The <c>hmac</c> field the caller supplied for this session (<c>TPM2B_AUTH</c>, TPM 2.0 Library Part 2,
/// clause 10.12.2, Table 156). A BORROWED reference to the carrier the request record owns; the verification
/// effect reads it at the fixed-time compare and never disposes it, and the request outlives the whole
/// verification queue, so the same borrow is safe across the re-thread that verifies each remaining session in
/// turn.
/// </param>
/// <param name="IsLockoutEntity">
/// Whether the entity this session authorizes is <c>TPM_RH_LOCKOUT</c> — the sole permanent hierarchy that is
/// dictionary-attack protected (TPM 2.0 Library Part 1, clause 16.8's own carve-out; every other permanent
/// hierarchy is DA-exempt). A mismatch against this entity disables <c>LockoutAuthEnabled</c> and anchors the
/// self-heal timer (clause 16.8.5), rather than incrementing the ordinary <c>FailedTries</c> counter every
/// other DA-protected entity's mismatch feeds — the same one-strike discipline
/// <c>TPM2_DictionaryAttackLockReset()</c>/<c>TPM2_DictionaryAttackParameters()</c> and the password arm of
/// <c>TPM2_PolicySecret()</c> already apply. <see langword="false"/> for every existing session-authorized
/// command (none of which authorizes a hierarchy), so <c>RejectSessionAuthFailure</c>'s existing generic
/// behavior is unchanged for them.
/// </param>
/// <param name="PolicyBindingKind">
/// <see cref="TpmPolicyCpHashKind.None"/> for an ordinary command-HMAC verification; otherwise this entry is a
/// POLICY-BINDING check that judges a policy session's latched cpHash (<see cref="TpmPolicyCpHashKind.CpHash"/>),
/// nameHash (<see cref="TpmPolicyCpHashKind.NameHash"/>) or pHash (<see cref="TpmPolicyCpHashKind.ParametersHash"/>)
/// against the command it authorizes (TPM 2.0 Library Part 3, clauses 23.13/23.14/23.15/23.24; Part 4
/// <c>CheckPolicyAuthSession</c>), reading no secret and never charging dictionary-attack state. Built by
/// <see cref="ForPolicyBinding"/>.
/// </param>
/// <param name="IsPasswordCompare">
/// Whether this entry is a <c>TPM_RS_PW</c> slot's password compare rather than a command-HMAC verification: the
/// effect compares <see cref="SuppliedHmac"/> — the password in the clear — against <see cref="AuthValue"/> as a
/// password (TPM 2.0 Library Part 1, clause 16.6.4.3), computing no cpHash, so the slot is judged in its wire
/// position between the real sessions around it (Part 3, clause 5.6; Part 4 <c>ParseSessionBuffer</c>). Built by
/// <see cref="ForPasswordCompare"/>.
/// </param>
/// <param name="PreGateRefusal">
/// The uncharged refusal this slot owes AHEAD of its credential — <c>TPM_RC_LOCKOUT</c> for a session bound to an
/// entity in lockout (Part 3, clause 11.1.1) or an authorized entity whose dictionary-attack standing is in
/// lockout (clause 5.6, check 3), <c>TPM_RC_POLICY_FAIL</c> for a <c>userWithAuth</c>-CLEAR object authorized by
/// a password or HMAC session (check 7.1; Part 1, clause 16.6.17) — decided when the area was resolved and
/// applied in the slot's own turn, so it answers only once every earlier slot has verified; <see langword="null"/>
/// when the slot owes none.
/// </param>
/// <param name="PolicyBoundDigest">
/// The latched digest a policy-binding entry checks the command against (<c>TPM2B_DIGEST</c>, TPM 2.0 Library
/// Part 2, clause 10.3.2, Table 90) — a BORROW of the carrier the durable session record owns; the verification
/// effect reads it at the fixed-time compare and never disposes it. <see langword="null"/> for an ordinary
/// command-HMAC verification.
/// </param>
public sealed record TpmPendingSessionVerification(
    TpmiShAuthSession SessionHandle,
    int SessionIndex,
    TpmiAlgHash SessionAlg,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth AuthValue,
    bool IsDaProtected,
    Tpm2bNonce NonceCaller,
    Tpm2bNonce NonceTpm,
    Tpm2bNonce FoldedNonceDecrypt,
    Tpm2bNonce FoldedNonceEncrypt,
    TpmaSession SessionAttributes,
    Tpm2bAuth SuppliedHmac,
    bool IsLockoutEntity = false,
    TpmPolicyCpHashKind PolicyBindingKind = TpmPolicyCpHashKind.None,
    Tpm2bDigest? PolicyBoundDigest = null,
    bool IsPasswordCompare = false,
    TpmRcConstants? PreGateRefusal = null)
{
    /// <summary>
    /// Builds a <c>TPM_RS_PW</c> slot's entry for a queue judged in wire order: the slot's plaintext password is
    /// compared against the entity's authValue as a password — both sides trailing-zero-stripped, in fixed time
    /// (TPM 2.0 Library Part 1, clause 16.6.4.3) — in its own turn, once every earlier slot has verified, so a
    /// mismatch is charged only on a request whose earlier authorizations were proved (Part 3, clause 5.6, judged
    /// per authorization in the order the sessions appear; Part 4 <c>ParseSessionBuffer</c>).
    /// </summary>
    /// <param name="sessionIndex">The slot's zero-based wire position.</param>
    /// <param name="authValue">The entity's authValue, borrowed from the durable state.</param>
    /// <param name="isDaProtected">Whether a mismatch charges <c>failedTries</c>.</param>
    /// <param name="suppliedPassword">The slot's <c>hmac</c> field — the password in the clear; borrowed from the request record.</param>
    /// <param name="preGateRefusal">The uncharged gate refusal the slot owes ahead of its compare, or <see langword="null"/>.</param>
    /// <returns>The password-compare entry.</returns>
    public static TpmPendingSessionVerification ForPasswordCompare(int sessionIndex, Tpm2bAuth authValue, bool isDaProtected, Tpm2bAuth suppliedPassword, TpmRcConstants? preGateRefusal) =>
        new(
            TpmiShAuthSession.FromValue((uint)TpmRh.TPM_RH_PW), sessionIndex, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL), SessionKey: TpmSimulatorState.EmptySessionKey,
            AuthValue: authValue, IsDaProtected: isDaProtected, NonceCaller: Tpm2bNonce.Empty, NonceTpm: Tpm2bNonce.Empty,
            FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty, SessionAttributes: default, SuppliedHmac: suppliedPassword,
            IsLockoutEntity: false, IsPasswordCompare: true, PreGateRefusal: preGateRefusal);

    /// <summary>
    /// Builds a POLICY-BINDING verification entry: a policy session's latched cpHash, nameHash or pHash is judged
    /// against the command it now authorizes (TPM 2.0 Library Part 3, clauses 23.13/23.14/23.15/23.24; Part 4
    /// <c>CheckPolicyAuthSession</c>) rather than a command HMAC being recomputed. The check reads no secret, so
    /// the entity/dictionary-attack fields carry their inert sentinels and the compare is not a dictionary-attack
    /// event.
    /// </summary>
    /// <param name="sessionHandle">The policy session's handle, for the session-index-encoded framing.</param>
    /// <param name="sessionIndex">The zero-based position of this session in the command's authorization area.</param>
    /// <param name="sessionAlg">The session's policy hash algorithm, sizing and selecting the digest the binding is checked under.</param>
    /// <param name="bindingKind">Whether the slot holds a cpHash (<see cref="TpmPolicyCpHashKind.CpHash"/>), a nameHash (<see cref="TpmPolicyCpHashKind.NameHash"/>) or a pHash (<see cref="TpmPolicyCpHashKind.ParametersHash"/>) binding.</param>
    /// <param name="boundDigest">The latched digest — a BORROW of the carrier the durable session record owns; the verification effect reads it and never disposes it.</param>
    /// <returns>The policy-binding verification entry.</returns>
    public static TpmPendingSessionVerification ForPolicyBinding(
        TpmiShAuthSession sessionHandle, int sessionIndex, TpmiAlgHash sessionAlg, TpmPolicyCpHashKind bindingKind, Tpm2bDigest boundDigest) =>
        new(
            sessionHandle, sessionIndex, sessionAlg, SessionKey: TpmSimulatorState.EmptySessionKey,
            AuthValue: Tpm2bAuth.Empty, IsDaProtected: false, NonceCaller: Tpm2bNonce.Empty, NonceTpm: Tpm2bNonce.Empty,
            FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty, SessionAttributes: default, SuppliedHmac: Tpm2bAuth.Empty,
            IsLockoutEntity: false, PolicyBindingKind: bindingKind, PolicyBoundDigest: boundDigest);
}

/// <summary>
/// The result of executing a <see cref="TpmVerifyCommandHmacAction"/>: whether the current pending session's
/// command HMAC matched, fed back so the transition can either reject (dictionary-attack-aware) or advance to the
/// next queued session, and — once the queue empties — resume the original command via <see cref="NextRequest"/>.
/// Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="Matched">Whether the recomputed command HMAC equalled the supplied one (TPM 2.0 Library Part 3, clause 5.6, check 9).</param>
/// <param name="CommandCode">The command code, echoed for the rejection's response framing.</param>
/// <param name="SessionIndex">The verified (or failed) session's zero-based index, for the format-one session-index encoding.</param>
/// <param name="IsDaProtected">Whether the verified session's authorized entity is dictionary-attack protected, deciding <c>AUTH_FAIL</c> versus <c>BAD_AUTH</c> on a mismatch.</param>
/// <param name="HandleNames">The command's handle-Name area as its ordered terms, threaded through so a subsequent queued session's cpHash can be recomputed. Every term is a BORROW; nothing here is owned.</param>
/// <param name="ParameterArea">The command's raw parameter-area bytes, threaded through for the same reason. A BORROW of the carrier <see cref="NextRequest"/> owns.</param>
/// <param name="Remaining">The still-unverified sessions in the command's authorization area, in order.</param>
/// <param name="NextRequest">The original parsed command request to resume once every session has verified.</param>
/// <param name="IsLockoutEntity">Threaded from <see cref="TpmPendingSessionVerification.IsLockoutEntity"/>: whether a mismatch must disable <c>LockoutAuthEnabled</c> rather than increment the ordinary DA counter.</param>
/// <param name="IsPolicyBinding">Whether the entry just judged was a POLICY-BINDING check (<see cref="TpmPendingSessionVerification.PolicyBindingKind"/>) rather than a command-HMAC verification: a mismatch is then the policy's own <c>TPM_RC_POLICY_FAIL</c>, uncharged, never a session-encoded authorization failure.</param>
/// <param name="AuditCpHash">
/// The just-verified session's cpHash, retained rather than released, when <see cref="AuditSession"/> claims
/// <c>audit</c> (TPM 2.0 Library Part 1, clause 17.1) — <see langword="null"/> for every other verified session.
/// OWNED until <see cref="TpmLifecycleTransitions"/>'s generic verified-feedback handler adopts it onto
/// <see cref="TpmSimulatorState.PendingAudit"/>; a handler that receives it without adopting it (a refusal on
/// another queued session) disposes it instead of leaking it.
/// </param>
/// <param name="AuditSession">The just-verified session's handle, when it is the one <see cref="AuditCpHash"/> was retained for; <see langword="default"/> otherwise.</param>
/// <param name="AuditAttributes">The just-verified session's command-side <c>TPMA_SESSION</c> octet, when it is the audit-claiming one; <see langword="default"/> otherwise.</param>
/// <param name="AuditSessionAlg">The just-verified session's hash algorithm, when it is the audit-claiming one; <see langword="default"/> otherwise.</param>
public sealed record TpmCommandHmacVerified(
    bool Matched,
    TpmCcConstants CommandCode,
    int SessionIndex,
    bool IsDaProtected,
    TpmCommandHandleNames HandleNames,
    TpmParameterArea ParameterArea,
    ImmutableArray<TpmPendingSessionVerification> Remaining,
    TpmSimulatorInput NextRequest,
    bool IsLockoutEntity = false,
    bool IsPolicyBinding = false,
    Tpm2bDigest? AuditCpHash = null,
    TpmiShAuthSession AuditSession = default,
    TpmaSession AuditAttributes = default,
    TpmiAlgHash AuditSessionAlg = default): TpmSimulatorInput;

/// <summary>
/// One already-verified session's material for framing a real per-session <c>TPM2_Unseal()</c> response entry
/// (TPM 2.0 Library Part 1, clauses 15.7 and 16.6.5): the effect rolls a fresh nonceTPM and computes a real response
/// HMAC for it — the general alternative to a satisfied plain policy session's zero-length-HMAC placeholder entry,
/// and general enough to cover both an authorizing HMAC session (Part 3, clause 5.6) and a separate
/// encrypt-only session (already shipped) uniformly, since the response HMAC uses THE SAME key the command HMAC
/// verification did (Part 1, clause 16.6.8).
/// </summary>
/// <param name="SessionHandle">The session handle whose nonceTPM is rolled once framed.</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session key — a borrowed reference to the carrier the durable session record owns; the framing effect reads it at the HMAC primitive and never disposes it.</param>
/// <param name="AuthValue">The authValue folded into the response HMAC key alongside <see cref="SessionKey"/> — a borrowed reference to the carrier the durable state owns, carrying the same value (and the same bind-omission decision) the command-HMAC verification used; the framing effect reads its trailing-zero-stripped view at the HMAC primitive and never disposes it.</param>
/// <param name="EntityAuthValue">
/// The authValue of the entity this session authorizes, folded into the CIPHER key alongside
/// <see cref="SessionKey"/> when <see cref="Encrypts"/> is set — the entity's LIVE value, UNRESOLVED by the
/// session's bind, because "the binding of the session is ignored" for parameter encryption (TPM 2.0 Library
/// Part 1, clause 18.1), unlike <see cref="AuthValue"/>, which carries the HMAC key's bind-omission decision
/// (clause 16.6.10, equation 22). The shared empty carrier when the session authorizes no entity, whose
/// sessionValue is then the session key alone. A borrowed reference the durable state owns.
/// </param>
/// <param name="NonceCaller">
/// This session's command caller nonce (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) —
/// the response HMAC's nonceOlder and, when <see cref="Encrypts"/> is set, the keystream's. OWNED by this
/// entry, transferred out of the request record by the continuation that built the entry, and released by the
/// framing effect's <see langword="finally"/>.
/// </param>
/// <param name="SessionAttributes">This session's command session-attributes octet, echoed into its response entry.</param>
/// <param name="Encrypts">Whether this session carries the <c>encrypt</c> attribute and so protects <c>outData</c> (TPM 2.0 Library Part 1, clause 18; at most one session may set it). Either slot may set it — "a session with this attribute does not need to be associated with an entity identified in the handle area" (clause 15.6.4, Table 15) — so the authorizing slot carries it as readily as a companion.</param>
/// <param name="Symmetric">The negotiated symmetric definition, meaningful only when <see cref="Encrypts"/> is set.</param>
public sealed record TpmUnsealResponseSession(
    TpmiShAuthSession SessionHandle,
    TpmiAlgHash SessionAlg,
    SymmetricKeyMemory SessionKey,
    Tpm2bAuth AuthValue,
    Tpm2bAuth EntityAuthValue,
    Tpm2bNonce NonceCaller,
    TpmaSession SessionAttributes,
    bool Encrypts,
    TpmtSymDef Symmetric);

/// <summary>
/// One framed real <c>TPM2_Unseal()</c> response session entry — the rolled nonceTPM and computed response HMAC
/// produced from a <see cref="TpmUnsealResponseSession"/> — carried by <see cref="TpmUnsealedOverSessions"/> for
/// the transition to roll the session's stored nonce and by <see cref="TpmSimulator"/> to frame the wire bytes.
/// </summary>
/// <param name="SessionHandle">The session whose nonceTPM is rolled to <paramref name="RetainedNonceTpm"/>.</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.3.4, Table 92) in an owned pooled carrier, framed as this entry's nonceNewer; the serialization step is its terminal owner.</param>
/// <param name="RetainedNonceTpm">The same octets in a SECOND owned carrier; the rolling transition transfers it onto the durable session record, and disposes it itself when that session has already left its table. Two carriers because the two owners' lifetimes are disjoint — the framed one dies with the response, the session's lives until the next roll or the session's flush.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="Hmac">The response HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c> as the <c>TPMS_AUTH_RESPONSE.hmac</c> <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2, clause 10.12.3, Table 157); owned, disposed after framing.</param>
/// <param name="NewAuditDigest">The extended audit digest (TPM 2.0 Library Part 1, clause 17.1, equation 30), OWNED, when this session claims <c>audit</c>; <see langword="null"/> otherwise. Released by <c>RollHmacSessionNonceAndAudit</c>'s adoption onto the durable session record, or by the entry's own release on a fault.</param>
public sealed record TpmUnsealFramedSessionEntry(
    TpmiShAuthSession SessionHandle,
    Tpm2bNonce NewNonceTpm,
    Tpm2bNonce RetainedNonceTpm,
    TpmaSession SessionAttributes,
    Tpm2bAuth Hmac,
    Tpm2bDigest? NewAuditDigest = null);

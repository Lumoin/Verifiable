using System;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// One session's material for a pending command-HMAC verification (TPM 2.0 Library Part 1, clause 19.6; Part 3,
/// clause 5.6): the resolved session's key/nonce, the entity authValue (if any) and dictionary-attack-protection
/// flag for this authorization, the nonce-binding fold terms (Part 1, clause 19.6.3.4 — only ever non-empty for
/// the first session in a command's authorization area), and the supplied <c>hmac</c> to compare against. Carried
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
/// <param name="SessionKey">The session's KDFa-derived session key.</param>
/// <param name="AuthValue">
/// The authorization value folded into the HMAC key alongside <see cref="SessionKey"/> (TPM 2.0 Library Part 1,
/// clause 17.6.10 equation 21), or empty when this session authorizes no entity, or when the bind-omission applies
/// (the session's bound entity Name equals the entity being authorized now, equation 22).
/// </param>
/// <param name="IsDaProtected">
/// Whether the entity this session authorizes is dictionary-attack protected (<see langword="false"/> when the
/// session authorizes no entity) — decides whether a mismatch increments <c>FailedTries</c> (<c>TPM_RC_AUTH_FAIL</c>)
/// or leaves it untouched (<c>TPM_RC_BAD_AUTH</c>), TPM 2.0 Library Part 3, clause 5.6.
/// </param>
/// <param name="NonceCaller">This command's caller nonce for the session (the cpHash-verification nonceNewer).</param>
/// <param name="NonceTpm">The session's stored nonceTPM — the PRE-roll value the caller saw (the cpHash-verification nonceOlder); the roll to a fresh value happens only after verification succeeds.</param>
/// <param name="FoldedNonces">
/// The concatenated nonceTPM of any OTHER session in the command that carries the <c>decrypt</c> or <c>encrypt</c>
/// attribute (TPM 2.0 Library Part 1, clause 19.6.3.4): non-empty only when <see cref="SessionIndex"/> is zero and
/// this session itself authorizes an entity; empty for every other session and for a decrypt/encrypt session that
/// IS this session (its own nonceTPM already counts once as <see cref="NonceTpm"/>, so folding it again would be
/// redundant, not additive).
/// </param>
/// <param name="SessionAttributes">This session's command session-attributes octet.</param>
/// <param name="SuppliedHmac">The <c>hmac</c> field the caller supplied for this session.</param>
public sealed record TpmPendingSessionVerification(
    uint SessionHandle,
    int SessionIndex,
    TpmAlgIdConstants SessionAlg,
    ReadOnlyMemory<byte> SessionKey,
    ReadOnlyMemory<byte> AuthValue,
    bool IsDaProtected,
    ReadOnlyMemory<byte> NonceCaller,
    ReadOnlyMemory<byte> NonceTpm,
    ReadOnlyMemory<byte> FoldedNonces,
    byte SessionAttributes,
    ReadOnlyMemory<byte> SuppliedHmac);

/// <summary>
/// The result of executing a <see cref="TpmVerifyCommandHmacAction"/>: whether the current pending session's
/// command HMAC matched, fed back so the transition can either reject (dictionary-attack-aware) or advance to the
/// next queued session, and — once the queue empties — resume the original command via <see cref="NextRequest"/>.
/// Internal to the effect loop; never arrives from the command transport.
/// </summary>
/// <param name="Matched">Whether the recomputed command HMAC equalled the supplied one (TPM 2.0 Library Part 3, clause 5.6, check 8).</param>
/// <param name="CommandCode">The command code, echoed for the rejection's response framing.</param>
/// <param name="SessionIndex">The verified (or failed) session's zero-based index, for the format-one session-index encoding.</param>
/// <param name="IsDaProtected">Whether the verified session's authorized entity is dictionary-attack protected, deciding <c>AUTH_FAIL</c> versus <c>BAD_AUTH</c> on a mismatch.</param>
/// <param name="HandleNames">The command's handle-Name area, threaded through so a subsequent queued session's cpHash can be recomputed.</param>
/// <param name="ParameterArea">The command's raw parameter-area bytes, threaded through for the same reason.</param>
/// <param name="Remaining">The still-unverified sessions in the command's authorization area, in order.</param>
/// <param name="NextRequest">The original parsed command request to resume once every session has verified.</param>
public sealed record TpmCommandHmacVerified(
    bool Matched,
    TpmCcConstants CommandCode,
    int SessionIndex,
    bool IsDaProtected,
    ReadOnlyMemory<byte> HandleNames,
    ReadOnlyMemory<byte> ParameterArea,
    ImmutableArray<TpmPendingSessionVerification> Remaining,
    TpmSimulatorInput NextRequest): TpmSimulatorInput;

/// <summary>
/// One already-verified session's material for framing a real per-session <c>TPM2_Unseal()</c> response entry
/// (TPM 2.0 Library Part 1, clauses 18.7 and 19.6): the effect rolls a fresh nonceTPM and computes a real response
/// HMAC for it — the general alternative to a satisfied plain policy session's zero-length-HMAC placeholder entry,
/// and general enough to cover both an authorizing HMAC session (Part 3, clause 5.6, this wave) and a separate
/// encrypt-only session (already shipped) uniformly, since the response HMAC uses THE SAME key the command HMAC
/// verification did (Part 1, clause 19.6.8).
/// </summary>
/// <param name="SessionHandle">The session handle whose nonceTPM is rolled once framed.</param>
/// <param name="SessionAlg">The session hash algorithm driving rpHash and the response HMAC.</param>
/// <param name="SessionKey">The session key.</param>
/// <param name="AuthValue">The authValue folded into the response HMAC key alongside <see cref="SessionKey"/> — the same value (and the same bind-omission decision) the command-HMAC verification used.</param>
/// <param name="NonceCaller">This session's command caller nonce (the response HMAC's nonceOlder).</param>
/// <param name="SessionAttributes">This session's command session-attributes octet, echoed into its response entry.</param>
/// <param name="Encrypts">Whether this session carries the <c>encrypt</c> attribute and so protects <c>outData</c> (TPM 2.0 Library Part 1, clause 19; at most one session may set it).</param>
/// <param name="Symmetric">The negotiated symmetric definition, meaningful only when <see cref="Encrypts"/> is set.</param>
public sealed record TpmUnsealResponseSession(
    uint SessionHandle,
    TpmAlgIdConstants SessionAlg,
    ReadOnlyMemory<byte> SessionKey,
    ReadOnlyMemory<byte> AuthValue,
    ReadOnlyMemory<byte> NonceCaller,
    byte SessionAttributes,
    bool Encrypts,
    TpmtSymDef Symmetric);

/// <summary>
/// One framed real <c>TPM2_Unseal()</c> response session entry — the rolled nonceTPM and computed response HMAC
/// produced from a <see cref="TpmUnsealResponseSession"/> — carried by <see cref="TpmUnsealedOverSessions"/> for
/// the transition to roll the session's stored nonce and by <see cref="TpmSimulator"/> to frame the wire bytes.
/// </summary>
/// <param name="SessionHandle">The session whose nonceTPM is rolled to <paramref name="NewNonceTpm"/>.</param>
/// <param name="NewNonceTpm">The freshly generated nonceTPM: framed as this entry's nonceNewer and stored as the session's rolled nonce.</param>
/// <param name="SessionAttributes">The response session-attributes octet, framed and folded into the response HMAC exactly as it was HMAC'd.</param>
/// <param name="Hmac">The response HMAC over <c>rpHash ‖ nonceTPM ‖ nonceCaller ‖ sessionAttributes</c>; disposed after framing.</param>
/// <param name="HmacLength">The number of valid octets in <paramref name="Hmac"/>.</param>
public sealed record TpmUnsealFramedSessionEntry(
    uint SessionHandle,
    ReadOnlyMemory<byte> NewNonceTpm,
    byte SessionAttributes,
    IMemoryOwner<byte> Hmac,
    int HmacLength);

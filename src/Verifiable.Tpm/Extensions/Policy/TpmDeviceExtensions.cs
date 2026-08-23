using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Policy;

/// <summary>
/// Policy (enhanced authorization) extensions for <see cref="TpmDevice"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Channel protection.</b> The policy assertion commands (<c>PolicyCommandCode</c>, <c>PolicyAuthValue</c>)
/// and <c>PolicyGetDigest</c> carry no confidential parameters — a command code, or the public policyDigest — so
/// they run without a parameter-encryption session. <c>PolicySecret</c> is the exception: its authHandle
/// authorization stands in for a real entity's authorization value, so its default verbs compose a bound HMAC
/// session against authHandle rather than a plaintext password session (see <c>PolicySecretAsync</c>'s own
/// remarks). The confidentiality- and integrity-sensitive step beyond that is the authorized command performed
/// under the policy session (for example <c>TPM2_Sign</c>); there the library offers the maximum-security
/// channel — a salted or bound session with AES-CFB parameter encryption and response-HMAC verification —
/// rather than an unprotected one.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with latest syntax.")]
public static class TpmDeviceExtensions
{
    /// <summary>The hash algorithm for the bound HMAC session <c>PolicySecretAsync</c> composes internally as its secure default.</summary>
    private const TpmAlgIdConstants PolicySecretSessionHash = TpmAlgIdConstants.TPM_ALG_SHA256;

    extension(TpmDevice device)
    {
        /// <summary>
        /// Starts a trial policy session, which accumulates a policyDigest without authorizing anything — used to
        /// compute the digest to set as an object's authPolicy.
        /// </summary>
        /// <param name="policyHash">The policy session's hash algorithm.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the started session or an error.</returns>
        public ValueTask<TpmResult<StartAuthSessionResponse>> StartTrialPolicySessionAsync(
            TpmAlgIdConstants policyHash, CancellationToken cancellationToken = default)
        {
            return StartPolicySessionCoreAsync(device, TpmSeConstants.TPM_SE_TRIAL, policyHash, cancellationToken);
        }

        /// <summary>
        /// Starts a policy session for authorization. The policyDigest it accumulates must match an object's
        /// authPolicy for the session to authorize use of that object.
        /// </summary>
        /// <param name="policyHash">The policy session's hash algorithm.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the started session or an error.</returns>
        public ValueTask<TpmResult<StartAuthSessionResponse>> StartPolicySessionAsync(
            TpmAlgIdConstants policyHash, CancellationToken cancellationToken = default)
        {
            return StartPolicySessionCoreAsync(device, TpmSeConstants.TPM_SE_POLICY, policyHash, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyCommandCode</c>, restricting the policy session to a single command.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="restrictedCommand">The command code the policy is restricted to.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyCommandCodeResponse>> PolicyCommandCodeAsync(
            uint policySession, TpmCcConstants restrictedCommand, CancellationToken cancellationToken = default)
        {
            return PolicyCommandCodeCoreAsync(device, policySession, restrictedCommand, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyAuthValue</c>, binding the policy to the authorized object's authorization value.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyAuthValueResponse>> PolicyAuthValueAsync(
            uint policySession, CancellationToken cancellationToken = default)
        {
            return PolicyAuthValueCoreAsync(device, policySession, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyPCR</c>, binding the policy to a set of PCRs.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="pcrBank">The PCR bank (hash algorithm) to select from.</param>
        /// <param name="pcrIndices">The PCR indices (0-23) to bind to.</param>
        /// <param name="pcrDigest">The expected digest of the selected PCR values, or empty to bind to the current PCR state.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyPcrResponse>> PolicyPcrAsync(
            uint policySession, TpmAlgIdConstants pcrBank, int[] pcrIndices, ReadOnlyMemory<byte> pcrDigest = default, CancellationToken cancellationToken = default)
        {
            return PolicyPcrCoreAsync(device, policySession, pcrBank, pcrIndices, pcrDigest, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyOR</c>, authorizing the session when its current policyDigest matches one of
        /// <paramref name="branchDigests"/> and collapsing the session to the OR digest
        /// (<c>H(0 || TPM_CC_PolicyOR || branches)</c>). On a trial session the match is skipped and the digest is
        /// set unconditionally.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="branchDigests">The allowed branch policy digests.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyOrResponse>> PolicyOrAsync(
            uint policySession, IReadOnlyList<ReadOnlyMemory<byte>> branchDigests, CancellationToken cancellationToken = default)
        {
            return PolicyOrCoreAsync(device, policySession, branchDigests, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyNV</c>, authorizing the session only when the contents of <paramref name="nvIndex"/>
        /// at <paramref name="offset"/> compare to <paramref name="operandB"/> as specified by
        /// <paramref name="operation"/>. The read of the Index is authorized with an empty-auth password session
        /// (the common case: an Index or hierarchy whose authorization value has not been set).
        /// </summary>
        /// <param name="authHandle">The authorization for reading the Index (the Index itself, or a hierarchy with the matching read attribute).</param>
        /// <param name="nvIndex">The NV Index whose contents are compared.</param>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="operandB">The value to compare the NV data against.</param>
        /// <param name="offset">The octet offset into the NV Index data.</param>
        /// <param name="operation">The TPM_EO comparison operation.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyNvResponse>> PolicyNvAsync(
            uint authHandle, uint nvIndex, uint policySession, ReadOnlyMemory<byte> operandB, ushort offset, TpmEoConstants operation, CancellationToken cancellationToken = default)
        {
            return PolicyNvCoreAsync(device, authHandle, nvIndex, policySession, operandB, offset, operation, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyCounterTimer</c>, authorizing the session only when the TPM's live
        /// <c>TPMS_TIME_INFO</c> (Time, Clock, resetCount, restartCount, Safe), at <paramref name="offset"/>,
        /// compares to <paramref name="operandB"/> as specified by <paramref name="operation"/>.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="operandB">The value to compare the live TPMS_TIME_INFO against.</param>
        /// <param name="offset">The octet offset into the marshaled TPMS_TIME_INFO.</param>
        /// <param name="operation">The TPM_EO comparison operation.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyCounterTimerResponse>> PolicyCounterTimerAsync(
            uint policySession, ReadOnlyMemory<byte> operandB, ushort offset, TpmEoConstants operation, CancellationToken cancellationToken = default)
        {
            return PolicyCounterTimerCoreAsync(device, policySession, operandB, offset, operation, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicySecret</c> (immediate form: <c>expiration = 0</c>, no ticket produced), binding the
        /// policy to the authorization of the entity at <paramref name="authHandle"/>. Binding to
        /// <c>TPM_RH_ENDORSEMENT</c> yields the well-known endorsement-key authorization policy. For the
        /// non-immediate form (real nonceTPM/cpHashA/policyRef and a negative <c>expiration</c> that mints a
        /// ticket), use the overload that accepts those parameters.
        /// </summary>
        /// <remarks>
        /// This verb composes a bound, unsalted HMAC session against <paramref name="authHandle"/> internally as
        /// its secure default — except for <c>TPM_RH_NULL</c>, the one handle that cannot bind (bind = TPM_RH_NULL
        /// means no bind entity on the wire), where the composed session is unbound and unsalted with the Empty
        /// Buffer session key. For every other handle the composition is
        /// its secure default (TPM 2.0 Library Part 1, Section 17.6.10, equation 20): the command carries a real
        /// structured cpHash/nonce/attribute-bound authHMAC rather than a plaintext password body, so a mismatch
        /// (wrong parameters, replayed bytes, a stale nonce) is always detected. When <paramref name="authHandle"/>'s
        /// own authorization value is empty — the common case this overload targets, e.g. the endorsement-key
        /// policy above — that authHMAC's key is itself derived (KDFa, still well-defined over a zero-length input
        /// key, RFC 2104) from material that crosses the wire in the clear on both sides (the StartAuthSession
        /// nonces), so it is NOT secret: an interposer who observed the StartAuthSession exchange can recompute it
        /// and forge a valid command or response. There is no bus-attacker confidentiality or integrity here while
        /// the authorization value is empty; the moment it is not, the session key genuinely incorporates that
        /// secret and the same mechanism becomes real integrity protection against exactly that attacker. An
        /// entity with a nonempty authorization value needs a caller-driven session built directly against
        /// <see cref="PolicySecretInput"/> and <see cref="TpmCommandExecutor"/> instead of this verb — the
        /// composed session presumes an empty value, so a nonempty one fails the HMAC. Salting is not the default:
        /// it needs a loaded decrypt key this verb group cannot generically assume is available (TPM 2.0 Library
        /// Part 1, Section 17.6.11/17.6.12) — salting is what would make the key secret even with an empty
        /// authValue; a caller holding a decrypt key composes a session with
        /// <see cref="StartAuthSessionInputExtensions.CreateSaltedHmacSession(uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/> or its bound-and-salted sibling directly. Against the SAME threat
        /// model (an observer of the StartAuthSession exchange), the explicit low-protection opt-out
        /// (<see cref="PolicySecretWithPasswordAsync(uint, uint, CancellationToken)"/>, an empty password
        /// authorization sent in the clear) is no worse — its value is the structural cpHash/nonce binding once
        /// authValues are non-empty and the shorter round trip, not confidentiality against that observer.
        /// </remarks>
        /// <param name="authHandle">The entity whose authorization the policy requires (for example <c>(uint)TpmRh.TPM_RH_ENDORSEMENT</c>).</param>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the timeout and ticket (dispose the response) or an error.</returns>
        public ValueTask<TpmResult<PolicySecretResponse>> PolicySecretAsync(
            uint authHandle, uint policySession, CancellationToken cancellationToken = default)
        {
            return PolicySecretCoreAsync(device, authHandle, policySession, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicySecret</c> (non-immediate form), binding the policy to the authorization of the
        /// entity at <paramref name="authHandle"/> and, when <paramref name="expiration"/> is negative, minting an
        /// authorization ticket whose timeout the policy session tracks (TPM 2.0 Library Part 3, Section 23.4,
        /// Section 23.2.5).
        /// </summary>
        /// <remarks>
        /// This verb composes a bound, unsalted HMAC session against <paramref name="authHandle"/> internally as
        /// its secure default — except for <c>TPM_RH_NULL</c>, the one handle that cannot bind (bind = TPM_RH_NULL
        /// means no bind entity on the wire), where the composed session is unbound and unsalted with the Empty
        /// Buffer session key. For every other handle the composition is
        /// its secure default (TPM 2.0 Library Part 1, Section 17.6.10, equation 20): the command carries a real
        /// structured cpHash/nonce/attribute-bound authHMAC rather than a plaintext password body, so a mismatch
        /// (wrong parameters, replayed bytes, a stale nonce) is always detected. When <paramref name="authHandle"/>'s
        /// own authorization value is empty — the common case this overload targets, a hierarchy whose
        /// authorization value has not been set — that authHMAC's key is itself derived (KDFa, still well-defined
        /// over a zero-length input key, RFC 2104) from material that crosses the wire in the clear on both sides
        /// (the StartAuthSession nonces), so it is NOT secret: an interposer who observed the StartAuthSession
        /// exchange can recompute it and forge a valid command or response. There is no bus-attacker
        /// confidentiality or integrity here while the authorization value is empty; the moment it is not, the
        /// session key genuinely incorporates that secret and the same mechanism becomes real integrity protection
        /// against exactly that attacker. An entity with a nonempty authorization value needs a caller-driven
        /// session built directly against <see cref="PolicySecretInput"/> and <see cref="TpmCommandExecutor"/>
        /// instead of this verb — the composed session presumes an empty value, so a nonempty one fails the HMAC.
        /// Salting is not the default: it needs a loaded decrypt key this verb group cannot generically assume is
        /// available (TPM 2.0 Library Part 1, Section 17.6.11/17.6.12) — salting is what would make the key secret
        /// even with an empty authValue; a caller holding a decrypt key composes a session with
        /// <see cref="StartAuthSessionInputExtensions.CreateSaltedHmacSession(uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/> or its bound-and-salted sibling directly. Against the SAME threat
        /// model (an observer of the StartAuthSession exchange), the explicit low-protection opt-out
        /// (<see cref="PolicySecretWithPasswordAsync(uint, uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, int, CancellationToken)"/>,
        /// an empty password authorization sent in the clear) is no worse — its value is the structural
        /// cpHash/nonce binding once authValues are non-empty and the shorter round trip, not confidentiality
        /// against that observer.
        /// </remarks>
        /// <param name="authHandle">The entity whose authorization the policy requires (for example <c>(uint)TpmRh.TPM_RH_ENDORSEMENT</c>).</param>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="nonceTpm">The policy session's retained nonceTPM, or empty for a session-unbound authorization.</param>
        /// <param name="cpHashA">The digest of the command parameters being authorized, or empty if unbound.</param>
        /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
        /// <param name="expiration">Seconds from nonceTPM's generation until expiry; 0 = no expiry, negative = ticket requested.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the timeout and ticket (dispose the response) or an error.</returns>
        public ValueTask<TpmResult<PolicySecretResponse>> PolicySecretAsync(
            uint authHandle,
            uint policySession,
            ReadOnlyMemory<byte> nonceTpm,
            ReadOnlyMemory<byte> cpHashA,
            ReadOnlyMemory<byte> policyRef,
            int expiration,
            CancellationToken cancellationToken = default)
        {
            return PolicySecretCoreAsync(device, authHandle, policySession, nonceTpm, cpHashA, policyRef, expiration, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicySecret</c> (immediate form: <c>expiration = 0</c>, no ticket produced) over an empty
        /// password authorization session, binding the policy to the authorization of the entity at
        /// <paramref name="authHandle"/>. The explicit low-protection opt-out for
        /// <see cref="PolicySecretAsync(uint, uint, CancellationToken)"/>.
        /// </summary>
        /// <remarks>
        /// A password session carries <paramref name="authHandle"/>'s authorization value — always empty here,
        /// the session accepts no other value — and the command's own parameters in the clear on a real bus, with
        /// no cpHash/rpHash HMAC integrity at all: unlike the bound default, nothing here detects a tampered or
        /// replayed command. Fine for a hierarchy whose authorization value has not been set and for diagnostics
        /// that want to avoid the bound default's extra StartAuthSession/FlushContext round trip; wrong for
        /// anything security-sensitive, where
        /// <see cref="PolicySecretAsync(uint, uint, CancellationToken)"/>'s bound HMAC session is the right
        /// default — its structural cpHash/nonce/attribute binding detects tampering this arm cannot, and it
        /// upgrades automatically to genuinely secret-keyed once <paramref name="authHandle"/>'s authorization
        /// value is non-empty, where this arm cannot authorize at all.
        /// </remarks>
        /// <param name="authHandle">The entity whose authorization the policy requires (for example <c>(uint)TpmRh.TPM_RH_ENDORSEMENT</c>).</param>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the timeout and ticket (dispose the response) or an error.</returns>
        public ValueTask<TpmResult<PolicySecretResponse>> PolicySecretWithPasswordAsync(
            uint authHandle, uint policySession, CancellationToken cancellationToken = default)
        {
            return PolicySecretWithPasswordCoreAsync(device, authHandle, policySession, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicySecret</c> (non-immediate form) over an empty password authorization session,
        /// binding the policy to the authorization of the entity at <paramref name="authHandle"/> and, when
        /// <paramref name="expiration"/> is negative, minting an authorization ticket whose timeout the policy
        /// session tracks (TPM 2.0 Library Part 3, Section 23.4, Section 23.2.5). The explicit low-protection
        /// opt-out for
        /// <see cref="PolicySecretAsync(uint, uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, int, CancellationToken)"/>.
        /// </summary>
        /// <remarks>
        /// A password session carries <paramref name="authHandle"/>'s authorization value — always empty here,
        /// the session accepts no other value — and the command's own parameters in the clear on a real bus, with
        /// no cpHash/rpHash HMAC integrity at all: unlike the bound default, nothing here detects a tampered or
        /// replayed command. Fine for a hierarchy whose authorization value has not been set and for diagnostics
        /// that want to avoid the bound default's extra StartAuthSession/FlushContext round trip; wrong for
        /// anything security-sensitive, where
        /// <see cref="PolicySecretAsync(uint, uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, int, CancellationToken)"/>'s
        /// bound HMAC session is the right default — its structural cpHash/nonce/attribute binding detects
        /// tampering this arm cannot, and it upgrades automatically to genuinely secret-keyed once
        /// <paramref name="authHandle"/>'s authorization value is non-empty, where this arm cannot authorize at
        /// all.
        /// </remarks>
        /// <param name="authHandle">The entity whose authorization the policy requires (for example <c>(uint)TpmRh.TPM_RH_ENDORSEMENT</c>).</param>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="nonceTpm">The policy session's retained nonceTPM, or empty for a session-unbound authorization.</param>
        /// <param name="cpHashA">The digest of the command parameters being authorized, or empty if unbound.</param>
        /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
        /// <param name="expiration">Seconds from nonceTPM's generation until expiry; 0 = no expiry, negative = ticket requested.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the timeout and ticket (dispose the response) or an error.</returns>
        public ValueTask<TpmResult<PolicySecretResponse>> PolicySecretWithPasswordAsync(
            uint authHandle,
            uint policySession,
            ReadOnlyMemory<byte> nonceTpm,
            ReadOnlyMemory<byte> cpHashA,
            ReadOnlyMemory<byte> policyRef,
            int expiration,
            CancellationToken cancellationToken = default)
        {
            return PolicySecretWithPasswordCoreAsync(device, authHandle, policySession, nonceTpm, cpHashA, policyRef, expiration, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicySigned</c>, binding the policy session to a signature over
        /// <c>aHash = H_authAlg(nonceTPM || expiration || cpHashA || policyRef)</c> made by the key at
        /// <paramref name="authObject"/>. Neither <paramref name="authObject"/> nor <paramref name="policySession"/>
        /// requires authorization (TPM 2.0 Library Part 3, Section 23.3), so the command carries no authorization
        /// area at all.
        /// </summary>
        /// <param name="authObject">The handle of the key whose public part validates the signature.</param>
        /// <param name="policySession">The policy session handle being extended.</param>
        /// <param name="nonceTpm">The policy session's retained nonceTPM, or empty for a session-unbound authorization.</param>
        /// <param name="cpHashA">The digest of the command parameters being authorized, or empty if unbound.</param>
        /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
        /// <param name="expiration">The signed expiration; 0 = no expiry, negative = a real authorization ticket is minted and the session's timeout is tracked (TPM 2.0 Library Part 3, Section 23.2.5).</param>
        /// <param name="signature">The signature octets: IEEE P1363 r ‖ s for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.</param>
        /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).</param>
        /// <param name="schemeHashAlg">The hash algorithm carried inside the signature (H_authAlg, which builds aHash).</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the timeout and ticket (dispose the response) or an error.</returns>
        public ValueTask<TpmResult<PolicySignedResponse>> PolicySignedAsync(
            uint authObject,
            uint policySession,
            ReadOnlyMemory<byte> nonceTpm,
            ReadOnlyMemory<byte> cpHashA,
            ReadOnlyMemory<byte> policyRef,
            int expiration,
            ReadOnlyMemory<byte> signature,
            TpmAlgIdConstants signatureScheme,
            TpmAlgIdConstants schemeHashAlg,
            CancellationToken cancellationToken = default)
        {
            return PolicySignedCoreAsync(
                device, authObject, policySession, nonceTpm, cpHashA, policyRef, expiration, signature, signatureScheme, schemeHashAlg, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyTicket</c>, replaying a ticket a prior <c>TPM2_PolicySigned</c> or
        /// <c>TPM2_PolicySecret</c> call minted with a negative <c>expiration</c>. The TPM recomputes the ticket's
        /// HMAC from <paramref name="timeout"/>, <paramref name="cpHashA"/>, <paramref name="policyRef"/>, and
        /// <paramref name="authName"/> and compares it to <paramref name="ticket"/>; on a match it folds the
        /// session exactly as the original TPM2_PolicySigned/TPM2_PolicySecret call would have, dispatched by the
        /// ticket's own tag (<c>TPM_ST_AUTH_SIGNED</c> or <c>TPM_ST_AUTH_SECRET</c>) rather than by
        /// <c>TPM_CC_PolicyTicket</c> itself (TPM 2.0 Library Part 3, Section 23.5). Neither
        /// <paramref name="policySession"/> nor the command as a whole requires authorization (Auth Index: None),
        /// so it carries no authorization area at all, exactly as TPM2_PolicySigned/TPM2_VerifySignature do.
        /// </summary>
        /// <param name="policySession">The policy session handle being extended.</param>
        /// <param name="timeout">The TPM2B_TIMEOUT value returned when the ticket was minted, replayed verbatim (bit 63 = expires-on-reset).</param>
        /// <param name="cpHashA">The digest of the command parameters this authorization is limited to, or empty if unlimited.</param>
        /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
        /// <param name="authName">The Name of the object that provided the original authorization.</param>
        /// <param name="ticket">The authorization ticket to replay (from <see cref="PolicySignedResponse.PolicyTicket"/> or <see cref="PolicySecretResponse.PolicyTicket"/>).</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyTicketResponse>> PolicyTicketAsync(
            uint policySession,
            ReadOnlyMemory<byte> timeout,
            ReadOnlyMemory<byte> cpHashA,
            ReadOnlyMemory<byte> policyRef,
            ReadOnlyMemory<byte> authName,
            TpmtTkAuth ticket,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(ticket);

            return PolicyTicketCoreAsync(device, policySession, timeout, cpHashA, policyRef, authName, ticket, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyAuthorize</c>, authorizing the session when its policyDigest equals
        /// <paramref name="approvedPolicy"/> and <paramref name="checkTicket"/> proves <paramref name="keySign"/> signed
        /// <c>H(approvedPolicy || policyRef)</c>, then replacing the digest with
        /// <c>H(H(0...0 || TPM_CC_PolicyAuthorize || keySign) || policyRef)</c> (TPM 2.0 Library Part 3, Section
        /// 23.16) — letting the session accept a policy the authority can revise at will.
        /// </summary>
        /// <param name="policySession">The policy session handle being extended.</param>
        /// <param name="approvedPolicy">The policy digest being approved; must equal the session's current policyDigest.</param>
        /// <param name="policyRef">The opaque policy qualifier, or empty for none.</param>
        /// <param name="keySign">The Name of the key that signed the approval.</param>
        /// <param name="checkTicket">The verification ticket (a genuine <c>TPM2_VerifySignature()</c> ticket, or <see cref="TpmtTkVerified.Null"/> for a trial session); a borrow the call does not retain.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<PolicyAuthorizeResponse>> PolicyAuthorizeAsync(
            uint policySession,
            ReadOnlyMemory<byte> approvedPolicy,
            ReadOnlyMemory<byte> policyRef,
            ReadOnlyMemory<byte> keySign,
            TpmtTkVerified checkTicket,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(checkTicket);

            return PolicyAuthorizeCoreAsync(device, policySession, approvedPolicy, policyRef, keySign, checkTicket, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_PolicyGetDigest</c>, returning the session's current policyDigest.
        /// </summary>
        /// <param name="policySession">The policy session handle.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the policyDigest (dispose the response to release it) or an error.</returns>
        public ValueTask<TpmResult<PolicyGetDigestResponse>> PolicyGetDigestAsync(
            uint policySession, CancellationToken cancellationToken = default)
        {
            return PolicyGetDigestCoreAsync(device, policySession, cancellationToken);
        }

        /// <summary>
        /// Runs <c>TPM2_FlushContext</c>, releasing a transient session or object handle.
        /// </summary>
        /// <param name="handle">The handle to flush.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<FlushContextResponse>> FlushContextAsync(
            uint handle, CancellationToken cancellationToken = default)
        {
            return FlushContextCoreAsync(device, handle, cancellationToken);
        }
    }

    private static async ValueTask<TpmResult<StartAuthSessionResponse>> StartPolicySessionCoreAsync(
        TpmDevice device, TpmSeConstants sessionType, TpmAlgIdConstants policyHash, CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);

        StartAuthSessionInput input = sessionType == TpmSeConstants.TPM_SE_TRIAL
            ? StartAuthSessionInput.CreateTrialPolicySession(policyHash)
            : StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(policyHash);

        return await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyCommandCodeResponse>> PolicyCommandCodeCoreAsync(
        TpmDevice device, uint policySession, TpmCcConstants restrictedCommand, CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);

        PolicyCommandCodeInput input = PolicyCommandCodeInput.Create(policySession, restrictedCommand);

        return await TpmCommandExecutor.ExecuteAsync<PolicyCommandCodeResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyAuthValueResponse>> PolicyAuthValueCoreAsync(
        TpmDevice device, uint policySession, CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyAuthValue, TpmResponseCodec.PolicyAuthValue);

        PolicyAuthValueInput input = PolicyAuthValueInput.ForSession(policySession);

        return await TpmCommandExecutor.ExecuteAsync<PolicyAuthValueResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the PCR selection transfers to the PolicyPcrInput, which is disposed by its using declaration.")]
    private static async ValueTask<TpmResult<PolicyPcrResponse>> PolicyPcrCoreAsync(
        TpmDevice device, uint policySession, TpmAlgIdConstants pcrBank, int[] pcrIndices, ReadOnlyMemory<byte> pcrDigest, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pcrIndices);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyPCR, TpmResponseCodec.PolicyPcr);

        using PolicyPcrInput input = PolicyPcrInput.Create(
            policySession, pcrDigest.Span, TpmlPcrSelection.Create(pcrBank, pcrIndices, pool), pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicyPcrResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyOrResponse>> PolicyOrCoreAsync(
        TpmDevice device, uint policySession, IReadOnlyList<ReadOnlyMemory<byte>> branchDigests, CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyOR, TpmResponseCodec.PolicyOr);

        var input = new PolicyOrInput(policySession, branchDigests);

        return await TpmCommandExecutor.ExecuteAsync<PolicyOrResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyNvResponse>> PolicyNvCoreAsync(
        TpmDevice device, uint authHandle, uint nvIndex, uint policySession, ReadOnlyMemory<byte> operandB, ushort offset, TpmEoConstants operation, CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyNV, TpmResponseCodec.PolicyNv);

        //PolicyNV reads the Index, authorized at USER role; an empty-auth password session covers an Index or
        //hierarchy whose authorization value has not been set.
        using TpmPasswordSession authSession = TpmPasswordSession.CreateEmpty(pool);
        var input = new PolicyNvInput(authHandle, nvIndex, policySession, operandB, offset, operation);

        return await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
            device, input, [authSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyCounterTimerResponse>> PolicyCounterTimerCoreAsync(
        TpmDevice device, uint policySession, ReadOnlyMemory<byte> operandB, ushort offset, TpmEoConstants operation, CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmResponseCodec.PolicyCounterTimer);

        var input = new PolicyCounterTimerInput(policySession, operandB, offset, operation);

        return await TpmCommandExecutor.ExecuteAsync<PolicyCounterTimerResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static ValueTask<TpmResult<PolicySecretResponse>> PolicySecretCoreAsync(
        TpmDevice device, uint authHandle, uint policySession, CancellationToken cancellationToken)
    {
        //The immediate form is the non-immediate form with every TPM2B empty and expiration = 0 (TPM 2.0 Library
        //Part 3, Section 23.4) — delegating avoids a second copy of the registry/session/execute body.
        return PolicySecretCoreAsync(
            device, authHandle, policySession, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, 0, cancellationToken);
    }

    private static async ValueTask<TpmResult<PolicySecretResponse>> PolicySecretCoreAsync(
        TpmDevice device,
        uint authHandle,
        uint policySession,
        ReadOnlyMemory<byte> nonceTpm,
        ReadOnlyMemory<byte> cpHashA,
        ReadOnlyMemory<byte> policyRef,
        int expiration,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //PolicySecret authorizes authHandle at USER role; the secure default binds a fresh HMAC session to
        //authHandle instead of sending its authorization value in the clear (TPM 2.0 Library Part 1, Section
        //17.6.10, equation 20), giving the command a real structured cpHash/nonce/attribute-bound authHMAC a
        //password session cannot offer. The bind entity's authorization value is presumed empty here — the common
        //case this verb group targets, a hierarchy whose authorization value has not been set — so the session key
        //reduces to KDFa(Empty, "ATH", nonceTPM, nonceCaller, bits): still a genuine non-empty, per-exchange key
        //(HMAC with an empty key is well-defined, RFC 2104), but one derived entirely from the StartAuthSession
        //nonces, which cross the wire in the clear on both sides — so it is NOT secret against a party who
        //observed that exchange (see PolicySecretAsync's own remarks). Salting, not binding, is what would make
        //this key secret with an empty authValue; this verb group cannot generically assume a loaded decrypt key.
        //TPM_RH_NULL is the exception to the bound shape entirely: bind = TPM_RH_NULL means "no bind entity" on
        //the wire, so its session is unbound and unsalted with the Empty Buffer session key (clause 17.6.9) —
        //see CreateAuthorizationSessionAsync.
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(authHandle, PolicySecretSessionHash);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!startResult.IsSuccess)
        {
            return startResult.Map<PolicySecretResponse>(_ => null!);
        }

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        //The composed session occupies a TPM session slot from here on, so every path below — including
        //CreateBoundAsync itself failing — must still flush it. The flush runs under CancellationToken.None: the
        //caller's own token is exactly what may have taken control out of the try block below (a cancelled call
        //must not also skip releasing the session it opened), and its own outcome is caught and discarded rather
        //than allowed to escape the finally, so a flush failure can never replace the primary result (success, a
        //TpmResult error, or the original exception) the try block already produced — mirroring the Seal
        //extensions' transient-handle flush discarding its outcome (Extensions/Seal/TpmDeviceExtensions.cs), but
        //additionally guarding the case that outcome is an exception instead of a return value.
        try
        {
            //CreateBoundAsync takes ownership of started.NonceTPM (disposing it itself on a derivation failure),
            //so 'started' is never disposed independently — the same ownership-transfer shape
            //TpmInHouseSimulatorSessionAuthTests' bound-session helper follows. TPM_RH_NULL is the one authHandle
            //that cannot bind: on the wire, bind = TPM_RH_NULL MEANS "no bind entity" (TPM 2.0 Library Part 1,
            //clause 17.6.9 — the session key derivation is gated on the bind HANDLE), so the session is
            //unbound+unsalted with the Empty Buffer session key, and the plain constructor models exactly that
            //(same nonceTPM ownership transfer).
            using TpmSession authSession = await CreateAuthorizationSessionAsync(
                authHandle, sessionHandle, startInput, started, pool, cancellationToken).ConfigureAwait(false);

            using PolicySecretInput input = PolicySecretInput.Create(
                authHandle, policySession, nonceTpm.Span, cpHashA.Span, policyRef.Span, expiration, pool);

            return await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                device, input, [authSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            try
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                //Compensating cleanup only: whatever the try block above already produced (a return value or an
                //in-flight exception) is this method's real outcome, and a flush failure must never replace it.
                //A session left loaded here is bounded by TPM_CAP_HANDLES enumeration plus TPM2_FlushContext, or
                //a device reset — not a correctness problem for the caller of this method.
            }
        }
    }

    /// <summary>
    /// Builds the host-side session object for the internally composed authorization session, taking ownership of
    /// <paramref name="started"/>'s nonceTPM. <c>TPM_RH_NULL</c> is the one authHandle that cannot bind: on the
    /// wire, bind = <c>TPM_RH_NULL</c> means "no bind entity" (TPM 2.0 Library Part 1, clause 17.6.9 — the
    /// session-key derivation is gated on the bind handle), so the session is unbound and unsalted with the Empty
    /// Buffer session key; every other permanent handle binds and derives the KDFa session key.
    /// </summary>
    private static async ValueTask<TpmSession> CreateAuthorizationSessionAsync(
        uint authHandle,
        uint sessionHandle,
        StartAuthSessionInput startInput,
        StartAuthSessionResponse started,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(authHandle == (uint)TpmRh.TPM_RH_NULL)
        {
            return new TpmSession(new TpmHandle(sessionHandle), started.NonceTPM, PolicySecretSessionHash, pool);
        }

        return await TpmSession.CreateBoundAsync(
            new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller, started.NonceTPM,
            PolicySecretSessionHash, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    private static ValueTask<TpmResult<PolicySecretResponse>> PolicySecretWithPasswordCoreAsync(
        TpmDevice device, uint authHandle, uint policySession, CancellationToken cancellationToken)
    {
        //The immediate form is the non-immediate form with every TPM2B empty and expiration = 0 (TPM 2.0 Library
        //Part 3, Section 23.4) — delegating avoids a second copy of the registry/session/execute body.
        return PolicySecretWithPasswordCoreAsync(
            device, authHandle, policySession, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, 0, cancellationToken);
    }

    private static async ValueTask<TpmResult<PolicySecretResponse>> PolicySecretWithPasswordCoreAsync(
        TpmDevice device,
        uint authHandle,
        uint policySession,
        ReadOnlyMemory<byte> nonceTpm,
        ReadOnlyMemory<byte> cpHashA,
        ReadOnlyMemory<byte> policyRef,
        int expiration,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret);

        //The explicit low-protection opt-out: an empty-password TPM_RS_PW session carries authHandle's
        //authorization value (here always empty) and the command's own parameters in the clear on a real bus,
        //with no cpHash/rpHash HMAC integrity at all — fine for a hierarchy whose authorization value has not
        //been set (the default for owner/endorsement/platform) and for diagnostics.
        using TpmPasswordSession authSession = TpmPasswordSession.CreateEmpty(pool);
        using PolicySecretInput input = PolicySecretInput.Create(
            authHandle, policySession, nonceTpm.Span, cpHashA.Span, policyRef.Span, expiration, pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
            device, input, [authSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicySignedResponse>> PolicySignedCoreAsync(
        TpmDevice device,
        uint authObject,
        uint policySession,
        ReadOnlyMemory<byte> nonceTpm,
        ReadOnlyMemory<byte> cpHashA,
        ReadOnlyMemory<byte> policyRef,
        int expiration,
        ReadOnlyMemory<byte> signature,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySigned, TpmResponseCodec.PolicySigned);

        //PolicySigned carries no authorization at all: neither authObject nor policySession needs one (a
        //public-key operation, TPM 2.0 Library Part 3, Section 23.3), so the executor is given no sessions and
        //frames TPM_ST_NO_SESSIONS, exactly as TPM2_VerifySignature() does.
        using PolicySignedInput input = PolicySignedInput.Create(
            authObject, policySession, nonceTpm.Span, cpHashA.Span, policyRef.Span, expiration, signature.Span, signatureScheme, schemeHashAlg, pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicySignedResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyTicketResponse>> PolicyTicketCoreAsync(
        TpmDevice device,
        uint policySession,
        ReadOnlyMemory<byte> timeout,
        ReadOnlyMemory<byte> cpHashA,
        ReadOnlyMemory<byte> policyRef,
        ReadOnlyMemory<byte> authName,
        TpmtTkAuth ticket,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyTicket, TpmResponseCodec.PolicyTicket);

        //PolicyTicket carries no authorization at all: policySession needs none (TPM 2.0 Library Part 3, Section
        //23.5, Auth Index: None), so the executor is given no sessions and frames TPM_ST_NO_SESSIONS, exactly as
        //TPM2_PolicySigned/TPM2_VerifySignature do.
        using PolicyTicketInput input = PolicyTicketInput.Create(
            policySession, timeout.Span, cpHashA.Span, policyRef.Span, authName.Span,
            (ushort)ticket.Tag, ticket.Hierarchy.Value, ticket.Digest, pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicyTicketResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyAuthorizeResponse>> PolicyAuthorizeCoreAsync(
        TpmDevice device,
        uint policySession,
        ReadOnlyMemory<byte> approvedPolicy,
        ReadOnlyMemory<byte> policyRef,
        ReadOnlyMemory<byte> keySign,
        TpmtTkVerified checkTicket,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyAuthorize, TpmResponseCodec.PolicyAuthorize);

        //PolicyAuthorize carries no authorization at all: policySession needs none (Part 3, Section 23.16), so
        //the executor is given no sessions and frames TPM_ST_NO_SESSIONS. The ticket type itself guarantees the
        //TPM_ST_VERIFIED tag a genuine TPM2_VerifySignature() ticket (real or NULL) always carries.
        using PolicyAuthorizeInput input = PolicyAuthorizeInput.Create(
            policySession, approvedPolicy.Span, policyRef.Span, keySign.Span,
            (ushort)checkTicket.Tag, checkTicket.Hierarchy.Value, checkTicket.Digest, pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicyAuthorizeResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<PolicyGetDigestResponse>> PolicyGetDigestCoreAsync(
        TpmDevice device, uint policySession, CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyGetDigest, TpmResponseCodec.PolicyGetDigest);

        PolicyGetDigestInput input = PolicyGetDigestInput.ForSession(policySession);

        return await TpmCommandExecutor.ExecuteAsync<PolicyGetDigestResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<TpmResult<FlushContextResponse>> FlushContextCoreAsync(
        TpmDevice device, uint handle, CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        FlushContextInput input = FlushContextInput.ForHandle(handle);

        return await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            device, input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }
}

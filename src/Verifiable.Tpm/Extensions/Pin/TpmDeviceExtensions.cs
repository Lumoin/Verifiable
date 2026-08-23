using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Pin;

/// <summary>
/// The <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> structure retained by a PIN Index's data area (TPM 2.0 Library
/// Part 2, Section 13.3): the current attempt count and the attempt threshold it is compared against.
/// </summary>
/// <param name="PinCount">The current attempt count.</param>
/// <param name="PinLimit">The attempt threshold; the Index's own authValue stops being usable once <see cref="PinCount"/> reaches this.</param>
public readonly record struct TpmPinCounterParameters(uint PinCount, uint PinLimit);

/// <summary>
/// Persistent PIN-retry-budget ("throttle") business-capability extensions for <see cref="TpmDevice"/>, composed
/// over a <c>TPM_NT_PIN_FAIL</c> NV Index (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 1, Section 35.2.6.6).
/// </summary>
/// <remarks>
/// <para>
/// These verbs compose the shipped <c>TPM2_NV_DefineSpace</c>/<c>TPM2_NV_Read</c>/<c>TPM2_NV_Write</c>/
/// <c>TPM2_NV_UndefineSpace</c>/<c>TPM2_NV_ChangeAuth</c> surface (Part 3, Sections 31.3, 31.13, 31.7, 31.4,
/// 31.15) into a single business
/// capability: a PIN-retry counter whose own compare-and-move is one atomic TPM command, so there is no
/// window between "check the PIN" and "record the attempt" for a caller to exploit. Every session this group
/// composes is built and disposed internally; a caller never hands in a pre-built session.
/// </para>
/// <para>
/// <b>Channel protection.</b> Every verb defaults to a real cryptographic channel rather than a plaintext
/// password session, and every default that CAN carry a <c>…WithPasswordAsync</c> opt-out carries one with the
/// identical shape and the current-body semantics unchanged:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>
///   composes an UNBOUND, unsalted HMAC session (TPM 2.0 Library Part 1, Section 17.6.9's Empty Buffer session
///   key) and sets <paramref name="candidatePinHash"/> as that session's authValue - never a session bound to
///   the PIN Index itself, which Part 1, Section 35.2.8.3 forbids outright (<c>TPM_RC_HANDLE</c>): "the sequence
///   in which the TPM processes authorizations would enable a hammering attack on the Index." The candidate PIN
///   never crosses the bus as a password; a wrong candidate is an HMAC mismatch, not a plaintext compare. See
///   that verb's own remarks for the honest channel accounting - this default closes the on-the-wire plaintext
///   exposure, not the offline-guessing surface, which the salted overload closes.</description></item>
///   <item><description>The four owner-authorized verbs (<see cref="DefinePinFailIndexAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, CancellationToken)"/>,
///   <see cref="ReadPinCountersAsync"/>, <see cref="ResetPinCountAsync"/>, <see cref="UndefinePinIndexAsync"/>)
///   default to an HMAC session BOUND to <c>TPM_RH_OWNER</c> (Part 1, Section 17.6.10, equation 20): the owner
///   authorization value feeds the session key's KDFa derivation, so a genuinely secret owner authValue never
///   crosses the bus and the command carries a structured cpHash/nonce-bound authHMAC a password session cannot
///   offer. As with <c>Extensions/Policy</c>'s <c>PolicySecretAsync</c>, when the owner's own authorization value
///   is empty (unset), that KDFa key is derivable by anyone who observed the <c>TPM2_StartAuthSession</c>
///   exchange (its nonces cross the wire in the clear); the mechanism still becomes real integrity protection
///   the moment a real owner authValue is set. Each of these four verbs folds the target PIN Index's own real,
///   current Name (Part 1, Section 14, Table 6) into the cpHash of every command it composes against an
///   ALREADY-DEFINED Index, deriving it host-side via
///   <see cref="Nv.TpmDeviceExtensions.NvReadPublicAsync(uint, CancellationToken)"/> rather than recomputing it
///   blind. The composed <c>TPM2_NV_DefineSpace</c> is the exception: it is single-handle, and no Index exists
///   yet to have a Name, so its cpHash carries the owner handle alone.</description></item>
///   <item><description><see cref="ChangePinAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/>
///   is the one verb with NO <c>…WithPasswordAsync</c> opt-out at all: <c>TPM2_NV_ChangeAuth</c> authorizes the
///   Index at ADMIN role, which an NV Index can satisfy only with a policy session (Part 3, Section 31.15.1;
///   Part 1, Section 17.2 and Section 35.2.3), so no plaintext arm can exist to offer. It composes an UNBOUND
///   policy session that folds the current PIN form in via <c>TPM2_PolicyAuthValue</c>, plus a separate decrypt
///   companion carrying the replacement value - see that verb's own remarks for the full accounting.</description></item>
/// </list>
/// <para>
/// <b>Enrollment confidentiality.</b> <see cref="DefinePinFailIndexAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, CancellationToken)"/> installs the stored PIN form as the
/// new Index's authValue by riding <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> command PARAMETER - the reference's
/// DECRYPT_2-eligible first parameter, which a decrypt-attributed session encrypts on the bus. That encryption
/// is only as confidential as the session key it is keyed on, exactly as the owner-verb INTEGRITY is: an
/// owner-bound session whose owner authValue is empty (unset) derives the parameter-encryption stream from the
/// <c>TPM2_StartAuthSession</c> nonces alone, which cross the wire in the clear, so a bus observer can recompute
/// it - the same caveat <see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>'s unbound
/// key carries. A non-empty owner authValue, or the salted define, makes that encryption genuinely secret
/// against such an observer. The default composition keys a parameter-encryption session over that parameter;
/// that session is confidential only under a salt (the salted <see cref="DefinePinFailIndexAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, CancellationToken)"/>
/// overload) or a non-empty owner authValue, so with an empty owner authValue over the unsalted default a bus
/// observer can still recover the stored PIN form from the enrollment exchange - provision over a trusted bus,
/// set an owner authValue, or use the salted overload.
/// <see cref="ChangePinAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/> carries the
/// replacement value the same way, over its own decrypt session, with the same salted/unsalted split.
/// </para>
/// <para>
/// <b>Rotation is in place.</b> Every Index this group defines carries the <c>authPolicy</c>
/// <see cref="CreatePinIndexAuthPolicy"/> computes, which exists for exactly one purpose: it lets
/// <see cref="ChangePinAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/> replace the
/// Index's authorization value with one <c>TPM2_NV_ChangeAuth</c> (Part 3, Section 31.15) instead of undefining
/// and redefining the Index. The Index is never absent and its data area is never touched, so the throttle state
/// - <c>pinCount</c>, <c>pinLimit</c>, the written flag - and the Index's Name all survive a PIN change. That
/// policy is not an authorization path for anything else: the attributes below route read, write, and undefine
/// through the Index authValue or the owner hierarchy, never through a policy.
/// </para>
/// <para>
/// <b>PIN normalization.</b> A PIN's stored form is a hash the caller computes off-TPM; this group never sees a
/// raw PIN. The same UTF-8 encoding and the same Unicode normalization form MUST be applied at enrollment
/// (<see cref="DefinePinFailIndexAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, CancellationToken)"/>'s <c>pinHash</c>) and at every verification
/// (<see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>'s
/// <c>candidatePinHash</c>), and to both halves of every rotation
/// (<see cref="ChangePinAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/>'s
/// <c>oldPinHash</c> and <c>newPinHash</c>): two differently-normalized encodings of the same visual string hash to different
/// bytes, so a caller that normalizes inconsistently burns a legitimate retry against <c>pinCount</c> for a PIN
/// the user typed correctly. This is a caller-side contract this group cannot enforce - it only ever sees the
/// already-hashed form.
/// </para>
/// <para>
/// <b>PIN_FAIL only.</b> This group defines and drives only <c>TPM_NT_PIN_FAIL</c> Indexes: a wrong candidate
/// increments <c>pinCount</c>, a correct one below <c>pinLimit</c> resets it to zero, and at <c>pinLimit</c>
/// even the correct value is refused (Part 1, Section 35.2.6.6). <c>TPM_NT_PIN_PASS</c> composes the opposite
/// semantics (increment on success) and is out of this group's scope.
/// </para>
/// <para>
/// <b>Attributes are hard-coded.</b> Every Index this group defines carries exactly <c>TPM_NT_PIN_FAIL |
/// TPMA_NV_NO_DA | TPMA_NV_AUTHREAD | TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD</c>: <c>NO_DA</c> is
/// spec-mandated for a PIN Fail Index (Part 2, Section 13.4) so its own localized throttle never doubles up
/// with the TPM-wide dictionary-attack counter; <c>AUTHWRITE</c> is deliberately absent, so the Index's own
/// authValue can never write it (the PIN oracle the automaton's <c>TPM2_NV_DefineSpace()</c> gate refuses to
/// define in the first place); <c>OWNERWRITE</c>/<c>OWNERREAD</c> make the owner hierarchy the sole
/// administrative path for provisioning, reset, and no-oracle retry-count reporting.
/// </para>
/// <para>
/// <b>PIN is the authorization value.</b> Every candidate/authorization parameter here is
/// <see cref="ReadOnlyMemory{T}"/> carrying the already-hashed, fixed-width stored PIN form - this group
/// never sees or derives a raw PIN, matching the no-naked-bytes carrier discipline that binds every other
/// authorization value in this library.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class TpmDeviceExtensions
{
    /// <summary>The declared data area size (octets) of every PIN Fail Index this group defines - the whole 8-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> (TPM 2.0 Library Part 2, Section 13.3).</summary>
    private const ushort PinCounterParametersSize = 8;

    /// <summary>The Name hash algorithm fixed for every PIN Fail Index this group defines.</summary>
    private const TpmAlgIdConstants PinNameAlgorithm = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The hash algorithm for every HMAC session this group composes internally: the unbound/salted sessions
    /// <see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/> composes, and the
    /// owner-bound sessions the four administrative verbs compose.
    /// </summary>
    private const TpmAlgIdConstants PinAuthSessionHash = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The hard-coded <c>TPMA_NV</c> attribute set for every PIN Fail Index this group defines (TPM 2.0 Library
    /// Part 1, Section 35.2.6.1 and 35.2.6.6; Part 2, Section 13.4): <c>TPM_NT_PIN_FAIL</c>, spec-mandated
    /// <c>TPMA_NV_NO_DA</c>, Index-authValue reads via <c>TPMA_NV_AUTHREAD</c>, and owner-hierarchy
    /// provisioning/reporting via <c>TPMA_NV_OWNERWRITE</c>/<c>TPMA_NV_OWNERREAD</c>. <c>TPMA_NV_AUTHWRITE</c>
    /// is deliberately absent - the Index's own authValue may never write it.
    /// </summary>
    private const TpmaNv PinFailAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    extension(TpmDevice device)
    {
        /// <summary>
        /// Defines a new <c>TPM_NT_PIN_FAIL</c> NV Index under the owner hierarchy and provisions it with
        /// <paramref name="pinHash"/> as its authValue and a fresh <c>{pinCount: 0, pinLimit}</c> counter,
        /// composing <c>TPM2_NV_DefineSpace</c> then an owner-authorized <c>TPM2_NV_Write</c> internally.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A PIN Fail Index forbids <c>TPMA_NV_AUTHWRITE</c> (Part 1, Section 35.2.6.1), so the counter
        /// parameters can only ever be established by the owner-authorized write this verb composes -
        /// provisioning and the later <see cref="ResetPinCountAsync"/> recovery share the identical write
        /// shape. The Index is defined with the <c>authPolicy</c> <see cref="CreatePinIndexAuthPolicy"/>
        /// computes, which is what makes it rotation-capable: a later
        /// <see cref="ChangePinAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/>
        /// replaces the Index authValue in place, so a stale snapshot of the old authValue can never again
        /// resolve authorization against the rotated Index while the counter state it was throttled by survives.
        /// The choice is definition-time only - an Index defined without that policy can never satisfy the
        /// ADMIN-role check <c>TPM2_NV_ChangeAuth</c> demands, for the rest of its lifetime.
        /// </para>
        /// <para>
        /// Both the definition and the provisioning write run over ONE owner-bound HMAC session (see this
        /// group's own remarks): a single <c>TPM2_StartAuthSession</c>/<c>TPM2_FlushContext</c> bracket covers
        /// both commands. Use <see cref="DefinePinFailIndexWithPasswordAsync"/> for the plaintext-owner-password
        /// opt-out.
        /// </para>
        /// <para>
        /// <b>Honest channel accounting for <paramref name="pinHash"/>.</b> It is installed as the new Index's
        /// authValue by riding <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> command PARAMETER (Part 3, Section 31.3),
        /// the reference's DECRYPT_2-eligible first parameter, which a decrypt-attributed session encrypts on the
        /// bus. Its confidentiality against a bus observer tracks the session key exactly as the owner-verb
        /// integrity does: an empty owner authValue over an unsalted session keys that encryption from the public
        /// <c>TPM2_StartAuthSession</c> nonces, so an observer can recompute it, while a non-empty owner authValue
        /// or the salted define makes it genuinely secret. This default composition keys a parameter-encryption
        /// session over that parameter; that session is confidential only under a salt (the salted overload) or a
        /// non-empty owner authValue, so with an empty owner authValue over this unsalted default the stored PIN
        /// form is still recoverable from the enrollment exchange - provision over a trusted bus, set an owner
        /// authValue, or use the salted overload. <see cref="DefinePinFailIndexWithPasswordAsync"/> sends it as a
        /// plaintext password parameter with no encryption path at all.
        /// <see cref="ChangePinAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/> later
        /// carries a replacement value under its own decrypt session, with its own accounting.
        /// </para>
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The NV Index handle to define.</param>
        /// <param name="pinHash">The stored PIN form (already hashed) to install as the Index authValue.</param>
        /// <param name="pinLimit">The attempt threshold to provision.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the definition's or the provisioning write's error.</returns>
        public ValueTask<TpmResult<NvWriteResponse>> DefinePinFailIndexAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            ReadOnlyMemory<byte> pinHash,
            uint pinLimit,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return DefinePinFailIndexCoreAsync(device, ownerAuth, pinIndexHandle, pinHash, pinLimit, cancellationToken);
        }

        /// <summary>
        /// Defines and provisions a new <c>TPM_NT_PIN_FAIL</c> Index over a SALTED HMAC session, using
        /// <paramref name="tpmKey"/> to encrypt <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> parameter - the stored
        /// PIN form - under a key an on-the-wire observer cannot reconstruct.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The stored PIN form still enters as <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> command PARAMETER
        /// (Part 3, Section 31.3), but here the encrypting session is SALTED
        /// (<see cref="Infrastructure.Commands.StartAuthSessionInputExtensions.CreateSaltedHmacSession(uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/>):
        /// a fresh salt is RSA-OAEP-encrypted (TPM 2.0 Library Part 1, Annex B.10.2) to <paramref name="tpmKeyModulus"/>/
        /// <paramref name="tpmKeyExponent"/>, so only the TPM holding <paramref name="tpmKey"/>'s matching private
        /// key can recover it. The session key then folds that recovered salt (Part 1, Section 17.6.12, equation
        /// 25), so the parameter-encryption keystream keyed on it (Part 1, Section 21) is genuinely secret - unlike
        /// the unsalted default (see <see cref="DefinePinFailIndexAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, CancellationToken)"/>),
        /// an adversary who captured the enrollment transcript cannot recompute it, so the stored PIN form is no
        /// longer recoverable from the bus. This is where genuine enrollment confidentiality lives.
        /// </para>
        /// <para>
        /// The Index provisioned this way is byte-for-byte the one the unsalted default produces: the authValue is
        /// the same <paramref name="pinHash"/>, so a later <see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>
        /// (or its salted overload) with the right PIN succeeds. Use this overload whenever the bus the enrollment
        /// runs over is one a passive adversary might capture and a suitable loaded decrypt key (for example the
        /// Endorsement Key) is available. Use <see cref="DefinePinFailIndexWithPasswordAsync"/> for the plaintext
        /// opt-out, which sends the stored PIN form with no encryption path at all.
        /// </para>
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The NV Index handle to define.</param>
        /// <param name="pinHash">The stored PIN form (already hashed) to install as the Index authValue.</param>
        /// <param name="pinLimit">The attempt threshold to provision.</param>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
        /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP - an explicit per-call delegate, no closure capture.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the definition's or the provisioning write's error.</returns>
        public ValueTask<TpmResult<NvWriteResponse>> DefinePinFailIndexAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            ReadOnlyMemory<byte> pinHash,
            uint pinLimit,
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyModulus,
            uint tpmKeyExponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmRsaOaepEncryptDelegate encryptSalt,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return DefinePinFailIndexSaltedCoreAsync(
                device, ownerAuth, pinIndexHandle, pinHash, pinLimit, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for <see cref="DefinePinFailIndexAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, CancellationToken)"/>:
        /// defines and provisions the Index over a plaintext owner-password session rather than a bound HMAC session.
        /// </summary>
        /// <remarks>
        /// The owner authorization value is sent in the clear on both the definition and the provisioning write,
        /// with no cpHash/rpHash HMAC integrity at all. Fine for an owner hierarchy whose authorization value has
        /// not been set and for diagnostics; wrong for anything security-sensitive, where
        /// <see cref="DefinePinFailIndexAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, CancellationToken)"/>'s bound HMAC default is the right choice.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The NV Index handle to define.</param>
        /// <param name="pinHash">The stored PIN form (already hashed) to install as the Index authValue.</param>
        /// <param name="pinLimit">The attempt threshold to provision.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the definition's or the provisioning write's error.</returns>
        public ValueTask<TpmResult<NvWriteResponse>> DefinePinFailIndexWithPasswordAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            ReadOnlyMemory<byte> pinHash,
            uint pinLimit,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return DefinePinFailIndexWithPasswordCoreAsync(device, ownerAuth, pinIndexHandle, pinHash, pinLimit, cancellationToken);
        }

        /// <summary>
        /// Rotates <paramref name="pinIndexHandle"/>'s own authValue from <paramref name="oldPinHash"/> to
        /// <paramref name="newPinHash"/> in place, composing <c>TPM2_NV_ChangeAuth</c> under the Index's own
        /// ADMIN-role policy internally - the Index is never undefined, so its <c>pinLimit</c>, its written state,
        /// its accumulated <c>pinCount</c>, and its Name all outlive the rotation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>There is no <c>…WithPasswordAsync</c> opt-out, and there cannot be one.</b>
        /// <c>TPM2_NV_ChangeAuth</c> authorizes <paramref name="pinIndexHandle"/> at ADMIN role (TPM 2.0 Library
        /// Part 3, Section 31.15.1: the command "requires that a policy session be used for authorization of
        /// nvIndex so that the ADMIN role may be asserted and that commandCode in the policy session context shall
        /// be TPM_CC_NV_ChangeAuth"). Part 1, Section 17.2's ADMIN-role bullet offers an authValue path only for an
        /// object whose <c>adminWithPolicy</c> attribute is CLEAR, and an NV Index has no such attribute to be
        /// CLEAR - Part 1, Section 35.2.3 states the requirement for the NV family's other ADMIN-role command
        /// unconditionally, with no fallback clause at all. A password session, or a plain HMAC session on the
        /// Index, therefore cannot authorize this command at any protection level, so this verb has no
        /// plaintext-password arm to fall back to the way every other verb in this group does.
        /// </para>
        /// <para>
        /// <b>The Index must have been enrolled rotation-capable.</b> Only an Index whose <c>authPolicy</c> is the
        /// one <see cref="CreatePinIndexAuthPolicy"/> computes can satisfy that ADMIN check, which is why every
        /// define path in this group installs it. An Index defined elsewhere with an Empty Policy can never
        /// satisfy it (Part 1, Section 11.2), so its authorization value is fixed for the Index's whole lifetime
        /// and the only PIN change available to it is the destructive undefine-and-redefine that takes the
        /// throttle history with it.
        /// </para>
        /// <para>
        /// <b>Rotation deliberately costs the current PIN, and a wrong guess costs a retry.</b> The composed
        /// policy folds <c>TPM2_PolicyAuthValue</c>, so the session's command HMAC key incorporates the Index's
        /// CURRENT authorization value (Part 1, Section 17.6.5's policy note): <paramref name="oldPinHash"/> is
        /// proven by HMAC exactly as <see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>
        /// proves a candidate. The three consequences are the intended ones, not accidents:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>A wrong <paramref name="oldPinHash"/> is an HMAC mismatch, answered with a
        ///   session-encoded <c>TPM_RC_BAD_AUTH</c> and an incremented <c>pinCount</c> - a rotation attempt is a
        ///   PIN attempt and burns a retry, so this verb is not a throttle bypass.</description></item>
        ///   <item><description>A correct <paramref name="oldPinHash"/> below <c>pinLimit</c> resets
        ///   <c>pinCount</c> to zero, exactly as a successful verification does.</description></item>
        ///   <item><description>An Index already at <c>pinLimit</c> refuses the rotation with
        ///   <c>TPM_RC_AUTH_UNAVAILABLE</c> before the HMAC is ever evaluated, even for the correct
        ///   <paramref name="oldPinHash"/> (Part 1, Section 35.2.6.6). Recovering such an Index is the owner's
        ///   job - <see cref="ResetPinCountAsync"/> first, then rotate.</description></item>
        /// </list>
        /// <para>
        /// <b>Honest channel accounting.</b> The authorizing policy session is UNBOUND and unsalted (Part 1,
        /// Section 17.6.9's Empty Buffer session key), so its HMAC key IS the PIN form that leg proves and the
        /// offline-guessing surface is identical to the one
        /// <see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>'s own remarks describe in
        /// full: every other value the key derivation consumes crosses the wire in the clear, so a captured
        /// transcript lets an adversary test guesses offline, bounded only by the PIN's entropy, and the
        /// <c>pinLimit</c> throttle defends only the online path. BOTH PIN forms are exposed that way, not just
        /// the old one - the command leg is keyed on <paramref name="oldPinHash"/> and, because the rotation
        /// commits before the response is framed, the response leg is keyed on <paramref name="newPinHash"/>
        /// (Part 3, Section 31.15.1), so one transcript verifies guesses at either. Separately,
        /// <paramref name="newPinHash"/> rides <c>TPM2_NV_ChangeAuth</c>'s <c>newAuth</c> command PARAMETER
        /// (Part 3, Section 31.15) - the command's sole, and therefore first, sized parameter, which Part 1,
        /// Section 19.1 makes eligible for session encryption - under a SEPARATE decrypt session, never the
        /// authorizing one. That session is unsalted here, so its keystream derives from the public
        /// <c>TPM2_StartAuthSession</c> nonces alone and a bus observer can recompute it: the encryption is
        /// structural, not confidential, the same caveat enrollment carries. The salted overload of this verb
        /// closes all three surfaces at once - it salts the authorizing session as well as the companion.
        /// </para>
        /// <para>
        /// <b>The replacement value.</b> The TPM strips trailing zero octets from <paramref name="newPinHash"/>
        /// and then refuses anything still longer than <see cref="PinNameAlgorithm"/>'s digest size with
        /// <c>TPM_RC_SIZE</c>; hashing an over-long secret down to that size first is a caller-side convention the
        /// TPM does not perform (Part 1, Section 17.6.4.3: "The TPM does not enforce this transformation"). The
        /// PIN-normalization contract this group's own remarks state binds <paramref name="newPinHash"/> against
        /// every later verification exactly as it binds the enrollment hash.
        /// </para>
        /// <para>
        /// <b>The Name does not move.</b> An Index's authValue lives outside its <c>TPMS_NV_PUBLIC</c>, which is
        /// what the Name is computed over (Part 1, Section 14, Table 6), so a Name - or an attestation carrying
        /// one - obtained before the rotation stays valid after it and no caller needs to re-resolve it.
        /// </para>
        /// </remarks>
        /// <param name="pinIndexHandle">The PIN Fail Index to rotate.</param>
        /// <param name="oldPinHash">The Index's current stored PIN form; proven by HMAC, not sent.</param>
        /// <param name="newPinHash">The replacement stored PIN form to install as the Index authValue.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<NvChangeAuthResponse>> ChangePinAsync(
            uint pinIndexHandle,
            ReadOnlyMemory<byte> oldPinHash,
            ReadOnlyMemory<byte> newPinHash,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ChangePinCoreAsync(device, pinIndexHandle, oldPinHash, newPinHash, cancellationToken);
        }

        /// <summary>
        /// Rotates <paramref name="pinIndexHandle"/>'s own authValue over a fully salted composition: both the
        /// ADMIN-role session that AUTHORIZES the rotation and the companion session that ENCRYPTS
        /// <paramref name="newPinHash"/> draw their session keys from <paramref name="tpmKey"/>, so a captured
        /// transcript yields neither the replacement value nor a way to test a guess at either PIN form.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Identical in every authorization respect to
        /// <see cref="ChangePinAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/> - the
        /// same ADMIN-role policy, replayed in the same order, with the same retry and throttle semantics. What
        /// changes is the channel, on BOTH sessions. Each is SALTED
        /// (<see cref="Infrastructure.Commands.StartAuthSessionInputExtensions.CreateSaltedPolicySession(uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/>
        /// for the authorizing one,
        /// <see cref="Infrastructure.Commands.StartAuthSessionInputExtensions.CreateSaltedHmacSession(uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/>
        /// for the companion), and each draws its OWN salt: two independent secrets, never one reused across the
        /// pair. Every salt is RSA-OAEP-encrypted (TPM 2.0 Library Part 1, Annex B.10.2) to
        /// <paramref name="tpmKeyModulus"/>/<paramref name="tpmKeyExponent"/>, so only the TPM holding
        /// <paramref name="tpmKey"/>'s matching private key can recover it, and each recovered salt keys its own
        /// session's derived session key (Part 1, Section 17.6.12, equation 25).
        /// </para>
        /// <para>
        /// <b>The authorizing session's salt is what closes the offline oracle.</b> That session's per-command
        /// HMAC key is <c>sessionValue = sessionKey || authValue</c> (Part 1, Section 17.6.5), and
        /// <c>TPM2_PolicyAuthValue</c> is what puts the Index's authorization value into the authValue term. With
        /// an unsalted session the <c>sessionKey</c> in front of it is the Empty Buffer, leaving the PIN form as
        /// the key's only unknown; salting makes <c>sessionKey</c> a value no observer can reconstruct, so the
        /// key stops being derivable from public transcript data plus a guess. That holds on both legs and for
        /// both PIN forms: the command leg keyed on <paramref name="oldPinHash"/>, and - because the rotation
        /// commits before the response is framed (Part 3, Section 31.15.1) - the response leg keyed on
        /// <paramref name="newPinHash"/>. Neither can be recomputed offline, so <c>pinLimit</c>'s throttle governs
        /// the only guessing path that remains, which is the honest caveat the unsalted default still carries.
        /// </para>
        /// <para>
        /// <b>The companion session's salt is what makes the replacement value secret.</b>
        /// <paramref name="newPinHash"/> rides <c>newAuth</c> under a session separate from the authorizing one,
        /// never the same session, because a policy session carrying the decrypt attribute would fold the Index's
        /// authValue into its <c>sessionValue</c> whether or not the policy asserted <c>TPM2_PolicyAuthValue</c>
        /// (Part 1, Section 19.1's note) - keying the encryption of the NEW PIN form on the OLD one. Salted, that
        /// companion's keystream is genuinely secret rather than merely structural, so the replacement value is
        /// not recoverable from a captured transcript the way the unsalted default leaves it.
        /// </para>
        /// <para>
        /// Use this overload whenever the bus the rotation runs over is one a passive adversary might capture and
        /// a suitable loaded decrypt key (for example the Endorsement Key) is available. Rotating a PIN is the
        /// highest-value parameter-encryption target this group has: unlike a one-time enrollment, it carries a
        /// replacement secret that may be sent again every time the PIN changes.
        /// </para>
        /// </remarks>
        /// <param name="pinIndexHandle">The PIN Fail Index to rotate.</param>
        /// <param name="oldPinHash">The Index's current stored PIN form; proven by HMAC, not sent.</param>
        /// <param name="newPinHash">The replacement stored PIN form to install as the Index authValue.</param>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
        /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP - an explicit per-call delegate, no closure capture.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<NvChangeAuthResponse>> ChangePinAsync(
            uint pinIndexHandle,
            ReadOnlyMemory<byte> oldPinHash,
            ReadOnlyMemory<byte> newPinHash,
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyModulus,
            uint tpmKeyExponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmRsaOaepEncryptDelegate encryptSalt,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ChangePinSaltedCoreAsync(
                device, pinIndexHandle, oldPinHash, newPinHash, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken);
        }

        /// <summary>
        /// Verifies <paramref name="candidatePinHash"/> against <paramref name="pinIndexHandle"/>'s own
        /// authValue, composing an Index-authorized <c>TPM2_NV_Read</c> of the full counter window over an
        /// UNBOUND, unsalted HMAC session internally.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The compare and the <c>pinCount</c> move are resolved as ONE atomic TPM command (Part 1, Section
        /// 35.2.6.6): a correct candidate below <c>pinLimit</c> resets <c>pinCount</c> to zero and returns the
        /// reset parameters; a wrong one increments <c>pinCount</c> and answers a session-encoded
        /// <c>TPM_RC_BAD_AUTH</c> (a PIN Fail Index is spec-mandated <c>TPMA_NV_NO_DA</c>, so a wrong PIN is
        /// never <c>TPM_RC_AUTH_FAIL</c>; the code carries the session-index modifier - compare against
        /// <c>TpmResult{T}.BaseError</c>, not <c>ResponseCode</c>, directly); at <c>pinLimit</c> even the correct
        /// candidate is refused with <c>TPM_RC_AUTH_UNAVAILABLE</c> BEFORE the HMAC is ever evaluated, without
        /// moving <c>pinCount</c> further. There is no TOCTOU window between comparing and recording.
        /// </para>
        /// <para>
        /// <b>Why unbound, never bound to the Index.</b> Part 1, Section 35.2.8.3 forbids binding an
        /// authorization session to a PIN Pass or PIN Fail Index outright (<c>TPM_RC_HANDLE</c>): "the sequence
        /// in which the TPM processes authorizations would enable a hammering attack on the Index." This verb's
        /// session is therefore unbound (Part 1, Section 17.6.9's Empty Buffer session key); <paramref name="candidatePinHash"/>
        /// is instead set as the session's authValue, so it becomes the per-command HMAC key's authValue term
        /// (<c>sessionValue = sessionKey || authValue = Empty || candidatePinHash</c>) - the same mechanism
        /// <c>SetAuthValue</c> gives any authorized entity, applied here to an unbound rather than a bound
        /// session because binding this particular entity is spec-forbidden.
        /// </para>
        /// <para>
        /// <b>Honest channel accounting.</b> This default proves the candidate by HMAC rather than by a plaintext
        /// compare, so the candidate itself is never bytes on the bus a passive observer can read - unlike
        /// <see cref="VerifyPinWithPasswordAsync"/>, which sends it directly.
        /// It does NOT remove offline guessing: the unbound session's key IS <paramref name="candidatePinHash"/>
        /// (sessionKey contributes nothing, being the Empty Buffer), and every value that key derivation
        /// consumes - both StartAuthSession nonces, the command parameters, cpHash - crosses the wire in the
        /// clear. An adversary who captures one full transcript can therefore recompute the authHMAC for any
        /// candidate value entirely offline, with no further TPM interaction, bounded only by the PIN's own
        /// entropy - low for a short numeric PIN. The <c>pinLimit</c> throttle (via <c>pinCount</c>) defends only
        /// ONLINE guessing against the live TPM; it does nothing against this offline surface. Use the salted
        /// overload of this verb to remove it: a salted session's key additionally incorporates a salt
        /// RSA-OAEP-encrypted to a loaded decrypt key (for example the Endorsement Key), which only the TPM can
        /// recover, so an offline transcript alone is no longer sufficient to test a guess.
        /// </para>
        /// <para>
        /// See this group's own remarks for the PIN-normalization contract this verb's caller must uphold
        /// against <see cref="DefinePinFailIndexAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, CancellationToken)"/>'s enrollment hash.
        /// </para>
        /// </remarks>
        /// <param name="pinIndexHandle">The PIN Fail Index to verify against.</param>
        /// <param name="candidatePinHash">The candidate stored PIN form to verify.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the post-attempt counter parameters, or an error.</returns>
        public ValueTask<TpmResult<TpmPinCounterParameters>> VerifyPinAsync(
            uint pinIndexHandle,
            ReadOnlyMemory<byte> candidatePinHash,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return VerifyPinCoreAsync(device, pinIndexHandle, candidatePinHash, cancellationToken);
        }

        /// <summary>
        /// Verifies <paramref name="candidatePinHash"/> against <paramref name="pinIndexHandle"/>'s own
        /// authValue over a SALTED, unbound HMAC session, using <paramref name="tpmKey"/> to remove the offline-
        /// guessing surface the unsalted default carries.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Composes <see cref="Infrastructure.Commands.StartAuthSessionInputExtensions.CreateSaltedHmacSession(uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/>:
        /// a fresh salt is RSA-OAEP-encrypted (TPM 2.0 Library Part 1, Annex B.10.2) to <paramref name="tpmKeyModulus"/>/
        /// <paramref name="tpmKeyExponent"/>, so only the TPM holding <paramref name="tpmKey"/>'s matching
        /// private key can recover it. The session key then folds that recovered salt (Part 1, Section 17.6.12,
        /// equation 25) alongside <paramref name="candidatePinHash"/> as the session's authValue - unlike the
        /// unsalted default (see <see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>'s
        /// own remarks), an adversary who captured the wire transcript cannot recompute this key offline without
        /// also breaking the RSA-OAEP encryption, so a captured transcript alone no longer lets a candidate PIN be
        /// tested without the live TPM. The session remains unbound (never bound to
        /// <paramref name="pinIndexHandle"/>, which Part 1, Section 35.2.8.3 forbids) - only the source of key
        /// entropy changes.
        /// </para>
        /// <para>
        /// Use this overload whenever the bus a caller's <c>VerifyPinAsync</c> call runs over is one a passive
        /// adversary might capture (for example, an LPC/SPI TPM bus, or a virtualized/emulated transport) and a
        /// suitable loaded decrypt key (for example the Endorsement Key) is available; the unsalted default
        /// remains the right choice when no such key is loaded or the transport is already otherwise protected.
        /// </para>
        /// </remarks>
        /// <param name="pinIndexHandle">The PIN Fail Index to verify against.</param>
        /// <param name="candidatePinHash">The candidate stored PIN form to verify.</param>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
        /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP - an explicit per-call delegate, no closure capture.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the post-attempt counter parameters, or an error.</returns>
        public ValueTask<TpmResult<TpmPinCounterParameters>> VerifyPinAsync(
            uint pinIndexHandle,
            ReadOnlyMemory<byte> candidatePinHash,
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyModulus,
            uint tpmKeyExponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmRsaOaepEncryptDelegate encryptSalt,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return VerifyPinSaltedCoreAsync(
                device, pinIndexHandle, candidatePinHash, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for <see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>:
        /// verifies <paramref name="candidatePinHash"/> as a plaintext password rather than an HMAC session
        /// authValue.
        /// </summary>
        /// <remarks>
        /// The candidate PIN hash is sent in the clear as the session's password field - a passive bus observer
        /// reads it directly, with no HMAC derivation step to attack offline at all (there is nothing to derive;
        /// the value itself is the wire content). The atomic compare-and-move semantics of Part 1, Section
        /// 35.2.6.6 are otherwise identical to the HMAC default. Fine for diagnostics or an already-protected
        /// transport; wrong for anything where <see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>'s
        /// unbound HMAC default (or its salted overload) is the appropriate channel.
        /// </remarks>
        /// <param name="pinIndexHandle">The PIN Fail Index to verify against.</param>
        /// <param name="candidatePinHash">The candidate stored PIN form to verify.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the post-attempt counter parameters, or an error.</returns>
        public ValueTask<TpmResult<TpmPinCounterParameters>> VerifyPinWithPasswordAsync(
            uint pinIndexHandle,
            ReadOnlyMemory<byte> candidatePinHash,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return VerifyPinWithPasswordCoreAsync(device, pinIndexHandle, candidatePinHash, cancellationToken);
        }

        /// <summary>
        /// Reads <paramref name="pinIndexHandle"/>'s current counter parameters under owner authorization,
        /// composing the owner-authorized arm of <c>TPM2_NV_Read</c> over a bound HMAC session internally,
        /// without ever supplying or guessing the PIN.
        /// </summary>
        /// <remarks>
        /// The owner-read arm never moves <c>pinCount</c>: authorization is resolved entirely against the
        /// OWNER's own authValue, so this is a genuine no-oracle "how many tries remain" query - unlike a
        /// PIN-consuming <see cref="VerifyPinAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>
        /// guess, a caller may poll this as often as needed. An unwritten Index answers
        /// <c>TPM_RC_NV_UNINITIALIZED</c> on this arm specifically (the Index-arm's
        /// <c>TPM_RC_AUTH_UNAVAILABLE</c> pre-gate does not apply here, TPM 2.0 Library Part 1, Section
        /// 35.2.6.6). Use <see cref="ReadPinCountersWithPasswordAsync"/> for the plaintext-owner-password
        /// opt-out.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The PIN Fail Index to read.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the current counter parameters, or an error.</returns>
        public ValueTask<TpmResult<TpmPinCounterParameters>> ReadPinCountersAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ReadPinCountersCoreAsync(device, ownerAuth, pinIndexHandle, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for <see cref="ReadPinCountersAsync"/>: reads the counter
        /// parameters over a plaintext owner-password session rather than a bound HMAC session.
        /// </summary>
        /// <remarks>
        /// The owner authorization value is sent in the clear, with no cpHash/rpHash HMAC integrity. Fine for an
        /// owner hierarchy whose authorization value has not been set and for diagnostics; wrong for anything
        /// security-sensitive, where <see cref="ReadPinCountersAsync"/>'s bound HMAC default is the right choice.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The PIN Fail Index to read.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the current counter parameters, or an error.</returns>
        public ValueTask<TpmResult<TpmPinCounterParameters>> ReadPinCountersWithPasswordAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ReadPinCountersWithPasswordCoreAsync(device, ownerAuth, pinIndexHandle, cancellationToken);
        }

        /// <summary>
        /// Resets <paramref name="pinIndexHandle"/>'s <c>pinCount</c> to zero and (re)establishes
        /// <paramref name="pinLimit"/>, composing an owner-authorized <c>TPM2_NV_Write</c> of the full 8-octet
        /// counter window over a bound HMAC session internally - the sole recovery path once <c>pinCount</c> has
        /// reached <c>pinLimit</c> (Part 1, Section 35.2.8.1's "no automatic self-heal" note).
        /// </summary>
        /// <remarks>
        /// Use <see cref="ResetPinCountWithPasswordAsync"/> for the plaintext-owner-password opt-out.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The PIN Fail Index to reset.</param>
        /// <param name="pinLimit">The attempt threshold to (re)establish.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvWriteResponse>> ResetPinCountAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            uint pinLimit,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ResetPinCountCoreAsync(device, ownerAuth, pinIndexHandle, pinLimit, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for <see cref="ResetPinCountAsync"/>: resets the counter over a
        /// plaintext owner-password session rather than a bound HMAC session.
        /// </summary>
        /// <remarks>
        /// The owner authorization value is sent in the clear, with no cpHash/rpHash HMAC integrity. Fine for an
        /// owner hierarchy whose authorization value has not been set and for diagnostics; wrong for anything
        /// security-sensitive, where <see cref="ResetPinCountAsync"/>'s bound HMAC default is the right choice.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The PIN Fail Index to reset.</param>
        /// <param name="pinLimit">The attempt threshold to (re)establish.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvWriteResponse>> ResetPinCountWithPasswordAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            uint pinLimit,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ResetPinCountWithPasswordCoreAsync(device, ownerAuth, pinIndexHandle, pinLimit, cancellationToken);
        }

        /// <summary>
        /// Removes <paramref name="pinIndexHandle"/>'s definition, composing <c>TPM2_NV_UndefineSpace</c> over a
        /// bound HMAC session internally, authorized by the owner hierarchy's OWN authValue - never by the PIN.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Authorization is resolved against the owner hierarchy's own authValue (TPM 2.0 Library Part 3, Section
        /// 31.4): a wrong <paramref name="ownerAuth"/> is refused with a session-encoded <c>TPM_RC_BAD_AUTH</c>
        /// and the Index is left defined, so this verb is not a path to an unauthenticated PIN-throttle reset by
        /// undefining and re-running <see cref="DefinePinFailIndexAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, CancellationToken)"/>.
        /// </para>
        /// <para>
        /// Use <see cref="UndefinePinIndexWithPasswordAsync"/> for the plaintext-owner-password opt-out.
        /// </para>
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The PIN Fail Index to undefine.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefinePinIndexAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return UndefinePinIndexCoreAsync(device, ownerAuth, pinIndexHandle, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for <see cref="UndefinePinIndexAsync"/>: undefines the Index over
        /// a plaintext owner-password session rather than a bound HMAC session.
        /// </summary>
        /// <remarks>
        /// The owner authorization value is sent in the clear, with no cpHash/rpHash HMAC integrity. Fine for an
        /// owner hierarchy whose authorization value has not been set and for diagnostics; wrong for anything
        /// security-sensitive, where <see cref="UndefinePinIndexAsync"/>'s bound HMAC default is the right
        /// choice.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="pinIndexHandle">The PIN Fail Index to undefine.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefinePinIndexWithPasswordAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint pinIndexHandle,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return UndefinePinIndexWithPasswordCoreAsync(device, ownerAuth, pinIndexHandle, cancellationToken);
        }
    }

    /// <summary>
    /// The policy every PIN Fail Index this group defines carries as its <c>authPolicy</c>, and the one
    /// <see cref="ChangePinAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/> replays
    /// on the live policy session that authorizes <c>TPM2_NV_ChangeAuth</c>: <c>TPM2_PolicyAuthValue</c> folded
    /// first, then <c>TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One description drives both halves - <see cref="TpmPolicy.ComputeDigest"/> predicts the digest installed at
    /// definition time and <see cref="TpmPolicy.ExecuteAsync"/> replays the identical assertions, in the identical
    /// order, on the session that consumes it, so the predicted and the satisfied digest cannot drift apart.
    /// </para>
    /// <para>
    /// The <c>PolicyCommandCode</c> assertion is what makes the policy satisfy an ADMIN-role check at all: TPM 2.0
    /// Library Part 3, Section 31.15.1 requires the authorizing policy session's <c>commandCode</c> to be
    /// <c>TPM_CC_NV_ChangeAuth</c>, and Part 1, Section 17.2's ADMIN note states the same rule generically. The
    /// <c>PolicyAuthValue</c> assertion is the deliberate design choice on top of that requirement: it makes the
    /// session's command HMAC key incorporate the Index's CURRENT authorization value (Part 1, Section 17.6.5's
    /// policy note), so a rotation can only be performed by a caller who already knows the PIN being rotated away
    /// from - a wrong one is an HMAC mismatch that burns a retry against <c>pinCount</c> exactly as a failed
    /// verification does.
    /// </para>
    /// </remarks>
    private static TpmPolicy PinIndexRotationPolicy { get; } = new TpmPolicyBuilder()
        .WithAuthValue()
        .WithCommandCode(TpmCcConstants.TPM_CC_NV_ChangeAuth)
        .Build();

    /// <summary>
    /// Computes the <c>authPolicy</c> digest every PIN Fail Index this group defines carries - the one source
    /// every define path installs from, and the one a caller reproducing such an Index's public area (and
    /// therefore its Name) derives from, so no second hand-computed copy of the recipe can drift from it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The digest is folded over <see cref="PinNameAlgorithm"/> because that is the algorithm the authorizing
    /// session runs under. A policy session accumulates its <c>policyDigest</c> under the session's OWN
    /// <c>authHash</c> - the one fixed at <c>TPM2_StartAuthSession</c> (TPM 2.0 Library Part 3, Section 11.1),
    /// never one read from the entity being authorized (Part 1, Section 17.7). The Index's stored
    /// <c>authPolicy</c> is then compared against that accumulated digest, so the comparison carries meaning
    /// only when the two algorithms agree. That is the whole reason this group holds
    /// <see cref="PinAuthSessionHash"/> equal to <see cref="PinNameAlgorithm"/>: a session started under any
    /// other hash accumulates a digest the Index's <c>authPolicy</c> cannot match, and the ADMIN gate every
    /// rotation must pass would be unsatisfiable for reasons that have nothing to do with the policy's content.
    /// </para>
    /// <para>
    /// It is NOT an alternative authorization path for reading, writing, or undefining the Index: none of this
    /// group's <c>TPMA_NV</c> attributes routes any of those through a policy (no <c>TPMA_NV_POLICYWRITE</c>,
    /// <c>TPMA_NV_POLICYREAD</c>, or <c>TPMA_NV_POLICY_DELETE</c>), so the policy is reachable only where the TPM
    /// demands ADMIN role - the authValue rotation
    /// <see cref="ChangePinAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/> composes.
    /// Installing it is a definition-time decision that cannot be revisited: an Index defined with an Empty Policy
    /// can never satisfy an ADMIN-role check (Part 1, Section 11.2: a zero-length <c>authPolicy</c> disables the
    /// policy, and no digest is zero-length), so its authorization value is fixed for the Index's whole lifetime
    /// and the only way to change the PIN is the destructive undefine-and-redefine that discards the throttle
    /// history with it.
    /// </para>
    /// </remarks>
    /// <param name="pool">The memory pool backing the returned digest.</param>
    /// <returns>The policy digest; the caller owns and disposes it (or transfers it to a <see cref="TpmsNvPublic"/>, which does).</returns>
    private static Tpm2bDigest CreatePinIndexAuthPolicy(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int digestSize = TpmPolicyDigest.Size(PinNameAlgorithm);
        using IMemoryOwner<byte> digestOwner = pool.Rent(digestSize);
        Span<byte> digest = digestOwner.Memory.Span[..digestSize];
        _ = PinIndexRotationPolicy.ComputeDigest(PinNameAlgorithm, digest);

        return Tpm2bDigest.Create(digest, pool);
    }

    /// <summary>
    /// Composes <c>TPM2_NV_DefineSpace</c> for a new <c>TPM_NT_PIN_FAIL</c> Index under the owner hierarchy,
    /// then an owner-authorized <c>TPM2_NV_Write</c> of the fresh <c>{pinCount: 0, pinLimit}</c> counter, both
    /// over ONE owner-bound HMAC session.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The NV Index handle to define.</param>
    /// <param name="pinHash">The stored PIN form to install as the Index authValue.</param>
    /// <param name="pinLimit">The attempt threshold to provision.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The provisioning write's result, or the definition's error.</returns>
    private static async ValueTask<TpmResult<NvWriteResponse>> DefinePinFailIndexCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> pinHash,
        uint pinLimit,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //The owner-bound session negotiates XOR so it can carry the decrypt attribute over the define, encrypting
        //the auth parameter on the bus. With an empty owner authValue its session key derives from the public
        //StartAuthSession nonces, so that encryption is structural rather than confidential - the salted overload
        //(DefinePinFailIndexAsync's salted form) keys it from a secret only the TPM can recover.
        TpmResult<TpmSession> sessionResult = await StartOwnerBoundSessionAsync(
            device, pool, registry, ownerAuth, cancellationToken, symmetric: TpmtSymDef.Xor(PinAuthSessionHash)).ConfigureAwait(false);
        if(!sessionResult.IsSuccess)
        {
            return sessionResult.Map<NvWriteResponse>(_ => null!);
        }

        using TpmSession ownerSession = sessionResult.Value;
        uint sessionHandle = ownerSession.SessionHandle.Value;

        try
        {
            return await DefineAndProvisionOverSessionAsync(
                device, pool, registry, ownerSession, pinIndexHandle, pinHash, pinLimit, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            //The composed session occupies a TPM session slot from here on, so every path above must still
            //flush it. The flush runs under CancellationToken.None: the caller's own token is exactly what may
            //have taken control out of the try block, and its own outcome is caught and discarded rather than
            //allowed to escape the finally, so a flush failure can never replace the primary result the try
            //block already produced - mirroring Extensions/Policy's PolicySecretCoreAsync flush bracket.
            try
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                //Compensating cleanup only: whatever the try block above already produced (a return value or an
                //in-flight exception) is this method's real outcome, and a flush failure must never replace it.
            }
        }
    }

    /// <summary>
    /// Defines a new <c>TPM_NT_PIN_FAIL</c> Index with <paramref name="pinHash"/> as its authValue and provisions
    /// its <c>{pinCount: 0, pinLimit}</c> counter, both over the already-composed owner-authorized
    /// <paramref name="ownerSession"/> - the tail shared by the unsalted default
    /// (<see cref="DefinePinFailIndexCoreAsync"/>) and the salted overload
    /// (<see cref="DefinePinFailIndexSaltedCoreAsync"/>), which differ only in how that session's key is seeded.
    /// </summary>
    /// <remarks>
    /// The <c>auth</c> value is installed by riding <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> command PARAMETER
    /// (TPM 2.0 Library Part 3, Section 31.3), which the session encrypts on the bus while it carries the decrypt
    /// attribute. That attribute is set for the definition only and cleared before the provisioning
    /// <c>TPM2_NV_Write</c>, whose own arm exposes no parameter this group encrypts.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the NV_DefineSpace and NV_Write codecs.</param>
    /// <param name="ownerSession">The composed owner-authorized session; it negotiates a symmetric so it can carry the decrypt attribute.</param>
    /// <param name="pinIndexHandle">The NV Index handle to define.</param>
    /// <param name="pinHash">The stored PIN form to install as the Index authValue.</param>
    /// <param name="pinLimit">The attempt threshold to provision.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The provisioning write's result, or the definition's error.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the auth value and public area transfers to NvDefineSpaceInput and ownership of the policy digest transfers to TpmsNvPublic, each disposing what it owns; the redundant using locals satisfy CA2000 and are safe because all four types have idempotent disposal.")]
    private static async ValueTask<TpmResult<NvWriteResponse>> DefineAndProvisionOverSessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmSession ownerSession,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> pinHash,
        uint pinLimit,
        CancellationToken cancellationToken)
    {
        using Tpm2bAuth auth = Tpm2bAuth.Create(pinHash.Span, pool);
        using Tpm2bDigest authPolicy = CreatePinIndexAuthPolicy(pool);
        using TpmsNvPublic publicInfo = new(pinIndexHandle, PinNameAlgorithm, PinFailAttributes, authPolicy, PinCounterParametersSize);
        using NvDefineSpaceInput defineInput = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        //The decrypt attribute rides the definition alone: the executor encrypts NV_DefineSpace's auth parameter
        //when a session sets it (the input declares the parameter encryptable), and the simulator/TPM decrypts it
        //after the command HMAC verifies. It is cleared before the provisioning write, whose owner arm has no
        //encryptable parameter this group drives (a decrypt attribute there would be TPM_RC_ATTRIBUTES).
        ownerSession.SessionAttributes |= TpmaSession.DECRYPT;

        //NV_DefineSpace's single handle (@authHandle = owner) is a permanent handle - its Name is the raw
        //4-octet handle value, which the executor derives itself, so no handleNames entry is supplied.
        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, defineInput, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        ownerSession.SessionAttributes &= ~TpmaSession.DECRYPT;

        if(!defineResult.IsSuccess)
        {
            return defineResult.Map<NvWriteResponse>(_ => default!);
        }

        return await WritePinCounterParametersAsync(device, pool, registry, ownerSession, pinIndexHandle, pinCount: 0, pinLimit, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The salted composition core for <c>DefinePinFailIndexAsync</c>'s salted overload: defines and provisions
    /// the Index over an unbound, SALTED HMAC session (authorizing the owner by its own authValue) whose decrypt
    /// attribute encrypts <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> parameter under a key only the TPM can recover.
    /// </summary>
    /// <remarks>
    /// Mirrors <see cref="VerifyPinSaltedCoreAsync"/>'s session shape (TPM 2.0 Library Part 1, Section 17.6.12,
    /// equation 25): a fresh salt is RSA-OAEP-encrypted to <paramref name="tpmKey"/>, so the session key - and
    /// therefore the parameter-encryption keystream keyed on it - cannot be reproduced from the wire transcript
    /// alone, closing the offline-recovery surface the unsalted default leaves open for an empty owner authValue.
    /// The session authorizes the owner via <paramref name="ownerAuth"/> as its authValue term (unbound, so the
    /// value is folded per command rather than into the session key), and the same value keys both the auth HMAC
    /// and the parameter encryption.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
    /// <param name="pinIndexHandle">The NV Index handle to define.</param>
    /// <param name="pinHash">The stored PIN form to install as the Index authValue.</param>
    /// <param name="pinLimit">The attempt threshold to provision.</param>
    /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
    /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The provisioning write's result, or the definition's error.</returns>
    private static async ValueTask<TpmResult<NvWriteResponse>> DefinePinFailIndexSaltedCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> pinHash,
        uint pinLimit,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Unbound but salted, and negotiating XOR so it can carry the decrypt attribute over the define - the same
        //session shape VerifyPinAsync's salted overload composes, except the authValue term authorizes the owner
        //rather than the PIN Index. SetAuthValue below makes ownerAuth the per-command authValue term.
        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateSaltedHmacSession(
            tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, PinAuthSessionHash, encryptSalt, pool, cancellationToken, TpmtSymDef.Xor(PinAuthSessionHash)).ConfigureAwait(false);

        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, salted.Input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

            if(!startResult.IsSuccess)
            {
                return startResult.Map<NvWriteResponse>(_ => null!);
            }

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                using TpmSession ownerSession = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, salted.Input.NonceCaller, started.NonceTPM,
                    PinAuthSessionHash, pool, symmetric: TpmtSymDef.Xor(PinAuthSessionHash), salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: cancellationToken).ConfigureAwait(false);
                ownerSession.SetAuthValue(ownerAuth.Span, pool);

                return await DefineAndProvisionOverSessionAsync(
                    device, pool, registry, ownerSession, pinIndexHandle, pinHash, pinLimit, cancellationToken).ConfigureAwait(false);
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
                    //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
                }
            }
        }
        finally
        {
            salted.Salt.Memory.Span[..salted.SaltLength].Clear();
            salted.Salt.Dispose();
        }
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>DefinePinFailIndexWithPasswordAsync</c>: the original
    /// plaintext-owner-password composition, unchanged.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The NV Index handle to define.</param>
    /// <param name="pinHash">The stored PIN form to install as the Index authValue.</param>
    /// <param name="pinLimit">The attempt threshold to provision.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The provisioning write's result, or the definition's error.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the auth value and public area transfers to NvDefineSpaceInput and ownership of the policy digest transfers to TpmsNvPublic, each disposing what it owns; the redundant using locals satisfy CA2000 and are safe because all four types have idempotent disposal.")]
    private static async ValueTask<TpmResult<NvWriteResponse>> DefinePinFailIndexWithPasswordCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> pinHash,
        uint pinLimit,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

        using Tpm2bAuth auth = Tpm2bAuth.Create(pinHash.Span, pool);
        using Tpm2bDigest authPolicy = CreatePinIndexAuthPolicy(pool);
        using TpmsNvPublic publicInfo = new(pinIndexHandle, PinNameAlgorithm, PinFailAttributes, authPolicy, PinCounterParametersSize);
        using NvDefineSpaceInput defineInput = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);
        using TpmPasswordSession defineSession = TpmPasswordSession.Create(ownerAuth.Span, pool);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, defineInput, [defineSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!defineResult.IsSuccess)
        {
            return defineResult.Map<NvWriteResponse>(_ => default!);
        }

        using TpmPasswordSession writeSession = TpmPasswordSession.Create(ownerAuth.Span, pool);
        IMemoryOwner<byte> blobOwner = pool.Rent(PinCounterParametersSize);
        Tpm2bMaxNvBuffer data;
        try
        {
            Memory<byte> blob = blobOwner.Memory[..PinCounterParametersSize];
            BinaryPrimitives.WriteUInt32BigEndian(blob.Span, 0);
            BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

            //The rental is laid out in place and then adopted by the TPM2B_MAX_NV_BUFFER the command frames, so
            //the counter parameters cross into the input without a second copy; the carrier is the only owner
            //from there on.
            data = Tpm2bMaxNvBuffer.Adopt(blobOwner, PinCounterParametersSize);
        }
        catch
        {
            //This frame is the rental's only owner until the adoption returns, so a fault ahead of it releases
            //the rental here.
            blobOwner.Dispose();
            throw;
        }

        using(data)
        {
            var writeInput = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, pinIndexHandle, data, Offset: 0);

            return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                device, writeInput, [writeSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The unsalted composition core for <c>ChangePinAsync</c>: opens the ADMIN-role policy session, opens an
    /// unbound decrypt companion for the replacement value, and rotates - flushing both sessions on every path.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to rotate.</param>
    /// <param name="oldPinHash">The Index's current stored PIN form.</param>
    /// <param name="newPinHash">The replacement stored PIN form.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The rotation's result, or the first failing command's error.</returns>
    private static async ValueTask<TpmResult<NvChangeAuthResponse>> ChangePinCoreAsync(
        TpmDevice device,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> oldPinHash,
        ReadOnlyMemory<byte> newPinHash,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmResponseCodec.NvChangeAuth);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        TpmResult<TpmSession> authResult = await StartRotationPolicySessionAsync(device, pool, registry, cancellationToken).ConfigureAwait(false);
        if(!authResult.IsSuccess)
        {
            return authResult.Map<NvChangeAuthResponse>(_ => null!);
        }

        using TpmSession authSession = authResult.Value;
        uint authSessionHandle = authSession.SessionHandle.Value;

        try
        {
            //A SEPARATE session carries the decrypt attribute: the authorizing policy session may not, because a
            //policy session used for parameter encryption folds the entity's authValue into its sessionValue
            //whether or not the policy asserted TPM2_PolicyAuthValue (TPM 2.0 Library Part 1, Section 19.1's
            //note) - a different rule from the authorization-HMAC one, and one that would key the encryption of
            //the NEW PIN form on the OLD one. This companion is unbound and unsalted, so its own sessionValue is
            //the Empty Buffer session key (Section 17.6.9) and the encryption is structural rather than
            //confidential; ChangePinAsync's salted overload is where genuine confidentiality lives.
            StartAuthSessionInput decryptStartInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(
                PinAuthSessionHash, TpmtSymDef.Xor(PinAuthSessionHash));

            TpmResult<StartAuthSessionResponse> decryptStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, decryptStartInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

            if(!decryptStartResult.IsSuccess)
            {
                return decryptStartResult.Map<NvChangeAuthResponse>(_ => null!);
            }

            StartAuthSessionResponse decryptStarted = decryptStartResult.Value;
            uint decryptSessionHandle = decryptStarted.SessionHandle.Value;

            try
            {
                using TpmSession decryptSession = new(
                    new TpmHandle(decryptSessionHandle), decryptStarted.NonceTPM, PinAuthSessionHash, pool, TpmtSymDef.Xor(PinAuthSessionHash));

                return await ChangePinOverSessionsAsync(
                    device, pool, registry, pinIndexHandle, authSession, decryptSession, oldPinHash, newPinHash, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                        device, FlushContextInput.ForHandle(decryptSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
                }
            }
        }
        finally
        {
            try
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    device, FlushContextInput.ForHandle(authSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// The salted composition core for <c>ChangePinAsync</c>'s salted overload: identical to
    /// <see cref="ChangePinCoreAsync"/> except that BOTH sessions are SALTED against
    /// <paramref name="tpmKey"/> - the authorizing policy session, so neither leg of its HMAC can be recomputed
    /// from a captured transcript, and the decrypt companion, so the keystream protecting
    /// <paramref name="newPinHash"/> derives from a secret only the TPM holding <paramref name="tpmKey"/> can
    /// recover (TPM 2.0 Library Part 1, Section 17.6.12, equation 25).
    /// </summary>
    /// <remarks>
    /// The two sessions draw their salts from two independent <c>TPM2_StartAuthSession</c> exchanges, so each
    /// session key is derived from its own secret; a salt is never carried from one session to the other, which
    /// would make the pair's keys jointly recoverable from a single compromise.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to rotate.</param>
    /// <param name="oldPinHash">The Index's current stored PIN form.</param>
    /// <param name="newPinHash">The replacement stored PIN form.</param>
    /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm.</param>
    /// <param name="encryptSalt">Encrypts the drawn salt via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The rotation's result, or the first failing command's error.</returns>
    private static async ValueTask<TpmResult<NvChangeAuthResponse>> ChangePinSaltedCoreAsync(
        TpmDevice device,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> oldPinHash,
        ReadOnlyMemory<byte> newPinHash,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmResponseCodec.NvChangeAuth);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        TpmResult<TpmSession> authResult = await StartSaltedRotationPolicySessionAsync(
            device, pool, registry, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken).ConfigureAwait(false);

        if(!authResult.IsSuccess)
        {
            return authResult.Map<NvChangeAuthResponse>(_ => null!);
        }

        using TpmSession authSession = authResult.Value;
        uint authSessionHandle = authSession.SessionHandle.Value;

        try
        {
            //The same shape DefinePinFailIndexAsync's salted overload composes for the enrollment value, applied
            //here to the replacement one: unbound, salted, negotiating XOR so it can carry the decrypt attribute.
            //Its salt is drawn by this call alone and shares nothing with the authorizing session's.
            (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateSaltedHmacSession(
                tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, PinAuthSessionHash, encryptSalt, pool, cancellationToken, TpmtSymDef.Xor(PinAuthSessionHash)).ConfigureAwait(false);

            try
            {
                TpmResult<StartAuthSessionResponse> decryptStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                    device, salted.Input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

                if(!decryptStartResult.IsSuccess)
                {
                    return decryptStartResult.Map<NvChangeAuthResponse>(_ => null!);
                }

                StartAuthSessionResponse decryptStarted = decryptStartResult.Value;
                uint decryptSessionHandle = decryptStarted.SessionHandle.Value;

                try
                {
                    using TpmSession decryptSession = await TpmSession.CreateBoundAsync(
                        new TpmHandle(decryptSessionHandle), ReadOnlyMemory<byte>.Empty, salted.Input.NonceCaller, decryptStarted.NonceTPM,
                        PinAuthSessionHash, pool, symmetric: TpmtSymDef.Xor(PinAuthSessionHash), salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: cancellationToken).ConfigureAwait(false);

                    return await ChangePinOverSessionsAsync(
                        device, pool, registry, pinIndexHandle, authSession, decryptSession, oldPinHash, newPinHash, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    try
                    {
                        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                            device, FlushContextInput.ForHandle(decryptSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                        //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
                    }
                }
            }
            finally
            {
                salted.Salt.Memory.Span[..salted.SaltLength].Clear();
                salted.Salt.Dispose();
            }
        }
        finally
        {
            try
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    device, FlushContextInput.ForHandle(authSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// Starts the UNBOUND, unsalted POLICY session <see cref="ChangePinCoreAsync"/> authorizes
    /// <c>TPM2_NV_ChangeAuth</c> with - the ADMIN-role counterpart of
    /// <see cref="StartOwnerBoundSessionAsync"/>; <see cref="StartSaltedRotationPolicySessionAsync"/> is the
    /// salted sibling the salted core uses.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The plain <see cref="TpmSession"/> constructor is the honest model of an unbound, unsalted session: the
    /// session key is the Empty Buffer with no KDFa derivation at all (TPM 2.0 Library Part 1, Section 17.6.9),
    /// so once the caller sets the Index's authorization value the session's HMAC key
    /// (<c>sessionValue = sessionKey || authValue</c>) reduces to that value alone - exactly the term
    /// <c>TPM2_PolicyAuthValue</c> makes the TPM fold in on its own side (Part 1, Section 17.6.5's policy note).
    /// The alternative policy-session wrapper in this library deliberately sends an EMPTY authorization instead,
    /// which is right for a policy satisfied without an authValue and wrong here.
    /// </para>
    /// <para>
    /// Unlike <see cref="StartOwnerBoundSessionAsync"/> nothing asynchronous runs between the TPM allocating the
    /// session slot and this method returning the session that owns it, so no compensating flush is needed here -
    /// the caller's own bracket covers every path from the return onward.
    /// </para>
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry; must already carry the StartAuthSession codec.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the policy session (the caller disposes it and flushes its handle), or the StartAuthSession error.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the session transfers to the caller inside the returned result; the rotation cores dispose it and flush its handle in their own brackets.")]
    private static async ValueTask<TpmResult<TpmSession>> StartRotationPolicySessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        CancellationToken cancellationToken)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(PinAuthSessionHash);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!startResult.IsSuccess)
        {
            return startResult.Map<TpmSession>(_ => null!);
        }

        StartAuthSessionResponse started = startResult.Value;

        //The session takes ownership of started's nonceTPM, so the response is never disposed independently.
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, PinAuthSessionHash, pool);

        return TpmResult<TpmSession>.Success(session);
    }

    /// <summary>
    /// Starts the UNBOUND but SALTED POLICY session <see cref="ChangePinSaltedCoreAsync"/> authorizes
    /// <c>TPM2_NV_ChangeAuth</c> with: the salt is RSA-OAEP-encrypted to <paramref name="tpmKey"/>, so the
    /// session key this session derives is a secret only the TPM holding that key's private half can reproduce.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>TPM2_StartAuthSession</c> derives <c>sessionKey</c> identically for every session type (TPM 2.0
    /// Library Part 3, Section 11.1.1), so a POLICY session takes the same KDFa-over-the-recovered-salt recipe
    /// an HMAC session does (Part 1, Section 17.6.12, equation 25). Salting does not touch what the policy
    /// asserts or how the digest folds - it replaces the Empty Buffer session key the unsalted sibling
    /// (<see cref="StartRotationPolicySessionAsync"/>) is left with (Part 1, Section 17.6.9). The caller's
    /// <c>SetAuthValue</c> then layers the Index's authorization value on top exactly as before
    /// (<c>sessionValue = sessionKey || authValue</c>), which is what makes the difference load-bearing: with a
    /// secret <c>sessionKey</c> in front of it, the authValue term is no longer the key's only unknown, so a
    /// captured transcript plus a candidate PIN no longer reproduces the HMAC (Part 1, Section 17.6.5).
    /// </para>
    /// <para>
    /// The salt is zeroized and returned to the pool as soon as <c>CreateBoundAsync</c> has folded it into the
    /// derived session key; nothing downstream needs it again. From the instant the TPM allocates the session
    /// slot the derivation reaches an asynchronous crypto seam under the caller's own token, and the caller's
    /// flush bracket only opens once this helper has RETURNED a session, so a failing derivation releases the
    /// slot itself - the same compensating bracket <see cref="StartOwnerBoundSessionAsync"/> opens, and for the
    /// same reason.
    /// </para>
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry; must already carry the StartAuthSession and FlushContext codecs.</param>
    /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
    /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the policy session (the caller disposes it and flushes its handle), or the StartAuthSession error.</returns>
    private static async ValueTask<TpmResult<TpmSession>> StartSaltedRotationPolicySessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken)
    {
        //No symmetric definition is negotiated: this session authorizes only. A policy session that also carried
        //the decrypt attribute would fold the Index's authValue into its sessionValue whether or not the policy
        //asserted TPM2_PolicyAuthValue (TPM 2.0 Library Part 1, Section 19.1's note), which is precisely why the
        //replacement value rides a separate companion session instead.
        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateSaltedPolicySession(
            tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, PinAuthSessionHash, encryptSalt, pool, cancellationToken).ConfigureAwait(false);

        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, salted.Input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

            if(!startResult.IsSuccess)
            {
                return startResult.Map<TpmSession>(_ => null!);
            }

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                //Unbound (bindAuthValue empty) but salted, so sessionKey = KDFa(salt, ...) rather than the Empty
                //Buffer. The session takes ownership of started's nonceTPM, so the response is never disposed
                //independently.
                TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, salted.Input.NonceCaller, started.NonceTPM,
                    PinAuthSessionHash, pool, salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: cancellationToken).ConfigureAwait(false);

                return TpmResult<TpmSession>.Success(session);
            }
            catch
            {
                try
                {
                    _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                        device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
                }

                throw;
            }
        }
        finally
        {
            salted.Salt.Memory.Span[..salted.SaltLength].Clear();
            salted.Salt.Dispose();
        }
    }

    /// <summary>
    /// Shared by <see cref="ChangePinCoreAsync"/> and <see cref="ChangePinSaltedCoreAsync"/>: satisfies the
    /// Index's ADMIN-role policy on <paramref name="authSession"/>, resolves the Index's real current Name, and
    /// issues the <c>TPM2_NV_ChangeAuth</c> that swaps the authorization value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The policy is replayed from the same description its digest was predicted from
    /// (<see cref="PinIndexRotationPolicy"/>), so the session reaches the Index's stored <c>authPolicy</c> by
    /// construction: <c>TPM2_PolicyAuthValue</c> first, then
    /// <c>TPM2_PolicyCommandCode(TPM_CC_NV_ChangeAuth)</c>, which is what lets the session assert ADMIN role at
    /// all (TPM 2.0 Library Part 3, Section 31.15.1).
    /// </para>
    /// <para>
    /// <b>The response is keyed on the NEW value.</b> Part 3, Section 31.15.1: "Since the NV Index authorization
    /// is changed before the response HMAC is calculated, the newAuth value is used when generating the response
    /// HMAC key if required" - and it is required here, because <c>TPM2_PolicyAuthValue</c> put the Index's
    /// authorization value into this session's HMAC key. The command HMAC must therefore be keyed on the OLD
    /// value and the response HMAC on the NEW one, with the changeover at the instant the TPM commits the
    /// rotation. <see cref="TpmCommandExecutor"/> composes and verifies within one call and its only seam between
    /// the two is the submission itself, so the swap rides a submit handler layered over
    /// <paramref name="device"/>: the command is forwarded verbatim to the real device (whose own observers still
    /// see the exchange), and the authorization value is swapped the moment the response comes back off the
    /// transport, before the executor verifies it. <c>SetAuthValue</c> strips trailing zero octets on both sides
    /// of the swap, matching what the TPM stores and keys on (Part 1, Section 17.6.4.3).
    /// </para>
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the <c>NV_ChangeAuth</c> codec.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to rotate.</param>
    /// <param name="authSession">The composed ADMIN-role policy session; its authorization value is set here.</param>
    /// <param name="decryptSession">The composed decrypt companion; the decrypt attribute is set here.</param>
    /// <param name="oldPinHash">The Index's current stored PIN form.</param>
    /// <param name="newPinHash">The replacement stored PIN form.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The rotation's result, or the first failing command's error.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the replacement authorization value transfers to NvChangeAuthInput, which disposes it; the redundant using local satisfies CA2000 and is safe because both types have idempotent disposal.")]
    private static async ValueTask<TpmResult<NvChangeAuthResponse>> ChangePinOverSessionsAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        uint pinIndexHandle,
        TpmSession authSession,
        TpmSession decryptSession,
        ReadOnlyMemory<byte> oldPinHash,
        ReadOnlyMemory<byte> newPinHash,
        CancellationToken cancellationToken)
    {
        TpmResult<uint> policyResult = await PinIndexRotationPolicy.ExecuteAsync(
            device, authSession.SessionHandle.Value, cancellationToken).ConfigureAwait(false);

        if(!policyResult.IsSuccess)
        {
            return policyResult.Map<NvChangeAuthResponse>(_ => null!);
        }

        //NV_ChangeAuth's single handle is the Index itself (its own ADMIN-role authorization), and an NV Index
        //Name is hash-based, so the executor cannot derive it from the handle value - it is read back rather
        //than recomputed blind, exactly as the Index-authorized verbs above do.
        TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(pinIndexHandle, cancellationToken).ConfigureAwait(false);
        if(!nameResult.IsSuccess)
        {
            return nameResult.Map<NvChangeAuthResponse>(_ => null!);
        }

        using NvReadPublicResponse namePublic = nameResult.Value;
        ReadOnlyMemory<byte>[] handleNames = [namePublic.NvName.Span.ToArray()];

        //The command HMAC proves knowledge of the value being rotated AWAY from; the response HMAC is keyed on
        //the value being rotated TO (see this method's own remarks).
        authSession.SetAuthValue(oldPinHash.Span, pool);
        decryptSession.SessionAttributes |= TpmaSession.DECRYPT;

        using Tpm2bAuth newAuth = Tpm2bAuth.Create(newPinHash.Span, pool);
        using NvChangeAuthInput input = new(pinIndexHandle, newAuth);
        using TpmDevice rotationDevice = TpmDevice.Create(SubmitThenAdoptNewAuthAsync);

        return await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
            rotationDevice, input, [authSession, decryptSession], handleNames, pool, registry, cancellationToken).ConfigureAwait(false);

        /// <summary>
        /// Forwards one command to the real device unaltered and then moves the authorizing session onto the
        /// replacement authorization value, so the response the executor is about to verify is keyed the way the
        /// TPM framed it.
        /// </summary>
        async ValueTask<TpmResult<TpmResponse>> SubmitThenAdoptNewAuthAsync(
            ReadOnlyMemory<byte> command, BaseMemoryPool submitPool, CancellationToken submitCancellationToken)
        {
            TpmResult<TpmResponse> submitted = await device.SubmitAsync(command, submitPool, submitCancellationToken).ConfigureAwait(false);
            authSession.SetAuthValue(newPinHash.Span, pool);

            return submitted;
        }
    }

    /// <summary>
    /// Composes an Index-authorized <c>TPM2_NV_Read</c> of the full <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c>
    /// window over an UNBOUND, unsalted HMAC session whose authValue is <paramref name="candidatePinHash"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to verify against.</param>
    /// <param name="candidatePinHash">The candidate stored PIN form to verify.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the post-attempt counter parameters, or an error.</returns>
    private static async ValueTask<TpmResult<TpmPinCounterParameters>> VerifyPinCoreAsync(
        TpmDevice device,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> candidatePinHash,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Unbound, unsalted (Part 1, Section 17.6.9): TPM_RH_NULL bind, Empty Buffer sessionKey. Never bound to
        //pinIndexHandle - Part 1, Section 35.2.8.3 forbids binding a session to a PIN Index outright.
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(PinAuthSessionHash);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!startResult.IsSuccess)
        {
            return startResult.Map<TpmPinCounterParameters>(_ => default);
        }

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            //The plain constructor yields sessionKey = Empty Buffer (unbound/unsalted); SetAuthValue then makes
            //candidatePinHash the session's authValue term, so sessionValue = Empty || candidatePinHash =
            //candidatePinHash - the candidate becomes the per-command HMAC key exactly as this verb's own
            //remarks describe.
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, PinAuthSessionHash, pool);
            session.SetAuthValue(candidatePinHash.Span, pool);

            return await VerifyPinOverSessionAsync(device, pool, registry, pinIndexHandle, session, cancellationToken).ConfigureAwait(false);
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
                //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// Composes an Index-authorized <c>TPM2_NV_Read</c> of the full counter window over a SALTED, unbound HMAC
    /// session whose authValue is <paramref name="candidatePinHash"/> - the offline-guessing-resistant overload.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to verify against.</param>
    /// <param name="candidatePinHash">The candidate stored PIN form to verify.</param>
    /// <param name="tpmKey">The handle of a loaded RSA decrypt key the salt is encrypted to.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm.</param>
    /// <param name="encryptSalt">Encrypts the drawn salt via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the post-attempt counter parameters, or an error.</returns>
    private static async ValueTask<TpmResult<TpmPinCounterParameters>> VerifyPinSaltedCoreAsync(
        TpmDevice device,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> candidatePinHash,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateSaltedHmacSession(
            tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, PinAuthSessionHash, encryptSalt, pool, cancellationToken).ConfigureAwait(false);

        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, salted.Input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

            if(!startResult.IsSuccess)
            {
                return startResult.Map<TpmPinCounterParameters>(_ => default);
            }

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                //Unbound (bindAuthValue empty) but salted: sessionKey = KDFa(salt, ...). SetAuthValue then makes
                //candidatePinHash the session's authValue term on top, so an offline transcript alone can no
                //longer reproduce the HMAC key - see this overload's own remarks.
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, salted.Input.NonceCaller, started.NonceTPM,
                    PinAuthSessionHash, pool, salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: cancellationToken).ConfigureAwait(false);
                session.SetAuthValue(candidatePinHash.Span, pool);

                return await VerifyPinOverSessionAsync(device, pool, registry, pinIndexHandle, session, cancellationToken).ConfigureAwait(false);
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
                    //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
                }
            }
        }
        finally
        {
            salted.Salt.Memory.Span[..salted.SaltLength].Clear();
            salted.Salt.Dispose();
        }
    }

    /// <summary>
    /// Shared by <see cref="VerifyPinCoreAsync"/> and <see cref="VerifyPinSaltedCoreAsync"/>: derives the PIN
    /// Index's current Name via <c>NV_ReadPublic</c> (Name1 = Name2 = the Index's own Name, since it authorizes
    /// itself), then issues the Index-authorized <c>TPM2_NV_Read</c> over the already-composed
    /// <paramref name="session"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the <c>NV_Read</c> codec.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to verify against.</param>
    /// <param name="session">The already-composed authorization session (its authValue is the candidate PIN hash).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the post-attempt counter parameters, or an error.</returns>
    private static async ValueTask<TpmResult<TpmPinCounterParameters>> VerifyPinOverSessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        uint pinIndexHandle,
        TpmSessionBase session,
        CancellationToken cancellationToken)
    {
        TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(pinIndexHandle, cancellationToken).ConfigureAwait(false);
        if(!nameResult.IsSuccess)
        {
            return nameResult.Map<TpmPinCounterParameters>(_ => default);
        }

        using NvReadPublicResponse namePublic = nameResult.Value;
        ReadOnlyMemory<byte> indexName = namePublic.NvName.Span.ToArray();
        ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

        var readInput = new NvReadInput(AuthHandle: pinIndexHandle, NvIndex: pinIndexHandle, Size: PinCounterParametersSize, Offset: 0);

        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], handleNames, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!readResult.IsSuccess)
        {
            return readResult.Map<TpmPinCounterParameters>(_ => default);
        }

        using NvReadResponse response = readResult.Value;

        return TpmResult<TpmPinCounterParameters>.Success(ParsePinCounterParameters(response.Data));
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>VerifyPinWithPasswordAsync</c>: the original plaintext-
    /// password composition, unchanged.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to verify against.</param>
    /// <param name="candidatePinHash">The candidate stored PIN form to verify.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the post-attempt counter parameters, or an error.</returns>
    private static async ValueTask<TpmResult<TpmPinCounterParameters>> VerifyPinWithPasswordCoreAsync(
        TpmDevice device,
        uint pinIndexHandle,
        ReadOnlyMemory<byte> candidatePinHash,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

        using TpmPasswordSession session = TpmPasswordSession.Create(candidatePinHash.Span, pool);
        var readInput = new NvReadInput(AuthHandle: pinIndexHandle, NvIndex: pinIndexHandle, Size: PinCounterParametersSize, Offset: 0);

        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!readResult.IsSuccess)
        {
            return readResult.Map<TpmPinCounterParameters>(_ => default);
        }

        using NvReadResponse response = readResult.Value;

        return TpmResult<TpmPinCounterParameters>.Success(ParsePinCounterParameters(response.Data));
    }

    /// <summary>
    /// Composes the owner-authorized arm of <c>TPM2_NV_Read</c> against the full counter window over a bound
    /// HMAC session - a no-oracle retry-count query that never moves <c>pinCount</c> (TPM 2.0 Library Part 3,
    /// Section 31.13).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to read.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the current counter parameters, or an error.</returns>
    private static async ValueTask<TpmResult<TpmPinCounterParameters>> ReadPinCountersCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        TpmResult<TpmSession> sessionResult = await StartOwnerBoundSessionAsync(device, pool, registry, ownerAuth, cancellationToken).ConfigureAwait(false);
        if(!sessionResult.IsSuccess)
        {
            return sessionResult.Map<TpmPinCounterParameters>(_ => default);
        }

        using TpmSession ownerSession = sessionResult.Value;
        uint sessionHandle = ownerSession.SessionHandle.Value;

        try
        {
            TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(pinIndexHandle, cancellationToken).ConfigureAwait(false);
            if(!nameResult.IsSuccess)
            {
                return nameResult.Map<TpmPinCounterParameters>(_ => default);
            }

            using NvReadPublicResponse namePublic = nameResult.Value;

            //@authHandle = TPM_RH_OWNER is a permanent handle (its Name is the raw handle, derived by the
            //executor itself, so its entry is left empty); nvIndex needs its real, current, hash-based Name.
            ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, namePublic.NvName.Span.ToArray()];

            var readInput = new NvReadInput(AuthHandle: (uint)TpmRh.TPM_RH_OWNER, NvIndex: pinIndexHandle, Size: PinCounterParametersSize, Offset: 0);

            TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                device, readInput, [ownerSession], handleNames, pool, registry, cancellationToken).ConfigureAwait(false);

            if(!readResult.IsSuccess)
            {
                return readResult.Map<TpmPinCounterParameters>(_ => default);
            }

            using NvReadResponse response = readResult.Value;

            return TpmResult<TpmPinCounterParameters>.Success(ParsePinCounterParameters(response.Data));
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
                //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>ReadPinCountersWithPasswordAsync</c>: the original
    /// plaintext-owner-password composition, unchanged.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to read.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the current counter parameters, or an error.</returns>
    private static async ValueTask<TpmResult<TpmPinCounterParameters>> ReadPinCountersWithPasswordCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: (uint)TpmRh.TPM_RH_OWNER, NvIndex: pinIndexHandle, Size: PinCounterParametersSize, Offset: 0);

        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!readResult.IsSuccess)
        {
            return readResult.Map<TpmPinCounterParameters>(_ => default);
        }

        using NvReadResponse response = readResult.Value;

        return TpmResult<TpmPinCounterParameters>.Success(ParsePinCounterParameters(response.Data));
    }

    /// <summary>
    /// Composes an owner-authorized <c>TPM2_NV_Write</c> of the full 8-octet counter window over a bound HMAC
    /// session, resetting <c>pinCount</c> to zero and (re)establishing <paramref name="pinLimit"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to reset.</param>
    /// <param name="pinLimit">The attempt threshold to (re)establish.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The write result.</returns>
    private static async ValueTask<TpmResult<NvWriteResponse>> ResetPinCountCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        uint pinLimit,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        TpmResult<TpmSession> sessionResult = await StartOwnerBoundSessionAsync(device, pool, registry, ownerAuth, cancellationToken).ConfigureAwait(false);
        if(!sessionResult.IsSuccess)
        {
            return sessionResult.Map<NvWriteResponse>(_ => null!);
        }

        using TpmSession ownerSession = sessionResult.Value;
        uint sessionHandle = ownerSession.SessionHandle.Value;

        try
        {
            return await WritePinCounterParametersAsync(device, pool, registry, ownerSession, pinIndexHandle, pinCount: 0, pinLimit, cancellationToken).ConfigureAwait(false);
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
                //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>ResetPinCountWithPasswordAsync</c>: the original
    /// plaintext-owner-password composition, unchanged.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to reset.</param>
    /// <param name="pinLimit">The attempt threshold to (re)establish.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The write result.</returns>
    private static async ValueTask<TpmResult<NvWriteResponse>> ResetPinCountWithPasswordCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        uint pinLimit,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);
        IMemoryOwner<byte> blobOwner = pool.Rent(PinCounterParametersSize);
        Tpm2bMaxNvBuffer data;
        try
        {
            Memory<byte> blob = blobOwner.Memory[..PinCounterParametersSize];
            BinaryPrimitives.WriteUInt32BigEndian(blob.Span, 0);
            BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

            //The rental is laid out in place and then adopted by the TPM2B_MAX_NV_BUFFER the command frames, so
            //the counter parameters cross into the input without a second copy; the carrier is the only owner
            //from there on.
            data = Tpm2bMaxNvBuffer.Adopt(blobOwner, PinCounterParametersSize);
        }
        catch
        {
            //This frame is the rental's only owner until the adoption returns, so a fault ahead of it releases
            //the rental here.
            blobOwner.Dispose();
            throw;
        }

        using(data)
        {
            var writeInput = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, pinIndexHandle, data, Offset: 0);

            return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                device, writeInput, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Composes <c>TPM2_NV_UndefineSpace</c> against <paramref name="pinIndexHandle"/> over a bound HMAC
    /// session, authorized by the owner hierarchy's own authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to undefine.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The undefine-space result.</returns>
    private static async ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefinePinIndexCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        TpmResult<TpmSession> sessionResult = await StartOwnerBoundSessionAsync(device, pool, registry, ownerAuth, cancellationToken).ConfigureAwait(false);
        if(!sessionResult.IsSuccess)
        {
            return sessionResult.Map<NvUndefineSpaceResponse>(_ => null!);
        }

        using TpmSession ownerSession = sessionResult.Value;
        uint sessionHandle = ownerSession.SessionHandle.Value;

        try
        {
            TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(pinIndexHandle, cancellationToken).ConfigureAwait(false);
            if(!nameResult.IsSuccess)
            {
                return nameResult.Map<NvUndefineSpaceResponse>(_ => null!);
            }

            using NvReadPublicResponse namePublic = nameResult.Value;
            ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, namePublic.NvName.Span.ToArray()];

            var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, pinIndexHandle);

            return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
                device, input, [ownerSession], handleNames, pool, registry, cancellationToken).ConfigureAwait(false);
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
                //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>UndefinePinIndexWithPasswordAsync</c>: the original
    /// plaintext-owner-password composition, unchanged.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to undefine.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The undefine-space result.</returns>
    private static async ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefinePinIndexWithPasswordCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint pinIndexHandle,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, pinIndexHandle);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts and binds an HMAC session to the owner hierarchy - the shared bracket each owner-authorized Pin
    /// verb opens before its own command(s) and closes (regardless of outcome) after.
    /// </summary>
    /// <remarks>
    /// Mirrors <c>Extensions/Policy/TpmDeviceExtensions.cs</c>'s <c>PolicySecretCoreAsync</c>/
    /// <c>CreateAuthorizationSessionAsync</c> bracket (TPM 2.0 Library Part 1, Section 17.6.10, equation 20):
    /// binding folds <paramref name="ownerAuth"/> into the session key via KDFa, so the per-command authHMAC's
    /// key genuinely incorporates the owner's authorization value rather than sending it in the clear the way
    /// <c>…WithPasswordAsync</c> does. This is Pin's own sibling of that Policy-file helper - the two files are
    /// disjoint, so the composition is duplicated rather than shared.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry; must already carry the StartAuthSession and FlushContext codecs.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <param name="symmetric">
    /// The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for
    /// none. Only <see cref="DefinePinFailIndexAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, CancellationToken)"/> supplies one (to encrypt <c>TPM2_NV_DefineSpace</c>'s
    /// <c>auth</c> parameter); the read/reset/undefine verbs leave it unset, since their commands carry no
    /// parameter this group encrypts.
    /// </param>
    /// <returns>A result containing the bound session (the caller disposes it and flushes its handle), or the StartAuthSession error.</returns>
    private static async ValueTask<TpmResult<TpmSession>> StartOwnerBoundSessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        ReadOnlyMemory<byte> ownerAuth,
        CancellationToken cancellationToken,
        TpmtSymDef? symmetric = null)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession((uint)TpmRh.TPM_RH_OWNER, PinAuthSessionHash, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!startResult.IsSuccess)
        {
            return startResult.Map<TpmSession>(_ => null!);
        }

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        //The TPM has allocated a session slot from here on, and the caller's flush bracket only opens once this
        //helper has RETURNED a session - so the derivation below, which reaches the asynchronous crypto seam with
        //the caller's own token, must release that slot itself when it fails. The flush runs under
        //CancellationToken.None (the caller's token is exactly what may have aborted the derivation) and its own
        //outcome is caught and discarded, so it can never replace the exception that is this call's real outcome -
        //the bracket Extensions/Policy's PolicySecretCoreAsync opens before CreateBoundAsync for the same reason.
        try
        {
            //The bind authValue enters the session-key KDFa with its trailing zeros already removed (TPM 2.0
            //Library Part 1, Section 17.6.4.3, and CreateBoundAsync's own documented precondition): the TPM keys
            //eq. 20 (Part 1, clause 17.6.10) on the stripped form, so an owner authValue ending in zero octets would otherwise derive a
            //session key the TPM never agrees with.
            TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), StripTrailingZeros(ownerAuth), startInput.NonceCaller, started.NonceTPM,
                PinAuthSessionHash, pool, symmetric: symmetric, cancellationToken: cancellationToken).ConfigureAwait(false);

            return TpmResult<TpmSession>.Success(session);
        }
        catch
        {
            try
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                //Compensating cleanup only; see DefinePinFailIndexCoreAsync's identical bracket for the rationale.
            }

            throw;
        }
    }

    /// <summary>
    /// Removes trailing zero octets from an authorization value before it is used in an authorization
    /// computation (TPM 2.0 Library Part 1, Section 17.6.4.3: "Trailing octets of zero are to be removed from any
    /// string before it is used as an authValue"; Section 17.6.5 states the same for the authValue term of the
    /// HMAC key).
    /// </summary>
    /// <remarks>
    /// The candidate-PIN path gets this through <c>TpmSession.SetAuthValue</c>, which strips what it stores; the
    /// bind authValue reaches <c>TpmSession.CreateBoundAsync</c> as a plain parameter whose documented
    /// precondition is the stripped form, so this group strips it at the call site.
    /// </remarks>
    /// <param name="value">The authorization value to strip.</param>
    /// <returns>The value with any trailing zero octets removed.</returns>
    private static ReadOnlyMemory<byte> StripTrailingZeros(ReadOnlyMemory<byte> value)
    {
        ReadOnlySpan<byte> span = value.Span;
        int end = span.Length;
        while(end > 0 && span[end - 1] == 0)
        {
            end--;
        }

        return value[..end];
    }

    /// <summary>
    /// Issues an owner-authorized <c>TPM2_NV_Write</c> of the full 8-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c>
    /// blob over <paramref name="ownerSession"/> - the single shape shared by initial provisioning
    /// (<see cref="DefinePinFailIndexCoreAsync"/>) and later reset (<see cref="ResetPinCountCoreAsync"/>).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the <c>NV_Write</c> codec.</param>
    /// <param name="ownerSession">The already-composed owner-bound authorization session.</param>
    /// <param name="pinIndexHandle">The PIN Fail Index to write.</param>
    /// <param name="pinCount">The pinCount value to store.</param>
    /// <param name="pinLimit">The pinLimit value to store.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The write result.</returns>
    private static async ValueTask<TpmResult<NvWriteResponse>> WritePinCounterParametersAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmSessionBase ownerSession,
        uint pinIndexHandle,
        uint pinCount,
        uint pinLimit,
        CancellationToken cancellationToken)
    {
        TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(pinIndexHandle, cancellationToken).ConfigureAwait(false);
        if(!nameResult.IsSuccess)
        {
            return nameResult.Map<NvWriteResponse>(_ => null!);
        }

        using NvReadPublicResponse namePublic = nameResult.Value;
        ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, namePublic.NvName.Span.ToArray()];

        IMemoryOwner<byte> blobOwner = pool.Rent(PinCounterParametersSize);
        Tpm2bMaxNvBuffer data;
        try
        {
            Memory<byte> blob = blobOwner.Memory[..PinCounterParametersSize];
            BinaryPrimitives.WriteUInt32BigEndian(blob.Span, pinCount);
            BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

            //The rental is laid out in place and then adopted by the TPM2B_MAX_NV_BUFFER the command frames, so
            //the counter parameters cross into the input without a second copy; the carrier is the only owner
            //from there on.
            data = Tpm2bMaxNvBuffer.Adopt(blobOwner, PinCounterParametersSize);
        }
        catch
        {
            //This frame is the rental's only owner until the adoption returns, so a fault ahead of it releases
            //the rental here.
            blobOwner.Dispose();
            throw;
        }

        using(data)
        {
            var writeInput = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, pinIndexHandle, data, Offset: 0);

            return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                device, writeInput, [ownerSession], handleNames, pool, registry, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Parses the 8-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> window into its two big-endian <see cref="uint"/> fields.</summary>
    /// <param name="data">The octets a successful <c>TPM2_NV_Read</c> returned.</param>
    /// <returns>The parsed counter parameters.</returns>
    private static TpmPinCounterParameters ParsePinCounterParameters(ReadOnlySpan<byte> data) =>
        new(BinaryPrimitives.ReadUInt32BigEndian(data), BinaryPrimitives.ReadUInt32BigEndian(data[sizeof(uint)..]));
}

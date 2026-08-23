using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Hierarchy;

/// <summary>
/// Hierarchy and provisioning administration extensions for <see cref="TpmDevice"/>, composing the
/// <c>TPM2_HierarchyChangeAuth</c>/<c>TPM2_Clear</c>/<c>TPM2_ClearControl</c>/<c>TPM2_HierarchyControl</c>/
/// <c>TPM2_SetPrimaryPolicy</c> surface (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 3, Sections 24.8, 24.6, 24.7, 24.2 and 24.3).
/// </summary>
/// <remarks>
/// <para>
/// These are the TPM's ownership controls: who may authorize the storage, endorsement, platform and lockout
/// domains, whether each of those domains is usable at all, and whether the current owner's whole context can be
/// discarded. Every session these verbs need is built and disposed internally and every session handle is
/// flushed on every path, success or failure; a caller never hands in a pre-built session and never has a
/// session slot left behind by a cancelled call.
/// </para>
/// <para>
/// <b>Channel protection.</b> Every verb defaults to an HMAC session BOUND to the hierarchy it authorizes (Part
/// 1, Section 17.6.10, equation 20): the hierarchy's current authorization value feeds the session key's KDFa
/// derivation with its trailing zero octets already removed (Section 17.6.4.3), so a genuinely secret hierarchy
/// authorization value never crosses the bus and the command carries a structured cpHash/nonce-bound authHMAC a
/// password session cannot offer. Each default carries a <c>…WithPasswordAsync</c> opt-out with the identical
/// arguments and the plaintext-<c>TPM_RS_PW</c> composition, for provisioning over a trusted bus and for
/// diagnostics. As in <c>Extensions/Pin</c> and <c>Extensions/Policy</c>, that integrity is only as real as the
/// authorization value it is keyed on: while a hierarchy's authorization value is still the Empty Buffer - the
/// manufacture default for owner, endorsement, platform and lockout alike - the derived session key is
/// reproducible by anyone who observed the <c>TPM2_StartAuthSession</c> exchange, whose nonces cross the wire in
/// the clear. The mechanism becomes real protection the instant
/// <see cref="ChangeHierarchyAuthAsync(TpmRh, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/>
/// installs a real value, which is the first provisioning step these verbs exist to serve.
/// </para>
/// <para>
/// <b>Why the response-HMAC rule needs no key swap here.</b> Two of the five commands state that the response
/// HMAC is computed over the value the command just installed rather than the one that authorized it -
/// <c>TPM2_HierarchyChangeAuth</c> ("The HMAC in the response shall use the new authorization value when
/// computing the response HMAC", Part 3, Section 24.8.1) and <c>TPM2_Clear</c> ("If this command is authorized
/// using lockoutAuth, the HMAC in the response shall use the new lockoutAuth value (that is, the Empty Buffer)",
/// Part 3, Section 24.6.1). That rule bites only when the authorization value is a term of the HMAC key at all.
/// Under this group's bound default it is not: Part 1, Section 17.6.10's equations 21/22 drop the authValue term
/// whenever the session authorizing an entity is the session bound to that same entity, because binding already
/// folded the value into the session key, and the session key is fixed at <c>TPM2_StartAuthSession</c> and does
/// not move when the command rewrites the entity's authorization value. Both the command HMAC and the response
/// HMAC therefore key on the session key alone, and no post-submit key swap is composed - unlike
/// <c>Extensions/Pin</c>'s <c>ChangePinAsync</c>, whose authorizing session is a policy session that asserted
/// <c>TPM2_PolicyAuthValue</c> and so genuinely does carry the entity's value in its key on both legs. A caller
/// that composes its own UNBOUND HMAC session against these commands takes that swap back on: for an unbound
/// session the authValue term is present, the command leg keys on the pre-command value and the response leg on
/// the post-command one.
/// </para>
/// <para>
/// <b>Dictionary-attack asymmetry.</b> Owner, endorsement and platform authorization values are permanent-entity
/// values and are not dictionary-attack protected; <c>lockoutAuth</c> is the documented exception (Part 1,
/// Section 17.8.1), so every verb here that authorizes with <c>lockoutAuth</c> -
/// <see cref="ClearAsync"/> and the lockout arms of
/// <see cref="ClearControlAsync(TpmRh, ReadOnlyMemory{byte}, bool, CancellationToken)"/> and
/// <see cref="ChangeHierarchyAuthAsync(TpmRh, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/> -
/// gets exactly one strike: a wrong value disables further use of <c>lockoutAuth</c> until the configured
/// <c>lockoutRecovery</c> interval elapses, a <c>TPM2_Startup</c> runs, or <c>lockoutPolicy</c> is satisfied
/// (Part 1, Section 17.8.5), and a call made while that state is already engaged is refused with
/// <c>TPM_RC_LOCKOUT</c> before the value is compared. Platform-hierarchy authorizations are categorically
/// exempt from all of it (Part 3, Section 25.1), which is what makes the platform arms the recovery path when
/// the lockout arms have locked themselves out.
/// </para>
/// <para>
/// <b>Enables gate their own authorizations.</b> When a hierarchy's enable is CLEAR, neither its authorization
/// value nor its policy can authorize anything at all (Part 1, Section 11.2, Table 5) - so
/// <see cref="DisableHierarchyAsync"/> is the one verb here that can make the other four unusable for the
/// hierarchy it names, and re-enabling storage or endorsement afterwards is exclusively Platform Authorization's
/// privilege (<see cref="EnableHierarchyAsync"/>). The platform hierarchy's own enable is the sharpest case: it
/// can be CLEARed by this command surface and re-SET by nothing in it, only by a platform reset.
/// </para>
/// <para>
/// <b>Provisioning-time verbs.</b> <see cref="ClearAsync"/> is destructive to an extent no other verb in this
/// library approaches - it discards the storage primary seed and, with it, every key ever derived under the
/// storage and endorsement hierarchies - and <c>TPM2_Clear</c> takes no confirmation parameter of any kind
/// (Part 3, Section 24.6.2), so any "are you sure" gate belongs entirely above this boundary. Read that verb's
/// own remarks before composing it.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class TpmDeviceExtensions
{
    /// <summary>
    /// The hash algorithm for every session this group composes internally: the hierarchy-bound authorization
    /// sessions every verb defaults to, and the decrypt companion
    /// <see cref="ChangeHierarchyAuthAsync(TpmRh, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/>
    /// carries its replacement value over.
    /// </summary>
    private const TpmAlgIdConstants HierarchyAuthSessionHash = TpmAlgIdConstants.TPM_ALG_SHA256;

    extension(TpmDevice device)
    {
        /// <summary>
        /// Replaces <paramref name="hierarchyHandle"/>'s own authorization value with
        /// <paramref name="newAuth"/>, composing <c>TPM2_HierarchyChangeAuth</c> over an HMAC session bound to
        /// that same hierarchy and a separate decrypt companion that carries the replacement value.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>The current value authorizes the change.</b> The command authorizes at USER role with the
        /// authorization value it is about to replace (TPM 2.0 Library Part 3, Section 24.8.1), which
        /// <paramref name="currentAuth"/> supplies: it feeds the bound session's KDFa key derivation rather than
        /// crossing the bus, so a wrong value is an HMAC mismatch rather than a plaintext compare. Every
        /// hierarchy starts life with the Empty Buffer as its authorization value, so the first rotation of a
        /// factory-state hierarchy passes an empty <paramref name="currentAuth"/> - and, as this group's own
        /// remarks state, that first exchange's integrity is therefore only structural. Rotating over a bus a
        /// passive adversary may capture is what the salted overload exists for.
        /// </para>
        /// <para>
        /// <b>The replacement value is a command parameter, and rides its own session.</b>
        /// <paramref name="newAuth"/> is <c>newAuth</c>, the command's sole and therefore first sized parameter,
        /// which Part 1, Section 19.1 makes eligible for session-based parameter encryption. It is carried by a
        /// SECOND session that holds the decrypt attribute and authorizes nothing, never by the authorizing one:
        /// a session that both authorizes an entity and encrypts folds that entity's authorization value into
        /// its <c>sessionValue</c> (Section 19.1's note), which would key the encryption of the NEW value on the
        /// OLD one. That companion is itself bound to <paramref name="hierarchyHandle"/>, so its session key -
        /// and therefore the keystream protecting <paramref name="newAuth"/> - is derived from
        /// <paramref name="currentAuth"/> and is genuinely secret against a bus observer whenever the hierarchy
        /// already carries a real authorization value. Where it does not, the keystream reduces to a function of
        /// the public <c>TPM2_StartAuthSession</c> nonces and the encryption is structural only; the salted
        /// overload closes that case.
        /// </para>
        /// <para>
        /// <b>The value the TPM stores is the stripped value.</b> The TPM removes trailing zero octets from
        /// <paramref name="newAuth"/> and then refuses anything still longer than the digest produced by the
        /// hash algorithm used for context integrity with <c>TPM_RC_SIZE</c> (Part 1, Section 17.6.4.2: a
        /// hierarchy has no Name algorithm to bound its authorization value, so the context-integrity hash is
        /// what bounds it, and Section 24.8.1's own worked example - "If SHA384 is used ... then the largest
        /// authorization value is 48 octets"). Hashing an over-long secret down to that size first is a
        /// caller-side convention the TPM does not perform (Section 17.6.4.3: "The TPM does not enforce this
        /// transformation"). An empty <paramref name="newAuth"/> is legitimate and returns the hierarchy to its
        /// factory-state authorization value; it does not disable authorization, since the Empty Buffer is a
        /// knowable, usable authorization value (Part 1, Section 11.2, Table 5) - making a hierarchy's value
        /// genuinely unusable means installing a large random value and discarding it.
        /// </para>
        /// <para>
        /// <b>What this does not rotate.</b> Only the authorization value moves. The hierarchy's policy
        /// (<see cref="SetPrimaryPolicyAsync"/>), its enable, its primary seed, and every key already derived
        /// under it are untouched, so no key is invalidated and no attestation needs re-issuing - the offline
        /// caveat is that anyone who captured a prior transcript can still test guesses at the OLD value
        /// offline, and a rotation does not retract what that value already authorized.
        /// </para>
        /// <para>
        /// <b>The lockout arm costs a strike.</b> With <paramref name="hierarchyHandle"/> of
        /// <see cref="TpmRh.TPM_RH_LOCKOUT"/> a wrong <paramref name="currentAuth"/> engages the special
        /// lockoutAuth-failure state described in this group's own remarks, so a mistyped current value costs
        /// the whole lockout administration path until it recovers. A disabled hierarchy refuses the change
        /// outright with <c>TPM_RC_HIERARCHY</c>, since a CLEAR enable bars both the authorization value and the
        /// policy from authorizing anything (Part 1, Section 11.2).
        /// </para>
        /// </remarks>
        /// <param name="hierarchyHandle">
        /// The hierarchy whose authorization value is replaced: <see cref="TpmRh.TPM_RH_OWNER"/>,
        /// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/>, <see cref="TpmRh.TPM_RH_PLATFORM"/> or
        /// <see cref="TpmRh.TPM_RH_LOCKOUT"/>.
        /// </param>
        /// <param name="currentAuth">The hierarchy's current authorization value; proven by HMAC, not sent.</param>
        /// <param name="newAuth">The replacement authorization value; sent under the decrypt companion.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<HierarchyChangeAuthResponse>> ChangeHierarchyAuthAsync(
            TpmRh hierarchyHandle,
            ReadOnlyMemory<byte> currentAuth,
            ReadOnlyMemory<byte> newAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ChangeHierarchyAuthCoreAsync(device, hierarchyHandle, currentAuth, newAuth, cancellationToken);
        }

        /// <summary>
        /// Replaces <paramref name="hierarchyHandle"/>'s own authorization value over a fully salted
        /// composition: both the session that AUTHORIZES the change and the companion that ENCRYPTS
        /// <paramref name="newAuth"/> draw their session keys from <paramref name="tpmKey"/>, so a captured
        /// transcript yields neither the replacement value nor a way to test a guess at the current one.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Identical in every authorization respect to
        /// <see cref="ChangeHierarchyAuthAsync(TpmRh, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/>
        /// - the same bound sessions, the same USER-role authorization, the same size rule and the same lockout
        /// strike. What changes is the channel, on BOTH sessions. Each is bound AND salted
        /// (<see cref="Infrastructure.Commands.StartAuthSessionInputExtensions.CreateBoundAndSaltedHmacSession(uint, uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/>),
        /// and each draws its OWN salt: two independent secrets, never one reused across the pair. Every salt is
        /// RSA-OAEP-encrypted (TPM 2.0 Library Part 1, Annex B.10.2) to
        /// <paramref name="tpmKeyModulus"/>/<paramref name="tpmKeyExponent"/>, so only the TPM holding
        /// <paramref name="tpmKey"/>'s matching private key can recover it, and each recovered salt keys its own
        /// session's derived session key (Part 1, Section 17.6.12, equation 25).
        /// </para>
        /// <para>
        /// <b>What each salt buys.</b> The authorizing session's key is otherwise a KDFa over
        /// <paramref name="currentAuth"/> and two public nonces, so a captured transcript plus a candidate value
        /// reproduces it - salting adds a term no observer can reconstruct, which is what removes the offline
        /// guessing surface the unsalted default leaves against the current value. The companion's salt makes
        /// the keystream over <paramref name="newAuth"/> secret even when the hierarchy's current authorization
        /// value is still the Empty Buffer, which is exactly the first-provisioning case where the unsalted
        /// default's encryption is structural only. Use this overload whenever the bus is one a passive
        /// adversary might capture and a suitable loaded decrypt key (for example the Endorsement Key) is
        /// available.
        /// </para>
        /// </remarks>
        /// <param name="hierarchyHandle">The hierarchy whose authorization value is replaced.</param>
        /// <param name="currentAuth">The hierarchy's current authorization value; proven by HMAC, not sent.</param>
        /// <param name="newAuth">The replacement authorization value; sent under the salted decrypt companion.</param>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - each salt is encrypted to its public modulus.</param>
        /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes each drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
        /// <param name="encryptSalt">Encrypts each drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP - an explicit per-call delegate, no closure capture.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<HierarchyChangeAuthResponse>> ChangeHierarchyAuthAsync(
            TpmRh hierarchyHandle,
            ReadOnlyMemory<byte> currentAuth,
            ReadOnlyMemory<byte> newAuth,
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyModulus,
            uint tpmKeyExponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmRsaOaepEncryptDelegate encryptSalt,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ChangeHierarchyAuthSaltedCoreAsync(
                device, hierarchyHandle, currentAuth, newAuth, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for
        /// <see cref="ChangeHierarchyAuthAsync(TpmRh, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, CancellationToken)"/>:
        /// authorizes with a plaintext <c>TPM_RS_PW</c> session and sends <paramref name="newAuth"/> unencrypted.
        /// </summary>
        /// <remarks>
        /// Both authorization values cross the bus in the clear and the command carries no cpHash/rpHash
        /// integrity at all, so a bus observer learns the replacement value outright - the opposite of what a
        /// rotation is for. It exists for provisioning over a bus already trusted end to end and for diagnostics
        /// against a factory-state hierarchy whose authorization value is the Empty Buffer anyway.
        /// </remarks>
        /// <param name="hierarchyHandle">The hierarchy whose authorization value is replaced.</param>
        /// <param name="currentAuth">The hierarchy's current authorization value, sent in the clear.</param>
        /// <param name="newAuth">The replacement authorization value, sent in the clear.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<HierarchyChangeAuthResponse>> ChangeHierarchyAuthWithPasswordAsync(
            TpmRh hierarchyHandle,
            ReadOnlyMemory<byte> currentAuth,
            ReadOnlyMemory<byte> newAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ChangeHierarchyAuthWithPasswordCoreAsync(device, hierarchyHandle, currentAuth, newAuth, cancellationToken);
        }

        /// <summary>
        /// Discards the current owner's entire TPM context, composing <c>TPM2_Clear</c> under Lockout
        /// Authorization over an HMAC session bound to the lockout entity.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>Blast radius.</b> TPM 2.0 Library Part 3, Section 24.6.1 states the effect list, and every item on
        /// it is unconditional and irreversible:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>Every resident object in the storage and endorsement hierarchies is flushed -
        ///   transient and persistent alike, so anything made permanent with <c>TPM2_EvictControl</c> under
        ///   those two hierarchies is gone. Platform-hierarchy objects are not touched.</description></item>
        ///   <item><description>Every NV Index whose <c>TPMA_NV_PLATFORMCREATE</c> attribute is CLEAR - that is,
        ///   every Index defined under Owner Authorization, including every PIN Fail Index
        ///   <c>Extensions/Pin</c> defines and every monotonic counter - is deleted outright, data area and
        ///   all.</description></item>
        ///   <item><description>The storage primary seed is replaced from the TPM's random number generator, and
        ///   <c>shProof</c> and <c>ehProof</c> change with it. Nothing walks a list of outstanding tickets or
        ///   saved contexts: because a ticket is an HMAC keyed on the hierarchy proof (Part 1, Section 12.5), a
        ///   proof rotation silently stops every owner-hierarchy and endorsement-hierarchy ticket and saved
        ///   context from verifying, and a <c>TPM2_PolicyTicket</c> replay of one minted before the clear simply
        ///   no longer authorizes. The platform proof survives, so platform-hierarchy tickets do
        ///   too.</description></item>
        ///   <item><description><c>shEnable</c> and <c>ehEnable</c> are SET, so a storage or endorsement
        ///   hierarchy disabled by <see cref="DisableHierarchyAsync"/> comes back enabled.</description></item>
        ///   <item><description><c>ownerAuth</c>, <c>endorsementAuth</c> and <c>lockoutAuth</c> are all set to
        ///   the Empty Buffer, and <c>ownerPolicy</c>, <c>endorsementPolicy</c> and <c>lockoutPolicy</c> with
        ///   them - so every policy installed by <see cref="SetPrimaryPolicyAsync"/> on those three is gone and,
        ///   an empty policy matching no policy digest (Part 1, Section 11.2, Table 5), policy-session
        ///   authorization against them is disabled again. <c>platformAuth</c> and <c>platformPolicy</c> are NOT
        ///   touched.</description></item>
        ///   <item><description>The dictionary-attack failure counter is reset to zero (Part 1, Section 17.8.2:
        ///   "TPM2_Clear() will reset this counter to zero").</description></item>
        ///   <item><description><c>Clock</c>, <c>resetCount</c> and <c>restartCount</c> go to zero and
        ///   <c>Safe</c> to YES, so every clock-bound policy assertion measures against a restarted
        ///   epoch.</description></item>
        ///   <item><description><c>pcrUpdateCounter</c> is incremented, which invalidates any policy session
        ///   that folded <c>TPM2_PolicyPCR</c> - even one with an empty PCR selection, which is the documented
        ///   way to build a session that a clear is guaranteed to kill.</description></item>
        /// </list>
        /// <para>
        /// The platform primary seed, the platform hierarchy's objects, <c>platformAuth</c>,
        /// <c>platformPolicy</c> and <c>disableClear</c> itself all survive.
        /// </para>
        /// <para>
        /// <b>There is no confirmation on the wire.</b> <c>TPM2_Clear</c> takes no parameters at all (Part 3,
        /// Section 24.6.2) - the authorization handle is the entire command - so nothing below this boundary can
        /// distinguish a deliberate clear from an accidental one. Any confirmation gate belongs above it.
        /// </para>
        /// <para>
        /// <b>One strike, and it is the lockout strike.</b> This verb ships the lockout arm: a wrong
        /// <paramref name="lockoutAuth"/> engages the special lockoutAuth-failure state (Part 1, Section
        /// 17.8.5), and a call made while the TPM is already in Lockout mode is refused with
        /// <c>TPM_RC_LOCKOUT</c> before the value is compared - <c>TPM2_DictionaryAttackLockReset</c> is the one
        /// lockoutAuth-authorized command carved out of that gate, and this is not it. The wire also admits
        /// Platform Authorization for the same command (Part 3, Section 24.6.2), which is never
        /// dictionary-attack gated (Part 3, Section 25.1) and is the recovery path when the lockout arm has
        /// locked itself out; this verb does not compose it.
        /// </para>
        /// <para>
        /// <b>It can be disabled outright.</b> If <c>TPMA_PERMANENT.disableClear</c> is SET - by anyone holding
        /// either authorization, through <see cref="ClearControlAsync(TpmRh, ReadOnlyMemory{byte}, bool, CancellationToken)"/>
        /// - this command is refused with <c>TPM_RC_DISABLED</c>, and only Platform Authorization can CLEAR that
        /// control again (Part 3, Section 24.7.1).
        /// </para>
        /// <para>
        /// <b>Response HMAC.</b> Section 24.6.1's closing sentence keys the response HMAC on the new
        /// <c>lockoutAuth</c> - the Empty Buffer - when the command was authorized with <c>lockoutAuth</c>. As
        /// this group's own remarks explain, that rule is vacuous under the bound session composed here: the
        /// authorization value is not a term of either HMAC key to begin with.
        /// </para>
        /// </remarks>
        /// <param name="lockoutAuth">The lockout entity's current authorization value; proven by HMAC, not sent.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<ClearResponse>> ClearAsync(
            ReadOnlyMemory<byte> lockoutAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ClearCoreAsync(device, lockoutAuth, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for <see cref="ClearAsync"/>: authorizes the clear with a
        /// plaintext <c>TPM_RS_PW</c> session carrying <paramref name="lockoutAuth"/>.
        /// </summary>
        /// <remarks>
        /// The full blast radius <see cref="ClearAsync"/> documents applies unchanged; only the channel differs.
        /// <paramref name="lockoutAuth"/> crosses the bus in the clear and the command carries no HMAC
        /// integrity, so a bus observer both learns the lockout value and sees an unauthenticated command frame
        /// - for the single most destructive command in this library. Compose it only over a bus trusted end to
        /// end, or against a factory-state TPM whose lockout value is the Empty Buffer.
        /// </remarks>
        /// <param name="lockoutAuth">The lockout entity's current authorization value, sent in the clear.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<ClearResponse>> ClearWithPasswordAsync(
            ReadOnlyMemory<byte> lockoutAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ClearWithPasswordCoreAsync(device, lockoutAuth, cancellationToken);
        }

        /// <summary>
        /// Sets or clears <c>TPMA_PERMANENT.disableClear</c>, the persistent control that decides whether
        /// <see cref="ClearAsync"/> may execute at all, composing <c>TPM2_ClearControl</c> over an HMAC session
        /// bound to <paramref name="authHandle"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>The two authorizations are not symmetric.</b> TPM 2.0 Library Part 3, Section 24.7.1: "Lockout
        /// Authorization may be used to SET disableClear but not to CLEAR it. Platform Authorization may be used
        /// to SET or CLEAR disableClear." Lockout Authorization is therefore a one-way ratchet toward the more
        /// locked state - it can take <c>TPM2_Clear</c> away and cannot give it back - while Platform
        /// Authorization holds both directions, which is what lets platform firmware re-enable a clear when it
        /// needs one. An attempt to CLEAR the control under <see cref="TpmRh.TPM_RH_LOCKOUT"/> is refused with
        /// <c>TPM_RC_AUTH_FAIL</c>: the same code an ordinary authorization failure carries, even though nothing
        /// about the supplied value was wrong, and deliberately not the <c>TPM_RC_AUTH_TYPE</c> that
        /// <see cref="EnableHierarchyAsync"/>'s wrong-authorization case answers. The wire cannot express the
        /// asymmetry - both directions share one handle at one authorization role - so it is enforced as an
        /// explicit rule inside the command rather than by the authorization model.
        /// </para>
        /// <para>
        /// <b>What SET actually disables.</b> Only <c>TPM2_Clear</c>. Nothing else in this group is gated on
        /// <c>disableClear</c>, and the control survives every <c>TPM2_Startup</c> form - it is a manufacture-time
        /// value that persists until this command changes it, and <see cref="ClearAsync"/> itself does not reset
        /// it either.
        /// </para>
        /// <para>
        /// The parameter's own spec-printed description still calls the flag <c>disableOwnerClear</c>, a
        /// remnant name distinct from the <c>disable</c> wire field and from the <c>TPMA_PERMANENT.disableClear</c>
        /// attribute it sets; the wire type preserves that verbatim rather than normalizing it.
        /// </para>
        /// </remarks>
        /// <param name="authHandle">
        /// <see cref="TpmRh.TPM_RH_LOCKOUT"/> or <see cref="TpmRh.TPM_RH_PLATFORM"/>; lockout may only SET.
        /// </param>
        /// <param name="authValue"><paramref name="authHandle"/>'s current authorization value; proven by HMAC, not sent.</param>
        /// <param name="isDisablingClear"><see langword="true"/> to SET <c>disableClear</c> and bar <see cref="ClearAsync"/>, <see langword="false"/> to CLEAR it and permit the command again.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<ClearControlResponse>> ClearControlAsync(
            TpmRh authHandle,
            ReadOnlyMemory<byte> authValue,
            bool isDisablingClear,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ClearControlCoreAsync(device, authHandle, authValue, isDisablingClear, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for
        /// <see cref="ClearControlAsync(TpmRh, ReadOnlyMemory{byte}, bool, CancellationToken)"/>: authorizes with
        /// a plaintext <c>TPM_RS_PW</c> session carrying <paramref name="authValue"/>.
        /// </summary>
        /// <remarks>
        /// The authorization asymmetry the sessioned verb documents is a property of the command, not of the
        /// channel, so it applies here unchanged; only the integrity protection differs.
        /// </remarks>
        /// <param name="authHandle"><see cref="TpmRh.TPM_RH_LOCKOUT"/> or <see cref="TpmRh.TPM_RH_PLATFORM"/>.</param>
        /// <param name="authValue"><paramref name="authHandle"/>'s current authorization value, sent in the clear.</param>
        /// <param name="isDisablingClear"><see langword="true"/> to SET <c>disableClear</c>, <see langword="false"/> to CLEAR it.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<ClearControlResponse>> ClearControlWithPasswordAsync(
            TpmRh authHandle,
            ReadOnlyMemory<byte> authValue,
            bool isDisablingClear,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ClearControlWithPasswordCoreAsync(device, authHandle, authValue, isDisablingClear, cancellationToken);
        }

        /// <summary>
        /// CLEARs the enable that gates <paramref name="hierarchy"/>, composing <c>TPM2_HierarchyControl</c>
        /// over an HMAC session bound to <paramref name="authHandle"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>Why disabling and enabling are separate verbs.</b> They do not take the same authorizations. A
        /// hierarchy may be disabled by its own authorization OR by Platform Authorization, but re-enabled by
        /// Platform Authorization alone (TPM 2.0 Library Part 1, Sections 11.4 and 11.5), and the platform's own
        /// enable cannot be re-SET by this command at any authorization. One verb taking a direction flag would
        /// silently change which authorization the caller must hold depending on the flag's value, which is
        /// precisely the mistake this split makes impossible: <see cref="EnableHierarchyAsync"/> takes the
        /// platform value and nothing else, and this verb takes a choice that is genuinely open.
        /// </para>
        /// <para>
        /// <b>Which authorizations are open.</b> <see cref="TpmRh.TPM_RH_OWNER"/>'s enable may be CLEARed by
        /// owner or platform; <see cref="TpmRh.TPM_RH_ENDORSEMENT"/>'s by endorsement or platform;
        /// <see cref="TpmRh.TPM_RH_PLATFORM"/>'s and <see cref="TpmRh.TPM_RH_PLATFORM_NV"/>'s by platform only,
        /// with no fallback (Part 3, Section 24.2.1). Any other pairing is refused with
        /// <c>TPM_RC_AUTH_TYPE</c> - the authorization was supplied correctly but is not applicable to the
        /// hierarchy in its current state.
        /// </para>
        /// <para>
        /// <b>What CLEARing an enable does.</b> Neither the authorization value nor the policy of a disabled
        /// hierarchy can authorize anything while the enable stays CLEAR (Part 1, Section 11.2, Table 5), so a
        /// disabled hierarchy also loses the ability to re-enable itself. The TPM additionally disables use of
        /// every persistent entity associated with that hierarchy and flushes its transient objects; CLEARing
        /// <see cref="TpmRh.TPM_RH_OWNER"/> also bars access to every NV Index with
        /// <c>TPMA_NV_PLATFORMCREATE</c> CLEAR, and CLEARing <see cref="TpmRh.TPM_RH_PLATFORM_NV"/> bars every
        /// Index with it SET (Section 24.2.1). None of that is destructive: the objects, Indexes and seeds
        /// survive and become usable again when the enable comes back.
        /// </para>
        /// <para>
        /// <b>The platform enable is a one-way door.</b> <c>phEnable</c> may be CLEARed here and can be re-SET
        /// by nothing in this command surface - only <c>_TPM_Init</c> and the <c>TPM2_Startup</c> that follows
        /// it SET it again (Part 1, Section 11.3), and every <c>TPM2_Startup</c> form does so unconditionally.
        /// Disabling the platform hierarchy therefore hands control of the platform domain to whoever controls
        /// the next platform reset. <c>shEnable</c> and <c>ehEnable</c> also come back on a TPM Reset or TPM
        /// Restart, and on <see cref="ClearAsync"/>; a TPM Resume preserves whatever this verb last set.
        /// </para>
        /// </remarks>
        /// <param name="authHandle">
        /// The authorizing hierarchy: <paramref name="hierarchy"/>'s own handle, or
        /// <see cref="TpmRh.TPM_RH_PLATFORM"/>.
        /// </param>
        /// <param name="authValue"><paramref name="authHandle"/>'s current authorization value; proven by HMAC, not sent.</param>
        /// <param name="hierarchy">
        /// The enable being CLEARed: <see cref="TpmRh.TPM_RH_OWNER"/> (<c>shEnable</c>),
        /// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> (<c>ehEnable</c>), <see cref="TpmRh.TPM_RH_PLATFORM"/>
        /// (<c>phEnable</c>) or <see cref="TpmRh.TPM_RH_PLATFORM_NV"/> (<c>phEnableNV</c>).
        /// </param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<HierarchyControlResponse>> DisableHierarchyAsync(
            TpmRh authHandle,
            ReadOnlyMemory<byte> authValue,
            TpmRh hierarchy,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return HierarchyControlCoreAsync(device, authHandle, authValue, hierarchy, TpmiYesNo.No, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for <see cref="DisableHierarchyAsync"/>: authorizes with a
        /// plaintext <c>TPM_RS_PW</c> session carrying <paramref name="authValue"/>.
        /// </summary>
        /// <remarks>
        /// The authorization rules and the effects <see cref="DisableHierarchyAsync"/> documents are properties
        /// of the command and apply here unchanged; only the integrity protection differs.
        /// </remarks>
        /// <param name="authHandle">The authorizing hierarchy.</param>
        /// <param name="authValue"><paramref name="authHandle"/>'s current authorization value, sent in the clear.</param>
        /// <param name="hierarchy">The enable being CLEARed.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<HierarchyControlResponse>> DisableHierarchyWithPasswordAsync(
            TpmRh authHandle,
            ReadOnlyMemory<byte> authValue,
            TpmRh hierarchy,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return HierarchyControlWithPasswordCoreAsync(device, authHandle, authValue, hierarchy, TpmiYesNo.No, cancellationToken);
        }

        /// <summary>
        /// SETs the enable that gates <paramref name="hierarchy"/> under Platform Authorization, composing
        /// <c>TPM2_HierarchyControl</c> over an HMAC session bound to the platform hierarchy.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>There is no authorization handle to choose.</b> SETting <c>shEnable</c> or <c>ehEnable</c>
        /// requires Platform Authorization specifically, even though CLEARing either is open to the hierarchy's
        /// own authorization as well (TPM 2.0 Library Part 1, Sections 11.4 and 11.5) - a disabled hierarchy
        /// cannot authorize anything at all, including its own re-enablement (Section 11.2, Table 5), so the
        /// platform is the only party that can bring one back. This verb therefore takes
        /// <paramref name="platformAuth"/> and no handle: the only value that could be passed is the one it
        /// takes. An attempt made with any other authorization is refused with <c>TPM_RC_AUTH_TYPE</c>.
        /// </para>
        /// <para>
        /// <b>The platform enable cannot be SET here at all.</b> Passing
        /// <see cref="TpmRh.TPM_RH_PLATFORM"/> as <paramref name="hierarchy"/> is refused: <c>phEnable</c> is
        /// SET only by <c>_TPM_Init</c> and the <c>TPM2_Startup</c> that follows (Part 3, Section 24.2.1:
        /// "phEnable may not be SET using this command"), so recovering a disabled platform hierarchy is a
        /// platform reset, never a command. <see cref="TpmRh.TPM_RH_PLATFORM_NV"/> is likewise documented only
        /// on the CLEAR path.
        /// </para>
        /// <para>
        /// Re-enabling restores use of the hierarchy's authorization value, its policy, its persistent entities
        /// and - for <see cref="TpmRh.TPM_RH_OWNER"/> - its owner-created NV Indexes; nothing was destroyed
        /// while the enable was CLEAR, so nothing needs recreating.
        /// </para>
        /// </remarks>
        /// <param name="platformAuth">The platform hierarchy's current authorization value; proven by HMAC, not sent.</param>
        /// <param name="hierarchy">
        /// The enable being SET: <see cref="TpmRh.TPM_RH_OWNER"/> (<c>shEnable</c>) or
        /// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> (<c>ehEnable</c>).
        /// </param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<HierarchyControlResponse>> EnableHierarchyAsync(
            ReadOnlyMemory<byte> platformAuth,
            TpmRh hierarchy,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return HierarchyControlCoreAsync(device, TpmRh.TPM_RH_PLATFORM, platformAuth, hierarchy, TpmiYesNo.Yes, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for <see cref="EnableHierarchyAsync"/>: authorizes with a
        /// plaintext <c>TPM_RS_PW</c> session carrying <paramref name="platformAuth"/>.
        /// </summary>
        /// <remarks>
        /// The platform-only authorization rule and the phEnable exclusion <see cref="EnableHierarchyAsync"/>
        /// documents are properties of the command and apply here unchanged; only the integrity protection
        /// differs.
        /// </remarks>
        /// <param name="platformAuth">The platform hierarchy's current authorization value, sent in the clear.</param>
        /// <param name="hierarchy">The enable being SET.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<HierarchyControlResponse>> EnableHierarchyWithPasswordAsync(
            ReadOnlyMemory<byte> platformAuth,
            TpmRh hierarchy,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return HierarchyControlWithPasswordCoreAsync(device, TpmRh.TPM_RH_PLATFORM, platformAuth, hierarchy, TpmiYesNo.Yes, cancellationToken);
        }

        /// <summary>
        /// Installs <paramref name="policyDigest"/> as <paramref name="authHandle"/>'s authorization policy,
        /// composing <c>TPM2_SetPrimaryPolicy</c> over an HMAC session bound to that same hierarchy.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>This is what makes policy authorization of a hierarchy possible at all.</b> A hierarchy has two
        /// authorization paths - its authorization value and its policy - and the policy path starts out
        /// disabled: an empty policy digest cannot match any policy session's digest, so "the use of authPolicy
        /// is disabled" (TPM 2.0 Library Part 1, Section 11.2, Table 5). Until this command installs a real
        /// digest, a policy session presented as the authorizer for a hierarchy is answered with
        /// <c>TPM_RC_AUTH_UNAVAILABLE</c> rather than evaluated - which is exactly what
        /// <c>Extensions/Policy</c>'s <c>PolicySecretAsync</c> meets when it names a policy-less hierarchy as
        /// its secret-holding entity. Installing a digest here reverses that: a policy session whose digest
        /// reaches the installed value authorizes the hierarchy anywhere the hierarchy's own authorization value
        /// would have, and <c>TPM2_PolicySecret</c> against it starts succeeding on the policy path.
        /// </para>
        /// <para>
        /// <b>Installing the Empty Buffer disables the policy path again.</b> Passing an empty
        /// <paramref name="policyDigest"/> with <see cref="TpmAlgIdConstants.TPM_ALG_NULL"/> as
        /// <paramref name="hashAlg"/> is the documented way back to the factory state, and it is the state
        /// <see cref="ClearAsync"/> restores for owner, endorsement and lockout. That is a genuine
        /// authorization-surface change, not a formality: a hierarchy whose authorization value was deliberately
        /// made unknown and whose policy is then emptied can no longer be authorized by anything.
        /// </para>
        /// <para>
        /// <b>The two parameters must agree.</b> <paramref name="hashAlg"/> must be
        /// <see cref="TpmAlgIdConstants.TPM_ALG_NULL"/> if and only if <paramref name="policyDigest"/> is the
        /// Empty Buffer; where <paramref name="hashAlg"/> names a real algorithm,
        /// <paramref name="policyDigest"/>'s size must be that algorithm's digest size or the TPM answers
        /// <c>TPM_RC_SIZE</c> (Part 3, Section 24.3.1). A disabled hierarchy refuses the command with
        /// <c>TPM_RC_HIERARCHY</c>, since a CLEAR enable bars both the authorization value and the policy from
        /// authorizing the change.
        /// </para>
        /// <para>
        /// This command's handle type is the only one in this group that also admits an Authenticated Countdown
        /// Timer as its target; this library models no ACT, so <paramref name="authHandle"/> is restricted to
        /// the three hierarchy handles and the lockout handle.
        /// </para>
        /// </remarks>
        /// <param name="authHandle">
        /// The entity whose policy is installed: <see cref="TpmRh.TPM_RH_OWNER"/>,
        /// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/>, <see cref="TpmRh.TPM_RH_PLATFORM"/> or
        /// <see cref="TpmRh.TPM_RH_LOCKOUT"/>.
        /// </param>
        /// <param name="hierarchyAuth"><paramref name="authHandle"/>'s current authorization value; proven by HMAC, not sent.</param>
        /// <param name="policyDigest">The policy digest to install, or the Empty Buffer to disable policy authorization.</param>
        /// <param name="hashAlg">The hash algorithm <paramref name="policyDigest"/> was computed with, or <see cref="TpmAlgIdConstants.TPM_ALG_NULL"/> for the Empty Buffer.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<SetPrimaryPolicyResponse>> SetPrimaryPolicyAsync(
            TpmRh authHandle,
            ReadOnlyMemory<byte> hierarchyAuth,
            ReadOnlyMemory<byte> policyDigest,
            TpmAlgIdConstants hashAlg,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return SetPrimaryPolicyCoreAsync(device, authHandle, hierarchyAuth, policyDigest, hashAlg, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for <see cref="SetPrimaryPolicyAsync"/>: authorizes with a
        /// plaintext <c>TPM_RS_PW</c> session carrying <paramref name="hierarchyAuth"/>.
        /// </summary>
        /// <remarks>
        /// The policy digest itself is public material - it is a digest of a policy, not a secret - so the
        /// exposure this opt-out adds is the authorization value and the missing command integrity, not the
        /// installed policy. The parameter rules <see cref="SetPrimaryPolicyAsync"/> documents apply unchanged.
        /// </remarks>
        /// <param name="authHandle">The entity whose policy is installed.</param>
        /// <param name="hierarchyAuth"><paramref name="authHandle"/>'s current authorization value, sent in the clear.</param>
        /// <param name="policyDigest">The policy digest to install, or the Empty Buffer to disable policy authorization.</param>
        /// <param name="hashAlg">The hash algorithm <paramref name="policyDigest"/> was computed with, or <see cref="TpmAlgIdConstants.TPM_ALG_NULL"/> for the Empty Buffer.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success, or the failing command's error.</returns>
        public ValueTask<TpmResult<SetPrimaryPolicyResponse>> SetPrimaryPolicyWithPasswordAsync(
            TpmRh authHandle,
            ReadOnlyMemory<byte> hierarchyAuth,
            ReadOnlyMemory<byte> policyDigest,
            TpmAlgIdConstants hashAlg,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return SetPrimaryPolicyWithPasswordCoreAsync(device, authHandle, hierarchyAuth, policyDigest, hashAlg, cancellationToken);
        }
    }

    /// <summary>
    /// The unsalted composition core for <c>ChangeHierarchyAuthAsync</c>: opens the hierarchy-bound authorizing
    /// session, opens a second hierarchy-bound session to carry the replacement value under the decrypt
    /// attribute, and rotates - flushing both sessions on every path.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="hierarchyHandle">The hierarchy whose authorization value is replaced.</param>
    /// <param name="currentAuth">The hierarchy's current authorization value.</param>
    /// <param name="newAuth">The replacement authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The rotation's result, or the first failing command's error.</returns>
    private static async ValueTask<TpmResult<HierarchyChangeAuthResponse>> ChangeHierarchyAuthCoreAsync(
        TpmDevice device,
        TpmRh hierarchyHandle,
        ReadOnlyMemory<byte> currentAuth,
        ReadOnlyMemory<byte> newAuth,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        TpmResult<TpmSession> authResult = await StartHierarchyBoundSessionAsync(
            device, pool, registry, hierarchyHandle, currentAuth, cancellationToken).ConfigureAwait(false);

        if(!authResult.IsSuccess)
        {
            return authResult.Map<HierarchyChangeAuthResponse>(_ => null!);
        }

        using TpmSession authSession = authResult.Value;
        uint authSessionHandle = authSession.SessionHandle.Value;

        //Every path below - including a failure inside the companion's own composition - must still release the
        //session slot the TPM allocated above. The flush runs under CancellationToken.None because the caller's
        //token is exactly what may have aborted the exchange (a cancelled call must not also leak the session it
        //opened), and its own outcome is caught and discarded so it can never replace the primary result the try
        //block produced, whether that is a success, a TpmResult error, or an exception.
        try
        {
            //A SECOND session carries the decrypt attribute: the authorizing session may not, because a session
            //used both to authorize an entity and to encrypt folds that entity's authorization value into its
            //sessionValue (TPM 2.0 Library Part 1, Section 19.1's note), keying the encryption of the NEW value
            //on the OLD one. This companion authorizes nothing, so its sessionValue is its session key alone -
            //and binding it to the same hierarchy makes that key a KDFa over currentAuth, so the keystream is
            //secret whenever the hierarchy already carries a real authorization value.
            TpmResult<TpmSession> decryptResult = await StartHierarchyBoundSessionAsync(
                device, pool, registry, hierarchyHandle, currentAuth, cancellationToken, TpmtSymDef.Xor(HierarchyAuthSessionHash)).ConfigureAwait(false);

            if(!decryptResult.IsSuccess)
            {
                return decryptResult.Map<HierarchyChangeAuthResponse>(_ => null!);
            }

            using TpmSession decryptSession = decryptResult.Value;
            uint decryptSessionHandle = decryptSession.SessionHandle.Value;

            try
            {
                return await ChangeHierarchyAuthOverSessionsAsync(
                    device, pool, registry, hierarchyHandle, authSession, decryptSession, newAuth, cancellationToken).ConfigureAwait(false);
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
                    //Compensating cleanup only; see this method's own bracket comment for the rationale.
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
                //Compensating cleanup only; see this method's own bracket comment for the rationale.
            }
        }
    }

    /// <summary>
    /// The salted composition core for <c>ChangeHierarchyAuthAsync</c>'s salted overload: identical to
    /// <see cref="ChangeHierarchyAuthCoreAsync"/> except that BOTH sessions are additionally SALTED against
    /// <paramref name="tpmKey"/> - the authorizing one, so neither leg of its HMAC can be reproduced from a
    /// captured transcript plus a guess at <paramref name="currentAuth"/>, and the companion, so the keystream
    /// protecting <paramref name="newAuth"/> derives from a secret only the TPM holding
    /// <paramref name="tpmKey"/> can recover (TPM 2.0 Library Part 1, Section 17.6.12, equation 25).
    /// </summary>
    /// <remarks>
    /// The two sessions draw their salts from two independent <c>TPM2_StartAuthSession</c> exchanges, so each
    /// session key is derived from its own secret; a salt is never carried from one session to the other, which
    /// would make the pair's keys jointly recoverable from a single compromise.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="hierarchyHandle">The hierarchy whose authorization value is replaced.</param>
    /// <param name="currentAuth">The hierarchy's current authorization value.</param>
    /// <param name="newAuth">The replacement authorization value.</param>
    /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm.</param>
    /// <param name="encryptSalt">Encrypts each drawn salt via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The rotation's result, or the first failing command's error.</returns>
    private static async ValueTask<TpmResult<HierarchyChangeAuthResponse>> ChangeHierarchyAuthSaltedCoreAsync(
        TpmDevice device,
        TpmRh hierarchyHandle,
        ReadOnlyMemory<byte> currentAuth,
        ReadOnlyMemory<byte> newAuth,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        TpmResult<TpmSession> authResult = await StartHierarchyBoundAndSaltedSessionAsync(
            device, pool, registry, hierarchyHandle, currentAuth, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken).ConfigureAwait(false);

        if(!authResult.IsSuccess)
        {
            return authResult.Map<HierarchyChangeAuthResponse>(_ => null!);
        }

        using TpmSession authSession = authResult.Value;
        uint authSessionHandle = authSession.SessionHandle.Value;

        try
        {
            //The same separation the unsalted core documents, with the companion negotiating XOR so it can carry
            //the decrypt attribute and drawing its own salt, shared with nothing.
            TpmResult<TpmSession> decryptResult = await StartHierarchyBoundAndSaltedSessionAsync(
                device, pool, registry, hierarchyHandle, currentAuth, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken,
                TpmtSymDef.Xor(HierarchyAuthSessionHash)).ConfigureAwait(false);

            if(!decryptResult.IsSuccess)
            {
                return decryptResult.Map<HierarchyChangeAuthResponse>(_ => null!);
            }

            using TpmSession decryptSession = decryptResult.Value;
            uint decryptSessionHandle = decryptSession.SessionHandle.Value;

            try
            {
                return await ChangeHierarchyAuthOverSessionsAsync(
                    device, pool, registry, hierarchyHandle, authSession, decryptSession, newAuth, cancellationToken).ConfigureAwait(false);
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
                    //Compensating cleanup only; see ChangeHierarchyAuthCoreAsync's identical bracket for the rationale.
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
                //Compensating cleanup only; see ChangeHierarchyAuthCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// Shared by <see cref="ChangeHierarchyAuthCoreAsync"/> and
    /// <see cref="ChangeHierarchyAuthSaltedCoreAsync"/>: marks the companion as the decrypt session and issues
    /// the <c>TPM2_HierarchyChangeAuth</c> that swaps the authorization value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The command's single handle is a permanent handle, whose Name is its own four octets (TPM 2.0 Library
    /// Part 1, Section 14, Table 6), so the executor derives the cpHash Name area itself and no caller-supplied
    /// Name is needed - unlike the NV family, whose hash-based Names must be read back.
    /// </para>
    /// <para>
    /// <b>No response-key swap is composed.</b> Part 3, Section 24.8.1 keys the response HMAC on the value the
    /// command just installed, but the authorizing session here is bound to the very entity it authorizes, and
    /// Part 1, Section 17.6.10's equations 21/22 drop the authValue term from the HMAC key in exactly that case:
    /// the value the rule points at is not part of either key, so there is nothing to move between the command
    /// leg and the response leg. The session key that IS the key was fixed at <c>TPM2_StartAuthSession</c> from
    /// the pre-rotation value and does not change when the command commits. This is where an unbound
    /// composition would need the post-submit key swap that <c>Extensions/Pin</c>'s rotation performs for its
    /// policy-session authorizer.
    /// </para>
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the <c>HierarchyChangeAuth</c> codec.</param>
    /// <param name="hierarchyHandle">The hierarchy whose authorization value is replaced.</param>
    /// <param name="authSession">The composed hierarchy-bound authorizing session.</param>
    /// <param name="decryptSession">The composed companion; the decrypt attribute is set here.</param>
    /// <param name="newAuth">The replacement authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The rotation's result, or the failing command's error.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the replacement authorization value transfers to HierarchyChangeAuthInput, which disposes it; the redundant using local satisfies CA2000 and is safe because both types have idempotent disposal.")]
    private static async ValueTask<TpmResult<HierarchyChangeAuthResponse>> ChangeHierarchyAuthOverSessionsAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmRh hierarchyHandle,
        TpmSession authSession,
        TpmSession decryptSession,
        ReadOnlyMemory<byte> newAuth,
        CancellationToken cancellationToken)
    {
        decryptSession.SessionAttributes |= TpmaSession.DECRYPT;

        using Tpm2bAuth replacementAuth = Tpm2bAuth.Create(newAuth.Span, pool);
        using HierarchyChangeAuthInput input = new(hierarchyHandle, replacementAuth);

        return await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
            device, input, [authSession, decryptSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>ChangeHierarchyAuthWithPasswordAsync</c>: one
    /// <c>TPM_RS_PW</c> session carrying the current authorization value, and the replacement value sent
    /// unencrypted.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="hierarchyHandle">The hierarchy whose authorization value is replaced.</param>
    /// <param name="currentAuth">The hierarchy's current authorization value.</param>
    /// <param name="newAuth">The replacement authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The rotation's result, or the failing command's error.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the replacement authorization value transfers to HierarchyChangeAuthInput, which disposes it; the redundant using local satisfies CA2000 and is safe because both types have idempotent disposal.")]
    private static async ValueTask<TpmResult<HierarchyChangeAuthResponse>> ChangeHierarchyAuthWithPasswordCoreAsync(
        TpmDevice device,
        TpmRh hierarchyHandle,
        ReadOnlyMemory<byte> currentAuth,
        ReadOnlyMemory<byte> newAuth,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth);

        using TpmPasswordSession authSession = TpmPasswordSession.Create(currentAuth.Span, pool);
        using Tpm2bAuth replacementAuth = Tpm2bAuth.Create(newAuth.Span, pool);
        using HierarchyChangeAuthInput input = new(hierarchyHandle, replacementAuth);

        return await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
            device, input, [authSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The composition core for <c>ClearAsync</c>: opens a lockout-bound HMAC session and issues
    /// <c>TPM2_Clear</c> under it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="lockoutAuth">The lockout entity's current authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The clear's result, or the first failing command's error.</returns>
    private static async ValueTask<TpmResult<ClearResponse>> ClearCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> lockoutAuth,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Clear, TpmResponseCodec.Clear);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        var input = new ClearInput(TpmRh.TPM_RH_LOCKOUT);

        return await ExecuteOverBoundSessionAsync<ClearResponse>(
            device, pool, registry, TpmRh.TPM_RH_LOCKOUT, lockoutAuth, input, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>ClearWithPasswordAsync</c>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="lockoutAuth">The lockout entity's current authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The clear's result, or the failing command's error.</returns>
    private static async ValueTask<TpmResult<ClearResponse>> ClearWithPasswordCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> lockoutAuth,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Clear, TpmResponseCodec.Clear);

        var input = new ClearInput(TpmRh.TPM_RH_LOCKOUT);

        return await ExecuteOverPasswordSessionAsync<ClearResponse>(
            device, pool, registry, lockoutAuth, input, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The composition core for <c>ClearControlAsync</c>: opens a session bound to
    /// <paramref name="authHandle"/> and issues <c>TPM2_ClearControl</c> under it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="authHandle">The lockout or platform handle authorizing the change.</param>
    /// <param name="authValue"><paramref name="authHandle"/>'s current authorization value.</param>
    /// <param name="isDisablingClear">Whether <c>disableClear</c> is being SET.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The command's result, or the first failing command's error.</returns>
    private static async ValueTask<TpmResult<ClearControlResponse>> ClearControlCoreAsync(
        TpmDevice device,
        TpmRh authHandle,
        ReadOnlyMemory<byte> authValue,
        bool isDisablingClear,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_ClearControl, TpmResponseCodec.ClearControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        var input = new ClearControlInput(authHandle, isDisablingClear ? TpmiYesNo.Yes : TpmiYesNo.No);

        return await ExecuteOverBoundSessionAsync<ClearControlResponse>(
            device, pool, registry, authHandle, authValue, input, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>ClearControlWithPasswordAsync</c>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="authHandle">The lockout or platform handle authorizing the change.</param>
    /// <param name="authValue"><paramref name="authHandle"/>'s current authorization value.</param>
    /// <param name="isDisablingClear">Whether <c>disableClear</c> is being SET.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The command's result, or the failing command's error.</returns>
    private static async ValueTask<TpmResult<ClearControlResponse>> ClearControlWithPasswordCoreAsync(
        TpmDevice device,
        TpmRh authHandle,
        ReadOnlyMemory<byte> authValue,
        bool isDisablingClear,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_ClearControl, TpmResponseCodec.ClearControl);

        var input = new ClearControlInput(authHandle, isDisablingClear ? TpmiYesNo.Yes : TpmiYesNo.No);

        return await ExecuteOverPasswordSessionAsync<ClearControlResponse>(
            device, pool, registry, authValue, input, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The composition core shared by <c>DisableHierarchyAsync</c> and <c>EnableHierarchyAsync</c>: opens a
    /// session bound to <paramref name="authHandle"/> and issues <c>TPM2_HierarchyControl</c> under it.
    /// </summary>
    /// <remarks>
    /// The two public verbs differ only in the <paramref name="state"/> they pass and in which authorizations
    /// they let a caller choose from; the composition itself is one command with one handle, so it lives once
    /// here rather than being duplicated per direction.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="authValue"><paramref name="authHandle"/>'s current authorization value.</param>
    /// <param name="hierarchy">The enable being modified.</param>
    /// <param name="state">YES to SET the enable, NO to CLEAR it.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The command's result, or the first failing command's error.</returns>
    private static async ValueTask<TpmResult<HierarchyControlResponse>> HierarchyControlCoreAsync(
        TpmDevice device,
        TpmRh authHandle,
        ReadOnlyMemory<byte> authValue,
        TpmRh hierarchy,
        TpmiYesNo state,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        var input = new HierarchyControlInput(authHandle, hierarchy, state);

        return await ExecuteOverBoundSessionAsync<HierarchyControlResponse>(
            device, pool, registry, authHandle, authValue, input, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The explicit low-protection opt-out core shared by <c>DisableHierarchyWithPasswordAsync</c> and
    /// <c>EnableHierarchyWithPasswordAsync</c>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="authValue"><paramref name="authHandle"/>'s current authorization value.</param>
    /// <param name="hierarchy">The enable being modified.</param>
    /// <param name="state">YES to SET the enable, NO to CLEAR it.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The command's result, or the failing command's error.</returns>
    private static async ValueTask<TpmResult<HierarchyControlResponse>> HierarchyControlWithPasswordCoreAsync(
        TpmDevice device,
        TpmRh authHandle,
        ReadOnlyMemory<byte> authValue,
        TpmRh hierarchy,
        TpmiYesNo state,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl);

        var input = new HierarchyControlInput(authHandle, hierarchy, state);

        return await ExecuteOverPasswordSessionAsync<HierarchyControlResponse>(
            device, pool, registry, authValue, input, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The composition core for <c>SetPrimaryPolicyAsync</c>: opens a session bound to
    /// <paramref name="authHandle"/> and issues <c>TPM2_SetPrimaryPolicy</c> under it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="authHandle">The entity whose policy is installed.</param>
    /// <param name="hierarchyAuth"><paramref name="authHandle"/>'s current authorization value.</param>
    /// <param name="policyDigest">The policy digest to install, or the Empty Buffer.</param>
    /// <param name="hashAlg">The hash algorithm the digest was computed with, or <c>TPM_ALG_NULL</c>.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The command's result, or the first failing command's error.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the policy digest transfers to SetPrimaryPolicyInput, which disposes it; the redundant using local satisfies CA2000 and is safe because both types have idempotent disposal.")]
    private static async ValueTask<TpmResult<SetPrimaryPolicyResponse>> SetPrimaryPolicyCoreAsync(
        TpmDevice device,
        TpmRh authHandle,
        ReadOnlyMemory<byte> hierarchyAuth,
        ReadOnlyMemory<byte> policyDigest,
        TpmAlgIdConstants hashAlg,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_SetPrimaryPolicy, TpmResponseCodec.SetPrimaryPolicy);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        using Tpm2bDigest digest = Tpm2bDigest.Create(policyDigest.Span, pool);
        using SetPrimaryPolicyInput input = new(authHandle, digest, hashAlg);

        return await ExecuteOverBoundSessionAsync<SetPrimaryPolicyResponse>(
            device, pool, registry, authHandle, hierarchyAuth, input, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>SetPrimaryPolicyWithPasswordAsync</c>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="authHandle">The entity whose policy is installed.</param>
    /// <param name="hierarchyAuth"><paramref name="authHandle"/>'s current authorization value.</param>
    /// <param name="policyDigest">The policy digest to install, or the Empty Buffer.</param>
    /// <param name="hashAlg">The hash algorithm the digest was computed with, or <c>TPM_ALG_NULL</c>.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The command's result, or the failing command's error.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the policy digest transfers to SetPrimaryPolicyInput, which disposes it; the redundant using local satisfies CA2000 and is safe because both types have idempotent disposal.")]
    private static async ValueTask<TpmResult<SetPrimaryPolicyResponse>> SetPrimaryPolicyWithPasswordCoreAsync(
        TpmDevice device,
        TpmRh authHandle,
        ReadOnlyMemory<byte> hierarchyAuth,
        ReadOnlyMemory<byte> policyDigest,
        TpmAlgIdConstants hashAlg,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_SetPrimaryPolicy, TpmResponseCodec.SetPrimaryPolicy);

        using Tpm2bDigest digest = Tpm2bDigest.Create(policyDigest.Span, pool);
        using SetPrimaryPolicyInput input = new(authHandle, digest, hashAlg);

        return await ExecuteOverPasswordSessionAsync<SetPrimaryPolicyResponse>(
            device, pool, registry, hierarchyAuth, input, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The single-command bracket every sessioned verb in this group except the rotation runs through: opens an
    /// HMAC session bound to <paramref name="authHandle"/>, issues <paramref name="input"/> under it, and
    /// flushes the session handle on every path.
    /// </summary>
    /// <remarks>
    /// Each of these four commands carries exactly one handle, and that handle is a permanent handle whose Name
    /// is its own four octets (TPM 2.0 Library Part 1, Section 14, Table 6), so the executor derives the cpHash
    /// Name area itself and no caller-supplied Name is threaded through. The authorizing session is bound to the
    /// entity it authorizes, so its HMAC key is the session key alone (Part 1, Section 17.6.10, equations
    /// 21/22).
    /// </remarks>
    /// <typeparam name="TResponse">The command's response type.</typeparam>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the command's codec plus the StartAuthSession and FlushContext codecs.</param>
    /// <param name="authHandle">The hierarchy or lockout handle the session binds to and the command authorizes.</param>
    /// <param name="authValue"><paramref name="authHandle"/>'s current authorization value.</param>
    /// <param name="input">The already-built command input.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The command's result, or the first failing command's error.</returns>
    private static async ValueTask<TpmResult<TResponse>> ExecuteOverBoundSessionAsync<TResponse>(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmRh authHandle,
        ReadOnlyMemory<byte> authValue,
        ITpmCommandInput input,
        CancellationToken cancellationToken) where TResponse: class, ITpmWireType
    {
        TpmResult<TpmSession> sessionResult = await StartHierarchyBoundSessionAsync(
            device, pool, registry, authHandle, authValue, cancellationToken).ConfigureAwait(false);

        if(!sessionResult.IsSuccess)
        {
            return sessionResult.Map<TResponse>(_ => null!);
        }

        using TpmSession authSession = sessionResult.Value;
        uint sessionHandle = authSession.SessionHandle.Value;

        try
        {
            return await TpmCommandExecutor.ExecuteAsync<TResponse>(
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
                //Compensating cleanup only; see ChangeHierarchyAuthCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// The single-command shape every <c>…WithPasswordAsync</c> opt-out in this group runs through: one
    /// <c>TPM_RS_PW</c> session carrying <paramref name="authValue"/> in the clear, no session slot to open or
    /// flush.
    /// </summary>
    /// <typeparam name="TResponse">The command's response type.</typeparam>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the command's codec.</param>
    /// <param name="authValue">The authorizing entity's current authorization value, sent in the clear.</param>
    /// <param name="input">The already-built command input.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The command's result, or the failing command's error.</returns>
    private static async ValueTask<TpmResult<TResponse>> ExecuteOverPasswordSessionAsync<TResponse>(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        ReadOnlyMemory<byte> authValue,
        ITpmCommandInput input,
        CancellationToken cancellationToken) where TResponse: ITpmWireType
    {
        using TpmPasswordSession authSession = TpmPasswordSession.Create(authValue.Span, pool);

        return await TpmCommandExecutor.ExecuteAsync<TResponse>(
            device, input, [authSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts and binds an HMAC session to <paramref name="hierarchyHandle"/> - the shared bracket each
    /// sessioned verb in this group opens before its own command and closes, regardless of outcome, after.
    /// </summary>
    /// <remarks>
    /// The hierarchy generalization of <c>Extensions/Pin</c>'s owner-only equivalent and of
    /// <c>Extensions/Policy</c>'s authorization-session helper (TPM 2.0 Library Part 1, Section 17.6.10,
    /// equation 20): binding folds <paramref name="hierarchyAuth"/> into the session key via KDFa, so the
    /// per-command authHMAC's key genuinely incorporates the hierarchy's authorization value rather than sending
    /// it in the clear the way a <c>…WithPasswordAsync</c> opt-out does. Those files are disjoint from this one,
    /// so the composition is a sibling rather than a shared call.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry; must already carry the StartAuthSession and FlushContext codecs.</param>
    /// <param name="hierarchyHandle">The hierarchy or lockout handle to bind to.</param>
    /// <param name="hierarchyAuth">That entity's authorization value, or empty when it has none set.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <param name="symmetric">
    /// The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/>
    /// for none. Only the rotation's decrypt companion supplies one; every authorizing session leaves it unset,
    /// since no command here carries a parameter its authorizing session encrypts.
    /// </param>
    /// <returns>A result containing the bound session (the caller disposes it and flushes its handle), or the StartAuthSession error.</returns>
    private static async ValueTask<TpmResult<TpmSession>> StartHierarchyBoundSessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmRh hierarchyHandle,
        ReadOnlyMemory<byte> hierarchyAuth,
        CancellationToken cancellationToken,
        TpmtSymDef? symmetric = null)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession((uint)hierarchyHandle, HierarchyAuthSessionHash, symmetric);
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
        //outcome is caught and discarded, so it can never replace the exception that is this call's real outcome.
        try
        {
            //The bind authValue enters the session-key KDFa with its trailing zeros already removed (TPM 2.0
            //Library Part 1, Section 17.6.4.3, and CreateBoundAsync's own documented precondition): the TPM keys
            //equation 20 (Part 1, clause 17.6.10) on the stripped form, so a hierarchy authorization value ending in zero octets would
            //otherwise derive a session key the TPM never agrees with.
            TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), StripTrailingZeros(hierarchyAuth), startInput.NonceCaller, started.NonceTPM,
                HierarchyAuthSessionHash, pool, symmetric: symmetric, cancellationToken: cancellationToken).ConfigureAwait(false);

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
                //Compensating cleanup only; see ChangeHierarchyAuthCoreAsync's identical bracket for the rationale.
            }

            throw;
        }
    }

    /// <summary>
    /// Starts an HMAC session that is both BOUND to <paramref name="hierarchyHandle"/> and SALTED against
    /// <paramref name="tpmKey"/> - the composition the rotation's salted overload builds both of its sessions
    /// from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The session key becomes <c>KDFa(hierarchyAuth ‖ salt, …)</c> (TPM 2.0 Library Part 1, Section 17.6.12,
    /// equation 25) rather than a KDFa over the authorization value alone, so the term an observer would have to
    /// guess is no longer the only unknown: the salt is RSA-OAEP-encrypted to <paramref name="tpmKey"/> (Annex
    /// B.10.2) and only the TPM holding its private half can recover it.
    /// </para>
    /// <para>
    /// The salt is zeroized and returned to the pool as soon as <c>CreateBoundAsync</c> has folded it into the
    /// derived session key; nothing downstream needs it again. From the instant the TPM allocates the session
    /// slot the derivation reaches an asynchronous crypto seam under the caller's own token, and the caller's
    /// flush bracket only opens once this helper has RETURNED a session, so a failing derivation releases the
    /// slot itself - the same compensating bracket <see cref="StartHierarchyBoundSessionAsync"/> opens, and for
    /// the same reason.
    /// </para>
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry; must already carry the StartAuthSession and FlushContext codecs.</param>
    /// <param name="hierarchyHandle">The hierarchy or lockout handle to bind to.</param>
    /// <param name="hierarchyAuth">That entity's authorization value, or empty when it has none set.</param>
    /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
    /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
    /// <returns>A result containing the bound and salted session (the caller disposes it and flushes its handle), or the StartAuthSession error.</returns>
    private static async ValueTask<TpmResult<TpmSession>> StartHierarchyBoundAndSaltedSessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmRh hierarchyHandle,
        ReadOnlyMemory<byte> hierarchyAuth,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken,
        TpmtSymDef? symmetric = null)
    {
        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateBoundAndSaltedHmacSession(
            tpmKey, (uint)hierarchyHandle, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, HierarchyAuthSessionHash, encryptSalt, pool, cancellationToken, symmetric).ConfigureAwait(false);

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
                //Both terms of equation 25 (Part 1, clause 17.6.12) are present here: the stripped bind authValue and the recovered salt.
                //The session takes ownership of started's nonceTPM, so the response is never disposed
                //independently.
                TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), StripTrailingZeros(hierarchyAuth), salted.Input.NonceCaller, started.NonceTPM,
                    HierarchyAuthSessionHash, pool, symmetric: symmetric, salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: cancellationToken).ConfigureAwait(false);

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
                    //Compensating cleanup only; see ChangeHierarchyAuthCoreAsync's identical bracket for the rationale.
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
    /// Removes trailing zero octets from an authorization value before it is used in an authorization
    /// computation (TPM 2.0 Library Part 1, Section 17.6.4.3: "Trailing octets of zero are to be removed from any
    /// string before it is used as an authValue"; Section 17.6.5 states the same for the authValue term of the
    /// HMAC key).
    /// </summary>
    /// <remarks>
    /// The bind authValue reaches <c>TpmSession.CreateBoundAsync</c> as a plain parameter whose documented
    /// precondition is the stripped form, so this group strips it at the call site, exactly as
    /// <c>Extensions/Pin</c>'s sibling helper does for its own bound sessions.
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
}

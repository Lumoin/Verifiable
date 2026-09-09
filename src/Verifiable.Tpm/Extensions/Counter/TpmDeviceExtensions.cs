using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Extensions.Counter;

/// <summary>
/// Monotonic-counter ("rollback-proof event count") business-capability extensions for <see cref="TpmDevice"/>.
/// </summary>
/// <remarks>
/// <para>
/// These verbs compose the shipped <c>TPM2_NV_DefineSpace</c>/<c>TPM2_NV_Increment</c>/<c>TPM2_NV_Read</c>/
/// <c>TPM2_NV_UndefineSpace</c> surface (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 3, clauses 31.3, 31.8, 31.13, 31.4) into a single business capability:
/// a rollback-proof monotonic counter suitable for signature counters, revocation epochs, or anti-rollback version
/// stamps. Every session (the owner hierarchy's for the administrative arms, the Index's own for the counter arms)
/// is built and disposed internally; a caller never hands in a pre-built session, matching the existing
/// <c>Extensions/DictionaryAttack</c> and <c>Extensions/Seal</c> verb groups.
/// </para>
/// <para>
/// <b>Channel protection.</b> Every verb defaults to a real cryptographic channel rather than a plaintext password
/// session, every verb carries a <c>…WithPasswordAsync</c> plaintext opt-out with the identical composition and the
/// identical counter semantics, and every verb carries a SALTED overload that seeds its session key from a secret
/// only the TPM can recover:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/> and
///   <see cref="ReadCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/> compose an UNBOUND, unsalted
///   HMAC session (TPM 2.0 Library Part 1, clause 16.6.9's Empty Buffer session key, equation 19) and set the
///   Index's own authorization value as that session's authValue, so it becomes the per-command HMAC key's
///   authValue term (Part 1, clause 16.6.5, equation 17: <c>sessionValue = sessionKey || authValue</c>) rather
///   than plaintext on the bus. Part 1, clause 34.2.8.3's outright prohibition on binding a session to the
///   authorized Index covers PIN Pass and PIN Fail Indexes; it does not reach a Counter Index, so the unbound
///   form here is a channel decision rather than a spec constraint - it keeps ONE session shape across both
///   commands <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/> composes, and
///   its salted overload changes only where the key entropy comes from. See those verbs' own remarks for the
///   honest accounting: this default removes the on-the-wire plaintext exposure, not the offline-guessing
///   surface, which the salted overload removes.</description></item>
///   <item><description>The two owner-authorized verbs
///   (<see cref="DefineCounterAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, bool, CancellationToken)"/>,
///   <see cref="UndefineCounterAsync(ReadOnlyMemory{byte}, uint, CancellationToken)"/>) default to an HMAC
///   session BOUND to <c>TPM_RH_OWNER</c> (Part 1, clause 16.6.10, equation 20): the owner authorization value
///   feeds the session key's KDFa derivation, so it never crosses the bus and the session authorizing that same
///   bound entity omits it from the per-command HMAC key entirely (equation 22). As in <c>Extensions/Pin</c> and
///   <c>Extensions/Hierarchy</c>, when the owner's own authorization value is empty (unset) that KDFa key is
///   derivable by anyone who observed the <c>TPM2_StartAuthSession</c> exchange, whose nonces cross the wire in
///   the clear; the mechanism becomes real integrity protection the moment a real owner authValue is set. Each
///   folds the Counter Index's own real, current Name (Part 1, clause 13, Table 9) into the cpHash of every
///   command it composes against an ALREADY-DEFINED Index, deriving it via
///   <see cref="Nv.TpmDeviceExtensions.NvReadPublicAsync(uint, CancellationToken)"/> rather than recomputing it
///   blind. The composed <c>TPM2_NV_DefineSpace</c> is the exception: it is single-handle, and no Index exists yet
///   to have a Name, so its cpHash carries the owner handle alone.</description></item>
///   <item><description>Authorization failures answer identically on the HMAC and the password arm, because
///   Part 1, clause 16.8.1 enumerates the password use, the equation-17 HMAC authValue term, and the authValue
///   term of a bound session's session-key derivation (equation 18) together and states that "All uses of a DA
///   protected authValue receive DA protection". A wrong Index authorization value against a dictionary-attack-protected Counter
///   Index (this group's <c>noDa: false</c> default) is therefore <c>TPM_RC_AUTH_FAIL</c> with <c>failedTries</c>
///   advanced whether it was sent as a password or proven by HMAC, and against a <c>TPMA_NV_NO_DA</c> Index it is
///   <c>TPM_RC_BAD_AUTH</c> with the counter untouched (Part 2, clause 13.4, Table 249, bit 25); in Lockout mode
///   either arm is refused with <c>TPM_RC_LOCKOUT</c> (Part 1, clause 16.8.3). Flipping the channel changes what
///   an observer of the bus learns, never what the dictionary-attack logic does.</description></item>
/// </list>
/// <para>
/// <b>Rollback protection.</b> A Counter Index's value cannot be rolled back by deleting and redefining the same
/// handle: the in-house simulator retains the highest value any written Counter Index held at the moment it was
/// deleted (the "phantom counter" mechanism, TPM 2.0 Library Part 1, clause 34.2.6.3 NOTE 2/NOTE 6), so a
/// redefined counter's first <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>
/// always seeds strictly above the deleted counter's last value. This is the capability the group exists for, and
/// it is a property of the counter semantics alone - which channel authorized the increment never enters it.
/// </para>
/// <para>
/// <b>Counted value is public state.</b> Every verb here returns or accepts a plain <see cref="ulong"/> for the
/// counter's value - a count is public state, not a secret buffer, so the no-naked-bytes carrier discipline that
/// binds authorization values (which ride <see cref="ReadOnlyMemory{T}"/>) does not bind scalar counts.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer does not recognize C# 13 extension type syntax.")]
public static class TpmDeviceExtensions
{
    /// <summary>The declared data area size (octets) of every Counter Index this group defines - the whole 8-octet counter value (TPM 2.0 Library Part 2, clause 13.2).</summary>
    private const ushort CounterDataSize = 8;

    /// <summary>The Name hash algorithm fixed for every Counter Index this group defines.</summary>
    private const TpmAlgIdConstants CounterNameAlgorithm = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The hash algorithm for every HMAC session this group composes internally: the unbound sessions the counter
    /// arms compose, and the owner-bound sessions the two administrative verbs compose.
    /// </summary>
    private const TpmAlgIdConstants CounterAuthSessionHash = TpmAlgIdConstants.TPM_ALG_SHA256;

    extension(TpmDevice device)
    {
        /// <summary>
        /// Defines a new <c>TPM_NT_COUNTER</c> NV Index under the owner hierarchy over an owner-bound HMAC
        /// session, composing <c>TPM2_NV_DefineSpace</c> internally.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The Index is defined with <c>TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | TPMA_NV_OWNERWRITE</c> (both the Index
        /// authValue and the owner hierarchy may increment it) and a fixed 8-octet data area, the spec-mandated width
        /// of a Counter Index (TPM 2.0 Library Part 2, clause 13.2). See Part 3, clause 31.3.1.
        /// </para>
        /// <para>
        /// The session is BOUND to <c>TPM_RH_OWNER</c> (Part 1, clause 16.6.10, equation 20), so
        /// <paramref name="ownerAuth"/> seeds the session key by KDFa instead of crossing the bus, and the command
        /// carries a cpHash/nonce-bound authHMAC a password session cannot offer. Use
        /// <see cref="DefineCounterWithPasswordAsync"/> for the plaintext-owner-password opt-out.
        /// </para>
        /// <para>
        /// <b>Honest channel accounting for <paramref name="counterAuth"/>.</b> It is installed as the new Index's
        /// authValue by riding <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> command PARAMETER (Part 3, clause 31.3) -
        /// the command's first sized parameter, which Part 1, clause 18.1 makes eligible for session encryption
        /// and which this composition's decrypt-attributed session encrypts on the bus. That encryption is only as
        /// confidential as the session key it is keyed on, exactly as the owner integrity is: an owner-bound
        /// session whose owner authValue is empty (unset) derives its key from the <c>TPM2_StartAuthSession</c>
        /// nonces alone, which cross the wire in the clear, so a bus observer can recompute the keystream. A
        /// non-empty owner authValue, or the salted
        /// <see cref="DefineCounterAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, bool, uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, CancellationToken)"/>
        /// overload, makes it genuinely secret against such an observer - provision over a trusted bus, set an
        /// owner authValue, or use the salted overload. <see cref="DefineCounterWithPasswordAsync"/> sends the
        /// owner authorization value in the clear and has no encryption path for the enrollment value at all.
        /// </para>
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="nvIndex">The NV Index handle to define.</param>
        /// <param name="counterAuth">The authorization value assigned to the new Counter Index.</param>
        /// <param name="noDa">
        /// When <see langword="true"/>, authorization failures against the Counter Index never advance the
        /// dictionary-attack lockout counter. Defaults to <see langword="false"/> (dictionary-attack PROTECTED) - the
        /// secure default: a real <paramref name="counterAuth"/> is a brute-forceable secret and should count toward
        /// the shared lockout counter unless the caller has a specific reason to exempt it.
        /// </param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvDefineSpaceResponse>> DefineCounterAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            bool noDa = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return DefineCounterCoreAsync(device, ownerAuth, nvIndex, counterAuth, noDa, cancellationToken);
        }

        /// <summary>
        /// Defines a new <c>TPM_NT_COUNTER</c> NV Index over a session that is both BOUND to the owner hierarchy
        /// and SALTED against <paramref name="tpmKey"/>, so the keystream protecting
        /// <paramref name="counterAuth"/> on the bus derives from a secret an on-the-wire observer cannot
        /// reconstruct.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Identical in every authorization respect to
        /// <see cref="DefineCounterAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, bool, CancellationToken)"/> -
        /// the same owner-bound USER-role authorization, the same attributes, the same 8-octet data area. What
        /// changes is the source of the session key's entropy: the session is bound AND salted
        /// (<see cref="Infrastructure.Commands.StartAuthSessionInputExtensions.CreateBoundAndSaltedHmacSession(uint, uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/>),
        /// so <c>sessionKey = KDFa(ownerAuth ‖ salt, …)</c> (Part 1, clause 16.6.12, equation 25) and the
        /// authorization of that same bound entity omits the authValue term (equation 27). The salt is
        /// RSA-OAEP-encrypted (TPM 2.0 Library Part 1, clause 16.6.13) to <paramref name="tpmKeyModulus"/>/
        /// <paramref name="tpmKeyExponent"/>, so only the TPM holding <paramref name="tpmKey"/>'s matching private
        /// key can recover it.
        /// </para>
        /// <para>
        /// That is what makes the enrollment value genuinely confidential. <paramref name="counterAuth"/> still
        /// enters as <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> command PARAMETER (Part 3, clause 31.3) under the
        /// session's decrypt attribute, but the keystream is now keyed on a value no captured transcript yields -
        /// unlike the unsalted default with an empty owner authValue, where a bus observer can recompute it. The
        /// Index provisioned this way is byte-for-byte the one the unsalted default produces, so a later
        /// <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/> with the right
        /// authorization value succeeds either way. Use this overload whenever the bus the definition runs over is
        /// one a passive adversary might capture and a suitable loaded decrypt key (for example the Endorsement
        /// Key) is available.
        /// </para>
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="nvIndex">The NV Index handle to define.</param>
        /// <param name="counterAuth">The authorization value assigned to the new Counter Index.</param>
        /// <param name="noDa">
        /// When <see langword="true"/>, authorization failures against the Counter Index never advance the
        /// dictionary-attack lockout counter. Pass <see langword="false"/> (dictionary-attack PROTECTED) unless the
        /// caller has a specific reason to exempt the Index.
        /// </param>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
        /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP - an explicit per-call delegate, no closure capture.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvDefineSpaceResponse>> DefineCounterAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            bool noDa,
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyModulus,
            uint tpmKeyExponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmRsaOaepEncryptDelegate encryptSalt,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return DefineCounterSaltedCoreAsync(
                device, ownerAuth, nvIndex, counterAuth, noDa, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for
        /// <see cref="DefineCounterAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, bool, CancellationToken)"/>:
        /// defines the Counter Index over a plaintext owner-password session rather than a bound HMAC session.
        /// </summary>
        /// <remarks>
        /// The owner authorization value is sent in the clear, with no cpHash/rpHash HMAC integrity at all, and
        /// <paramref name="counterAuth"/> rides the <c>auth</c> parameter with no encryption path, so a passive
        /// bus observer reads both directly. Fine for an owner hierarchy whose authorization value has not been set
        /// and for diagnostics; wrong for anything security-sensitive, where
        /// <see cref="DefineCounterAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, bool, CancellationToken)"/>'s
        /// bound HMAC default - or its salted overload - is the right choice.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="nvIndex">The NV Index handle to define.</param>
        /// <param name="counterAuth">The authorization value assigned to the new Counter Index.</param>
        /// <param name="noDa">
        /// When <see langword="true"/>, authorization failures against the Counter Index never advance the
        /// dictionary-attack lockout counter. Defaults to <see langword="false"/> (dictionary-attack PROTECTED).
        /// </param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvDefineSpaceResponse>> DefineCounterWithPasswordAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            bool noDa = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return DefineCounterWithPasswordCoreAsync(device, ownerAuth, nvIndex, counterAuth, noDa, cancellationToken);
        }

        /// <summary>
        /// Advances <paramref name="nvIndex"/> by one and returns the fresh count, composing <c>TPM2_NV_Increment</c>
        /// (Part 3, clause 31.8) then <c>TPM2_NV_Read</c> internally over an UNBOUND, unsalted HMAC session whose
        /// authValue is <paramref name="counterAuth"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The first increment of an unwritten Counter Index always succeeds (Part 3, clause 31.8.1's explicit
        /// non-error) and never answers <c>TPM_RC_NV_UNINITIALIZED</c> - the contrast
        /// <see cref="ReadCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/> does exhibit before any
        /// increment has run. Both composed commands authorize <paramref name="nvIndex"/> at USER role by its own
        /// authorization value: the increment through <c>TPMA_NV_AUTHWRITE</c> (Part 3, clause 31.1's write-access
        /// rule) and the read-back through <c>TPMA_NV_AUTHREAD</c> (Part 1, clause 34.2.5), both of which this
        /// group's define sets.
        /// </para>
        /// <para>
        /// <b>Honest channel accounting.</b> The session is UNBOUND and unsalted (Part 1, clause 16.6.9's Empty
        /// Buffer session key) with <paramref name="counterAuth"/> set as its authValue, so the per-command HMAC
        /// key is <c>sessionValue = sessionKey || authValue = Empty || counterAuth</c> (Part 1, clause 16.6.5,
        /// equation 17, applied through equation 19). The authorization value is therefore never bytes on the bus a
        /// passive observer can read - unlike <see cref="IncrementCounterWithPasswordAsync"/>, which sends it
        /// directly. It does NOT remove offline guessing: <paramref name="counterAuth"/> is the key's only unknown,
        /// and every other value the derivation consumes (both <c>TPM2_StartAuthSession</c> nonces, the command
        /// handles, the cpHash) crosses the wire in the clear, so one captured transcript lets an adversary test
        /// candidate values offline with no further TPM interaction, bounded only by that value's entropy. A
        /// dictionary-attack-protected Index (this group's <c>noDa: false</c> default) throttles only ONLINE
        /// guessing against the live TPM. The salted overload,
        /// <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, CancellationToken)"/>,
        /// is what removes the offline surface.
        /// </para>
        /// <para>
        /// One session covers both commands, and the Index's Name is resolved for each of them separately: an NV
        /// Index Name hashes the whole <c>TPMS_NV_PUBLIC</c> including <c>TPMA_NV_WRITTEN</c> (Part 1, clause 13,
        /// Table 9), and the first increment SETs that attribute (Part 1, clause 34.2.6.3), so the cpHash Name the
        /// increment is authorized under and the one the read-back is authorized under are different values on a
        /// counter's first advance.
        /// </para>
        /// </remarks>
        /// <param name="nvIndex">The Counter Index to increment.</param>
        /// <param name="counterAuth">The Index's authorization value; proven by HMAC, not sent.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the fresh count, or the increment's or the read-back's error.</returns>
        public ValueTask<TpmResult<ulong>> IncrementCounterAsync(
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return IncrementCounterCoreAsync(device, nvIndex, counterAuth, cancellationToken);
        }

        /// <summary>
        /// Advances <paramref name="nvIndex"/> by one and returns the fresh count over a SALTED, unbound HMAC
        /// session, using <paramref name="tpmKey"/> to remove the offline-guessing surface the unsalted default
        /// carries.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Composes <see cref="Infrastructure.Commands.StartAuthSessionInputExtensions.CreateSaltedHmacSession(uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/>:
        /// a fresh salt is RSA-OAEP-encrypted (TPM 2.0 Library Part 1, clause 16.6.13) to
        /// <paramref name="tpmKeyModulus"/>/<paramref name="tpmKeyExponent"/>, so only the TPM holding
        /// <paramref name="tpmKey"/>'s matching private key can recover it. The session key then folds that
        /// recovered salt (Part 1, clause 16.6.11, equation 23) alongside <paramref name="counterAuth"/> as the
        /// session's authValue (equation 24) - unlike the unsalted default (see
        /// <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>'s own remarks), an
        /// adversary who captured the wire transcript cannot recompute this key offline without also breaking the
        /// RSA-OAEP encryption, so a captured transcript alone does not let a candidate authorization value be
        /// tested without the live TPM.
        /// </para>
        /// <para>
        /// The counter semantics are untouched: the same two commands, in the same order, with the same
        /// monotonicity and the same first-increment seeding. Only the source of key entropy changes; the session
        /// remains unbound.
        /// </para>
        /// </remarks>
        /// <param name="nvIndex">The Counter Index to increment.</param>
        /// <param name="counterAuth">The Index's authorization value; proven by HMAC, not sent.</param>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
        /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP - an explicit per-call delegate, no closure capture.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the fresh count, or the increment's or the read-back's error.</returns>
        public ValueTask<TpmResult<ulong>> IncrementCounterAsync(
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyModulus,
            uint tpmKeyExponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmRsaOaepEncryptDelegate encryptSalt,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return IncrementCounterSaltedCoreAsync(
                device, nvIndex, counterAuth, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for
        /// <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>: advances the counter
        /// with <paramref name="counterAuth"/> sent as a plaintext password rather than proven as an HMAC session
        /// authValue.
        /// </summary>
        /// <remarks>
        /// The Index's authorization value is sent in the clear as each session's password field - a passive bus
        /// observer reads it directly, with no HMAC derivation step to attack offline at all (there is nothing to
        /// derive; the value itself is the wire content) and no cpHash/rpHash integrity on either composed command.
        /// The counter semantics of Part 3, clause 31.8 are otherwise identical to the HMAC default. Fine for
        /// diagnostics or an already-protected transport; wrong for anything where
        /// <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>'s unbound HMAC
        /// default (or its salted overload) is the appropriate channel.
        /// </remarks>
        /// <param name="nvIndex">The Counter Index to increment.</param>
        /// <param name="counterAuth">The Index's authorization value.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the fresh count, or the increment's or the read-back's error.</returns>
        public ValueTask<TpmResult<ulong>> IncrementCounterWithPasswordAsync(
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return IncrementCounterWithPasswordCoreAsync(device, nvIndex, counterAuth, cancellationToken);
        }

        /// <summary>
        /// Reads the current count of <paramref name="nvIndex"/>, composing <c>TPM2_NV_Read</c> internally over an
        /// UNBOUND, unsalted HMAC session whose authValue is <paramref name="counterAuth"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Rejects with <c>TPM_RC_NV_UNINITIALIZED</c> (Part 3, clause 31.13.1) when no increment has ever run
        /// against the Index - the contrast
        /// <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/> never exhibits. Read
        /// authorization by the Index's own authorization value is what <c>TPMA_NV_AUTHREAD</c> permits (Part 1,
        /// clause 34.2.5), which this group's define sets.
        /// </para>
        /// <para>
        /// <b>Honest channel accounting.</b> Identical to
        /// <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>'s: the unbound,
        /// unsalted session key is the Empty Buffer (Part 1, clause 16.6.9), <paramref name="counterAuth"/> is the
        /// session's authValue and therefore the whole per-command HMAC key (Part 1, clause 16.6.5, equation 17
        /// through equation 19), so the value never crosses the bus but a captured transcript still permits offline
        /// guessing. The salted overload,
        /// <see cref="ReadCounterAsync(uint, ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, CancellationToken)"/>,
        /// removes that surface; <see cref="ReadCounterWithPasswordAsync"/> is the plaintext opt-out.
        /// </para>
        /// </remarks>
        /// <param name="nvIndex">The Counter Index to read.</param>
        /// <param name="counterAuth">The Index's authorization value; proven by HMAC, not sent.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the current count, or an error.</returns>
        public ValueTask<TpmResult<ulong>> ReadCounterAsync(
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ReadCounterCoreAsync(device, nvIndex, counterAuth, cancellationToken);
        }

        /// <summary>
        /// Reads the current count of <paramref name="nvIndex"/> over a SALTED, unbound HMAC session, using
        /// <paramref name="tpmKey"/> to remove the offline-guessing surface the unsalted default carries.
        /// </summary>
        /// <remarks>
        /// Composes <see cref="Infrastructure.Commands.StartAuthSessionInputExtensions.CreateSaltedHmacSession(uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/>
        /// exactly as
        /// <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, CancellationToken)"/>
        /// does, and for the same reason: the session key folds a salt RSA-OAEP-encrypted to
        /// <paramref name="tpmKey"/> (Part 1, clause 16.6.11, equation 23) with
        /// <paramref name="counterAuth"/> layered on as the session's authValue (equation 24), so the HMAC key
        /// stops being reproducible from public transcript data plus a guess. The read semantics are untouched -
        /// the same window, the same <c>TPM_RC_NV_UNINITIALIZED</c> answer before any increment; only the source of
        /// key entropy changes, and the session remains unbound.
        /// </remarks>
        /// <param name="nvIndex">The Counter Index to read.</param>
        /// <param name="counterAuth">The Index's authorization value; proven by HMAC, not sent.</param>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
        /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP - an explicit per-call delegate, no closure capture.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the current count, or an error.</returns>
        public ValueTask<TpmResult<ulong>> ReadCounterAsync(
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyModulus,
            uint tpmKeyExponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmRsaOaepEncryptDelegate encryptSalt,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ReadCounterSaltedCoreAsync(
                device, nvIndex, counterAuth, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for
        /// <see cref="ReadCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>: reads the count with
        /// <paramref name="counterAuth"/> sent as a plaintext password rather than proven as an HMAC session
        /// authValue.
        /// </summary>
        /// <remarks>
        /// The Index's authorization value is sent in the clear as the session's password field - a passive bus
        /// observer reads it directly, with no HMAC derivation step to attack offline and no cpHash/rpHash
        /// integrity on the exchange. The read semantics of Part 3, clause 31.13 are otherwise identical to the
        /// HMAC default. Fine for diagnostics or an already-protected transport; wrong for anything where
        /// <see cref="ReadCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/>'s unbound HMAC default (or
        /// its salted overload) is the appropriate channel.
        /// </remarks>
        /// <param name="nvIndex">The Counter Index to read.</param>
        /// <param name="counterAuth">The Index's authorization value.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result containing the current count, or an error.</returns>
        public ValueTask<TpmResult<ulong>> ReadCounterWithPasswordAsync(
            uint nvIndex,
            ReadOnlyMemory<byte> counterAuth,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return ReadCounterWithPasswordCoreAsync(device, nvIndex, counterAuth, cancellationToken);
        }

        /// <summary>
        /// Removes <paramref name="nvIndex"/>'s definition over an owner-bound HMAC session, composing
        /// <c>TPM2_NV_UndefineSpace</c> internally, authorized by the owner hierarchy's OWN authValue - never by
        /// the Index's.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The session is BOUND to <c>TPM_RH_OWNER</c> (Part 1, clause 16.6.10, equation 20), so
        /// <paramref name="ownerAuth"/> seeds the session key by KDFa instead of crossing the bus and the
        /// authorization of that same bound entity omits the authValue term from the per-command HMAC key
        /// (equation 22). A wrong <paramref name="ownerAuth"/> is refused (TPM 2.0 Library Part 3, clause 31.4)
        /// and the Index is left defined. Use <see cref="UndefineCounterWithPasswordAsync"/> for the
        /// plaintext-owner-password opt-out.
        /// </para>
        /// <para>
        /// The deleted counter's last value is retained as the simulator's phantom high-water mark (TPM 2.0 Library
        /// Part 1, clause 34.2.6.3 NOTE 2/NOTE 6): a subsequent
        /// <see cref="DefineCounterAsync(ReadOnlyMemory{byte}, uint, ReadOnlyMemory{byte}, bool, CancellationToken)"/>
        /// of the same handle seeds its first
        /// <see cref="IncrementCounterAsync(uint, ReadOnlyMemory{byte}, CancellationToken)"/> strictly above the
        /// deleted value, so delete-then-redefine can never roll a counter with this Name back. That is a property
        /// of the counter semantics, independent of which channel authorized the undefine.
        /// </para>
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="nvIndex">The Counter Index to undefine.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefineCounterAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint nvIndex,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return UndefineCounterCoreAsync(device, ownerAuth, nvIndex, cancellationToken);
        }

        /// <summary>
        /// Removes <paramref name="nvIndex"/>'s definition over a session that is both BOUND to the owner hierarchy
        /// and SALTED against <paramref name="tpmKey"/>, so the session key derives from a secret a captured
        /// transcript does not yield.
        /// </summary>
        /// <remarks>
        /// Identical in every authorization respect to
        /// <see cref="UndefineCounterAsync(ReadOnlyMemory{byte}, uint, CancellationToken)"/> - the same
        /// owner-authorized USER-role removal, the same phantom high-water retention. What changes is the source of
        /// the session key's entropy: the session is bound AND salted
        /// (<see cref="Infrastructure.Commands.StartAuthSessionInputExtensions.CreateBoundAndSaltedHmacSession(uint, uint, ReadOnlyMemory{byte}, uint, TpmAlgIdConstants, TpmAlgIdConstants, TpmRsaOaepEncryptDelegate, BaseMemoryPool, CancellationToken, TpmtSymDef?)"/>),
        /// so <c>sessionKey = KDFa(ownerAuth ‖ salt, …)</c> (Part 1, clause 16.6.12, equation 25) with the
        /// bound-entity authorization omitting the authValue term (equation 27), and the salt is
        /// RSA-OAEP-encrypted (Part 1, clause 16.6.13) to <paramref name="tpmKeyModulus"/>/
        /// <paramref name="tpmKeyExponent"/> so only the TPM holding <paramref name="tpmKey"/>'s matching private
        /// key can recover it. With an empty owner authValue this is what makes the command's authHMAC
        /// unforgeable by a bus observer at all, which the unsalted default cannot promise.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="nvIndex">The Counter Index to undefine.</param>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
        /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP - an explicit per-call delegate, no closure capture.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefineCounterAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint nvIndex,
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyModulus,
            uint tpmKeyExponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmRsaOaepEncryptDelegate encryptSalt,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return UndefineCounterSaltedCoreAsync(
                device, ownerAuth, nvIndex, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken);
        }

        /// <summary>
        /// The explicit low-protection opt-out for
        /// <see cref="UndefineCounterAsync(ReadOnlyMemory{byte}, uint, CancellationToken)"/>: undefines the Index
        /// over a plaintext owner-password session rather than a bound HMAC session.
        /// </summary>
        /// <remarks>
        /// The owner authorization value is sent in the clear, with no cpHash/rpHash HMAC integrity. Fine for an
        /// owner hierarchy whose authorization value has not been set and for diagnostics; wrong for anything
        /// security-sensitive, where
        /// <see cref="UndefineCounterAsync(ReadOnlyMemory{byte}, uint, CancellationToken)"/>'s bound HMAC default -
        /// or its salted overload - is the right choice.
        /// </remarks>
        /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
        /// <param name="nvIndex">The Counter Index to undefine.</param>
        /// <param name="cancellationToken">A token observed across the exchange.</param>
        /// <returns>A result indicating success or an error.</returns>
        public ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefineCounterWithPasswordAsync(
            ReadOnlyMemory<byte> ownerAuth,
            uint nvIndex,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(device);

            return UndefineCounterWithPasswordCoreAsync(device, ownerAuth, nvIndex, cancellationToken);
        }
    }

    /// <summary>
    /// Composes <c>TPM2_NV_DefineSpace</c> for a new <c>TPM_NT_COUNTER</c> Index under the owner hierarchy over an
    /// owner-bound HMAC session.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="nvIndex">The NV Index handle to define.</param>
    /// <param name="counterAuth">The authorization value assigned to the new Counter Index.</param>
    /// <param name="noDa">Whether the Counter Index opts out of dictionary-attack protection.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The define-space result.</returns>
    private static async ValueTask<TpmResult<NvDefineSpaceResponse>> DefineCounterCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        bool noDa,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //The owner-bound session negotiates XOR so it can carry the decrypt attribute over the definition,
        //encrypting the new Index's auth parameter on the bus. With an empty owner authValue its session key
        //derives from the public StartAuthSession nonces, so that encryption is structural rather than
        //confidential - the salted overload (DefineCounterSaltedCoreAsync) keys it from a secret only the TPM can
        //recover.
        TpmResult<TpmSession> sessionResult = await StartOwnerBoundSessionAsync(
            device, pool, registry, ownerAuth, cancellationToken, symmetric: TpmtSymDef.Xor(CounterAuthSessionHash)).ConfigureAwait(false);

        if(!sessionResult.IsSuccess)
        {
            return sessionResult.Map<NvDefineSpaceResponse>(_ => null!);
        }

        using TpmSession ownerSession = sessionResult.Value;
        uint sessionHandle = ownerSession.SessionHandle.Value;

        try
        {
            return await DefineCounterOverSessionAsync(
                device, pool, registry, ownerSession, nvIndex, counterAuth, noDa, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            //The composed session occupies a TPM session slot from here on, so every path above must still flush
            //it. The flush runs under CancellationToken.None: the caller's own token is exactly what may have
            //taken control out of the try block, and its own outcome is caught and discarded rather than allowed
            //to escape the finally, so a flush failure can never replace the primary result the try block already
            //produced - mirroring Extensions/Pin's DefinePinFailIndexCoreAsync flush bracket.
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
    /// The salted composition core for <c>DefineCounterAsync</c>'s salted overload: defines the Index over a
    /// session BOUND to the owner hierarchy and SALTED against <paramref name="tpmKey"/>, whose decrypt attribute
    /// encrypts <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> parameter under a key only the TPM can recover.
    /// </summary>
    /// <remarks>
    /// The session key becomes <c>KDFa(ownerAuth ‖ salt, …)</c> (TPM 2.0 Library Part 1, clause 16.6.12, equation
    /// 25), so neither the command's authHMAC nor the parameter-encryption keystream keyed on that session key can
    /// be reproduced from the wire transcript alone - closing the recovery surface the unsalted default leaves open
    /// for an empty owner authValue. Only the key's entropy changes; the authorization remains the owner
    /// hierarchy's own, at USER role, on the bound entity (equation 27).
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="nvIndex">The NV Index handle to define.</param>
    /// <param name="counterAuth">The authorization value assigned to the new Counter Index.</param>
    /// <param name="noDa">Whether the Counter Index opts out of dictionary-attack protection.</param>
    /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
    /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The define-space result.</returns>
    private static async ValueTask<TpmResult<NvDefineSpaceResponse>> DefineCounterSaltedCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        bool noDa,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        TpmResult<TpmSession> sessionResult = await StartOwnerBoundAndSaltedSessionAsync(
            device, pool, registry, ownerAuth, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken,
            symmetric: TpmtSymDef.Xor(CounterAuthSessionHash)).ConfigureAwait(false);

        if(!sessionResult.IsSuccess)
        {
            return sessionResult.Map<NvDefineSpaceResponse>(_ => null!);
        }

        using TpmSession ownerSession = sessionResult.Value;
        uint sessionHandle = ownerSession.SessionHandle.Value;

        try
        {
            return await DefineCounterOverSessionAsync(
                device, pool, registry, ownerSession, nvIndex, counterAuth, noDa, cancellationToken).ConfigureAwait(false);
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
                //Compensating cleanup only; see DefineCounterCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// Defines a new <c>TPM_NT_COUNTER</c> Index with <paramref name="counterAuth"/> as its authValue over the
    /// already-composed owner-authorized <paramref name="ownerSession"/> - the tail shared by the unsalted default
    /// (<see cref="DefineCounterCoreAsync"/>) and the salted overload
    /// (<see cref="DefineCounterSaltedCoreAsync"/>), which differ only in how that session's key is seeded.
    /// </summary>
    /// <remarks>
    /// The authorization value is installed by riding <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> command PARAMETER
    /// (TPM 2.0 Library Part 3, clause 31.3), which the session encrypts on the bus while it carries the decrypt
    /// attribute (Part 1, clause 18.1's first-sized-parameter rule). The attribute is set here because this
    /// session carries exactly one command, whose input declares that parameter encryptable; the definition's
    /// single handle (<c>@authHandle</c> = owner) is a permanent handle whose Name is the raw 4-octet handle value,
    /// which the executor derives itself, so no <c>handleNames</c> entry is supplied.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the NV_DefineSpace codec.</param>
    /// <param name="ownerSession">The composed owner-authorized session; it negotiates a symmetric so it can carry the decrypt attribute.</param>
    /// <param name="nvIndex">The NV Index handle to define.</param>
    /// <param name="counterAuth">The authorization value assigned to the new Counter Index.</param>
    /// <param name="noDa">Whether the Counter Index opts out of dictionary-attack protection.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The define-space result.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the auth value and public area transfers to NvDefineSpaceInput, which disposes both; the redundant using locals satisfy CA2000 and are safe because all three types have idempotent disposal.")]
    private static async ValueTask<TpmResult<NvDefineSpaceResponse>> DefineCounterOverSessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmSessionBase ownerSession,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        bool noDa,
        CancellationToken cancellationToken)
    {
        const TpmaNv baseAttributes =
            TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE
            | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);
        TpmaNv attributes = noDa ? baseAttributes | TpmaNv.TPMA_NV_NO_DA : baseAttributes;

        using Tpm2bAuth auth = Tpm2bAuth.Create(counterAuth.Span, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, CounterNameAlgorithm, attributes, Tpm2bDigest.Empty, CounterDataSize);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        ownerSession.SessionAttributes |= TpmaSession.DECRYPT;

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>DefineCounterWithPasswordAsync</c>: the plaintext-owner-
    /// password composition, with the new Index's authorization value riding the <c>auth</c> parameter unencrypted.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="nvIndex">The NV Index handle to define.</param>
    /// <param name="counterAuth">The authorization value assigned to the new Counter Index.</param>
    /// <param name="noDa">Whether the Counter Index opts out of dictionary-attack protection.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The define-space result.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the auth value and public area transfers to NvDefineSpaceInput, which disposes both; the redundant using locals satisfy CA2000 and are safe because all three types have idempotent disposal.")]
    private static async ValueTask<TpmResult<NvDefineSpaceResponse>> DefineCounterWithPasswordCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        bool noDa,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);

        const TpmaNv baseAttributes =
            TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE
            | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);
        TpmaNv attributes = noDa ? baseAttributes | TpmaNv.TPMA_NV_NO_DA : baseAttributes;

        using Tpm2bAuth auth = Tpm2bAuth.Create(counterAuth.Span, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, CounterNameAlgorithm, attributes, Tpm2bDigest.Empty, CounterDataSize);
        using NvDefineSpaceInput input = new(TpmRh.TPM_RH_OWNER, auth, publicInfo);
        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Composes <c>TPM2_NV_Increment</c> then <c>TPM2_NV_Read</c> against <paramref name="nvIndex"/> over ONE
    /// UNBOUND, unsalted HMAC session whose authValue is <paramref name="counterAuth"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Counter Index to increment.</param>
    /// <param name="counterAuth">The Index's authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the fresh count, or the increment's or the read-back's error.</returns>
    private static async ValueTask<TpmResult<ulong>> IncrementCounterCoreAsync(
        TpmDevice device,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Unbound, unsalted (Part 1, clause 16.6.9): TPM_RH_NULL bind, Empty Buffer sessionKey. No symmetric is
        //negotiated and neither composed command carries a decrypt or encrypt attribute, for two different
        //reasons. TPM2_NV_Increment is parameterless in both directions (Part 3, clause 31.8.2), so there is
        //nothing an attribute could act on and one set anyway is refused TPM_RC_ATTRIBUTES rather than silently
        //ignored (Part 3, clause 5.7). TPM2_NV_Read's returned data, by contrast, IS the first sized response
        //parameter Part 1, clause 18.1 makes encryption-eligible - see ReadCounterCoreAsync for why this group
        //declines that capability deliberately.
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(CounterAuthSessionHash, device.Rng, pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!startResult.IsSuccess)
        {
            return startResult.Map<ulong>(_ => default);
        }

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            //The plain constructor yields sessionKey = Empty Buffer (unbound/unsalted); SetAuthValue then makes
            //counterAuth the session's authValue term, so sessionValue = Empty || counterAuth = counterAuth - the
            //Index's authorization value becomes the per-command HMAC key (Part 1, clause 16.6.5, equation 17,
            //applied through equation 19) instead of plaintext on the bus.
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, CounterAuthSessionHash, device.Rng, pool);
            session.SetAuthValue(counterAuth.Span, pool);

            return await IncrementCounterOverSessionAsync(device, pool, registry, nvIndex, session, cancellationToken).ConfigureAwait(false);
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
                //Compensating cleanup only; see DefineCounterCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// Composes <c>TPM2_NV_Increment</c> then <c>TPM2_NV_Read</c> over a SALTED, unbound HMAC session whose
    /// authValue is <paramref name="counterAuth"/> - the offline-guessing-resistant overload's core.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Counter Index to increment.</param>
    /// <param name="counterAuth">The Index's authorization value.</param>
    /// <param name="tpmKey">The handle of a loaded RSA decrypt key the salt is encrypted to.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm.</param>
    /// <param name="encryptSalt">Encrypts the drawn salt via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the fresh count, or the increment's or the read-back's error.</returns>
    private static async ValueTask<TpmResult<ulong>> IncrementCounterSaltedCoreAsync(
        TpmDevice device,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateSaltedHmacSession(
            tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, CounterAuthSessionHash, encryptSalt, device.Rng, pool, cancellationToken).ConfigureAwait(false);

        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, salted.Input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

            if(!startResult.IsSuccess)
            {
                return startResult.Map<ulong>(_ => default);
            }

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                //Unbound (bindAuthValue empty) but salted: sessionKey = KDFa(salt, ...) (Part 1, clause 16.6.11,
                //equation 23). SetAuthValue then makes counterAuth the session's authValue term on top (equation
                //24), so an offline transcript alone cannot reproduce the HMAC key.
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, salted.Input.NonceCaller, started.NonceTPM,
                    CounterAuthSessionHash, device.Rng, pool, salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: cancellationToken).ConfigureAwait(false);
                session.SetAuthValue(counterAuth.Span, pool);

                return await IncrementCounterOverSessionAsync(device, pool, registry, nvIndex, session, cancellationToken).ConfigureAwait(false);
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
                    //Compensating cleanup only; see DefineCounterCoreAsync's identical bracket for the rationale.
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
    /// Shared by <see cref="IncrementCounterCoreAsync"/> and <see cref="IncrementCounterSaltedCoreAsync"/>:
    /// resolves the Index's current Name, issues the Index-authorized <c>TPM2_NV_Increment</c>, re-resolves the
    /// Name, then reads the fresh count back - all over the already-composed <paramref name="session"/>.
    /// </summary>
    /// <remarks>
    /// Both commands are two-handle (<c>@authHandle</c> = <c>nvIndex</c> authorizing itself, then <c>nvIndex</c>),
    /// so Name1 and Name2 of each cpHash are the same value (TPM 2.0 Library Part 1, clause 15.7, equation 15).
    /// An NV Index Name is hash-based, so it is read back rather than recomputed blind, and it is read TWICE
    /// because the Name hashes the whole <c>TPMS_NV_PUBLIC</c> including <c>TPMA_NV_WRITTEN</c> (Part 1, clause
    /// 13, Table 9) and the first increment of a fresh Counter Index SETs that attribute (Part 1, clause
    /// 34.2.6.3): the value the increment is authorized under is not the value the read-back is authorized under
    /// on a counter's first advance.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the NV_Increment and NV_Read codecs.</param>
    /// <param name="nvIndex">The Counter Index to increment.</param>
    /// <param name="session">The already-composed authorization session (its authValue is the Index's authorization value).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the fresh count, or the increment's or the read-back's error.</returns>
    private static async ValueTask<TpmResult<ulong>> IncrementCounterOverSessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        uint nvIndex,
        TpmSessionBase session,
        CancellationToken cancellationToken)
    {
        TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(nvIndex, cancellationToken).ConfigureAwait(false);
        if(!nameResult.IsSuccess)
        {
            return nameResult.Map<ulong>(_ => default);
        }

        using NvReadPublicResponse namePublic = nameResult.Value;
        ReadOnlyMemory<byte> indexName = namePublic.NvName.Span.ToArray();
        ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

        var incrementInput = new NvIncrementInput(nvIndex, nvIndex);

        TpmResult<NvIncrementResponse> incrementResult = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, incrementInput, [session], handleNames, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!incrementResult.IsSuccess)
        {
            return incrementResult.Map<ulong>(_ => default);
        }

        return await ReadCounterOverSessionAsync(device, pool, registry, nvIndex, session, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>IncrementCounterWithPasswordAsync</c>: the plaintext-
    /// password composition, one password session per composed command.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Counter Index to increment.</param>
    /// <param name="counterAuth">The Index's authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the fresh count, or the increment's or the read-back's error.</returns>
    private static async ValueTask<TpmResult<ulong>> IncrementCounterWithPasswordCoreAsync(
        TpmDevice device,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

        using TpmPasswordSession incrementSession = TpmPasswordSession.Create(counterAuth.Span, pool);
        var incrementInput = new NvIncrementInput(nvIndex, nvIndex);

        TpmResult<NvIncrementResponse> incrementResult = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, incrementInput, [incrementSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!incrementResult.IsSuccess)
        {
            return incrementResult.Map<ulong>(_ => default);
        }

        using TpmPasswordSession readSession = TpmPasswordSession.Create(counterAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: CounterDataSize, Offset: 0);

        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [readSession], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!readResult.IsSuccess)
        {
            return readResult.Map<ulong>(_ => default);
        }

        using NvReadResponse response = readResult.Value;

        return TpmResult<ulong>.Success(BinaryPrimitives.ReadUInt64BigEndian(response.Data));
    }

    /// <summary>
    /// Composes <c>TPM2_NV_Read</c> against <paramref name="nvIndex"/>'s full 8-octet counter window over an
    /// UNBOUND, unsalted HMAC session whose authValue is <paramref name="counterAuth"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Counter Index to read.</param>
    /// <param name="counterAuth">The Index's authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the current count, or an error.</returns>
    private static async ValueTask<TpmResult<ulong>> ReadCounterCoreAsync(
        TpmDevice device,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Unbound, unsalted (Part 1, clause 16.6.9): TPM_RH_NULL bind, Empty Buffer sessionKey. No symmetric is
        //negotiated and no encrypt attribute is set. That is a deliberate decline, not an absent capability: the
        //data TPM2_NV_Read returns is the first sized response parameter, which Part 1, clause 18.1 makes
        //eligible for session encryption, but a counter value is public state (see this group's own remarks), so
        //encrypting it would protect nothing this group treats as secret. TPM2_NV_Increment reaches the same
        //no-attribute composition from the opposite direction - it has no parameter to encrypt at all.
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(CounterAuthSessionHash, device.Rng, pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!startResult.IsSuccess)
        {
            return startResult.Map<ulong>(_ => default);
        }

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, CounterAuthSessionHash, device.Rng, pool);
            session.SetAuthValue(counterAuth.Span, pool);

            return await ReadCounterOverSessionAsync(device, pool, registry, nvIndex, session, cancellationToken).ConfigureAwait(false);
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
                //Compensating cleanup only; see DefineCounterCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// Composes <c>TPM2_NV_Read</c> against <paramref name="nvIndex"/>'s counter window over a SALTED, unbound
    /// HMAC session whose authValue is <paramref name="counterAuth"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Counter Index to read.</param>
    /// <param name="counterAuth">The Index's authorization value.</param>
    /// <param name="tpmKey">The handle of a loaded RSA decrypt key the salt is encrypted to.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm.</param>
    /// <param name="encryptSalt">Encrypts the drawn salt via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the current count, or an error.</returns>
    private static async ValueTask<TpmResult<ulong>> ReadCounterSaltedCoreAsync(
        TpmDevice device,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateSaltedHmacSession(
            tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, CounterAuthSessionHash, encryptSalt, device.Rng, pool, cancellationToken).ConfigureAwait(false);

        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, salted.Input, [], null, pool, registry, cancellationToken).ConfigureAwait(false);

            if(!startResult.IsSuccess)
            {
                return startResult.Map<ulong>(_ => default);
            }

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                //Unbound (bindAuthValue empty) but salted: sessionKey = KDFa(salt, ...) (Part 1, clause 16.6.11,
                //equation 23), with counterAuth layered on as the session's authValue term (equation 24).
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, salted.Input.NonceCaller, started.NonceTPM,
                    CounterAuthSessionHash, device.Rng, pool, salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: cancellationToken).ConfigureAwait(false);
                session.SetAuthValue(counterAuth.Span, pool);

                return await ReadCounterOverSessionAsync(device, pool, registry, nvIndex, session, cancellationToken).ConfigureAwait(false);
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
                    //Compensating cleanup only; see DefineCounterCoreAsync's identical bracket for the rationale.
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
    /// Shared by <see cref="ReadCounterCoreAsync"/>, <see cref="ReadCounterSaltedCoreAsync"/>, and the tail of
    /// <see cref="IncrementCounterOverSessionAsync"/>: resolves the Index's current Name, then issues the
    /// Index-authorized <c>TPM2_NV_Read</c> of the full 8-octet counter window over the already-composed
    /// <paramref name="session"/>.
    /// </summary>
    /// <remarks>
    /// <c>TPM2_NV_Read</c> is two-handle (<c>@authHandle</c> = <c>nvIndex</c> authorizing itself, then
    /// <c>nvIndex</c>), so Name1 and Name2 of the cpHash are the same value (TPM 2.0 Library Part 1, clause 15.7,
    /// equation 15). An NV Index Name is hash-based, so the executor cannot derive it from the handle value - it is
    /// read back at the moment of use rather than cached across a command that may have moved it.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the NV_Read codec.</param>
    /// <param name="nvIndex">The Counter Index to read.</param>
    /// <param name="session">The already-composed authorization session (its authValue is the Index's authorization value).</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the current count, or an error.</returns>
    private static async ValueTask<TpmResult<ulong>> ReadCounterOverSessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        uint nvIndex,
        TpmSessionBase session,
        CancellationToken cancellationToken)
    {
        TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(nvIndex, cancellationToken).ConfigureAwait(false);
        if(!nameResult.IsSuccess)
        {
            return nameResult.Map<ulong>(_ => default);
        }

        using NvReadPublicResponse namePublic = nameResult.Value;
        ReadOnlyMemory<byte> indexName = namePublic.NvName.Span.ToArray();
        ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: CounterDataSize, Offset: 0);

        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], handleNames, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!readResult.IsSuccess)
        {
            return readResult.Map<ulong>(_ => default);
        }

        using NvReadResponse response = readResult.Value;

        return TpmResult<ulong>.Success(BinaryPrimitives.ReadUInt64BigEndian(response.Data));
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>ReadCounterWithPasswordAsync</c>: the plaintext-password
    /// composition.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Counter Index to read.</param>
    /// <param name="counterAuth">The Index's authorization value.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>A result containing the current count, or an error.</returns>
    private static async ValueTask<TpmResult<ulong>> ReadCounterWithPasswordCoreAsync(
        TpmDevice device,
        uint nvIndex,
        ReadOnlyMemory<byte> counterAuth,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

        using TpmPasswordSession session = TpmPasswordSession.Create(counterAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: CounterDataSize, Offset: 0);

        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, cancellationToken).ConfigureAwait(false);

        if(!readResult.IsSuccess)
        {
            return readResult.Map<ulong>(_ => default);
        }

        using NvReadResponse response = readResult.Value;

        return TpmResult<ulong>.Success(BinaryPrimitives.ReadUInt64BigEndian(response.Data));
    }

    /// <summary>
    /// Composes <c>TPM2_NV_UndefineSpace</c> against <paramref name="nvIndex"/> over an owner-bound HMAC session,
    /// authorized by the owner hierarchy's own authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="nvIndex">The Counter Index to undefine.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The undefine-space result.</returns>
    private static async ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefineCounterCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint nvIndex,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //No symmetric is negotiated: TPM2_NV_UndefineSpace carries no parameter this group encrypts, so a decrypt
        //or encrypt attribute on this session would have nothing to act on.
        TpmResult<TpmSession> sessionResult = await StartOwnerBoundSessionAsync(
            device, pool, registry, ownerAuth, cancellationToken).ConfigureAwait(false);

        if(!sessionResult.IsSuccess)
        {
            return sessionResult.Map<NvUndefineSpaceResponse>(_ => null!);
        }

        using TpmSession ownerSession = sessionResult.Value;
        uint sessionHandle = ownerSession.SessionHandle.Value;

        try
        {
            return await UndefineCounterOverSessionAsync(device, pool, registry, ownerSession, nvIndex, cancellationToken).ConfigureAwait(false);
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
                //Compensating cleanup only; see DefineCounterCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// The salted composition core for <c>UndefineCounterAsync</c>'s salted overload: undefines the Index over a
    /// session BOUND to the owner hierarchy and SALTED against <paramref name="tpmKey"/>.
    /// </summary>
    /// <remarks>
    /// The session key becomes <c>KDFa(ownerAuth ‖ salt, …)</c> (TPM 2.0 Library Part 1, clause 16.6.12, equation
    /// 25), so the command's authHMAC (equation 27, the bound entity authorizing itself) cannot be reproduced from
    /// the wire transcript even when the owner's own authorization value is empty.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="nvIndex">The Counter Index to undefine.</param>
    /// <param name="tpmKey">The handle of a loaded RSA decrypt key the salt is encrypted to.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm.</param>
    /// <param name="encryptSalt">Encrypts the drawn salt via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The undefine-space result.</returns>
    private static async ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefineCounterSaltedCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint nvIndex,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        TpmResult<TpmSession> sessionResult = await StartOwnerBoundAndSaltedSessionAsync(
            device, pool, registry, ownerAuth, tpmKey, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, encryptSalt, cancellationToken).ConfigureAwait(false);

        if(!sessionResult.IsSuccess)
        {
            return sessionResult.Map<NvUndefineSpaceResponse>(_ => null!);
        }

        using TpmSession ownerSession = sessionResult.Value;
        uint sessionHandle = ownerSession.SessionHandle.Value;

        try
        {
            return await UndefineCounterOverSessionAsync(device, pool, registry, ownerSession, nvIndex, cancellationToken).ConfigureAwait(false);
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
                //Compensating cleanup only; see DefineCounterCoreAsync's identical bracket for the rationale.
            }
        }
    }

    /// <summary>
    /// Shared by <see cref="UndefineCounterCoreAsync"/> and <see cref="UndefineCounterSaltedCoreAsync"/>: resolves
    /// the Index's current Name, then issues the owner-authorized <c>TPM2_NV_UndefineSpace</c> over the
    /// already-composed <paramref name="ownerSession"/>.
    /// </summary>
    /// <remarks>
    /// <c>@authHandle</c> = <c>TPM_RH_OWNER</c> is a permanent handle whose Name is the raw 4-octet handle value,
    /// which the executor derives itself, so its <c>handleNames</c> entry is left empty; <c>nvIndex</c> needs its
    /// real, current, hash-based Name (TPM 2.0 Library Part 1, clause 15.7, equation 15's Name2 term).
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry, already carrying the NV_UndefineSpace codec.</param>
    /// <param name="ownerSession">The already-composed owner-authorized session.</param>
    /// <param name="nvIndex">The Counter Index to undefine.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The undefine-space result.</returns>
    private static async ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefineCounterOverSessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        TpmSessionBase ownerSession,
        uint nvIndex,
        CancellationToken cancellationToken)
    {
        TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(nvIndex, cancellationToken).ConfigureAwait(false);
        if(!nameResult.IsSuccess)
        {
            return nameResult.Map<NvUndefineSpaceResponse>(_ => null!);
        }

        using NvReadPublicResponse namePublic = nameResult.Value;
        ReadOnlyMemory<byte>[] handleNames = [ReadOnlyMemory<byte>.Empty, namePublic.NvName.Span.ToArray()];

        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [ownerSession], handleNames, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The explicit low-protection opt-out core for <c>UndefineCounterWithPasswordAsync</c>: the plaintext-owner-
    /// password composition.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value.</param>
    /// <param name="nvIndex">The Counter Index to undefine.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The undefine-space result.</returns>
    private static async ValueTask<TpmResult<NvUndefineSpaceResponse>> UndefineCounterWithPasswordCoreAsync(
        TpmDevice device,
        ReadOnlyMemory<byte> ownerAuth,
        uint nvIndex,
        CancellationToken cancellationToken)
    {
        BaseMemoryPool pool = device.Pool;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(ownerAuth.Span, pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts and binds an HMAC session to the owner hierarchy - the shared bracket each owner-authorized Counter
    /// verb opens before its own command and closes (regardless of outcome) after.
    /// </summary>
    /// <remarks>
    /// Mirrors <c>Extensions/Pin</c>'s and <c>Extensions/Hierarchy</c>'s sibling helpers (TPM 2.0 Library Part 1,
    /// clause 16.6.10, equation 20): binding folds <paramref name="ownerAuth"/> into the session key via KDFa, so
    /// the per-command authHMAC's key genuinely incorporates the owner's authorization value rather than sending it
    /// in the clear the way <c>…WithPasswordAsync</c> does, and a session authorizing that same bound entity omits
    /// the authValue term entirely (equation 22). Those files are disjoint from this one, so the composition is
    /// duplicated rather than shared.
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry; must already carry the StartAuthSession and FlushContext codecs.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <param name="symmetric">
    /// The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for
    /// none. Only the define path supplies one (to encrypt <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> parameter); the
    /// undefine path leaves it unset, since its command carries no parameter this group encrypts.
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
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession((uint)TpmRh.TPM_RH_OWNER, CounterAuthSessionHash, device.Rng, pool, symmetric);
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
            //Library Part 1, clause 16.6.4.3, and CreateBoundAsync's own documented precondition): the TPM keys
            //equation 20 (Part 1, clause 16.6.10) on the stripped form, so an owner authValue ending in zero
            //octets would otherwise derive a session key the TPM never agrees with.
            TpmSession session = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), StripTrailingZeros(ownerAuth), startInput.NonceCaller, started.NonceTPM,
                CounterAuthSessionHash, device.Rng, pool, symmetric: symmetric, cancellationToken: cancellationToken).ConfigureAwait(false);

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
                //Compensating cleanup only; see DefineCounterCoreAsync's identical bracket for the rationale.
            }

            throw;
        }
    }

    /// <summary>
    /// Starts an HMAC session that is both BOUND to the owner hierarchy and SALTED against
    /// <paramref name="tpmKey"/> - the composition both salted owner-authorized overloads build their session from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The session key becomes <c>KDFa(ownerAuth ‖ salt, …)</c> (TPM 2.0 Library Part 1, clause 16.6.12, equation
    /// 25) rather than a KDFa over the authorization value alone, so the term an observer would have to guess is no
    /// longer the only unknown: the salt is RSA-OAEP-encrypted to <paramref name="tpmKey"/> (Part 1, clause 16.6.13)
    /// and only the TPM holding its private half can recover it.
    /// </para>
    /// <para>
    /// The salt is zeroized and returned to the pool as soon as <c>CreateBoundAsync</c> has folded it into the
    /// derived session key; nothing downstream needs it again. From the instant the TPM allocates the session slot
    /// the derivation reaches an asynchronous crypto seam under the caller's own token, and the caller's flush
    /// bracket only opens once this helper has RETURNED a session, so a failing derivation releases the slot
    /// itself - the same compensating bracket <see cref="StartOwnerBoundSessionAsync"/> opens, and for the same
    /// reason.
    /// </para>
    /// </remarks>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry; must already carry the StartAuthSession and FlushContext codecs.</param>
    /// <param name="ownerAuth">The owner hierarchy's authorization value, or empty when the owner has no auth set.</param>
    /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set - the salt is encrypted to its public modulus.</param>
    /// <param name="tpmKeyModulus">tpmKey's public modulus, unsigned big-endian.</param>
    /// <param name="tpmKeyExponent">tpmKey's public exponent.</param>
    /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm - sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
    /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="tpmKeyModulus"/> via RSA-OAEP.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <param name="symmetric">
    /// The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for
    /// none. Only the salted define supplies one (to encrypt <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> parameter).
    /// </param>
    /// <returns>A result containing the bound and salted session (the caller disposes it and flushes its handle), or the StartAuthSession error.</returns>
    private static async ValueTask<TpmResult<TpmSession>> StartOwnerBoundAndSaltedSessionAsync(
        TpmDevice device,
        BaseMemoryPool pool,
        TpmResponseRegistry registry,
        ReadOnlyMemory<byte> ownerAuth,
        uint tpmKey,
        ReadOnlyMemory<byte> tpmKeyModulus,
        uint tpmKeyExponent,
        TpmAlgIdConstants tpmKeyNameAlg,
        TpmRsaOaepEncryptDelegate encryptSalt,
        CancellationToken cancellationToken,
        TpmtSymDef? symmetric = null)
    {
        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateBoundAndSaltedHmacSession(
            tpmKey, (uint)TpmRh.TPM_RH_OWNER, tpmKeyModulus, tpmKeyExponent, tpmKeyNameAlg, CounterAuthSessionHash, encryptSalt, device.Rng, pool, cancellationToken, symmetric).ConfigureAwait(false);

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
                //Both terms of equation 25 (Part 1, clause 16.6.12) are present here: the stripped bind authValue
                //and the recovered salt. The session takes ownership of started's nonceTPM, so the response is
                //never disposed independently.
                TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), StripTrailingZeros(ownerAuth), salted.Input.NonceCaller, started.NonceTPM,
                    CounterAuthSessionHash, device.Rng, pool, symmetric: symmetric, salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: cancellationToken).ConfigureAwait(false);

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
                    //Compensating cleanup only; see DefineCounterCoreAsync's identical bracket for the rationale.
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
    /// Removes trailing zero octets from an authorization value before it is used in an authorization computation
    /// (TPM 2.0 Library Part 1, clause 16.6.4.3: "Trailing octets of zero are to be removed from any string before
    /// it is used as an authValue"; clause 16.6.5 states the same for the authValue term of the HMAC key).
    /// </summary>
    /// <remarks>
    /// The Index-authorized paths get this through <c>TpmSession.SetAuthValue</c>, which strips what it stores; the
    /// bind authValue reaches <c>TpmSession.CreateBoundAsync</c> as a plain parameter whose documented precondition
    /// is the stripped form, so this group strips it at the call site, exactly as <c>Extensions/Pin</c>'s and
    /// <c>Extensions/Hierarchy</c>'s sibling helpers do for their own bound sessions.
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

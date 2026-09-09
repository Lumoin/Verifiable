using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Factory methods for creating <see cref="StartAuthSessionInput"/> configurations.
/// </summary>
/// <remarks>
/// <para>
/// This extension class provides convenient factory methods for common session configurations.
/// Session types include:
/// </para>
/// <list type="bullet">
///   <item><description><strong>Unbound, unsalted:</strong> Simplest session with no cryptographic binding.</description></item>
///   <item><description><strong>Bound:</strong> Session cryptographically bound to an entity's authValue.</description></item>
///   <item><description><strong>Salted:</strong> Session uses encrypted salt for additional entropy.</description></item>
///   <item><description><strong>Bound and salted:</strong> Maximum security with both binding and salt.</description></item>
/// </list>
/// <para>
/// See TPM 2.0 Library Part 1, clause 16.6 for session binding and salting details.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with latest syntax.")]
public static class StartAuthSessionInputExtensions
{
    extension(StartAuthSessionInput)
    {
        /// <summary>
        /// Creates an unbound, unsalted HMAC session.
        /// </summary>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="symmetric">
        /// The symmetric algorithm to negotiate for session-based parameter encryption, or
        /// <see langword="null"/> for none (<see cref="TpmtSymDef.Null"/>). Pass
        /// <see cref="TpmtSymDef.Xor(TpmAlgIdConstants)"/> to enable XOR obfuscation; the per-command
        /// <c>decrypt</c>/<c>encrypt</c> attributes then select which parameters are protected. Note that an
        /// unbound, unsalted session has an empty session key, so parameter encryption derives only from the
        /// authValue (Part 1, clause 18.1); a bound or salted session is required to secure it for commands without an
        /// authValue.
        /// </param>
        /// <param name="rng">The entropy the caller's nonce is drawn from.</param>
        /// <param name="pool">The memory pool for the nonce scratch buffer.</param>
        /// <returns>A StartAuthSessionInput configured for an unbound, unsalted HMAC session.</returns>
        /// <remarks>
        /// <para>
        /// This is the simplest HMAC session configuration. The session provides integrity
        /// protection via cpHash/rpHash verification but has no cryptographic binding to
        /// any entity and no additional entropy from a salt.
        /// </para>
        /// <para>
        /// Use cases include:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>Auditing command execution.</description></item>
        ///   <item><description>Response integrity verification for commands that don't require authorization.</description></item>
        ///   <item><description>Testing and development scenarios.</description></item>
        /// </list>
        /// </remarks>
        public static StartAuthSessionInput CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants authHash, FillEntropyDelegate rng, BaseMemoryPool pool, TpmtSymDef? symmetric = null)
        {
            byte[] nonce = DrawNonce(authHash, rng, pool);

            return new StartAuthSessionInput
            {
                TpmKey = (uint)TpmRh.TPM_RH_NULL,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = nonce,
                EncryptedSalt = ReadOnlyMemory<byte>.Empty,
                SessionType = TpmSeConstants.TPM_SE_HMAC,
                AuthHash = authHash,
                Symmetric = symmetric ?? TpmtSymDef.Null
            };
        }

        /// <summary>
        /// Creates a bound, unsalted HMAC session against the supplied entity.
        /// </summary>
        /// <param name="bind">
        /// The handle of the entity to bind to (an object or NV index handle, or a permanent handle such as
        /// a hierarchy). The TPM reads this entity's authorization value when deriving the session key, so
        /// the caller must pass the same handle to the entity whose authValue it feeds to
        /// <see cref="Sessions.TpmSession.CreateBoundAsync"/>.
        /// </param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="symmetric">
        /// The symmetric algorithm to negotiate for session-based parameter encryption, or
        /// <see langword="null"/> for none (<see cref="TpmtSymDef.Null"/>). Pass
        /// <see cref="TpmtSymDef.Xor(TpmAlgIdConstants)"/> to enable XOR obfuscation; a bound session has a
        /// non-empty session key, so it secures parameter encryption even for commands without an authValue.
        /// </param>
        /// <param name="rng">The entropy the caller's nonce is drawn from.</param>
        /// <param name="pool">The memory pool for the nonce scratch buffer.</param>
        /// <returns>A StartAuthSessionInput configured for a bound, unsalted HMAC session.</returns>
        /// <remarks>
        /// <para>
        /// Binding folds the bind entity's authValue into the session key
        /// (<c>sessionKey = KDFa(authHash, bindAuthValue, "ATH", nonceTPM, nonceCaller, bits)</c>, Part 1
        /// clause 16.6.10 eq 20), so a session that subsequently authorizes the bind entity omits that authValue from
        /// the per-command HMAC key (Part 1, clause 16.6.10 eq 21/22).
        /// </para>
        /// <para>
        /// The generated <see cref="StartAuthSessionInput.NonceCaller"/> is the nonceCaller that the key
        /// derivation also consumes; read it back from the returned input and pass it verbatim to
        /// <see cref="Sessions.TpmSession.CreateBoundAsync"/> so the host and the TPM derive the same key.
        /// </para>
        /// </remarks>
        public static StartAuthSessionInput CreateBoundUnsaltedHmacSession(uint bind, TpmAlgIdConstants authHash, FillEntropyDelegate rng, BaseMemoryPool pool, TpmtSymDef? symmetric = null)
        {
            byte[] nonce = DrawNonce(authHash, rng, pool);

            return new StartAuthSessionInput
            {
                TpmKey = (uint)TpmRh.TPM_RH_NULL,
                Bind = bind,
                NonceCaller = nonce,
                EncryptedSalt = ReadOnlyMemory<byte>.Empty,
                SessionType = TpmSeConstants.TPM_SE_HMAC,
                AuthHash = authHash,
                Symmetric = symmetric ?? TpmtSymDef.Null
            };
        }

        /// <summary>
        /// Creates a salted, unbound HMAC session against an RSA <paramref name="tpmKey"/>.
        /// </summary>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set — the salt is encrypted to its public modulus.</param>
        /// <param name="modulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="exponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">
        /// tpmKey's own Name algorithm — sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1 (TPM 2.0
        /// Library Part 1, clause 43.10.1); independent of <paramref name="authHash"/>.
        /// </param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="encryptSalt">
        /// Encrypts the drawn salt to <paramref name="modulus"/> via RSA-OAEP (label <c>"SECRET"</c>, TPM 2.0
        /// Library Part 1, clause 16.6.13) — an explicit per-call delegate, no closure capture. A
        /// <c>TpmRsaSigningBackend.EncryptOaep</c> delegate instance composes directly.
        /// </param>
        /// <param name="rng">The entropy the caller's nonce and the drawn salt are sourced from.</param>
        /// <param name="pool">The memory pool for the drawn salt and the OAEP scratch buffer.</param>
        /// <param name="cancellationToken">A token observed across the OAEP encryption.</param>
        /// <param name="symmetric">
        /// The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.
        /// </param>
        /// <returns>
        /// The configured <see cref="StartAuthSessionInput"/> and the drawn salt (with its valid length) — the
        /// caller must pass <c>Salt.Memory[..SaltLength]</c> verbatim to
        /// <see cref="Sessions.TpmSession.CreateBoundAsync"/> and then dispose <c>Salt</c>.
        /// </returns>
        /// <remarks>
        /// The salt is drawn via the entropy provider at <c>digestSize(tpmKeyNameAlg)</c> octets (clause 43.10.1's
        /// cap); the wire <c>encryptedSalt</c> is the flat OAEP ciphertext (Part 2, Table 223/224).
        /// </remarks>
        public static ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateSaltedHmacSession(
            uint tpmKey,
            ReadOnlyMemory<byte> modulus,
            uint exponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmRsaOaepEncryptDelegate encryptSalt,
            FillEntropyDelegate rng,
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateRsaSaltedSessionCore(tpmKey, (uint)TpmRh.TPM_RH_NULL, modulus, exponent, tpmKeyNameAlg, authHash, TpmSeConstants.TPM_SE_HMAC, encryptSalt, rng, pool, symmetric, cancellationToken);

        /// <summary>
        /// Creates a salted, bound HMAC session against an RSA <paramref name="tpmKey"/> and the supplied bind entity.
        /// </summary>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set — the salt is encrypted to its public modulus.</param>
        /// <param name="bind">The handle of the entity to bind to, whose authorization value additionally seeds the session key.</param>
        /// <param name="modulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="exponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm — sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1; independent of <paramref name="authHash"/>.</param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="modulus"/> via RSA-OAEP (label <c>"SECRET"</c>) — an explicit per-call delegate, no closure capture.</param>
        /// <param name="rng">The entropy the caller's nonce and the drawn salt are sourced from.</param>
        /// <param name="pool">The memory pool for the drawn salt and the OAEP scratch buffer.</param>
        /// <param name="cancellationToken">A token observed across the OAEP encryption.</param>
        /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
        /// <returns>
        /// The configured <see cref="StartAuthSessionInput"/> and the drawn salt (with its valid length) — the
        /// caller must pass both <paramref name="bind"/>'s authorization value and <c>Salt.Memory[..SaltLength]</c>
        /// to <see cref="Sessions.TpmSession.CreateBoundAsync"/> and then dispose <c>Salt</c>.
        /// </returns>
        public static ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateBoundAndSaltedHmacSession(
            uint tpmKey,
            uint bind,
            ReadOnlyMemory<byte> modulus,
            uint exponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmRsaOaepEncryptDelegate encryptSalt,
            FillEntropyDelegate rng,
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateRsaSaltedSessionCore(tpmKey, bind, modulus, exponent, tpmKeyNameAlg, authHash, TpmSeConstants.TPM_SE_HMAC, encryptSalt, rng, pool, symmetric, cancellationToken);

        /// <summary>
        /// Creates a salted, unbound HMAC session against an ECC <paramref name="tpmKey"/>.
        /// </summary>
        /// <param name="tpmKey">The handle of a loaded ECC key with the decrypt attribute set — the salt is derived via ECDH against its public point.</param>
        /// <param name="tpmKeyPublicPoint">tpmKey's own exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</param>
        /// <param name="curve">The ECC curve tpmKey lives on.</param>
        /// <param name="tpmKeyNameAlg">
        /// tpmKey's own Name algorithm — sizes the drawn salt and keys <c>KDFe</c> (TPM 2.0 Library Part 1, clauses
        /// 44.7.1 and 16.6.13); independent of <paramref name="authHash"/> (a mixed-hash session is legal and must NOT
        /// leak <paramref name="authHash"/> into this derivation).
        /// </param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="generateEphemeralKey">
        /// Generates the one-time ephemeral key pair this session's initiator role requires (clause 44.7.1) — an
        /// explicit per-call delegate, no closure capture. A <c>TpmEccSigningBackend.GenerateKey</c> delegate
        /// instance composes directly.
        /// </param>
        /// <param name="computeSharedSecret">
        /// Computes the ECDH shared value <c>Z</c> between the ephemeral private scalar and
        /// <paramref name="tpmKeyPublicPoint"/> (clause 44.7.1) — an explicit per-call delegate, no closure capture.
        /// A <c>TpmEccSigningBackend.ComputeSharedSecret</c> delegate instance composes directly.
        /// </param>
        /// <param name="rng">The entropy the caller's nonce is sourced from.</param>
        /// <param name="pool">The memory pool for the ephemeral key, the shared value, and the derived salt.</param>
        /// <param name="cancellationToken">A token observed across the ECDH exchange and <c>KDFe</c>.</param>
        /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
        /// <returns>
        /// The configured <see cref="StartAuthSessionInput"/> and the derived salt (with its valid length) — the
        /// caller must pass <c>Salt.Memory[..SaltLength]</c> verbatim to
        /// <see cref="Sessions.TpmSession.CreateBoundAsync"/> and then dispose <c>Salt</c>.
        /// </returns>
        /// <remarks>
        /// The wire <c>encryptedSalt</c> is a marshaled <c>TPMS_ECC_POINT</c> (two size-prefixed coordinates)
        /// carrying the ephemeral public point — not a flat buffer (TPM 2.0 Library Part 2, Table 223/224).
        /// </remarks>
        public static ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateSaltedHmacSession(
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyPublicPoint,
            TpmEccCurveConstants curve,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmEccKeyGenerationDelegate generateEphemeralKey,
            TpmEccSharedSecretDelegate computeSharedSecret,
            FillEntropyDelegate rng,
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateEccSaltedSessionCore(tpmKey, (uint)TpmRh.TPM_RH_NULL, tpmKeyPublicPoint, curve, tpmKeyNameAlg, authHash, TpmSeConstants.TPM_SE_HMAC, generateEphemeralKey, computeSharedSecret, rng, pool, symmetric, cancellationToken);

        /// <summary>
        /// Creates a salted, bound HMAC session against an ECC <paramref name="tpmKey"/> and the supplied bind entity.
        /// </summary>
        /// <param name="tpmKey">The handle of a loaded ECC key with the decrypt attribute set — the salt is derived via ECDH against its public point.</param>
        /// <param name="bind">The handle of the entity to bind to, whose authorization value additionally seeds the session key.</param>
        /// <param name="tpmKeyPublicPoint">tpmKey's own exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</param>
        /// <param name="curve">The ECC curve tpmKey lives on.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm — sizes the drawn salt and keys <c>KDFe</c>; independent of <paramref name="authHash"/>.</param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="generateEphemeralKey">Generates the one-time ephemeral key pair this session's initiator role requires — an explicit per-call delegate, no closure capture.</param>
        /// <param name="computeSharedSecret">Computes the ECDH shared value <c>Z</c> — an explicit per-call delegate, no closure capture.</param>
        /// <param name="rng">The entropy the caller's nonce is sourced from.</param>
        /// <param name="pool">The memory pool for the ephemeral key, the shared value, and the derived salt.</param>
        /// <param name="cancellationToken">A token observed across the ECDH exchange and <c>KDFe</c>.</param>
        /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
        /// <returns>
        /// The configured <see cref="StartAuthSessionInput"/> and the derived salt (with its valid length) — the
        /// caller must pass both <paramref name="bind"/>'s authorization value and <c>Salt.Memory[..SaltLength]</c>
        /// to <see cref="Sessions.TpmSession.CreateBoundAsync"/> and then dispose <c>Salt</c>.
        /// </returns>
        public static ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateBoundAndSaltedHmacSession(
            uint tpmKey,
            uint bind,
            ReadOnlyMemory<byte> tpmKeyPublicPoint,
            TpmEccCurveConstants curve,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmEccKeyGenerationDelegate generateEphemeralKey,
            TpmEccSharedSecretDelegate computeSharedSecret,
            FillEntropyDelegate rng,
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateEccSaltedSessionCore(tpmKey, bind, tpmKeyPublicPoint, curve, tpmKeyNameAlg, authHash, TpmSeConstants.TPM_SE_HMAC, generateEphemeralKey, computeSharedSecret, rng, pool, symmetric, cancellationToken);

        /// <summary>
        /// Shared RSA salted-session core: draws the salt, OAEP-encrypts it, and frames the flat-ciphertext
        /// <c>encryptedSalt</c> — used by all four RSA salted factories (<paramref name="bind"/> = <c>TPM_RH_NULL</c>
        /// selects unbound; <paramref name="sessionType"/> selects HMAC or POLICY).
        /// </summary>
        /// <param name="tpmKey">The handle of the loaded RSA key the salt is encrypted to.</param>
        /// <param name="bind">The bind entity's handle, or <c>TPM_RH_NULL</c> for unbound.</param>
        /// <param name="modulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="exponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm — sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="sessionType">
        /// <see cref="TpmSeConstants.TPM_SE_HMAC"/> or <see cref="TpmSeConstants.TPM_SE_POLICY"/>. Per TPM 2.0
        /// Library Part 3, clause 11.1.1, sessionKey derivation (the salt handling this core performs) is
        /// identical for both — sessionType changes only the policy-session-context defaults StartAuthSession
        /// additionally sets, none of which this core is responsible for.
        /// </param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="modulus"/> via RSA-OAEP.</param>
        /// <param name="rng">The entropy the caller's nonce and the drawn salt are sourced from.</param>
        /// <param name="pool">The memory pool for the drawn salt and the OAEP scratch buffer.</param>
        /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
        /// <param name="cancellationToken">A token observed across the OAEP encryption.</param>
        /// <returns>The configured <see cref="StartAuthSessionInput"/> and the drawn salt (with its valid length).</returns>
        private static async ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateRsaSaltedSessionCore(
            uint tpmKey,
            uint bind,
            ReadOnlyMemory<byte> modulus,
            uint exponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmSeConstants sessionType,
            TpmRsaOaepEncryptDelegate encryptSalt,
            FillEntropyDelegate rng,
            BaseMemoryPool pool,
            TpmtSymDef? symmetric,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(encryptSalt);
            ArgumentNullException.ThrowIfNull(rng);
            ArgumentNullException.ThrowIfNull(pool);

            byte[] nonce = DrawNonce(authHash, rng, pool);

            int saltSize = GetDigestSize(tpmKeyNameAlg);
            IMemoryOwner<byte> salt = pool.Rent(saltSize, AllocationKind.Pinned);
            rng(salt.Memory.Span[..saltSize]);

            byte[] encryptedSalt;
            try
            {
                using IMemoryOwner<byte> ciphertext = await encryptSalt(
                    modulus, exponent, salt.Memory[..saltSize], SaltOaepLabel, tpmKeyNameAlg, tpmKeyNameAlg, pool, cancellationToken).ConfigureAwait(false);
                encryptedSalt = ciphertext.Memory.ToArray();
            }
            catch
            {
                salt.Memory.Span[..saltSize].Clear();
                salt.Dispose();

                throw;
            }

            var input = new StartAuthSessionInput
            {
                TpmKey = tpmKey,
                Bind = bind,
                NonceCaller = nonce,
                EncryptedSalt = encryptedSalt,
                SessionType = sessionType,
                AuthHash = authHash,
                Symmetric = symmetric ?? TpmtSymDef.Null
            };

            return (input, salt, saltSize);
        }

        /// <summary>
        /// Shared ECC salted-session core: generates the ephemeral key pair, ECDH-exchanges against tpmKey's
        /// static public point, derives the salt via <c>KDFe</c>, and frames <c>encryptedSalt</c> as a marshaled
        /// <c>TPMS_ECC_POINT</c> — used by all four ECC salted factories (<paramref name="bind"/> = <c>TPM_RH_NULL</c>
        /// selects unbound; <paramref name="sessionType"/> selects HMAC or POLICY).
        /// </summary>
        /// <param name="tpmKey">The handle of the loaded ECC key the salt is derived against.</param>
        /// <param name="bind">The bind entity's handle, or <c>TPM_RH_NULL</c> for unbound.</param>
        /// <param name="tpmKeyPublicPoint">tpmKey's own exported public point, SEC1 uncompressed.</param>
        /// <param name="curve">The ECC curve tpmKey lives on.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm — sizes the drawn salt and keys <c>KDFe</c>.</param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="sessionType">
        /// <see cref="TpmSeConstants.TPM_SE_HMAC"/> or <see cref="TpmSeConstants.TPM_SE_POLICY"/>. Per TPM 2.0
        /// Library Part 3, clause 11.1.1, sessionKey derivation (the ECDH+<c>KDFe</c> salt this core derives) is
        /// identical for both — sessionType changes only the policy-session-context defaults StartAuthSession
        /// additionally sets, none of which this core is responsible for.
        /// </param>
        /// <param name="generateEphemeralKey">Generates the one-time ephemeral key pair.</param>
        /// <param name="computeSharedSecret">Computes the ECDH shared value <c>Z</c>.</param>
        /// <param name="rng">The entropy the caller's nonce is sourced from.</param>
        /// <param name="pool">The memory pool for the ephemeral key, the shared value, and the derived salt.</param>
        /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
        /// <param name="cancellationToken">A token observed across the ECDH exchange and <c>KDFe</c>.</param>
        /// <returns>The configured <see cref="StartAuthSessionInput"/> and the derived salt (with its valid length).</returns>
        private static async ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateEccSaltedSessionCore(
            uint tpmKey,
            uint bind,
            ReadOnlyMemory<byte> tpmKeyPublicPoint,
            TpmEccCurveConstants curve,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmSeConstants sessionType,
            TpmEccKeyGenerationDelegate generateEphemeralKey,
            TpmEccSharedSecretDelegate computeSharedSecret,
            FillEntropyDelegate rng,
            BaseMemoryPool pool,
            TpmtSymDef? symmetric,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(generateEphemeralKey);
            ArgumentNullException.ThrowIfNull(computeSharedSecret);
            ArgumentNullException.ThrowIfNull(rng);
            ArgumentNullException.ThrowIfNull(pool);

            byte[] nonce = DrawNonce(authHash, rng, pool);

            int fieldWidth = (tpmKeyPublicPoint.Length - 1) / 2;
            int saltSize = GetDigestSize(tpmKeyNameAlg);

            using TpmGeneratedEccKey ephemeral = await generateEphemeralKey(curve, pool, cancellationToken).ConfigureAwait(false);

            //The ephemeral point and scalar ride their own pooled carriers straight through this method — the
            //using above keeps ephemeral (and its PublicPoint/PrivateScalar) alive across every await below, so
            //the SEC1 point and the two KDFe x-coordinate slices (partyUInfo = the ephemeral point's x,
            //partyVInfo = tpmKey's x) are Memory views over already-owned storage, never heap copies, and the
            //ephemeral scalar rides straight into computeSharedSecret with no separate copy to zero afterward —
            //ephemeral's own Dispose (the using above) already clears and releases its pinned PrivateScalar
            //carrier, mirroring TpmSimulator.EncapsulateEccAsync's established shape for the same hazard.
            ReadOnlyMemory<byte> ephemeralPoint = ephemeral.PublicPoint.AsReadOnlyMemory();
            ReadOnlySpan<byte> ephemeralXSpan = EllipticCurveUtilities.SliceXCoordinate(ephemeralPoint.Span);
            ReadOnlyMemory<byte> ephemeralX = ephemeralPoint.Slice(1, ephemeralXSpan.Length);
            ReadOnlySpan<byte> tpmKeyXSpan = EllipticCurveUtilities.SliceXCoordinate(tpmKeyPublicPoint.Span);
            ReadOnlyMemory<byte> tpmKeyX = tpmKeyPublicPoint.Slice(1, tpmKeyXSpan.Length);

            using IMemoryOwner<byte> sharedValue = await computeSharedSecret(
                ephemeral.PrivateScalar.AsReadOnlyMemory(), tpmKeyPublicPoint, curve, pool, cancellationToken).ConfigureAwait(false);

            IMemoryOwner<byte> salt = await Kdfe.DeriveAsync(
                ToHashAlgorithmName(tpmKeyNameAlg), sharedValue.Memory[..fieldWidth], "SECRET", ephemeralX, tpmKeyX, saltSize * 8, pool, cancellationToken).ConfigureAwait(false);

            using TpmsEccPoint eccPoint = TpmsEccPoint.Create(ephemeralPoint.Span.Slice(1, fieldWidth), ephemeralPoint.Span.Slice(1 + fieldWidth, fieldWidth), pool);
            int pointSize = eccPoint.GetSerializedSize();
            byte[] encryptedSalt = new byte[pointSize];
            var writer = new TpmWriter(encryptedSalt);
            eccPoint.WriteTo(ref writer);

            var input = new StartAuthSessionInput
            {
                TpmKey = tpmKey,
                Bind = bind,
                NonceCaller = nonce,
                EncryptedSalt = encryptedSalt,
                SessionType = sessionType,
                AuthHash = authHash,
                Symmetric = symmetric ?? TpmtSymDef.Null
            };

            return (input, salt, saltSize);
        }

        /// <summary>
        /// Maps a session/Name hash algorithm to its framework name, for the <c>KDFe</c> call the ECC salted arm drives.
        /// </summary>
        /// <param name="hashAlg">The hash algorithm.</param>
        /// <returns>The matching <see cref="HashAlgorithmName"/>.</returns>
        private static HashAlgorithmName ToHashAlgorithmName(TpmAlgIdConstants hashAlg) => hashAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA1 => HashAlgorithmName.SHA1,
            TpmAlgIdConstants.TPM_ALG_SHA256 => HashAlgorithmName.SHA256,
            TpmAlgIdConstants.TPM_ALG_SHA384 => HashAlgorithmName.SHA384,
            TpmAlgIdConstants.TPM_ALG_SHA512 => HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException($"Hash algorithm '{hashAlg}' is not supported.")
        };

        /// <summary>
        /// Creates an unbound, unsalted policy session.
        /// </summary>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="rng">The entropy the caller's nonce is drawn from.</param>
        /// <param name="pool">The memory pool for the nonce scratch buffer.</param>
        /// <returns>A StartAuthSessionInput configured for an unbound, unsalted policy session.</returns>
        /// <remarks>
        /// <para>
        /// Policy sessions are used for policy-based authorization. Commands update the
        /// session's policyDigest, and the final digest must match the object's authPolicy.
        /// </para>
        /// </remarks>
        public static StartAuthSessionInput CreateUnboundUnsaltedPolicySession(TpmAlgIdConstants authHash, FillEntropyDelegate rng, BaseMemoryPool pool)
        {
            byte[] nonce = DrawNonce(authHash, rng, pool);

            return new StartAuthSessionInput
            {
                TpmKey = (uint)TpmRh.TPM_RH_NULL,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = nonce,
                EncryptedSalt = ReadOnlyMemory<byte>.Empty,
                SessionType = TpmSeConstants.TPM_SE_POLICY,
                AuthHash = authHash
            };
        }

        /// <summary>
        /// Creates a salted, unbound policy session against an RSA <paramref name="tpmKey"/>.
        /// </summary>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set — the salt is encrypted to its public modulus.</param>
        /// <param name="modulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="exponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">
        /// tpmKey's own Name algorithm — sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1 (TPM 2.0
        /// Library Part 1, clause 43.10.1); independent of <paramref name="authHash"/>.
        /// </param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="encryptSalt">
        /// Encrypts the drawn salt to <paramref name="modulus"/> via RSA-OAEP (label <c>"SECRET"</c>, TPM 2.0
        /// Library Part 1, clause 16.6.13) — an explicit per-call delegate, no closure capture. A
        /// <c>TpmRsaSigningBackend.EncryptOaep</c> delegate instance composes directly.
        /// </param>
        /// <param name="rng">The entropy the caller's nonce and the drawn salt are sourced from.</param>
        /// <param name="pool">The memory pool for the drawn salt and the OAEP scratch buffer.</param>
        /// <param name="cancellationToken">A token observed across the OAEP encryption.</param>
        /// <param name="symmetric">
        /// The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.
        /// </param>
        /// <returns>
        /// The configured <see cref="StartAuthSessionInput"/> and the drawn salt (with its valid length) — the
        /// caller must pass <c>Salt.Memory[..SaltLength]</c> verbatim to
        /// <see cref="Sessions.TpmSession.CreateBoundAsync"/> and then dispose <c>Salt</c>.
        /// </returns>
        /// <remarks>
        /// <para>
        /// Per TPM 2.0 Library Part 3, clause 11.1.1, <c>TPM2_StartAuthSession</c> derives sessionKey identically
        /// for every sessionType — a salted POLICY session's key comes from the same OAEP-salt KDFa recipe (Part 1
        /// clause 16.6.11) as a salted HMAC session. What differs is the policy session's own context defaults: a fresh
        /// POLICY session is never "bound" in the auth-omission sense an HMAC session is (Part 1, clause 16.6.10's
        /// bind-entity-authValue-omission optimization) — whether the per-command authHMAC additionally layers the
        /// authorized entity's authValue on top of sessionKey (equations 26/27) is governed solely by the policy
        /// session's isAuthValueNeeded/isPasswordNeeded state (set by TPM2_PolicyAuthValue/TPM2_PolicyPassword),
        /// never by boundness. This unbound-salted factory has no bind entity, so sessionKey reduces to the salt
        /// term alone.
        /// </para>
        /// <para>
        /// The salt is drawn via the entropy provider at <c>digestSize(tpmKeyNameAlg)</c> octets (clause 43.10.1's
        /// cap); the wire <c>encryptedSalt</c> is the flat OAEP ciphertext (Part 2, Table 223/224).
        /// </para>
        /// </remarks>
        public static ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateSaltedPolicySession(
            uint tpmKey,
            ReadOnlyMemory<byte> modulus,
            uint exponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmRsaOaepEncryptDelegate encryptSalt,
            FillEntropyDelegate rng,
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateRsaSaltedSessionCore(tpmKey, (uint)TpmRh.TPM_RH_NULL, modulus, exponent, tpmKeyNameAlg, authHash, TpmSeConstants.TPM_SE_POLICY, encryptSalt, rng, pool, symmetric, cancellationToken);

        /// <summary>
        /// Creates a salted, bound policy session against an RSA <paramref name="tpmKey"/> and the supplied bind entity.
        /// </summary>
        /// <param name="tpmKey">The handle of a loaded RSA key with the decrypt attribute set — the salt is encrypted to its public modulus.</param>
        /// <param name="bind">The handle of the entity to bind to, whose authorization value additionally seeds the session key.</param>
        /// <param name="modulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="exponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm — sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1; independent of <paramref name="authHash"/>.</param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="modulus"/> via RSA-OAEP (label <c>"SECRET"</c>) — an explicit per-call delegate, no closure capture.</param>
        /// <param name="rng">The entropy the caller's nonce and the drawn salt are sourced from.</param>
        /// <param name="pool">The memory pool for the drawn salt and the OAEP scratch buffer.</param>
        /// <param name="cancellationToken">A token observed across the OAEP encryption.</param>
        /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
        /// <returns>
        /// The configured <see cref="StartAuthSessionInput"/> and the drawn salt (with its valid length) — the
        /// caller must pass both <paramref name="bind"/>'s authorization value and <c>Salt.Memory[..SaltLength]</c>
        /// to <see cref="Sessions.TpmSession.CreateBoundAsync"/> and then dispose <c>Salt</c>.
        /// </returns>
        /// <remarks>
        /// Per TPM 2.0 Library Part 3, clause 11.1.1, sessionKey derivation is identical to the RSA
        /// <c>CreateBoundAndSaltedHmacSession</c> overload — the KDFa key folds <paramref name="bind"/>'s authValue
        /// then the salt (Part 1, clause 16.6.12, equation 25) regardless of sessionType. The distinction is downstream
        /// of key derivation: a POLICY session is never "bound" in the auth-omission sense (Part 1, clause 16.6.10) —
        /// <paramref name="bind"/>'s authValue strengthens the derived sessionKey only, once, here. It is never
        /// folded a second time into the per-command authHMAC merely because the session is bound; that fold
        /// happens only when the policy session's isAuthValueNeeded/isPasswordNeeded flag is SET (equation 26, Part
        /// 1, clause 16.6.12), and is omitted entirely (equation 27) otherwise — an HMAC-session concept (binding omits
        /// the authValue term) does not carry over.
        /// </remarks>
        public static ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateBoundAndSaltedPolicySession(
            uint tpmKey,
            uint bind,
            ReadOnlyMemory<byte> modulus,
            uint exponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmRsaOaepEncryptDelegate encryptSalt,
            FillEntropyDelegate rng,
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateRsaSaltedSessionCore(tpmKey, bind, modulus, exponent, tpmKeyNameAlg, authHash, TpmSeConstants.TPM_SE_POLICY, encryptSalt, rng, pool, symmetric, cancellationToken);

        /// <summary>
        /// Creates a salted, unbound policy session against an ECC <paramref name="tpmKey"/>.
        /// </summary>
        /// <param name="tpmKey">The handle of a loaded ECC key with the decrypt attribute set — the salt is derived via ECDH against its public point.</param>
        /// <param name="tpmKeyPublicPoint">tpmKey's own exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</param>
        /// <param name="curve">The ECC curve tpmKey lives on.</param>
        /// <param name="tpmKeyNameAlg">
        /// tpmKey's own Name algorithm — sizes the drawn salt and keys <c>KDFe</c> (TPM 2.0 Library Part 1, clauses
        /// 44.7.1 and 16.6.13); independent of <paramref name="authHash"/> (a mixed-hash session is legal and must NOT
        /// leak <paramref name="authHash"/> into this derivation).
        /// </param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="generateEphemeralKey">
        /// Generates the one-time ephemeral key pair this session's initiator role requires (clause 44.7.1) — an
        /// explicit per-call delegate, no closure capture. A <c>TpmEccSigningBackend.GenerateKey</c> delegate
        /// instance composes directly.
        /// </param>
        /// <param name="computeSharedSecret">
        /// Computes the ECDH shared value <c>Z</c> between the ephemeral private scalar and
        /// <paramref name="tpmKeyPublicPoint"/> (clause 44.7.1) — an explicit per-call delegate, no closure capture.
        /// A <c>TpmEccSigningBackend.ComputeSharedSecret</c> delegate instance composes directly.
        /// </param>
        /// <param name="rng">The entropy the caller's nonce is sourced from.</param>
        /// <param name="pool">The memory pool for the ephemeral key, the shared value, and the derived salt.</param>
        /// <param name="cancellationToken">A token observed across the ECDH exchange and <c>KDFe</c>.</param>
        /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
        /// <returns>
        /// The configured <see cref="StartAuthSessionInput"/> and the derived salt (with its valid length) — the
        /// caller must pass <c>Salt.Memory[..SaltLength]</c> verbatim to
        /// <see cref="Sessions.TpmSession.CreateBoundAsync"/> and then dispose <c>Salt</c>.
        /// </returns>
        /// <remarks>
        /// <para>
        /// Per TPM 2.0 Library Part 3, clause 11.1.1, sessionKey derivation is identical for every sessionType —
        /// a salted POLICY session's key comes from the same ECDH+<c>KDFe</c> recipe as a salted HMAC session. A
        /// fresh POLICY session is never "bound" in the auth-omission sense an HMAC session is (Part 1, clause 16.6.10);
        /// this unbound-salted factory has no bind entity in the first place, so the point is moot here — see the
        /// ECC <c>CreateBoundAndSaltedPolicySession</c> overload for the case where it applies.
        /// </para>
        /// <para>
        /// The wire <c>encryptedSalt</c> is a marshaled <c>TPMS_ECC_POINT</c> (two size-prefixed coordinates)
        /// carrying the ephemeral public point — not a flat buffer (TPM 2.0 Library Part 2, Table 223/224).
        /// </para>
        /// </remarks>
        public static ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateSaltedPolicySession(
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyPublicPoint,
            TpmEccCurveConstants curve,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmEccKeyGenerationDelegate generateEphemeralKey,
            TpmEccSharedSecretDelegate computeSharedSecret,
            FillEntropyDelegate rng,
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateEccSaltedSessionCore(tpmKey, (uint)TpmRh.TPM_RH_NULL, tpmKeyPublicPoint, curve, tpmKeyNameAlg, authHash, TpmSeConstants.TPM_SE_POLICY, generateEphemeralKey, computeSharedSecret, rng, pool, symmetric, cancellationToken);

        /// <summary>
        /// Creates a salted, bound policy session against an ECC <paramref name="tpmKey"/> and the supplied bind entity.
        /// </summary>
        /// <param name="tpmKey">The handle of a loaded ECC key with the decrypt attribute set — the salt is derived via ECDH against its public point.</param>
        /// <param name="bind">The handle of the entity to bind to, whose authorization value additionally seeds the session key.</param>
        /// <param name="tpmKeyPublicPoint">tpmKey's own exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</param>
        /// <param name="curve">The ECC curve tpmKey lives on.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm — sizes the drawn salt and keys <c>KDFe</c>; independent of <paramref name="authHash"/>.</param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="generateEphemeralKey">Generates the one-time ephemeral key pair this session's initiator role requires — an explicit per-call delegate, no closure capture.</param>
        /// <param name="computeSharedSecret">Computes the ECDH shared value <c>Z</c> — an explicit per-call delegate, no closure capture.</param>
        /// <param name="rng">The entropy the caller's nonce is sourced from.</param>
        /// <param name="pool">The memory pool for the ephemeral key, the shared value, and the derived salt.</param>
        /// <param name="cancellationToken">A token observed across the ECDH exchange and <c>KDFe</c>.</param>
        /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
        /// <returns>
        /// The configured <see cref="StartAuthSessionInput"/> and the derived salt (with its valid length) — the
        /// caller must pass both <paramref name="bind"/>'s authorization value and <c>Salt.Memory[..SaltLength]</c>
        /// to <see cref="Sessions.TpmSession.CreateBoundAsync"/> and then dispose <c>Salt</c>.
        /// </returns>
        /// <remarks>
        /// Per TPM 2.0 Library Part 3, clause 11.1.1, sessionKey derivation is identical to the ECC
        /// <c>CreateBoundAndSaltedHmacSession</c> overload — <paramref name="bind"/>'s authValue folds into the
        /// KDFa key alongside the ECDH-derived salt regardless of sessionType. The distinction is downstream of key
        /// derivation: a POLICY session is never "bound" in the auth-omission sense (Part 1, clause 16.6.10) —
        /// <paramref name="bind"/>'s authValue strengthens the derived sessionKey only, once, here, and is never
        /// folded a second time into the per-command authHMAC merely because the session is bound. That fold
        /// happens only when the policy session's isAuthValueNeeded/isPasswordNeeded flag is SET (equation 26, Part
        /// 1, clause 16.6.12), and is omitted entirely (equation 27) otherwise.
        /// </remarks>
        public static ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateBoundAndSaltedPolicySession(
            uint tpmKey,
            uint bind,
            ReadOnlyMemory<byte> tpmKeyPublicPoint,
            TpmEccCurveConstants curve,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmEccKeyGenerationDelegate generateEphemeralKey,
            TpmEccSharedSecretDelegate computeSharedSecret,
            FillEntropyDelegate rng,
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateEccSaltedSessionCore(tpmKey, bind, tpmKeyPublicPoint, curve, tpmKeyNameAlg, authHash, TpmSeConstants.TPM_SE_POLICY, generateEphemeralKey, computeSharedSecret, rng, pool, symmetric, cancellationToken);

        /// <summary>
        /// Creates a trial policy session.
        /// </summary>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="rng">The entropy the caller's nonce is drawn from.</param>
        /// <param name="pool">The memory pool for the nonce scratch buffer.</param>
        /// <returns>A StartAuthSessionInput configured for a trial policy session.</returns>
        /// <remarks>
        /// <para>
        /// Trial sessions are used to compute policy digests without actually authorizing
        /// any commands. The resulting policyDigest can then be used when creating objects
        /// with policy-based authorization.
        /// </para>
        /// </remarks>
        public static StartAuthSessionInput CreateTrialPolicySession(TpmAlgIdConstants authHash, FillEntropyDelegate rng, BaseMemoryPool pool)
        {
            byte[] nonce = DrawNonce(authHash, rng, pool);

            return new StartAuthSessionInput
            {
                TpmKey = (uint)TpmRh.TPM_RH_NULL,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = nonce,
                EncryptedSalt = ReadOnlyMemory<byte>.Empty,
                SessionType = TpmSeConstants.TPM_SE_TRIAL,
                AuthHash = authHash
            };
        }

        /// <summary>
        /// Draws a fresh <c>nonceCaller</c> of <paramref name="authHash"/>'s digest size from
        /// <paramref name="rng"/>, through a pooled scratch rental, into the plain array
        /// <see cref="StartAuthSessionInput.NonceCaller"/> carries (the record has no disposable
        /// component of its own, so the final octets are copied out of the rental before it is released).
        /// </summary>
        /// <param name="authHash">The session hash algorithm the nonce is sized for.</param>
        /// <param name="rng">The entropy source the nonce bytes are drawn from.</param>
        /// <param name="pool">The memory pool the scratch rental comes from.</param>
        /// <returns>The drawn nonce bytes.</returns>
        private static byte[] DrawNonce(TpmAlgIdConstants authHash, FillEntropyDelegate rng, BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(rng);
            ArgumentNullException.ThrowIfNull(pool);

            int size = GetDigestSize(authHash);
            using IMemoryOwner<byte> owner = pool.Rent(size);
            Span<byte> span = owner.Memory.Span[..size];
            rng(span);

            return span.ToArray();
        }

        private static int GetDigestSize(TpmAlgIdConstants authHash) => authHash switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA1 => 20,
            TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
            TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
            TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
            TpmAlgIdConstants.TPM_ALG_SM3_256 => 32,
            _ => 32 //Default to SHA-256 size.
        };
    }

    /// <summary>
    /// The session-salt OAEP label (TPM 2.0 Library Part 1, clause 16.6.13): <c>"SECRET"</c> plus the trailing NUL
    /// octet the <c>lhash</c> digest input requires as part of <c>L</c> (OAEP's own convention, distinct from
    /// KDFa/KDFe's auto-appended label terminator). Declared outside the <c>extension(StartAuthSessionInput)</c>
    /// block (a static property with an initializer is not permitted inside one) but still accessible to it as
    /// an ordinary sibling class member.
    /// </summary>
    private static ReadOnlyMemory<byte> SaltOaepLabel { get; } = "SECRET\0"u8.ToArray();
}

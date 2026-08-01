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
/// See TPM 2.0 Part 1, Section 17.6 for session binding and salting details.
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
        /// authValue (Part 1 §19.1); a bound or salted session is required to secure it for commands without an
        /// authValue.
        /// </param>
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
        public static StartAuthSessionInput CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants authHash, TpmtSymDef? symmetric = null)
        {
            byte[] nonce = new byte[GetDigestSize(authHash)];
            RandomNumberGenerator.Fill(nonce);

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
        /// <returns>A StartAuthSessionInput configured for a bound, unsalted HMAC session.</returns>
        /// <remarks>
        /// <para>
        /// Binding folds the bind entity's authValue into the session key
        /// (<c>sessionKey = KDFa(authHash, bindAuthValue, "ATH", nonceTPM, nonceCaller, bits)</c>, Part 1
        /// §17.6.10 eq 20), so a session that subsequently authorizes the bind entity omits that authValue from
        /// the per-command HMAC key (Part 1 §17.6.10 eq 21/22).
        /// </para>
        /// <para>
        /// The generated <see cref="StartAuthSessionInput.NonceCaller"/> is the nonceCaller that the key
        /// derivation also consumes; read it back from the returned input and pass it verbatim to
        /// <see cref="Sessions.TpmSession.CreateBoundAsync"/> so the host and the TPM derive the same key.
        /// </para>
        /// </remarks>
        public static StartAuthSessionInput CreateBoundUnsaltedHmacSession(uint bind, TpmAlgIdConstants authHash, TpmtSymDef? symmetric = null)
        {
            byte[] nonce = new byte[GetDigestSize(authHash)];
            RandomNumberGenerator.Fill(nonce);

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
        /// Library Part 1, Annex B.10.1); independent of <paramref name="authHash"/>.
        /// </param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="encryptSalt">
        /// Encrypts the drawn salt to <paramref name="modulus"/> via RSA-OAEP (label <c>"SECRET"</c>, TPM 2.0
        /// Library Part 1, Annex B.10.2) — an explicit per-call delegate, no closure capture. A
        /// <c>TpmRsaSigningBackend.EncryptOaep</c> delegate instance composes directly.
        /// </param>
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
        /// The salt is drawn via the entropy provider at <c>digestSize(tpmKeyNameAlg)</c> octets (Annex B.10.1's
        /// cap); the wire <c>encryptedSalt</c> is the flat OAEP ciphertext (Part 2, Table 190/191).
        /// </remarks>
        public static ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateSaltedHmacSession(
            uint tpmKey,
            ReadOnlyMemory<byte> modulus,
            uint exponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmRsaOaepEncryptDelegate encryptSalt,
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateRsaSaltedHmacSessionCore(tpmKey, (uint)TpmRh.TPM_RH_NULL, modulus, exponent, tpmKeyNameAlg, authHash, encryptSalt, pool, symmetric, cancellationToken);

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
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateRsaSaltedHmacSessionCore(tpmKey, bind, modulus, exponent, tpmKeyNameAlg, authHash, encryptSalt, pool, symmetric, cancellationToken);

        /// <summary>
        /// Creates a salted, unbound HMAC session against an ECC <paramref name="tpmKey"/>.
        /// </summary>
        /// <param name="tpmKey">The handle of a loaded ECC key with the decrypt attribute set — the salt is derived via ECDH against its public point.</param>
        /// <param name="tpmKeyPublicPoint">tpmKey's own exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</param>
        /// <param name="curve">The ECC curve tpmKey lives on.</param>
        /// <param name="tpmKeyNameAlg">
        /// tpmKey's own Name algorithm — sizes the drawn salt and keys <c>KDFe</c> (TPM 2.0 Library Part 1, Annex
        /// C.6.1/C.6.2); independent of <paramref name="authHash"/> (a mixed-hash session is legal and must NOT
        /// leak <paramref name="authHash"/> into this derivation).
        /// </param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="generateEphemeralKey">
        /// Generates the one-time ephemeral key pair this session's initiator role requires (Annex C.6.1) — an
        /// explicit per-call delegate, no closure capture. A <c>TpmEccSigningBackend.GenerateKey</c> delegate
        /// instance composes directly.
        /// </param>
        /// <param name="computeSharedSecret">
        /// Computes the ECDH shared value <c>Z</c> between the ephemeral private scalar and
        /// <paramref name="tpmKeyPublicPoint"/> (Annex C.6.1) — an explicit per-call delegate, no closure capture.
        /// A <c>TpmEccSigningBackend.ComputeSharedSecret</c> delegate instance composes directly.
        /// </param>
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
        /// carrying the ephemeral public point — not a flat buffer (TPM 2.0 Library Part 2, Table 190/191).
        /// </remarks>
        public static ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateSaltedHmacSession(
            uint tpmKey,
            ReadOnlyMemory<byte> tpmKeyPublicPoint,
            TpmEccCurveConstants curve,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmEccKeyGenerationDelegate generateEphemeralKey,
            TpmEccSharedSecretDelegate computeSharedSecret,
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateEccSaltedHmacSessionCore(tpmKey, (uint)TpmRh.TPM_RH_NULL, tpmKeyPublicPoint, curve, tpmKeyNameAlg, authHash, generateEphemeralKey, computeSharedSecret, pool, symmetric, cancellationToken);

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
            BaseMemoryPool pool,
            CancellationToken cancellationToken,
            TpmtSymDef? symmetric = null) =>
            CreateEccSaltedHmacSessionCore(tpmKey, bind, tpmKeyPublicPoint, curve, tpmKeyNameAlg, authHash, generateEphemeralKey, computeSharedSecret, pool, symmetric, cancellationToken);

        /// <summary>
        /// Shared RSA salted-session core: draws the salt, OAEP-encrypts it, and frames the flat-ciphertext
        /// <c>encryptedSalt</c> — used by both the unbound and bound RSA factories (<paramref name="bind"/> =
        /// <c>TPM_RH_NULL</c> selects unbound).
        /// </summary>
        /// <param name="tpmKey">The handle of the loaded RSA key the salt is encrypted to.</param>
        /// <param name="bind">The bind entity's handle, or <c>TPM_RH_NULL</c> for unbound.</param>
        /// <param name="modulus">tpmKey's public modulus, unsigned big-endian.</param>
        /// <param name="exponent">tpmKey's public exponent.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm — sizes the drawn salt and drives OAEP's <c>lhash</c>/MGF1.</param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="encryptSalt">Encrypts the drawn salt to <paramref name="modulus"/> via RSA-OAEP.</param>
        /// <param name="pool">The memory pool for the drawn salt and the OAEP scratch buffer.</param>
        /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
        /// <param name="cancellationToken">A token observed across the OAEP encryption.</param>
        /// <returns>The configured <see cref="StartAuthSessionInput"/> and the drawn salt (with its valid length).</returns>
        private static async ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateRsaSaltedHmacSessionCore(
            uint tpmKey,
            uint bind,
            ReadOnlyMemory<byte> modulus,
            uint exponent,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmRsaOaepEncryptDelegate encryptSalt,
            BaseMemoryPool pool,
            TpmtSymDef? symmetric,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(encryptSalt);
            ArgumentNullException.ThrowIfNull(pool);

            byte[] nonce = new byte[GetDigestSize(authHash)];
            RandomNumberGenerator.Fill(nonce);

            int saltSize = GetDigestSize(tpmKeyNameAlg);
            IMemoryOwner<byte> salt = pool.Rent(saltSize);
            RandomNumberGenerator.Fill(salt.Memory.Span[..saltSize]);

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
                SessionType = TpmSeConstants.TPM_SE_HMAC,
                AuthHash = authHash,
                Symmetric = symmetric ?? TpmtSymDef.Null
            };

            return (input, salt, saltSize);
        }

        /// <summary>
        /// Shared ECC salted-session core: generates the ephemeral key pair, ECDH-exchanges against tpmKey's
        /// static public point, derives the salt via <c>KDFe</c>, and frames <c>encryptedSalt</c> as a marshaled
        /// <c>TPMS_ECC_POINT</c> — used by both the unbound and bound ECC factories (<paramref name="bind"/> =
        /// <c>TPM_RH_NULL</c> selects unbound).
        /// </summary>
        /// <param name="tpmKey">The handle of the loaded ECC key the salt is derived against.</param>
        /// <param name="bind">The bind entity's handle, or <c>TPM_RH_NULL</c> for unbound.</param>
        /// <param name="tpmKeyPublicPoint">tpmKey's own exported public point, SEC1 uncompressed.</param>
        /// <param name="curve">The ECC curve tpmKey lives on.</param>
        /// <param name="tpmKeyNameAlg">tpmKey's own Name algorithm — sizes the drawn salt and keys <c>KDFe</c>.</param>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <param name="generateEphemeralKey">Generates the one-time ephemeral key pair.</param>
        /// <param name="computeSharedSecret">Computes the ECDH shared value <c>Z</c>.</param>
        /// <param name="pool">The memory pool for the ephemeral key, the shared value, and the derived salt.</param>
        /// <param name="symmetric">The symmetric algorithm to negotiate for session-based parameter encryption, or <see langword="null"/> for none.</param>
        /// <param name="cancellationToken">A token observed across the ECDH exchange and <c>KDFe</c>.</param>
        /// <returns>The configured <see cref="StartAuthSessionInput"/> and the derived salt (with its valid length).</returns>
        private static async ValueTask<(StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength)> CreateEccSaltedHmacSessionCore(
            uint tpmKey,
            uint bind,
            ReadOnlyMemory<byte> tpmKeyPublicPoint,
            TpmEccCurveConstants curve,
            TpmAlgIdConstants tpmKeyNameAlg,
            TpmAlgIdConstants authHash,
            TpmEccKeyGenerationDelegate generateEphemeralKey,
            TpmEccSharedSecretDelegate computeSharedSecret,
            BaseMemoryPool pool,
            TpmtSymDef? symmetric,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(generateEphemeralKey);
            ArgumentNullException.ThrowIfNull(computeSharedSecret);
            ArgumentNullException.ThrowIfNull(pool);

            byte[] nonce = new byte[GetDigestSize(authHash)];
            RandomNumberGenerator.Fill(nonce);

            int fieldWidth = (tpmKeyPublicPoint.Length - 1) / 2;
            int saltSize = GetDigestSize(tpmKeyNameAlg);

            using TpmGeneratedEccKey ephemeral = await generateEphemeralKey(curve, pool, cancellationToken).ConfigureAwait(false);

            byte[] ephemeralPoint = ephemeral.PublicPoint.AsReadOnlySpan().ToArray();
            byte[] ephemeralScalar = ephemeral.PrivateScalar.AsReadOnlySpan().ToArray();
            byte[] ephemeralX = EllipticCurveUtilities.SliceXCoordinate(ephemeralPoint).ToArray();
            byte[] tpmKeyX = EllipticCurveUtilities.SliceXCoordinate(tpmKeyPublicPoint.Span).ToArray();

            IMemoryOwner<byte> salt;
            try
            {
                using IMemoryOwner<byte> sharedValue = await computeSharedSecret(
                    ephemeralScalar, tpmKeyPublicPoint, curve, pool, cancellationToken).ConfigureAwait(false);

                salt = await Kdfe.DeriveAsync(
                    ToHashAlgorithmName(tpmKeyNameAlg), sharedValue.Memory[..fieldWidth], "SECRET", ephemeralX, tpmKeyX, saltSize * 8, pool, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ephemeralScalar);
            }

            using TpmsEccPoint eccPoint = TpmsEccPoint.Create(ephemeralPoint.AsSpan(1, fieldWidth), ephemeralPoint.AsSpan(1 + fieldWidth, fieldWidth), pool);
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
                SessionType = TpmSeConstants.TPM_SE_HMAC,
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
        /// <returns>A StartAuthSessionInput configured for an unbound, unsalted policy session.</returns>
        /// <remarks>
        /// <para>
        /// Policy sessions are used for policy-based authorization. Commands update the
        /// session's policyDigest, and the final digest must match the object's authPolicy.
        /// </para>
        /// </remarks>
        public static StartAuthSessionInput CreateUnboundUnsaltedPolicySession(TpmAlgIdConstants authHash)
        {
            byte[] nonce = new byte[GetDigestSize(authHash)];
            RandomNumberGenerator.Fill(nonce);

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
        /// Creates a trial policy session.
        /// </summary>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <returns>A StartAuthSessionInput configured for a trial policy session.</returns>
        /// <remarks>
        /// <para>
        /// Trial sessions are used to compute policy digests without actually authorizing
        /// any commands. The resulting policyDigest can then be used when creating objects
        /// with policy-based authorization.
        /// </para>
        /// </remarks>
        public static StartAuthSessionInput CreateTrialPolicySession(TpmAlgIdConstants authHash)
        {
            byte[] nonce = new byte[GetDigestSize(authHash)];
            RandomNumberGenerator.Fill(nonce);

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
    /// The session-salt OAEP label (TPM 2.0 Library Part 1, Annex B.10.2): <c>"SECRET"</c> plus the trailing NUL
    /// octet the <c>lhash</c> digest input requires as part of <c>L</c> (OAEP's own convention, distinct from
    /// KDFa/KDFe's auto-appended label terminator). Declared outside the <c>extension(StartAuthSessionInput)</c>
    /// block (a static property with an initializer is not permitted inside one) but still accessible to it as
    /// an ordinary sibling class member.
    /// </summary>
    private static ReadOnlyMemory<byte> SaltOaepLabel { get; } = "SECRET\0"u8.ToArray();
}

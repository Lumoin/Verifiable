using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// Extension methods that expose ECDH key agreement operations on
/// <see cref="PublicKeyMemory"/> and <see cref="PrivateKeyMemory"/>.
/// </summary>
/// <remarks>
/// <para>
/// Key agreement is a prerequisite to AEAD encryption but is not AEAD itself.
/// These extensions live in <c>Verifiable.Cryptography</c> rather than the
/// <c>Aead</c> sub-namespace because the types they extend — <see cref="PublicKeyMemory"/>
/// and <see cref="PrivateKeyMemory"/> — belong at the cryptography layer, not the
/// message-format layer.
/// </para>
/// <para>
/// The encrypt and decrypt flows are symmetric:
/// </para>
/// <list type="bullet">
/// <item><description>
/// Encrypt: <c>PublicKeyMemory.AgreementEncryptAsync</c> →
/// <see cref="EphemeralKeyAgreementResult"/> → derive CEK →
/// AEAD encrypt → <see cref="AeadEncryptResult"/>.
/// </description></item>
/// <item><description>
/// Decrypt: <c>PrivateKeyMemory.AgreementDecryptAsync</c> →
/// <see cref="SharedSecret"/> → derive CEK →
/// AEAD decrypt → <see cref="DecryptedContent"/>.
/// </description></item>
/// </list>
/// <para>
/// Higher-level layers (e.g. <c>Verifiable.JCose</c>) orchestrate these steps,
/// inserting the AAD computation between key agreement and symmetric encryption.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "The analyzer is not yet up to date with extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case",
    Justification = "The analyzer is not yet up to date with extension syntax.")]
public static class KeyAgreementExtensions
{
    extension(PublicKeyMemory publicKey)
    {
        /// <summary>
        /// Performs ECDH key agreement on the encrypt side using the supplied delegate.
        /// </summary>
        /// <param name="agreementDelegate">The key agreement delegate.</param>
        /// <param name="pool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The ephemeral key agreement result containing the shared secret and the
        /// ephemeral public key in uncompressed encoding. The caller owns and must dispose.
        /// </returns>
        public ValueTask<EphemeralKeyAgreementResult> AgreementEncryptAsync(
            KeyAgreementEncryptDelegate agreementDelegate,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(agreementDelegate);
            ArgumentNullException.ThrowIfNull(pool);

            return agreementDelegate(publicKey, pool, cancellationToken);
        }


        /// <summary>
        /// Performs ECDH key agreement on the encrypt side by resolving the delegate
        /// from the registry using the key's <see cref="Tag"/>.
        /// </summary>
        /// <param name="pool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The ephemeral key agreement result. The caller owns and must dispose.
        /// </returns>
        public ValueTask<EphemeralKeyAgreementResult> AgreementEncryptAsync(
            MemoryPool<byte> pool,
            CancellationToken cancellationToken = default)
        {
            CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
            Purpose purpose = publicKey.Tag.Get<Purpose>();
            KeyAgreementEncryptDelegate agreementDelegate =
                KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAgreementEncrypt(
                    algorithm, purpose);

            return publicKey.AgreementEncryptAsync(agreementDelegate, pool, cancellationToken);
        }
    }


    extension(PrivateKeyMemory privateKey)
    {
        /// <summary>
        /// Performs ECDH key agreement on the decrypt side using the supplied delegate.
        /// </summary>
        /// <param name="epk">
        /// The sender's ephemeral public key in uncompressed encoding:
        /// <c>0x04 || X || Y</c>.
        /// </param>
        /// <param name="agreementDelegate">The key agreement delegate.</param>
        /// <param name="pool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The shared secret Z. The caller owns and must dispose.</returns>
        public ValueTask<SharedSecret> AgreementDecryptAsync(
            PublicKeyMemory epk,
            KeyAgreementDecryptDelegate agreementDelegate,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(epk);
            ArgumentNullException.ThrowIfNull(agreementDelegate);
            ArgumentNullException.ThrowIfNull(pool);

            return privateKey.WithKeyBytesAsync(
                static (keyBytes, state) =>
                    state.Delegate(keyBytes, state.Epk, state.Pool, state.CancellationToken),
                (Delegate: agreementDelegate,
                 Epk: epk,
                 Pool: pool,
                 CancellationToken: cancellationToken));
        }


        /// <summary>
        /// Performs ECDH key agreement on the decrypt side by resolving the delegate
        /// from the registry using the key's <see cref="Tag"/>.
        /// </summary>
        /// <param name="epk">
        /// The sender's ephemeral public key in uncompressed encoding:
        /// <c>0x04 || X || Y</c>.
        /// </param>
        /// <param name="pool">Memory pool for allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The shared secret Z. The caller owns and must dispose.</returns>
        public ValueTask<SharedSecret> AgreementDecryptAsync(
            PublicKeyMemory epk,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken = default)
        {
            CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
            Purpose purpose = privateKey.Tag.Get<Purpose>();
            KeyAgreementDecryptDelegate agreementDelegate =
                KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAgreementDecrypt(
                    algorithm, purpose);

            return privateKey.AgreementDecryptAsync(epk, agreementDelegate, pool, cancellationToken);
        }
    }
}

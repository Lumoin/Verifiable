using System.Buffers;
using System.Collections.Frozen;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// Represents a private cryptographic key with bound signing functionality.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class combines private key material with a signing function, creating a ready-to-use
    /// key object. Once constructed, the key can sign data without requiring the caller to
    /// provide the signing function each time.
    /// </para>
    /// <para>
    /// Two constructor overloads are provided:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>Generic function constructor</strong> - Accepts <see cref="SigningFunction{TPrivateKeyBytes, TDataToSign, TResult}"/>
    /// for maximum flexibility and type safety.
    /// </description></item>
    /// <item><description>
    /// <strong>Registry delegate constructor</strong> - Accepts <see cref="SigningDelegate"/> directly,
    /// allowing seamless use of functions from cryptographic driver implementations.
    /// </description></item>
    /// </list>
    /// </remarks>
    /// <seealso cref="PrivateKeyMemory"/>
    /// <seealso cref="PublicKey"/>
    /// <seealso cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    public class PrivateKey: SensitiveMemoryKey
    {
        /// <summary>
        /// The signing delegate that calculates signatures on data using this key.
        /// </summary>
        private readonly SigningDelegate signingDelegate;

        /// <summary>
        /// The default context to use for signing operations when none is provided.
        /// </summary>
        private readonly FrozenDictionary<string, object>? defaultContext;


        /// <summary>
        /// Private key constructor using a <see cref="SigningDelegate"/>.
        /// </summary>
        /// <param name="privateKeyMaterial">The private key bytes of this key.</param>
        /// <param name="id">The identifier for this private key.</param>
        /// <param name="signingDelegate">The delegate this key uses for signing.</param>
        /// <param name="context">Optional default context for signing operations.</param>
        public PrivateKey(PrivateKeyMemory privateKeyMaterial, string id, SigningDelegate signingDelegate, FrozenDictionary<string, object>? context = null): base(privateKeyMaterial, id)
        {
            ArgumentNullException.ThrowIfNull(privateKeyMaterial, nameof(privateKeyMaterial));
            ArgumentException.ThrowIfNullOrEmpty(id, nameof(id));
            ArgumentNullException.ThrowIfNull(signingDelegate, nameof(signingDelegate));

            this.signingDelegate = signingDelegate;
            this.defaultContext = context;
        }


        /// <summary>
        /// A convenience getter to return <see cref="PrivateKeyMemory"/> instead of a <see cref="SensitiveMemory"/>.
        /// </summary>
        /// <remarks>Since this is a private key, this stores private key memory material. This is a type cast.</remarks>
        protected new PrivateKeyMemory KeyMaterial { get { return (PrivateKeyMemory)base.KeyMaterial; } }


        /// <summary>
        /// Signs data given by <paramref name="dataToSign"/> using this key.
        /// </summary>
        /// <param name="dataToSign">The data to be signed.</param>
        /// <param name="signaturePool">The pool from which to reserve the memory for the signature.</param>
        /// <param name="context">Optional context for this signing operation. If not provided,
        /// the default context from construction is used.</param>
        /// <returns>The signature of the data.</returns>
        public ValueTask<Signature> SignAsync(ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
        {
            return KeyMaterial.WithKeyBytesAsync(async (privateKeyBytes, dataToSign, signaturePool) =>
                await signingDelegate(privateKeyBytes, dataToSign, signaturePool, context ?? defaultContext), dataToSign, signaturePool);
        }
    }
}

using System.Collections.Frozen;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// Represents a public cryptographic key with bound verification functionality.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class combines public key material with a verification function, creating a ready-to-use
    /// key object. Once constructed, the key can verify signatures without requiring the caller to
    /// provide the verification function each time.
    /// </para>
    /// <para>
    /// Two constructor overloads are provided:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>Generic function constructor</strong> - Accepts <see cref="VerificationFunction{TVerificationContext, TDataToVerify, TSignature, TResult}"/>
    /// for maximum flexibility and type safety.
    /// </description></item>
    /// <item><description>
    /// <strong>Registry delegate constructor</strong> - Accepts <see cref="Cryptography.VerificationDelegate"/> directly,
    /// allowing seamless use of functions from cryptographic driver implementations.
    /// </description></item>
    /// </list>
    /// </remarks>
    /// <seealso cref="PublicKeyMemory"/>
    /// <seealso cref="PrivateKey"/>
    /// <seealso cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    public class PublicKey: SensitiveMemoryKey
    {
        /// <summary>
        /// The verification delegate that verifies signatures against data using this key.
        /// </summary>
        private VerificationDelegate VerificationDelegate { get; }

        /// <summary>
        /// The default context to use for verification operations when none is provided.
        /// </summary>
        private FrozenDictionary<string, object>? DefaultContext { get; }

        /// <summary>
        /// A convenience getter to return the public key memory instead of a generic one.
        /// </summary>
        protected new PublicKeyMemory KeyMaterial { get { return (PublicKeyMemory)base.KeyMaterial; } }


        /// <summary>
        /// Public key constructor using a <see cref="Cryptography.VerificationDelegate"/>.
        /// </summary>
        /// <param name="sensitiveMemory">The public key bytes of this key.</param>
        /// <param name="id">The key identifier.</param>
        /// <param name="verificationDelegate">The delegate that verifies the signature against data using this key.</param>
        /// <param name="context">Optional default context for verification operations.</param>
        public PublicKey(PublicKeyMemory sensitiveMemory, string id, VerificationDelegate verificationDelegate, FrozenDictionary<string, object>? context = null): base(sensitiveMemory, id)
        {
            this.VerificationDelegate = verificationDelegate;
            this.DefaultContext = context;
        }


        /// <summary>
        /// Verifies if <paramref name="signature"/> generated using a private key corresponding to
        /// this public key matches <paramref name="dataToVerify"/>.
        /// </summary>
        /// <param name="dataToVerify">The data from which the signature supposedly has been generated.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="context">Optional context for this verification operation. If not provided,
        /// the default context from construction is used.</param>
        /// <returns><em>True</em> if the signature matches the data. <em>False</em> otherwise.</returns>
        /// <remarks>
        /// This is the choke point for every verification performed through a <see cref="PublicKey"/>:
        /// it unwraps the <see cref="VerificationCompletedEvent"/> the bound delegate constructs
        /// and emits it through <see cref="CryptographicKeyEvents.Events"/> when non-null. Library
        /// layers that invoke a resolved <see cref="Cryptography.VerificationDelegate"/> directly (the COSE/JOSE
        /// and smart-card stacks) emit through their own trailing <see cref="CryptoEventSink"/>
        /// parameter instead, reaching the same <see cref="CryptographicKeyEvents.Events"/> stream
        /// by default — see <see cref="CryptoEventSink"/> for the two-route rationale.
        /// </remarks>
        public async ValueTask<bool> VerifyAsync(ReadOnlyMemory<byte> dataToVerify, Signature signature, FrozenDictionary<string, object>? context = null)
        {
            (bool isVerified, CryptoEvent? evt) = await KeyMaterial.WithKeyBytesAsync((publicKeyBytes, dataToVerify, sig) =>
                VerificationDelegate(dataToVerify, sig.AsReadOnlyMemory(), publicKeyBytes, context ?? DefaultContext), dataToVerify, signature).ConfigureAwait(false);

            CryptographicKeyEvents.Emit(evt);

            return isVerified;
        }
    }
}

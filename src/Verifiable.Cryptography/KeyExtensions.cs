using System.Buffers;
using System.Collections.Frozen;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// Extension methods for key memory types that provide convenient access to cryptographic operations.
/// </summary>
/// <remarks>
/// <para>
/// These extensions bridge the gap between raw key memory (<see cref="PublicKeyMemory"/>, 
/// <see cref="PrivateKeyMemory"/>) and cryptographic operations without requiring the full
/// <see cref="PublicKey"/> or <see cref="PrivateKey"/> wrapper classes.
/// </para>
/// <para>
/// Two sets of overloads are provided:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Generic function overloads</strong> - Accept <see cref="SigningFunction{TPrivateKeyBytes, TDataToSign, TResult}"/>
/// and <see cref="VerificationFunction{TVerificationContext, TDataToVerify, TSignature, TResult}"/> for maximum flexibility.
/// </description></item>
/// <item><description>
/// <strong>Registry delegate overloads</strong> - Accept <see cref="SigningDelegate"/> and <see cref="VerificationDelegate"/>
/// directly, allowing seamless use of functions from <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
/// or cryptographic driver implementations like BouncyCastle or Microsoft CNG.
/// </description></item>
/// </list>
/// </remarks>
public static class KeyExtensions
{
    /// <summary>
    /// Signs data using private key memory and a specified signing function.
    /// This method provides direct access to signing operations without requiring a <see cref="PrivateKey"/> instance.
    /// </summary>
    /// <param name="privateKey">The private key memory containing the key material.</param>
    /// <param name="dataToSign">The data which needs to be signed.</param>
    /// <param name="signingFunction">The function that signs the data.</param>
    /// <param name="signaturePool">The memory pool for allocating the signature buffer.</param>
    /// <returns>The signature of the data.</returns>
    /// <remarks>
    /// This extension is used internally by <see cref="PrivateKey.SignAsync"/> and can also be used
    /// directly when you need to combine different signing functions with the same key material.
    /// </remarks>
    /// <seealso cref="PrivateKey.SignAsync"/>
    public static ValueTask<Signature> SignAsync(this PrivateKeyMemory privateKey, ReadOnlyMemory<byte> dataToSign, SigningFunction<byte, byte, ValueTask<Signature>> signingFunction, MemoryPool<byte> signaturePool)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingFunction);
        ArgumentNullException.ThrowIfNull(signaturePool);
        return privateKey.SignWithKeyBytesAsync((privateKeyBytes, dataToSign, signaturePool) => signingFunction(privateKeyBytes, dataToSign, signaturePool), dataToSign, signaturePool);
    }


    /// <summary>
    /// Signs data using private key memory and a <see cref="SigningDelegate"/>.
    /// This overload accepts the registry delegate type directly for seamless integration with
    /// cryptographic driver implementations.
    /// </summary>
    /// <param name="privateKey">The private key memory containing the key material.</param>
    /// <param name="dataToSign">The data which needs to be signed.</param>
    /// <param name="signingDelegate">The signing delegate, typically from a cryptographic driver
    /// such as <c>BouncyCastleCryptographicFunctions.SignEd25519Async</c>.</param>
    /// <param name="signaturePool">The memory pool for allocating the signature buffer.</param>
    /// <param name="context">Optional context parameters for the signing operation.</param>
    /// <returns>The signature of the data.</returns>
    public static async ValueTask<Signature> SignAsync(this PrivateKeyMemory privateKey, ReadOnlyMemory<byte> dataToSign, SigningDelegate signingDelegate, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(signaturePool);
        return await privateKey.SignWithKeyBytesAsync(async (privateKeyBytes, dataToSign, signaturePool) => await signingDelegate(privateKeyBytes, dataToSign, signaturePool, context).ConfigureAwait(false), dataToSign, signaturePool)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Signs data using the signing delegate resolved from the key's Tag via CryptoFunctionRegistry.
    /// </summary>
    public static async ValueTask<Signature> SignAsync(this PrivateKeyMemory privateKey, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signaturePool);
        var algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        var purpose = privateKey.Tag.Get<Purpose>();
        var signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);
        
        return await privateKey.SignAsync(dataToSign, signingDelegate, signaturePool).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies data using public key memory and a specified verification function.
    /// This method provides direct access to verification operations without requiring a <see cref="PublicKey"/> instance.
    /// </summary>
    /// <param name="publicKey">The public key memory containing the key material.</param>
    /// <param name="dataToVerify">The data which needs to be verified using <paramref name="signature"/>.</param>
    /// <param name="signature">The signature used to verify <paramref name="dataToVerify"/>.</param>
    /// <param name="verificationFunction">The function that verifies the data with the given signature.</param>
    /// <returns>True if the signature matches the data for the used key. False otherwise.</returns>
    /// <remarks>
    /// This extension is used internally by <see cref="PublicKey.VerifyAsync"/> and can also be used
    /// directly when you need to combine different verification functions with the same key material.
    /// </remarks>
    /// <seealso cref="PublicKey.VerifyAsync"/>
    public static ValueTask<bool> VerifyAsync(this PublicKeyMemory publicKey, ReadOnlyMemory<byte> dataToVerify, Signature signature, VerificationFunction<byte, byte, Signature, ValueTask<bool>> verificationFunction)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(verificationFunction);
        return publicKey.WithKeyBytesAsync((publicKeyBytes, dataToVerify, signature) => verificationFunction(publicKeyBytes, dataToVerify, signature), dataToVerify, signature);
    }


    /// <summary>
    /// Verifies data using public key memory and a <see cref="VerificationDelegate"/>.
    /// This overload accepts the registry delegate type directly for seamless integration with
    /// cryptographic driver implementations.
    /// </summary>
    /// <param name="publicKey">The public key memory containing the key material.</param>
    /// <param name="dataToVerify">The data which needs to be verified.</param>
    /// <param name="signature">The signature used to verify <paramref name="dataToVerify"/>.</param>
    /// <param name="verificationDelegate">The verification delegate, typically from a cryptographic driver
    /// such as <c>BouncyCastleCryptographicFunctions.VerifyEd25519Async</c>.</param>
    /// <param name="context">Optional context parameters for the verification operation.</param>
    /// <returns>True if the signature matches the data for the used key. False otherwise.</returns>
    public static ValueTask<bool> VerifyAsync(this PublicKeyMemory publicKey, ReadOnlyMemory<byte> dataToVerify, Signature signature, VerificationDelegate verificationDelegate, FrozenDictionary<string, object>? context = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        return publicKey.WithKeyBytesAsync((publicKeyBytes, dataToVerify, sig) => verificationDelegate(dataToVerify, sig.AsReadOnlyMemory(), publicKeyBytes, context), dataToVerify, signature);
    }
}

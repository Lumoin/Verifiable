using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.BouncyCastle
{
    /// <summary>
    /// This class has a collection of adapter functions used in <see cref="SensitiveMemoryKey"/> operations matching delegates in <see cref="SensitiveMemory"/>.
    /// </summary>
    public static class BouncyCastleAlgorithms
    {
        /// <summary>
        /// A function that adapts <see cref="PrivateKey.SignAsync(ReadOnlyMemory{byte}, MemoryPool{byte})"/> with delegate <see cref="SigningFunction{TPrivateKeyBytes, TDataToSign, TResult}"/>.
        /// </summary>
        /// <param name="privateKeyBytes">The private key bytes.</param>
        /// <param name="dataToSign">The data to be signed.</param>
        /// <param name="signaturePool">The pool from where to reserve the memory for <see cref="Signature"/>.</param>
        /// <returns>The signature created from <paramref name="dataToSign"/> using <paramref name="privateKeyBytes"/>.</returns>
        public static ValueTask<Signature> SignEd25519Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            //TODO: Parameter checking...

            //TODO: The BouncyCastle inner types can probably used directly here:
            //https://github.com/bcgit/bc-csharp/blob/93b32a75656955faf7996d0f3e0ed391968d2ac6/crypto/src/crypto/parameters/Ed25519PrivateKeyParameters.cs
            //https://github.com/bcgit/bc-csharp/blob/93b32a75656955faf7996d0f3e0ed391968d2ac6/crypto/src/crypto/signers/Ed25519Signer.cs

            AsymmetricKeyParameter keyParameter = new Ed25519PrivateKeyParameters(privateKeyBytes.ToArray(), 0);
            var privateKey = (Ed25519PrivateKeyParameters)keyParameter;

            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, privateKey);

            //TODO: Can the span be pinned and internal array/pointer passed to BouncyCastle? Or write a .NET core
            //wrapper that calls it directly instead of this library?
            signer.BlockUpdate(dataToSign.ToArray(), off: 0, len: dataToSign.Length);

            var signature = (ReadOnlySpan<byte>)signer.GenerateSignature();
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            return ValueTask.FromResult(new Signature(memoryPooledSignature, Tag.Ed25519Signature));
        }


        public static ValueTask<bool> VerifyEd25519Async(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlyMemory<byte> dataToVerify, Signature signature)
        {
            var publicKey = new Ed25519PublicKeyParameters(publicKeyBytes.ToArray(), 0);
            var validator = new Ed25519Signer();
            validator.Init(forSigning: false, publicKey);
            validator.BlockUpdate(dataToVerify.ToArray(), off: 0, len: dataToVerify.Length);

            return ValueTask.FromResult(validator.VerifySignature(((ReadOnlySpan<byte>)signature).ToArray()));
        }
    }
}

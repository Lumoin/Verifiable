using Verifiable.Core.Cryptography;
using NSec.Cryptography;
using System;
using System.Buffers;

namespace Verifiable.NSec
{
    /// <summary>
    /// This class has a collection of adapter functions used in <see cref="Key"/> operations matching delegates in <see cref="SensitiveMemory"/>.
    /// </summary>
    public static class NSecAlgorithms
    {
        /// <summary>
        /// A function that adapts <see cref="PrivateKey.Sign(ReadOnlySpan{byte}, MemoryPool{byte})"/> with delegate <see cref="SigningFunction{TPrivateKeyBytes, TDataToSign, TResult}"/>.
        /// </summary>
        /// <param name="privateKeyBytes">The private key bytes.</param>
        /// <param name="dataToSign">The data to be signed.</param>
        /// <param name="signaturePool">The pool from where to reserve the memory for <see cref="Signature"/>.</param>
        /// <returns>The signature created from <paramref name="dataToSign"/> using <paramref name="privateKeyBytes"/>.</returns>
        public static Signature SignEd25519(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            //TODO: Parameter checking...
            
            var algorithm = SignatureAlgorithm.Ed25519;
            _ = global::NSec.Cryptography.Key.TryImport(algorithm, privateKeyBytes, KeyBlobFormat.RawPrivateKey, out global::NSec.Cryptography.Key? signingKey);

            var signature = (ReadOnlySpan<byte>)algorithm.Sign(signingKey!, dataToSign);
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            return new Signature(memoryPooledSignature, Tag.Ed25519Signature);
        }


        public static bool VerifyEd25519(ReadOnlySpan<byte> publicKeyBytes, ReadOnlySpan<byte> dataBuf, Signature signature)
        {
            global::NSec.Cryptography.PublicKey publicKey = global::NSec.Cryptography.PublicKey.Import(SignatureAlgorithm.Ed25519, publicKeyBytes, KeyBlobFormat.RawPublicKey);
            return SignatureAlgorithm.Ed25519.Verify(publicKey, dataBuf, signature);
        }
    }
}

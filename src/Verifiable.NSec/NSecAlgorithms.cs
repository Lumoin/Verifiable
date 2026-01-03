using NSec.Cryptography;
using System;
using System.Buffers;
using System.Threading.Tasks;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.NSec
{
    /// <summary>
    /// This class has a collection of adapter functions used in <see cref="Key"/> operations matching delegates in <see cref="SensitiveMemory"/>.
    /// </summary>
    public static class NSecAlgorithms
    {
        /// <summary>
        /// A function that adapts <see cref="PrivateKey.SignAsync(ReadOnlyMemory{byte}, MemoryPool{byte})"/> with delegate <see cref="SigningFunction{TPrivateKeyBytes, TDataToSign, TResult}"/>.
        /// </summary>
        /// <param name="privateKeyBytes">The private key bytes.</param>
        /// <param name="dataToSign">The data to be signed.</param>
        /// <param name="signaturePool">The pool from where to reserve the memory for <see cref="Signature"/>.</param>
        /// <returns>The signature created from <paramref name="dataToSign"/> using <paramref name="privateKeyBytes"/>.</returns>
        [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of Signature is transferred to the caller.")]
        public static ValueTask<Signature> SignEd25519Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);

            //TODO: Parameter checking...

            var algorithm = SignatureAlgorithm.Ed25519;
            _ = global::NSec.Cryptography.Key.TryImport(algorithm, privateKeyBytes.Span, KeyBlobFormat.RawPrivateKey, out global::NSec.Cryptography.Key? signingKey);

            var signature = (ReadOnlySpan<byte>)algorithm.Sign(signingKey!, dataToSign.Span);
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            //No CA2000 violation: transfer ownership to caller via ValueTask<Signature>.
            return ValueTask.FromResult(new Signature(memoryPooledSignature, Tag.Ed25519Signature));
        }


        public static ValueTask<bool> VerifyEd25519(ReadOnlyMemory<byte> publicKeyBytes, ReadOnlyMemory<byte> dataBuf, Signature signature)
        {
            global::NSec.Cryptography.PublicKey publicKey = global::NSec.Cryptography.PublicKey.Import(SignatureAlgorithm.Ed25519, publicKeyBytes.Span, KeyBlobFormat.RawPublicKey);
            return ValueTask.FromResult(SignatureAlgorithm.Ed25519.Verify(publicKey, dataBuf.Span, signature));
        }
    }
}

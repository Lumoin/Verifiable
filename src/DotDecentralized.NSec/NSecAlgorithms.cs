using DotDecentralized.Core.Cryptography;
using NSec.Cryptography;
using System;
using System.Buffers;

namespace DotDecentralized.NSec
{
    public static class NSecAlgorithms
    {
        public static Signature SignEd25519(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
            //TODO: Failures...
            var algorithm = SignatureAlgorithm.Ed25519;
            _ = global::NSec.Cryptography.Key.TryImport(algorithm, privateKeyBytes, KeyBlobFormat.RawPrivateKey, out global::NSec.Cryptography.Key? signingKey);

            var signature = (ReadOnlySpan<byte>)algorithm.Sign(signingKey!, dataToSign);
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            return new Signature(memoryPooledSignature);
        }


        public static bool VerifyEd25519(ReadOnlySpan<byte> publicKeyBytes, ReadOnlySpan<byte> dataBuf, Signature signature)
        {
            global::NSec.Cryptography.PublicKey publicKey = global::NSec.Cryptography.PublicKey.Import(SignatureAlgorithm.Ed25519, publicKeyBytes, KeyBlobFormat.RawPublicKey);
            return SignatureAlgorithm.Ed25519.Verify(publicKey, dataBuf, signature);
        }
    }
}

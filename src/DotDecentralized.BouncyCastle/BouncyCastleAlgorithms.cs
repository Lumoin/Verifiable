using DotDecentralized.Core.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.Buffers;

namespace DotDecentralized.BouncyCastle
{
    public static class BouncyCastleAlgorithms
    {
        public static Signature SignEd25519(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool)
        {
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

            return new Signature(memoryPooledSignature);
        }


        public static bool VerifyEd25519(ReadOnlySpan<byte> publicKeyBytes, ReadOnlySpan<byte> dataBuf, Signature signature)
        {
            var publicKey = new Ed25519PublicKeyParameters(publicKeyBytes.ToArray(), 0);
            var validator = new Ed25519Signer();
            validator.Init(forSigning: false, publicKey);
            validator.BlockUpdate(dataBuf.ToArray(), off: 0, len: dataBuf.Length);

            return validator.VerifySignature(((ReadOnlySpan<byte>)signature).ToArray());
        }
    }
}

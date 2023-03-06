using System;
using System.Buffers;
using System.Security.Cryptography;
using Verifiable.Core.Cryptography;


namespace Verifiable.Microsoft
{
    public static class MicrosoftKeyCreator
    {
        public static PublicPrivateKeyMaterial<PublicKeyMemoryDerived, PrivateKeyMemoryDerived> CreateP256KeyDerived(MemoryPool<byte> memoryPool)
        {
            var keys = CreateP256Keys(memoryPool);
            return new PublicPrivateKeyMaterial<PublicKeyMemoryDerived, PrivateKeyMemoryDerived>(
                new PublicKeyMemoryDerived(null!, Tag.Empty),
                new PrivateKeyMemoryDerived(null!, Tag.Empty));
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.NamedCurves.nistP256, memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.NamedCurves.nistP384, memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.NamedCurves.nistP521, memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256k1Keys(MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.CreateFromFriendlyName("secP256k1"), memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa2048Keys(MemoryPool<byte> memoryPool)
        {
            return CreateRsaKeys(2048, memoryPool);
        }

        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa4096Keys(MemoryPool<byte> memoryPool)
        {
            return CreateRsaKeys(4096, memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256Keys<TKeyLoadData>(TKeyLoadData state, MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.NamedCurves.nistP256, memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384Keys<TKeyLoadData>(TKeyLoadData state, MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.NamedCurves.nistP384, memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521Keys<TKeyLoadData>(TKeyLoadData state, MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.NamedCurves.nistP521, memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256l1Keys<TKeyLoadData>(TKeyLoadData state, MemoryPool<byte> memoryPool)
        {
            return CreateEcKeys(ECCurve.CreateFromFriendlyName("secP256k1"), memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa2048Keys<TKeyLoadData>(TKeyLoadData state, MemoryPool<byte> memoryPool)
        {
            return CreateRsaKeys(2048, memoryPool);
        }


        public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa4096Keys<TKeyLoadData>(TKeyLoadData state, MemoryPool<byte> memoryPool)
        {
            return CreateRsaKeys(4096, memoryPool);
        }


        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEcKeys(ECCurve namedCurve, MemoryPool<byte> memoryPool)
        {
            static (Tag PublicKeyTag, Tag PrivateKeyTag) GetTags(ECCurve namedCurve)
            {
                return namedCurve.Oid.FriendlyName switch
                {
                    "nistP256" => (Tag.P256PublicKey, Tag.P256PrivateKey),
                    "nistP384" => (Tag.P384PublicKey, Tag.P384PrivateKey),
                    "nistP521" => (Tag.P521PublicKey, Tag.P521PrivateKey),
                    "secP256k1" => (Tag.Secp256k1PublicKey, Tag.Secp256k1PrivateKey),
                    _ => throw new NotSupportedException($"The curve {namedCurve.Oid.FriendlyName} is not supported.")
                };
            }

            using(var key = ECDsa.Create(namedCurve))
            {
                ECParameters parameters = key.ExportParameters(includePrivateParameters: true);
                byte[] compressedKeyMaterial = EllipticCurveUtilities.Compress(parameters.Q.X, parameters.Q.Y);

                var (publicKeyTag, privateKeyTag) = GetTags(namedCurve);
                var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(compressedKeyMaterial, memoryPool), publicKeyTag);
                var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(parameters.D!, memoryPool), privateKeyTag);
                Array.Clear(compressedKeyMaterial, 0, compressedKeyMaterial.Length);
                Array.Clear(parameters.Q.X!, 0, parameters.Q.X!.Length);
                Array.Clear(parameters.Q.Y!, 0, parameters.Q.Y!.Length);
                Array.Clear(parameters.D!, 0, parameters.D!.Length);

                return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
            }
        }


        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsaKeys(int keySizeInBits, MemoryPool<byte> memoryPool)
        {
            static (Tag PublicKeyTag, Tag PrivateKeyTag) GetTags(int keySizeInBits)
            {
                return keySizeInBits switch
                {
                    2048 => (Tag.Rsa2048PublicKey, Tag.Rsa2048PrivateKey),
                    4096 => (Tag.Rsa4096PublicKey, Tag.Rsa4096PrivateKey),
                    _ => throw new NotSupportedException($"The RSA key size {keySizeInBits} bits is not supported.")
                };
            }

            using(var key = RSA.Create(keySizeInBits))
            {
                RSAParameters parameters = key.ExportParameters(includePrivateParameters: true);
                byte[] derEncodedPublicKey = RsaUtilities.Encode(parameters.Modulus!);

                var (publicKeyTag, privateKeyTag) = GetTags(keySizeInBits);
                var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(derEncodedPublicKey, memoryPool), publicKeyTag);
                var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(parameters.D!, memoryPool), privateKeyTag);
                Array.Clear(derEncodedPublicKey, 0, derEncodedPublicKey.Length);
                Array.Clear(parameters.Modulus!, 0, parameters.Modulus!.Length);
                Array.Clear(parameters.D!, 0, parameters.D!.Length);

                return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
            }
        }


        private static IMemoryOwner<byte> AsPooledMemory(byte[] keyBytes, MemoryPool<byte> memoryPool)
        {
            //It may be that the provided MemoryPool allocates more bytes than asked for.
            //Like the default .NET MemoryPool. But for many of the DID key operations
            //that create string representations of the key material, such as Base58 encoding,
            //it is important that the key material is not padded with zeroes.
            IMemoryOwner<byte> keyBuffer = memoryPool.Rent(keyBytes.Length);
            keyBytes.AsSpan().CopyTo(keyBuffer.Memory.Span.Slice(0, keyBytes.Length));

            return keyBuffer;
        }
    }
}

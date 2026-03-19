using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.BouncyCastle;

/// <summary>
/// Creates cryptographic key material using the BouncyCastle library.
/// </summary>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "The caller is responsible for disposing the returned key material instances.")]
public static class BouncyCastleKeyMaterialCreator
{
    private static readonly SecureRandom random = new();


    /// <summary>Creates a P-256 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateEcKeys("secp256r1", CryptoTags.P256PublicKey, CryptoTags.P256PrivateKey, memoryPool);
    }


    /// <summary>Creates a P-384 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateEcKeys("secp384r1", CryptoTags.P384PublicKey, CryptoTags.P384PrivateKey, memoryPool);
    }


    /// <summary>Creates a P-521 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateEcKeys("secp521r1", CryptoTags.P521PublicKey, CryptoTags.P521PrivateKey, memoryPool);
    }


    /// <summary>Creates a secp256k1 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256k1Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateEcKeys("secp256k1", CryptoTags.Secp256k1PublicKey, CryptoTags.Secp256k1PrivateKey, memoryPool);
    }


    /// <summary>Creates an RSA 2048-bit key pair.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa2048Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateRsaKeys(2048, memoryPool);
    }


    /// <summary>Creates an RSA 4096-bit key pair.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa4096Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateRsaKeys(4096, memoryPool);
    }


    /// <summary>Creates an Ed25519 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEd25519Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);

        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(random));
        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

        byte[] publicKey = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded();
        byte[] privateKey = ((Ed25519PrivateKeyParameters)keyPair.Private).GetEncoded();

        var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKey, memoryPool), CryptoTags.Ed25519PublicKey);
        var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKey, memoryPool), CryptoTags.Ed25519PrivateKey);

        Array.Clear(publicKey, 0, publicKey.Length);
        Array.Clear(privateKey, 0, privateKey.Length);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
    }


    /// <summary>Creates an X25519 key pair for ECDH key agreement.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateX25519Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);

        var generator = new X25519KeyPairGenerator();
        generator.Init(new X25519KeyGenerationParameters(random));
        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

        byte[] publicKey = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
        byte[] privateKey = ((X25519PrivateKeyParameters)keyPair.Private).GetEncoded();

        var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKey, memoryPool), CryptoTags.X25519PublicKey);
        var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKey, memoryPool), CryptoTags.X25519PrivateKey);

        Array.Clear(publicKey, 0, publicKey.Length);
        Array.Clear(privateKey, 0, privateKey.Length);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
    }


    /// <summary>
    /// Creates a P-256 ephemeral key pair for ECDH-ES key agreement.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The public key is stored as an uncompressed EC point (<c>0x04 || X || Y</c>)
    /// tagged with <see cref="CryptoTags.P256ExchangePublicKey"/>. Callers use
    /// <see cref="EllipticCurveUtilities.SliceXCoordinate"/> and
    /// <see cref="EllipticCurveUtilities.SliceYCoordinate"/> to extract the coordinates
    /// when building the JWK for the JAR <c>client_metadata.jwks</c> header via
    /// <see cref="Verifiable.JCose.JwtHeaderExtensions"/>.
    /// </para>
    /// <para>
    /// The private key scalar is tagged with <see cref="CryptoTags.P256ExchangePrivateKey"/>.
    /// Only the private key needs to be carried forward in flow state after the JAR is built.
    /// </para>
    /// </remarks>
    /// <param name="memoryPool">Memory pool for key material allocation.</param>
    /// <returns>A new key pair. The caller owns and must dispose each key individually.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256ExchangeKeys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);

        var secCurve = SecNamedCurves.GetByName("secp256r1");
        var domainParams = new ECDomainParameters(
            secCurve.Curve, secCurve.G, secCurve.N, secCurve.H, secCurve.GetSeed());
        var keyGenParam = new ECKeyGenerationParameters(domainParams, random);
        var generator = new ECKeyPairGenerator();
        generator.Init(keyGenParam);

        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
        var publicParam = (ECPublicKeyParameters)keyPair.Public;
        var privateParam = (ECPrivateKeyParameters)keyPair.Private;

        //Uncompressed public point: 0x04 || X (32 bytes) || Y (32 bytes).
        byte[] uncompressed = publicParam.Q.GetEncoded(compressed: false);

        try
        {
            byte[] dBytes = privateParam.D.ToByteArrayUnsigned();

            try
            {
                int fieldSize = (secCurve.Curve.FieldSize + 7) / 8;
                IMemoryOwner<byte> privateKeyBuffer = memoryPool.Rent(fieldSize);
                privateKeyBuffer.Memory.Span.Clear();

                if(dBytes.Length < fieldSize)
                {
                    dBytes.CopyTo(privateKeyBuffer.Memory.Span[(fieldSize - dBytes.Length)..]);
                }
                else
                {
                    dBytes.AsSpan(0, fieldSize).CopyTo(privateKeyBuffer.Memory.Span);
                }

                var publicKeyMemory = new PublicKeyMemory(
                    AsPooledMemory(uncompressed, memoryPool),
                    CryptoTags.P256ExchangePublicKey);
                var privateKeyMemory = new PrivateKeyMemory(
                    privateKeyBuffer,
                    CryptoTags.P256ExchangePrivateKey);

                return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(
                    publicKeyMemory, privateKeyMemory);
            }
            finally
            {
                Array.Clear(dBytes, 0, dBytes.Length);
            }
        }
        finally
        {
            Array.Clear(uncompressed, 0, uncompressed.Length);
        }
    }


    /// <summary>Creates ML-DSA-44 key material (NIST FIPS 204, security level 2).</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa44Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlDsaKeys(MLDsaParameters.ml_dsa_44, memoryPool, CryptoTags.MlDsa44PublicKey, CryptoTags.MlDsa44PrivateKey);
    }


    /// <summary>Creates ML-DSA-65 key material (NIST FIPS 204, security level 3).</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa65Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlDsaKeys(MLDsaParameters.ml_dsa_65, memoryPool, CryptoTags.MlDsa65PublicKey, CryptoTags.MlDsa65PrivateKey);
    }


    /// <summary>Creates ML-DSA-87 key material (NIST FIPS 204, security level 5).</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa87Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlDsaKeys(MLDsaParameters.ml_dsa_87, memoryPool, CryptoTags.MlDsa87PublicKey, CryptoTags.MlDsa87PrivateKey);
    }


    /// <summary>Creates ML-KEM-512 key material (NIST FIPS 203, security level 1).</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem512Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlKemKeys(MLKemParameters.ml_kem_512, memoryPool, CryptoTags.MlKem512PublicKey, CryptoTags.MlKem512PrivateKey);
    }


    /// <summary>Creates ML-KEM-768 key material (NIST FIPS 203, security level 3).</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem768Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlKemKeys(MLKemParameters.ml_kem_768, memoryPool, CryptoTags.MlKem768PublicKey, CryptoTags.MlKem768PrivateKey);
    }


    /// <summary>Creates ML-KEM-1024 key material (NIST FIPS 203, security level 5).</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem1024Keys(MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlKemKeys(MLKemParameters.ml_kem_1024, memoryPool, CryptoTags.MlKem1024PublicKey, CryptoTags.MlKem1024PrivateKey);
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEcKeys(
        string secCurveName,
        Tag publicKeyTag,
        Tag privateKeyTag,
        MemoryPool<byte> memoryPool)
    {
        var curve = SecNamedCurves.GetByName(secCurveName);
        var domainParams = new ECDomainParameters(
            curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        var keyGenParam = new ECKeyGenerationParameters(domainParams, random);
        var generator = new ECKeyPairGenerator();
        generator.Init(keyGenParam);

        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
        var publicKeyParam = (ECPublicKeyParameters)keyPair.Public;
        var privateKeyParam = (ECPrivateKeyParameters)keyPair.Private;

        byte[] compressedPublicKey = publicKeyParam.Q.GetEncoded(compressed: true);
        byte[] privateKeyBytes = privateKeyParam.D.ToByteArrayUnsigned();

        int expectedKeySize = (curve.Curve.FieldSize + 7) / 8;
        IMemoryOwner<byte> privateKeyBuffer;

        if(privateKeyBytes.Length < expectedKeySize)
        {
            privateKeyBuffer = memoryPool.Rent(expectedKeySize);
            privateKeyBuffer.Memory.Span.Clear();
            privateKeyBytes.CopyTo(privateKeyBuffer.Memory.Span[(expectedKeySize - privateKeyBytes.Length)..]);
        }
        else
        {
            privateKeyBuffer = AsPooledMemory(privateKeyBytes, memoryPool);
        }

        var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(compressedPublicKey, memoryPool), publicKeyTag);
        var privateKeyMemory = new PrivateKeyMemory(privateKeyBuffer, privateKeyTag);

        Array.Clear(compressedPublicKey, 0, compressedPublicKey.Length);
        Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsaKeys(
        int keySizeInBits,
        MemoryPool<byte> memoryPool)
    {
        static (Tag PublicKeyTag, Tag PrivateKeyTag) GetTags(int keySizeInBits) => keySizeInBits switch
        {
            2048 => (CryptoTags.Rsa2048PublicKey, CryptoTags.Rsa2048PrivateKey),
            4096 => (CryptoTags.Rsa4096PublicKey, CryptoTags.Rsa4096PrivateKey),
            _ => throw new NotSupportedException($"The RSA key size {keySizeInBits} bits is not supported.")
        };

        var generator = new RsaKeyPairGenerator();
        var keyGenParam = new KeyGenerationParameters(random, keySizeInBits);
        generator.Init(keyGenParam);

        AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
        var publicKeyParam = (RsaKeyParameters)keyPair.Public;
        var privateKeyParam = (RsaPrivateCrtKeyParameters)keyPair.Private;

        byte[] modulusBytes = publicKeyParam.Modulus.ToByteArrayUnsigned();
        byte[] derEncodedPublicKey = RsaUtilities.Encode(modulusBytes);
        byte[] privateKeyBytes = RsaPrivateKeyStructure.GetInstance(new RsaPrivateKeyStructure(
            privateKeyParam.Modulus,
            privateKeyParam.PublicExponent,
            privateKeyParam.Exponent,
            privateKeyParam.P,
            privateKeyParam.Q,
            privateKeyParam.DP,
            privateKeyParam.DQ,
            privateKeyParam.QInv)).GetDerEncoded();

        var (publicKeyTag, privateKeyTag) = GetTags(keySizeInBits);
        var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(derEncodedPublicKey, memoryPool), publicKeyTag);
        var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKeyBytes, memoryPool), privateKeyTag);

        Array.Clear(modulusBytes, 0, modulusBytes.Length);
        Array.Clear(derEncodedPublicKey, 0, derEncodedPublicKey.Length);
        Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsaKeys(
        MLDsaParameters parameters,
        MemoryPool<byte> memoryPool,
        Tag publicKeyTag,
        Tag privateKeyTag)
    {
        var keyGenParameters = new MLDsaKeyGenerationParameters(random, parameters);
        var keyPairGen = new MLDsaKeyPairGenerator();
        keyPairGen.Init(keyGenParameters);

        AsymmetricCipherKeyPair keyPair = keyPairGen.GenerateKeyPair();
        byte[] publicKeyBytes = ((MLDsaPublicKeyParameters)keyPair.Public).GetEncoded();
        byte[] privateKeyBytes = ((MLDsaPrivateKeyParameters)keyPair.Private).GetEncoded();

        var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKeyBytes, memoryPool), publicKeyTag);
        var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKeyBytes, memoryPool), privateKeyTag);

        Array.Clear(publicKeyBytes, 0, publicKeyBytes.Length);
        Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKemKeys(
        MLKemParameters parameters,
        MemoryPool<byte> memoryPool,
        Tag publicKeyTag,
        Tag privateKeyTag)
    {
        var keyGenParameters = new MLKemKeyGenerationParameters(random, parameters);
        var keyPairGen = new MLKemKeyPairGenerator();
        keyPairGen.Init(keyGenParameters);

        AsymmetricCipherKeyPair keyPair = keyPairGen.GenerateKeyPair();
        byte[] publicKeyBytes = ((MLKemPublicKeyParameters)keyPair.Public).GetEncoded();
        byte[] privateKeyBytes = ((MLKemPrivateKeyParameters)keyPair.Private).GetEncoded();

        var publicKeyMemory = new PublicKeyMemory(AsPooledMemory(publicKeyBytes, memoryPool), publicKeyTag);
        var privateKeyMemory = new PrivateKeyMemory(AsPooledMemory(privateKeyBytes, memoryPool), privateKeyTag);

        Array.Clear(publicKeyBytes, 0, publicKeyBytes.Length);
        Array.Clear(privateKeyBytes, 0, privateKeyBytes.Length);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
    }


    private static IMemoryOwner<byte> AsPooledMemory(byte[] keyBytes, MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(keyBytes);
        ArgumentNullException.ThrowIfNull(memoryPool);

        IMemoryOwner<byte> keyBuffer = memoryPool.Rent(keyBytes.Length);

        if(keyBuffer.Memory.Length != keyBytes.Length)
        {
            keyBuffer.Dispose();
            throw new InvalidOperationException(
                "The rented buffer size does not match the requested size.");
        }

        keyBytes.AsSpan().CopyTo(keyBuffer.Memory.Span);
        return keyBuffer;
    }
}

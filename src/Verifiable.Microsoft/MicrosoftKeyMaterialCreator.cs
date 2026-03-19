using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography;

namespace Verifiable.Microsoft;

/// <summary>
/// Creates cryptographic key material using .NET platform cryptography.
/// </summary>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "The caller is responsible for disposing the returned key material instances.")]
public static class MicrosoftKeyMaterialCreator
{
    /// <summary>Creates a P-256 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256Keys(MemoryPool<byte> memoryPool)
    {
        return CreateEcKeys(ECCurve.NamedCurves.nistP256, memoryPool);
    }


    /// <summary>Creates a P-384 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384Keys(MemoryPool<byte> memoryPool)
    {
        return CreateEcKeys(ECCurve.NamedCurves.nistP384, memoryPool);
    }


    /// <summary>Creates a P-521 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521Keys(MemoryPool<byte> memoryPool)
    {
        return CreateEcKeys(ECCurve.NamedCurves.nistP521, memoryPool);
    }


    /// <summary>Creates a secp256k1 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256k1Keys(MemoryPool<byte> memoryPool)
    {
        return CreateEcKeys(ECCurve.CreateFromFriendlyName("secP256k1"), memoryPool);
    }


    /// <summary>Creates an RSA 2048-bit key pair.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa2048Keys(MemoryPool<byte> memoryPool)
    {
        return CreateRsaKeys(2048, memoryPool);
    }


    /// <summary>Creates an RSA 4096-bit key pair.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa4096Keys(MemoryPool<byte> memoryPool)
    {
        return CreateRsaKeys(4096, memoryPool);
    }


    /// <summary>
    /// Creates a P-256 ephemeral key pair for ECDH-ES key agreement using the .NET
    /// platform <see cref="ECDiffieHellman"/> implementation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The public key is stored as an uncompressed EC point (<c>0x04 || X || Y</c>)
    /// tagged with <see cref="CryptoTags.P256ExchangePublicKey"/>. Callers use
    /// <see cref="EllipticCurveUtilities.SliceXCoordinate"/> and
    /// <see cref="EllipticCurveUtilities.SliceYCoordinate"/> to extract coordinates
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

        using ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdh.ExportParameters(includePrivateParameters: true);

        try
        {
            //Store the full uncompressed point so callers can slice coordinates via
            //EllipticCurveUtilities when building the JWK for the JAR header.
            byte[] uncompressed = new byte[65];
            uncompressed[0] = 0x04;
            parameters.Q.X!.CopyTo(uncompressed, 1);
            parameters.Q.Y!.CopyTo(uncompressed, 33);

            var publicKeyMemory = new PublicKeyMemory(
                AsPooledMemory(uncompressed, memoryPool),
                CryptoTags.P256ExchangePublicKey);

            var privateKeyMemory = new PrivateKeyMemory(
                AsPooledMemory(parameters.D!, memoryPool),
                CryptoTags.P256ExchangePrivateKey);

            Array.Clear(uncompressed, 0, uncompressed.Length);

            return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(
                publicKeyMemory, privateKeyMemory);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(parameters.Q.X);
            CryptographicOperations.ZeroMemory(parameters.Q.Y);
            CryptographicOperations.ZeroMemory(parameters.D);
        }
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEcKeys(
        ECCurve namedCurve,
        MemoryPool<byte> memoryPool)
    {
        static (Tag PublicKeyTag, Tag PrivateKeyTag) GetTags(ECCurve namedCurve) =>
            namedCurve.Oid.FriendlyName switch
            {
                "nistP256" => (CryptoTags.P256PublicKey, CryptoTags.P256PrivateKey),
                "nistP384" => (CryptoTags.P384PublicKey, CryptoTags.P384PrivateKey),
                "nistP521" => (CryptoTags.P521PublicKey, CryptoTags.P521PrivateKey),
                "secP256k1" => (CryptoTags.Secp256k1PublicKey, CryptoTags.Secp256k1PrivateKey),
                _ => throw new NotSupportedException(
                    $"The curve {namedCurve.Oid.FriendlyName} is not supported.")
            };

        using ECDsa key = ECDsa.Create(namedCurve);
        ECParameters parameters = key.ExportParameters(includePrivateParameters: true);

        byte[] compressedKeyMaterial = EllipticCurveUtilities.Compress(
            parameters.Q.X, parameters.Q.Y);

        var (publicKeyTag, privateKeyTag) = GetTags(namedCurve);
        var publicKeyMemory = new PublicKeyMemory(
            AsPooledMemory(compressedKeyMaterial, memoryPool), publicKeyTag);
        var privateKeyMemory = new PrivateKeyMemory(
            AsPooledMemory(parameters.D!, memoryPool), privateKeyTag);

        CryptographicOperations.ZeroMemory(compressedKeyMaterial);
        CryptographicOperations.ZeroMemory(parameters.Q.X);
        CryptographicOperations.ZeroMemory(parameters.Q.Y);
        CryptographicOperations.ZeroMemory(parameters.D);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(
            publicKeyMemory, privateKeyMemory);
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsaKeys(
        int keySizeInBits,
        MemoryPool<byte> memoryPool)
    {
        static (Tag PublicKeyTag, Tag PrivateKeyTag) GetTags(int keySizeInBits) =>
            keySizeInBits switch
            {
                2048 => (CryptoTags.Rsa2048PublicKey, CryptoTags.Rsa2048PrivateKey),
                4096 => (CryptoTags.Rsa4096PublicKey, CryptoTags.Rsa4096PrivateKey),
                _ => throw new NotSupportedException(
                    $"The RSA key size {keySizeInBits} bits is not supported.")
            };

        using RSA key = RSA.Create(keySizeInBits);
        RSAParameters parameters = key.ExportParameters(includePrivateParameters: true);

        byte[] derEncodedPublicKey = RsaUtilities.Encode(parameters.Modulus!);
        var (publicKeyTag, privateKeyTag) = GetTags(keySizeInBits);

        var publicKeyMemory = new PublicKeyMemory(
            AsPooledMemory(derEncodedPublicKey, memoryPool), publicKeyTag);
        var privateKeyMemory = new PrivateKeyMemory(
            AsPooledMemory(key.ExportRSAPrivateKey(), memoryPool), privateKeyTag);

        CryptographicOperations.ZeroMemory(derEncodedPublicKey);
        CryptographicOperations.ZeroMemory(parameters.Modulus);
        CryptographicOperations.ZeroMemory(parameters.D);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(
            publicKeyMemory, privateKeyMemory);
    }


    private static IMemoryOwner<byte> AsPooledMemory(byte[] keyBytes, MemoryPool<byte> memoryPool)
    {
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

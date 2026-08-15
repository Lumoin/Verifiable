using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.Microsoft;

/// <summary>
/// Creates cryptographic key material using .NET platform cryptography.
/// </summary>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "The caller is responsible for disposing the returned key material instances.")]
public static class MicrosoftKeyMaterialCreator
{
    private static ProviderLibrary ProviderLib { get; } = new(
        typeof(MicrosoftKeyMaterialCreator).Assembly.GetName().Name
            ?? "Verifiable.Microsoft",
        typeof(MicrosoftKeyMaterialCreator).Assembly.GetName().Version?.ToString()
            ?? "Unknown");

    private static CryptoLibraryInfo CryptoLib { get; } = new(
        "System.Security.Cryptography",
        typeof(RandomNumberGenerator).Assembly.GetName().Version?.ToString()
            ?? System.Environment.Version.ToString());

    private static ProviderClass ProviderCls { get; } =
        new(nameof(MicrosoftKeyMaterialCreator));


    /// <summary>Creates a P-256 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256Keys(BaseMemoryPool memoryPool)
    {
        return CreateEcKeys(ECCurve.NamedCurves.nistP256, memoryPool);
    }


    /// <summary>Creates a P-384 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384Keys(BaseMemoryPool memoryPool)
    {
        return CreateEcKeys(ECCurve.NamedCurves.nistP384, memoryPool);
    }


    /// <summary>Creates a P-521 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521Keys(BaseMemoryPool memoryPool)
    {
        return CreateEcKeys(ECCurve.NamedCurves.nistP521, memoryPool);
    }


    /// <summary>Creates a secp256k1 key pair for signing and verification.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateSecp256k1Keys(BaseMemoryPool memoryPool)
    {
        return CreateEcKeys(ECCurve.CreateFromFriendlyName("secP256k1"), memoryPool);
    }


    /// <summary>Creates an RSA 2048-bit key pair.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa2048Keys(BaseMemoryPool memoryPool)
    {
        return CreateRsaKeys(2048, memoryPool);
    }


    /// <summary>Creates an RSA 4096-bit key pair.</summary>
    /// <param name="memoryPool">The memory pool for key data allocation.</param>
    /// <returns>The public and private key material.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsa4096Keys(BaseMemoryPool memoryPool)
    {
        return CreateRsaKeys(4096, memoryPool);
    }

#pragma warning disable SYSLIB5006 //The platform post-quantum surface is experimental; these creators gate on IsSupported and the BouncyCastle creator remains the portable fallback.

    /// <summary>Creates ML-DSA-44 key material (NIST FIPS 204, security level 2) using the platform implementation.</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    /// <exception cref="PlatformNotSupportedException">Thrown when the platform ships no ML-DSA implementation (<see cref="MLDsa.IsSupported"/>).</exception>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa44Keys(BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlDsaKeys(MLDsaAlgorithm.MLDsa44, memoryPool, CryptoTags.MlDsa44PublicKey, CryptoTags.MlDsa44PrivateKey);
    }


    /// <summary>Creates ML-DSA-65 key material (NIST FIPS 204, security level 3) using the platform implementation.</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    /// <exception cref="PlatformNotSupportedException">Thrown when the platform ships no ML-DSA implementation (<see cref="MLDsa.IsSupported"/>).</exception>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa65Keys(BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlDsaKeys(MLDsaAlgorithm.MLDsa65, memoryPool, CryptoTags.MlDsa65PublicKey, CryptoTags.MlDsa65PrivateKey);
    }


    /// <summary>Creates ML-DSA-87 key material (NIST FIPS 204, security level 5) using the platform implementation.</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    /// <exception cref="PlatformNotSupportedException">Thrown when the platform ships no ML-DSA implementation (<see cref="MLDsa.IsSupported"/>).</exception>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsa87Keys(BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlDsaKeys(MLDsaAlgorithm.MLDsa87, memoryPool, CryptoTags.MlDsa87PublicKey, CryptoTags.MlDsa87PrivateKey);
    }


    /// <summary>Creates ML-KEM-512 key material (NIST FIPS 203, security level 1) using the platform implementation.</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    /// <exception cref="PlatformNotSupportedException">Thrown when the platform ships no ML-KEM implementation (<see cref="MLKem.IsSupported"/>).</exception>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem512Keys(BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlKemKeys(MLKemAlgorithm.MLKem512, memoryPool, CryptoTags.MlKem512PublicKey, CryptoTags.MlKem512PrivateKey);
    }


    /// <summary>Creates ML-KEM-768 key material (NIST FIPS 203, security level 3) using the platform implementation.</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    /// <exception cref="PlatformNotSupportedException">Thrown when the platform ships no ML-KEM implementation (<see cref="MLKem.IsSupported"/>).</exception>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem768Keys(BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlKemKeys(MLKemAlgorithm.MLKem768, memoryPool, CryptoTags.MlKem768PublicKey, CryptoTags.MlKem768PrivateKey);
    }


    /// <summary>Creates ML-KEM-1024 key material (NIST FIPS 203, security level 5) using the platform implementation.</summary>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    /// <exception cref="PlatformNotSupportedException">Thrown when the platform ships no ML-KEM implementation (<see cref="MLKem.IsSupported"/>).</exception>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKem1024Keys(BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateMlKemKeys(MLKemAlgorithm.MLKem1024, memoryPool, CryptoTags.MlKem1024PublicKey, CryptoTags.MlKem1024PrivateKey);
    }

#pragma warning restore SYSLIB5006


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
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP256ExchangeKeys(BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);

        ProviderOperation operation = new(nameof(CreateP256ExchangeKeys));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyGen);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            CryptoAlgorithm keyAlgorithm = CryptoTags.P256ExchangePrivateKey.Get<CryptoAlgorithm>();
            activity.SetTag(CryptoTelemetry.Key.AlgorithmCode, keyAlgorithm.Algorithm.ToString(CultureInfo.InvariantCulture));
            activity.SetTag(CryptoTelemetry.Key.Algorithm, keyAlgorithm.ToString());
            activity.SetTag(CryptoTelemetry.Key.Type, "private-key");
        }

        using ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdh.ExportParameters(includePrivateParameters: true);

        try
        {
            //Store the full uncompressed point so callers can slice coordinates via
            //EllipticCurveUtilities when building the JWK for the JAR header.
            byte[] uncompressed = new byte[65];
            uncompressed[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
            parameters.Q.X!.CopyTo(uncompressed, 1);
            parameters.Q.Y!.CopyTo(uncompressed, 33);

            var publicKeyMemory = new PublicKeyMemory(
                AsPooledMemory(uncompressed, memoryPool, AllocationKind.Managed),
                CryptoTags.P256ExchangePublicKey);

            var privateKeyMemory = new PrivateKeyMemory(
                AsPooledMemory(parameters.D!, memoryPool, AllocationKind.Pinned),
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


    /// <summary>
    /// Creates a NIST P-384 ephemeral key pair for ECDH-ES key agreement using the .NET
    /// platform <see cref="ECDiffieHellman"/> implementation.
    /// </summary>
    /// <remarks>
    /// Curve <c>nistP384</c> per <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2">RFC 7518 §6.2.1.2</see>;
    /// coordinate size is 48 bytes, so the uncompressed point (<c>0x04 || X || Y</c>) is 97 bytes.
    /// </remarks>
    /// <param name="memoryPool">Memory pool for key material allocation.</param>
    /// <returns>A new key pair. The caller owns and must dispose each key individually.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP384ExchangeKeys(BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateEcExchangeKeys(
            ECCurve.NamedCurves.nistP384,
            CryptoTags.P384ExchangePublicKey,
            CryptoTags.P384ExchangePrivateKey,
            memoryPool);
    }


    /// <summary>
    /// Creates a NIST P-521 ephemeral key pair for ECDH-ES key agreement using the .NET
    /// platform <see cref="ECDiffieHellman"/> implementation.
    /// </summary>
    /// <remarks>
    /// Curve <c>nistP521</c> per <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3">RFC 7518 §6.2.1.3</see>;
    /// the 521-bit coordinate rounds up to 66 bytes, so the uncompressed point (<c>0x04 || X || Y</c>) is 133 bytes.
    /// </remarks>
    /// <param name="memoryPool">Memory pool for key material allocation.</param>
    /// <returns>A new key pair. The caller owns and must dispose each key individually.</returns>
    public static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateP521ExchangeKeys(BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);
        return CreateEcExchangeKeys(
            ECCurve.NamedCurves.nistP521,
            CryptoTags.P521ExchangePublicKey,
            CryptoTags.P521ExchangePrivateKey,
            memoryPool);
    }


    //Exchange counterpart of CreateP256ExchangeKeys, parameterized over the NIST curve
    //and its coordinate length. The coordinate length is derived from the exported Q.X
    //(48 for P-384, 66 for P-521) so the uncompressed point is sized 1 + 2*len.
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateEcExchangeKeys(
        ECCurve namedCurve,
        Tag publicKeyTag,
        Tag privateKeyTag,
        BaseMemoryPool memoryPool)
    {
        ProviderOperation operation = new(nameof(CreateEcExchangeKeys));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyGen);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            CryptoAlgorithm keyAlgorithm = privateKeyTag.Get<CryptoAlgorithm>();
            activity.SetTag(CryptoTelemetry.Key.AlgorithmCode, keyAlgorithm.Algorithm.ToString(CultureInfo.InvariantCulture));
            activity.SetTag(CryptoTelemetry.Key.Algorithm, keyAlgorithm.ToString());
            activity.SetTag(CryptoTelemetry.Key.Type, "private-key");
        }

        using ECDiffieHellman ecdh = ECDiffieHellman.Create(namedCurve);
        ECParameters parameters = ecdh.ExportParameters(includePrivateParameters: true);

        try
        {
            //Store the full uncompressed point so callers can slice coordinates via
            //EllipticCurveUtilities when building the JWK for the JAR header.
            int coordinateLength = parameters.Q.X!.Length;
            byte[] uncompressed = new byte[1 + (2 * coordinateLength)];
            uncompressed[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
            parameters.Q.X!.CopyTo(uncompressed, 1);
            parameters.Q.Y!.CopyTo(uncompressed, 1 + coordinateLength);

            var publicKeyMemory = new PublicKeyMemory(
                AsPooledMemory(uncompressed, memoryPool, AllocationKind.Managed),
                publicKeyTag);

            var privateKeyMemory = new PrivateKeyMemory(
                AsPooledMemory(parameters.D!, memoryPool, AllocationKind.Pinned),
                privateKeyTag);

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
        BaseMemoryPool memoryPool)
    {
        ProviderOperation operation = new(nameof(CreateEcKeys));
        var (publicKeyTag, privateKeyTag) = GetTags(namedCurve);
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyGen);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            CryptoAlgorithm keyAlgorithm = privateKeyTag.Get<CryptoAlgorithm>();
            activity.SetTag(CryptoTelemetry.Key.AlgorithmCode, keyAlgorithm.Algorithm.ToString(CultureInfo.InvariantCulture));
            activity.SetTag(CryptoTelemetry.Key.Algorithm, keyAlgorithm.ToString());
            activity.SetTag(CryptoTelemetry.Key.Type, "private-key");
        }

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

        var publicKeyMemory = new PublicKeyMemory(
            AsPooledMemory(compressedKeyMaterial, memoryPool, AllocationKind.Managed), publicKeyTag);
        var privateKeyMemory = new PrivateKeyMemory(
            AsPooledMemory(parameters.D!, memoryPool, AllocationKind.Pinned), privateKeyTag);

        CryptographicOperations.ZeroMemory(compressedKeyMaterial);
        CryptographicOperations.ZeroMemory(parameters.Q.X);
        CryptographicOperations.ZeroMemory(parameters.Q.Y);
        CryptographicOperations.ZeroMemory(parameters.D);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(
            publicKeyMemory, privateKeyMemory);
    }


    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsaKeys(
        int keySizeInBits,
        BaseMemoryPool memoryPool)
    {
        ProviderOperation operation = new(nameof(CreateRsaKeys));
        var (publicKeyTag, privateKeyTag) = GetTags(keySizeInBits);
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyGen);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            CryptoAlgorithm keyAlgorithm = privateKeyTag.Get<CryptoAlgorithm>();
            activity.SetTag(CryptoTelemetry.Key.AlgorithmCode, keyAlgorithm.Algorithm.ToString(CultureInfo.InvariantCulture));
            activity.SetTag(CryptoTelemetry.Key.Algorithm, keyAlgorithm.ToString());
            activity.SetTag(CryptoTelemetry.Key.Type, "private-key");
        }

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

        var publicKeyMemory = new PublicKeyMemory(
            AsPooledMemory(derEncodedPublicKey, memoryPool, AllocationKind.Managed), publicKeyTag);
        var privateKeyMemory = new PrivateKeyMemory(
            AsPooledMemory(key.ExportRSAPrivateKey(), memoryPool, AllocationKind.Pinned), privateKeyTag);

        CryptographicOperations.ZeroMemory(derEncodedPublicKey);
        CryptographicOperations.ZeroMemory(parameters.Modulus);
        CryptographicOperations.ZeroMemory(parameters.D);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(
            publicKeyMemory, privateKeyMemory);
    }


#pragma warning disable SYSLIB5006 //The platform post-quantum surface is experimental; these cores gate on IsSupported and the BouncyCastle creator remains the portable fallback.

    /// <summary>
    /// Creates an ML-DSA key pair through the platform <see cref="MLDsa"/> implementation
    /// (<see href="https://csrc.nist.gov/pubs/fips/204/final">NIST FIPS 204</see>).
    /// </summary>
    /// <remarks>
    /// The FIPS 204 private key exports through <see cref="MLDsa.ExportMLDsaPrivateKey(Span{byte})"/>
    /// directly into an exact-length <see cref="AllocationKind.Pinned"/> rental, so no transient
    /// movable copy of the private key ever exists on the managed heap — the property the
    /// BouncyCastle creator cannot offer because its key parameter types export only through
    /// <c>byte[]</c>. The public key exports into a Managed rental the same way.
    /// </remarks>
    /// <param name="algorithm">The FIPS 204 parameter set.</param>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <param name="publicKeyTag">The tag the public key carries.</param>
    /// <param name="privateKeyTag">The tag the private key carries.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlDsaKeys(
        MLDsaAlgorithm algorithm,
        BaseMemoryPool memoryPool,
        Tag publicKeyTag,
        Tag privateKeyTag)
    {
        if(!MLDsa.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "The platform ships no ML-DSA implementation; use the BouncyCastle creator where platform support is absent.");
        }

        ProviderOperation operation = new(nameof(CreateMlDsaKeys));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyGen);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            CryptoAlgorithm keyAlgorithm = privateKeyTag.Get<CryptoAlgorithm>();
            activity.SetTag(CryptoTelemetry.Key.AlgorithmCode, keyAlgorithm.Algorithm.ToString(CultureInfo.InvariantCulture));
            activity.SetTag(CryptoTelemetry.Key.Algorithm, keyAlgorithm.ToString());
            activity.SetTag(CryptoTelemetry.Key.Type, "private-key");
        }

        using MLDsa key = MLDsa.GenerateKey(algorithm);

        //One guard covers both exports AND the second rent: a throwing pinned rental must release
        //the already-populated public-key rental rather than leak it.
        IMemoryOwner<byte> publicKeyBuffer = memoryPool.Rent(algorithm.PublicKeySizeInBytes);
        IMemoryOwner<byte>? privateKeyBuffer = null;
        try
        {
            key.ExportMLDsaPublicKey(publicKeyBuffer.Memory.Span[..algorithm.PublicKeySizeInBytes]);
            privateKeyBuffer = memoryPool.Rent(algorithm.PrivateKeySizeInBytes, AllocationKind.Pinned);
            key.ExportMLDsaPrivateKey(privateKeyBuffer.Memory.Span[..algorithm.PrivateKeySizeInBytes]);
        }
        catch
        {
            privateKeyBuffer?.Dispose();
            publicKeyBuffer.Dispose();
            throw;
        }

        var publicKeyMemory = new PublicKeyMemory(publicKeyBuffer, publicKeyTag);
        var privateKeyMemory = new PrivateKeyMemory(privateKeyBuffer, privateKeyTag);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
    }


    /// <summary>
    /// Creates an ML-KEM key pair through the platform <see cref="MLKem"/> implementation
    /// (<see href="https://csrc.nist.gov/pubs/fips/203/final">NIST FIPS 203</see>).
    /// </summary>
    /// <remarks>
    /// The FIPS 203 decapsulation key exports through <see cref="MLKem.ExportDecapsulationKey(Span{byte})"/>
    /// directly into an exact-length <see cref="AllocationKind.Pinned"/> rental, so no transient
    /// movable copy of the private key ever exists on the managed heap. The encapsulation key
    /// exports into a Managed rental the same way.
    /// </remarks>
    /// <param name="algorithm">The FIPS 203 parameter set.</param>
    /// <param name="memoryPool">The memory pool to allocate key buffers from.</param>
    /// <param name="publicKeyTag">The tag the encapsulation key carries.</param>
    /// <param name="privateKeyTag">The tag the decapsulation key carries.</param>
    /// <returns>A new key pair. The caller must dispose each key individually.</returns>
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateMlKemKeys(
        MLKemAlgorithm algorithm,
        BaseMemoryPool memoryPool,
        Tag publicKeyTag,
        Tag privateKeyTag)
    {
        if(!MLKem.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "The platform ships no ML-KEM implementation; use the BouncyCastle creator where platform support is absent.");
        }

        ProviderOperation operation = new(nameof(CreateMlKemKeys));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.KeyGen);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            CryptoAlgorithm keyAlgorithm = privateKeyTag.Get<CryptoAlgorithm>();
            activity.SetTag(CryptoTelemetry.Key.AlgorithmCode, keyAlgorithm.Algorithm.ToString(CultureInfo.InvariantCulture));
            activity.SetTag(CryptoTelemetry.Key.Algorithm, keyAlgorithm.ToString());
            activity.SetTag(CryptoTelemetry.Key.Type, "private-key");
        }

        using MLKem key = MLKem.GenerateKey(algorithm);

        //One guard covers both exports AND the second rent: a throwing pinned rental must release
        //the already-populated encapsulation-key rental rather than leak it.
        IMemoryOwner<byte> publicKeyBuffer = memoryPool.Rent(algorithm.EncapsulationKeySizeInBytes);
        IMemoryOwner<byte>? privateKeyBuffer = null;
        try
        {
            key.ExportEncapsulationKey(publicKeyBuffer.Memory.Span[..algorithm.EncapsulationKeySizeInBytes]);
            privateKeyBuffer = memoryPool.Rent(algorithm.DecapsulationKeySizeInBytes, AllocationKind.Pinned);
            key.ExportDecapsulationKey(privateKeyBuffer.Memory.Span[..algorithm.DecapsulationKeySizeInBytes]);
        }
        catch
        {
            privateKeyBuffer?.Dispose();
            publicKeyBuffer.Dispose();
            throw;
        }

        var publicKeyMemory = new PublicKeyMemory(publicKeyBuffer, publicKeyTag);
        var privateKeyMemory = new PrivateKeyMemory(privateKeyBuffer, privateKeyTag);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKeyMemory, privateKeyMemory);
    }

#pragma warning restore SYSLIB5006

    /// <summary>
    /// Wraps one of this class's own <c>Create*Keys</c> methods into the
    /// <see cref="KeyCreationDelegate"/> tuple shape <see cref="KeyCreationFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// resolves, without changing that method's own signature — every existing call site that invokes
    /// <c>Create*Keys</c> directly keeps compiling and keeps forfeiting the event, exactly as a direct
    /// <see cref="SigningDelegate"/> call forfeits <see cref="SignatureProducedEvent"/>. Constructs the
    /// <see cref="KeyMaterialGeneratedEvent"/> from this class's own already-visible <see cref="CryptoLib"/>
    /// identity, mirroring how <c>MicrosoftCryptographicFunctions</c> constructs
    /// <see cref="SignatureProducedEvent"/>/<see cref="VerificationCompletedEvent"/> from the same kind of
    /// field for the sign/verify tuple route.
    /// </summary>
    /// <param name="creator">One of this class's own <c>Create*Keys</c> methods, passed by method group.</param>
    /// <param name="algorithm">The algorithm the created key pair represents.</param>
    /// <param name="purpose">The purpose (signing, exchange) the created key pair is registered for.</param>
    /// <param name="memoryPool">The memory pool to allocate key material from.</param>
    /// <returns>The created key pair, paired with the <see cref="KeyMaterialGeneratedEvent"/> describing it.</returns>
    public static (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Keys, CryptoEvent? Event) CreateKeysWithEvent(
        PublicPrivateKeyCreationDelegate<PublicKeyMemory, PrivateKeyMemory> creator,
        CryptoAlgorithm algorithm,
        Purpose purpose,
        BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(creator);
        ArgumentNullException.ThrowIfNull(memoryPool);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = creator(memoryPool);
        CryptoEvent evt = KeyMaterialGeneratedEvent.Create(algorithm, purpose, MaterialSemantics.Direct, CryptoLib.Name);

        return (keys, evt);
    }


    /// <summary>
    /// Copies <paramref name="keyBytes"/> into an exact-length pool rental of the requested
    /// <paramref name="kind"/> — <see cref="AllocationKind.Pinned"/> for private key bytes so the
    /// zeroize-on-dispose actually wipes the memory rather than a GC-moved copy,
    /// <see cref="AllocationKind.Managed"/> for public key encodings.
    /// </summary>
    /// <param name="keyBytes">The key bytes to copy into pooled memory.</param>
    /// <param name="memoryPool">The pool to rent the copy from.</param>
    /// <param name="kind">The allocation kind the rental requests.</param>
    /// <returns>The pool-owned copy; ownership transfers to the caller.</returns>
    private static IMemoryOwner<byte> AsPooledMemory(byte[] keyBytes, BaseMemoryPool memoryPool, AllocationKind kind)
    {
        IMemoryOwner<byte> keyBuffer = memoryPool.Rent(keyBytes.Length, kind);

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
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Jose;
using Verifiable.Json.Converters;
using Verifiable.Tests.DataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests using predefined JWT test data from external sources like jwt.io.
/// </summary>
[TestClass]
public sealed class JwsTestsWithPredefinedData
{
    /// <summary>
    /// JSON serializer options with dictionary converter.
    /// </summary>
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Converters = { new DictionaryStringObjectJsonConverter() }
    };


    [TestMethod]
    [DynamicData(nameof(JwtTestDataProvider.GetESTestData), typeof(JwtTestDataProvider))]
    public async Task EcdsaJwtFromTestDataVerifies(ESTestData testData)
    {
        using ECDsa ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(testData.PrivateKeyInPem);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);

        Tag privateKeyTag = GetEcdsaPrivateKeyTag(testData.Header);
        Tag signatureTag = GetEcdsaSignatureTag(testData.Header);
        HashAlgorithmName hashAlgorithm = GetEcdsaHashAlgorithm(testData.Header);
        ECCurve curve = GetEcdsaCurve(testData.Header);

        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(parameters.D!, privateKeyTag);

        SigningFunction<byte, byte, ValueTask<Signature>> signingFunction = (privateKeyBytes, dataToSign, signaturePool) =>
        {
            using ECDsa key = ECDsa.Create(new ECParameters { Curve = curve, D = privateKeyBytes.ToArray() });
            byte[] signatureBytes = key.SignData(dataToSign.Span, hashAlgorithm);
            IMemoryOwner<byte> memoryOwner = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryOwner.Memory.Span);
            return ValueTask.FromResult(new Signature(memoryOwner, signatureTag));
        };

        string signedJwt = await Jws.SignAsync(
            testData.Header,
            testData.Payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            signingFunction,
            SensitiveMemoryPool<byte>.Shared);

        //Header and payload should match the cross-check JWT exactly.
        Assert.AreEqual(testData.CrossCheckJwt.Split('.')[0], signedJwt.Split('.')[0], "Header segment should match.");
        Assert.AreEqual(testData.CrossCheckJwt.Split('.')[1], signedJwt.Split('.')[1], "Payload segment should match.");

        //Verify the signature we created.
        using ECDsa verifyKey = ECDsa.Create();
        verifyKey.ImportFromPem(testData.PublicKeyInPem);
        byte[] publicKeyBytes = verifyKey.ExportSubjectPublicKeyInfo();

        Tag publicKeyTag = GetEcdsaPublicKeyTag(testData.Header);
        using PublicKeyMemory publicKey = CreatePublicKeyMemory(publicKeyBytes, publicKeyTag);

        VerificationFunctionWithBytes<byte, byte, byte, bool> verificationFunction = (pubKey, data, sig) =>
        {
            using ECDsa key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(pubKey.Span, out _);
            return key.VerifyData(data, sig.Span, hashAlgorithm);
        };

        bool isValid = await Jws.VerifyAsync(
            signedJwt,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            publicKey,
            verificationFunction);

        Assert.IsTrue(isValid, "Signature verification should succeed.");
    }


    [TestMethod]
    [DynamicData(nameof(JwtTestDataProvider.GetRsaRsTestData), typeof(JwtTestDataProvider))]
    public async Task RsaRsJwtFromTestDataVerifies(RsaRSTestData testData)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(testData.PrivateKeyInPem);
        byte[] privateKeyBytes = rsa.ExportPkcs8PrivateKey();

        HashAlgorithmName hashAlgorithm = GetRsaHashAlgorithm(testData.Header);

        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(privateKeyBytes, Tag.Rsa2048PrivateKey);

        SigningFunction<byte, byte, ValueTask<Signature>> signingFunction = (privKey, dataToSign, signaturePool) =>
        {
            using RSA key = RSA.Create();
            key.ImportPkcs8PrivateKey(privKey.Span, out _);
            byte[] signatureBytes = key.SignData(dataToSign.Span, hashAlgorithm, RSASignaturePadding.Pkcs1);
            IMemoryOwner<byte> memoryOwner = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryOwner.Memory.Span);
            return ValueTask.FromResult(new Signature(memoryOwner, Tag.Empty));
        };

        string signedJwt = await Jws.SignAsync(
            testData.Header,
            testData.Payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            signingFunction,
            SensitiveMemoryPool<byte>.Shared);

        //RSA-PKCS1 signatures are deterministic, so all parts should match.
        Assert.AreEqual(testData.CrossCheckJwt, signedJwt, "Signed JWT should match cross-check JWT exactly.");
    }


    [TestMethod]
    [DynamicData(nameof(JwtTestDataProvider.GetRsaPsTestData), typeof(JwtTestDataProvider))]
    public async Task RsaPsJwtFromTestDataVerifies(RsaPSTestData testData)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(testData.PrivateKeyInPem);
        byte[] privateKeyBytes = rsa.ExportPkcs8PrivateKey();
        byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();

        HashAlgorithmName hashAlgorithm = GetRsaPsHashAlgorithm(testData.Header);

        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(privateKeyBytes, Tag.Rsa2048PrivateKey);

        SigningFunction<byte, byte, ValueTask<Signature>> signingFunction = (privKey, dataToSign, signaturePool) =>
        {
            using RSA key = RSA.Create();
            key.ImportPkcs8PrivateKey(privKey.Span, out _);
            byte[] signatureBytes = key.SignData(dataToSign.Span, hashAlgorithm, RSASignaturePadding.Pss);
            IMemoryOwner<byte> memoryOwner = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryOwner.Memory.Span);
            return ValueTask.FromResult(new Signature(memoryOwner, Tag.Empty));
        };

        string signedJwt = await Jws.SignAsync(
            testData.Header,
            testData.Payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            signingFunction,
            SensitiveMemoryPool<byte>.Shared);

        //Header and payload should match exactly.
        Assert.AreEqual(testData.CrossCheckJwt.Split('.')[0], signedJwt.Split('.')[0], "Header segment should match.");
        Assert.AreEqual(testData.CrossCheckJwt.Split('.')[1], signedJwt.Split('.')[1], "Payload segment should match.");

        //Verify the signature since PSS uses random padding.
        using PublicKeyMemory publicKey = CreatePublicKeyMemory(publicKeyBytes, Tag.Rsa2048PublicKey);

        VerificationFunctionWithBytes<byte, byte, byte, bool> verificationFunction = (pubKey, data, sig) =>
        {
            using RSA key = RSA.Create();
            key.ImportSubjectPublicKeyInfo(pubKey.Span, out _);
            return key.VerifyData(data, sig.Span, hashAlgorithm, RSASignaturePadding.Pss);
        };

        bool isValid = await Jws.VerifyAsync(
            signedJwt,
            TestSetup.Base64UrlDecoder,
            DecodeJwtPart,
            SensitiveMemoryPool<byte>.Shared,
            publicKey,
            verificationFunction);

        Assert.IsTrue(isValid, "RSA-PSS signature verification should succeed.");
    }


    /// <summary>
    /// Creates a <see cref="PrivateKeyMemory"/> from raw key bytes.
    /// </summary>
    private static PrivateKeyMemory CreatePrivateKeyMemory(byte[] keyBytes, Tag tag)
    {
        IMemoryOwner<byte> memoryOwner = SensitiveMemoryPool<byte>.Shared.Rent(keyBytes.Length);
        keyBytes.CopyTo(memoryOwner.Memory.Span);
        return new PrivateKeyMemory(memoryOwner, tag);
    }


    /// <summary>
    /// Creates a <see cref="PublicKeyMemory"/> from raw key bytes.
    /// </summary>
    private static PublicKeyMemory CreatePublicKeyMemory(byte[] keyBytes, Tag tag)
    {
        IMemoryOwner<byte> memoryOwner = SensitiveMemoryPool<byte>.Shared.Rent(keyBytes.Length);
        keyBytes.CopyTo(memoryOwner.Memory.Span);
        return new PublicKeyMemory(memoryOwner, tag);
    }


    private static Tag GetEcdsaPrivateKeyTag(Dictionary<string, object> header)
    {
        string alg = (string)header[JwkProperties.Alg];

        if(WellKnownJwaValues.IsEs256(alg))
        {
            return Tag.P256PrivateKey;
        }

        if(WellKnownJwaValues.IsEs384(alg))
        {
            return Tag.P384PrivateKey;
        }

        if(WellKnownJwaValues.IsEs512(alg))
        {
            return Tag.P521PrivateKey;
        }

        throw new NotSupportedException($"Algorithm '{alg}' is not supported.");
    }


    private static Tag GetEcdsaPublicKeyTag(Dictionary<string, object> header)
    {
        string alg = (string)header[JwkProperties.Alg];

        if(WellKnownJwaValues.IsEs256(alg))
        {
            return Tag.P256PublicKey;
        }

        if(WellKnownJwaValues.IsEs384(alg))
        {
            return Tag.P384PublicKey;
        }

        if(WellKnownJwaValues.IsEs512(alg))
        {
            return Tag.P521PublicKey;
        }

        throw new NotSupportedException($"Algorithm '{alg}' is not supported.");
    }


    private static Tag GetEcdsaSignatureTag(Dictionary<string, object> header)
    {
        string alg = (string)header[JwkProperties.Alg];

        if(WellKnownJwaValues.IsEs256(alg))
        {
            return Tag.P256Signature;
        }

        if(WellKnownJwaValues.IsEs384(alg))
        {
            return Tag.P384Signature;
        }

        if(WellKnownJwaValues.IsEs512(alg))
        {
            return Tag.P521Signature;
        }

        throw new NotSupportedException($"Algorithm '{alg}' is not supported.");
    }


    private static HashAlgorithmName GetEcdsaHashAlgorithm(Dictionary<string, object> header)
    {
        string alg = (string)header[JwkProperties.Alg];

        if(WellKnownJwaValues.IsEs256(alg))
        {
            return HashAlgorithmName.SHA256;
        }

        if(WellKnownJwaValues.IsEs384(alg))
        {
            return HashAlgorithmName.SHA384;
        }

        if(WellKnownJwaValues.IsEs512(alg))
        {
            return HashAlgorithmName.SHA512;
        }

        throw new NotSupportedException($"Algorithm '{alg}' is not supported.");
    }


    private static ECCurve GetEcdsaCurve(Dictionary<string, object> header)
    {
        string alg = (string)header[JwkProperties.Alg];

        if(WellKnownJwaValues.IsEs256(alg))
        {
            return ECCurve.NamedCurves.nistP256;
        }

        if(WellKnownJwaValues.IsEs384(alg))
        {
            return ECCurve.NamedCurves.nistP384;
        }

        if(WellKnownJwaValues.IsEs512(alg))
        {
            return ECCurve.NamedCurves.nistP521;
        }

        throw new NotSupportedException($"Algorithm '{alg}' is not supported.");
    }


    private static HashAlgorithmName GetRsaHashAlgorithm(Dictionary<string, object> header)
    {
        string alg = (string)header[JwkProperties.Alg];

        if(WellKnownJwaValues.IsRs256(alg))
        {
            return HashAlgorithmName.SHA256;
        }

        if(WellKnownJwaValues.IsRs384(alg))
        {
            return HashAlgorithmName.SHA384;
        }

        if(WellKnownJwaValues.IsRs512(alg))
        {
            return HashAlgorithmName.SHA512;
        }

        throw new NotSupportedException($"Algorithm '{alg}' is not supported.");
    }


    private static HashAlgorithmName GetRsaPsHashAlgorithm(Dictionary<string, object> header)
    {
        string alg = (string)header[JwkProperties.Alg];

        if(WellKnownJwaValues.IsPs256(alg))
        {
            return HashAlgorithmName.SHA256;
        }

        if(WellKnownJwaValues.IsPs384(alg))
        {
            return HashAlgorithmName.SHA384;
        }

        if(WellKnownJwaValues.IsPs512(alg))
        {
            return HashAlgorithmName.SHA512;
        }

        throw new NotSupportedException($"Algorithm '{alg}' is not supported.");
    }


    /// <summary>
    /// Encodes a JWT part (dictionary) to UTF-8 JSON bytes.
    /// </summary>
    private static ReadOnlySpan<byte> EncodeJwtPart(Dictionary<string, object> part)
    {
        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(part));
    }


    /// <summary>
    /// Decodes UTF-8 JSON bytes to a dictionary.
    /// </summary>
    private static Dictionary<string, object> DecodeJwtPart(ReadOnlySpan<byte> bytes)
    {
        string json = Encoding.UTF8.GetString(bytes);
        return JsonSerializer.Deserialize<Dictionary<string, object>>(json, JsonOptions)!;
    }
}
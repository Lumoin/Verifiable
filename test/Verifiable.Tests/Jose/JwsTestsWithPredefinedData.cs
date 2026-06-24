using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests using predefined JWT test data from external sources like jwt.io.
/// </summary>
[TestClass]
internal sealed class JwsTestsWithPredefinedData
{
    /// <summary>
    /// Test context for async operations.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


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

        SigningDelegate signingDelegate = (privateKeyBytes, dataToSign, signaturePool, context, cancellationToken) =>
        {
            using ECDsa key = ECDsa.Create(new ECParameters { Curve = curve, D = privateKeyBytes.ToArray() });
            byte[] signatureBytes = key.SignData(dataToSign.Span, hashAlgorithm);
            IMemoryOwner<byte> memoryOwner = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryOwner.Memory.Span);
            return ValueTask.FromResult(new Signature(memoryOwner, signatureTag));
        };

        JwsMessage jwsMessage = await Jws.SignAsync(
            testData.Header,
            testData.Payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            signingDelegate,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        string signedJwt = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        //Header and payload should match the cross-check JWT exactly.
        Assert.AreEqual(testData.CrossCheckJwt.Split('.')[0], signedJwt.Split('.')[0], "Header segment should match.");
        Assert.AreEqual(testData.CrossCheckJwt.Split('.')[1], signedJwt.Split('.')[1], "Payload segment should match.");

        //Verify the signature we created.
        using ECDsa verifyKey = ECDsa.Create();
        verifyKey.ImportFromPem(testData.PublicKeyInPem);
        byte[] publicKeyBytes = verifyKey.ExportSubjectPublicKeyInfo();

        Tag publicKeyTag = GetEcdsaPublicKeyTag(testData.Header);
        using PublicKeyMemory publicKey = CreatePublicKeyMemory(publicKeyBytes, publicKeyTag);

        VerificationDelegate verificationDelegate = (dataToVerify, signature, publicKeyBytes, context, cancellationToken) =>
        {
            using ECDsa key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKeyBytes.Span, out _);
            return ValueTask.FromResult(key.VerifyData(dataToVerify.Span, signature.Span, hashAlgorithm));
        };

        bool isValid = await Jws.VerifyAsync(
            signedJwt,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            verificationDelegate,
            TestContext.CancellationToken).ConfigureAwait(false);

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

        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(privateKeyBytes, CryptoTags.Rsa2048PrivateKey);

        SigningDelegate signingDelegate = (privKey, dataToSign, signaturePool, context, cancellationToken) =>
        {
            using RSA key = RSA.Create();
            key.ImportPkcs8PrivateKey(privKey.Span, out _);
            byte[] signatureBytes = key.SignData(dataToSign.Span, hashAlgorithm, RSASignaturePadding.Pkcs1);
            IMemoryOwner<byte> memoryOwner = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryOwner.Memory.Span);
            return ValueTask.FromResult(new Signature(memoryOwner, Tag.Empty));
        };

        JwsMessage jwsMessage = await Jws.SignAsync(
            testData.Header,
            testData.Payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            signingDelegate,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        string signedJwt = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

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

        using PrivateKeyMemory privateKey = CreatePrivateKeyMemory(privateKeyBytes, CryptoTags.Rsa2048PrivateKey);

        SigningDelegate signingDelegate = (privKey, dataToSign, signaturePool, context, cancellationToken) =>
        {
            using RSA key = RSA.Create();
            key.ImportPkcs8PrivateKey(privKey.Span, out _);
            byte[] signatureBytes = key.SignData(dataToSign.Span, hashAlgorithm, RSASignaturePadding.Pss);
            IMemoryOwner<byte> memoryOwner = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryOwner.Memory.Span);
            return ValueTask.FromResult(new Signature(memoryOwner, Tag.Empty));
        };

        JwsMessage jwsMessage = await Jws.SignAsync(
            testData.Header,
            testData.Payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            signingDelegate,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        string signedJwt = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        //Header and payload should match exactly.
        Assert.AreEqual(testData.CrossCheckJwt.Split('.')[0], signedJwt.Split('.')[0], "Header segment should match.");
        Assert.AreEqual(testData.CrossCheckJwt.Split('.')[1], signedJwt.Split('.')[1], "Payload segment should match.");

        //Verify the signature since PSS uses random padding.
        using PublicKeyMemory publicKey = CreatePublicKeyMemory(publicKeyBytes, CryptoTags.Rsa2048PublicKey);

        VerificationDelegate verificationDelegate = (dataToVerify, signature, pubKey, context, cancellationToken) =>
        {
            using RSA key = RSA.Create();
            key.ImportSubjectPublicKeyInfo(pubKey.Span, out _);
            return ValueTask.FromResult(key.VerifyData(dataToVerify.Span, signature.Span, hashAlgorithm, RSASignaturePadding.Pss));
        };

        bool isValid = await Jws.VerifyAsync(
            signedJwt,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            verificationDelegate,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid, "RSA-PSS signature verification should succeed.");
    }


    /// <summary>
    /// A malformed signature segment — base64url the decoder rejects, such as an out-of-alphabet
    /// character or a non-canonical final character — must make <see cref="Jws.VerifyAsync"/> return
    /// <see langword="false"/>, never throw. Verification of untrusted input fails closed: a signature
    /// that cannot be decoded cannot verify. Regression for an unguarded signature decode that
    /// surfaced malformed tokens as an escaping exception (a 500) instead of a clean rejection.
    /// </summary>
    [TestMethod]
    public async Task MalformedSignatureSegmentVerifiesAsFalseWithoutThrowing()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        var header = new Dictionary<string, object>
        {
            [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256,
            [WellKnownJoseHeaderNames.Typ] = "JWT"
        };
        var payload = new Dictionary<string, object> { ["sub"] = "malformed-signature-regression" };

        //Sign and verify through the registry-resolved primitives — the key's Tag selects the P-256
        //functions — so the test carries no raw cryptography and no naked key bytes.
        JwsMessage jwsMessage = await Jws.SignAsync(
            header,
            payload,
            EncodeJwtPart,
            TestSetup.Base64UrlEncoder,
            privateKey,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        string signedJwt = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);
        string[] segments = signedJwt.Split('.');
        Assert.HasCount(3, segments);

        //(a) An out-of-alphabet character in the signature segment — every compliant base64url decoder
        //rejects it. Before the leaf guard the decoder's exception escaped Jws.VerifyAsync.
        string invalidCharJwt = string.Join('.', segments[0], segments[1],
            string.Concat(segments[2].AsSpan(0, segments[2].Length - 1), "!"));

        bool invalidCharIsValid = await Jws.VerifyAsync(
            invalidCharJwt,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(invalidCharIsValid, "An out-of-alphabet base64url signature must verify as false, not throw.");

        //(b) A non-canonical final character (the exact shape that intermittently crashed before the
        //guard): for a 64-byte ES256 signature 'B' sets the unused padding bits non-zero.
        string nonCanonicalJwt = string.Join('.', segments[0], segments[1],
            string.Concat(segments[2].AsSpan(0, segments[2].Length - 1), "B"));

        bool nonCanonicalIsValid = await Jws.VerifyAsync(
            nonCanonicalJwt,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            publicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(nonCanonicalIsValid, "A non-canonical base64url signature must verify as false, not throw.");
    }


    /// <summary>
    /// Creates a <see cref="PrivateKeyMemory"/> from raw key bytes.
    /// </summary>
    private static PrivateKeyMemory CreatePrivateKeyMemory(byte[] keyBytes, Tag tag)
    {
        IMemoryOwner<byte> memoryOwner = BaseMemoryPool.Shared.Rent(keyBytes.Length);
        keyBytes.CopyTo(memoryOwner.Memory.Span);
        return new PrivateKeyMemory(memoryOwner, tag);
    }


    /// <summary>
    /// Creates a <see cref="PublicKeyMemory"/> from raw key bytes.
    /// </summary>
    private static PublicKeyMemory CreatePublicKeyMemory(byte[] keyBytes, Tag tag)
    {
        IMemoryOwner<byte> memoryOwner = BaseMemoryPool.Shared.Rent(keyBytes.Length);
        keyBytes.CopyTo(memoryOwner.Memory.Span);
        return new PublicKeyMemory(memoryOwner, tag);
    }


    private static Tag GetEcdsaPrivateKeyTag(Dictionary<string, object> header)
    {
        string alg = (string)header[WellKnownJwkMemberNames.Alg];

        if(WellKnownJwaValues.IsEs256(alg))
        {
            return CryptoTags.P256PrivateKey;
        }

        if(WellKnownJwaValues.IsEs384(alg))
        {
            return CryptoTags.P384PrivateKey;
        }

        if(WellKnownJwaValues.IsEs512(alg))
        {
            return CryptoTags.P521PrivateKey;
        }

        throw new NotSupportedException($"Algorithm '{alg}' is not supported.");
    }


    private static Tag GetEcdsaPublicKeyTag(Dictionary<string, object> header)
    {
        string alg = (string)header[WellKnownJwkMemberNames.Alg];

        if(WellKnownJwaValues.IsEs256(alg))
        {
            return CryptoTags.P256PublicKey;
        }

        if(WellKnownJwaValues.IsEs384(alg))
        {
            return CryptoTags.P384PublicKey;
        }

        if(WellKnownJwaValues.IsEs512(alg))
        {
            return CryptoTags.P521PublicKey;
        }

        throw new NotSupportedException($"Algorithm '{alg}' is not supported.");
    }


    private static Tag GetEcdsaSignatureTag(Dictionary<string, object> header)
    {
        string alg = (string)header[WellKnownJwkMemberNames.Alg];

        if(WellKnownJwaValues.IsEs256(alg))
        {
            return CryptoTags.P256Signature;
        }

        if(WellKnownJwaValues.IsEs384(alg))
        {
            return CryptoTags.P384Signature;
        }

        if(WellKnownJwaValues.IsEs512(alg))
        {
            return CryptoTags.P521Signature;
        }

        throw new NotSupportedException($"Algorithm '{alg}' is not supported.");
    }


    private static HashAlgorithmName GetEcdsaHashAlgorithm(Dictionary<string, object> header)
    {
        string alg = (string)header[WellKnownJwkMemberNames.Alg];

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
        string alg = (string)header[WellKnownJwkMemberNames.Alg];

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
        string alg = (string)header[WellKnownJwkMemberNames.Alg];

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
        string alg = (string)header[WellKnownJwkMemberNames.Alg];

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
    /// Encodes a JWT part (dictionary) to tagged memory with UTF-8 JSON bytes.
    /// </summary>
    private static TaggedMemory<byte> EncodeJwtPart(Dictionary<string, object> part)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializerExtensions.Serialize(part, TestSetup.DefaultSerializationOptions));
        return new TaggedMemory<byte>(bytes, BufferTags.Json);
    }
}
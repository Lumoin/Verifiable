using System.Buffers;
using System.Formats.Cbor;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VDS.RDF;
using VDS.RDF.Parsing;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Proofs;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Jose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Credential;

/// <summary>
/// Tests all W3C VC Data Model 2.0 securing methods using the same unsigned credential.
/// Mirrors the tabs shown in W3C VC Data Model 2.0 spec: Credential | ecdsa | ecdsa-sd | jose | cose | sd-jwt.
/// </summary>
/// <remarks>
/// <para>
/// Each test takes the same unsigned credential and produces output in a different format,
/// demonstrating the library user's workflow for each securing mechanism.
/// </para>
/// <para>
/// BBS is excluded as it requires pairing-friendly curves not yet implemented.
/// </para>
/// </remarks>
[TestClass]
public sealed class CredentialSecuringMethodsTests
{
    /// <summary>
    /// Test context for cancellation token support.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>
    /// P-256 issuer key material generated using BouncyCastle for cross-platform compatibility.
    /// </summary>
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256IssuerKeys { get; } =
        BouncyCastleKeyCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

    /// <summary>
    /// P-256 ephemeral key material generated using BouncyCastle for cross-platform compatibility.
    /// </summary>
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256EphemeralKeys { get; } =
        BouncyCastleKeyCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

    /// <summary>
    /// Ed25519 public key from W3C Data Integrity EdDSA spec.
    /// </summary>
    private const string Ed25519PublicKeyMultibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    /// <summary>
    /// Ed25519 secret key from W3C Data Integrity EdDSA spec.
    /// </summary>
    private const string Ed25519SecretKeyMultibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

    /// <summary>
    /// Verification method DID URL for Ed25519 test key.
    /// </summary>
    private const string Ed25519VerificationMethodId = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    /// <summary>
    /// Unsigned credential JSON based on W3C VC Data Model 2.0 Example 5.
    /// </summary>
    private const string UnsignedCredentialJson = /*lang=json,strict*/ """
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": {
                "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
                "name": "Example University"
            },
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                    "type": "ExampleBachelorDegree",
                    "name": "Bachelor of Science and Arts"
                }
            }
        }
        """;

    /// <summary>
    /// Proof options JSON for eddsa-rdfc-2022.
    /// </summary>
    private const string ProofOptionsJson = /*lang=json,strict*/ """
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "created": "2024-01-01T00:00:00Z",
            "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            "proofPurpose": "assertionMethod",
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ]
        }
        """;

    /// <summary>
    /// Tests eddsa-rdfc-2022 Data Integrity proof (the "ecdsa" tab equivalent with EdDSA).
    /// </summary>
    [TestMethod]
    public async ValueTask EddsaRdfc2022DataIntegrityProofSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;
        var credentialJson = JsonSerializer.Serialize(credential, JsonOptions);

        var canonicalCredential = Canonicalize(credentialJson);
        var canonicalProofOptions = Canonicalize(ProofOptionsJson);

        var credentialHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalCredential));
        var proofOptionsHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalProofOptions));
        var hashData = proofOptionsHash.Concat(credentialHash).ToArray();

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        var signature = await privateKeyMemory.SignAsync(hashData, BouncyCastleAlgorithms.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);
        var proofValue = $"{MultibaseAlgorithms.Base58Btc}{TestSetup.Base58Encoder(signature.AsReadOnlySpan())}";

        credential.Proof =
        [
            new DataIntegrityProof
            {
                Type = "DataIntegrityProof",
                Cryptosuite = CryptosuiteInfoExtensions.FromName("eddsa-rdfc-2022"),
                Created = "2024-01-01T00:00:00Z",
                VerificationMethod = new AssertionMethod(Ed25519VerificationMethodId),
                ProofPurpose = "assertionMethod",
                ProofValue = proofValue
            }
        ];

        Assert.IsNotNull(proofValue);
        Assert.StartsWith("z", proofValue, "Proof value must be base58btc encoded.");
        Assert.IsGreaterThan(80, proofValue.Length, "Ed25519 signature should produce substantial proof value.");
        Assert.IsNotNull(credential.Proof);
        Assert.HasCount(1, credential.Proof);

        //Verify signature.
        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase,
            MulticodecHeaders.Ed25519PublicKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var signatureBytes = MultibaseSerializer.Decode(proofValue, 0, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        var signatureToVerify = new Signature(signatureBytes, CryptoTags.Ed25519Signature);

        bool isValid = await publicKeyMemory.VerifyAsync(hashData, signatureToVerify, BouncyCastleAlgorithms.VerifyEd25519Async);
        Assert.IsTrue(isValid, "Signature verification must succeed.");
    }


    /// <summary>
    /// Tests ecdsa-sd-2023 Data Integrity proof with selective disclosure (the "ecdsa-sd" tab).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This test demonstrates the full ecdsa-sd-2023 workflow:
    /// </para>
    /// <list type="number">
    /// <item><description>Issuer creates base proof with all statements signed.</description></item>
    /// <item><description>Holder derives proof selecting which claims to disclose.</description></item>
    /// <item><description>Verifier validates the derived proof.</description></item>
    /// </list>
    /// <para>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#ecdsa-sd-2023">
    /// W3C VC DI ECDSA §3.3 ecdsa-sd-2023</see>.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async ValueTask EcdsaSd2023DataIntegrityProofSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;
        var credentialJson = JsonSerializer.Serialize(credential, JsonOptions);

        //Step 1: Canonicalize credential to N-Quads.
        var canonicalNQuads = Canonicalize(credentialJson);
        var statements = canonicalNQuads.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.IsGreaterThan(0, statements.Length, "Credential must canonicalize to at least one N-Quad statement.");

        //Step 2: Define mandatory pointers (claims that are always disclosed).
        var mandatoryPointers = new List<string>
        {
            "/issuer/id",
            "/validFrom",
            "/credentialSubject/id"
        };

        //Step 3: Use pre-generated P-256 cryptographic material from BouncyCastle.
        var issuerKeys = P256IssuerKeys;
        var ephemeralKeys = P256EphemeralKeys;

        var hmacKey = RandomNumberGenerator.GetBytes(32);

        //Step 4: HMAC-relabel blank nodes for unlinkability.
        var relabeledStatements = new List<string>();
        foreach(var statement in statements)
        {
            var relabeled = RelabelBlankNodes(statement, hmacKey);
            relabeledStatements.Add(relabeled);
        }

        //Step 5: Separate mandatory and non-mandatory statements.
        //For simplicity, treat first 2 statements as mandatory, rest as non-mandatory.
        var mandatoryStatements = relabeledStatements.Take(2).ToList();
        var nonMandatoryStatements = relabeledStatements.Skip(2).ToList();

        //Step 6: Hash mandatory statements together.
        var mandatoryHash = SHA256.HashData(
            Encoding.UTF8.GetBytes(string.Join("\n", mandatoryStatements)));

        //Step 7: Get ephemeral public key in multikey format (compressed with header).
        var ephemeralPublicKeyBytes = ephemeralKeys.PublicKey.AsReadOnlySpan().ToArray();
        var ephemeralPublicKey = new byte[2 + ephemeralPublicKeyBytes.Length];
        ephemeralPublicKey[0] = 0x80; //Multikey header byte 1.
        ephemeralPublicKey[1] = 0x24; //Multikey header byte 2 for P-256.
        ephemeralPublicKeyBytes.CopyTo(ephemeralPublicKey.AsSpan(2));

        //Step 8: Create base signature over (proofHash || publicKey || mandatoryHash).
        var proofOptionsJson = /*lang=json,strict*/ """
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "ecdsa-sd-2023",
                "created": "2024-01-01T00:00:00Z",
                "verificationMethod": "did:example:issuer#key-1",
                "proofPurpose": "assertionMethod",
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://www.w3.org/ns/credentials/examples/v2"
                ]
            }
            """;
        var canonicalProofOptions = Canonicalize(proofOptionsJson);
        var proofHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalProofOptions));

        var baseSignatureInput = new byte[proofHash.Length + ephemeralPublicKey.Length + mandatoryHash.Length];
        proofHash.CopyTo(baseSignatureInput.AsSpan());
        ephemeralPublicKey.CopyTo(baseSignatureInput.AsSpan(proofHash.Length));
        mandatoryHash.CopyTo(baseSignatureInput.AsSpan(proofHash.Length + ephemeralPublicKey.Length));

        using var baseSignature = await issuerKeys.PrivateKey.SignAsync(
            baseSignatureInput,
            BouncyCastleAlgorithms.SignP256Async,
            SensitiveMemoryPool<byte>.Shared);

        //Step 9: Sign each non-mandatory statement with ephemeral key.
        var statementSignatures = new List<byte[]>();
        foreach(var statement in nonMandatoryStatements)
        {
            var statementBytes = Encoding.UTF8.GetBytes(statement);
            using var statementSignature = await ephemeralKeys.PrivateKey.SignAsync(
                statementBytes,
                BouncyCastleAlgorithms.SignP256Async,
                SensitiveMemoryPool<byte>.Shared);
            statementSignatures.Add(statementSignature.AsReadOnlySpan().ToArray());
        }

        //Step 10: Serialize base proof.
        var baseProofValue = EcdsaSd2023CborSerializer.SerializeBaseProof(
            baseSignature.AsReadOnlySpan(),
            ephemeralPublicKey,
            hmacKey,
            statementSignatures,
            mandatoryPointers,
            TestSetup.Base64UrlEncoder);

        Assert.StartsWith("u", baseProofValue, "Base proof must use base64url-no-pad multibase encoding.");

        //Step 11: Parse base proof to verify round-trip.
        var parsedBase = EcdsaSd2023CborSerializer.ParseBaseProof(
            baseProofValue,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(baseSignature.AsReadOnlySpan().SequenceEqual(parsedBase.BaseSignature), "Base signature must round-trip.");
        Assert.IsTrue(ephemeralPublicKey.AsSpan().SequenceEqual(parsedBase.PublicKey), "Public key must round-trip.");
        Assert.IsTrue(hmacKey.AsSpan().SequenceEqual(parsedBase.HmacKey), "HMAC key must round-trip.");
        Assert.HasCount(statementSignatures.Count, parsedBase.Signatures, "Signature count must match.");
        Assert.HasCount(mandatoryPointers.Count, parsedBase.MandatoryPointers, "Mandatory pointer count must match.");

        //Step 12: Holder creates derived proof (selective disclosure).
        //Holder chooses to disclose only first non-mandatory statement.
        var disclosedIndexes = new List<int> { 0 };
        var disclosedSignatures = disclosedIndexes
            .Where(i => i < statementSignatures.Count)
            .Select(i => statementSignatures[i])
            .ToList();

        //Build label map for disclosed statements.
        var labelMap = new Dictionary<string, string>
        {
            ["c14n0"] = "u" + TestSetup.Base64UrlEncoder(RandomNumberGenerator.GetBytes(32)),
            ["c14n1"] = "u" + TestSetup.Base64UrlEncoder(RandomNumberGenerator.GetBytes(32))
        };

        var mandatoryIndexes = new List<int> { 0, 1 };

        var derivedProofValue = EcdsaSd2023CborSerializer.SerializeDerivedProof(
            baseSignature.AsReadOnlySpan(),
            ephemeralPublicKey,
            disclosedSignatures,
            labelMap,
            mandatoryIndexes,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared);

        Assert.StartsWith("u", derivedProofValue, "Derived proof must use base64url-no-pad multibase encoding.");

        //Step 13: Verifier parses and validates derived proof.
        var parsedDerived = EcdsaSd2023CborSerializer.ParseDerivedProof(
            derivedProofValue,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(baseSignature.AsReadOnlySpan().SequenceEqual(parsedDerived.BaseSignature), "Derived proof base signature must match.");
        Assert.IsTrue(ephemeralPublicKey.AsSpan().SequenceEqual(parsedDerived.PublicKey), "Derived proof public key must match.");
        Assert.HasCount(disclosedSignatures.Count, parsedDerived.Signatures, "Disclosed signature count must match.");
        Assert.HasCount(labelMap.Count, parsedDerived.LabelMap, "Label map count must match.");
        Assert.HasCount(mandatoryIndexes.Count, parsedDerived.MandatoryIndexes, "Mandatory indexes count must match.");

        //Step 14: Verify base signature using issuer's public key.
        var baseSignatureMemory = SensitiveMemoryPool<byte>.Shared.Rent(parsedDerived.BaseSignature.Length);
        parsedDerived.BaseSignature.CopyTo(baseSignatureMemory.Memory.Span);
        var baseSignatureToVerify = new Signature(baseSignatureMemory, CryptoTags.P256Signature);
        bool baseSignatureValid = await issuerKeys.PublicKey.VerifyAsync(
            baseSignatureInput,
            baseSignatureToVerify,
            BouncyCastleAlgorithms.VerifyP256Async);

        Assert.IsTrue(baseSignatureValid, "Base signature verification must succeed.");

        //Step 15: Verify disclosed statement signatures using ephemeral public key.
        for(int i = 0; i < parsedDerived.Signatures.Count; i++)
        {
            var disclosedStatementIndex = disclosedIndexes[i];
            var statement = nonMandatoryStatements[disclosedStatementIndex];
            var statementBytes = Encoding.UTF8.GetBytes(statement);

            var statementSignatureMemory = SensitiveMemoryPool<byte>.Shared.Rent(parsedDerived.Signatures[i].Length);
            parsedDerived.Signatures[i].CopyTo(statementSignatureMemory.Memory.Span);
            var statementSignatureToVerify = new Signature(statementSignatureMemory, CryptoTags.P256Signature);
            bool statementValid = await ephemeralKeys.PublicKey.VerifyAsync(
                statementBytes,
                statementSignatureToVerify,
                BouncyCastleAlgorithms.VerifyP256Async);

            Assert.IsTrue(statementValid, $"Statement {i} signature verification must succeed.");
        }

        //Step 16: Attach proof to credential for completeness.
        credential.Proof =
        [
            new DataIntegrityProof
            {
                Type = "DataIntegrityProof",
                Cryptosuite = EcdsaSd2023CryptosuiteInfo.Instance,
                Created = "2024-01-01T00:00:00Z",
                VerificationMethod = new AssertionMethod("did:example:issuer#key-1"),
                ProofPurpose = "assertionMethod",
                ProofValue = derivedProofValue
            }
        ];

        Assert.IsNotNull(credential.Proof);
        Assert.HasCount(1, credential.Proof);
        Assert.AreEqual("ecdsa-sd-2023", credential.Proof[0].Cryptosuite?.CryptosuiteName);
    }


    /// <summary>
    /// Relabels blank nodes in an N-Quad using HMAC for unlinkability.
    /// </summary>
    private static string RelabelBlankNodes(string nquad, byte[] hmacKey)
    {
        var result = nquad;
        var index = 0;

        while((index = result.IndexOf("_:c", index, StringComparison.Ordinal)) >= 0)
        {
            var endIndex = index + 3;
            while(endIndex < result.Length && char.IsDigit(result[endIndex]))
            {
                endIndex++;
            }

            var blankNodeId = result[(index + 2)..endIndex];
            var hmacBytes = HMACSHA256.HashData(hmacKey, Encoding.UTF8.GetBytes(blankNodeId));
            var hmacId = "u" + TestSetup.Base64UrlEncoder(hmacBytes);

            result = string.Concat(result.AsSpan(0, index), "_:", hmacId, result.AsSpan(endIndex));
            index += 2 + hmacId.Length;
        }

        return result;
    }


    /// <summary>
    /// Tests application/vc+jwt envelope (the "jose" tab).
    /// Uses the credential.SignJwsAsync() extension method.
    /// </summary>
    [TestMethod]
    public async ValueTask JoseJwtEnvelopeSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKeyMemory,
            Ed25519VerificationMethodId,
            CredentialSerializer,
            HeaderSerializer,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(jws);
        var parts = jws.Split('.');
        Assert.HasCount(3, parts);
        Assert.IsNotEmpty(parts[0], "Header must not be empty.");
        Assert.IsNotEmpty(parts[1], "Payload must not be empty.");
        Assert.IsNotEmpty(parts[2], "Signature must not be empty.");

        //Verify signature.
        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase,
            MulticodecHeaders.Ed25519PublicKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var verificationResult = await JwsCredentialVerification.VerifyAsync(
            jws,
            publicKeyMemory,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            CredentialDeserializer,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(verificationResult.IsValid, "JWT signature verification must succeed.");
        Assert.IsNotNull(verificationResult.Credential);
        Assert.AreEqual(credential.Id, verificationResult.Credential.Id);
    }


    /// <summary>
    /// Tests application/vc+cose envelope (the "cose" tab).
    /// Uses COSE_Sign1 structure per RFC 9052.
    /// </summary>
    [TestMethod]
    public async ValueTask CoseEnvelopeSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        //Serialize credential to JSON payload.
        var payload = JsonSerializer.SerializeToUtf8Bytes(credential, JsonOptions);

        //Build protected header using CoseSerialization.
        var headerMap = new Dictionary<int, object>
        {
            [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.EdDsa,
            [CoseHeaderParameters.Kid] = Ed25519VerificationMethodId
        };
        var protectedHeader = CoseSerialization.SerializeProtectedHeader(headerMap);

        //Sign using library Cose.SignAsync.
        var message = await Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKeyMemory,
            BouncyCastleAlgorithms.SignEd25519Async,
            SensitiveMemoryPool<byte>.Shared);

        //Serialize to wire format.
        byte[] coseSign1 = CoseSerialization.SerializeCoseSign1(message);

        Assert.IsNotNull(coseSign1);
        Assert.IsGreaterThan(100, coseSign1.Length, "COSE_Sign1 should be substantial.");

        //Verify using the extracted verification method.
        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase,
            MulticodecHeaders.Ed25519PublicKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        //Parse and verify using library APIs.
        var parsedMessage = CoseSerialization.ParseCoseSign1(coseSign1);

        bool isValid = await Cose.VerifyAsync(
            parsedMessage,
            CoseSerialization.BuildSigStructure,
            publicKeyMemory,
            BouncyCastleAlgorithms.VerifyEd25519Async,
            SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(isValid, "COSE signature verification must succeed.");
        Assert.IsGreaterThan(0, parsedMessage.Payload.Length, "Payload must not be empty.");

        //Verify payload deserializes back to credential.
        var deserializedCredential = JsonSerializer.Deserialize<VerifiableCredential>(parsedMessage.Payload.Span, JsonOptions);
        Assert.IsNotNull(deserializedCredential);
        Assert.AreEqual(credential.Id, deserializedCredential.Id);
    }


    /// <summary>
    /// Tests SD-JWT envelope with selective disclosure (the "sd-jwt" tab).
    /// </summary>
    [TestMethod]
    public async ValueTask SdJwtEnvelopeSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        //Create disclosures for selectively disclosable claims.
        byte[] salt1 = SdSaltGenerator.Generate();
        byte[] salt2 = SdSaltGenerator.Generate();

        var disclosure1 = SdDisclosure.CreateProperty(
            salt1,
            "degree",
            new Dictionary<string, object>
            {
                ["type"] = "ExampleBachelorDegree",
                ["name"] = "Bachelor of Science and Arts"
            });

        var disclosure2 = SdDisclosure.CreateProperty(
            salt2,
            "name",
            "Example University");

        //Encode disclosures for wire format.
        string encodedDisclosure1 = EncodeDisclosure(disclosure1, TestSetup.Base64UrlEncoder);
        string encodedDisclosure2 = EncodeDisclosure(disclosure2, TestSetup.Base64UrlEncoder);

        //Compute digests for _sd array.
        string digest1 = ComputeDisclosureDigest(encodedDisclosure1, TestSetup.Base64UrlEncoder);
        string digest2 = ComputeDisclosureDigest(encodedDisclosure2, TestSetup.Base64UrlEncoder);

        //Build SD-JWT payload with _sd claims.
        var sdPayload = new Dictionary<string, object>
        {
            ["@context"] = credential.Context!,
            ["id"] = credential.Id!,
            ["type"] = credential.Type!,
            ["issuer"] = new Dictionary<string, object>
            {
                ["id"] = credential.Issuer!.Id!,
                [SdConstants.SdClaimName] = new[] { digest2 }
            },
            ["validFrom"] = credential.ValidFrom!,
            ["credentialSubject"] = new Dictionary<string, object>
            {
                ["id"] = credential.CredentialSubject![0].Id!,
                [SdConstants.SdClaimName] = new[] { digest1 }
            },
            [SdConstants.SdAlgorithmClaimName] = SdConstants.DefaultHashAlgorithm
        };

        //Sign the SD-JWT payload as a regular JWT.
        var header = new Dictionary<string, object>
        {
            [JwkProperties.Alg] = WellKnownJwaValues.EdDsa,
            [JwkProperties.Typ] = "vc+sd-jwt",
            [JwkProperties.Kid] = Ed25519VerificationMethodId
        };

        var headerJson = JsonSerializer.SerializeToUtf8Bytes(header);
        var payloadJson = JsonSerializer.SerializeToUtf8Bytes(sdPayload);

        var headerBase64Url = TestSetup.Base64UrlEncoder(headerJson);
        var payloadBase64Url = TestSetup.Base64UrlEncoder(payloadJson);
        var signingInput = $"{headerBase64Url}.{payloadBase64Url}";

        var signature = await privateKeyMemory.SignAsync(
            Encoding.ASCII.GetBytes(signingInput),
            BouncyCastleAlgorithms.SignEd25519Async,
            SensitiveMemoryPool<byte>.Shared);

        var issuerSignedJwt = $"{signingInput}.{TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan())}";

        //Build SD-JWT wire format: jwt~disclosure1~disclosure2~
        var sdJwt = $"{issuerSignedJwt}{SdConstants.JwtSeparator}{encodedDisclosure1}{SdConstants.JwtSeparator}{encodedDisclosure2}{SdConstants.JwtSeparator}";

        Assert.IsNotNull(sdJwt);
        Assert.Contains("~", sdJwt);
        Assert.EndsWith("~", sdJwt, "SD-JWT without key binding must end with tilde.");

        //Verify structure by parsing.
        var parts = sdJwt.Split(SdConstants.JwtSeparator);
        Assert.IsGreaterThan(3, parts.Length, "SD-JWT must have JWT plus disclosures.");
        Assert.AreEqual(issuerSignedJwt, parts[0]);

        //Verify JWT signature.
        var jwtParts = parts[0].Split('.');
        Assert.HasCount(3, jwtParts);

        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase,
            MulticodecHeaders.Ed25519PublicKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var verificationInput = Encoding.ASCII.GetBytes($"{jwtParts[0]}.{jwtParts[1]}");
        using var signatureBytesFromJwt = TestSetup.Base64UrlDecoder(jwtParts[2], SensitiveMemoryPool<byte>.Shared);
        var signatureToVerify = new Signature(signatureBytesFromJwt, CryptoTags.Ed25519Signature);
        bool isValid = await publicKeyMemory.VerifyAsync(verificationInput, signatureToVerify, BouncyCastleAlgorithms.VerifyEd25519Async);
        Assert.IsTrue(isValid, "SD-JWT signature verification must succeed.");
    }


    /// <summary>
    /// Tests SD-CWT envelope with selective disclosure (IETF SPICE draft).
    /// </summary>
    /// <remarks>
    /// <para>
    /// SD-CWT is the CBOR equivalent of SD-JWT, using COSE_Sign1 as the envelope
    /// with disclosures in the unprotected header.
    /// </para>
    /// <para>
    /// See <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
    /// draft-ietf-spice-sd-cwt</see>.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async ValueTask SdCwtEnvelopeSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        //Create disclosures for selectively disclosable claims.
        var disclosure1 = SdDisclosure.CreateProperty(
            SdSaltGenerator.Generate(),
            "degree",
            new Dictionary<string, object?>
            {
                ["type"] = "ExampleBachelorDegree",
                ["name"] = "Bachelor of Science and Arts"
            });

        var disclosure2 = SdDisclosure.CreateProperty(
            SdSaltGenerator.Generate(),
            "name",
            "Example University");

        var disclosures = new[] { disclosure1, disclosure2 };

        //Build CWT claims payload.
        byte[] payload = BuildCwtPayload(credential);

        //Build protected header.
        byte[] protectedHeader = BuildSdCwtProtectedHeader();

        //Sign the SD-CWT using library APIs.
        var message = await Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            privateKeyMemory,
            BouncyCastleAlgorithms.SignEd25519Async,
            SensitiveMemoryPool<byte>.Shared);

        //Create and serialize the SD-CWT message with disclosures.
        var sdCwtMessage = new SdCwtMessage(payload, protectedHeader, message.Signature.ToArray(), disclosures);
        byte[] sdCwt = SdCwtSerializer.Serialize(sdCwtMessage);

        Assert.IsGreaterThan(100, sdCwt.Length, "SD-CWT should be substantial.");

        //Verify the COSE_Sign1 structure using library APIs.
        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase,
            MulticodecHeaders.Ed25519PublicKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        //Parse SD-CWT and verify.
        SdCwtMessage parsed = SdCwtSerializer.Parse(sdCwt);

        var coseMessage = new CoseSign1Message(
            parsed.ProtectedHeader,
            unprotectedHeader: null,
            parsed.Payload,
            parsed.Signature);

        bool isValid = await Cose.VerifyAsync(
            coseMessage,
            CoseSerialization.BuildSigStructure,
            publicKeyMemory,
            BouncyCastleAlgorithms.VerifyEd25519Async,
            SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(isValid, "SD-CWT signature verification must succeed.");
        Assert.IsGreaterThan(0, parsed.Payload.Length, "Payload must not be empty.");

        //Verify disclosures.
        Assert.HasCount(2, parsed.Disclosures);
        Assert.AreEqual("degree", parsed.Disclosures[0].ClaimName);
        Assert.AreEqual("name", parsed.Disclosures[1].ClaimName);
    }


    /// <summary>
    /// Builds a CWT claims payload from a credential.
    /// </summary>
    private static byte[] BuildCwtPayload(VerifiableCredential credential)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(3);

        //iss (1).
        writer.WriteInt32(WellKnownCwtClaims.Iss);
        writer.WriteTextString(credential.Issuer!.Id!);

        //sub (2).
        writer.WriteInt32(WellKnownCwtClaims.Sub);
        writer.WriteTextString(credential.CredentialSubject![0].Id!);

        //iat (6).
        writer.WriteInt32(WellKnownCwtClaims.Iat);
        long issuedAt = !string.IsNullOrEmpty(credential.ValidFrom)
            ? DateTimeOffset.Parse(credential.ValidFrom, CultureInfo.InvariantCulture).ToUnixTimeSeconds()
            : 0L;
        writer.WriteInt64(issuedAt);

        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>
    /// Builds an SD-CWT protected header.
    /// </summary>
    private static byte[] BuildSdCwtProtectedHeader()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(CoseHeaderParameters.Alg);
        writer.WriteInt32(WellKnownCoseAlgorithms.EdDsa);
        writer.WriteInt32(CoseHeaderParameters.Typ);
        writer.WriteTextString(SdCwtSerializer.SdCwtMediaType);
        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>
    /// Canonicalizes a JSON-LD document using RDFC-1.0 via dotNetRdf.
    /// </summary>
    private static string Canonicalize(string jsonLdDocument)
    {
        var store = new TripleStore();
        var parser = new JsonLdParser();
        using var reader = new StringReader(jsonLdDocument);
        parser.Load(store, reader);

        var canonicalizer = new RdfCanonicalizer();
        var canonicalizedResult = canonicalizer.Canonicalize(store);

        return canonicalizedResult.SerializedNQuads;
    }


    private static ReadOnlySpan<byte> CredentialSerializer(VerifiableCredential credential) =>
        JsonSerializer.SerializeToUtf8Bytes(credential, JsonOptions);


    private static ReadOnlySpan<byte> HeaderSerializer(Dictionary<string, object> header) =>
        JsonSerializer.SerializeToUtf8Bytes(header);


    private static Dictionary<string, object>? HeaderDeserializer(ReadOnlySpan<byte> headerBytes) =>
        JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes);


    private static VerifiableCredential CredentialDeserializer(ReadOnlySpan<byte> credentialBytes) =>
        JsonSerializer.Deserialize<VerifiableCredential>(credentialBytes, JsonOptions)!;


    /// <summary>
    /// Encodes a disclosure to Base64Url JSON array format.
    /// </summary>
    private static string EncodeDisclosure(SdDisclosure disclosure, EncodeDelegate base64UrlEncoder)
    {
        string saltBase64Url = base64UrlEncoder(disclosure.Salt.Span);
        string json;

        if(disclosure.ClaimName is not null)
        {
            string valueJson = JsonSerializer.Serialize(disclosure.ClaimValue);
            json = $"[\"{saltBase64Url}\",\"{disclosure.ClaimName}\",{valueJson}]";
        }
        else
        {
            string valueJson = JsonSerializer.Serialize(disclosure.ClaimValue);
            json = $"[\"{saltBase64Url}\",{valueJson}]";
        }

        return base64UrlEncoder(Encoding.UTF8.GetBytes(json));
    }


    /// <summary>
    /// Computes the digest of an encoded disclosure.
    /// </summary>
    private static string ComputeDisclosureDigest(string encodedDisclosure, EncodeDelegate base64UrlEncoder)
    {
        byte[] disclosureBytes = Encoding.ASCII.GetBytes(encodedDisclosure);
        byte[] hashBytes = SHA256.HashData(disclosureBytes);
        return base64UrlEncoder(hashBytes);
    }
}
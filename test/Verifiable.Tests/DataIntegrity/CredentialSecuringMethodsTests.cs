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
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Jose;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Tests all W3C VC Data Model 2.0 securing methods using the same unsigned credential.
/// </summary>
[TestClass]
public sealed class CredentialSecuringMethodsTests
{
    public TestContext TestContext { get; set; } = null!;

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256IssuerKeys { get; } = BouncyCastleKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256EphemeralKeys { get; } = BouncyCastleKeyMaterialCreator.CreateP256Keys(SensitiveMemoryPool<byte>.Shared);

    private const string Ed25519PublicKeyMultibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    private const string Ed25519SecretKeyMultibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";
    private const string Ed25519VerificationMethodId = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

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

    private static readonly DateTime ProofCreated = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);


    /// <summary>
    /// Tests eddsa-rdfc-2022 Data Integrity proof using SignAsync and VerifyAsync.
    /// </summary>
    [TestMethod]
    public async ValueTask EddsaRdfc2022DataIntegrityProofSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        var didDocument = CreateDidDocument(Ed25519VerificationMethodId, Ed25519PublicKeyMultibase);

        var signedCredential = await credential.SignAsync(
            privateKeyMemory,
            Ed25519VerificationMethodId,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            ProofCreated,
            RdfcCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsNotNull(signedCredential.Proof);
        Assert.HasCount(1, signedCredential.Proof);

        var proof = signedCredential.Proof[0];
        Assert.AreEqual("DataIntegrityProof", proof.Type);
        Assert.AreEqual("eddsa-rdfc-2022", proof.Cryptosuite?.CryptosuiteName);
        Assert.StartsWith("z", proof.ProofValue, "Proof value must be base58btc encoded.");

        var verificationResult = await signedCredential.VerifyAsync(
            didDocument,
            RdfcCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(CredentialVerificationResult.Success(), verificationResult);
    }


    /// <summary>
    /// Tests ecdsa-sd-2023 Data Integrity proof with selective disclosure.
    /// Demonstrates the Issuer -> Holder -> Verifier flow using the library API.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This test demonstrates the realistic three-party flow where each party only has
    /// access to information they would receive in production:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Issuer: Has unsigned credential and keys, creates base proof.</description></item>
    /// <item><description>Holder: Receives signed credential, verifies, stores it, later creates derived proof.</description></item>
    /// <item><description>Verifier: Receives derived credential, verifies.</description></item>
    /// </list>
    /// </remarks>
    [TestMethod]
    public async ValueTask EcdsaSd2023BaseAndDerivedProofSucceeds()
    {
        var cancellationToken = TestContext.CancellationToken;
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        //Mandatory paths are always disclosed regardless of verifier request or user preference.
        var mandatoryPaths = new List<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/issuer"),
            CredentialPath.FromJsonPointer("/type")
        };

        var rdfcCanonicalizer = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();
        var contextResolver = CanonicalizationTestUtilities.CreateTestContextResolver();

        //Issuer creates base proof containing all claims with selective disclosure capability.
        const string SelectedVerificationMethodId = "did:example:issuer#key-1";
        var signedCredential = await credential.CreateBaseProofAsync(
            P256IssuerKeys.PrivateKey,
            P256EphemeralKeys,
            SelectedVerificationMethodId,
            ProofCreated,
            mandatoryPaths,
            () => RandomNumberGenerator.GetBytes(32),
            JsonLdSelection.PartitionStatements,            
            rdfcCanonicalizer,
            contextResolver,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken);

        Assert.IsNotNull(signedCredential.Proof);
        Assert.StartsWith(
            MultibaseAlgorithms.Base64Url.ToString(),
            signedCredential.Proof[0].ProofValue,
            "Base proof must use base64url-no-pad multibase encoding.");

        //Holder receives credential and verifies issuer signature.
        var holderVerifyResult = await signedCredential.VerifyBaseProofAsync(
            P256IssuerKeys.PublicKey,
            BouncyCastleCryptographicFunctions.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            rdfcCanonicalizer,
            contextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken);

        Assert.AreEqual(CredentialVerificationResult.Success(), holderVerifyResult);

        //Holder stores the credential (just the POCO, no internal state needed).
        //Later, when presenting to a verifier...

        //Verifier requests specific claims. Holder decides what to disclose.
        var verifierRequestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/degree/name")
        };

        //User could exclude certain paths, but in this test we don't exclude anything.
        IReadOnlySet<CredentialPath>? userExclusions = null;

        //Holder creates derived proof with selected claims.
        var derivedCredential = await signedCredential.DeriveProofAsync(
            verifierRequestedPaths,
            userExclusions,
            JsonLdSelection.PartitionStatements,
            JsonLdSelection.SelectFragments,
            rdfcCanonicalizer,
            contextResolver,
            SerializeCredential,
            DeserializeCredential,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            EcdsaSd2023CborSerializer.SerializeDerivedProof,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken);

        Assert.IsNotNull(derivedCredential.Proof);
        Assert.StartsWith(
            MultibaseAlgorithms.Base64Url.ToString(),
            derivedCredential.Proof[0].ProofValue!,
            "Derived proof must use base64url-no-pad multibase encoding.");

        //Verifier receives derived credential and verifies the selective disclosure proof.
        var verificationResult = await derivedCredential.VerifyDerivedProofAsync(
            P256IssuerKeys.PublicKey,
            BouncyCastleCryptographicFunctions.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            rdfcCanonicalizer,
            contextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken);

        Assert.AreEqual(CredentialVerificationResult.Success(), verificationResult);
    }



    /// <summary>
    /// Tests eddsa-jcs-2022 Data Integrity proof using SignAsync and VerifyAsync.
    /// </summary>
    [TestMethod]
    public async ValueTask EddsaJcs2022DataIntegrityProofSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        var didDocument = CreateDidDocument(Ed25519VerificationMethodId, Ed25519PublicKeyMultibase);

        var signedCredential = await credential.SignAsync(
            privateKeyMemory,
            Ed25519VerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            ProofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsNotNull(signedCredential.Proof);
        Assert.HasCount(1, signedCredential.Proof);

        var proof = signedCredential.Proof[0];
        Assert.AreEqual("DataIntegrityProof", proof.Type);
        Assert.AreEqual("eddsa-jcs-2022", proof.Cryptosuite?.CryptosuiteName);
        Assert.StartsWith("z", proof.ProofValue, "Proof value must be base58btc encoded.");

        var verificationResult = await signedCredential.VerifyAsync(
            didDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(CredentialVerificationResult.Success(), verificationResult);
    }


    /// <summary>
    /// Tests application/vc+jwt envelope (the "jose" tab).
    /// </summary>
    [TestMethod]
    public async ValueTask JoseJwtEnvelopeSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase, MulticodecHeaders.Ed25519PrivateKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKeyMemory, Ed25519VerificationMethodId, CredentialSerializer, HeaderSerializer,
            TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared, cancellationToken: TestContext.CancellationToken);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(jws);
        var parts = jws.Split('.');
        Assert.HasCount(3, parts);

        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase, MulticodecHeaders.Ed25519PublicKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var verificationResult = await JwsCredentialVerification.VerifyAsync(
            jws, publicKeyMemory, TestSetup.Base64UrlDecoder, HeaderDeserializer, CredentialDeserializer,
            cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(verificationResult.IsValid, "JWT signature verification must succeed.");
        Assert.AreEqual(credential.Id, verificationResult.Credential!.Id);
    }


    /// <summary>
    /// Tests application/vc+cose envelope (the "cose" tab).
    /// </summary>
    [TestMethod]
    public async ValueTask CoseEnvelopeSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase, MulticodecHeaders.Ed25519PrivateKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        var protectedHeader = new CborWriter(CborConformanceMode.Canonical);
        protectedHeader.WriteStartMap(2);
        protectedHeader.WriteInt32(CoseHeaderParameters.Alg);
        protectedHeader.WriteInt32(WellKnownCoseAlgorithms.EdDsa);
        protectedHeader.WriteInt32(CoseHeaderParameters.Kid);
        protectedHeader.WriteTextString(Ed25519VerificationMethodId);
        protectedHeader.WriteEndMap();
        var protectedHeaderBytes = protectedHeader.Encode();

        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(credential, JsonOptions);

        var sigStructure = new CborWriter(CborConformanceMode.Canonical);
        sigStructure.WriteStartArray(4);
        sigStructure.WriteTextString("Signature1");
        sigStructure.WriteByteString(protectedHeaderBytes);
        sigStructure.WriteByteString([]);
        sigStructure.WriteByteString(payloadBytes);
        sigStructure.WriteEndArray();
        var sigStructureBytes = sigStructure.Encode();

        using var signature = await privateKeyMemory.SignAsync(
            sigStructureBytes, BouncyCastleCryptographicFunctions.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);

        var coseSign1 = new CborWriter(CborConformanceMode.Canonical);
        coseSign1.WriteTag((CborTag)CoseTags.Sign1);
        coseSign1.WriteStartArray(4);
        coseSign1.WriteByteString(protectedHeaderBytes);
        coseSign1.WriteStartMap(0);
        coseSign1.WriteEndMap();
        coseSign1.WriteByteString(payloadBytes);
        coseSign1.WriteByteString(signature.AsReadOnlySpan());
        coseSign1.WriteEndArray();
        var coseSign1Bytes = coseSign1.Encode();

        Assert.IsNotNull(coseSign1Bytes);
        Assert.IsGreaterThan(100, coseSign1Bytes.Length, "COSE_Sign1 should have substantial length.");

        var reader = new CborReader(coseSign1Bytes, CborConformanceMode.Lax);
        var tag = reader.ReadTag();
        Assert.AreEqual((CborTag)CoseTags.Sign1, tag);

        reader.ReadStartArray();
        var readProtectedHeader = reader.ReadByteString();
        reader.ReadStartMap();
        reader.ReadEndMap();
        var readPayload = reader.ReadByteString();
        var readSignature = reader.ReadByteString();
        reader.ReadEndArray();

        Assert.IsTrue(protectedHeaderBytes.AsSpan().SequenceEqual(readProtectedHeader), "Protected header must round-trip.");
        Assert.IsTrue(payloadBytes.AsSpan().SequenceEqual(readPayload), "Payload must round-trip.");

        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase, MulticodecHeaders.Ed25519PublicKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var signatureMemory = SensitiveMemoryPool<byte>.Shared.Rent(readSignature.Length);
        readSignature.CopyTo(signatureMemory.Memory.Span);
        var signatureToVerify = new Signature(signatureMemory, CryptoTags.Ed25519Signature);
        bool isValid = await publicKeyMemory.VerifyAsync(sigStructureBytes, signatureToVerify, BouncyCastleCryptographicFunctions.VerifyEd25519Async);

        Assert.IsTrue(isValid, "COSE_Sign1 signature verification must succeed.");
    }


    /// <summary>
    /// Tests SD-JWT envelope with selective disclosure.
    /// </summary>
    [TestMethod]
    public async ValueTask SdJwtEnvelopeSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase, MulticodecHeaders.Ed25519PrivateKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        byte[] salt1 = SdSaltGenerator.Generate();
        byte[] salt2 = SdSaltGenerator.Generate();

        var disclosure1 = SdDisclosure.CreateProperty(salt1, "degree",
            new Dictionary<string, object> { ["type"] = "ExampleBachelorDegree", ["name"] = "Bachelor of Science and Arts" });
        var disclosure2 = SdDisclosure.CreateProperty(salt2, "name", "Example University");

        string encodedDisclosure1 = EncodeDisclosure(disclosure1, TestSetup.Base64UrlEncoder);
        string encodedDisclosure2 = EncodeDisclosure(disclosure2, TestSetup.Base64UrlEncoder);

        string digest1 = ComputeDisclosureDigest(encodedDisclosure1, TestSetup.Base64UrlEncoder);
        string digest2 = ComputeDisclosureDigest(encodedDisclosure2, TestSetup.Base64UrlEncoder);

        var sdPayload = new Dictionary<string, object>
        {
            ["@context"] = credential.Context!,
            ["id"] = credential.Id!,
            ["type"] = credential.Type!,
            ["issuer"] = new Dictionary<string, object> { ["id"] = credential.Issuer!.Id!, [SdConstants.SdClaimName] = new[] { digest2 } },
            ["validFrom"] = credential.ValidFrom!,
            ["credentialSubject"] = new Dictionary<string, object> { ["id"] = credential.CredentialSubject![0].Id!, [SdConstants.SdClaimName] = new[] { digest1 } },
            [SdConstants.SdAlgorithmClaimName] = SdConstants.DefaultHashAlgorithm
        };

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
            Encoding.ASCII.GetBytes(signingInput), BouncyCastleCryptographicFunctions.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);

        var issuerSignedJwt = $"{signingInput}.{TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan())}";
        var sdJwt = $"{issuerSignedJwt}{SdConstants.JwtSeparator}{encodedDisclosure1}{SdConstants.JwtSeparator}{encodedDisclosure2}{SdConstants.JwtSeparator}";

        Assert.IsNotNull(sdJwt);
        Assert.Contains("~", sdJwt);
        Assert.EndsWith("~", sdJwt, "SD-JWT without key binding must end with tilde.");

        var parts = sdJwt.Split(SdConstants.JwtSeparator);
        Assert.IsGreaterThan(3, parts.Length, "SD-JWT must have JWT plus disclosures.");

        var jwtParts = parts[0].Split('.');
        Assert.HasCount(3, jwtParts);

        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase, MulticodecHeaders.Ed25519PublicKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var verificationInput = Encoding.ASCII.GetBytes($"{jwtParts[0]}.{jwtParts[1]}");
        using var signatureBytesFromJwt = TestSetup.Base64UrlDecoder(jwtParts[2], SensitiveMemoryPool<byte>.Shared);
        var signatureToVerify = new Signature(signatureBytesFromJwt, CryptoTags.Ed25519Signature);
        bool isValid = await publicKeyMemory.VerifyAsync(verificationInput, signatureToVerify, BouncyCastleCryptographicFunctions.VerifyEd25519Async);

        Assert.IsTrue(isValid, "SD-JWT signature verification must succeed.");
    }


    /// <summary>
    /// Tests SD-CWT envelope with selective disclosure.
    /// </summary>
    [TestMethod]
    public async ValueTask SdCwtEnvelopeSucceeds()
    {
        var credential = JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase, MulticodecHeaders.Ed25519PrivateKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        var disclosure1 = SdDisclosure.CreateProperty(SdSaltGenerator.Generate(), "degree",
            new Dictionary<string, object?> { ["type"] = "ExampleBachelorDegree", ["name"] = "Bachelor of Science and Arts" });
        var disclosure2 = SdDisclosure.CreateProperty(SdSaltGenerator.Generate(), "name", "Example University");

        var protectedHeader = BuildSdCwtProtectedHeader();
        byte[] payload = BuildCwtPayload(credential);

        var sigStructure = new CborWriter(CborConformanceMode.Canonical);
        sigStructure.WriteStartArray(4);
        sigStructure.WriteTextString("Signature1");
        sigStructure.WriteByteString(protectedHeader);
        sigStructure.WriteByteString([]);
        sigStructure.WriteByteString(payload);
        sigStructure.WriteEndArray();
        var sigStructureBytes = sigStructure.Encode();

        using var signature = await privateKeyMemory.SignAsync(
            sigStructureBytes, BouncyCastleCryptographicFunctions.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);

        var sdCwtMessage = new SdCwtMessage(
            payload.AsMemory(), protectedHeader.AsMemory(), signature.AsReadOnlySpan().ToArray(), [disclosure1, disclosure2]);

        var sdCwtBytes = SdCwtSerializer.Serialize(sdCwtMessage);

        Assert.IsNotNull(sdCwtBytes);
        Assert.IsGreaterThan(100, sdCwtBytes.Length, "SD-CWT should have substantial length.");

        var parsedMessage = SdCwtSerializer.Parse(sdCwtBytes);

        Assert.IsTrue(payload.AsSpan().SequenceEqual(parsedMessage.Payload.Span), "Payload must round-trip.");
        Assert.HasCount(2, parsedMessage.Disclosures, "Disclosures must round-trip.");

        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase, MulticodecHeaders.Ed25519PublicKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var signatureMemory = SensitiveMemoryPool<byte>.Shared.Rent(parsedMessage.Signature.Length);
        parsedMessage.Signature.Span.CopyTo(signatureMemory.Memory.Span);
        var signatureToVerify = new Signature(signatureMemory, CryptoTags.Ed25519Signature);
        bool isValid = await publicKeyMemory.VerifyAsync(sigStructureBytes, signatureToVerify, BouncyCastleCryptographicFunctions.VerifyEd25519Async);

        Assert.IsTrue(isValid, "SD-CWT signature verification must succeed.");
    }


    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, cancellationToken) =>
        ValueTask.FromResult(Jcs.Canonicalize(json));

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } = (json, contextResolver, cancellationToken) =>
    {
        var store = new TripleStore();
        var parser = new JsonLdParser();
        using var reader = new StringReader(json);
        parser.Load(store, reader);
        var canonicalizer = new RdfCanonicalizer();
        return ValueTask.FromResult(canonicalizer.Canonicalize(store).SerializedNQuads);
    };

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializer.Serialize(credential, JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializer.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        (type, cryptosuiteName, created, verificationMethodId, proofPurpose, context) =>
            context != null
                ? JsonSerializer.Serialize(new { type, cryptosuite = cryptosuiteName, created, verificationMethod = verificationMethodId, proofPurpose, context }, JsonOptions)
                : JsonSerializer.Serialize(new { type, cryptosuite = cryptosuiteName, created, verificationMethod = verificationMethodId, proofPurpose }, JsonOptions);

    private static ReadOnlySpan<byte> CredentialSerializer(VerifiableCredential credential) =>
        JsonSerializer.SerializeToUtf8Bytes(credential, JsonOptions);

    private static ReadOnlySpan<byte> HeaderSerializer(Dictionary<string, object> header) =>
        JsonSerializer.SerializeToUtf8Bytes(header);

    private static Dictionary<string, object>? HeaderDeserializer(ReadOnlySpan<byte> headerBytes) =>
        JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes);

    private static VerifiableCredential CredentialDeserializer(ReadOnlySpan<byte> credentialBytes) =>
        JsonSerializer.Deserialize<VerifiableCredential>(credentialBytes, JsonOptions)!;

    private static DidDocument CreateDidDocument(string verificationMethodId, string publicKeyMultibase)
    {
        var did = verificationMethodId.Split('#')[0];
        return new DidDocument
        {
            Id = new GenericDidMethod(did),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = verificationMethodId,
                    Type = "Multikey",
                    Controller = did,
                    KeyFormat = new PublicKeyMultibase(publicKeyMultibase)
                }
            ],
            AssertionMethod = [new AssertionMethod(verificationMethodId)]
        };
    }

        
    private static string EncodeDisclosure(SdDisclosure disclosure, EncodeDelegate base64UrlEncoder)
    {
        string saltBase64Url = base64UrlEncoder(disclosure.Salt.Span);
        string json = disclosure.ClaimName is not null
            ? $"[\"{saltBase64Url}\",\"{disclosure.ClaimName}\",{JsonSerializer.Serialize(disclosure.ClaimValue)}]"
            : $"[\"{saltBase64Url}\",{JsonSerializer.Serialize(disclosure.ClaimValue)}]";
        return base64UrlEncoder(Encoding.UTF8.GetBytes(json));
    }

    private static string ComputeDisclosureDigest(string encodedDisclosure, EncodeDelegate base64UrlEncoder) =>
        base64UrlEncoder(SHA256.HashData(Encoding.ASCII.GetBytes(encodedDisclosure)));

    private static byte[] BuildCwtPayload(VerifiableCredential credential)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(WellKnownCwtClaims.Iss);
        writer.WriteTextString(credential.Issuer!.Id!);
        writer.WriteInt32(WellKnownCwtClaims.Sub);
        writer.WriteTextString(credential.CredentialSubject![0].Id!);
        writer.WriteInt32(WellKnownCwtClaims.Iat);
        writer.WriteInt64(!string.IsNullOrEmpty(credential.ValidFrom) ? DateTimeOffset.Parse(credential.ValidFrom, CultureInfo.InvariantCulture).ToUnixTimeSeconds() : 0L);
        writer.WriteEndMap();
        return writer.Encode();
    }

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
}
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VDS.RDF;
using VDS.RDF.Parsing;
using Verifiable.BouncyCastle;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Proofs;
using Verifiable.Cryptography;
using Verifiable.Jose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Credential;

/// <summary>
/// Tests for W3C Data Integrity proofs using the eddsa-rdfc-2022 cryptosuite.
/// Uses official W3C test vectors from Data Integrity EdDSA Cryptosuites v1.0, Appendix B.1.
/// </summary>
/// <remarks>
/// See <see href="https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-rdfc-2022">
/// W3C Data Integrity EdDSA Cryptosuites v1.0 §B.1</see>.
/// </remarks>
[TestClass]
public sealed class DataIntegrityTests
{
    /// <summary>
    /// JSON serialization options with all required converters for Verifiable Credentials.
    /// Uses the library's default configuration to ensure proper JSON-LD serialization.
    /// </summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>
    /// Ed25519 public key in Multikey format.
    /// Source: https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-rdfc-2022 Example 7.
    /// </summary>
    public const string PublicKeyMultibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    /// <summary>
    /// Ed25519 secret key in Multikey format.
    /// Source: https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-rdfc-2022 Example 7.
    /// </summary>
    public const string SecretKeyMultibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

    /// <summary>
    /// Verification method DID URL for the test key.
    /// </summary>
    public const string VerificationMethodId = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    /// <summary>
    /// Unsigned credential JSON from W3C test vectors (Example 8).
    /// </summary>    
    private const string UnsignedCredentialJson = /*lang=json,strict*/ """
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "name": "Alumni Credential",
            "description": "A minimum viable example of an Alumni Credential.",
            "issuer": "https://vc.example/issuers/5678",
            "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:abcdefgh",
                "alumniOf": "The School of Examples"
            }
        }
        """;

    /// <summary>
    /// Proof options JSON from W3C test vectors (Example 11).
    /// </summary>
    /*lang=json,strict*/
    private const string ProofOptionsJson = """
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "created": "2023-02-24T23:36:38Z",
            "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            "proofPurpose": "assertionMethod",
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ]
        }
        """;

    /// <summary>
    /// Deserialized unsigned credential using library converters.
    /// </summary>
    public static VerifiableCredential UnsignedCredential { get; } =
        JsonSerializer.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

    /// <summary>
    /// Deserialized proof options using library converters.
    /// </summary>
    public static DataIntegrityProof ProofOptions { get; } =
        JsonSerializer.Deserialize<DataIntegrityProof>(ProofOptionsJson, JsonOptions)!;

    /// <summary>
    /// Expected W3C test vector values.
    /// </summary>
    public const string ExpectedCanonicalCredential = "<did:example:abcdefgh> <https://www.w3.org/ns/credentials/examples#alumniOf> \"The School of Examples\" .\n<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#AlumniCredential> .\n<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://schema.org/description> \"A minimum viable example of an Alumni Credential.\" .\n<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://schema.org/name> \"Alumni Credential\" .\n<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:abcdefgh> .\n<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#issuer> <https://vc.example/issuers/5678> .\n<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#validFrom> \"2023-01-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n";
    public const string ExpectedCanonicalProofOptions = "_:c14n0 <http://purl.org/dc/terms/created> \"2023-02-24T23:36:38Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .\n_:c14n0 <https://w3id.org/security#cryptosuite> \"eddsa-rdfc-2022\"^^<https://w3id.org/security#cryptosuiteString> .\n_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .\n_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2> .\n";
    public const string ExpectedCredentialHashHex = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017";
    public const string ExpectedProofOptionsHashHex = "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0";
    public const string ExpectedCombinedHashesHex = "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017";
    public const string ExpectedSignatureHex = "4d8e53c2d5b3f2a7891753eb16ca993325bdb0d3cfc5be1093d0a18426f5ef8578cadc0fd4b5f4dd0d1ce0aefd15ab120b7a894d0eb094ffda4e6553cd1ed50d";
    public const string ExpectedProofValue = "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme";

    /// <summary>
    /// Canonicalizes a JSON-LD document using RDFC-1.0 via dotNetRdf.
    /// </summary>
    private static string Canonicalize(string jsonLdDocument)
    {
        var store = new TripleStore();
        var parser = new JsonLdParser();
        using var reader = new System.IO.StringReader(jsonLdDocument);
        parser.Load(store, reader);

        var canonicalizer = new RdfCanonicalizer();
        var canonicalizedResult = canonicalizer.Canonicalize(store);

        return canonicalizedResult.SerializedNQuads;
    }


    /// <summary>
    /// Tests the complete Data Integrity proof creation workflow, verifying all intermediate
    /// values against W3C test vectors including canonicalization, hashing, and signing.
    /// </summary>
    [TestMethod]
    public async ValueTask CreateDataIntegrityProofMatchesTestVector()
    {
        //Verify deserialization worked.
        Assert.IsNotNull(UnsignedCredential);
        Assert.AreEqual("urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33", UnsignedCredential.Id);
        Assert.IsNotNull(UnsignedCredential.Type);
        Assert.Contains("VerifiableCredential", UnsignedCredential.Type);
        Assert.Contains("AlumniCredential", UnsignedCredential.Type);

        //Serialize credential back to JSON for canonicalization (round-trip test).
        var credentialJson = JsonSerializer.Serialize(UnsignedCredential, JsonOptions);

        //Canonicalize credential via dotNetRdf and verify against test vector.
        var canonicalCredential = Canonicalize(credentialJson);
        Assert.AreEqual(ExpectedCanonicalCredential, canonicalCredential, "Canonical credential must match W3C test vector.");

        //Canonicalize proof options and verify against test vector.
        var canonicalProofOptions = Canonicalize(ProofOptionsJson);
        Assert.AreEqual(ExpectedCanonicalProofOptions, canonicalProofOptions, "Canonical proof options must match W3C test vector.");

        //Hash credential and verify.
        var credentialHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalCredential));
        Assert.AreEqual(ExpectedCredentialHashHex, Convert.ToHexStringLower(credentialHash), "Credential hash must match W3C test vector.");

        //Hash proof options and verify.
        var proofOptionsHash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalProofOptions));
        Assert.AreEqual(ExpectedProofOptionsHashHex, Convert.ToHexStringLower(proofOptionsHash), "Proof options hash must match W3C test vector.");

        //Combine hashes and verify.
        var hashData = proofOptionsHash.Concat(credentialHash).ToArray();
        Assert.AreEqual(ExpectedCombinedHashesHex, Convert.ToHexStringLower(hashData), "Combined hash must match W3C test vector.");

        //Sign and verify signature.
        var privateKeyBytes = MultibaseSerializer.Decode(SecretKeyMultibase, MulticodecHeaders.Ed25519PrivateKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, Tag.Ed25519PrivateKey);

        var signature = await privateKeyMemory.SignAsync(hashData, BouncyCastleAlgorithms.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);
        Assert.AreEqual(ExpectedSignatureHex, Convert.ToHexStringLower(signature.AsReadOnlySpan()), "Signature must match W3C test vector.");

        //Encode proofValue and verify.
        var proofValue = $"{MultibaseAlgorithms.Base58Btc}{TestSetup.Base58Encoder(signature.AsReadOnlySpan())}";
        Assert.AreEqual(ExpectedProofValue, proofValue, "ProofValue must match W3C test vector.");

        //Build the signed credential with proof by deserializing a fresh copy.
        var signedCredential = JsonSerializer.Deserialize<VerifiableCredential>(credentialJson, JsonOptions)!;
        signedCredential.Proof =
        [
            new DataIntegrityProof
            {
                Type = "DataIntegrityProof",
                Cryptosuite = CryptosuiteInfoExtensions.FromName("eddsa-rdfc-2022"),
                Created = "2023-02-24T23:36:38Z",
                VerificationMethod = new AssertionMethod(VerificationMethodId),
                ProofPurpose = "assertionMethod",
                ProofValue = proofValue
            }
        ];

        Assert.IsNotNull(signedCredential.Proof);
        Assert.HasCount(1, signedCredential.Proof);
        Assert.AreEqual(ExpectedProofValue, signedCredential.Proof[0].ProofValue);

        //Verify the signature can be validated.
        var publicKeyBytes = MultibaseSerializer.Decode(PublicKeyMultibase, MulticodecHeaders.Ed25519PublicKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, Tag.Ed25519PublicKey);

        var signatureBytes = MultibaseSerializer.Decode(proofValue, 0, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        var signatureToVerify = new Signature(signatureBytes, Tag.Ed25519Signature);

        bool isVerified = await publicKeyMemory.VerifyAsync(hashData, signatureToVerify, BouncyCastleAlgorithms.VerifyEd25519Async);
        Assert.IsTrue(isVerified, "Signature verification must succeed.");

        //Verify tamper detection.
        var tamperedCredentialJson = credentialJson.Replace("The School of Examples", "Tampered School", StringComparison.Ordinal);
        var tamperedCanonical = Canonicalize(tamperedCredentialJson);
        var tamperedHash = SHA256.HashData(Encoding.UTF8.GetBytes(tamperedCanonical));
        var tamperedHashData = proofOptionsHash.Concat(tamperedHash).ToArray();

        bool isTamperedVerified = await publicKeyMemory.VerifyAsync(tamperedHashData, signatureToVerify, BouncyCastleAlgorithms.VerifyEd25519Async);
        Assert.IsFalse(isTamperedVerified, "Tampered credential verification must fail.");
    }


    /// <summary>
    /// Tests JWT signing of the W3C test vector credential using EdDSA.
    /// </summary>
    [TestMethod]
    public async ValueTask SignCredentialAsJwtSucceeds()
    {
        Assert.IsNotNull(UnsignedCredential);

        var privateKeyBytes = MultibaseSerializer.Decode(SecretKeyMultibase, MulticodecHeaders.Ed25519PrivateKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        var publicKeyBytes = MultibaseSerializer.Decode(PublicKeyMultibase, MulticodecHeaders.Ed25519PublicKey.Length, TestSetup.Base58Decoder, SensitiveMemoryPool<byte>.Shared);
        PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, Tag.Ed25519PrivateKey);
        PublicKeyMemory publicKeyMemory = new(publicKeyBytes, Tag.Ed25519PublicKey);

        //Serialize credential to JSON for JWT payload.
        var credentialJson = JsonSerializer.Serialize(UnsignedCredential, JsonOptions);

        //Build and sign JWT.
        var header = new { alg = WellKnownJwaValues.EdDsa, typ = WellKnownMediaTypes.Jwt.VcLdJwt, kid = VerificationMethodId };
        var headerJson = JsonSerializer.Serialize(header);
        var headerBase64Url = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(headerJson));
        var payloadBase64Url = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(credentialJson));

        var signingInput = $"{headerBase64Url}.{payloadBase64Url}";
        var signature = await privateKeyMemory.SignAsync(Encoding.UTF8.GetBytes(signingInput), BouncyCastleAlgorithms.SignEd25519Async, SensitiveMemoryPool<byte>.Shared);
        var jwt = $"{signingInput}.{TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan())}";

        //Verify JWT structure and signature.
        var parts = jwt.Split('.');
        Assert.HasCount(3, parts);

        var verificationInput = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");
        using var signatureBytesFromJwt = TestSetup.Base64UrlDecoder(parts[2], SensitiveMemoryPool<byte>.Shared);
        var signatureToVerify = new Signature(signatureBytesFromJwt, Tag.Ed25519Signature);

        bool isValid = await publicKeyMemory.VerifyAsync(verificationInput, signatureToVerify, BouncyCastleAlgorithms.VerifyEd25519Async);
        Assert.IsTrue(isValid, "JWT signature verification must succeed.");

        //Verify payload round-trips through VerifiableCredential model.
        using var decodedPayloadBytes = TestSetup.Base64UrlDecoder(parts[1], SensitiveMemoryPool<byte>.Shared);
        var decodedPayload = Encoding.UTF8.GetString(decodedPayloadBytes.Memory.Span);
        var decodedCredential = JsonSerializer.Deserialize<VerifiableCredential>(decodedPayload, JsonOptions);
        Assert.IsNotNull(decodedCredential);
        Assert.AreEqual(UnsignedCredential.Id, decodedCredential.Id);
    }
}
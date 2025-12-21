using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using System.Text.Json.Nodes;
using VDS.RDF;
using VDS.RDF.JsonLd;
using VDS.RDF.JsonLd.Syntax;
using VDS.RDF.Parsing;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Proofs;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.Resolver;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.FlowTests;

/// <summary>
/// End-to-end flow tests for Verifiable Credential issuance and verification.
/// These tests demonstrate the complete trust triangle: Issuer, Holder, Verifier.
/// </summary>
/// <remarks>
/// <para>
/// The credential issuance and verification flow involves three parties:
/// </para>
/// <list type="number">
/// <item><description>Issuer: Creates and signs credentials using their DID's assertionMethod key.</description></item>
/// <item><description>Holder: Receives credentials about themselves (identified by their DID as subject).</description></item>
/// <item><description>Verifier: Validates credential authenticity by resolving issuer's DID and verifying signature.</description></item>
/// </list>
/// <para>
/// Two cryptosuites are tested:
/// </para>
/// <list type="bullet">
/// <item><description>eddsa-rdfc-2022: Uses JSON-LD canonicalization (RDFC-1.0). Only claims defined in @context are signed.</description></item>
/// <item><description>eddsa-jcs-2022: Uses JSON Canonicalization Scheme. ALL JSON properties are signed regardless of context.</description></item>
/// </list>
/// <para>
/// <strong>Time Handling</strong>
/// </para>
/// <para>
/// All timestamps are provided explicitly by the caller using <see cref="FakeTimeProvider"/>. The library
/// only verifies cryptographic correctness; temporal policy decisions (e.g., "is this credential expired")
/// are the caller's responsibility. See individual test methods for examples of how to compare credential
/// validity periods against the caller's time source.
/// </para>
/// </remarks>
[TestClass]
public sealed class CredentialIssuanceFlowTests
{
    /// <summary>
    /// Test context providing test run information and cancellation support.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    //Test DID identifiers.
    private const string IssuerDomain = "university.example";
    private const string IssuerDidWeb = "did:web:university.example";
    private const string HolderDidExample = "did:example:holder";

    //Credential constants.
    private const string AlumniCredentialType = "AlumniCredential";

    //Claim keys and values.
    private const string ClaimAlumniOf = "alumniOf";
    private const string ClaimValueUniversityName = "Example University";
    private const string ClaimValueFakeUniversity = "Fake University";

    //JSON-LD context URLs.
    private const string CredentialsV2ContextUrl = "https://www.w3.org/ns/credentials/v2";
    private const string CredentialsExamplesV2ContextUrl = "https://www.w3.org/ns/credentials/examples/v2";

    //Cryptosuite constants.
    private const string DataIntegrityProofType = "DataIntegrityProof";

    /// <summary>
    /// W3C Verifiable Credentials Data Model 2.0 context.
    /// Source: https://www.w3.org/ns/credentials/v2
    /// </summary>
    private const string CredentialsV2ContextJson =
        /*lang=json,strict*/
        """
        {
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "description": "https://schema.org/description",
            "digestMultibase": {
              "@id": "https://w3id.org/security#digestMultibase",
              "@type": "https://w3id.org/security#multibase"
            },
            "digestSRI": {
              "@id": "https://www.w3.org/2018/credentials#digestSRI",
              "@type": "https://www.w3.org/2018/credentials#sriString"
            },
            "mediaType": {
              "@id": "https://schema.org/encodingFormat"
            },
            "name": "https://schema.org/name",
            "VerifiableCredential": {
              "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
              "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "confidenceMethod": {
                  "@id": "https://www.w3.org/2018/credentials#confidenceMethod",
                  "@type": "@id"
                },
                "credentialSchema": {
                  "@id": "https://www.w3.org/2018/credentials#credentialSchema",
                  "@type": "@id"
                },
                "credentialStatus": {
                  "@id": "https://www.w3.org/2018/credentials#credentialStatus",
                  "@type": "@id"
                },
                "credentialSubject": {
                  "@id": "https://www.w3.org/2018/credentials#credentialSubject",
                  "@type": "@id"
                },
                "description": "https://schema.org/description",
                "evidence": {
                  "@id": "https://www.w3.org/2018/credentials#evidence",
                  "@type": "@id"
                },
                "issuer": {
                  "@id": "https://www.w3.org/2018/credentials#issuer",
                  "@type": "@id"
                },
                "name": "https://schema.org/name",
                "proof": {
                  "@id": "https://w3id.org/security#proof",
                  "@type": "@id",
                  "@container": "@graph"
                },
                "refreshService": {
                  "@id": "https://www.w3.org/2018/credentials#refreshService",
                  "@type": "@id"
                },
                "relatedResource": {
                  "@id": "https://www.w3.org/2018/credentials#relatedResource",
                  "@type": "@id"
                },
                "renderMethod": {
                  "@id": "https://www.w3.org/2018/credentials#renderMethod",
                  "@type": "@id"
                },
                "termsOfUse": {
                  "@id": "https://www.w3.org/2018/credentials#termsOfUse",
                  "@type": "@id"
                },
                "validFrom": {
                  "@id": "https://www.w3.org/2018/credentials#validFrom",
                  "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                },
                "validUntil": {
                  "@id": "https://www.w3.org/2018/credentials#validUntil",
                  "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                }
              }
            },
            "DataIntegrityProof": {
              "@id": "https://w3id.org/security#DataIntegrityProof",
              "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "challenge": "https://w3id.org/security#challenge",
                "created": {
                  "@id": "http://purl.org/dc/terms/created",
                  "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                },
                "domain": "https://w3id.org/security#domain",
                "expires": {
                  "@id": "https://w3id.org/security#expiration",
                  "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                },
                "nonce": "https://w3id.org/security#nonce",
                "previousProof": {
                  "@id": "https://w3id.org/security#previousProof",
                  "@type": "@id"
                },
                "proofPurpose": {
                  "@id": "https://w3id.org/security#proofPurpose",
                  "@type": "@vocab",
                  "@context": {
                    "@protected": true,
                    "id": "@id",
                    "type": "@type",
                    "assertionMethod": {
                      "@id": "https://w3id.org/security#assertionMethod",
                      "@type": "@id",
                      "@container": "@set"
                    }
                  }
                },
                "cryptosuite": {
                  "@id": "https://w3id.org/security#cryptosuite",
                  "@type": "https://w3id.org/security#cryptosuiteString"
                },
                "proofValue": {
                  "@id": "https://w3id.org/security#proofValue",
                  "@type": "https://w3id.org/security#multibase"
                },
                "verificationMethod": {
                  "@id": "https://w3id.org/security#verificationMethod",
                  "@type": "@id"
                }
              }
            }
          }
        }
        """;

    /// <summary>
    /// W3C Verifiable Credentials Examples context.
    /// Source: https://www.w3.org/ns/credentials/examples/v2
    /// </summary>
    private const string CredentialsExamplesV2ContextJson =
        /*lang=json,strict*/
        """
        {
          "@context": {
            "@vocab": "https://www.w3.org/ns/credentials/examples#"
          }
        }
        """;


    /// <summary>
    /// JSON serialization options with all required converters for Verifiable Credentials.
    /// </summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>
    /// Shared credential builder instance.
    /// </summary>
    private static CredentialBuilder CredentialBuilder { get; } = new CredentialBuilder();

    /// <summary>
    /// Shared key DID builder instance.
    /// </summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new KeyDidBuilder();

    /// <summary>
    /// Shared web DID builder instance.
    /// </summary>
    private static WebDidBuilder WebDidBuilder { get; } = new WebDidBuilder();

    /// <summary>
    /// Fake time provider for deterministic testing.
    /// </summary>
    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));


    /// <summary>
    /// Context resolver delegate for JSON-LD processing.
    /// Resolves W3C context URIs to embedded JSON strings.
    /// </summary>
    private static ContextResolverDelegate ContextResolver { get; } = (uri, cancellationToken) =>
    {
        var contextJson = uri.ToString() switch
        {
            CredentialsV2ContextUrl => CredentialsV2ContextJson,
            CredentialsExamplesV2ContextUrl => CredentialsExamplesV2ContextJson,
            _ => null
        };
        return ValueTask.FromResult(contextJson);
    };


    /// <summary>
    /// JCS canonicalization delegate. Ignores context resolver since JCS does not use JSON-LD.
    /// </summary>
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, cancellationToken) =>
    {
        var canonical = Jcs.Canonicalize(json);
        return ValueTask.FromResult(canonical);
    };


    /// <summary>
    /// RDFC-1.0 canonicalization delegate using dotNetRdf.
    /// </summary>
    private static CanonicalizationDelegate RdfcCanonicalizer { get; } = (json, contextResolver, cancellationToken) =>
    {
        var store = new TripleStore();
        var parserOptions = new JsonLdProcessorOptions
        {
            ProcessingMode = JsonLdProcessingMode.JsonLd11,
            DocumentLoader = CreateDotNetRdfContextLoader(contextResolver)
        };
        var parser = new JsonLdParser(parserOptions);

        using var reader = new StringReader(json);
        parser.Load(store, reader);

        var canonicalizer = new RdfCanonicalizer();
        var canonicalizedResult = canonicalizer.Canonicalize(store);

        return ValueTask.FromResult(canonicalizedResult.SerializedNQuads);
    };


    /// <summary>
    /// Proof value encoder delegate using multibase Base58Btc encoding.
    /// </summary>
    private static ProofValueEncoderDelegate ProofValueEncoder { get; } = (signatureBytes) =>
    {
        return $"{MultibaseAlgorithms.Base58Btc}{TestSetup.Base58Encoder(signatureBytes)}";
    };


    /// <summary>
    /// Proof value decoder delegate using multibase Base58Btc decoding.
    /// </summary>
    private static ProofValueDecoderDelegate ProofValueDecoder { get; } = (proofValue, memoryPool) =>
    {
        return MultibaseSerializer.Decode(proofValue, 0, TestSetup.Base58Decoder, memoryPool);
    };


    /// <summary>
    /// Credential serialization delegate using System.Text.Json.
    /// </summary>
    private static CredentialSerializeDelegate SerializeCredential { get; } = (credential) =>
    {
        return JsonSerializer.Serialize(credential, JsonOptions);
    };


    /// <summary>
    /// Credential deserialization delegate using System.Text.Json.
    /// </summary>
    private static CredentialDeserializeDelegate DeserializeCredential { get; } = (serialized) =>
    {
        return JsonSerializer.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;
    };


    /// <summary>
    /// Proof options serialization delegate using System.Text.Json.
    /// </summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        (type, cryptosuiteName, created, verificationMethodId, proofPurpose, context) =>
        {
            if(context != null)
            {
                return JsonSerializer.Serialize(new
                {
                    type,
                    cryptosuite = cryptosuiteName,
                    created,
                    verificationMethod = verificationMethodId,
                    proofPurpose,
                    context
                }, JsonOptions);
            }
            else
            {
                return JsonSerializer.Serialize(new
                {
                    type,
                    cryptosuite = cryptosuiteName,
                    created,
                    verificationMethod = verificationMethodId,
                    proofPurpose
                }, JsonOptions);
            }
        };


    /// <summary>
    /// Creates a dotNetRdf document loader that delegates to our context resolver.
    /// </summary>
    private static Func<Uri, JsonLdLoaderOptions?, RemoteDocument> CreateDotNetRdfContextLoader(
        ContextResolverDelegate? contextResolver)
    {
        return (uri, options) =>
        {
            string? contextJson = null;

            if(contextResolver != null)
            {
                //Synchronously wait since dotNetRdf's loader is synchronous.
                contextJson = contextResolver(uri, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            }

            if(contextJson == null)
            {
                throw new JsonLdProcessorException(
                    JsonLdErrorCode.LoadingDocumentFailed,
                    $"Unknown context URI: {uri}");
            }

            return new RemoteDocument
            {
                DocumentUrl = uri,
                Document = contextJson
            };
        };
    }


    /// <summary>
    /// Verifies that JSON-LD canonicalization includes claims only when context defines them.
    /// Without the examples context, alumniOf is dropped during expansion.
    /// With the examples context, alumniOf is included in the canonical form.
    /// </summary>
    [TestMethod]
    public async Task CanonicalFormIncludesClaimsOnlyWhenContextDefinesThem()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = TimeProvider.GetUtcNow().UtcDateTime;
        var credential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            cancellationToken: TestContext.CancellationToken);
        var credentialJson = JsonSerializer.Serialize(credential, JsonOptions);

        //Canonicalize without examples context. The alumniOf claim should be dropped.
        var canonicalFormWithoutContext = await RdfcCanonicalizer(credentialJson, ContextResolver, cancellationToken: TestContext.CancellationToken);
        var alumniOfInCanonicalWithoutContext = canonicalFormWithoutContext.Contains(ClaimValueUniversityName, StringComparison.Ordinal);

        //Add examples context and canonicalize again. The alumniOf claim should now be included.
        var credentialWithContext = AddContextToCredential(credentialJson, CredentialsExamplesV2ContextUrl);
        var canonicalFormWithContext = await RdfcCanonicalizer(credentialWithContext, ContextResolver, cancellationToken: TestContext.CancellationToken);
        var alumniOfInCanonicalWithContext = canonicalFormWithContext.Contains(ClaimValueUniversityName, StringComparison.Ordinal);

        Assert.IsFalse(alumniOfInCanonicalWithoutContext, "Claim should NOT be in canonical form without examples context.");
        Assert.IsTrue(alumniOfInCanonicalWithContext, "Claim should be in canonical form with examples context.");
    }


    /// <summary>
    /// Tests the complete credential issuance and verification flow using RDFC canonicalization.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task IssueAndVerifyCredentialWithRdfcSucceeds(DidWebTestData testData)
    {
        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken);

        var holderDid = holderDidDocument.Id!.ToString();

        var issuer = new Issuer { Id = IssuerDidWeb, Name = ClaimValueUniversityName };
        var subject = new CredentialSubjectInput
        {
            Id = holderDid,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = TimeProvider.GetUtcNow().UtcDateTime;
        var validUntil = validFrom.AddYears(10);
        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            validUntil: validUntil,
            cancellationToken: TestContext.CancellationToken);

        //Add examples context so alumniOf is protected by signature.
        var credentialJson = JsonSerializer.Serialize(unsignedCredential, JsonOptions);
        var credentialWithContext = AddContextToCredential(credentialJson, CredentialsExamplesV2ContextUrl);
        var credentialWithContextObj = JsonSerializer.Deserialize<VerifiableCredential>(credentialWithContext, JsonOptions)!;

        var signedCredential = await credentialWithContextObj.SignAsync(
            testData.KeyPair.PrivateKey,
            issuerVerificationMethodId,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            proofCreated,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        var verificationResult = await signedCredential.VerifyAsync(
            issuerDidDocument,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueDecoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(CredentialVerificationResult.Success(), verificationResult);
        Assert.AreEqual(holderDid, signedCredential.CredentialSubject![0].Id);
        Assert.AreEqual(IssuerDidWeb, signedCredential.Issuer!.Id);
    }


    /// <summary>
    /// Tests the complete credential issuance and verification flow using JCS canonicalization.
    /// JCS signs ALL JSON properties regardless of context.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task IssueAndVerifyCredentialWithJcsSucceeds(DidWebTestData testData)
    {
        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken);

        var holderDid = holderDidDocument.Id!.ToString();

        var issuer = new Issuer { Id = IssuerDidWeb, Name = ClaimValueUniversityName };
        var subject = new CredentialSubjectInput
        {
            Id = holderDid,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = TimeProvider.GetUtcNow().UtcDateTime;
        var validUntil = validFrom.AddYears(10);
        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            validUntil: validUntil,
            cancellationToken: TestContext.CancellationToken);

        //No need for examples context with JCS since all properties are signed.
        var signedCredential = await unsignedCredential.SignAsync(
            testData.KeyPair.PrivateKey,
            issuerVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        var verificationResult = await signedCredential.VerifyAsync(
            issuerDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(CredentialVerificationResult.Success(), verificationResult);
        Assert.AreEqual(holderDid, signedCredential.CredentialSubject![0].Id);
        Assert.AreEqual(IssuerDidWeb, signedCredential.Issuer!.Id);
    }


    /// <summary>
    /// Tests that tampered credentials fail verification with RDFC.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task TamperedCredentialFailsVerificationWithRdfc(DidWebTestData testData)
    {
        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = TimeProvider.GetUtcNow().UtcDateTime;
        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            cancellationToken: TestContext.CancellationToken);

        var credentialJson = JsonSerializer.Serialize(unsignedCredential, JsonOptions);
        var credentialWithContext = AddContextToCredential(credentialJson, CredentialsExamplesV2ContextUrl);
        var credentialWithContextObj = JsonSerializer.Deserialize<VerifiableCredential>(credentialWithContext, JsonOptions)!;

        var signedCredential = await credentialWithContextObj.SignAsync(
            testData.KeyPair.PrivateKey,
            issuerVerificationMethodId,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            proofCreated,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        //Tamper by modifying the JSON string directly.
        var signedCredentialJson = JsonSerializer.Serialize(signedCredential, JsonOptions);
        var tamperedJson = signedCredentialJson.Replace(ClaimValueUniversityName, ClaimValueFakeUniversity, StringComparison.Ordinal);
        var tamperedCredential = JsonSerializer.Deserialize<VerifiableCredential>(tamperedJson, JsonOptions)!;

        var verificationResult = await tamperedCredential.VerifyAsync(
            issuerDidDocument,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueDecoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), verificationResult);
    }


    /// <summary>
    /// Tests that tampered credentials fail verification with JCS.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task TamperedCredentialFailsVerificationWithJcs(DidWebTestData testData)
    {
        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            testData.KeyPair.PublicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = HolderDidExample,
            Claims = new Dictionary<string, object> { [ClaimAlumniOf] = ClaimValueUniversityName }
        };

        var validFrom = TimeProvider.GetUtcNow().UtcDateTime;
        var proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        var unsignedCredential = await CredentialBuilder.BuildAsync(
            issuer,
            subject,
            validFrom,
            additionalTypes: [AlumniCredentialType],
            cancellationToken: TestContext.CancellationToken);

        var signedCredential = await unsignedCredential.SignAsync(
            testData.KeyPair.PrivateKey,
            issuerVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        //Tamper by modifying the JSON string directly.
        var signedCredentialJson = JsonSerializer.Serialize(signedCredential, JsonOptions);
        var tamperedJson = signedCredentialJson.Replace(ClaimValueUniversityName, ClaimValueFakeUniversity, StringComparison.Ordinal);
        var tamperedCredential = JsonSerializer.Deserialize<VerifiableCredential>(tamperedJson, JsonOptions)!;

        var verificationResult = await tamperedCredential.VerifyAsync(
            issuerDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken);

        Assert.AreEqual(CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), verificationResult);
    }


    /// <summary>
    /// Tests DID resolution as part of the verification flow.
    /// </summary>
    [TestMethod]
    public void DidWebResolutionProducesCorrectUrl()
    {
        var simpleDidWeb = "did:web:university.example";
        var resolvedUrl = WebDidResolver.Resolve(simpleDidWeb);
        Assert.AreEqual("https://university.example/.well-known/did.json", resolvedUrl);

        var didWebWithPath = "did:web:university.example:departments:cs";
        var resolvedUrlWithPath = WebDidResolver.Resolve(didWebWithPath);
        Assert.AreEqual("https://university.example/departments/cs/did.json", resolvedUrlWithPath);

        var didWebWithPort = "did:web:localhost%3A8080:issuers:test";
        var resolvedUrlWithPort = WebDidResolver.Resolve(didWebWithPort);
        Assert.AreEqual("https://localhost:8080/issuers/test/did.json", resolvedUrlWithPort);
    }


    /// <summary>
    /// Adds an additional context to a credential JSON string.
    /// </summary>
    private static string AddContextToCredential(string credentialJson, string contextToAdd)
    {
        var jsonNode = JsonNode.Parse(credentialJson)!;
        var contextNode = jsonNode["@context"];

        if(contextNode is JsonArray contextArray)
        {
            contextArray.Add(contextToAdd);
        }
        else if(contextNode is JsonValue contextValue)
        {
            jsonNode["@context"] = new JsonArray(JsonValue.Create(contextValue.GetValue<string>()), JsonValue.Create(contextToAdd));
        }

        return jsonNode.ToJsonString(JsonOptions);
    }
}
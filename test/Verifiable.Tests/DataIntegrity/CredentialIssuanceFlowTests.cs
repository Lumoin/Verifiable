using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.Resolver;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using VDS.RDF.JsonLd;

namespace Verifiable.Tests.DataIntegrity;

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
/// <para>
/// <strong>Context Resolution</strong>
/// </para>
/// <para>
/// These tests use <see cref="CanonicalizationTestUtilities.CreateTestContextResolver"/> which provides
/// embedded context documents for deterministic, offline testing. See 
/// <see cref="CanonicalizationTestUtilities.CreateProductionContextResolver"/> for production patterns
/// that verify context integrity using SHA-256 hashes per the W3C Data Integrity specification.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CredentialIssuanceFlowTests
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
    /// Context resolver for tests using embedded W3C contexts.
    /// </summary>
    /// <remarks>
    /// Uses embedded contexts for deterministic testing. See <see cref="CanonicalizationTestUtilities"/>
    /// for production context resolution with integrity verification.
    /// </remarks>
    private static ContextResolverDelegate ContextResolver { get; } =
        CanonicalizationTestUtilities.CreateTestContextResolver();

    /// <summary>
    /// RDFC-1.0 canonicalizer using dotNetRdf.
    /// </summary>
    /// <remarks>
    /// Implements RDF Dataset Canonicalization per W3C specification.
    /// See <see cref="CanonicalizationTestUtilities.CreateRdfcCanonicalizer"/> for details.
    /// </remarks>
    private static CanonicalizationDelegate RdfcCanonicalizer { get; } =
        CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    /// <summary>
    /// JCS canonicalization delegate. Ignores context resolver since JCS does not use JSON-LD.
    /// </summary>
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, cancellationToken) =>
    {
        var canonical = Jcs.Canonicalize(json);
        return ValueTask.FromResult(canonical);
    };

    /// <summary>
    /// Proof value encoder delegate using multibase Base58Btc encoding.
    /// </summary>
    private static ProofValueEncoderDelegate ProofValueEncoder { get; } = ProofValueCodecs.EncodeBase58Btc;

    /// <summary>
    /// Proof value decoder delegate using multibase Base58Btc decoding.
    /// </summary>
    private static ProofValueDecoderDelegate ProofValueDecoder { get; } = ProofValueCodecs.DecodeBase58Btc;

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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var credentialJson = JsonSerializer.Serialize(credential, JsonOptions);

        //Canonicalize without examples context. The alumniOf claim should be dropped.
        var canonicalFormWithoutContext = await RdfcCanonicalizer(credentialJson, ContextResolver, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var alumniOfInCanonicalWithoutContext = canonicalFormWithoutContext.Contains(ClaimValueUniversityName, StringComparison.Ordinal);

        //Add examples context and canonicalize again. The alumniOf claim should now be included.
        var credentialWithContext = AddContextToCredential(credentialJson, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl);
        var canonicalFormWithContext = await RdfcCanonicalizer(credentialWithContext, ContextResolver, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
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
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Add examples context so alumniOf is protected by signature.
        var credentialJson = JsonSerializer.Serialize(unsignedCredential, JsonOptions);
        var credentialWithContext = AddContextToCredential(credentialJson, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl);
        var credentialWithContextObj = JsonSerializer.Deserialize<VerifiableCredential>(credentialWithContext, JsonOptions)!;

        var signedCredential = await credentialWithContextObj.SignAsync(
            privateKey,
            issuerVerificationMethodId,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            proofCreated,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var verificationResult = await signedCredential.VerifyAsync(
            issuerDidDocument,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueDecoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var issuerVerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;

        var holderDidDocument = await KeyDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //No need for examples context with JCS since all properties are signed.
        var signedCredential = await unsignedCredential.SignAsync(
            privateKey,
            issuerVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var verificationResult = await signedCredential.VerifyAsync(
            issuerDidDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueDecoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var credentialJson = JsonSerializer.Serialize(unsignedCredential, JsonOptions);
        var credentialWithContext = AddContextToCredential(credentialJson, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl);
        var credentialWithContextObj = JsonSerializer.Deserialize<VerifiableCredential>(credentialWithContext, JsonOptions)!;

        var signedCredential = await credentialWithContextObj.SignAsync(
            privateKey,
            issuerVerificationMethodId,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            proofCreated,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CredentialVerificationResult.Failed(VerificationFailureReason.SignatureInvalid), verificationResult);
    }


    /// <summary>
    /// Tests that tampered credentials fail verification with JCS.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(DidWebTheoryData.GetDidTheoryTestData), typeof(DidWebTheoryData))]
    public async Task TamperedCredentialFailsVerificationWithJcs(DidWebTestData testData)
    {
        var keyPair = testData.KeyPairFactory();
        using var publicKey = keyPair.PublicKey;
        using var privateKey = keyPair.PrivateKey;

        var issuerDidDocument = await WebDidBuilder.BuildAsync(
            publicKey,
            testData.VerificationMethodTypeInfo,
            IssuerDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var signedCredential = await unsignedCredential.SignAsync(
            privateKey,
            issuerVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            TestSetup.Base58Decoder,
            SensitiveMemoryPool<byte>.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
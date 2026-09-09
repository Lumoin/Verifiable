using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Veritas.Cbor;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Tests all W3C VC Data Model 2.0 securing methods using the same unsigned credential.
/// </summary>
[SuppressMessage(
    "Reliability", "CA2000",
    Justification =
        "Tests construct Salt instances and pass them to SdDisclosure factory methods " +
        "which take ownership; the disclosures are explicitly disposed via using " +
        "declarations. The analyzer cannot see ownership transfer through factory methods.")]
[TestClass]
internal sealed class CredentialSecuringMethodsTests
{
    public TestContext TestContext { get; set; } = null!;

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256IssuerKeys { get; } = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);

    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> P256EphemeralKeys { get; } = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);

    private const string Ed25519PublicKeyMultibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    private const string Ed25519SecretKeyMultibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";
    private const string Ed25519VerificationMethodId = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    //Controller-RESOLUTION semantics: the credential path now binds issuer == the resolved
    //verification method's own controller, so the fixture's DID document must name the SAME issuer
    //UnsignedCredentialJson declares below.
    private const string IssuerDid = "did:example:76e12ec712ebc6f1c221ebfeb1f";

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

    private static DateTime ProofCreated { get; } = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);


    /// <summary>
    /// Tests eddsa-rdfc-2022 Data Integrity proof using SignAsync and VerifyAsync.
    /// </summary>
    [TestMethod]
    public async ValueTask EddsaRdfc2022DataIntegrityProofSucceeds()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            BaseMemoryPool.Shared);
        using PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        var didDocument = CreateDidDocument(Ed25519VerificationMethodId, Ed25519PublicKeyMultibase);

        var signedCredential = await credential.SignAsync(
            privateKeyMemory,
            Ed25519VerificationMethodId,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            ProofCreated,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(signedCredential.Proof);
        Assert.HasCount(1, signedCredential.Proof);

        var proof = signedCredential.Proof[0];
        Assert.AreEqual("DataIntegrityProof", proof.Type);
        Assert.AreEqual("eddsa-rdfc-2022", proof.Cryptosuite?.CryptosuiteName);
        Assert.StartsWith("z", proof.ProofValue, "Proof value must be base58btc encoded.");

        var verificationResult = await signedCredential.VerifyAsync(
            didDocument,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid);
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
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        //Mandatory paths are always disclosed regardless of verifier request or user preference.
        var mandatoryPaths = new List<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/issuer"),
            CredentialPath.FromJsonPointer("/type")
        };

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
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(signedCredential.Proof);
        Assert.StartsWith(
            MultibaseAlgorithms.Base64Url.ToString(),
            signedCredential.Proof[0].ProofValue,
            "Base proof must use base64url-no-pad multibase encoding.");

        //Holder receives credential and verifies issuer signature.
        var holderVerifyResult = await signedCredential.VerifyBaseProofAsync(
            P256IssuerKeys.PublicKey,
            BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(holderVerifyResult.IsValid);

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
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            EcdsaSd2023CborSerializer.SerializeDerivedProof,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(derivedCredential.Proof);
        Assert.StartsWith(
            MultibaseAlgorithms.Base64Url.ToString(),
            derivedCredential.Proof[0].ProofValue!,
            "Derived proof must use base64url-no-pad multibase encoding.");

        //Verifier receives derived credential and verifies the selective disclosure proof.
        var verificationResult = await derivedCredential.VerifyDerivedProofAsync(
            P256IssuerKeys.PublicKey,
            BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid);
    }



    /// <summary>
    /// Tests eddsa-jcs-2022 Data Integrity proof using SignAsync and VerifyAsync.
    /// </summary>
    [TestMethod]
    public async ValueTask EddsaJcs2022DataIntegrityProofSucceeds()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            BaseMemoryPool.Shared);
        using PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

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
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid);
    }


    /// <summary>
    /// An eddsa-jcs-2022 proof over a credential whose <c>@context</c> is a two-IRI array plus an
    /// inline definition containing a <see langword="null"/>-valued member survives a
    /// serialize→parse→re-serialize cycle byte-identically and the proof still verifies.
    /// </summary>
    /// <remarks>
    /// <para>
    /// eddsa-jcs-2022 canonicalizes by JSON Canonicalization Scheme (RFC 8785), not RDF Dataset
    /// Canonicalization — see
    /// <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022">VC Data Integrity EdDSA
    /// Cryptosuites: eddsa-jcs-2022, the "Transformation" and "Proof Configuration" algorithms</see>,
    /// which serialize the credential (transformed document) and the proof options document as JCS
    /// and hash the concatenated bytes; the canonical bytes therefore have to be exactly what was
    /// signed, which is what this test proves for the array-plus-inline-definition-with-null shape a
    /// literal JSON re-serialization has to reproduce.
    /// </para>
    /// <para>
    /// The pre-signing re-serialization is checked against a JSON literal authored by hand, in the
    /// exact member order <see cref="Verifiable.Json.Converters.VerifiableCredentialConverter"/> and
    /// <see cref="Verifiable.Json.Converters.JsonLdContextConverter"/> write, rather than against a
    /// value the sign/verify round trip below produced: a deterministic wire-form change (member
    /// order, a dropped null, an escaped character) fails this assertion even in a build where the
    /// round trip below would still pass.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async ValueTask EddsaJcs2022DataIntegrityProofSucceedsWithArrayContextAndInlineDefinitionContainingNull()
    {
        const string UnsignedCredentialWithNullInDefinitionJson = /*lang=json,strict*/ """
        {"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2",{"@vocab":null}],"id":"http://university.example/credentials/3733","type":["VerifiableCredential","ExampleDegreeCredential"],"issuer":{"id":"did:example:76e12ec712ebc6f1c221ebfeb1f","name":"Example University"},"credentialSubject":{"id":"did:example:ebfeb1f712ebc6f1c276e12ec21","degree":{"type":"ExampleBachelorDegree","name":"Bachelor of Science and Arts"}},"validFrom":"2010-01-01T19:23:24Z"}
        """;

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredentialWithNullInDefinitionJson, JsonOptions)!;

        //The credential round-trips byte-identically before signing is even attempted, against the
        //hand-authored literal above rather than a value this test produced: the null-valued member
        //inside the inline definition is data (JSON-LD 1.1's way to clear @vocab), not something
        //ManualJsonReader may drop, and no member may move from the order the converter writes.
        string reserializedCredential = SerializeCredential(credential);
        Assert.AreEqual(UnsignedCredentialWithNullInDefinitionJson, reserializedCredential, "The unsigned credential must re-serialize byte-identically to the authored literal.");

        using(var beforeSigningDocument = JsonDocument.Parse(reserializedCredential))
        {
            Assert.IsTrue(beforeSigningDocument.RootElement.GetProperty("@context")[2].TryGetProperty("@vocab", out JsonElement vocabElement));
            Assert.AreEqual(JsonValueKind.Null, vocabElement.ValueKind);
        }

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            BaseMemoryPool.Shared);
        using PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

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
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Serialize, then parse and re-serialize again — the shape a signed credential actually
        //travels through on the wire — before verifying.
        string firstSerialization = SerializeCredential(signedCredential);
        var reparsedCredential = (DataIntegritySecuredCredential)DeserializeCredential(firstSerialization);
        string secondSerialization = SerializeCredential(reparsedCredential);
        Assert.AreEqual(firstSerialization, secondSerialization, "The array-plus-inline-definition-with-null @context must survive a parse→re-serialize cycle byte-identically.");

        var verificationResult = await reparsedCredential.VerifyAsync(
            didDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid);
    }


    /// <summary>
    /// An eddsa-jcs-2022 proof over a credential whose <c>@context</c> is authored as a bare
    /// scalar URL string, not an array, survives a serialize-&gt;parse-&gt;re-serialize cycle
    /// preserving that scalar wire shape byte-identically, and the proof still verifies.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 4.3
    /// Contexts</see> requires the array ("ordered set") form: "The value of the @context
    /// property MUST be an ordered set where the first item is a URL with the value
    /// https://www.w3.org/ns/credentials/v2." This library's
    /// <see cref="Verifiable.Core.Model.Common.Context"/> additionally accepts the more
    /// permissive bare-IRI-string shape JSON-LD contexts also take, the same scalar form
    /// <see cref="Verifiable.Json.Converters.JsonLdContextConverter"/> already round-trips for
    /// DID documents, and records which shape was read as
    /// <see cref="ContextForm.Scalar"/> so the writer reproduces it rather than upgrading it to
    /// a one-element array.
    /// </para>
    /// <para>
    /// Per <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022">VC Data Integrity
    /// EdDSA Cryptosuites: eddsa-jcs-2022, the "Transformation" algorithm</see>: "Let
    /// canonicalDocument be the result of applying the JSON Canonicalization Scheme [RFC8785]
    /// to a JSON serialization of the unsecuredDocument." A writer that silently wraps a scalar
    /// @context into an array before that step would sign and verify against different bytes
    /// than the document as authored; this test proves the scalar branch survives the whole
    /// proof path unchanged.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async ValueTask EddsaJcs2022DataIntegrityProofSucceedsWithScalarContext()
    {
        const string UnsignedCredentialWithScalarContextJson = /*lang=json,strict*/ """
        {"@context":"https://www.w3.org/ns/credentials/v2","id":"http://university.example/credentials/3736","type":["VerifiableCredential"],"issuer":{"id":"did:example:76e12ec712ebc6f1c221ebfeb1f","name":"Example University"},"credentialSubject":{"id":"did:example:ebfeb1f712ebc6f1c276e12ec21"},"validFrom":"2010-01-01T19:23:24Z"}
        """;

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredentialWithScalarContextJson, JsonOptions)!;
        Assert.AreEqual(ContextForm.Scalar, credential.Context!.Form);
        Assert.HasCount(1, credential.Context!.Entries);

        //The scalar @context round-trips byte-identically before signing is even attempted,
        //against the hand-authored literal above: the writer must reproduce the bare-string
        //shape rather than upgrading it to a one-element array.
        string reserializedCredential = SerializeCredential(credential);
        Assert.AreEqual(UnsignedCredentialWithScalarContextJson, reserializedCredential, "The scalar-form @context must survive a parse->re-serialize cycle byte-identically before any signing.");

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            BaseMemoryPool.Shared);
        using PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

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
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string firstSerialization = SerializeCredential(signedCredential);
        var reparsedCredential = (DataIntegritySecuredCredential)DeserializeCredential(firstSerialization);
        string secondSerialization = SerializeCredential(reparsedCredential);
        Assert.AreEqual(firstSerialization, secondSerialization, "The signed credential's scalar-form @context must survive a parse->re-serialize cycle byte-identically.");
        Assert.AreEqual(ContextForm.Scalar, reparsedCredential.Context!.Form, "The scalar form must not be upgraded to an array by the sign/verify round trip.");

        var verificationResult = await reparsedCredential.VerifyAsync(
            didDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid);
    }


    /// <summary>
    /// An eddsa-jcs-2022 proof over a credential whose <c>credentialSubject</c> carries a
    /// top-level <see langword="null"/>-valued member survives a
    /// serialize-&gt;parse-&gt;re-serialize cycle byte-identically, both before and after
    /// signing, and the proof still verifies.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#credential-subject">VC Data Model
    /// 2.0 4.8 Credential Subject</see> lets a subject carry arbitrary claims; a claim whose
    /// value is JSON <see langword="null"/> is a claim asserting that value, not an absent
    /// claim, so <see cref="Verifiable.Json.Converters.CredentialSubjectConverter"/> keeps it in
    /// <see cref="CredentialSubject.AdditionalData"/> and re-emits the <c>null</c> literal on
    /// write.
    /// </para>
    /// <para>
    /// Dropping that member on re-serialization would corrupt the canonicalization input
    /// eddsa-jcs-2022 signs: per
    /// <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022">VC Data Integrity EdDSA
    /// Cryptosuites: eddsa-jcs-2022, the "Transformation" algorithm</see>, "Let
    /// canonicalDocument be the result of applying the JSON Canonicalization Scheme [RFC8785]
    /// to a JSON serialization of the unsecuredDocument" - a member missing from that JSON
    /// serialization is a member the canonicalized, signed bytes never saw, so a verifier
    /// re-deriving the digest from a document an issuer authored with the null present would
    /// compute a different digest than one re-serialized with it dropped. This test proves the
    /// null member neither disappears nor changes the digest across the whole proof path.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async ValueTask EddsaJcs2022DataIntegrityProofSucceedsWithNullValuedCredentialSubjectMember()
    {
        const string UnsignedCredentialWithNullValuedSubjectMemberJson = /*lang=json,strict*/ """
        {"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"id":"http://university.example/credentials/3737","type":["VerifiableCredential","ExampleDegreeCredential"],"issuer":{"id":"did:example:76e12ec712ebc6f1c221ebfeb1f","name":"Example University"},"credentialSubject":{"id":"did:example:ebfeb1f712ebc6f1c276e12ec21","name":null},"validFrom":"2010-01-01T19:23:24Z"}
        """;

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredentialWithNullValuedSubjectMemberJson, JsonOptions)!;

        //The credential round-trips byte-identically before signing is even attempted, against
        //the hand-authored literal above: the credentialSubject's null-valued "name" member is
        //data, not an absent member, and CredentialSubjectConverter must not drop it.
        string reserializedCredential = SerializeCredential(credential);
        Assert.AreEqual(UnsignedCredentialWithNullValuedSubjectMemberJson, reserializedCredential, "The credentialSubject's null-valued member must survive a parse->re-serialize cycle byte-identically before any signing.");

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            BaseMemoryPool.Shared);
        using PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

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
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string firstSerialization = SerializeCredential(signedCredential);
        var reparsedCredential = (DataIntegritySecuredCredential)DeserializeCredential(firstSerialization);
        string secondSerialization = SerializeCredential(reparsedCredential);
        Assert.AreEqual(firstSerialization, secondSerialization, "The signed credential's null-valued credentialSubject member must survive a parse->re-serialize cycle byte-identically.");

        using(var signedDocument = JsonDocument.Parse(secondSerialization))
        {
            Assert.IsTrue(signedDocument.RootElement.GetProperty("credentialSubject").TryGetProperty("name", out JsonElement nameElement));
            Assert.AreEqual(JsonValueKind.Null, nameElement.ValueKind);
        }

        var verificationResult = await reparsedCredential.VerifyAsync(
            didDocument,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid);
    }


    /// <summary>
    /// Tests application/vc+jwt envelope (the "jose" tab).
    /// </summary>
    [TestMethod]
    public async ValueTask JoseJwtEnvelopeSucceeds()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase, MulticodecHeaders.Ed25519PrivateKey.Length, TestSetup.Base58Decoder, BaseMemoryPool.Shared);
        using PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        JwsMessage jwsMessage = await credential.SignJwsAsync(
            privateKeyMemory, Ed25519VerificationMethodId, CredentialSerializer, HeaderSerializer,
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jws = JwsSerialization.SerializeCompact(jwsMessage, TestSetup.Base64UrlEncoder);

        Assert.IsNotNull(jws);
        var parts = jws.Split('.');
        Assert.HasCount(3, parts);

        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase, MulticodecHeaders.Ed25519PublicKey.Length, TestSetup.Base58Decoder, BaseMemoryPool.Shared);
        using PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var verificationResult = await CredentialJwsExtensions.VerifyJwsAsync(
            jws, publicKeyMemory, TestSetup.Base64UrlDecoder, HeaderDeserializer, CredentialDeserializer,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verificationResult.IsValid, "JWT signature verification must succeed.");
        Assert.AreEqual(credential.Id, verificationResult.Credential!.Value.Value.Id);
    }


    /// <summary>
    /// Tests application/vc+cose envelope (the "cose" tab).
    /// </summary>
    [TestMethod]
    public async ValueTask CoseEnvelopeSucceeds()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase, MulticodecHeaders.Ed25519PrivateKey.Length, TestSetup.Base58Decoder, BaseMemoryPool.Shared);
        using PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        var protectedHeaderBuffer = new ArrayBufferWriter<byte>();
        var protectedHeader = new CborWriter(protectedHeaderBuffer, CborOptions.RfcCanonical);
        protectedHeader.WriteStartMap(2);
        protectedHeader.WriteInt32(CoseHeaderParameters.Alg);
        protectedHeader.WriteInt32(WellKnownCoseAlgorithms.EdDsa);
        protectedHeader.WriteInt32(CoseHeaderParameters.Kid);
        protectedHeader.WriteTextString(Ed25519VerificationMethodId);
        protectedHeader.WriteEndMap();
        var protectedHeaderBytes = protectedHeaderBuffer.WrittenSpan.ToArray();

        var payloadBytes = JsonSerializerExtensions.SerializeToUtf8Bytes(credential, JsonOptions);

        var sigStructureBuffer = new ArrayBufferWriter<byte>();
        var sigStructure = new CborWriter(sigStructureBuffer, CborOptions.RfcCanonical);
        sigStructure.WriteStartArray(4);
        sigStructure.WriteTextString("Signature1");
        sigStructure.WriteByteString(protectedHeaderBytes);
        sigStructure.WriteByteString([]);
        sigStructure.WriteByteString(payloadBytes);
        sigStructure.WriteEndArray();
        var sigStructureBytes = sigStructureBuffer.WrittenSpan.ToArray();

        using var signature = await privateKeyMemory.SignAsync(
            sigStructureBytes, BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async, BaseMemoryPool.Shared).ConfigureAwait(false);

        var coseSign1Buffer = new ArrayBufferWriter<byte>();
        var coseSign1 = new CborWriter(coseSign1Buffer, CborOptions.RfcCanonical);
        coseSign1.WriteTag(new CborTag((ulong)CoseTags.Sign1));
        coseSign1.WriteStartArray(4);
        coseSign1.WriteByteString(protectedHeaderBytes);
        coseSign1.WriteStartMap(0);
        coseSign1.WriteEndMap();
        coseSign1.WriteByteString(payloadBytes);
        coseSign1.WriteByteString(signature.AsReadOnlySpan());
        coseSign1.WriteEndArray();
        var coseSign1Bytes = coseSign1Buffer.WrittenSpan.ToArray();

        Assert.IsNotNull(coseSign1Bytes);
        Assert.IsGreaterThan(100, coseSign1Bytes.Length, "COSE_Sign1 should have substantial length.");

        var reader = new CborReader(coseSign1Bytes, CborOptions.Lax);
        var tag = reader.ReadTag();
        Assert.AreEqual(new CborTag((ulong)CoseTags.Sign1), tag);

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
            Ed25519PublicKeyMultibase, MulticodecHeaders.Ed25519PublicKey.Length, TestSetup.Base58Decoder, BaseMemoryPool.Shared);
        using PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var signatureMemory = BaseMemoryPool.Shared.Rent(readSignature.Length);
        readSignature.CopyTo(signatureMemory.Memory.Span);
        using var signatureToVerify = new Signature(signatureMemory, CryptoTags.Ed25519Signature);
        bool isValid = await publicKeyMemory.VerifyAsync(sigStructureBytes, signatureToVerify, BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "COSE_Sign1 signature verification must succeed.");
    }


    /// <summary>
    /// Tests SD-JWT envelope with selective disclosure.
    /// </summary>
    [TestMethod]
    public async ValueTask SdJwtEnvelopeSucceeds()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase, MulticodecHeaders.Ed25519PrivateKey.Length, TestSetup.Base58Decoder, BaseMemoryPool.Shared);
        using PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        byte[] salt1 = RandomNumberGenerator.GetBytes(SdConstants.DefaultSaltLengthBytes);
        byte[] salt2 = RandomNumberGenerator.GetBytes(SdConstants.DefaultSaltLengthBytes);

        using SdDisclosure disclosure1 = SdDisclosure.CreateProperty(TestSalts.FromBytes(salt1), "degree",
            new Dictionary<string, object> { ["type"] = "ExampleBachelorDegree", ["name"] = "Bachelor of Science and Arts" });
        using SdDisclosure disclosure2 = SdDisclosure.CreateProperty(TestSalts.FromBytes(salt2), "name", "Example University");

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
            [SdConstants.SdAlgorithmClaimName] = WellKnownHashAlgorithms.Sha256Iana
        };

        var header = new Dictionary<string, object>
        {
            [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.EdDsa,
            [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Application.VcSdJwt,
            [WellKnownJwkMemberNames.Kid] = Ed25519VerificationMethodId
        };

        var headerJson = JsonSerializerExtensions.SerializeToUtf8Bytes(header, JsonOptions);
        var payloadJson = JsonSerializerExtensions.SerializeToUtf8Bytes(sdPayload, JsonOptions);

        var headerBase64Url = TestSetup.Base64UrlEncoder(headerJson);
        var payloadBase64Url = TestSetup.Base64UrlEncoder(payloadJson);
        var signingInput = $"{headerBase64Url}.{payloadBase64Url}";

        var signature = await privateKeyMemory.SignAsync(
            Encoding.ASCII.GetBytes(signingInput), BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async, BaseMemoryPool.Shared).ConfigureAwait(false);

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
            Ed25519PublicKeyMultibase, MulticodecHeaders.Ed25519PublicKey.Length, TestSetup.Base58Decoder, BaseMemoryPool.Shared);
        using PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var verificationInput = Encoding.ASCII.GetBytes($"{jwtParts[0]}.{jwtParts[1]}");
        using var signatureBytesFromJwt = TestSetup.Base64UrlDecoder(jwtParts[2], BaseMemoryPool.Shared);
        using var signatureToVerify = new Signature(signatureBytesFromJwt, CryptoTags.Ed25519Signature);
        bool isValid = await publicKeyMemory.VerifyAsync(verificationInput, signatureToVerify, BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "SD-JWT signature verification must succeed.");
    }


    /// <summary>
    /// Tests SD-CWT envelope with selective disclosure.
    /// </summary>
    [TestMethod]
    public async ValueTask SdCwtEnvelopeSucceeds()
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredentialJson, JsonOptions)!;

        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase, MulticodecHeaders.Ed25519PrivateKey.Length, TestSetup.Base58Decoder, BaseMemoryPool.Shared);
        using PrivateKeyMemory privateKeyMemory = new(privateKeyBytes, CryptoTags.Ed25519PrivateKey);

        using SdDisclosure disclosure1 = SdDisclosure.CreateProperty(TestSalts.FromBytes(RandomNumberGenerator.GetBytes(SdConstants.DefaultSaltLengthBytes)), "degree",
            new Dictionary<string, object?> { ["type"] = "ExampleBachelorDegree", ["name"] = "Bachelor of Science and Arts" });
        using SdDisclosure disclosure2 = SdDisclosure.CreateProperty(TestSalts.FromBytes(RandomNumberGenerator.GetBytes(SdConstants.DefaultSaltLengthBytes)), "name", "Example University");

        var protectedHeader = BuildSdCwtProtectedHeader();
        byte[] payload = BuildCwtPayload(credential);

        var sigStructureBuffer = new ArrayBufferWriter<byte>();
        var sigStructure = new CborWriter(sigStructureBuffer, CborOptions.RfcCanonical);
        sigStructure.WriteStartArray(4);
        sigStructure.WriteTextString("Signature1");
        sigStructure.WriteByteString(protectedHeader);
        sigStructure.WriteByteString([]);
        sigStructure.WriteByteString(payload);
        sigStructure.WriteEndArray();
        var sigStructureBytes = sigStructureBuffer.WrittenSpan.ToArray();

        using var signature = await privateKeyMemory.SignAsync(
            sigStructureBytes, BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async, BaseMemoryPool.Shared).ConfigureAwait(false);

        var sdCwtMessage = new SdCwtMessage(
            payload.AsMemory(), protectedHeader.AsMemory(), signature.AsReadOnlySpan().ToArray(), [disclosure1, disclosure2]);

        var sdCwtBytes = SdCwtSerializer.Serialize(sdCwtMessage);

        Assert.IsNotNull(sdCwtBytes);
        Assert.IsGreaterThan(100, sdCwtBytes.Length, "SD-CWT should have substantial length.");

        var parsedMessage = SdCwtSerializer.Parse(sdCwtBytes, TestSalts.TestSaltTag, BaseMemoryPool.Shared);

        Assert.IsTrue(payload.AsSpan().SequenceEqual(parsedMessage.Payload.Span), "Payload must round-trip.");
        Assert.HasCount(2, parsedMessage.Disclosures, "Disclosures must round-trip.");

        var publicKeyBytes = MultibaseSerializer.Decode(
            Ed25519PublicKeyMultibase, MulticodecHeaders.Ed25519PublicKey.Length, TestSetup.Base58Decoder, BaseMemoryPool.Shared);
        using PublicKeyMemory publicKeyMemory = new(publicKeyBytes, CryptoTags.Ed25519PublicKey);

        var signatureMemory = BaseMemoryPool.Shared.Rent(parsedMessage.Signature.Length);
        parsedMessage.Signature.Span.CopyTo(signatureMemory.Memory.Span);
        using var signatureToVerify = new Signature(signatureMemory, CryptoTags.Ed25519Signature);
        bool isValid = await publicKeyMemory.VerifyAsync(sigStructureBytes, signatureToVerify, BouncyCastleCryptographicFunctionsAdapter.VerifyEd25519Async).ConfigureAwait(false);

        Assert.IsTrue(isValid, "SD-CWT signature verification must succeed.");
    }


    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    //Canonicalization/signing here is in-memory; a default context yields the
    //secure-default SSRF policy and satisfies the policy-carrying parameter.
    private static ExchangeContext EmptyContext { get; } = new();

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } = CanonicalizationTestUtilities.CreateTestContextResolver();

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    private static ReadOnlySpan<byte> CredentialSerializer(VerifiableCredential credential) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(credential, JsonOptions);

    private static ReadOnlySpan<byte> HeaderSerializer(Dictionary<string, object> header) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(header, JsonOptions);

    private static Dictionary<string, object>? HeaderDeserializer(ReadOnlySpan<byte> headerBytes) =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(headerBytes, JsonOptions);

    private static VerifiableCredential CredentialDeserializer(ReadOnlySpan<byte> credentialBytes) =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(credentialBytes, JsonOptions)!;

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
                    Controller = IssuerDid,
                    KeyFormat = new PublicKeyMultibase(publicKeyMultibase)
                }
            ],
            AssertionMethod = [new AssertionMethod(verificationMethodId)]
        };
    }


    [UnconditionalSuppressMessage("Trimming", "IL2026", Justification =
        """
        ClaimValue is object? — the concrete runtime type is unknown at compile time.
        SD-JWT claim values are primitive JSON types (string, number, bool, null) in practice,
        which are handled by the built-in serializer without reflection on user types.
        """)]
    private static string EncodeDisclosure(SdDisclosure disclosure, EncodeDelegate base64UrlEncoder)
    {
        string saltBase64Url = base64UrlEncoder(disclosure.Salt.AsReadOnlySpan());
        string json = disclosure.ClaimName is not null
            ? $"[\"{saltBase64Url}\",\"{disclosure.ClaimName}\",{JsonSerializer.Serialize(disclosure.ClaimValue)}]"
            : $"[\"{saltBase64Url}\",{JsonSerializer.Serialize(disclosure.ClaimValue)}]";
        return base64UrlEncoder(Encoding.UTF8.GetBytes(json));
    }

    private static string ComputeDisclosureDigest(string encodedDisclosure, EncodeDelegate base64UrlEncoder) =>
        base64UrlEncoder(SHA256.HashData(Encoding.ASCII.GetBytes(encodedDisclosure)));

    private static byte[] BuildCwtPayload(VerifiableCredential credential)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(WellKnownCwtClaimNames.Iss);
        writer.WriteTextString(credential.Issuer!.Id!);
        writer.WriteInt32(WellKnownCwtClaimNames.Sub);
        writer.WriteTextString(credential.CredentialSubject![0].Id!);
        writer.WriteInt32(WellKnownCwtClaimNames.Iat);
        writer.WriteInt64(!string.IsNullOrEmpty(credential.ValidFrom) ? DateTimeOffset.Parse(credential.ValidFrom, CultureInfo.InvariantCulture).ToUnixTimeSeconds() : 0L);
        writer.WriteEndMap();
        return buffer.WrittenSpan.ToArray();
    }

    private static byte[] BuildSdCwtProtectedHeader()
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(CoseHeaderParameters.Alg);
        writer.WriteInt32(WellKnownCoseAlgorithms.EdDsa);
        writer.WriteInt32(CoseHeaderParameters.Typ);
        writer.WriteTextString(SdCwtSerializer.SdCwtMediaType);
        writer.WriteEndMap();
        return buffer.WrittenSpan.ToArray();
    }
}

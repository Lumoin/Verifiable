using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared wiring for tests that present a verifier with a Data Integrity secured credential
/// whose <c>@context</c> was altered after signing.
/// </summary>
/// <remarks>
/// <para>
/// This fixture collects the quintet every Data Integrity test class otherwise declares by
/// hand (an RDFC-1.0 canonicalizer, a JCS canonicalizer, a closed test context resolver, an
/// empty <see cref="ExchangeContext"/>, and the credential/proof-options serialization
/// delegates), plus a single known Ed25519 key pair and issuer <see cref="DidDocument"/>, so a
/// tampering test only has to state which entry of <c>@context</c> it disturbs.
/// </para>
/// <para>
/// The key material is the Ed25519 test vector from
/// <see href="https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-rdfc-2022">VC Data
/// Integrity EdDSA Cryptosuites v1.0, Appendix B.1, Example 7</see>, the same pair
/// <see cref="Verifiable.Tests.DataIntegrity.DataIntegrityTests"/> and
/// <see cref="Verifiable.Tests.DataIntegrity.CredentialSecuringMethodsTests"/> already use.
/// </para>
/// </remarks>
internal static class DataIntegrityContextTamperingFixture
{
    /// <summary>Ed25519 public key in Multikey format (W3C test vector).</summary>
    public const string Ed25519PublicKeyMultibase = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    /// <summary>Ed25519 secret key in Multikey format (W3C test vector).</summary>
    public const string Ed25519SecretKeyMultibase = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

    /// <summary>The issuer verification method's DID URL for the test key.</summary>
    public const string Ed25519VerificationMethodId = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    /// <summary>The <c>did:example</c> controller the issued credential's <c>issuer.id</c> names, matching the resolved verification method's own controller.</summary>
    public const string IssuerControllerDid = "did:example:76e12ec712ebc6f1c221ebfeb1f";

    /// <summary>The subject DID the issued credential's <c>credentialSubject.id</c> names.</summary>
    public const string HolderDid = "did:example:ebfeb1f712ebc6f1c276e12ec21";

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>An RDFC-1.0 canonicalizer backed by the closed, three-URL test context resolver.</summary>
    public static CanonicalizationDelegate RdfcCanonicalizer { get; } = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    /// <summary>A context resolver that knows exactly three URLs and returns <see langword="null"/> for every other.</summary>
    public static ContextResolverDelegate ContextResolver { get; } = CanonicalizationTestUtilities.CreateTestContextResolver();

    /// <summary>A JCS canonicalizer; it ignores the context resolver since JCS performs no JSON-LD expansion.</summary>
    public static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    //Canonicalization/signing here is in-memory; a default context yields the
    //secure-default SSRF policy and satisfies the policy-carrying parameter.
    public static ExchangeContext EmptyContext { get; } = [];

    /// <summary>
    /// The known <c>@context</c> a verifier checks the tampered credential against: the same
    /// two-entry ordered set <see cref="CreateUnsignedCredentialJson"/> signs, untampered.
    /// </summary>
    public static Context KnownContext { get; } = Context.FromIris(Context.Credentials20, Context.CredentialsExamples20);

    /// <summary>An unresolvable, unknown context URL appended after signing (tampering variant a).</summary>
    public const string TamperedContextExtraUnknownUrl = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", "https://unknown.example/context/v1"]
        """;

    /// <summary>A known context URL not originally named, appended after signing (tampering variant b).</summary>
    public const string TamperedContextExtraKnownUrl = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", "https://w3id.org/citizenship/v4rc1"]
        """;

    /// <summary>A known context substituted for another known context after signing (tampering variant c).</summary>
    public const string TamperedContextSubstitutedKnownUrl = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/citizenship/v4rc1"]
        """;

    /// <summary>The signed two-entry <c>@context</c> reordered after signing (tampering variant d).</summary>
    public const string TamperedContextReordered = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/examples/v2", "https://www.w3.org/ns/credentials/v2"]
        """;

    /// <summary>A context entry duplicated after signing (tampering variant e).</summary>
    public const string TamperedContextDuplicated = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", "https://www.w3.org/ns/credentials/examples/v2"]
        """;

    /// <summary>An inline context object appended that redefines the <c>alumniOf</c> term the credential uses (tampering variant f, redefining case).</summary>
    public const string TamperedContextInlineRedefinesUsedTerm = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", {"alumniOf": "https://attacker.example/vocab#alumniOf"}]
        """;

    /// <summary>An inline context object appended that defines only an unused term (tampering variant f, unused-term case).</summary>
    public const string TamperedContextInlineDefinesUnusedTerm = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", {"neverUsedTerm": "https://attacker.example/vocab#neverUsedTerm"}]
        """;

    /// <summary>A known context that is not the VC Data Model base context placed first (tampering variant g).</summary>
    public const string TamperedContextNonBaseFirst = /*lang=json,strict*/ """
        ["https://w3id.org/citizenship/v4rc1", "https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"]
        """;

    /// <summary>Serializes a credential with <see cref="TestSetup.DefaultSerializationOptions"/>.</summary>
    public static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    /// <summary>Deserializes a credential with <see cref="TestSetup.DefaultSerializationOptions"/>.</summary>
    public static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    /// <summary>Serializes a presentation with <see cref="TestSetup.DefaultSerializationOptions"/>.</summary>
    public static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    /// <summary>Deserializes a presentation with <see cref="TestSetup.DefaultSerializationOptions"/>.</summary>
    public static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    /// <summary>Serializes a proof options document with <see cref="TestSetup.DefaultSerializationOptions"/>.</summary>
    public static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    /// <summary>Creates the Ed25519 private key from the embedded W3C test vector.</summary>
    /// <returns>An owned <see cref="PrivateKeyMemory"/>; the caller disposes it.</returns>
    public static PrivateKeyMemory CreatePrivateKey()
    {
        var privateKeyBytes = MultibaseSerializer.Decode(
            Ed25519SecretKeyMultibase,
            MulticodecHeaders.Ed25519PrivateKey.Length,
            TestSetup.Base58Decoder,
            BaseMemoryPool.Shared);

        return new PrivateKeyMemory(privateKeyBytes, CryptoTags.Ed25519PrivateKey);
    }

    /// <summary>Builds the issuer's DID document naming the fixture's verification method and controller.</summary>
    public static DidDocument CreateIssuerDidDocument()
    {
        return new DidDocument
        {
            Id = new GenericDidMethod(Ed25519VerificationMethodId.Split('#')[0]),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = Ed25519VerificationMethodId,
                    Type = "Multikey",
                    Controller = IssuerControllerDid,
                    KeyFormat = new PublicKeyMultibase(Ed25519PublicKeyMultibase)
                }
            ],
            AssertionMethod = [new AssertionMethod(Ed25519VerificationMethodId)]
        };
    }

    /// <summary>Builds the holder's DID document naming the fixture's verification method under <c>authentication</c>.</summary>
    public static DidDocument CreateHolderDidDocument()
    {
        return new DidDocument
        {
            Id = new GenericDidMethod(Ed25519VerificationMethodId.Split('#')[0]),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = Ed25519VerificationMethodId,
                    Type = "Multikey",
                    Controller = IssuerControllerDid,
                    KeyFormat = new PublicKeyMultibase(Ed25519PublicKeyMultibase)
                }
            ],
            Authentication = [new AuthenticationMethod(Ed25519VerificationMethodId)]
        };
    }

    /// <summary>
    /// An unsigned presentation naming the fixture's holder, with a two-entry <c>@context</c> array.
    /// </summary>
    /// <param name="presentationId">The presentation's own <c>id</c>.</param>
    /// <returns>The unsigned presentation JSON text.</returns>
    public static string CreateUnsignedPresentationJson(string presentationId)
    {
        return $$"""
        {
            "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
            "id": "{{presentationId}}",
            "type": ["VerifiablePresentation"],
            "holder": "{{IssuerControllerDid}}"
        }
        """;
    }

    /// <summary>
    /// An unsigned credential naming the given id, with an <c>alumniOf</c> claim whose predicate
    /// mapping only the Credentials Examples v2 context (the second known context URL) defines.
    /// </summary>
    /// <param name="credentialId">The credential's own <c>id</c>.</param>
    /// <returns>The unsigned credential JSON text, with a two-entry <c>@context</c> array.</returns>
    public static string CreateUnsignedCredentialJson(string credentialId)
    {
        return $$"""
        {
            "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
            "id": "{{credentialId}}",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "issuer": {
                "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
                "name": "Example University"
            },
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "alumniOf": "Example University"
            }
        }
        """;
    }

    /// <summary>Signs the given unsigned credential JSON with the fixture's key and returns the signed credential and its issuer's DID document.</summary>
    /// <param name="unsignedCredentialJson">The unsigned credential JSON text.</param>
    /// <param name="cryptosuite">The cryptosuite to sign with.</param>
    /// <param name="canonicalize">The canonicalization delegate matching <paramref name="cryptosuite"/>.</param>
    /// <param name="contextResolver">The context resolver; <see langword="null"/> for JCS cryptosuites.</param>
    /// <param name="proofCreated">The proof's <c>created</c> timestamp.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed credential and the issuer's DID document a verifier resolves against.</returns>
    public static async ValueTask<(DataIntegritySecuredCredential Signed, DidDocument Issuer)> SignCredentialAsync(
        string unsignedCredentialJson,
        CryptosuiteInfo cryptosuite,
        CanonicalizationDelegate canonicalize,
        ContextResolverDelegate? contextResolver,
        DateTime proofCreated,
        CancellationToken cancellationToken)
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(unsignedCredentialJson, JsonOptions)!;
        using var privateKey = CreatePrivateKey();
        var issuerDidDocument = CreateIssuerDidDocument();

        var signed = await credential.SignAsync(
            privateKey,
            Ed25519VerificationMethodId,
            cryptosuite,
            proofCreated,
            canonicalize,
            contextResolver,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return (signed, issuerDidDocument);
    }

    /// <summary>
    /// Serializes a signed credential, replaces its <c>@context</c> member with
    /// <paramref name="tamperedContext"/>, and re-parses the result the way a presented
    /// credential travels the wire.
    /// </summary>
    /// <param name="signed">The signed credential to tamper.</param>
    /// <param name="tamperedContext">The replacement <c>@context</c> JSON node.</param>
    /// <returns>The re-parsed, context-tampered credential.</returns>
    public static DataIntegritySecuredCredential ReserializeWithTamperedContext(DataIntegritySecuredCredential signed, JsonNode tamperedContext)
    {
        var json = SerializeCredential(signed);
        var node = JsonNode.Parse(json)!;
        node["@context"] = tamperedContext;
        var tamperedJson = node.ToJsonString(JsonOptions);

        return (DataIntegritySecuredCredential)DeserializeCredential(tamperedJson);
    }


    /// <summary>Signs the given unsigned presentation JSON with the fixture's key and returns the signed presentation and the holder's DID document.</summary>
    /// <param name="unsignedPresentationJson">The unsigned presentation JSON text.</param>
    /// <param name="cryptosuite">The cryptosuite to sign with.</param>
    /// <param name="canonicalize">The canonicalization delegate matching <paramref name="cryptosuite"/>.</param>
    /// <param name="contextResolver">The context resolver; <see langword="null"/> for JCS cryptosuites.</param>
    /// <param name="proofCreated">The proof's <c>created</c> timestamp.</param>
    /// <param name="challenge">The proof's <c>challenge</c>.</param>
    /// <param name="domain">The proof's <c>domain</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed presentation and the holder's DID document a verifier resolves against.</returns>
    public static async ValueTask<(DataIntegritySecuredPresentation Signed, DidDocument Holder)> SignPresentationAsync(
        string unsignedPresentationJson,
        CryptosuiteInfo cryptosuite,
        CanonicalizationDelegate canonicalize,
        ContextResolverDelegate? contextResolver,
        DateTime proofCreated,
        string challenge,
        string domain,
        CancellationToken cancellationToken)
    {
        var presentation = JsonSerializerExtensions.Deserialize<VerifiablePresentation>(unsignedPresentationJson, JsonOptions)!;
        using var privateKey = CreatePrivateKey();
        var holderDidDocument = CreateHolderDidDocument();

        var signed = await presentation.SignAsync(
            privateKey,
            Ed25519VerificationMethodId,
            cryptosuite,
            proofCreated,
            challenge,
            domain,
            canonicalize,
            contextResolver,
            ProofValueCodecs.EncodeBase58Btc,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return (signed, holderDidDocument);
    }


    /// <summary>
    /// Serializes a signed presentation, replaces its <c>@context</c> member with
    /// <paramref name="tamperedContext"/>, and re-parses the result the way a presented
    /// presentation travels the wire.
    /// </summary>
    /// <param name="signed">The signed presentation to tamper.</param>
    /// <param name="tamperedContext">The replacement <c>@context</c> JSON node.</param>
    /// <returns>The re-parsed, context-tampered presentation.</returns>
    public static DataIntegritySecuredPresentation ReserializeWithTamperedContext(DataIntegritySecuredPresentation signed, JsonNode tamperedContext)
    {
        var json = SerializePresentation(signed);
        var node = JsonNode.Parse(json)!;
        node["@context"] = tamperedContext;
        var tamperedJson = node.ToJsonString(JsonOptions);

        return (DataIntegritySecuredPresentation)DeserializePresentation(tamperedJson);
    }


    /// <summary>The ecdsa-sd-2023 issuer's verification method DID URL, under <see cref="IssuerControllerDid"/>.</summary>
    public const string EcdsaSdVerificationMethodId = IssuerControllerDid + "#ecdsa-sd-key-1";

    /// <summary>The bbs-2023 issuer's verification method DID URL, under <see cref="IssuerControllerDid"/>.</summary>
    public const string BbsVerificationMethodId = IssuerControllerDid + "#bbs-key-1";

    /// <summary>Mandatory paths for an ecdsa-sd-2023/bbs-2023 base proof: always-disclosed <c>issuer</c> and <c>type</c>.</summary>
    public static IReadOnlyList<CredentialPath> SelectiveDisclosureMandatoryPaths { get; } =
    [
        CredentialPath.FromJsonPointer("/issuer"),
        CredentialPath.FromJsonPointer("/type")
    ];

    /// <summary>The claim path an ecdsa-sd-2023/bbs-2023 derived-proof tampering test discloses.</summary>
    public static IReadOnlySet<CredentialPath> SelectiveDisclosureRevealedPaths { get; } =
        new HashSet<CredentialPath> { CredentialPath.FromJsonPointer("/credentialSubject/alumniOf") };


    /// <summary>Builds an issuer <see cref="DidDocument"/> naming <paramref name="verificationMethodId"/> under <see cref="IssuerControllerDid"/>, keyed by <paramref name="publicKeyBytes"/> under <paramref name="multicodecHeader"/>.</summary>
    /// <param name="publicKeyBytes">The issuer's public key bytes.</param>
    /// <param name="multicodecHeader">The Multikey multicodec header for the key's algorithm.</param>
    /// <param name="verificationMethodId">The verification method's own DID URL.</param>
    /// <returns>The issuer's DID document.</returns>
    private static DidDocument CreateSelectiveDisclosureIssuerDidDocument(
        ReadOnlySpan<byte> publicKeyBytes, ReadOnlySpan<byte> multicodecHeader, string verificationMethodId)
    {
        string publicKeyMultibase = MultibaseSerializer.Encode(
            publicKeyBytes, multicodecHeader, MultibaseAlgorithms.Base58Btc, TestSetup.Base58Encoder, BaseMemoryPool.Shared);

        return new DidDocument
        {
            Id = new GenericDidMethod(IssuerControllerDid),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = verificationMethodId,
                    Type = "Multikey",
                    Controller = IssuerControllerDid,
                    KeyFormat = new PublicKeyMultibase(publicKeyMultibase)
                }
            ],
            AssertionMethod = [new AssertionMethod(verificationMethodId)]
        };
    }


    /// <summary>Signs <paramref name="unsignedCredentialJson"/> with an ecdsa-sd-2023 base proof (P-256).</summary>
    /// <param name="unsignedCredentialJson">The unsigned credential JSON text.</param>
    /// <param name="proofCreated">The proof's <c>created</c> timestamp.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The base-proofed credential, the issuer's public key (caller disposes), and the issuer's DID document.</returns>
    public static async ValueTask<(DataIntegritySecuredCredential Signed, PublicKeyMemory IssuerPublicKey, DidDocument Issuer)> CreateEcdsaSdBaseProofAsync(
        string unsignedCredentialJson, DateTime proofCreated, CancellationToken cancellationToken)
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(unsignedCredentialJson, JsonOptions)!;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        var ephemeralPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);

        var signed = await credential.CreateBaseProofAsync(
            issuerPair.PrivateKey,
            ephemeralPair,
            EcdsaSdVerificationMethodId,
            proofCreated,
            SelectiveDisclosureMandatoryPaths,
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

        ephemeralPair.PrivateKey.Dispose();
        ephemeralPair.PublicKey.Dispose();
        issuerPair.PrivateKey.Dispose();

        var issuerDidDocument = CreateSelectiveDisclosureIssuerDidDocument(
            issuerPair.PublicKey.AsReadOnlySpan(), MulticodecHeaders.P256PublicKey, EcdsaSdVerificationMethodId);

        return (signed, issuerPair.PublicKey, issuerDidDocument);
    }


    /// <summary>Derives an ecdsa-sd-2023 proof from <paramref name="signed"/>, revealing <see cref="SelectiveDisclosureRevealedPaths"/>.</summary>
    /// <param name="signed">The base-proofed credential to derive from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The derived credential.</returns>
    public static ValueTask<DataIntegritySecuredCredential> DeriveEcdsaSdProofAsync(
        DataIntegritySecuredCredential signed, CancellationToken cancellationToken)
    {
        return signed.DeriveProofAsync(
            SelectiveDisclosureRevealedPaths,
            userExclusions: null,
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
            cancellationToken);
    }


    /// <summary>Signs <paramref name="unsignedCredentialJson"/> with a bbs-2023 base proof, using <paramref name="bbs"/>'s key pair.</summary>
    /// <param name="bbs">The BBS operations bound to a freshly generated BLS12-381 key pair.</param>
    /// <param name="unsignedCredentialJson">The unsigned credential JSON text.</param>
    /// <param name="proofCreated">The proof's <c>created</c> timestamp.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The base-proofed credential and the issuer's DID document.</returns>
    public static async ValueTask<(DataIntegritySecuredCredential Signed, DidDocument Issuer)> CreateBbsBaseProofAsync(
        Verifiable.Tests.DataIntegrity.Bbs2023ResolvingBindingTests.ResolvingBbsOperations bbs,
        string unsignedCredentialJson,
        DateTime proofCreated,
        CancellationToken cancellationToken)
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(unsignedCredentialJson, JsonOptions)!;

        var signed = await credential.CreateBaseProofAsync(
            bbs.PublicKeyBytes,
            BbsVerificationMethodId,
            proofCreated,
            SelectiveDisclosureMandatoryPaths,
            () => RandomNumberGenerator.GetBytes(32),
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            Bbs2023CborSerializer.SerializeBaseProof,
            bbs.Sign,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        var issuerDidDocument = CreateSelectiveDisclosureIssuerDidDocument(
            bbs.PublicKeyBytes, MulticodecHeaders.Bls12381G2PublicKey, BbsVerificationMethodId);

        return (signed, issuerDidDocument);
    }


    /// <summary>Derives a bbs-2023 proof from <paramref name="signed"/>, revealing <see cref="SelectiveDisclosureRevealedPaths"/>.</summary>
    /// <param name="signed">The base-proofed credential to derive from.</param>
    /// <param name="bbs">The BBS operations bound to the same key pair the base proof was signed with.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The derived credential.</returns>
    public static ValueTask<DataIntegritySecuredCredential> DeriveBbsProofAsync(
        DataIntegritySecuredCredential signed,
        Verifiable.Tests.DataIntegrity.Bbs2023ResolvingBindingTests.ResolvingBbsOperations bbs,
        CancellationToken cancellationToken)
    {
        return signed.DeriveProofAsync(
            SelectiveDisclosureRevealedPaths,
            userExclusions: null,
            Array.Empty<byte>(),
            JsonLdSelection.PartitionStatements,
            JsonLdSelection.SelectFragments,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            Bbs2023CborSerializer.ParseBaseProof,
            Bbs2023CborSerializer.SerializeDerivedProof,
            bbs.ProofGen,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken);
    }
}

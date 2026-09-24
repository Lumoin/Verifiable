using System.Text;
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

    /// <summary>The serializer options every JSON read and write of the fixture uses.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>An RDFC-1.0 canonicalizer backed by the closed, three-URL test context resolver.</summary>
    public static CanonicalizationDelegate RdfcCanonicalizer { get; } = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    /// <summary>A context resolver that knows exactly three URLs and returns <see langword="null"/> for every other.</summary>
    public static ContextResolverDelegate ContextResolver { get; } = CanonicalizationTestUtilities.CreateTestContextResolver();

    /// <summary>A JCS canonicalizer; it ignores the context resolver since JCS performs no JSON-LD expansion.</summary>
    public static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    /// <summary>
    /// The per-operation context the fixture's in-memory canonicalization and signing take: an empty context carries
    /// the secure-default outbound-fetch policy, which satisfies the policy-carrying parameter without any network.
    /// </summary>
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
    /// The length, in bytes, of the HMAC key a selective-disclosure base proof relabels blank nodes with: the 32 bytes
    /// the ecdsa-sd-2023 and bbs-2023 base proofs of these tests are created with.
    /// </summary>
    private static int SelectiveDisclosureHmacKeyByteLength => 32;


    /// <summary>
    /// Draws a fresh HMAC key for a selective-disclosure base proof from the project's entropy provider
    /// (<see cref="BouncyCastleEntropyFunctionsAdapter.GenerateNonce"/>) under the HMAC-SHA-256 key's own purpose
    /// (<see cref="CryptoTags.HmacSha256Key"/>), never as a nonce: a salt, a nonce and a key carry different invariants.
    /// The base proof's <see cref="HmacKeyGeneratorDelegate"/> takes the key as a byte array, so the drawn value is
    /// copied out of its pooled buffer once, and the buffer is returned to the pool.
    /// </summary>
    /// <returns>The HMAC key bytes.</returns>
    public static byte[] GenerateSelectiveDisclosureHmacKey()
    {
        (Nonce drawn, _) = BouncyCastleEntropyFunctionsAdapter.GenerateNonce(
            SelectiveDisclosureHmacKeyByteLength, CryptoTags.HmacSha256Key, BaseMemoryPool.Shared);
        using(drawn)
        {
            byte[] hmacKey = new byte[SelectiveDisclosureHmacKeyByteLength];
            drawn.AsReadOnlySpan()[..SelectiveDisclosureHmacKeyByteLength].CopyTo(hmacKey);

            return hmacKey;
        }
    }


    /// <summary>
    /// Signs an eddsa-jcs-2022 presentation for the holder of <paramref name="holderDidDocument"/> with the document's
    /// first verification method, through
    /// <see cref="SignJcsPresentationAsync(string, string, PrivateKeyMemory, string?, string?, DateTime, List{VerifiableCredential}?, List{EnvelopedVerifiableCredential}?)"/>.
    /// </summary>
    /// <param name="holderDidDocument">
    /// The holder's DID document: its first verification method signs, and its <c>id</c> is the presentation's holder.
    /// </param>
    /// <param name="privateKey">The holder's Ed25519 private key.</param>
    /// <param name="challenge">The challenge to bind into the proof, or <see langword="null"/> for none.</param>
    /// <param name="domain">The domain to bind into the proof, or <see langword="null"/> for none.</param>
    /// <param name="proofCreated">The instant written into the proof's <c>created</c> member.</param>
    /// <returns>The secured presentation.</returns>
    public static Task<DataIntegritySecuredPresentation> SignJcsPresentationAsync(
        DidDocument holderDidDocument, PrivateKeyMemory privateKey, string? challenge, string? domain, DateTime proofCreated) =>
        SignJcsPresentationAsync(
            holderDidDocument.Id!.ToString(), holderDidDocument.VerificationMethod![0].Id!, privateKey, challenge, domain, proofCreated);


    /// <summary>
    /// Signs an eddsa-jcs-2022 presentation claiming <paramref name="holderDid"/> with <paramref name="signerPrivateKey"/>
    /// under <paramref name="signerVerificationMethodId"/>, whose proof carries only the binding given: a
    /// <c>challenge</c> and a <c>domain</c> appear in the signed proof options when, and only when, a value is supplied.
    /// The signature covers SHA-256 of the JCS form of the proof options followed by SHA-256 of the JCS form of the
    /// presentation, the eddsa-jcs-2022 hashing a bound signer performs too, so a verifier checks the proof over whatever
    /// binding it carries. The holder and the signer are separate inputs so a test can present a holder that does not
    /// control the signing method. When <paramref name="containedCredentials"/> or <paramref name="envelopedCredentials"/>
    /// is given, its entries are part of the presentation this signs over, so a caller may embed an ALREADY tampered
    /// contained credential and still get a validly-signed outer presentation: the signature covers whatever bytes are
    /// present at signing time, tampered or not.
    /// </summary>
    /// <param name="holderDid">The DID the presentation's <c>holder</c> member claims.</param>
    /// <param name="signerVerificationMethodId">The verification method the proof's <c>verificationMethod</c> names.</param>
    /// <param name="signerPrivateKey">The Ed25519 private key that signs the proof.</param>
    /// <param name="challenge">The challenge to bind into the proof, or <see langword="null"/> for none.</param>
    /// <param name="domain">The domain to bind into the proof, or <see langword="null"/> for none.</param>
    /// <param name="proofCreated">The instant written into the proof's <c>created</c> member.</param>
    /// <param name="containedCredentials">The presentation's <c>verifiableCredential</c> entries, or <see langword="null"/> for none.</param>
    /// <param name="envelopedCredentials">The presentation's enveloped credential entries, or <see langword="null"/> for none.</param>
    /// <returns>The secured presentation.</returns>
    public static async Task<DataIntegritySecuredPresentation> SignJcsPresentationAsync(
        string holderDid,
        string signerVerificationMethodId,
        PrivateKeyMemory signerPrivateKey,
        string? challenge,
        string? domain,
        DateTime proofCreated,
        List<VerifiableCredential>? containedCredentials = null,
        List<EnvelopedVerifiableCredential>? envelopedCredentials = null)
    {
        VerifiablePresentation unsigned = new()
        {
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            Holder = holderDid,
            VerifiableCredential = containedCredentials,
            EnvelopedVerifiableCredential = envelopedCredentials
        };

        DataIntegrityProof newProof = new()
        {
            Type = DataIntegrityProof.DataIntegrityProofType,
            Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
            Created = DateTimeStampFormat.Format(proofCreated),
            VerificationMethod = new AuthenticationMethod(signerVerificationMethodId),
            ProofPurpose = AuthenticationMethod.Purpose
        };

        if(challenge is not null)
        {
            newProof.Challenge = challenge;
        }

        if(domain is not null)
        {
            newProof.Domain = [domain];
        }

        string proofOptionsSerialized = SerializeProofOptions(ProofOptionsDocument.FromProof(newProof, null));
        string presentationSerialized = SerializePresentation(unsigned);

        using System.Buffers.IMemoryOwner<byte> hashOwner = BaseMemoryPool.Shared.Rent(64);
        Memory<byte> hashData = hashOwner.Memory[..64];
        HashCanonical(proofOptionsSerialized, hashData.Span[..32]);
        HashCanonical(presentationSerialized, hashData.Span[32..]);

        using Signature signature = await signerPrivateKey.SignAsync(hashData, BaseMemoryPool.Shared).ConfigureAwait(false);
        newProof.ProofValue = ProofValueCodecs.EncodeBase58Btc(signature.AsReadOnlySpan(), TestSetup.Base58Encoder, BaseMemoryPool.Shared);

        return new DataIntegritySecuredPresentation
        {
            Context = unsigned.Context,
            Type = unsigned.Type,
            Holder = unsigned.Holder,
            VerifiableCredential = unsigned.VerifiableCredential,
            EnvelopedVerifiableCredential = unsigned.EnvelopedVerifiableCredential,
            Proof = [newProof]
        };
    }


    /// <summary>
    /// Writes SHA-256 of the JCS form of <paramref name="json"/> into <paramref name="destination"/>, the canonical
    /// JSON wrapped as JSON-tagged memory rather than materialized as a naked array.
    /// </summary>
    /// <param name="json">The JSON text to canonicalize and hash.</param>
    /// <param name="destination">The 32-byte span receiving the digest.</param>
    private static void HashCanonical(string json, Span<byte> destination)
    {
        var canonical = new TaggedMemory<byte>(Jcs.CanonicalizeToUtf8Bytes(json), BufferTags.Json);
        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(canonical.Span, destination.Length, CryptoTags.Sha256Digest, BaseMemoryPool.Shared);
        digest.AsReadOnlySpan().CopyTo(destination);
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


    /// <summary>
    /// The first proof map of a secured credential's or presentation's JSON: the member itself when <c>proof</c>
    /// is a single map, its first element when <c>proof</c> is an array (a proof set or chain).
    /// </summary>
    /// <param name="securedDocument">The secured document's JSON object.</param>
    /// <returns>The first proof map, which the caller may change in place.</returns>
    public static JsonObject FirstProof(JsonObject securedDocument) => securedDocument["proof"] switch
    {
        JsonArray proofs => proofs[0]!.AsObject(),
        JsonObject proof => proof,
        _ => throw new AssertFailedException("The secured document must carry a proof map.")
    };


    /// <summary>
    /// Applies one structural change to a secured credential's or presentation's JSON after signing, the way
    /// an altered document travels the wire, and returns the changed JSON.
    /// </summary>
    /// <remarks>
    /// <paramref name="mutation"/> is <c>delete:&lt;path&gt;</c>, <c>set:&lt;path&gt;=&lt;json&gt;</c> or
    /// <c>setArray:&lt;path&gt;=&lt;json&gt;</c>, the last setting a one-element array that holds the value.
    /// <c>&lt;path&gt;</c> names a top-level member, or one member of a nested map as <c>parent.member</c>:
    /// <c>proof.member</c> addresses <see cref="FirstProof"/>, and a parent that is not a map is replaced by a
    /// map holding only the set member. <c>&lt;json&gt;</c> is any JSON value, a string written with its quotes.
    /// </remarks>
    /// <param name="securedDocumentJson">The signed document's JSON text.</param>
    /// <param name="mutation">The change to apply.</param>
    /// <returns>The changed document's JSON text.</returns>
    public static string MutateSecuredDocumentJson(string securedDocumentJson, string mutation)
    {
        JsonObject document = JsonNode.Parse(securedDocumentJson)!.AsObject();
        int operationEnd = mutation.IndexOf(':', StringComparison.Ordinal);
        string operation = mutation[..operationEnd];
        string target = mutation[(operationEnd + 1)..];
        int valueStart = target.IndexOf('=', StringComparison.Ordinal);
        string path = valueStart < 0 ? target : target[..valueStart];
        JsonNode? value = valueStart < 0 ? null : JsonNode.Parse(target[(valueStart + 1)..]);
        int memberStart = path.IndexOf('.', StringComparison.Ordinal);
        string member = memberStart < 0 ? path : path[(memberStart + 1)..];
        JsonObject parent = memberStart < 0 ? document : NestedMap(document, path[..memberStart]);

        Action apply = operation switch
        {
            "delete" => () => parent.Remove(member),
            "set" => () => parent[member] = value,
            "setArray" => () => parent[member] = new JsonArray(value),
            _ => throw new ArgumentOutOfRangeException(nameof(mutation), mutation, "Unknown mutation.")
        };
        apply();

        return document.ToJsonString();
    }


    /// <summary>
    /// The nested map <see cref="MutateSecuredDocumentJson"/> changes for a <c>parent.member</c> path: the first
    /// proof for <c>proof</c>, the existing map for any other parent, or a new empty map replacing a parent that
    /// is not a map.
    /// </summary>
    /// <param name="document">The document being changed.</param>
    /// <param name="parentName">The top-level member holding the nested map.</param>
    /// <returns>The map to change.</returns>
    private static JsonObject NestedMap(JsonObject document, string parentName) => (parentName, document[parentName]) switch
    {
        ("proof", _) => FirstProof(document),
        (_, JsonObject existing) => existing,
        _ => (document[parentName] = new JsonObject()).AsObject()
    };


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
            GenerateSelectiveDisclosureHmacKey,
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


    /// <summary>
    /// Signs <paramref name="unsignedCredentialJson"/> with an ecdsa-sd-2023 base proof (P-256) under the purpose
    /// <paramref name="purposeMethod"/> names, one no verification relationship models, so the proof's signature is valid
    /// over proof options that carry that purpose.
    /// </summary>
    /// <remarks>
    /// The library's base-proof creation takes no purpose: it signs every base proof for <c>assertionMethod</c>. This
    /// overload keeps what that creation prepares independently of the purpose, the per-statement signatures under the
    /// proof-scoped key, the HMAC key and the mandatory hash, and signs the base signature itself over the sign data
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#serializesigndata">VC-DI-ECDSA §3.5.1 serializeSignData</see>
    /// defines, "the concatenation of proofHash, publicKey, and mandatoryHash, in that order", for the proof options of
    /// <see cref="CreatePurposeBoundProofSkeleton"/>. The proof reads back from JSON as a verifier receives it.
    /// </remarks>
    /// <param name="unsignedCredentialJson">The unsigned credential JSON text.</param>
    /// <param name="proofCreated">The proof's <c>created</c> timestamp.</param>
    /// <param name="purposeMethod">The verification method reference carrying the purpose the proof is signed under.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The base-proofed credential, the issuer's public key (caller disposes), and the issuer's DID document.</returns>
    public static async ValueTask<(DataIntegritySecuredCredential Signed, PublicKeyMemory IssuerPublicKey, DidDocument Issuer)> CreateEcdsaSdBaseProofAsync(
        string unsignedCredentialJson, DateTime proofCreated, UnknownPurposeMethod purposeMethod, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(purposeMethod);

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(unsignedCredentialJson, JsonOptions)!;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        var ephemeralPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PrivateKeyMemory issuerPrivateKey = issuerPair.PrivateKey;
        using PrivateKeyMemory ephemeralPrivateKey = ephemeralPair.PrivateKey;
        using PublicKeyMemory ephemeralPublicKey = ephemeralPair.PublicKey;

        using BaseProofResult prepared = await CreateEcdsaSdBaseProofVerboseAsync(
            credential, issuerPrivateKey, ephemeralPair, purposeMethod.Id!, proofCreated, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        DataIntegrityProof proof = CreatePurposeBoundProofSkeleton(EcdsaSd2023CryptosuiteInfo.Instance, proofCreated, purposeMethod);
        using DigestValue proofHash = await HashProofOptionsAsync(proof, credential, cancellationToken).ConfigureAwait(false);

        int publicKeyLength = prepared.EphemeralPublicKeyWithHeader.Memory.Length;
        int signDataLength = proofHash.Length + publicKeyLength + prepared.MandatoryHash.Length;
        using System.Buffers.IMemoryOwner<byte> signData = BaseMemoryPool.Shared.Rent(signDataLength);
        proofHash.AsReadOnlySpan().CopyTo(signData.Memory.Span);
        prepared.EphemeralPublicKeyWithHeader.Memory.Span.CopyTo(signData.Memory.Span[proofHash.Length..]);
        prepared.MandatoryHash.CopyTo(signData.Memory.Span[(proofHash.Length + publicKeyLength)..]);

        using Signature baseSignature = await issuerPrivateKey.SignAsync(signData.Memory[..signDataLength], BaseMemoryPool.Shared).ConfigureAwait(false);

        //A re-signing that did not cover these sign data would leave a proof that fails its signature check, and a test
        //that expects the purpose to be refused would stay green for the wrong reason: the fixture fails here instead.
        bool isBaseSignatureValid = await issuerPair.PublicKey.VerifyAsync(
            signData.Memory[..signDataLength], baseSignature, MicrosoftCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        Assert.IsTrue(isBaseSignatureValid, "The base signature re-signed over the purpose-bound sign data must verify under the issuer's key.");

        proof.ProofValue = EcdsaSd2023CborSerializer.SerializeBaseProof(
            baseSignature.AsReadOnlySpan(),
            prepared.EphemeralPublicKeyWithHeader.Memory.Span,
            prepared.HmacKey,
            [.. prepared.SignedStatements.Select(static statement => statement.Signature.AsReadOnlySpan().ToArray())],
            SelectiveDisclosureMandatoryPointers,
            TestSetup.Base64UrlEncoder);

        var issuerDidDocument = CreateSelectiveDisclosureIssuerDidDocument(
            issuerPair.PublicKey.AsReadOnlySpan(), MulticodecHeaders.P256PublicKey, purposeMethod.Id!);

        return (AttachProof(credential, proof), issuerPair.PublicKey, issuerDidDocument);
    }


    /// <summary>
    /// Runs the library's verbose ecdsa-sd-2023 base proof creation over <paramref name="credential"/> with the fixture's
    /// mandatory paths, HMAC key source, RDFC-1.0 canonicalizer and serializers, renting from <paramref name="pool"/>, so a
    /// test reaches every intermediate the creation prepares and every buffer it rents.
    /// </summary>
    /// <param name="credential">The unsigned credential.</param>
    /// <param name="issuerPrivateKey">The issuer's P-256 private key the base signature is made with.</param>
    /// <param name="ephemeralPair">The proof-scoped P-256 key pair the disclosable statements are signed with.</param>
    /// <param name="verificationMethodId">The issuer's verification method the proof names.</param>
    /// <param name="proofCreated">The proof's <c>created</c> timestamp.</param>
    /// <param name="pool">The pool the creation rents its buffers from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The creation's intermediate state; the caller disposes it.</returns>
    public static ValueTask<BaseProofResult> CreateEcdsaSdBaseProofVerboseAsync(
        VerifiableCredential credential,
        PrivateKeyMemory issuerPrivateKey,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralPair,
        string verificationMethodId,
        DateTime proofCreated,
        BaseMemoryPool pool,
        CancellationToken cancellationToken) =>
        credential.CreateBaseProofVerboseAsync(
            issuerPrivateKey,
            ephemeralPair,
            verificationMethodId,
            proofCreated,
            SelectiveDisclosureMandatoryPaths,
            GenerateSelectiveDisclosureHmacKey,
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            pool,
            EmptyContext,
            cancellationToken);


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
            GenerateSelectiveDisclosureHmacKey,
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


    /// <summary>
    /// Signs <paramref name="unsignedCredentialJson"/> with a bbs-2023 base proof, using <paramref name="bbs"/>'s key pair,
    /// under the purpose <paramref name="purposeMethod"/> names, one no verification relationship models, so the proof's
    /// signature is valid over proof options that carry that purpose.
    /// </summary>
    /// <remarks>
    /// The library's base-proof creation takes no purpose: it signs every base proof for <c>assertionMethod</c>. This
    /// overload keeps what that creation prepares independently of the purpose, the non-mandatory statements that become
    /// the BBS messages, the HMAC key and the mandatory hash, and signs the messages itself under the header
    /// <see href="https://www.w3.org/TR/vc-di-bbs/#base-proof-serialization-bbs-2023">VC-DI-BBS §3.3.2 Base Proof
    /// Serialization</see> defines, "the concatenation of proofHash and mandatoryHash in that order", for the proof
    /// options of <see cref="CreatePurposeBoundProofSkeleton"/>. The proof reads back from JSON as a verifier receives it.
    /// </remarks>
    /// <param name="bbs">The BBS operations bound to a freshly generated BLS12-381 key pair.</param>
    /// <param name="unsignedCredentialJson">The unsigned credential JSON text.</param>
    /// <param name="proofCreated">The proof's <c>created</c> timestamp.</param>
    /// <param name="purposeMethod">The verification method reference carrying the purpose the proof is signed under.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The base-proofed credential and the issuer's DID document.</returns>
    public static async ValueTask<(DataIntegritySecuredCredential Signed, DidDocument Issuer)> CreateBbsBaseProofAsync(
        Verifiable.Tests.DataIntegrity.Bbs2023ResolvingBindingTests.ResolvingBbsOperations bbs,
        string unsignedCredentialJson,
        DateTime proofCreated,
        UnknownPurposeMethod purposeMethod,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(bbs);
        ArgumentNullException.ThrowIfNull(purposeMethod);

        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(unsignedCredentialJson, JsonOptions)!;

        using BbsBaseProofResult prepared = await credential.CreateBaseProofVerboseAsync(
            bbs.PublicKeyBytes,
            purposeMethod.Id!,
            proofCreated,
            SelectiveDisclosureMandatoryPaths,
            GenerateSelectiveDisclosureHmacKey,
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

        DataIntegrityProof proof = CreatePurposeBoundProofSkeleton(Bbs2023CryptosuiteInfo.Instance, proofCreated, purposeMethod);
        using DigestValue proofHash = await HashProofOptionsAsync(proof, credential, cancellationToken).ConfigureAwait(false);

        int bbsHeaderLength = proofHash.Length + prepared.MandatoryHash.Length;
        using System.Buffers.IMemoryOwner<byte> bbsHeader = BaseMemoryPool.Shared.Rent(bbsHeaderLength);
        proofHash.AsReadOnlySpan().CopyTo(bbsHeader.Memory.Span);
        prepared.MandatoryHash.CopyTo(bbsHeader.Memory.Span[proofHash.Length..]);

        byte[][] messages = [.. prepared.NonMandatoryStatements.Select(static statement => Encoding.UTF8.GetBytes(statement))];
        byte[] bbsSignature = bbs.Sign(bbsHeader.Memory[..bbsHeaderLength], messages, BaseMemoryPool.Shared);

        //A re-signing that did not cover this header and these messages would leave a proof that fails its signature
        //check, and a test that expects the purpose to be refused would stay green for the wrong reason: the fixture
        //fails here instead.
        Assert.IsTrue(bbs.Verify(bbsSignature, bbsHeader.Memory[..bbsHeaderLength], messages, BaseMemoryPool.Shared),
            "The BBS signature re-signed under the purpose-bound header must verify under the issuer's key.");

        proof.ProofValue = Bbs2023CborSerializer.SerializeBaseProof(
            bbsSignature,
            bbsHeader.Memory.Span[..bbsHeaderLength],
            bbs.PublicKeyBytes,
            prepared.HmacKey,
            SelectiveDisclosureMandatoryPointers,
            TestSetup.Base64UrlEncoder);

        var issuerDidDocument = CreateSelectiveDisclosureIssuerDidDocument(
            bbs.PublicKeyBytes, MulticodecHeaders.Bls12381G2PublicKey, purposeMethod.Id!);

        return (AttachProof(credential, proof), issuerDidDocument);
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


    /// <summary>
    /// The mandatory pointers a selective-disclosure base proof value carries: <see cref="SelectiveDisclosureMandatoryPaths"/>
    /// as JSON Pointer strings, the form both base proof serializations take them in.
    /// </summary>
    private static IReadOnlyList<string> SelectiveDisclosureMandatoryPointers =>
        [.. SelectiveDisclosureMandatoryPaths.Select(static path => path.ToJsonPointerString())];

    /// <summary>
    /// The length, in bytes, of the proof hash a selective-disclosure base signature covers: a SHA-256 digest, the hash
    /// both the ecdsa-sd-2023 and the bbs-2023 cryptosuites of these tests use.
    /// </summary>
    private static int ProofHashByteLength => 32;


    /// <summary>
    /// The proof a selective-disclosure base proof signed under <paramref name="purposeMethod"/>'s purpose carries, its
    /// proof value aside: every member the base signature covers, with <paramref name="purposeMethod"/> as the
    /// verification method and its purpose as <c>proofPurpose</c>, as the JSON proof reader reads such a proof back.
    /// </summary>
    /// <param name="cryptosuite">The selective-disclosure cryptosuite the proof names.</param>
    /// <param name="proofCreated">The proof's <c>created</c> timestamp.</param>
    /// <param name="purposeMethod">The verification method reference carrying the purpose.</param>
    /// <returns>The proof without its <c>proofValue</c>.</returns>
    private static DataIntegrityProof CreatePurposeBoundProofSkeleton(CryptosuiteInfo cryptosuite, DateTime proofCreated, UnknownPurposeMethod purposeMethod) => new()
    {
        Type = DataIntegrityProof.DataIntegrityProofType,
        Cryptosuite = cryptosuite,
        Created = DateTimeStampFormat.Format(proofCreated),
        VerificationMethod = purposeMethod,
        ProofPurpose = purposeMethod.PurposeName
    };


    /// <summary>
    /// The proof hash of <paramref name="proof"/>: the SHA-256 digest of the RDFC-1.0 canonical form of the proof options
    /// <see cref="ProofOptionsDocument.FromProof"/> derives from <paramref name="proof"/> and <paramref name="credential"/>'s
    /// <c>@context</c>, the same options a verifier derives from the proof it receives.
    /// </summary>
    /// <param name="proof">The proof skeleton the options derive from.</param>
    /// <param name="credential">The credential whose <c>@context</c> the options carry.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The proof hash; the caller disposes it.</returns>
    private static async ValueTask<DigestValue> HashProofOptionsAsync(
        DataIntegrityProof proof, VerifiableCredential credential, CancellationToken cancellationToken)
    {
        string proofOptionsJson = SerializeProofOptions(ProofOptionsDocument.FromProof(proof, credential.Context));
        CanonicalizationResult canonical = await RdfcCanonicalizer(proofOptionsJson, ContextResolver, EmptyContext, cancellationToken)
            .ConfigureAwait(false);

        int canonicalByteCount = Encoding.UTF8.GetByteCount(canonical.CanonicalForm);
        using System.Buffers.IMemoryOwner<byte> canonicalBytes = BaseMemoryPool.Shared.Rent(canonicalByteCount);
        int written = Encoding.UTF8.GetBytes(canonical.CanonicalForm, canonicalBytes.Memory.Span);

        return CryptographicKeyEvents.ComputeDigest(
            canonicalBytes.Memory.Span[..written], ProofHashByteLength, CryptoTags.Sha256Digest, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Secures <paramref name="credential"/> with <paramref name="proof"/> as its one proof, read from JSON as a verifier
    /// receives a secured credential, so the proof's members read back exactly as the JSON proof reader reads them.
    /// </summary>
    /// <param name="credential">The unsigned credential.</param>
    /// <param name="proof">The complete proof.</param>
    /// <returns>The secured credential.</returns>
    private static DataIntegritySecuredCredential AttachProof(VerifiableCredential credential, DataIntegrityProof proof)
    {
        JsonObject document = JsonNode.Parse(SerializeCredential(credential))!.AsObject();
        document["proof"] = JsonNode.Parse(JsonSerializerExtensions.Serialize(proof, JsonOptions));

        return (DataIntegritySecuredCredential)DeserializeCredential(document.ToJsonString());
    }
}

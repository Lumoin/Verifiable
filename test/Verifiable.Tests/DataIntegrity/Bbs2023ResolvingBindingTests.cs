using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core.Algebraic;
using System.Buffers;
using System.Security.Cryptography;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Tests for the RESOLVING <c>VerifyBaseProofAsync(DidDocument, ...)</c>/<c>VerifyDerivedProofAsync(DidDocument, ...)</c>
/// overloads on bbs-2023 (<see cref="CredentialBbs2023Extensions"/>). Each folds into the SAME
/// controller-resolution gate the embedded-proof Data Integrity credential path uses
/// (<c>SelectiveDisclosureIdentityBinding</c> -&gt; <see cref="BoundProvenance.TryBindByControllerArtifact"/>):
/// proof-purpose check, <c>assertionMethod</c>-relationship-scoped resolution, the cryptographic
/// check against the resolved key, and controller-RESOLUTION, ALL before minting
/// <see cref="Verified{T}.IsIdentityBound"/> <see langword="true"/>. The BLS12-381 algebraic
/// operations are supplied by Lumoin.Veridical.Bbs and Lumoin.Veridical.Backends.Managed, with a
/// freshly-generated real key pair per test (<see cref="ResolvingBbsOperations.Generate"/>).
/// </summary>
[TestClass]
internal sealed class Bbs2023ResolvingBindingTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string IssuerDid = "did:example:bbs-issuer";
    private const string SignerKeyId = "did:example:bbs-issuer#key-1";

    private static DateTime ProofCreated { get; } = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static byte[] PresentationHeader { get; } = [0x01, 0x02, 0x03, 0x04];

    //Canonicalization/signing here is in-memory; a default context yields the
    //secure-default SSRF policy and satisfies the policy-carrying parameter.
    private static ExchangeContext EmptyContext { get; } = [];

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } = CanonicalizationTestUtilities.CreateTestContextResolver();

    private static Context KnownContext { get; } = Context.FromIris(Context.Credentials20, Context.CredentialsExamples20);

    private static IReadOnlyList<CredentialPath> MandatoryPaths { get; } =
    [
        CredentialPath.FromJsonPointer("/issuer")
    ];

    private const string CredentialJson = /*lang=json,strict*/ """
    {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "http://university.example/credentials/9822",
        "type": ["VerifiableCredential", "ExampleDegreeCredential"],
        "issuer": "did:example:bbs-issuer",
        "validFrom": "2024-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:subject",
            "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
            }
        }
    }
    """;


    /// <summary>
    /// Positive Bound mint (base proof) plus the witness-tie half: the resolving overload mints
    /// <see cref="BoundProvenance"/> (<see cref="ResolutionSource.CallerControllerArtifact"/>,
    /// <see cref="VerificationRelationship.AssertionMethod"/>) over a genuinely issuer-signed base
    /// proof, and the SAME <see cref="BoundProvenance"/> refuses to mint over a DIFFERENT credential
    /// instance via <see cref="Verified{T}.TryCreateBound"/>.
    /// </summary>
    [TestMethod]
    public async Task ResolvingBaseProofMintsBoundOnGenuineSignatureAndWitnessRefusesADifferentCredential()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        var signedCredential = await SignBaseAsync(bbs, cancellationToken).ConfigureAwait(false);
        var issuerDidDocument = CreateIssuerDidDocument(bbs.PublicKeyBytes);

        var result = await VerifyBaseResolvingAsync(signedCredential, issuerDidDocument, bbs, cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The resolving overload must verify a genuinely issuer-signed base proof.");
        Assert.IsNotNull(result.Verified);
        var verified = result.Verified.Value;
        Assert.IsTrue(verified.IsIdentityBound, "The resolving overload must mint Bound, not Asserted.");
        Assert.IsTrue(verified.Provenance is BoundProvenance);
        var bound = (BoundProvenance)verified.Provenance;
        Assert.AreEqual(ResolutionSource.CallerControllerArtifact, bound.Source);
        Assert.AreEqual(VerificationRelationship.AssertionMethod, bound.Relationship);
        Assert.AreEqual(SignerKeyId, bound.Identity?.Value);

        //Witness tie: the SAME BoundProvenance refuses to mint over a DIFFERENT credential instance.
        var otherSigned = await SignBaseAsync(bbs, cancellationToken).ConfigureAwait(false);
        Verified<DataIntegritySecuredCredential>? witnessMismatch = Verified<DataIntegritySecuredCredential>.TryCreateBound(otherSigned, bound);
        Assert.IsNull(witnessMismatch, "A BoundProvenance established for one credential instance must refuse to mint over a different instance.");
    }


    /// <summary>
    /// Controller-RESOLUTION semantics: a resolved method whose own <c>controller</c> does
    /// NOT equal the credential's <c>issuer</c> is refused, even though the signature, proof purpose,
    /// and <c>assertionMethod</c> scoping all otherwise hold.
    /// </summary>
    [TestMethod]
    public async Task BaseProofIssuerControllerMismatchIsRefused()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        var signedCredential = await SignBaseAsync(bbs, cancellationToken).ConfigureAwait(false);

        //The resolved method's own controller is deliberately NOT the credential's issuer.
        var mismatchedDidDocument = CreateIssuerDidDocument(bbs.PublicKeyBytes, controller: "did:example:someone-else-entirely");

        var result = await VerifyBaseResolvingAsync(signedCredential, mismatchedDidDocument, bbs, cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.ControllerMismatch, result.FailureReason);
        Assert.IsNull(result.Verified);
    }


    /// <summary>
    /// Data Integrity 1.0 §4.2: a proof whose declared <c>proofPurpose</c> is not <c>assertionMethod</c>
    /// is refused before any resolution or cryptographic work, even for an otherwise genuine signature.
    /// </summary>
    [TestMethod]
    public async Task BaseProofWrongProofPurposeIsRefused()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        var signedCredential = await SignBaseAsync(bbs, cancellationToken).ConfigureAwait(false);

        //Forge the purpose: the same key, the same signature, but a proof minted for authentication
        //rather than assertionMethod.
        signedCredential.Proof![0].ProofPurpose = AuthenticationMethod.Purpose;

        var issuerDidDocument = CreateIssuerDidDocument(bbs.PublicKeyBytes);
        var result = await VerifyBaseResolvingAsync(signedCredential, issuerDidDocument, bbs, cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.ProofPurposeMismatch, result.FailureReason);
    }


    /// <summary>The BYOK base-proof overload's behavior is unchanged: it mints Asserted, never Bound.</summary>
    [TestMethod]
    public async Task ByokBaseProofOverloadStillMintsAssertedNotBound()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        var signedCredential = await SignBaseAsync(bbs, cancellationToken).ConfigureAwait(false);

        var result = await signedCredential.VerifyBaseProofAsync(
            bbs.Verify,
            Bbs2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            KnownContext,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.Verified);
        Assert.IsFalse(result.Verified.Value.IsIdentityBound, "The BYOK overload must mint Asserted, never Bound.");
        Assert.IsTrue(result.Verified.Value.Provenance is AssertedProvenance);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-bbs/#base-proof-transformation-bbs-2023">W3C VC Data
    /// Integrity BBS Cryptosuites v1.0 §3.2.2 transformation</see>: createVerifyData canonicalizes the
    /// credential before the mandatory hash and the BBS message vector are computed from it. A
    /// credential with no resolvable JSON-LD context canonicalizes to zero statements, so both would be
    /// computed over nothing; the issuer must refuse to mint a base proof over such a credential rather
    /// than sign a proof that would later verify trivially.
    /// </summary>
    [TestMethod]
    public async Task BaseProofCreationRefusesAContextlessCredential()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await SignBaseAsync(bbs, "{}", mandatoryPaths: [], cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-bbs/#verify-base-proof-bbs-2023">W3C VC Data Integrity BBS
    /// Cryptosuites v1.0 §3.2.4 verifyBaseProof</see>: the mandatory hash and the BBS message vector
    /// createVerifyData builds from the credential are what the base signature is checked against. A
    /// credential that canonicalizes to zero statements would have both computed over nothing, and a
    /// BBS signature verification over an empty message list verifies as valid regardless of what the
    /// credential displays; that case is refused before the cryptographic call.
    /// </summary>
    [TestMethod]
    public async Task BaseProofVerificationRefusesAProofThatCoversNoStatements()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        //CreateBaseProofAsync now refuses to mint a base proof over a context-less credential
        //(BaseProofCreationRefusesAContextlessCredential), so this proof cannot be produced through
        //that path any more. It is hand-built here the same way BuildVacuousDerivedCredential builds a
        //vacuous derived proof: the same real BBS signing call, over the same empty header and empty
        //message vector an unguarded issuer implementation would have produced.
        var credential = await BuildVacuousBaseProofCredentialAsync(bbs, cancellationToken).ConfigureAwait(false);

        var result = await credential.VerifyBaseProofAsync(
            bbs.Verify,
            Bbs2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            KnownContext,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A base proof that canonicalizes to no statements covers nothing and must be refused.");
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason);
    }


    /// <summary>
    /// Positive Bound mint (derived proof): a derived proof's <c>verificationMethod</c> is the same
    /// issuer method the base proof carried, so the resolving derived overload runs the same
    /// resolve-and-bind recipe and mints Bound.
    /// </summary>
    [TestMethod]
    public async Task ResolvingDerivedProofMintsBoundOnGenuineSignature()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        var signedCredential = await SignBaseAsync(bbs, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, bbs, cancellationToken).ConfigureAwait(false);
        var issuerDidDocument = CreateIssuerDidDocument(bbs.PublicKeyBytes);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            issuerDidDocument,
            bbs.ProofVerifyFactory,
            Bbs2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            KnownContext,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "The resolving overload must verify a genuinely issuer-signed derived proof.");
        Assert.IsNotNull(result.Verified);
        var verified = result.Verified.Value;
        Assert.IsTrue(verified.IsIdentityBound, "The resolving overload must mint Bound, not Asserted.");
        Assert.IsTrue(verified.Provenance is BoundProvenance);
        var bound = (BoundProvenance)verified.Provenance;
        Assert.AreEqual(ResolutionSource.CallerControllerArtifact, bound.Source);
        Assert.AreEqual(VerificationRelationship.AssertionMethod, bound.Relationship);
        Assert.AreEqual(SignerKeyId, bound.Identity?.Value);
    }


    /// <summary>On the derived-proof resolving overload: a resolved-method controller mismatch is refused.</summary>
    [TestMethod]
    public async Task DerivedProofIssuerControllerMismatchIsRefused()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        var signedCredential = await SignBaseAsync(bbs, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, bbs, cancellationToken).ConfigureAwait(false);

        var mismatchedDidDocument = CreateIssuerDidDocument(bbs.PublicKeyBytes, controller: "did:example:someone-else-entirely");

        var result = await derivedCredential.VerifyDerivedProofAsync(
            mismatchedDidDocument,
            bbs.ProofVerifyFactory,
            Bbs2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            KnownContext,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.ControllerMismatch, result.FailureReason);
        Assert.IsNull(result.Verified);
    }


    /// <summary>The BYOK derived-proof overload's behavior is unchanged: it mints Asserted, never Bound.</summary>
    [TestMethod]
    public async Task ByokDerivedProofOverloadStillMintsAssertedNotBound()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        var signedCredential = await SignBaseAsync(bbs, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, bbs, cancellationToken).ConfigureAwait(false);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            bbs.ProofVerify,
            Bbs2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            KnownContext,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.Verified);
        Assert.IsFalse(result.Verified.Value.IsIdentityBound, "The BYOK overload must mint Asserted, never Bound.");
        Assert.IsTrue(result.Verified.Value.Provenance is AssertedProvenance);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-bbs/#verify-derived-proof-bbs-2023">W3C VC Data Integrity
    /// BBS Cryptosuites v1.0 §3.3.8 verifyDerivedProof</see>: createVerifyData canonicalizes the reveal
    /// document before the mandatory hash and the BBS message list are computed. With no JSON-LD context
    /// no property key resolves to an absolute IRI, so canonicalization yields zero statements; a proof
    /// computed over zero statements proves nothing about any claim and must be refused rather than
    /// accepted because the BBS check happens to pass over an empty message list.
    /// </summary>
    [TestMethod]
    public async Task DerivedProofVerificationRefusesACredentialWithNoContext()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        //The base-proofed credential is "{}": no @context, no claims, nothing mandatory. Its BBS
        //signature covers zero messages, so a hand-built derived proof over zero messages and zero
        //disclosed indexes is internally consistent with it -- this reproduces a derived credential
        //arriving at a verifier with its JSON-LD context already lost. Built through
        //BuildVacuousBaseProofCredentialAsync because CreateBaseProofAsync now refuses to mint a base
        //proof over "{}" (BaseProofCreationRefusesAContextlessCredential), and then through
        //BuildVacuousDerivedCredential because DeriveProofAsync now refuses to derive from it too
        //(DeriveRefusesACredentialWhoseRevealDocumentCanonicalizesToNothing) -- neither guard can
        //intercept a proof hand-built the way an unguarded implementation would have produced it.
        var signedCredential = await BuildVacuousBaseProofCredentialAsync(bbs, cancellationToken).ConfigureAwait(false);
        var derivedCredential = BuildVacuousDerivedCredential(signedCredential, bbs);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            bbs.ProofVerify,
            Bbs2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            KnownContext,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A derived proof over a credential with no @context canonicalizes to zero statements and must be refused.");
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-bbs/#verify-derived-proof-bbs-2023">W3C VC Data Integrity
    /// BBS Cryptosuites v1.0 §3.3.8 verifyDerivedProof</see>: a derived proof that discloses no
    /// non-mandatory statement is not thereby vacuous when its mandatory statements are non-empty -- the
    /// mandatory hash still binds real content into the header, and the BBS proof is still a genuine
    /// proof of possession of the issuer's signature over it. A holder who reveals only the mandatory
    /// content, selectively disclosing nothing further, presents a proof that verifies.
    /// </summary>
    [TestMethod]
    public async Task DerivedProofVerificationVerifiesDisclosureOfMandatoryContentOnly()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        //Nothing beyond the mandatory /issuer pointer is requested, so every reveal statement is
        //mandatory and the BBS message vector this proof discloses is empty. The reveal document itself
        //is non-empty (id, type, issuer): the mandatory hash binds real content, so this is a genuine,
        //legitimate presentation rather than the jointly-empty case the previous test refuses.
        var signedCredential = await SignBaseAsync(bbs, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, bbs, new HashSet<CredentialPath>(), cancellationToken).ConfigureAwait(false);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            bbs.ProofVerify,
            Bbs2023CborSerializer.ParseDerivedProof,
            RdfcCanonicalizer,
            ContextResolver,
            KnownContext,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A derived proof disclosing only mandatory content binds real content through the header and must verify.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-bbs/#createdisclosuredata">W3C VC Data Integrity BBS
    /// Cryptosuites v1.0 §3.3.3 createDisclosureData</see>: the reveal document createDisclosureData
    /// builds from the disclosed pointers is what verifyDerivedProof will later canonicalize. When the
    /// mandatory and selectively-requested pointers are both empty and the credential carries no root
    /// "id" or "type" to fall back on, the reveal document canonicalizes to zero statements; deriving a
    /// proof over it would only ever verify trivially, so derive refuses to mint one. The base proof is
    /// built through BuildVacuousBaseProofCredentialAsync because CreateBaseProofAsync itself now
    /// refuses to mint a base proof over the same "{}" credential
    /// (BaseProofCreationRefusesAContextlessCredential): "type" is required for any VCDM 2.0 term to
    /// resolve at all, and selectJsonLd copies "type" into every reveal unconditionally, so a real,
    /// issuer-signed credential with disclosable content never reaches an empty reveal -- only a
    /// credential that was already vacuous at issuance does, which is what this base proof reproduces.
    /// </summary>
    [TestMethod]
    public async Task DeriveRefusesACredentialWhoseRevealDocumentCanonicalizesToNothing()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = ResolvingBbsOperations.Generate();

        var signedCredential = await BuildVacuousBaseProofCredentialAsync(bbs, cancellationToken).ConfigureAwait(false);

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await DeriveAsync(signedCredential, bbs, new HashSet<CredentialPath>(), cancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    private static Task<DataIntegritySecuredCredential> SignBaseAsync(ResolvingBbsOperations bbs, CancellationToken cancellationToken) =>
        SignBaseAsync(bbs, CredentialJson, MandatoryPaths, cancellationToken);


    private static async Task<DataIntegritySecuredCredential> SignBaseAsync(
        ResolvingBbsOperations bbs,
        string credentialJson,
        IReadOnlyList<CredentialPath> mandatoryPaths,
        CancellationToken cancellationToken)
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(credentialJson, TestSetup.DefaultSerializationOptions)!;

        return await credential.CreateBaseProofAsync(
            bbs.PublicKeyBytes,
            SignerKeyId,
            ProofCreated,
            mandatoryPaths,
            () => RandomNumberGenerator.GetBytes(32),
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.DeserializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            Bbs2023CborSerializer.SerializeBaseProof,
            bbs.Sign,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);
    }


    private static Task<DataIntegritySecuredCredential> DeriveAsync(
        DataIntegritySecuredCredential signedCredential,
        ResolvingBbsOperations bbs,
        CancellationToken cancellationToken) =>
        DeriveAsync(
            signedCredential,
            bbs,
            new HashSet<CredentialPath> { CredentialPath.FromJsonPointer("/credentialSubject/degree/name") },
            cancellationToken);


    private static Task<DataIntegritySecuredCredential> DeriveAsync(
        DataIntegritySecuredCredential signedCredential,
        ResolvingBbsOperations bbs,
        IReadOnlySet<CredentialPath> verifierRequestedPaths,
        CancellationToken cancellationToken)
    {
        return signedCredential.DeriveProofAsync(
            verifierRequestedPaths,
            userExclusions: null,
            PresentationHeader,
            JsonLdSelection.PartitionStatements,
            JsonLdSelection.SelectFragments,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.DeserializeCredential,
            Bbs2023CborSerializer.ParseBaseProof,
            Bbs2023CborSerializer.SerializeDerivedProof,
            bbs.ProofGen,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).AsTask();
    }


    //Hand-builds a derived proof over zero BBS messages and zero disclosed indexes directly from a base
    //proof that itself covers zero messages, bypassing DeriveProofAsync so the derive-side refusal this
    //task adds cannot intercept it. The result is what a verifier would receive from a derived credential
    //whose JSON-LD context was already lost -- exactly the wire shape DerivedProofVerificationRefusesACredentialWithNoContext
    //exercises against the verify-side refusal.
    private static DataIntegritySecuredCredential BuildVacuousDerivedCredential(
        DataIntegritySecuredCredential signedCredential,
        ResolvingBbsOperations bbs)
    {
        var proof = signedCredential.Proof![0];
        using var parsedBaseProof = Bbs2023CborSerializer.ParseBaseProof(proof.ProofValue!, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        var bbsProofBytes = bbs.ProofGen(
            parsedBaseProof.BbsSignature,
            parsedBaseProof.BbsHeader,
            PresentationHeader,
            messages: [],
            disclosedIndexes: [],
            BaseMemoryPool.Shared);

        var derivedProofValue = Bbs2023CborSerializer.SerializeDerivedProof(
            bbsProofBytes,
            new Dictionary<string, string>(),
            [],
            [],
            PresentationHeader,
            TestSetup.Base64UrlEncoder);

        var derivedProof = new DataIntegrityProof
        {
            Id = proof.Id,
            Type = proof.Type,
            Cryptosuite = proof.Cryptosuite,
            Created = proof.Created,
            VerificationMethod = proof.VerificationMethod,
            ProofPurpose = proof.ProofPurpose,
            ProofValue = derivedProofValue
        };

        return new DataIntegritySecuredCredential
        {
            Proof = [derivedProof]
        };
    }


    //Hand-builds a base proof over a "{}" credential (no @context, no claims) directly, bypassing
    //CreateBaseProofAsync so the creation-side refusal this task adds cannot intercept it. Replicates
    //the pre-guard CreateBaseProofVerboseAsync computation: the mandatory hash and the BBS message
    //vector are both computed over nothing, using the same real BBS signing call. The result is what
    //an unguarded issuer implementation would have put on the wire.
    private static async Task<DataIntegritySecuredCredential> BuildVacuousBaseProofCredentialAsync(
        ResolvingBbsOperations bbs,
        CancellationToken cancellationToken)
    {
        var proofSkeleton = new DataIntegrityProof
        {
            Type = CredentialConstants.DataIntegrityProofType,
            Cryptosuite = Bbs2023CryptosuiteInfo.Instance,
            Created = DateTimeStampFormat.Format(ProofCreated),
            VerificationMethod = new AssertionMethod(SignerKeyId),
            ProofPurpose = AssertionMethod.Purpose
        };

        var proofOptions = ProofOptionsDocument.FromProof(proofSkeleton, context: null);
        var proofOptionsJson = CanonicalizationTestUtilities.SerializeProofOptions(proofOptions);
        var proofOptionsCanonicalization = await RdfcCanonicalizer(proofOptionsJson, ContextResolver, EmptyContext, cancellationToken).ConfigureAwait(false);

        using DigestValue mandatoryHash = await CryptographicKeyEvents.ComputeDigestAsync(
            ReadOnlySequence<byte>.Empty,
            outputByteLength: 32,
            tag: CryptoTags.Sha256Digest,
            pool: BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using DigestValue proofHash = await CryptographicKeyEvents.ComputeDigestAsync(
            System.Text.Encoding.UTF8.GetBytes(proofOptionsCanonicalization.CanonicalForm),
            outputByteLength: 32,
            tag: CryptoTags.Sha256Digest,
            pool: BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        var bbsHeaderBytes = new byte[proofHash.Length + mandatoryHash.Length];
        proofHash.AsReadOnlySpan().CopyTo(bbsHeaderBytes);
        mandatoryHash.AsReadOnlySpan().CopyTo(bbsHeaderBytes.AsSpan(proofHash.Length));

        var bbsSignature = bbs.Sign(bbsHeaderBytes, messages: [], BaseMemoryPool.Shared);

        var proofValue = Bbs2023CborSerializer.SerializeBaseProof(
            bbsSignature,
            bbsHeaderBytes,
            bbs.PublicKeyBytes,
            hmacKey: RandomNumberGenerator.GetBytes(32),
            mandatoryPointers: [],
            TestSetup.Base64UrlEncoder);

        var baseProof = new DataIntegrityProof
        {
            Type = proofSkeleton.Type,
            Cryptosuite = proofSkeleton.Cryptosuite,
            Created = proofSkeleton.Created,
            VerificationMethod = proofSkeleton.VerificationMethod,
            ProofPurpose = proofSkeleton.ProofPurpose,
            ProofValue = proofValue
        };

        return new DataIntegritySecuredCredential
        {
            Proof = [baseProof]
        };
    }


    private static ValueTask<CredentialVerificationResult<DataIntegritySecuredCredential>> VerifyBaseResolvingAsync(
        DataIntegritySecuredCredential credential,
        DidDocument issuerDidDocument,
        ResolvingBbsOperations bbs,
        CancellationToken cancellationToken) =>
        credential.VerifyBaseProofAsync(
            issuerDidDocument,
            bbs.VerifyFactory,
            Bbs2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            KnownContext,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken);


    //Controller-RESOLUTION semantics: the resolved method's own controller, which the caller
    //may point at any DID -- not necessarily documentDid -- so the mismatch tests can name a
    //controller distinct from both the credential's issuer and the resolved document's own id.
    private static DidDocument CreateIssuerDidDocument(
        byte[] issuerPublicKeyBytes,
        string verificationMethodId = SignerKeyId,
        string documentDid = IssuerDid,
        string? controller = null)
    {
        string publicKeyMultibase = MultibaseSerializer.Encode(
            issuerPublicKeyBytes,
            MulticodecHeaders.Bls12381G2PublicKey,
            MultibaseAlgorithms.Base58Btc,
            TestSetup.Base58Encoder,
            BaseMemoryPool.Shared);

        return new DidDocument
        {
            Id = new GenericDidMethod(documentDid),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = verificationMethodId,
                    Type = "Multikey",
                    Controller = controller ?? documentDid,
                    KeyFormat = new PublicKeyMultibase(publicKeyMultibase)
                }
            ],
            AssertionMethod = [new AssertionMethod(verificationMethodId)]
        };
    }


    /// <summary>
    /// Generates a real BLS12-381 key pair (<see cref="BbsKeyGenerationExtensions.Generate"/>) and
    /// binds BBS Sign/ProofGen (issuer/holder side, bound to THIS instance's key) plus
    /// resolved-key Verify/ProofVerify factories (verifier side, shaped as
    /// <see cref="BbsVerifySignatureFactoryDelegate"/>/<see cref="BbsProofVerifyFactoryDelegate"/>) to
    /// the Lumoin.Veridical BBS primitive. The factories build a FRESH <see cref="BbsPublicKey"/> from
    /// whatever bytes the resolving overload hands them -- the DID document's resolved key, not
    /// necessarily this instance's own key -- so a substituted DID document key genuinely fails
    /// verification rather than trivially matching a pre-bound key. Mirrors the structure of
    /// <see cref="Bbs2023W3cVectorTests.BbsOperations"/> (spec-vector fixed keys) but for a freshly
    /// generated key pair and resolved-key verification.
    /// </summary>
    internal sealed class ResolvingBbsOperations: IDisposable
    {
        private static BbsCiphersuite Ciphersuite { get; } = BbsCiphersuite.Bls12Curve381Sha256;

        //BBS secret keys, signatures, and proofs request AllocationKind.Native. The shared pool disallows
        //native degradation, so a dedicated pool that degrades Native to Pinned backs the BBS value types.
        private BaseMemoryPool KeyPool { get; }
        private ScalarArithmeticBackend ScalarBackend { get; }
        private G1ArithmeticBackend G1Backend { get; }
        private G2ArithmeticBackend G2Backend { get; }
        private PairingBackend PairingBackend { get; }
        private ScalarHashToScalarDelegate HashToScalar { get; }
        private G1HashToCurveDelegate HashToCurve { get; }
        private BbsSecretKey SecretKey { get; }
        private BbsPublicKey PublicKey { get; }

        private ResolvingBbsOperations(
            BaseMemoryPool keyPool,
            ScalarArithmeticBackend scalarBackend,
            G1ArithmeticBackend g1Backend,
            G2ArithmeticBackend g2Backend,
            PairingBackend pairingBackend,
            ScalarHashToScalarDelegate hashToScalar,
            G1HashToCurveDelegate hashToCurve,
            BbsSecretKey secretKey,
            BbsPublicKey publicKey)
        {
            this.KeyPool = keyPool;
            this.ScalarBackend = scalarBackend;
            this.G1Backend = g1Backend;
            this.G2Backend = g2Backend;
            this.PairingBackend = pairingBackend;
            this.HashToScalar = hashToScalar;
            this.HashToCurve = hashToCurve;
            this.SecretKey = secretKey;
            this.PublicKey = publicKey;
        }


        public static ResolvingBbsOperations Generate()
        {
            var keyPool = new BaseMemoryPool(allowNativeDegradation: true);
            var scalarBackend = Bls12Curve381ManagedScalarBackend.Create();
            var g1Backend = Bls12Curve381ManagedG1Backend.Create();
            var g2Backend = Bls12Curve381ManagedG2Backend.Create();
            var pairingBackend = Bls12Curve381ManagedPairingBackend.Create();
            var hashToScalar = Bls12Curve381ManagedScalarBackend.GetHashToScalarSha256();
            var hashToCurve = Bls12Curve381ManagedG1Backend.GetHashToCurveSha256();

            byte[] keyMaterial = RandomNumberGenerator.GetBytes(32);
            var keyPair = BbsKeyGenerationExtensions.Generate(
                Ciphersuite,
                keyMaterial,
                ReadOnlySpan<byte>.Empty,
                hashToScalar,
                g2Backend.ScalarMultiply,
                keyPool);

            return new ResolvingBbsOperations(
                keyPool, scalarBackend, g1Backend, g2Backend, pairingBackend, hashToScalar, hashToCurve,
                keyPair.SecretKey, keyPair.PublicKey);
        }


        public byte[] PublicKeyBytes => PublicKey.AsReadOnlySpan().ToArray();


        public byte[] Sign(ReadOnlyMemory<byte> bbsHeader, IReadOnlyList<byte[]> messages, BaseMemoryPool pool)
        {
            var header = new BbsHeader(bbsHeader);
            var bbsMessages = ToBbsMessages(messages);

            using var signature = BbsSigningExtensions.Sign(
                SecretKey,
                PublicKey,
                header,
                bbsMessages,
                Rfc9380ExpandMessage.ExpandMessageXmdSha256,
                HashToScalar,
                ScalarBackend.Add,
                ScalarBackend.Invert,
                G1Backend.Add,
                G1Backend.ScalarMultiply,
                G1Backend.MultiScalarMultiply,
                HashToCurve,
                KeyPool);

            return signature.AsReadOnlySpan().ToArray();
        }


        //Bound BYOK-shaped delegate: verifies against THIS instance's own key (the pre-bound key a
        //caller who fetched/pinned the key out of band would close over).
        public bool Verify(ReadOnlyMemory<byte> bbsSignature, ReadOnlyMemory<byte> bbsHeader, IReadOnlyList<byte[]> messages, BaseMemoryPool pool)
        {
            var header = new BbsHeader(bbsHeader);
            var bbsMessages = ToBbsMessages(messages);
            using var signature = BbsSignature.FromCanonical(bbsSignature.Span, Ciphersuite, KeyPool, BbsSignature.GetAlgebraicTag(Ciphersuite));

            return VerifyAgainst(PublicKey, signature, header, bbsMessages);
        }


        //RESOLVING factory: builds a fresh BbsPublicKey from the RESOLVED bytes the caller hands in
        //(the resolving overload's issuerPublicKey.AsReadOnlyMemory()), never the pre-bound publicKey
        //field, so a substituted DID document key genuinely fails verification.
        public BbsVerifySignatureDelegate VerifyFactory(ReadOnlyMemory<byte> issuerPublicKey)
        {
            return (bbsSignature, bbsHeader, messages, pool) =>
            {
                using var resolvedPublicKey = BbsPublicKey.FromCanonical(issuerPublicKey.Span, Ciphersuite, KeyPool, BbsPublicKey.GetAlgebraicTag(Ciphersuite));
                var header = new BbsHeader(bbsHeader);
                var bbsMessages = ToBbsMessages(messages);
                using var signature = BbsSignature.FromCanonical(bbsSignature.Span, Ciphersuite, KeyPool, BbsSignature.GetAlgebraicTag(Ciphersuite));

                return VerifyAgainst(resolvedPublicKey, signature, header, bbsMessages);
            };
        }


        public byte[] ProofGen(
            ReadOnlyMemory<byte> bbsSignature,
            ReadOnlyMemory<byte> bbsHeader,
            ReadOnlyMemory<byte> presentationHeader,
            IReadOnlyList<byte[]> messages,
            IReadOnlyList<int> disclosedIndexes,
            BaseMemoryPool pool)
        {
            var header = new BbsHeader(bbsHeader);
            var ph = new BbsPresentationHeader(presentationHeader);
            var bbsMessages = ToBbsMessages(messages);

            using var signature = BbsSignature.FromCanonical(bbsSignature.Span, Ciphersuite, KeyPool, BbsSignature.GetAlgebraicTag(Ciphersuite));

            using var proof = BbsProofGenerationExtensions.GenerateProof(
                signature,
                PublicKey,
                header,
                ph,
                bbsMessages,
                disclosedIndexes.ToArray(),
                Rfc9380ExpandMessage.ExpandMessageXmdSha256,
                HashToScalar,
                ScalarBackend.Add,
                ScalarBackend.Subtract,
                ScalarBackend.Multiply,
                ScalarBackend.Negate,
                ScalarBackend.Invert,
                ScalarBackend.Random,
                G1Backend.Add,
                G1Backend.ScalarMultiply,
                G1Backend.MultiScalarMultiply,
                HashToCurve,
                G1Backend.IsOnCurve!,
                G1Backend.IsInPrimeOrderSubgroup!,
                KeyPool);

            return proof.AsReadOnlySpan().ToArray();
        }


        //Bound BYOK-shaped delegate: verifies against THIS instance's own key.
        public bool ProofVerify(
            ReadOnlyMemory<byte> bbsProof,
            ReadOnlyMemory<byte> bbsHeader,
            ReadOnlyMemory<byte> presentationHeader,
            IReadOnlyList<byte[]> disclosedMessages,
            IReadOnlyList<int> disclosedIndexes,
            BaseMemoryPool pool)
        {
            using var proof = BbsProof.FromCanonical(bbsProof.Span, Ciphersuite, KeyPool, BbsProof.GetAlgebraicTag(Ciphersuite));

            return ProofVerifyAgainst(PublicKey, proof, bbsHeader, presentationHeader, disclosedMessages, disclosedIndexes);
        }


        //RESOLVING factory: builds a fresh BbsPublicKey from the RESOLVED bytes the caller hands in.
        public BbsProofVerifyDelegate ProofVerifyFactory(ReadOnlyMemory<byte> issuerPublicKey)
        {
            return (bbsProof, bbsHeader, presentationHeader, disclosedMessages, disclosedIndexes, pool) =>
            {
                using var resolvedPublicKey = BbsPublicKey.FromCanonical(issuerPublicKey.Span, Ciphersuite, KeyPool, BbsPublicKey.GetAlgebraicTag(Ciphersuite));
                using var proof = BbsProof.FromCanonical(bbsProof.Span, Ciphersuite, KeyPool, BbsProof.GetAlgebraicTag(Ciphersuite));

                return ProofVerifyAgainst(resolvedPublicKey, proof, bbsHeader, presentationHeader, disclosedMessages, disclosedIndexes);
            };
        }


        private bool VerifyAgainst(BbsPublicKey key, BbsSignature signature, BbsHeader header, ReadOnlyMemory<BbsMessage> bbsMessages)
        {
            return BbsVerificationExtensions.Verify(
                key,
                signature,
                header,
                bbsMessages,
                Rfc9380ExpandMessage.ExpandMessageXmdSha256,
                HashToScalar,
                G1Backend.Add,
                G1Backend.MultiScalarMultiply,
                HashToCurve,
                G1Backend.IsOnCurve!,
                G1Backend.IsInPrimeOrderSubgroup!,
                G2Backend.Add,
                G2Backend.ScalarMultiply,
                G2Backend.IsOnCurve,
                G2Backend.IsInPrimeOrderSubgroup,
                PairingBackend.Pairing,
                KeyPool);
        }


        private bool ProofVerifyAgainst(
            BbsPublicKey key,
            BbsProof proof,
            ReadOnlyMemory<byte> bbsHeader,
            ReadOnlyMemory<byte> presentationHeader,
            IReadOnlyList<byte[]> disclosedMessages,
            IReadOnlyList<int> disclosedIndexes)
        {
            var header = new BbsHeader(bbsHeader);
            var ph = new BbsPresentationHeader(presentationHeader);
            var bbsMessages = ToBbsMessages(disclosedMessages);

            return BbsProofVerificationExtensions.VerifyProof(
                key,
                proof,
                header,
                ph,
                bbsMessages,
                disclosedIndexes.ToArray(),
                Rfc9380ExpandMessage.ExpandMessageXmdSha256,
                HashToScalar,
                G1Backend.Add,
                G1Backend.MultiScalarMultiply,
                HashToCurve,
                G1Backend.IsOnCurve!,
                G1Backend.IsInPrimeOrderSubgroup!,
                G2Backend.Add,
                G2Backend.ScalarMultiply,
                G2Backend.IsOnCurve,
                G2Backend.IsInPrimeOrderSubgroup,
                PairingBackend.Pairing,
                KeyPool);
        }


        private static ReadOnlyMemory<BbsMessage> ToBbsMessages(IReadOnlyList<byte[]> messages)
        {
            var bbsMessages = new BbsMessage[messages.Count];
            for(int i = 0; i < messages.Count; i++)
            {
                bbsMessages[i] = new BbsMessage(messages[i]);
            }

            return bbsMessages;
        }


        public void Dispose()
        {
            SecretKey.Dispose();
            PublicKey.Dispose();
            ScalarBackend.Dispose();
            G1Backend.Dispose();
            G2Backend.Dispose();
            PairingBackend.Dispose();
            KeyPool.Dispose();
        }
    }
}

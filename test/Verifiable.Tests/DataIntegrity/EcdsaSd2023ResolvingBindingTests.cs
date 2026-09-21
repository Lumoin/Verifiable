using System.Collections.Frozen;
using System.Security.Cryptography;
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
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Tests for the RESOLVING <c>VerifyBaseProofAsync(DidDocument, ...)</c>/<c>VerifyDerivedProofAsync(DidDocument, ...)</c>
/// overloads on ecdsa-sd-2023 (<see cref="CredentialEcdsaSd2023Extensions"/>). Each folds
/// into the SAME controller-resolution gate the embedded-proof Data Integrity credential path uses
/// (<c>SelectiveDisclosureIdentityBinding</c> -&gt; <see cref="BoundProvenance.TryBindByControllerArtifact"/>):
/// proof-purpose check, <c>assertionMethod</c>-relationship-scoped resolution, the cryptographic
/// check against the resolved key, and controller-RESOLUTION, ALL before minting
/// <see cref="Verified{T}.IsIdentityBound"/> <see langword="true"/>.
/// </summary>
[TestClass]
internal sealed class EcdsaSd2023ResolvingBindingTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string IssuerDid = "did:example:ecdsa-sd-issuer";
    private const string SignerKeyId = "did:example:ecdsa-sd-issuer#key-1";

    private static DateTime ProofCreated { get; } = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    //Canonicalization/signing here is in-memory; a default context yields the
    //secure-default SSRF policy and satisfies the policy-carrying parameter.
    private static ExchangeContext EmptyContext { get; } = [];

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } = CanonicalizationTestUtilities.CreateTestContextResolver();

    private static Context KnownContext { get; } = Context.FromIris(Context.Credentials20, Context.CredentialsExamples20);

    private static IReadOnlyList<CredentialPath> MandatoryPaths { get; } =
    [
        CredentialPath.FromJsonPointer("/issuer"),
        CredentialPath.FromJsonPointer("/type")
    ];

    private const string CredentialJson = /*lang=json,strict*/ """
    {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "http://university.example/credentials/9821",
        "type": ["VerifiableCredential", "ExampleDegreeCredential"],
        "issuer": "did:example:ecdsa-sd-issuer",
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
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var issuerDidDocument = CreateIssuerDidDocument(issuerPublicKey);

        var result = await VerifyBaseResolvingAsync(signedCredential, issuerDidDocument, cancellationToken).ConfigureAwait(false);

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
        var otherSigned = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
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
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);

        //The resolved method's own controller is deliberately NOT the credential's issuer.
        var mismatchedDidDocument = CreateIssuerDidDocument(issuerPublicKey, controller: "did:example:someone-else-entirely");

        var result = await VerifyBaseResolvingAsync(signedCredential, mismatchedDidDocument, cancellationToken).ConfigureAwait(false);

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
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);

        //Forge the purpose: the same key, the same signature, but a proof minted for authentication
        //rather than assertionMethod.
        signedCredential.Proof![0].ProofPurpose = AuthenticationMethod.Purpose;

        var issuerDidDocument = CreateIssuerDidDocument(issuerPublicKey);
        var result = await VerifyBaseResolvingAsync(signedCredential, issuerDidDocument, cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(VerificationFailureReason.ProofPurposeMismatch, result.FailureReason);
    }


    /// <summary>The BYOK base-proof overload's behavior is unchanged: it mints Asserted, never Bound.</summary>
    [TestMethod]
    public async Task ByokBaseProofOverloadStillMintsAssertedNotBound()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);

        var result = await signedCredential.VerifyBaseProofAsync(
            issuerPublicKey,
            BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
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
    /// Positive Bound mint (derived proof): a derived proof's <c>verificationMethod</c> is the same
    /// issuer method the base proof carried, so the resolving derived overload runs the same
    /// resolve-and-bind recipe and mints Bound.
    /// </summary>
    [TestMethod]
    public async Task ResolvingDerivedProofMintsBoundOnGenuineSignature()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, cancellationToken).ConfigureAwait(false);
        var issuerDidDocument = CreateIssuerDidDocument(issuerPublicKey);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            issuerDidDocument,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
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
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, cancellationToken).ConfigureAwait(false);

        var mismatchedDidDocument = CreateIssuerDidDocument(issuerPublicKey, controller: "did:example:someone-else-entirely");

        var result = await derivedCredential.VerifyDerivedProofAsync(
            mismatchedDidDocument,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
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
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, cancellationToken).ConfigureAwait(false);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            issuerPublicKey,
            BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
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
    /// A derived proof's per-statement signature list must contain exactly one signature for
    /// every disclosed (non-mandatory) statement: the base signature commits only to the
    /// mandatory hash, the proof options hash, and the ephemeral public key, never to disclosed
    /// statement content, per
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023">
    /// VC Data Integrity ECDSA Cryptosuites: Verify Derived Proof (ecdsa-sd-2023)</see>. A
    /// derived proof re-encoded with an EMPTY signature array - structurally valid, decodable,
    /// carrying the genuine base signature, key, label map and mandatory indexes - together with
    /// a tampered disclosed claim literal must be refused rather than accepted on the strength of
    /// the (unrelated) base signature alone.
    /// </summary>
    [TestMethod]
    public async Task DerivedProofWithEmptySignatureArrayAndTamperedDisclosedClaimIsRefused()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, cancellationToken).ConfigureAwait(false);

        //Tamper one disclosed claim's literal: the honestly-derived per-statement signatures,
        //had they been carried through, no longer cover the statement this literal now produces.
        var degree = (Dictionary<string, object>)derivedCredential.CredentialSubject![0].AdditionalData!["degree"];
        degree["name"] = "Tampered Degree Name";

        //Re-encode the derived proof value through the SAME serializer the parse side uses,
        //keeping the genuine base signature, ephemeral key, label map, and mandatory indexes,
        //but with an EMPTY per-statement signature array: the proof stays structurally valid
        //CBOR/multibase and only the signature-to-disclosure count is wrong.
        using var parsedDerivedProof = EcdsaSd2023CborSerializer.ParseDerivedProof(
            derivedCredential.Proof![0].ProofValue!,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared);

        using var ephemeralKeyWithHeader = MultibaseSerializer.PrependHeader(
            parsedDerivedProof.EphemeralPublicKey,
            BaseMemoryPool.Shared);

        derivedCredential.Proof[0].ProofValue = EcdsaSd2023CborSerializer.SerializeDerivedProof(
            parsedDerivedProof.BaseSignature.AsReadOnlySpan(),
            ephemeralKeyWithHeader.Memory.Span,
            [],
            parsedDerivedProof.LabelMap,
            parsedDerivedProof.MandatoryIndexes,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            issuerPublicKey,
            BouncyCastleCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
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

        Assert.IsFalse(result.IsValid, "A derived proof carrying no per-statement signatures for its disclosed statements must be refused, never accepted on the base signature alone.");
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason);
    }


    /// <summary>
    /// A derived proof's label map must cover every canonical blank node the verifier's own
    /// canonicalization of the reveal document produces, per
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023">
    /// VC Data Integrity ECDSA Cryptosuites: Verify Derived Proof (ecdsa-sd-2023)</see>. A
    /// reveal document with two anonymous objects carries two blank nodes; a derived proof
    /// re-encoded with a genuine base signature, key, and per-statement signatures but with
    /// only ONE of the two blank nodes' entries removed -- so the label map is non-empty, not
    /// entirely absent -- must still be refused rather than silently leaving that one blank node
    /// under its raw canonical label. The statement-signature checks are stubbed to always
    /// succeed so this test isolates the label map's own completeness gate from the (separate)
    /// per-statement signature checks that would otherwise also reject the tampered content.
    /// </summary>
    [TestMethod]
    public async Task DerivedProofWithOneOfTwoBlankNodeEntriesRemovedIsRefused()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignTwoAnonymousObjectsBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveBothAnonymousObjectsAsync(signedCredential, cancellationToken).ConfigureAwait(false);

        using var parsedDerivedProof = EcdsaSd2023CborSerializer.ParseDerivedProof(
            derivedCredential.Proof![0].ProofValue!,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared);

        Assert.HasCount(2, parsedDerivedProof.LabelMap, "The reveal document carries two blank nodes: the anonymous 'degree' and 'homeAddress' objects.");

        //Re-encode the derived proof value through the SAME serializer the parse side uses,
        //keeping the genuine base signature, ephemeral key, and per-statement signatures, but
        //with only ONE of the two blank nodes' entries removed from the label map.
        var removedKey = parsedDerivedProof.LabelMap.Keys.First();
        var mutatedLabelMap = parsedDerivedProof.LabelMap
            .Where(entry => entry.Key != removedKey)
            .ToDictionary(entry => entry.Key, entry => entry.Value);

        Assert.HasCount(1, mutatedLabelMap, "Only one of the two entries was removed; the map is not empty.");

        using var ephemeralKeyWithHeader = MultibaseSerializer.PrependHeader(
            parsedDerivedProof.EphemeralPublicKey,
            BaseMemoryPool.Shared);

        derivedCredential.Proof[0].ProofValue = EcdsaSd2023CborSerializer.SerializeDerivedProof(
            parsedDerivedProof.BaseSignature.AsReadOnlySpan(),
            ephemeralKeyWithHeader.Memory.Span,
            parsedDerivedProof.Signatures.Select(signature => signature.AsReadOnlySpan().ToArray()).ToList(),
            mutatedLabelMap,
            parsedDerivedProof.MandatoryIndexes,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            issuerPublicKey,
            AlwaysValidVerification,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
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

        Assert.IsFalse(result.IsValid, "A derived proof whose label map has no entry for a blank node present in the reveal document must be refused, even when another blank node's entry is present.");
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason);
    }


    /// <summary>
    /// Simulates the cross-engine case: two conformant implementations of
    /// <see href="https://www.w3.org/TR/rdf-canon/">RDF Dataset Canonicalization 1.0</see> can
    /// assign different canonical labels to the same graph, so a label map built by one and
    /// applied by the other carries keys that do not match the verifier's own canonical labels.
    /// A derived proof re-encoded with its sole blank node's label map key changed to a
    /// different canonical label -- simulating that condition without running a second engine,
    /// since this single-blank-node reveal document is deterministically labeled "c14n0" by this
    /// library's own canonicalization -- must be refused rather than silently verified, per
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023">
    /// VC Data Integrity ECDSA Cryptosuites: Verify Derived Proof (ecdsa-sd-2023)</see>. The
    /// statement-signature checks are stubbed to always succeed so this test isolates the label
    /// map's own completeness gate from the (separate) per-statement signature checks that would
    /// otherwise also reject the tampered content.
    /// </summary>
    [TestMethod]
    public async Task DerivedProofWithLabelMapKeyedToADifferentCanonicalLabelIsRefused()
    {
        var cancellationToken = TestContext.CancellationToken;
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var issuerPublicKey = issuerPair.PublicKey;
        using var issuerPrivateKey = issuerPair.PrivateKey;

        var signedCredential = await SignBaseAsync(issuerPrivateKey, cancellationToken).ConfigureAwait(false);
        var derivedCredential = await DeriveAsync(signedCredential, cancellationToken).ConfigureAwait(false);

        using var parsedDerivedProof = EcdsaSd2023CborSerializer.ParseDerivedProof(
            derivedCredential.Proof![0].ProofValue!,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared);

        Assert.HasCount(1, parsedDerivedProof.LabelMap, "The reveal document carries exactly one blank node: the anonymous 'degree' object.");
        var (originalKey, hmacValue) = parsedDerivedProof.LabelMap.Single();

        //Rekey the sole entry to a canonical label distinct from the one this library's own
        //canonicalization assigns to this graph's only blank node, standing in for a second
        //RDFC-1.0 implementation that assigned the same blank node a different label.
        var crossEngineLabelMap = new Dictionary<string, string> { [originalKey + "9"] = hmacValue };

        using var ephemeralKeyWithHeader = MultibaseSerializer.PrependHeader(
            parsedDerivedProof.EphemeralPublicKey,
            BaseMemoryPool.Shared);

        derivedCredential.Proof[0].ProofValue = EcdsaSd2023CborSerializer.SerializeDerivedProof(
            parsedDerivedProof.BaseSignature.AsReadOnlySpan(),
            ephemeralKeyWithHeader.Memory.Span,
            parsedDerivedProof.Signatures.Select(signature => signature.AsReadOnlySpan().ToArray()).ToList(),
            crossEngineLabelMap,
            parsedDerivedProof.MandatoryIndexes,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared);

        var result = await derivedCredential.VerifyDerivedProofAsync(
            issuerPublicKey,
            AlwaysValidVerification,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
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

        Assert.IsFalse(result.IsValid, "A derived proof whose label map keys do not match the verifier's own canonical labels must be refused.");
        Assert.AreEqual(VerificationFailureReason.SignatureInvalid, result.FailureReason);
    }


    /// <summary>
    /// A <see cref="VerificationDelegate"/> stub that always reports a valid signature, used to
    /// isolate the label map completeness gate in
    /// <see cref="CredentialEcdsaSd2023Extensions.extension(DataIntegritySecuredCredential).VerifyDerivedProofVerboseAsync(PublicKeyMemory, VerificationDelegate, ParseDerivedProofDelegate, CanonicalizationDelegate, ContextResolverDelegate?, CredentialSerializeDelegate, ProofOptionsSerializeDelegate, EncodeDelegate, DecodeDelegate, BaseMemoryPool, ExchangeContext, CancellationToken)"/>
    /// from the statement-signature checks that follow it.
    /// </summary>
    private static ValueTask<(bool IsVerified, CryptoEvent? Event)> AlwaysValidVerification(
        ReadOnlyMemory<byte> dataToVerify,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> publicKeyMaterial,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<(bool IsVerified, CryptoEvent? Event)>((true, null));


    private const string TwoAnonymousObjectsCredentialJson = /*lang=json,strict*/ """
    {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "http://university.example/credentials/9822",
        "type": ["VerifiableCredential", "ExampleDegreeCredential"],
        "issuer": "did:example:ecdsa-sd-issuer",
        "validFrom": "2024-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:subject",
            "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
            },
            "homeAddress": {
                "type": "ExampleAddress",
                "streetAddress": "1 Example Street"
            }
        }
    }
    """;


    private static async Task<DataIntegritySecuredCredential> SignTwoAnonymousObjectsBaseAsync(PrivateKeyMemory issuerPrivateKey, CancellationToken cancellationToken)
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(TwoAnonymousObjectsCredentialJson, TestSetup.DefaultSerializationOptions)!;
        var ephemeralPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var ephemeralPublicKey = ephemeralPair.PublicKey;
        using var ephemeralPrivateKey = ephemeralPair.PrivateKey;

        return await credential.CreateBaseProofAsync(
            issuerPrivateKey,
            ephemeralPair,
            SignerKeyId,
            ProofCreated,
            MandatoryPaths,
            () => RandomNumberGenerator.GetBytes(32),
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.DeserializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);
    }


    private static Task<DataIntegritySecuredCredential> DeriveBothAnonymousObjectsAsync(DataIntegritySecuredCredential signedCredential, CancellationToken cancellationToken)
    {
        var verifierRequestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/degree/name"),
            CredentialPath.FromJsonPointer("/credentialSubject/homeAddress/streetAddress")
        };

        return signedCredential.DeriveProofAsync(
            verifierRequestedPaths,
            userExclusions: null,
            JsonLdSelection.PartitionStatements,
            JsonLdSelection.SelectFragments,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.DeserializeCredential,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            EcdsaSd2023CborSerializer.SerializeDerivedProof,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).AsTask();
    }


    private static async Task<DataIntegritySecuredCredential> SignBaseAsync(PrivateKeyMemory issuerPrivateKey, CancellationToken cancellationToken)
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(CredentialJson, TestSetup.DefaultSerializationOptions)!;
        var ephemeralPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using var ephemeralPublicKey = ephemeralPair.PublicKey;
        using var ephemeralPrivateKey = ephemeralPair.PrivateKey;

        return await credential.CreateBaseProofAsync(
            issuerPrivateKey,
            ephemeralPair,
            SignerKeyId,
            ProofCreated,
            MandatoryPaths,
            () => RandomNumberGenerator.GetBytes(32),
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.DeserializeCredential,
            CanonicalizationTestUtilities.SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).ConfigureAwait(false);
    }


    private static Task<DataIntegritySecuredCredential> DeriveAsync(DataIntegritySecuredCredential signedCredential, CancellationToken cancellationToken)
    {
        var verifierRequestedPaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/degree/name")
        };

        return signedCredential.DeriveProofAsync(
            verifierRequestedPaths,
            userExclusions: null,
            JsonLdSelection.PartitionStatements,
            JsonLdSelection.SelectFragments,
            RdfcCanonicalizer,
            ContextResolver,
            CanonicalizationTestUtilities.SerializeCredential,
            CanonicalizationTestUtilities.DeserializeCredential,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            EcdsaSd2023CborSerializer.SerializeDerivedProof,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            EmptyContext,
            cancellationToken).AsTask();
    }


    private static ValueTask<CredentialVerificationResult<DataIntegritySecuredCredential>> VerifyBaseResolvingAsync(
        DataIntegritySecuredCredential credential,
        DidDocument issuerDidDocument,
        CancellationToken cancellationToken) =>
        credential.VerifyBaseProofAsync(
            issuerDidDocument,
            EcdsaSd2023CborSerializer.ParseBaseProof,
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
        PublicKeyMemory issuerPublicKey,
        string verificationMethodId = SignerKeyId,
        string documentDid = IssuerDid,
        string? controller = null)
    {
        string publicKeyMultibase = MultibaseSerializer.Encode(
            issuerPublicKey.AsReadOnlySpan(),
            MulticodecHeaders.P256PublicKey,
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
}

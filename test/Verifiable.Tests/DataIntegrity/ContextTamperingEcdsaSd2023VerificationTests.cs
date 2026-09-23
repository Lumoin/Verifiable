using System.Text.Json.Nodes;
using Verifiable.Cbor;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Presents the ecdsa-sd-2023 base-proof and derived-proof verifiers
/// (<see cref="CredentialEcdsaSd2023Extensions"/>) with a credential whose <c>@context</c> was
/// altered after signing (for the derived proof: after derivation), for each of the alteration
/// shapes named by <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC
/// Data Integrity 1.0 §2.4.1 Validating Contexts</see> and
/// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context
/// Validation</see>. A variant whose tampering changes the credential's RDF canonical form is
/// refused by the proof check first, before the context check ever runs; every other variant
/// leaves the canonical form unchanged and is refused by the context check.
/// </summary>
[TestClass]
internal sealed class ContextTamperingEcdsaSd2023VerificationTests
{
    /// <summary>The MSTest context of the running test; its cancellation token bounds every verification in this class.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The instant written into every base proof's <c>created</c> member.</summary>
    private static DateTime ProofCreated { get; } = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>The <c>id</c> of the credential every test of this class signs.</summary>
    private const string BaseCredentialId = "urn:uuid:9d3f9b2a-6b7e-4e6a-8f0a-ecdsa-sd-context";


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">Data Integrity §2.4.1 Validating
    /// Contexts</see>: "Applications MUST use the algorithm in Section 4.6 Context Validation, or one that achieves
    /// equivalent protections, to validate contexts in a conforming secured document." An ecdsa-sd-2023 base proof over a
    /// credential whose <c>@context</c> was altered after signing is refused for the reason the alteration produces.
    /// </summary>
    /// <param name="variantName">The name of the alteration.</param>
    /// <param name="tamperedContextJson">The altered <c>@context</c>.</param>
    /// <param name="expectedReason">The reason the alteration is refused for.</param>
    [TestMethod]
    [DataRow("ExtraUnknownContext", DataIntegrityContextTamperingFixture.TamperedContextExtraUnknownUrl, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("ExtraKnownContext", DataIntegrityContextTamperingFixture.TamperedContextExtraKnownUrl, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("SubstitutedKnownContext", DataIntegrityContextTamperingFixture.TamperedContextSubstitutedKnownUrl, VerificationFailureReason.SignatureInvalid)]
    [DataRow("ReorderedContext", DataIntegrityContextTamperingFixture.TamperedContextReordered, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("DuplicatedContext", DataIntegrityContextTamperingFixture.TamperedContextDuplicated, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("InlineRedefinesUsedTerm", DataIntegrityContextTamperingFixture.TamperedContextInlineRedefinesUsedTerm, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("InlineDefinesUnusedTerm", DataIntegrityContextTamperingFixture.TamperedContextInlineDefinesUnusedTerm, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("NonBaseFirstContext", DataIntegrityContextTamperingFixture.TamperedContextNonBaseFirst, VerificationFailureReason.ContextValidationFailed)]
    public async Task BaseProofRefusesTamperedContext(string variantName, string tamperedContextJson, VerificationFailureReason expectedReason)
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, issuer) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        var tampered = DataIntegrityContextTamperingFixture.ReserializeWithTamperedContext(signed, JsonNode.Parse(tamperedContextJson)!);

        var result = await tampered.VerifyBaseProofAsync(
            issuer,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, $"ecdsa-sd-2023 base proof: variant '{variantName}' must be refused (VC Data Integrity 1.0 §2.4.1/§4.6).");
        Assert.AreEqual(expectedReason, result.FailureReason, $"ecdsa-sd-2023 base proof: variant '{variantName}' must be refused for the specific reason it actually produces.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">Data Integrity §2.4.1 Validating
    /// Contexts</see>: "Applications MUST use the algorithm in Section 4.6 Context Validation, or one that achieves
    /// equivalent protections, to validate contexts in a conforming secured document." An ecdsa-sd-2023 derived proof over
    /// a credential whose <c>@context</c> was altered after derivation is refused for the reason the alteration produces.
    /// </summary>
    /// <param name="variantName">The name of the alteration.</param>
    /// <param name="tamperedContextJson">The altered <c>@context</c>.</param>
    /// <param name="expectedReason">The reason the alteration is refused for.</param>
    [TestMethod]
    [DataRow("ExtraUnknownContext", DataIntegrityContextTamperingFixture.TamperedContextExtraUnknownUrl, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("ExtraKnownContext", DataIntegrityContextTamperingFixture.TamperedContextExtraKnownUrl, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("SubstitutedKnownContext", DataIntegrityContextTamperingFixture.TamperedContextSubstitutedKnownUrl, VerificationFailureReason.SignatureInvalid)]
    [DataRow("ReorderedContext", DataIntegrityContextTamperingFixture.TamperedContextReordered, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("DuplicatedContext", DataIntegrityContextTamperingFixture.TamperedContextDuplicated, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("InlineRedefinesUsedTerm", DataIntegrityContextTamperingFixture.TamperedContextInlineRedefinesUsedTerm, VerificationFailureReason.SignatureInvalid)]
    [DataRow("InlineDefinesUnusedTerm", DataIntegrityContextTamperingFixture.TamperedContextInlineDefinesUnusedTerm, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("NonBaseFirstContext", DataIntegrityContextTamperingFixture.TamperedContextNonBaseFirst, VerificationFailureReason.ContextValidationFailed)]
    public async Task DerivedProofRefusesTamperedContext(string variantName, string tamperedContextJson, VerificationFailureReason expectedReason)
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, issuer) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        var derived = await DataIntegrityContextTamperingFixture.DeriveEcdsaSdProofAsync(signed, cancellationToken).ConfigureAwait(false);
        var tampered = DataIntegrityContextTamperingFixture.ReserializeWithTamperedContext(derived, JsonNode.Parse(tamperedContextJson)!);

        var result = await tampered.VerifyDerivedProofAsync(
            issuer,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, $"ecdsa-sd-2023 derived proof: variant '{variantName}' must be refused (VC Data Integrity 1.0 §2.4.1/§4.6).");
        Assert.AreEqual(expectedReason, result.FailureReason, $"ecdsa-sd-2023 derived proof: variant '{variantName}' must be refused for the specific reason it actually produces.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">Data Integrity §2.4.1 Validating
    /// Contexts</see>: "Context validation MUST be run after running the applicable algorithm in either Section 4.4
    /// Verify Proof or Section 4.5 Verify Proof Sets and Chains." An untampered ecdsa-sd-2023 base proof, checked against
    /// its own <c>@context</c>, passes both and verifies.
    /// </summary>
    [TestMethod]
    public async Task BaseProofWithOwnUntamperedContextVerifiesAsValid()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, issuer) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        var result = await signed.VerifyBaseProofAsync(
            issuer,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "An untampered ecdsa-sd-2023 base proof, checked against its own @context, must verify as valid.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">Data Integrity §2.4.1 Validating
    /// Contexts</see>: "Context validation MUST be run after running the applicable algorithm in either Section 4.4
    /// Verify Proof or Section 4.5 Verify Proof Sets and Chains." An untampered ecdsa-sd-2023 derived proof, checked
    /// against its own <c>@context</c>, passes both and verifies.
    /// </summary>
    [TestMethod]
    public async Task DerivedProofWithOwnUntamperedContextVerifiesAsValid()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, issuer) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        var derived = await DataIntegrityContextTamperingFixture.DeriveEcdsaSdProofAsync(signed, cancellationToken).ConfigureAwait(false);

        var result = await derived.VerifyDerivedProofAsync(
            issuer,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "An untampered ecdsa-sd-2023 derived proof, checked against its own @context, must verify as valid.");
    }

    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// if one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist,
    /// an error MUST be raised and SHOULD convey PROOF_VERIFICATION_ERROR.
    /// </summary>
    /// <remarks>
    /// Proves the Core verification path directly, in-process; the wire proof of this rule is the VCALM
    /// verifier's real-wire test over <see cref="Verifiable.Vcalm.VcalmVerificationService"/>.
    /// </remarks>
    [TestMethod]
    public async Task EcdsaSdBaseProofWithoutTypeIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, issuer) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        signed.Proof![0].Type = null!;

        var result = await signed.VerifyBaseProofAsync(
            issuerPublicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Data Integrity §4.4: a proof without type MUST be refused.");
        Assert.AreEqual(VerificationFailureReason.MissingVerificationMethod, result.FailureReason,
            "Missing mandatory proof options share the existing verification failure result.");
    }

    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// if one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist,
    /// an error MUST be raised and SHOULD convey PROOF_VERIFICATION_ERROR.
    /// </summary>
    /// <remarks>
    /// Proves the Core verification path directly, in-process; the wire proof of this rule is the VCALM
    /// verifier's real-wire test over <see cref="Verifiable.Vcalm.VcalmVerificationService"/>.
    /// </remarks>
    [TestMethod]
    public async Task EcdsaSdDerivedProofWithoutTypeIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, issuer) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        var derived = await DataIntegrityContextTamperingFixture.DeriveEcdsaSdProofAsync(signed, cancellationToken).ConfigureAwait(false);

        derived.Proof![0].Type = null!;

        var result = await derived.VerifyDerivedProofAsync(
            issuerPublicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Data Integrity §4.4: a proof without type MUST be refused.");
        Assert.AreEqual(VerificationFailureReason.MissingVerificationMethod, result.FailureReason,
            "Missing mandatory proof options share the existing verification failure result.");
    }

    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// if one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist,
    /// an error MUST be raised and SHOULD convey PROOF_VERIFICATION_ERROR — exercised here for a
    /// missing verificationMethod, exactly as <see cref="EcdsaSdBaseProofWithoutTypeIsRejected"/>
    /// exercises a missing type.
    /// </summary>
    /// <remarks>
    /// Proves the Core verification path directly, in-process; the wire proof of this rule is the VCALM
    /// verifier's real-wire test over <see cref="Verifiable.Vcalm.VcalmVerificationService"/>.
    /// </remarks>
    [TestMethod]
    public async Task EcdsaSdBaseProofWithoutVerificationMethodIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, issuer) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        signed.Proof![0].VerificationMethod = null;

        var result = await signed.VerifyBaseProofAsync(
            issuerPublicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Data Integrity §4.4: a proof without verificationMethod MUST be refused.");
        Assert.AreEqual(VerificationFailureReason.MissingVerificationMethod, result.FailureReason,
            "Missing mandatory proof options share the existing verification failure result.");
    }

    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// if one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist,
    /// an error MUST be raised and SHOULD convey PROOF_VERIFICATION_ERROR — exercised here for a
    /// missing proofPurpose.
    /// </summary>
    /// <remarks>
    /// Proves the Core verification path directly, in-process; the wire proof of this rule is the VCALM
    /// verifier's real-wire test over <see cref="Verifiable.Vcalm.VcalmVerificationService"/>.
    /// </remarks>
    [TestMethod]
    public async Task EcdsaSdBaseProofWithoutProofPurposeIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, issuer) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        signed.Proof![0].ProofPurpose = null;

        var result = await signed.VerifyBaseProofAsync(
            issuerPublicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Data Integrity §4.4: a proof without proofPurpose MUST be refused.");
        Assert.AreEqual(VerificationFailureReason.MissingVerificationMethod, result.FailureReason,
            "Missing mandatory proof options share the existing verification failure result.");
    }

    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// if one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist,
    /// an error MUST be raised and SHOULD convey PROOF_VERIFICATION_ERROR — exercised here for a
    /// missing verificationMethod on the derived proof.
    /// </summary>
    /// <remarks>
    /// Proves the Core verification path directly, in-process; the wire proof of this rule is the VCALM
    /// verifier's real-wire test over <see cref="Verifiable.Vcalm.VcalmVerificationService"/>.
    /// </remarks>
    [TestMethod]
    public async Task EcdsaSdDerivedProofWithoutVerificationMethodIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, issuer) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        var derived = await DataIntegrityContextTamperingFixture.DeriveEcdsaSdProofAsync(signed, cancellationToken).ConfigureAwait(false);

        derived.Proof![0].VerificationMethod = null;

        var result = await derived.VerifyDerivedProofAsync(
            issuerPublicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Data Integrity §4.4: a proof without verificationMethod MUST be refused.");
        Assert.AreEqual(VerificationFailureReason.MissingVerificationMethod, result.FailureReason,
            "Missing mandatory proof options share the existing verification failure result.");
    }

    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// if one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist,
    /// an error MUST be raised and SHOULD convey PROOF_VERIFICATION_ERROR — exercised here for a
    /// missing proofPurpose on the derived proof.
    /// </summary>
    /// <remarks>
    /// Proves the Core verification path directly, in-process; the wire proof of this rule is the VCALM
    /// verifier's real-wire test over <see cref="Verifiable.Vcalm.VcalmVerificationService"/>.
    /// </remarks>
    [TestMethod]
    public async Task EcdsaSdDerivedProofWithoutProofPurposeIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, issuer) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        var derived = await DataIntegrityContextTamperingFixture.DeriveEcdsaSdProofAsync(signed, cancellationToken).ConfigureAwait(false);

        derived.Proof![0].ProofPurpose = null;

        var result = await derived.VerifyDerivedProofAsync(
            issuerPublicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Data Integrity §4.4: a proof without proofPurpose MUST be refused.");
        Assert.AreEqual(VerificationFailureReason.MissingVerificationMethod, result.FailureReason,
            "Missing mandatory proof options share the existing verification failure result.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>: "If
    /// expectedProofPurpose was given, and it does not match proof.proofPurpose, an error MUST be raised and SHOULD convey
    /// an error type of PROOF_VERIFICATION_ERROR." A credential proof's expected purpose is <c>assertionMethod</c>, so the
    /// ecdsa-sd-2023 base proof verifier that takes the issuer's key from its caller refuses a proof declaring the purpose
    /// <c>x</c>, one no verification relationship models, before it verifies anything.
    /// </summary>
    [TestMethod]
    public async Task EcdsaSdBaseProofWithUnexpectedPurposeIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, _) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        DataIntegrityContextTamperingFixture.DeclareUnmodelledPurpose(signed.Proof![0], "x");

        var (result, context) = await signed.VerifyBaseProofVerboseAsync(
            issuerPublicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);
        context?.Dispose();

        Assert.IsFalse(result.IsValid, "Data Integrity §4.4: a proof whose purpose is not the expected one MUST be refused.");
        Assert.AreEqual(VerificationFailureReason.ProofPurposeMismatch, result.FailureReason,
            "The proof is refused for its purpose, whichever key the caller supplied.");
        Assert.IsNull(context, "A refused proof yields no verification state.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>: "If
    /// expectedProofPurpose was given, and it does not match proof.proofPurpose, an error MUST be raised and SHOULD convey
    /// an error type of PROOF_VERIFICATION_ERROR." A derived proof keeps its base proof's <c>assertionMethod</c> purpose,
    /// so the ecdsa-sd-2023 derived proof verifier that takes the issuer's key from its caller refuses a derived proof
    /// declaring the purpose <c>x</c>, one no verification relationship models, before it verifies anything.
    /// </summary>
    [TestMethod]
    public async Task EcdsaSdDerivedProofWithUnexpectedPurposeIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, _) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        var derived = await DataIntegrityContextTamperingFixture.DeriveEcdsaSdProofAsync(signed, cancellationToken).ConfigureAwait(false);

        DataIntegrityContextTamperingFixture.DeclareUnmodelledPurpose(derived.Proof![0], "x");

        var (result, context) = await derived.VerifyDerivedProofVerboseAsync(
            issuerPublicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken).ConfigureAwait(false);
        context?.Dispose();

        Assert.IsFalse(result.IsValid, "Data Integrity §4.4: a proof whose purpose is not the expected one MUST be refused.");
        Assert.AreEqual(VerificationFailureReason.ProofPurposeMismatch, result.FailureReason,
            "The proof is refused for its purpose, whichever key the caller supplied.");
        Assert.IsNull(context, "A refused proof yields no verification state.");
    }
}

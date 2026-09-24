using System.Collections.Frozen;
using System.Text.Json.Nodes;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
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
    /// ecdsa-sd-2023 base proof verifier that takes the issuer's key from its caller refuses a proof signed under the
    /// purpose <c>x</c>, one no verification relationship models, before it verifies anything, although the proof's
    /// signature is valid over that purpose.
    /// </summary>
    /// <remarks>
    /// Proves the Core verification path directly, in-process, with the issuer's key supplied by the caller; the wire proof
    /// of the rule is the VCALM verifier's real-wire test
    /// <see cref="Verifiable.Tests.Vcalm.VcalmVerifierEndpointTests.ExtensionProofPurposeReportsPurposeMismatchProblem"/>.
    /// </remarks>
    [TestMethod]
    public async Task EcdsaSdBaseProofWithUnexpectedPurposeIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, _) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId),
            ProofCreated,
            new UnknownPurposeMethod("x", DataIntegrityContextTamperingFixture.EcdsaSdVerificationMethodId),
            cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

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
    /// an error type of PROOF_VERIFICATION_ERROR." A derived proof keeps its base proof's purpose, and a credential proof's
    /// expected purpose is <c>assertionMethod</c>, so the ecdsa-sd-2023 derived proof verifier that takes the issuer's key
    /// from its caller refuses a proof derived from a base proof signed under the purpose <c>x</c>, one no verification
    /// relationship models, before it verifies anything, although the proof's signatures are valid over that purpose.
    /// </summary>
    /// <remarks>
    /// Proves the Core verification path directly, in-process, with the issuer's key supplied by the caller; the wire proof
    /// of the rule is the VCALM verifier's real-wire test
    /// <see cref="Verifiable.Tests.Vcalm.VcalmVerifierEndpointTests.ExtensionProofPurposeReportsPurposeMismatchProblem"/>.
    /// </remarks>
    [TestMethod]
    public async Task EcdsaSdDerivedProofWithUnexpectedPurposeIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, _) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId),
            ProofCreated,
            new UnknownPurposeMethod("x", DataIntegrityContextTamperingFixture.EcdsaSdVerificationMethodId),
            cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;

        var derived = await DataIntegrityContextTamperingFixture.DeriveEcdsaSdProofAsync(signed, cancellationToken).ConfigureAwait(false);

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


    /// <summary>
    /// The length, in bytes, of the sign data an ecdsa-sd-2023 base signature of this class covers, which the base proof
    /// creation, the base proof verifier and the derived proof verifier each rent one buffer of exactly this length for:
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#serializesigndata">VC-DI-ECDSA §3.5.1 serializeSignData</see> returns
    /// "the concatenation of proofHash, publicKey, and mandatoryHash, in that order", two SHA-256 digests of 32 bytes each
    /// around the proof-scoped P-256 key, multikey-encoded as its multicodec header and its 33-byte compressed point.
    /// </summary>
    private static int SignDataByteLength => 32 + MulticodecHeaders.P256PublicKey.Length + 33 + 32;


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023">VC-DI-ECDSA §3.6.7 Verify Derived
    /// Proof</see> checks the base signature over the sign data of
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#serializesigndata">§3.5.1 serializeSignData</see> and then, "For every
    /// entry (index, signature) in signatures, verify every signature for every selectively disclosed (non-mandatory)
    /// statement". A caller that cancels as the sign data is assembled, while the base signature is checked, or while a
    /// disclosed statement's signature is checked ends the verification with its cancellation, and every buffer the
    /// verification rented is back in the pool: the sign data, the proof-scoped key and each disclosed statement's
    /// signature copy.
    /// </summary>
    /// <remarks>
    /// Proves the Core verification path directly, in-process, over a pool whose own rent and return counters are read,
    /// so a buffer kept past the cancellation shows as an outstanding rental.
    /// </remarks>
    /// <param name="cancellationPoint">Where in the verification the caller cancels.</param>
    [TestMethod]
    [DataRow("sign data assembled")]
    [DataRow("base signature checked")]
    [DataRow("disclosed signature checked")]
    public async Task EcdsaSdDerivedProofVerificationCancelledBetweenItsChecksReturnsEveryRentedBuffer(string cancellationPoint)
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, _) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;
        var derived = await DataIntegrityContextTamperingFixture.DeriveEcdsaSdProofAsync(signed, cancellationToken).ConfigureAwait(false);

        //The signature check during which the caller cancels: the base signature's is the first and the first disclosed
        //statement's the second. As the sign data is assembled no check has run yet.
        int cancellingCheck = cancellationPoint switch
        {
            "base signature checked" => 1,
            "disclosed signature checked" => 2,
            _ => 0
        };
        bool isCancelledAsSignDataIsRented = cancellingCheck == 0;

        using MeteredHousePool metered = new();
        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        metered.OnRent = _ =>
        {
            if(isCancelledAsSignDataIsRented && metered.RentedCountOfSize(SignDataByteLength) > 0)
            {
                caller.Cancel();
            }
        };

        int signatureChecks = 0;
        async ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyWhileTheCallerCancelsAsync(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> publicKeyMaterial,
            FrozenDictionary<string, object>? context,
            CancellationToken verificationToken)
        {
            signatureChecks++;
            if(signatureChecks == cancellingCheck)
            {
                await caller.CancelAsync().ConfigureAwait(false);
            }

            return await MicrosoftCryptographicFunctionsAdapter.VerifyP256Async(
                dataToVerify, signature, publicKeyMaterial, context, verificationToken).ConfigureAwait(false);
        }

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => derived.VerifyDerivedProofVerboseAsync(
            issuerPublicKey,
            VerifyWhileTheCallerCancelsAsync,
            EcdsaSd2023CborSerializer.ParseDerivedProof,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            metered.Pool,
            DataIntegrityContextTamperingFixture.EmptyContext,
            caller.Token).AsTask()).ConfigureAwait(false);

        Assert.IsGreaterThan(0, metered.RentedCount, "The verification rents its buffers from the pool it is given.");
        Assert.AreEqual(0, metered.OutstandingCount,
            $"Cancelled as the {cancellationPoint}, the verification must return every buffer it rented to the pool.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#base-proof-serialization-ecdsa-sd-2023">VC-DI-ECDSA §3.6.5 Base Proof
    /// Serialization</see>: "Initialize toSign to the result of calling the algorithm in Section 3.5.1 serializeSignData,
    /// passing proofHash, publicKey, and mandatoryHash as parameters to the algorithm." and "Initialize baseSignature to the
    /// result of digitally signing toSign using the private key associated with the base proof verification method." The
    /// holder that verifies a base proof checks that base signature over the same sign data. A caller that cancels as the
    /// sign data is assembled, or while the base signature is checked, ends the verification with its cancellation, and
    /// every buffer the verification rented is back in the pool.
    /// </summary>
    /// <remarks>
    /// Proves the Core verification path directly, in-process, over a pool whose own rent and return counters are read,
    /// so a buffer kept past the cancellation shows as an outstanding rental.
    /// </remarks>
    /// <param name="cancellationPoint">Where in the verification the caller cancels.</param>
    [TestMethod]
    [DataRow("sign data assembled")]
    [DataRow("base signature checked")]
    public async Task EcdsaSdBaseProofVerificationCancelledAfterItsSignDataReturnsEveryRentedBuffer(string cancellationPoint)
    {
        var cancellationToken = TestContext.CancellationToken;
        var (signed, issuerPublicKey, _) = await DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofAsync(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);
        using PublicKeyMemory owned = issuerPublicKey;
        bool isCancelledAsSignDataIsRented = string.Equals(cancellationPoint, "sign data assembled", StringComparison.Ordinal);

        using MeteredHousePool metered = new();
        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        metered.OnRent = _ =>
        {
            if(isCancelledAsSignDataIsRented && metered.RentedCountOfSize(SignDataByteLength) > 0)
            {
                caller.Cancel();
            }
        };

        //While the base signature is checked the caller cancels, and the check ends with that cancellation, as a
        //signature function that observes its caller's cancellation does.
        async ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyWhileTheCallerCancelsAsync(
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> publicKeyMaterial,
            FrozenDictionary<string, object>? context,
            CancellationToken verificationToken)
        {
            if(!isCancelledAsSignDataIsRented)
            {
                await caller.CancelAsync().ConfigureAwait(false);
                caller.Token.ThrowIfCancellationRequested();
            }

            return await MicrosoftCryptographicFunctionsAdapter.VerifyP256Async(
                dataToVerify, signature, publicKeyMaterial, context, verificationToken).ConfigureAwait(false);
        }

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => signed.VerifyBaseProofVerboseAsync(
            issuerPublicKey,
            VerifyWhileTheCallerCancelsAsync,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            JsonLdSelection.PartitionStatements,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            metered.Pool,
            DataIntegrityContextTamperingFixture.EmptyContext,
            caller.Token).AsTask()).ConfigureAwait(false);

        Assert.IsGreaterThan(0, metered.RentedCount, "The verification rents its buffers from the pool it is given.");
        Assert.AreEqual(0, metered.OutstandingCount,
            $"Cancelled as the {cancellationPoint}, the verification must return every buffer it rented to the pool.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#base-proof-serialization-ecdsa-sd-2023">VC-DI-ECDSA §3.6.5 Base Proof
    /// Serialization</see>: "Initialize signatures to an array where each element holds the result of digitally signing
    /// the UTF-8 representation of each N-Quad string in nonMandatory, in order." and "Initialize baseSignature to the
    /// result of digitally signing toSign using the private key associated with the base proof verification method." A
    /// caller that cancels as the sign data is assembled, as the base signature is made, or as the first disclosable
    /// statement is signed ends the creation with its cancellation, and every buffer the creation rented is back in the
    /// pool: the proof-scoped key's multikey form, the sign data, the base signature and each statement signature already
    /// made.
    /// </summary>
    /// <remarks>
    /// Proves the Core creation path directly, in-process, over a pool whose own rent and return counters are read, so a
    /// buffer kept past the cancellation shows as an outstanding rental. The caller cancels on a rent the creation makes:
    /// the sign data's own, the first after it, which holds the base signature, or the second after it, which holds the
    /// first disclosable statement's signature.
    /// </remarks>
    /// <param name="cancellationPoint">Where in the creation the caller cancels.</param>
    [TestMethod]
    [DataRow("sign data assembled")]
    [DataRow("base signature made")]
    [DataRow("first statement signed")]
    public async Task EcdsaSdBaseProofCreationCancelledBetweenItsSignaturesReturnsEveryRentedBuffer(string cancellationPoint)
    {
        var cancellationToken = TestContext.CancellationToken;
        var credential = DataIntegrityContextTamperingFixture.DeserializeCredential(
            DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId));
        var issuerPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        var ephemeralPair = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PrivateKeyMemory issuerPrivateKey = issuerPair.PrivateKey;
        using PublicKeyMemory issuerPublicKey = issuerPair.PublicKey;
        using PrivateKeyMemory ephemeralPrivateKey = ephemeralPair.PrivateKey;
        using PublicKeyMemory ephemeralPublicKey = ephemeralPair.PublicKey;

        //How many of the creation's rents after the sign data's pass before the caller cancels on the next.
        int rentsAfterSignData = cancellationPoint switch
        {
            "base signature made" => 1,
            "first statement signed" => 2,
            _ => 0
        };

        using MeteredHousePool metered = new();
        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        long signDataRent = 0;
        metered.OnRent = rentOrdinal =>
        {
            if(signDataRent == 0 && metered.RentedCountOfSize(SignDataByteLength) > 0)
            {
                signDataRent = rentOrdinal;
            }

            if(signDataRent > 0 && rentOrdinal == signDataRent + rentsAfterSignData)
            {
                caller.Cancel();
            }
        };

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(() => DataIntegrityContextTamperingFixture.CreateEcdsaSdBaseProofVerboseAsync(
            credential,
            issuerPrivateKey,
            ephemeralPair,
            DataIntegrityContextTamperingFixture.EcdsaSdVerificationMethodId,
            ProofCreated,
            metered.Pool,
            caller.Token).AsTask()).ConfigureAwait(false);

        Assert.IsGreaterThan(0, metered.RentedCount, "The creation rents its buffers from the pool it is given.");
        Assert.AreEqual(0, metered.OutstandingCount,
            $"Cancelled as the {cancellationPoint}, the creation must return every buffer it rented to the pool.");
    }
}

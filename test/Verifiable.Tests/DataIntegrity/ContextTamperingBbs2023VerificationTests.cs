using System.Text.Json.Nodes;
using Verifiable.Cbor;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Presents the bbs-2023 base-proof and derived-proof verifiers
/// (<see cref="CredentialBbs2023Extensions"/>) with a credential whose <c>@context</c> was
/// altered after signing (for the derived proof: after derivation), for each of the alteration
/// shapes named by <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC
/// Data Integrity 1.0 §2.4.1 Validating Contexts</see> and
/// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context
/// Validation</see>. A variant whose tampering changes the credential's RDF canonical form is
/// refused by the proof check first, before the context check ever runs; every other variant
/// leaves the canonical form unchanged and is refused by the context check.
/// </summary>
[TestClass]
internal sealed class ContextTamperingBbs2023VerificationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static DateTime ProofCreated { get; } = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private const string BaseCredentialId = "urn:uuid:9d3f9b2a-6b7e-4e6a-8f0a-bbs-context";


    [TestMethod]
    [DataRow("ExtraUnknownContext", DataIntegrityContextTamperingFixture.TamperedContextExtraUnknownUrl, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("ExtraKnownContext", DataIntegrityContextTamperingFixture.TamperedContextExtraKnownUrl, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("SubstitutedKnownContext", DataIntegrityContextTamperingFixture.TamperedContextSubstitutedKnownUrl, VerificationFailureReason.SignatureInvalid)]
    [DataRow("ReorderedContext", DataIntegrityContextTamperingFixture.TamperedContextReordered, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("DuplicatedContext", DataIntegrityContextTamperingFixture.TamperedContextDuplicated, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("InlineRedefinesUsedTerm", DataIntegrityContextTamperingFixture.TamperedContextInlineRedefinesUsedTerm, VerificationFailureReason.SignatureInvalid)]
    [DataRow("InlineDefinesUnusedTerm", DataIntegrityContextTamperingFixture.TamperedContextInlineDefinesUnusedTerm, VerificationFailureReason.ContextValidationFailed)]
    [DataRow("NonBaseFirstContext", DataIntegrityContextTamperingFixture.TamperedContextNonBaseFirst, VerificationFailureReason.ContextValidationFailed)]
    public async Task BaseProofRefusesTamperedContext(string variantName, string tamperedContextJson, VerificationFailureReason expectedReason)
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = Bbs2023ResolvingBindingTests.ResolvingBbsOperations.Generate();

        var (signed, issuer) = await DataIntegrityContextTamperingFixture.CreateBbsBaseProofAsync(
            bbs, DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);

        var tampered = DataIntegrityContextTamperingFixture.ReserializeWithTamperedContext(signed, JsonNode.Parse(tamperedContextJson)!);

        var result = await tampered.VerifyBaseProofAsync(
            bbs.Verify,
            Bbs2023CborSerializer.ParseBaseProof,
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

        Assert.IsFalse(result.IsValid, $"bbs-2023 base proof: variant '{variantName}' must be refused (VC Data Integrity 1.0 §2.4.1/§4.6).");
        Assert.AreEqual(expectedReason, result.FailureReason, $"bbs-2023 base proof: variant '{variantName}' must be refused for the specific reason it actually produces.");
    }


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
        using var bbs = Bbs2023ResolvingBindingTests.ResolvingBbsOperations.Generate();

        var (signed, issuer) = await DataIntegrityContextTamperingFixture.CreateBbsBaseProofAsync(
            bbs, DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);

        var derived = await DataIntegrityContextTamperingFixture.DeriveBbsProofAsync(signed, bbs, cancellationToken).ConfigureAwait(false);
        var tampered = DataIntegrityContextTamperingFixture.ReserializeWithTamperedContext(derived, JsonNode.Parse(tamperedContextJson)!);

        var result = await tampered.VerifyDerivedProofAsync(
            bbs.ProofVerify,
            Bbs2023CborSerializer.ParseDerivedProof,
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

        Assert.IsFalse(result.IsValid, $"bbs-2023 derived proof: variant '{variantName}' must be refused (VC Data Integrity 1.0 §2.4.1/§4.6).");
        Assert.AreEqual(expectedReason, result.FailureReason, $"bbs-2023 derived proof: variant '{variantName}' must be refused for the specific reason it actually produces.");
    }


    [TestMethod]
    public async Task BaseProofWithOwnUntamperedContextVerifiesAsValid()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = Bbs2023ResolvingBindingTests.ResolvingBbsOperations.Generate();

        var (signed, issuer) = await DataIntegrityContextTamperingFixture.CreateBbsBaseProofAsync(
            bbs, DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);

        var result = await signed.VerifyBaseProofAsync(
            bbs.Verify,
            Bbs2023CborSerializer.ParseBaseProof,
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

        Assert.IsTrue(result.IsValid, "An untampered bbs-2023 base proof, checked against its own @context, must verify as valid.");
    }


    [TestMethod]
    public async Task DerivedProofWithOwnUntamperedContextVerifiesAsValid()
    {
        var cancellationToken = TestContext.CancellationToken;
        using var bbs = Bbs2023ResolvingBindingTests.ResolvingBbsOperations.Generate();

        var (signed, issuer) = await DataIntegrityContextTamperingFixture.CreateBbsBaseProofAsync(
            bbs, DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(BaseCredentialId), ProofCreated, cancellationToken).ConfigureAwait(false);

        var derived = await DataIntegrityContextTamperingFixture.DeriveBbsProofAsync(signed, bbs, cancellationToken).ConfigureAwait(false);

        var result = await derived.VerifyDerivedProofAsync(
            bbs.ProofVerify,
            Bbs2023CborSerializer.ParseDerivedProof,
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

        Assert.IsTrue(result.IsValid, "An untampered bbs-2023 derived proof, checked against its own @context, must verify as valid.");
    }
}

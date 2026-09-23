using System.Text.Json.Nodes;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Presents <see cref="PresentationDataIntegrityExtensions.VerifyAsync"/> with a Data Integrity
/// secured presentation whose OWN <c>@context</c> was altered AFTER signing, for the same
/// alteration shapes <see cref="ContextTamperingCredentialVerificationTests"/> exercises for a
/// credential, per
/// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data Integrity
/// 1.0 §2.4.1 Validating Contexts</see> and
/// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context
/// Validation</see>. Every variant here alters the presentation's own <c>@context</c> array,
/// with no embedded credential present; an embedded credential's <c>@context</c> is the
/// credential verifier's subject.
/// </summary>
[TestClass]
internal sealed class ContextTamperingPresentationVerificationTests
{
    /// <summary>The MSTest context, whose cancellation token bounds every signing and verification.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fixed <c>created</c> timestamp of every proof these tests sign.</summary>
    private static DateTime ProofCreated { get; } = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>The <c>id</c> of the presentation these tests sign and then tamper with.</summary>
    private const string PresentationId = "urn:uuid:3f9d9b2a-6b7e-4e6a-8f0a-context-tampering-vp";

    /// <summary>The challenge the presentation proof binds and the verifier expects.</summary>
    private const string VerifierChallenge = "verifier-challenge-context-tampering";

    /// <summary>The domain the presentation proof binds and the verifier expects.</summary>
    private const string VerifierDomain = "verifier.example";

    /// <summary>An unresolvable, unknown context URL appended after signing (variant a).</summary>
    private const string TamperedContextExtraUnknownUrl = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", "https://unknown.example/context/v1"]
        """;

    /// <summary>A known context URL the presentation did not originally name, appended after signing (variant b).</summary>
    private const string TamperedContextExtraKnownUrl = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", "https://w3id.org/citizenship/v4rc1"]
        """;

    /// <summary>A known context substituted for another known context after signing (variant c).</summary>
    private const string TamperedContextSubstitutedKnownUrl = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/citizenship/v4rc1"]
        """;

    /// <summary>The signed two-entry <c>@context</c> reordered after signing (variant d).</summary>
    private const string TamperedContextReordered = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/examples/v2", "https://www.w3.org/ns/credentials/v2"]
        """;

    /// <summary>A context entry duplicated after signing (variant e).</summary>
    private const string TamperedContextDuplicated = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", "https://www.w3.org/ns/credentials/examples/v2"]
        """;

    /// <summary>An inline context object appended that redefines the <c>holder</c> term (variant f, redefining case).</summary>
    private const string TamperedContextInlineRedefinesTerm = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", {"holder": "https://attacker.example/vocab#holder"}]
        """;

    /// <summary>An inline context object appended that defines only an unused term (variant f, unused-term case).</summary>
    private const string TamperedContextInlineDefinesUnusedTerm = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", {"neverUsedTerm": "https://attacker.example/vocab#neverUsedTerm"}]
        """;

    /// <summary>A known context that is not the VC Data Model base context placed first (variant g).</summary>
    private const string TamperedContextNonBaseFirst = /*lang=json,strict*/ """
        ["https://w3id.org/citizenship/v4rc1", "https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"]
        """;


    /// <summary>
    /// Signs the fixture's presentation with eddsa-rdfc-2022 bound to <see cref="VerifierChallenge"/> and
    /// <see cref="VerifierDomain"/>, replaces its own <c>@context</c> with <paramref name="tamperedContextJson"/>
    /// after signing, and verifies the result against the fixture's known contexts.
    /// </summary>
    /// <param name="tamperedContextJson">The <c>@context</c> array substituted after signing.</param>
    /// <param name="cancellationToken">The cancellation token of the running test.</param>
    /// <returns>The verification result of the tampered presentation.</returns>
    private static async ValueTask<CredentialVerificationResult<DataIntegritySecuredPresentation>> VerifyWithTamperedContextAsync(
        string tamperedContextJson,
        CancellationToken cancellationToken)
    {
        var unsigned = DataIntegrityContextTamperingFixture.CreateUnsignedPresentationJson(PresentationId);
        var (signed, holder) = await DataIntegrityContextTamperingFixture.SignPresentationAsync(
            unsigned,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            ProofCreated,
            VerifierChallenge,
            VerifierDomain,
            cancellationToken).ConfigureAwait(false);

        var tamperedContext = JsonNode.Parse(tamperedContextJson)!;
        var tampered = DataIntegrityContextTamperingFixture.ReserializeWithTamperedContext(signed, tamperedContext);

        return await tampered.VerifyAsync(
            holder,
            VerifierChallenge,
            VerifierDomain,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            ProofValueCodecs.DecodeBase58Btc,
            DataIntegrityContextTamperingFixture.SerializePresentation,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a presentation naming an extra, unresolvable context URL after signing.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesExtraUnknownContext()
    {
        var result = await VerifyWithTamperedContextAsync(TamperedContextExtraUnknownUrl, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: an unresolvable context URL appended after signing is not the known set of contexts and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a presentation naming an extra context URL the verifier knows but the presentation did not originally carry.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesExtraKnownContext()
    {
        var result = await VerifyWithTamperedContextAsync(TamperedContextExtraKnownUrl, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: a known context URL appended after signing changes the context set from the one the verifier expects and must be refused, even when the appended URL is itself known.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a presentation with one known context substituted for another known context.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesSubstitutedKnownContext()
    {
        var result = await VerifyWithTamperedContextAsync(TamperedContextSubstitutedKnownUrl, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: substituting one known context for another after signing is not the known set in the known order and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a presentation whose context entries were reordered after signing.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesReorderedContext()
    {
        var result = await VerifyWithTamperedContextAsync(TamperedContextReordered, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: reordering context entries after signing is not the known order and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a presentation with a context entry duplicated after signing.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesDuplicatedContext()
    {
        var result = await VerifyWithTamperedContextAsync(TamperedContextDuplicated, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: a duplicated context entry after signing is not the known set in the known order and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a presentation carrying an inline context that redefines a term the presentation's own members use.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesInlineContextRedefiningTerm()
    {
        var result = await VerifyWithTamperedContextAsync(TamperedContextInlineRedefinesTerm, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: an inline context redefining a term after signing is not the known set of contexts and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a presentation carrying an inline context that defines only a term the presentation never uses.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesInlineContextDefiningUnusedTerm()
    {
        var result = await VerifyWithTamperedContextAsync(TamperedContextInlineDefinesUnusedTerm, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: an inline context defining an unused term is still an addition to the known set of contexts and must be refused, even though the presentation's own members do not reference the new term.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a presentation whose first context entry is not the VC Data Model base context.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesNonBaseFirstContext()
    {
        var result = await VerifyWithTamperedContextAsync(TamperedContextNonBaseFirst, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: a first context entry other than the VC Data Model base context is not the known order and must be refused.");
    }

    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// "If one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist, an error MUST
    /// be raised and SHOULD convey an error type of PROOF_VERIFICATION_ERROR."
    /// </summary>
    /// <remarks>
    /// This drives the Core presentation verification directly rather than an endpoint, so it proves Core's own
    /// refusal, which a caller that checks the mandatory members first would otherwise never reach.
    /// </remarks>
    [TestMethod]
    public async Task PresentationProofWithoutTypeIsRejected()
    {
        var cancellationToken = TestContext.CancellationToken;
        var unsigned = DataIntegrityContextTamperingFixture.CreateUnsignedPresentationJson(PresentationId);
        var (signed, holder) = await DataIntegrityContextTamperingFixture.SignPresentationAsync(
            unsigned,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            ProofCreated,
            VerifierChallenge,
            VerifierDomain,
            cancellationToken).ConfigureAwait(false);

        signed.Proof![0].Type = null!;

        var result = await signed.VerifyAsync(
            holder,
            VerifierChallenge,
            VerifierDomain,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            ProofValueCodecs.DecodeBase58Btc,
            DataIntegrityContextTamperingFixture.SerializePresentation,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Data Integrity §4.4: a proof without type MUST be refused.");
        Assert.AreEqual(VerificationFailureReason.MissingVerificationMethod, result.FailureReason,
            "Missing mandatory proof options share the existing verification failure result.");
    }

}

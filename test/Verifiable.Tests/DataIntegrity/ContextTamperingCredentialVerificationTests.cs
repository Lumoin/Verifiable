using System.Text.Json.Nodes;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Presents <see cref="CredentialDataIntegrityExtensions.VerifyAsync"/> with a Data Integrity
/// secured credential whose <c>@context</c> was altered AFTER signing, for each of the
/// alteration shapes named by
/// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">VC Data Integrity
/// 1.0 §2.4.1 Validating Contexts</see> and
/// <see href="https://www.w3.org/TR/vc-data-integrity/#context-validation">§4.6 Context
/// Validation</see>.
/// </summary>
/// <remarks>
/// <para>
/// §2.4.1 requires: "Applications MUST use the algorithm in Section 4.6 Context Validation, or
/// one that achieves equivalent protections, to validate contexts in a conforming secured
/// document. Context validation MUST be run after running the applicable algorithm in either
/// Section 4.4 Verify Proof or Section 4.5 Verify Proof Sets and Chains." §4.6 refuses a
/// document whose contexts are not the verifier's known ones in the known order.
/// </para>
/// <para>
/// <see cref="CredentialDataIntegrityExtensions.VerifyAsync"/> calls no such algorithm; each
/// test here observes, rather than assumes, whether the RDFC-1.0 canonicalizer's own semantic
/// processing (which changes the signed hash whenever a redefined or dropped term changes the
/// expanded RDF graph) or JCS's literal byte coverage of <c>@context</c> refuses the tampering
/// anyway. Where neither happens, the verifier reports the credential valid and the assertion
/// below is written to the specification's expected refusal, so the test stays red until a
/// context-validation step is wired into the pipeline.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ContextTamperingCredentialVerificationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static DateTime ProofCreated { get; } = new(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private const string CredentialId = "urn:uuid:9d3f9b2a-6b7e-4e6a-8f0a-context-tampering";

    /// <summary>An unresolvable, unknown context URL appended after signing (variant a).</summary>
    private const string TamperedContextExtraUnknownUrl = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", "https://unknown.example/context/v1"]
        """;

    /// <summary>A known context URL the credential did not originally name, appended after signing (variant b).</summary>
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

    /// <summary>An inline context object appended that redefines the <c>alumniOf</c> term the credential uses (variant f, redefining case).</summary>
    private const string TamperedContextInlineRedefinesUsedTerm = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", {"alumniOf": "https://attacker.example/vocab#alumniOf"}]
        """;

    /// <summary>An inline context object appended that defines only an unused term (variant f, unused-term case).</summary>
    private const string TamperedContextInlineDefinesUnusedTerm = /*lang=json,strict*/ """
        ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", {"neverUsedTerm": "https://attacker.example/vocab#neverUsedTerm"}]
        """;

    /// <summary>A known context that is not the VC Data Model base context placed first (variant g).</summary>
    private const string TamperedContextNonBaseFirst = /*lang=json,strict*/ """
        ["https://w3id.org/citizenship/v4rc1", "https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"]
        """;


    private static async ValueTask<CredentialVerificationResult<DataIntegritySecuredCredential>> VerifyWithTamperedContextAsync(
        CryptosuiteInfo cryptosuite,
        CanonicalizationDelegate canonicalize,
        ContextResolverDelegate? contextResolver,
        string tamperedContextJson,
        CancellationToken cancellationToken)
    {
        var unsigned = DataIntegrityContextTamperingFixture.CreateUnsignedCredentialJson(CredentialId);
        var (signed, issuer) = await DataIntegrityContextTamperingFixture.SignCredentialAsync(
            unsigned, cryptosuite, canonicalize, contextResolver, ProofCreated, cancellationToken).ConfigureAwait(false);

        var tamperedContext = JsonNode.Parse(tamperedContextJson)!;
        var tampered = DataIntegrityContextTamperingFixture.ReserializeWithTamperedContext(signed, tamperedContext);

        return await tampered.VerifyAsync(
            issuer,
            canonicalize,
            contextResolver,
            DataIntegrityContextTamperingFixture.KnownContext,
            ProofValueCodecs.DecodeBase58Btc,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a document naming an extra, unresolvable context URL after signing.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesExtraUnknownContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            TamperedContextExtraUnknownUrl,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: an unresolvable context URL appended after signing is not the known set of contexts and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a document naming an extra context URL the verifier knows but the credential did not originally carry.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesExtraKnownContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            TamperedContextExtraKnownUrl,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: a known context URL appended after signing changes the context set from the one the verifier expects and must be refused, even when the appended URL is itself known.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a document with one known context substituted for another known context.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesSubstitutedKnownContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            TamperedContextSubstitutedKnownUrl,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: substituting one known context for another after signing is not the known set in the known order and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a document whose context entries were reordered after signing.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesReorderedContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            TamperedContextReordered,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: reordering context entries after signing is not the known order and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a document with a context entry duplicated after signing.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesDuplicatedContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            TamperedContextDuplicated,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: a duplicated context entry after signing is not the known set in the known order and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a document carrying an inline context that redefines the term a claim already uses.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesInlineContextRedefiningUsedTerm()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            TamperedContextInlineRedefinesUsedTerm,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: an inline context redefining a term the credential's claims use after signing is not the known set of contexts and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a document carrying an inline context that defines only a term the credential never uses.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesInlineContextDefiningUnusedTerm()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            TamperedContextInlineDefinesUnusedTerm,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: an inline context defining an unused term is still an addition to the known set of contexts and must be refused, even though the credential's own claims do not reference the new term.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 refuses a document whose first context entry is not the VC Data Model base context.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationRefusesNonBaseFirstContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            TamperedContextNonBaseFirst,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: a first context entry other than the VC Data Model base context is not the known order and must be refused.");
    }


    /// <summary>eddsa-jcs-2022: §4.6 refuses a document naming an extra, unresolvable context URL after signing.</summary>
    [TestMethod]
    public async ValueTask JcsVerificationRefusesExtraUnknownContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaJcs2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.JcsCanonicalizer,
            contextResolver: null,
            TamperedContextExtraUnknownUrl,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: an unresolvable context URL appended after signing is not the known set of contexts and must be refused.");
    }


    /// <summary>eddsa-jcs-2022: §4.6 refuses a document naming an extra context URL the verifier knows but the credential did not originally carry.</summary>
    [TestMethod]
    public async ValueTask JcsVerificationRefusesExtraKnownContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaJcs2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.JcsCanonicalizer,
            contextResolver: null,
            TamperedContextExtraKnownUrl,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: a known context URL appended after signing changes the context set from the one the verifier expects and must be refused, even when the appended URL is itself known.");
    }


    /// <summary>eddsa-jcs-2022: §4.6 refuses a document with one known context substituted for another known context.</summary>
    [TestMethod]
    public async ValueTask JcsVerificationRefusesSubstitutedKnownContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaJcs2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.JcsCanonicalizer,
            contextResolver: null,
            TamperedContextSubstitutedKnownUrl,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: substituting one known context for another after signing is not the known set in the known order and must be refused.");
    }


    /// <summary>eddsa-jcs-2022: §4.6 refuses a document whose context entries were reordered after signing.</summary>
    [TestMethod]
    public async ValueTask JcsVerificationRefusesReorderedContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaJcs2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.JcsCanonicalizer,
            contextResolver: null,
            TamperedContextReordered,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: reordering context entries after signing is not the known order and must be refused.");
    }


    /// <summary>eddsa-jcs-2022: §4.6 refuses a document with a context entry duplicated after signing.</summary>
    [TestMethod]
    public async ValueTask JcsVerificationRefusesDuplicatedContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaJcs2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.JcsCanonicalizer,
            contextResolver: null,
            TamperedContextDuplicated,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: a duplicated context entry after signing is not the known set in the known order and must be refused.");
    }


    /// <summary>eddsa-jcs-2022: §4.6 refuses a document carrying an inline context that redefines the term a claim already uses.</summary>
    [TestMethod]
    public async ValueTask JcsVerificationRefusesInlineContextRedefiningUsedTerm()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaJcs2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.JcsCanonicalizer,
            contextResolver: null,
            TamperedContextInlineRedefinesUsedTerm,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: an inline context redefining a term the credential's claims use after signing is not the known set of contexts and must be refused.");
    }


    /// <summary>eddsa-jcs-2022: §4.6 refuses a document carrying an inline context that defines only a term the credential never uses.</summary>
    [TestMethod]
    public async ValueTask JcsVerificationRefusesInlineContextDefiningUnusedTerm()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaJcs2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.JcsCanonicalizer,
            contextResolver: null,
            TamperedContextInlineDefinesUnusedTerm,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: an inline context defining an unused term is still an addition to the known set of contexts and must be refused, even though the credential's own claims do not reference the new term.");
    }


    /// <summary>eddsa-jcs-2022: §4.6 refuses a document whose first context entry is not the VC Data Model base context.</summary>
    [TestMethod]
    public async ValueTask JcsVerificationRefusesNonBaseFirstContext()
    {
        var result = await VerifyWithTamperedContextAsync(
            EddsaJcs2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.JcsCanonicalizer,
            contextResolver: null,
            TamperedContextNonBaseFirst,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "VC Data Integrity 1.0 §2.4.1/§4.6: a first context entry other than the VC Data Model base context is not the known order and must be refused.");
    }


    /// <summary>eddsa-rdfc-2022: §4.6 accepts a credential whose (untampered) <c>@context</c> deeply equals the known list, when the known list itself holds an inline context object.</summary>
    [TestMethod]
    public async ValueTask RdfcVerificationAcceptsUntamperedContextWithInlineDefinitionInKnownList()
    {
        const string CredentialWithInlineDefinitionJson = /*lang=json,strict*/ """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", {"customTerm": "https://attacker.example/vocab#customTerm"}],
                "id": "urn:uuid:9d3f9b2a-6b7e-4e6a-8f0a-context-inline-known",
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

        var (signed, issuer) = await DataIntegrityContextTamperingFixture.SignCredentialAsync(
            CredentialWithInlineDefinitionJson,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            ProofCreated,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Deeply equal to the credential's own (untampered) @context, including the inline definition,
        //entry by entry — the exact shape VC Data Integrity 1.0 §4.6 Context Validation step 3 compares.
        Context knownContextWithInlineDefinition = new(
            [
                ContextEntry.FromIri("https://www.w3.org/ns/credentials/v2"),
                ContextEntry.FromIri("https://www.w3.org/ns/credentials/examples/v2"),
                ContextEntry.FromDefinition(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["customTerm"] = "https://attacker.example/vocab#customTerm"
                })
            ],
            ContextForm.Array);

        var result = await signed.VerifyAsync(
            issuer,
            DataIntegrityContextTamperingFixture.RdfcCanonicalizer,
            DataIntegrityContextTamperingFixture.ContextResolver,
            knownContextWithInlineDefinition,
            ProofValueCodecs.DecodeBase58Btc,
            DataIntegrityContextTamperingFixture.SerializeCredential,
            DataIntegrityContextTamperingFixture.SerializeProofOptions,
            TestSetup.Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            DataIntegrityContextTamperingFixture.EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"VC Data Integrity 1.0 §4.6: an untampered @context deeply equal to the known list, including an inline context object entry, must verify VALID; got {result.FailureReason}.");
    }
}

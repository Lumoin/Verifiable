using CsCheck;
using System.Text.Json;
using Verifiable.Cbor;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.DataIntegrity.Bbs2023W3cVectorTests;
using static Verifiable.Tests.TestInfrastructure.CanonicalizationTestUtilities;
using static Verifiable.Tests.TestInfrastructure.DerivedCredentialDisclosureAssertions;

namespace Verifiable.Tests.DataIntegrity;

/// <summary>
/// Property-based tests (CsCheck) for the bbs-2023 selective-disclosure pipeline exercised in
/// <see cref="Bbs2023W3cVectorTests"/>: invariants that must hold for every subset of the W3C
/// Appendix A.1 credential's selectable claims, not just the hand-picked disclosure sets in the
/// hand-written vector tests.
/// </summary>
[TestClass]
internal sealed class Bbs2023W3cVectorPropertyTests
{
    /// <summary>
    /// A selectable claim of the A.1 credential paired with a value that, when the claim is disclosed,
    /// must appear in the reduced credential and, when it is hidden, must be absent.
    /// </summary>
    private sealed record SelectableClaim(string Pointer, string DisclosedValue);

    /// <summary>The A.1 credential's own <c>@context</c>, from W3C Example 18.</summary>
    private static Context KnownContext { get; } = Context.FromIris(Context.Credentials20, "https://w3id.org/citizenship/v4rc1");

    /// <summary>
    /// The leaf claims of the A.1 credential the holder may selectively disclose. The mandatory
    /// <c>/issuer</c> pointer is always disclosed and is therefore excluded from this set; each value is
    /// unique enough to assert presence or absence in the reduced JSON.
    /// </summary>
    private static SelectableClaim[] SelectableClaims { get; } =
    [
        new SelectableClaim("/validFrom", "2024-12-16T00:00:00Z"),
        new SelectableClaim("/validUntil", "2025-12-16T23:59:59Z"),
        new SelectableClaim("/credentialSubject/birthCountry", "Arcadia"),
        new SelectableClaim("/credentialSubject/givenName", "JANE"),
        new SelectableClaim("/credentialSubject/familyName", "SMITH"),
        new SelectableClaim("/credentialSubject/birthDate", "1978-07-17")
    ];


    /// <summary>
    /// Randomized property test over the REAL pipeline (dotNetRdf RDFC-1.0 + <see cref="JsonLdSelection"/>
    /// partition/select): for any non-empty subset of the A.1 credential's selectable claims, the
    /// issue -> verify-base -> derive -> verify-derived round-trip must produce a derived proof that
    /// verifies, and the reduced credential must disclose exactly the chosen claims (plus the mandatory
    /// issuer) while hiding the rest.
    /// </summary>
    [TestMethod]
    public async Task RandomDisclosureSubsetsRoundTrip()
    {
        byte[] hmacKey = Convert.FromHexString(HmacKeyHex);
        byte[] publicKeyBytes = Convert.FromHexString(PublicKeyHex);
        byte[] presentationHeader = Convert.FromHexString(PresentationHeaderHex);

        var rdfcCanonicalizer = CanonicalizationTestUtilities.CreateRdfcCanonicalizer();
        var contextResolver = CanonicalizationTestUtilities.CreateTestContextResolver();
        var mandatoryPaths = MandatoryPointers.Select(CredentialPath.FromJsonPointer).ToArray();

        //Generate a non-empty subset of the selectable-claim indexes.
        Gen<int[]> subsetGen =
            from mask in Gen.Int[1, (1 << SelectableClaims.Length) - 1]
            select Enumerable.Range(0, SelectableClaims.Length).Where(i => (mask & (1 << i)) != 0).ToArray();

        await subsetGen.SampleAsync(async subset =>
        {
            var disclosed = subset.Select(i => SelectableClaims[i]).ToArray();

            using var bbs = BbsOperations.Create(PrivateKeyHex, PublicKeyHex);

            var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(UnsignedCredential, TestSetup.DefaultSerializationOptions)!;

            var signedCredential = await credential.CreateBaseProofAsync(
                publicKeyBytes,
                VerificationMethodId,
                DateTime.Parse("2023-08-15T23:36:38Z", null, System.Globalization.DateTimeStyles.RoundtripKind),
                mandatoryPaths,
                () => hmacKey,
                JsonLdSelection.PartitionStatements,
                rdfcCanonicalizer,
                contextResolver,
                SerializeCredential,
                DeserializeCredential,
                SerializeProofOptions,
                Bbs2023CborSerializer.SerializeBaseProof,
                bbs.Sign,
                TestSetup.Base64UrlEncoder,
                BaseMemoryPool.Shared,
                EmptyContext,
                CancellationToken.None).AsTask();

            var baseVerify = await signedCredential.VerifyBaseProofAsync(
                bbs.Verify,
                Bbs2023CborSerializer.ParseBaseProof,
                JsonLdSelection.PartitionStatements,
                rdfcCanonicalizer,
                contextResolver,
                KnownContext,
                SerializeCredential,
                SerializeProofOptions,
                TestSetup.Base64UrlEncoder,
                TestSetup.Base64UrlDecoder,
                BaseMemoryPool.Shared,
                EmptyContext,
                CancellationToken.None).AsTask();

            Assert.IsTrue(baseVerify.IsValid, "Holder must verify the base proof.");

            var verifierRequestedPaths = disclosed
                .Select(c => CredentialPath.FromJsonPointer(c.Pointer))
                .ToHashSet();

            var derivedCredential = await signedCredential.DeriveProofAsync(
                verifierRequestedPaths,
                userExclusions: null,
                presentationHeader,
                JsonLdSelection.PartitionStatements,
                JsonLdSelection.SelectFragments,
                rdfcCanonicalizer,
                contextResolver,
                SerializeCredential,
                DeserializeCredential,
                Bbs2023CborSerializer.ParseBaseProof,
                Bbs2023CborSerializer.SerializeDerivedProof,
                bbs.ProofGen,
                TestSetup.Base64UrlEncoder,
                TestSetup.Base64UrlDecoder,
                BaseMemoryPool.Shared,
                EmptyContext,
                CancellationToken.None).AsTask();

            var derivedVerify = await derivedCredential.VerifyDerivedProofAsync(
                bbs.ProofVerify,
                Bbs2023CborSerializer.ParseDerivedProof,
                rdfcCanonicalizer,
                contextResolver,
                KnownContext,
                SerializeCredential,
                SerializeProofOptions,
                TestSetup.Base64UrlEncoder,
                TestSetup.Base64UrlDecoder,
                BaseMemoryPool.Shared,
                EmptyContext,
                CancellationToken.None).AsTask();

            Assert.IsTrue(derivedVerify.IsValid, $"Derived proof must verify for subset [{string.Join(",", disclosed.Select(c => c.Pointer))}].");

            //The reduced credential discloses the mandatory issuer plus exactly the chosen claims, and
            //hides every selectable claim that was not chosen. This is checked against the derived
            //credential's own JSON structure, the shape a verifier actually reads, never against its
            //serialized text: the proof value is a fresh random draw each run, so a short undisclosed
            //value can appear inside it by coincidence, and a substring search over the whole document
            //both fails a correct hiding and passes a real leak that lands under a different literal.
            var derivedJson = SerializeCredential(derivedCredential);
            using JsonDocument derivedDocument = JsonDocument.Parse(derivedJson);
            JsonElement derivedRoot = derivedDocument.RootElement;

            AssertClaimDisclosed(derivedRoot, "/issuer/id", "did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg");

            var disclosedPointers = disclosed.Select(c => c.Pointer).ToHashSet();
            foreach(var claim in SelectableClaims)
            {
                if(disclosedPointers.Contains(claim.Pointer))
                {
                    AssertClaimDisclosed(derivedRoot, claim.Pointer, claim.DisclosedValue);
                }
                else
                {
                    AssertClaimHidden(derivedRoot, claim.Pointer, claim.DisclosedValue);
                }
            }
        }, iter: 30, threads: CsCheckSampling.Threads);
    }


    /// <summary>
    /// Proves that <see cref="DerivedCredentialDisclosureAssertions.AssertClaimHidden"/> fails a
    /// real leak rather than merely never firing: a fabricated disclosed structure in which the
    /// undisclosed <c>birthCountry</c> value has leaked into an unrelated disclosed field must
    /// fail the check, naming that leak, rather than pass it.
    /// </summary>
    [TestMethod]
    public void AssertClaimHiddenFailsWhenTheUndisclosedValueLeaksElsewhere()
    {
        using JsonDocument leaking = JsonDocument.Parse(/*lang=json,strict*/ """
        {
          "issuer": { "id": "did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg" },
          "validFrom": "2024-12-16T00:00:00Z",
          "description": "Arcadia"
        }
        """);

        AssertFailedException failure = Assert.Throws<AssertFailedException>(
            () => AssertClaimHidden(leaking.RootElement, "/credentialSubject/birthCountry", "Arcadia"));

        Assert.Contains("must not appear anywhere in the disclosed structure", failure.Message);
    }
}

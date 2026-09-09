using System.Text;
using System.Text.Json;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Focused tests for <see cref="SdTokenDcqlAdapter"/> — the format-neutral
/// DcqlEvaluator adapter over a parsed <see cref="SdToken{TEnvelope}"/>. The
/// full end-to-end evaluator path is covered by the SD-JWT / SD-CWT presentation
/// flow tests; these pin the extractor contracts directly, including nested
/// (multi-segment) path resolution over a real parsed token.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Reliability", "CA2000:Dispose objects before losing scope",
    Justification =
        "The fixture builders construct Salt/SdDisclosure instances that transfer ownership " +
        "into the SdToken built from them (SdJwtSerializer.ParseToken), which each test disposes " +
        "via a using declaration; the analyzer cannot see ownership transfer through the wire " +
        "round-trip.")]
[TestClass]
internal sealed class SdTokenDcqlAdapterTests
{
    public TestContext TestContext { get; set; } = null!;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string TestIssuer = "https://issuer.example.com";
    private const string TestVct = "urn:eudi:pid:1";


    /// <summary>
    /// Builds a genuinely parsed SD-JWT VC token: <c>vct</c>/<c>iss</c> always-disclosed,
    /// <c>given_name</c> a top-level disclosure, and <c>employer</c> a recursive disclosure
    /// whose own revealed value carries the nested <c>family_name</c> disclosure (RFC 9901
    /// §4.2.6). Only a parsed token carries <see cref="SdToken{TEnvelope}.DisclosurePaths"/> and
    /// <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> — the adapter reads both directly, with
    /// no caller-supplied type or issuer string.
    /// </summary>
    private static SdToken<string> BuildToken()
    {
        SdDisclosure givenName = CreateDisclosure("salt-given-name", "given_name", "Erika");
        SdDisclosure familyName = CreateDisclosure("salt-family-name", "family_name", "Mustermann");

        string familyNameEncoded = SdJwtSerializer.SerializeDisclosure(familyName, TestSetup.Base64UrlEncoder);
        string familyNameDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
            familyNameEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        JsonElement employerValue = JsonDocument.Parse(/*lang=json,strict*/ $$"""
        {
            "_sd": ["{{familyNameDigest}}"]
        }
        """).RootElement;
        SdDisclosure employer = SdDisclosure.CreateProperty(
            TestSalts.FromBytes(Encoding.UTF8.GetBytes("salt-employer")), "employer", employerValue);

        string employerEncoded = SdJwtSerializer.SerializeDisclosure(employer, TestSetup.Base64UrlEncoder);
        string employerDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
            employerEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string givenNameEncoded = SdJwtSerializer.SerializeDisclosure(givenName, TestSetup.Base64UrlEncoder);
        string givenNameDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
            givenNameEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string payloadJson = /*lang=json,strict*/ $$"""
        {
            "_sd_alg": "sha-256",
            "iss": "{{TestIssuer}}",
            "vct": "{{TestVct}}",
            "_sd": ["{{givenNameDigest}}", "{{employerDigest}}"]
        }
        """;

        string jwt = CreateMinimalJwt(payloadJson);
        string wireFormat = $"{jwt}~{givenNameEncoded}~{employerEncoded}~{familyNameEncoded}~";

        return SdJwtSerializer.ParseToken(
            wireFormat, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag);
    }


    /// <summary>
    /// Builds a plain (non-VC) SD-JWT token carrying no <c>vct</c>/<c>iss</c> claim at all, to
    /// prove the metadata extractor reports <see langword="null"/> rather than inventing evidence.
    /// </summary>
    private static SdToken<string> BuildTokenWithoutTypeOrIssuer()
    {
        SdDisclosure givenName = CreateDisclosure("salt-given-name-2", "given_name", "Erika");

        string givenNameEncoded = SdJwtSerializer.SerializeDisclosure(givenName, TestSetup.Base64UrlEncoder);
        string givenNameDigest = SdJwtPathExtraction.ComputeDisclosureDigest(
            givenNameEncoded, WellKnownHashAlgorithms.Sha256Iana, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string payloadJson = /*lang=json,strict*/ $$"""
        {
            "_sd_alg": "sha-256",
            "_sd": ["{{givenNameDigest}}"]
        }
        """;

        string jwt = CreateMinimalJwt(payloadJson);
        string wireFormat = $"{jwt}~{givenNameEncoded}~";

        return SdJwtSerializer.ParseToken(
            wireFormat, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag);
    }


    /// <summary>
    /// The extractor answers the credential's own type evidence and the structure a query can
    /// address: SD-JWT VC Section 2.2.2.3's <c>vct</c>, and the union of every disclosure's
    /// position with every unconditionally disclosed node. The nested position is listed in full
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 9.3</see>, under
    /// which two namesakes at two depths are two disclosures. Per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>, the credential's own <c>iss</c>
    /// claim is not itself trust evidence, so it is addressable like any other claim but supplies
    /// no <see cref="DcqlCredentialMetadata.TrustedAuthorityEvidence"/>.
    /// </summary>
    [TestMethod]
    public void MetadataExtractorReportsFormatTypeAndAvailablePaths()
    {
        using SdToken<string> token = BuildToken();

        DcqlMetadataExtractor<SdToken<string>> extractor = SdTokenDcqlAdapter.CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt);

        DcqlCredentialMetadata metadata = extractor(token);

        Assert.AreEqual(DcqlCredentialFormats.SdJwt, metadata.Format,
            "The metadata reports the format the extractor was built for.");
        Assert.AreEqual(TestVct, metadata.CredentialType,
            "SD-JWT VC Section 2.2.2.3: the credential type is the credential's own vct claim.");
        Assert.IsNull(metadata.TrustedAuthorityEvidence,
            "No TrustedAuthorityEvidenceSource was supplied, so the metadata carries no trust evidence.");
        Assert.IsNotNull(metadata.AvailablePaths,
            "A parsed credential exposes the positions a claims path pointer can address.");
        Assert.Contains(CredentialPath.FromJsonPointer("/given_name"), metadata.AvailablePaths!,
            "RFC 9901 Section 4.2.1: a top-level disclosure sits at the root object's path plus its name.");
        Assert.Contains(CredentialPath.FromJsonPointer("/employer"), metadata.AvailablePaths!,
            "RFC 9901 Section 4.2.6: the recursive disclosure is itself addressable.");
        Assert.Contains(CredentialPath.FromJsonPointer("/employer/family_name"), metadata.AvailablePaths!,
            "RFC 9901 Section 9.3: the nested namesake sits at its own containing object's path plus its name.");
        Assert.Contains(CredentialPath.FromJsonPointer("/iss"), metadata.AvailablePaths!,
            "SD-JWT VC Section 2.2.2.3: iss cannot be selectively disclosed, so it is addressable beside the disclosures.");
        Assert.Contains(CredentialPath.FromJsonPointer("/vct"), metadata.AvailablePaths!,
            "SD-JWT VC Section 2.2.2.3: vct cannot be selectively disclosed, so it is addressable beside the disclosures.");
        Assert.HasCount(5, metadata.AvailablePaths!,
            "The credential addresses exactly its three disclosures and its two unconditionally disclosed claims.");
    }


    /// <summary>
    /// A plain SD-JWT carries no
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see> <c>vct</c>, so the extractor reports the type absent rather
    /// than inventing it — and the evaluator decides what absent evidence means for a constraint.
    /// </summary>
    [TestMethod]
    public void MetadataExtractorLeavesTypeNullWhenTheTokenCarriesNone()
    {
        using SdToken<string> token = BuildTokenWithoutTypeOrIssuer();

        DcqlCredentialMetadata metadata = SdTokenDcqlAdapter
            .CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt)(token);

        Assert.AreEqual(DcqlCredentialFormats.SdJwt, metadata.Format,
            "The metadata reports the format the extractor was built for.");
        Assert.IsNull(metadata.CredentialType,
            "Section 2.2.2.3: a credential carrying no vct declares no type, and none is invented for it.");
    }


    /// <summary>
    /// A one-component claims path pointer selects the key it names, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If the component is a string, select
    /// the element in the respective key in the currently selected element(s)."
    /// </summary>
    [TestMethod]
    public void ClaimExtractorReturnsValueForSingleSegmentMatch()
    {
        using SdToken<string> token = BuildToken();

        bool found = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("given_name"), out object? value);

        Assert.IsTrue(found,
            "Section 7.1.1: the string component selects the top-level disclosure that bears that key.");
        Assert.AreEqual("Erika", value,
            "The resolved value is the disclosure's own claim value.");
    }


    /// <summary>
    /// A pointer naming a key the credential does not carry selects nothing, and
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see> ends processing on an empty selection:
    /// "If the set of elements currently selected is empty, abort processing and return an error."
    /// </summary>
    [TestMethod]
    public void ClaimExtractorReturnsFalseForUnknownClaim()
    {
        using SdToken<string> token = BuildToken();

        bool found = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("email"), out object? value);

        Assert.IsFalse(found,
            "Section 7.1.1: a pointer whose selection is empty resolves to no claim.");
        Assert.IsNull(value,
            "A pointer that resolves to no claim yields no value.");
    }


    /// <summary>
    /// A two-segment pattern into the credential's own nested structure resolves through the
    /// recursive disclosure's path — OpenID for Verifiable Presentations 1.0 §7.1.1's string
    /// components applied one after another, each selecting within what the one before it
    /// selected.
    /// </summary>
    [TestMethod]
    public void ClaimExtractorReturnsValueForNestedTwoSegmentMatch()
    {
        using SdToken<string> token = BuildToken();

        bool found = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("employer", "family_name"), out object? value);

        Assert.IsTrue(found);
        Assert.AreEqual("Mustermann", value);
    }


    /// <summary>
    /// A two-segment pattern into a path the credential does not have does not match — multi-segment
    /// patterns are resolved by <see cref="SdTokenDcqlAdapter.ClaimExtractor{TEnvelope}"/> (see
    /// <see cref="ClaimExtractorReturnsValueForNestedTwoSegmentMatch"/> for the positive case);
    /// this pin is the negative one, not a single-segment restriction.
    /// </summary>
    [TestMethod]
    public void ClaimExtractorReturnsFalseForTwoSegmentPatternNotInCredential()
    {
        using SdToken<string> token = BuildToken();

        bool found = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("ns", "given_name"), out object? value);

        Assert.IsFalse(found);
        Assert.IsNull(value);
    }


    private static SdDisclosure CreateDisclosure(string salt, string claimName, string claimValue) =>
        SdDisclosure.CreateProperty(
            TestSalts.FromBytes(Encoding.UTF8.GetBytes(salt)),
            claimName,
            JsonDocument.Parse($"\"{claimValue}\"").RootElement);


    private static string CreateMinimalJwt(string payloadJson)
    {
        string header = /*lang=json,strict*/ """{"alg":"ES256","typ":"JWT"}""";
        string headerEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(header));
        string payloadEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));
        string fakeSignature = TestSetup.Base64UrlEncoder(new byte[64]);

        return $"{headerEncoded}.{payloadEncoded}.{fakeSignature}";
    }
}

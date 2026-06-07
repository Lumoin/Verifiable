using System.Buffers;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Focused tests for <see cref="SdTokenDcqlAdapter"/> — the format-neutral
/// DcqlEvaluator adapter over a parsed <see cref="SdToken{TEnvelope}"/>. The
/// full end-to-end evaluator path is covered by the SD-JWT / SD-CWT presentation
/// flow tests; these pin the extractor contracts directly, including the
/// single-segment / unknown-claim guard branches.
/// </summary>
[TestClass]
internal sealed class SdTokenDcqlAdapterTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;


    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the disclosures transfers to the returned SdToken, which the caller disposes via 'using'; the cascade disposes the disclosures.")]
    private static SdToken<string> BuildToken()
    {
        //An SD-JWT-shaped token with two object-property disclosures. The
        //IssuerSigned envelope is opaque to the adapter, so a placeholder string
        //suffices — the adapter reads only the disclosure list. The disclosures
        //are built inline so ownership transfers to the SdToken (which the
        //caller disposes), satisfying the dispose-ownership analyzer.
        return new SdToken<string>(
            "issuer.signed.jwt",
            [
                SdDisclosure.CreateProperty(
                    TestSalts.Generate(TestSalts.TestSaltTag, Pool), "given_name", "Erika"),
                SdDisclosure.CreateProperty(
                    TestSalts.Generate(TestSalts.TestSaltTag, Pool), "family_name", "Mustermann")
            ]);
    }


    [TestMethod]
    public void MetadataExtractorReportsFormatTypeIssuerAndAvailablePaths()
    {
        using SdToken<string> token = BuildToken();

        DcqlMetadataExtractor<SdToken<string>> extractor = SdTokenDcqlAdapter.CreateMetadataExtractor<string>(
            DcqlCredentialFormats.SdJwt, credentialType: "urn:eudi:pid:1", issuer: "https://issuer.example.com");

        DcqlCredentialMetadata metadata = extractor(token);

        Assert.AreEqual(DcqlCredentialFormats.SdJwt, metadata.Format);
        Assert.AreEqual("urn:eudi:pid:1", metadata.CredentialType);
        Assert.AreEqual("https://issuer.example.com", metadata.Issuer);
        Assert.IsNotNull(metadata.AvailablePaths);
        Assert.Contains(CredentialPath.FromJsonPointer("/given_name"), metadata.AvailablePaths!);
        Assert.Contains(CredentialPath.FromJsonPointer("/family_name"), metadata.AvailablePaths!);
        Assert.HasCount(2, metadata.AvailablePaths!);
    }


    [TestMethod]
    public void MetadataExtractorLeavesTypeAndIssuerNullForClaimsOnlyQueries()
    {
        using SdToken<string> token = BuildToken();

        DcqlCredentialMetadata metadata = SdTokenDcqlAdapter
            .CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt)(token);

        Assert.AreEqual(DcqlCredentialFormats.SdJwt, metadata.Format);
        Assert.IsNull(metadata.CredentialType);
        Assert.IsNull(metadata.Issuer);
    }


    [TestMethod]
    public void ClaimExtractorReturnsValueForSingleSegmentMatch()
    {
        using SdToken<string> token = BuildToken();

        bool found = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("given_name"), out object? value);

        Assert.IsTrue(found);
        Assert.AreEqual("Erika", value);
    }


    [TestMethod]
    public void ClaimExtractorReturnsFalseForUnknownClaim()
    {
        using SdToken<string> token = BuildToken();

        bool found = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("email"), out object? value);

        Assert.IsFalse(found);
        Assert.IsNull(value);
    }


    [TestMethod]
    public void ClaimExtractorReturnsFalseForMultiSegmentPattern()
    {
        using SdToken<string> token = BuildToken();

        //SD-* disclosures are single-segment claim names; a two-segment pattern
        //(the mdoc namespace+element shape) does not apply and must not match.
        bool found = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("ns", "given_name"), out object? value);

        Assert.IsFalse(found);
        Assert.IsNull(value);
    }
}

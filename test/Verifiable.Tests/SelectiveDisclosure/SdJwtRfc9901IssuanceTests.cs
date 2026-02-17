using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Example-based tests for SD-JWT issuance of generic claim sets per
/// <see href="https://datatracker.ietf.org/doc/rfc9901/">RFC 9901</see>.
/// </summary>
/// <remarks>
/// <para>
/// These tests exercise the <see cref="SdJwtExtensions"/> POCO-based issuance API for
/// arbitrary types serializable via <see cref="JsonSerializer"/>. No W3C Verifiable Credential
/// awareness — flat and nested claim maps only.
/// </para>
/// <para>
/// Property-based tests for the same invariants are in
/// <see cref="SdJwtRfc9901IssuancePropertyTests"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SdJwtRfc9901IssuanceTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;


    [TestMethod]
    public async Task IssueSdJwtFromFlatDictionaryProducesValidCompactJws()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "did:example:76e12ec712ebc6f1c221ebfeb1f",
            ["vct"] = "ExampleDegreeCredential",
            ["iat"] = 1725244200,
            ["given_name"] = "Alice",
            ["family_name"] = "Smith"
        };
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/given_name"),
            CredentialPath.FromJsonPointer("/family_name")
        };

        SdTokenResult result = await claims.IssueSdJwtAsync(
            disclosablePaths, SaltGenerator.Create,
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsGreaterThan(0, result.SignedToken.Length, "Signed token must not be empty.");
        Assert.HasCount(2, result.Disclosures);

        //Compact JWS has three dot-separated segments.
        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        string[] parts = compactJws.Split('.');
        Assert.HasCount(3, parts);
    }


    [TestMethod]
    public async Task IssueSdJwtFromNestedDictionaryProducesCorrectDisclosureCount()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example.com",
            ["address"] = new Dictionary<string, object>
            {
                ["street"] = "Heidestrasse 17",
                ["city"] = "Köln",
                ["country"] = "DE"
            }
        };
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/address/city"),
            CredentialPath.FromJsonPointer("/address/country")
        };

        SdTokenResult result = await claims.IssueSdJwtAsync(
            disclosablePaths, SaltGenerator.Create,
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, result.Disclosures);
        Assert.AreEqual("city", result.Disclosures[0].ClaimName);
        Assert.AreEqual("country", result.Disclosures[1].ClaimName);
    }


    [TestMethod]
    public async Task IssueSdJwtWithNoDisclosablePathsProducesZeroDisclosures()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example.com",
            ["vct"] = "IdentityCredential",
            ["iat"] = 1700000000
        };

        SdTokenResult result = await claims.IssueSdJwtAsync(
            new HashSet<CredentialPath>(), SaltGenerator.Create,
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(0, result.Disclosures);
        Assert.IsGreaterThan(0, result.SignedToken.Length, "Token must still be produced.");
    }


    [TestMethod]
    public async Task IssueSdJwtWithWholeNestedObjectDisclosesEntireSubtree()
    {
        using PrivateKeyMemory privateKey = CredentialSecuringMaterial.DecodeEd25519PrivateKey();
        var claims = new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example.com",
            ["address"] = new Dictionary<string, object>
            {
                ["street"] = "Heidestrasse 17",
                ["city"] = "Köln"
            }
        };
        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/address")
        };

        SdTokenResult result = await claims.IssueSdJwtAsync(
            disclosablePaths, SaltGenerator.Create,
            privateKey, CredentialSecuringMaterial.VerificationMethodId, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, result.Disclosures);
        Assert.AreEqual("address", result.Disclosures[0].ClaimName);
    }
}
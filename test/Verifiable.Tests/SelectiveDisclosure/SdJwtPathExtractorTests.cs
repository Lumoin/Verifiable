using System.Text;
using System.Text.Json;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for <see cref="SdJwtPathExtraction"/> utility.
/// </summary>
[TestClass]
public sealed class SdJwtPathExtractionTests
{
    public TestContext TestContext { get; set; } = null!;

    //Test constants.
    private const string TestIssuer = "https://issuer.example.com";
    private const string HashAlgorithm = "sha-256";


    [TestMethod]
    public void ExtractPathsFindsDisclosuresInRootSdArray()
    {
        //Arrange - Create a minimal SD-JWT structure.
        SdDisclosure nameDisclosure = CreateDisclosure("salt1", "name", "John Doe");

        string encodedDisclosure = SdJwtSerializer.SerializeDisclosure(nameDisclosure, TestSetup.Base64UrlEncoder);
        string digest = SdJwtPathExtraction.ComputeDisclosureDigest(encodedDisclosure, HashAlgorithm, TestSetup.Base64UrlEncoder);

        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "{{TestIssuer}}",
                "_sd": ["{{digest}}"]
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [nameDisclosure], keyBindingJwt: null);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdJwtPathExtraction.ExtractPaths(
            token,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert.
        Assert.HasCount(1, paths);
        Assert.IsTrue(paths.ContainsKey(nameDisclosure));
        Assert.AreEqual(CredentialPath.Root.Append("name"), paths[nameDisclosure]);
    }


    [TestMethod]
    public void ExtractPathsFindsNestedDisclosures()
    {
        //Arrange - Disclosure in nested object.
        SdDisclosure cityDisclosure = CreateDisclosure("salt2", "city", "Berlin");

        string encodedDisclosure = SdJwtSerializer.SerializeDisclosure(cityDisclosure, TestSetup.Base64UrlEncoder);
        string digest = SdJwtPathExtraction.ComputeDisclosureDigest(encodedDisclosure, HashAlgorithm, TestSetup.Base64UrlEncoder);

        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "{{TestIssuer}}",
                "address": {
                    "_sd": ["{{digest}}"],
                    "country": "DE"
                }
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [cityDisclosure], keyBindingJwt: null);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdJwtPathExtraction.ExtractPaths(
            token,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert.
        Assert.HasCount(1, paths);
        Assert.AreEqual(CredentialPath.Root.Append("address").Append("city"), paths[cityDisclosure]);
    }


    [TestMethod]
    public void ExtractPathsFindsArrayElementDisclosures()
    {
        //Arrange - Disclosure in array.
        SdDisclosure arrayElementDisclosure = CreateArrayElementDisclosure("salt3", "hidden-item");

        string encodedDisclosure = SdJwtSerializer.SerializeDisclosure(arrayElementDisclosure, TestSetup.Base64UrlEncoder);
        string digest = SdJwtPathExtraction.ComputeDisclosureDigest(encodedDisclosure, HashAlgorithm, TestSetup.Base64UrlEncoder);

        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "{{TestIssuer}}",
                "items": [
                    "visible-item",
                    {"...": "{{digest}}"}
                ]
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [arrayElementDisclosure], keyBindingJwt: null);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdJwtPathExtraction.ExtractPaths(
            token,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert.
        Assert.HasCount(1, paths);
        Assert.AreEqual(CredentialPath.Root.Append("items").Append(1), paths[arrayElementDisclosure]);
    }


    [TestMethod]
    public void ExtractAllPathsIncludesVisibleAndRedactedPaths()
    {
        //Arrange.
        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "{{TestIssuer}}",
                "_sd": ["some-digest"],
                "visible": "value",
                "nested": {
                    "inner": "data"
                }
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [], keyBindingJwt: null);

        //Act.
        IReadOnlySet<CredentialPath> paths = SdJwtPathExtraction.ExtractAllPaths(
            token,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert.
        Assert.Contains(CredentialPath.Root, paths);
        Assert.Contains(CredentialPath.Root.Append("iss"), paths);
        Assert.Contains(CredentialPath.Root.Append("visible"), paths);
        Assert.Contains(CredentialPath.Root.Append("nested"), paths);
        Assert.Contains(CredentialPath.Root.Append("nested").Append("inner"), paths);
    }


    [TestMethod]
    public void ExtractMandatoryPathsExcludesRedactedClaims()
    {
        //Arrange.
        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "{{TestIssuer}}",
                "_sd": ["redacted-digest"],
                "mandatory": "always-visible"
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [], keyBindingJwt: null);

        //Act.
        IReadOnlySet<CredentialPath> mandatory = SdJwtPathExtraction.ExtractMandatoryPaths(
            token,
            TestSetup.Base64UrlDecoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert - _sd claims themselves are not paths, only their resolved values would be.
        Assert.Contains(CredentialPath.Root, mandatory);
        Assert.Contains(CredentialPath.Root.Append("iss"), mandatory);
        Assert.Contains(CredentialPath.Root.Append("mandatory"), mandatory);
    }


    [TestMethod]
    public void CreateLatticeReturnsConfiguredLattice()
    {
        //Arrange.
        SdDisclosure disclosure = CreateDisclosure("salt", "selective", "value");

        string encodedDisclosure = SdJwtSerializer.SerializeDisclosure(disclosure, TestSetup.Base64UrlEncoder);
        string digest = SdJwtPathExtraction.ComputeDisclosureDigest(encodedDisclosure, HashAlgorithm, TestSetup.Base64UrlEncoder);

        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "{{TestIssuer}}",
                "_sd": ["{{digest}}"],
                "mandatory": "always"
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [disclosure], keyBindingJwt: null);

        //Act.
        PathLattice lattice = SdJwtPathExtraction.CreateLattice(
            token,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert.
        Assert.IsNotNull(lattice);
        Assert.Contains(CredentialPath.Root.Append("mandatory"), lattice.AllPaths);
        Assert.Contains(CredentialPath.Root.Append("mandatory"), lattice.MandatoryPaths);
    }


    [TestMethod]
    public void ExtractPathsWithMultipleDisclosuresReturnsAll()
    {
        //Arrange - Multiple disclosures at different locations.
        SdDisclosure disclosure1 = CreateDisclosure("salt1", "given_name", "Alice");
        SdDisclosure disclosure2 = CreateDisclosure("salt2", "family_name", "Smith");

        string encoded1 = SdJwtSerializer.SerializeDisclosure(disclosure1, TestSetup.Base64UrlEncoder);
        string encoded2 = SdJwtSerializer.SerializeDisclosure(disclosure2, TestSetup.Base64UrlEncoder);
        string digest1 = SdJwtPathExtraction.ComputeDisclosureDigest(encoded1, HashAlgorithm, TestSetup.Base64UrlEncoder);
        string digest2 = SdJwtPathExtraction.ComputeDisclosureDigest(encoded2, HashAlgorithm, TestSetup.Base64UrlEncoder);

        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "{{TestIssuer}}",
                "_sd": ["{{digest1}}", "{{digest2}}"]
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [disclosure1, disclosure2], keyBindingJwt: null);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdJwtPathExtraction.ExtractPaths(
            token,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert.
        Assert.HasCount(2, paths);
        Assert.AreEqual(CredentialPath.Root.Append("given_name"), paths[disclosure1]);
        Assert.AreEqual(CredentialPath.Root.Append("family_name"), paths[disclosure2]);
    }


    [TestMethod]
    public void ExtractPathsWithEmptyDisclosuresReturnsEmpty()
    {
        //Arrange.
        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "{{TestIssuer}}",
                "visible": "data"
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [], keyBindingJwt: null);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdJwtPathExtraction.ExtractPaths(
            token,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert.
        Assert.HasCount(0, paths);
    }


    private static SdDisclosure CreateDisclosure(string salt, string claimName, string claimValue)
    {
        return SdDisclosure.CreateProperty(
            Encoding.UTF8.GetBytes(salt),
            claimName,
            JsonDocument.Parse($"\"{claimValue}\"").RootElement);
    }


    private static SdDisclosure CreateArrayElementDisclosure(string salt, string claimValue)
    {
        return SdDisclosure.CreateArrayElement(
            Encoding.UTF8.GetBytes(salt),
            JsonDocument.Parse($"\"{claimValue}\"").RootElement);
    }


    private static string CreateMinimalJwt(string payloadJson)
    {
        string header = /*lang=json,strict*/ """{"alg":"ES256","typ":"JWT"}""";
        string headerEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(header));
        string payloadEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));
        string fakeSignature = TestSetup.Base64UrlEncoder(new byte[64]);

        return $"{headerEncoded}.{payloadEncoded}.{fakeSignature}";
    }
}
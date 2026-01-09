using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Disclosure;
using Verifiable.Cryptography;
using Verifiable.JCose.Sd;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.Utilities;

namespace Verifiable.Tests.Sd;

/// <summary>
/// Tests for <see cref="SdJwtPathExtractor"/> utility.
/// </summary>
[TestClass]
public sealed class SdJwtPathExtractorTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void ExtractPathsFindsDisclosuresInRootSdArray()
    {
        //Arrange - Create a minimal SD-JWT structure.
        SdDisclosure nameDisclosure = SdDisclosure.CreateProperty(
            Encoding.UTF8.GetBytes("salt1"),
            "name",
            JsonDocument.Parse(/*lang=json,strict*/ "\"John Doe\"").RootElement);

        string encodedDisclosure = SdJwtSerializer.SerializeDisclosure(nameDisclosure, TestSetup.Base64UrlEncoder);
        string digest = ComputeSha256Digest(encodedDisclosure);

        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "https://issuer.example.com",
                "_sd": ["{{digest}}"]
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [nameDisclosure], keyBindingJwt: null);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdJwtPathExtractor.ExtractPaths(
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
        SdDisclosure cityDisclosure = SdDisclosure.CreateProperty(
            Encoding.UTF8.GetBytes("salt2"),
            "city",
            JsonDocument.Parse(/*lang=json,strict*/ "\"Berlin\"").RootElement);

        string encodedDisclosure = SdJwtSerializer.SerializeDisclosure(cityDisclosure, TestSetup.Base64UrlEncoder);
        string digest = ComputeSha256Digest(encodedDisclosure);

        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "https://issuer.example.com",
                "address": {
                    "_sd": ["{{digest}}"],
                    "country": "DE"
                }
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [cityDisclosure], keyBindingJwt: null);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdJwtPathExtractor.ExtractPaths(
            token,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert.
        Assert.HasCount(1, paths);
        CredentialPath expectedPath = CredentialPath.Root.Append("address").Append("city");
        Assert.AreEqual(expectedPath, paths[cityDisclosure]);
    }


    [TestMethod]
    public void ExtractPathsFindsArrayElementDisclosures()
    {
        //Arrange - Disclosure in array.
        SdDisclosure arrayElementDisclosure = SdDisclosure.CreateArrayElement(
            Encoding.UTF8.GetBytes("salt3"),
            JsonDocument.Parse(/*lang=json,strict*/ "\"hidden-item\"").RootElement);

        string encodedDisclosure = SdJwtSerializer.SerializeDisclosure(arrayElementDisclosure, TestSetup.Base64UrlEncoder);
        string digest = ComputeSha256Digest(encodedDisclosure);

        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "https://issuer.example.com",
                "items": [
                    "visible-item",
                    {"...": "{{digest}}"}
                ]
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [arrayElementDisclosure], keyBindingJwt: null);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdJwtPathExtractor.ExtractPaths(
            token,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert.
        Assert.HasCount(1, paths);
        CredentialPath expectedPath = CredentialPath.Root.Append("items").Append(1);
        Assert.AreEqual(expectedPath, paths[arrayElementDisclosure]);
    }


    [TestMethod]
    public void ExtractAllPathsIncludesVisibleAndRedactedPaths()
    {
        //Arrange.
        string payloadJson = /*lang=json,strict*/ """
            {
                "_sd_alg": "sha-256",
                "iss": "https://issuer.example.com",
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
        IReadOnlySet<CredentialPath> paths = SdJwtPathExtractor.ExtractAllPaths(
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
        string payloadJson = /*lang=json,strict*/ """
            {
                "_sd_alg": "sha-256",
                "iss": "https://issuer.example.com",
                "_sd": ["redacted-digest"],
                "mandatory": "always-visible"
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [], keyBindingJwt: null);

        //Act.
        IReadOnlySet<CredentialPath> mandatory = SdJwtPathExtractor.ExtractMandatoryPaths(
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
        SdDisclosure disclosure = SdDisclosure.CreateProperty(
            Encoding.UTF8.GetBytes("salt"),
            "selective",
            JsonDocument.Parse(/*lang=json,strict*/ "\"value\"").RootElement);

        string encodedDisclosure = SdJwtSerializer.SerializeDisclosure(disclosure, TestSetup.Base64UrlEncoder);
        string digest = ComputeSha256Digest(encodedDisclosure);

        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "https://issuer.example.com",
                "_sd": ["{{digest}}"],
                "mandatory": "always"
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [disclosure], keyBindingJwt: null);

        //Act.
        PathLattice lattice = SdJwtPathExtractor.CreateLattice(
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
        SdDisclosure disclosure1 = SdDisclosure.CreateProperty(
            Encoding.UTF8.GetBytes("salt1"),
            "given_name",
            JsonDocument.Parse(/*lang=json,strict*/ "\"Alice\"").RootElement);

        SdDisclosure disclosure2 = SdDisclosure.CreateProperty(
            Encoding.UTF8.GetBytes("salt2"),
            "family_name",
            JsonDocument.Parse(/*lang=json,strict*/ "\"Smith\"").RootElement);

        string encoded1 = SdJwtSerializer.SerializeDisclosure(disclosure1, TestSetup.Base64UrlEncoder);
        string encoded2 = SdJwtSerializer.SerializeDisclosure(disclosure2, TestSetup.Base64UrlEncoder);
        string digest1 = ComputeSha256Digest(encoded1);
        string digest2 = ComputeSha256Digest(encoded2);

        string payloadJson = /*lang=json,strict*/ $$"""
            {
                "_sd_alg": "sha-256",
                "iss": "https://issuer.example.com",
                "_sd": ["{{digest1}}", "{{digest2}}"]
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [disclosure1, disclosure2], keyBindingJwt: null);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdJwtPathExtractor.ExtractPaths(
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
        string payloadJson = /*lang=json,strict*/ """
            {
                "_sd_alg": "sha-256",
                "iss": "https://issuer.example.com",
                "visible": "data"
            }
            """;

        string jwt = CreateMinimalJwt(payloadJson);
        var token = new SdJwtToken(jwt, [], keyBindingJwt: null);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdJwtPathExtractor.ExtractPaths(
            token,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        //Assert.
        Assert.HasCount(0, paths);
    }


    private static string CreateMinimalJwt(string payloadJson)
    {
        string header = /*lang=json,strict*/ """{"alg":"ES256","typ":"JWT"}""";
        string headerEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(header));
        string payloadEncoded = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));
        string fakeSignature = TestSetup.Base64UrlEncoder(new byte[64]);

        return $"{headerEncoded}.{payloadEncoded}.{fakeSignature}";
    }


    private static string ComputeSha256Digest(string encodedDisclosure)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(encodedDisclosure);
        byte[] hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return TestSetup.Base64UrlEncoder(hash);
    }
}
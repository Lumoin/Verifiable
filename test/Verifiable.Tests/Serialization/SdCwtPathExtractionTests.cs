using System.Formats.Cbor;
using System.Text;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Tests.SelectiveDisclosure;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Tests for <see cref="SdCwtPathExtraction"/> utility.
/// </summary>
/// <remarks>
/// <para>
/// These tests use CBOR-native value types (strings, integers) for disclosure values
/// rather than <see cref="System.Text.Json.JsonElement"/> because CBOR serialization
/// does not support JsonElement. The JSON counterpart tests in <see cref="SdJwtPathExtractionTests"/>
/// use JsonElement values which are appropriate for JSON serialization.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SdCwtPathExtractionTests
{
    /// <summary>
    /// The test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A test issuer.
    /// </summary>
    private const string TestIssuer = "https://issuer.example.com";

    /// <summary>
    /// The hash algorithm used for disclosure digests.
    /// </summary>
    private const string HashAlgorithm = "sha-256";


    [TestMethod]
    public void ExtractPathsFindsDisclosuresInRootSdArray()
    {
        //A minimal SD-CWT structure.
        SdDisclosure nameDisclosure = CreateCborDisclosure("salt1", "name", "John Doe");

        byte[] disclosureCbor = SdCwtSerializer.SerializeDisclosure(nameDisclosure);
        byte[] digest = SdCwtSerializer.ComputeDisclosureDigest(disclosureCbor, HashAlgorithm);
        string digestBase64 = TestSetup.Base64UrlEncoder(digest);

        byte[] payload = CreateCwtPayloadWithDigests([digestBase64]);
        SdCwtMessage message = CreateMinimalSdCwt(payload, [nameDisclosure]);
        
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdCwtPathExtraction.ExtractPaths(
            message,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);
        
        Assert.HasCount(1, paths);
        Assert.IsTrue(paths.ContainsKey(nameDisclosure));
        Assert.AreEqual(CredentialPath.Root.Append("name"), paths[nameDisclosure]);
    }


    [TestMethod]
    public void ExtractAllPathsIncludesVisiblePaths()
    {        
        byte[] payload = CreateSimpleCwtPayload();
        SdCwtMessage message = CreateMinimalSdCwt(payload, []);
        
        IReadOnlySet<CredentialPath> paths = SdCwtPathExtraction.ExtractAllPaths(message, SensitiveMemoryPool<byte>.Shared);
        
        Assert.Contains(CredentialPath.Root, paths);
    }


    [TestMethod]
    public void ExtractMandatoryPathsReturnsVisibleClaims()
    {        
        byte[] payload = CreateSimpleCwtPayload();
        SdCwtMessage message = CreateMinimalSdCwt(payload, []);
        
        IReadOnlySet<CredentialPath> mandatory = SdCwtPathExtraction.ExtractMandatoryPaths(
            message,
            SensitiveMemoryPool<byte>.Shared);
        
        Assert.Contains(CredentialPath.Root, mandatory);
    }


    [TestMethod]
    public void CreateLatticeReturnsConfiguredLattice()
    {        
        SdDisclosure disclosure = CreateCborDisclosure("salt", "selective", "value");

        byte[] disclosureCbor = SdCwtSerializer.SerializeDisclosure(disclosure);
        byte[] digest = SdCwtSerializer.ComputeDisclosureDigest(disclosureCbor, HashAlgorithm);
        string digestBase64 = TestSetup.Base64UrlEncoder(digest);

        byte[] payload = CreateCwtPayloadWithDigests([digestBase64]);
        SdCwtMessage message = CreateMinimalSdCwt(payload, [disclosure]);
        
        PathLattice lattice = SdCwtPathExtraction.CreateLattice(
            message,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        Assert.IsNotNull(lattice);
    }


    [TestMethod]
    public void ExtractPathsWithEmptyDisclosuresReturnsEmpty()
    {        
        byte[] payload = CreateSimpleCwtPayload();
        SdCwtMessage message = CreateMinimalSdCwt(payload, []);

        //Act.
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdCwtPathExtraction.ExtractPaths(
            message,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);
        
        Assert.HasCount(0, paths);
    }


    [TestMethod]
    public void ExtractPathsWithMultipleDisclosuresReturnsAll()
    {        
        SdDisclosure disclosure1 = CreateCborDisclosure("salt1", "given_name", "Alice");
        SdDisclosure disclosure2 = CreateCborDisclosure("salt2", "family_name", "Smith");

        byte[] cbor1 = SdCwtSerializer.SerializeDisclosure(disclosure1);
        byte[] cbor2 = SdCwtSerializer.SerializeDisclosure(disclosure2);
        string digest1 = TestSetup.Base64UrlEncoder(SdCwtSerializer.ComputeDisclosureDigest(cbor1, HashAlgorithm));
        string digest2 = TestSetup.Base64UrlEncoder(SdCwtSerializer.ComputeDisclosureDigest(cbor2, HashAlgorithm));

        byte[] payload = CreateCwtPayloadWithMultipleDigests([digest1, digest2]);
        SdCwtMessage message = CreateMinimalSdCwt(payload, [disclosure1, disclosure2]);
        
        IReadOnlyDictionary<SdDisclosure, CredentialPath> paths = SdCwtPathExtraction.ExtractPaths(
            message,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);
        
        Assert.HasCount(2, paths);
        Assert.AreEqual(CredentialPath.Root.Append("given_name"), paths[disclosure1]);
        Assert.AreEqual(CredentialPath.Root.Append("family_name"), paths[disclosure2]);
    }


    /// <summary>
    /// Creates an SD disclosure with CBOR-compatible value types.
    /// </summary>
    /// <remarks>
    /// Unlike the JSON tests which use <see cref="System.Text.Json.JsonElement"/>,
    /// CBOR tests must use native types that <see cref="CborValueConverter"/> supports.
    /// </remarks>
    private static SdDisclosure CreateCborDisclosure(string salt, string claimName, object claimValue)
    {
        return SdDisclosure.CreateProperty(
            Encoding.UTF8.GetBytes(salt),
            claimName,
            claimValue);
    }


    private static SdCwtMessage CreateMinimalSdCwt(byte[] payload, IReadOnlyList<SdDisclosure> disclosures)
    {
        //Create minimal protected header with algorithm.
        var headerWriter = new CborWriter(CborConformanceMode.Canonical);
        headerWriter.WriteStartMap(1);
        headerWriter.WriteInt32(CoseHeaderParameters.Alg);
        headerWriter.WriteInt32(WellKnownCoseAlgorithms.Es256);
        headerWriter.WriteEndMap();
        byte[] protectedHeader = headerWriter.Encode();

        //Create fake signature (64 bytes for ES256).
        byte[] signature = new byte[64];

        return new SdCwtMessage(payload, protectedHeader, signature, disclosures.ToList());
    }


    private static byte[] CreateSimpleCwtPayload()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(SdCwtConstants.IssClaimKey);
        writer.WriteTextString(TestIssuer);
        writer.WriteEndMap();
        return writer.Encode();
    }


    private static byte[] CreateCwtPayloadWithDigests(string[] digests)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(3);

        //iss claim.
        writer.WriteInt32(SdCwtConstants.IssClaimKey);
        writer.WriteTextString(TestIssuer);

        //_sd array.
        writer.WriteInt32(CoseHeaderParameters.SdClaims);
        writer.WriteStartArray(digests.Length);
        foreach(string digest in digests)
        {
            writer.WriteTextString(digest);
        }
        writer.WriteEndArray();

        //A visible claim for structure.
        writer.WriteTextString("visible");
        writer.WriteTextString("data");

        writer.WriteEndMap();
        return writer.Encode();
    }


    private static byte[] CreateCwtPayloadWithMultipleDigests(string[] digests)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(2);

        //iss claim.
        writer.WriteInt32(SdCwtConstants.IssClaimKey);
        writer.WriteTextString(TestIssuer);

        //_sd array.
        writer.WriteInt32(CoseHeaderParameters.SdClaims);
        writer.WriteStartArray(digests.Length);
        foreach(string digest in digests)
        {
            writer.WriteTextString(digest);
        }
        writer.WriteEndArray();
        writer.WriteEndMap();

        return writer.Encode();
    }
}
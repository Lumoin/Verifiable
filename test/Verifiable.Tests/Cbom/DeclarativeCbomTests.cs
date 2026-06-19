using System.Linq;
using System.Text.Json;
using Verifiable.Cryptography.Cbom;

namespace Verifiable.Tests.Cbom;

/// <summary>
/// Tests for the declarative ("capabilities") CBOM. The capabilities view enumerates
/// every cryptographic asset the library can describe from the registry, independent of
/// which backend provider happens to be wired.
/// </summary>
/// <remarks>
/// <para>
/// Assertions parse the emitted CycloneDX JSON with <see cref="System.Text.Json"/> rather
/// than reflecting over the model, exercising the same serialization path the CLI and MCP
/// server use (<see cref="CbomJsonRenderer"/>).
/// </para>
/// </remarks>
[TestClass]
internal sealed class DeclarativeCbomTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void DeclarativeCbomIsValidCycloneDxWithCryptographicAssets()
    {
        CbomDocument document = DeclarativeCbomGenerator.Generate("2026-06-18T00:00:00Z", "1.2.3");
        string json = CbomJsonRenderer.Render(document);

        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement root = parsed.RootElement;

        Assert.AreEqual("CycloneDX", root.GetProperty("bomFormat").GetString(),
            "The BOM must declare bomFormat 'CycloneDX'.");
        Assert.AreEqual("1.6", root.GetProperty("specVersion").GetString(),
            "The BOM must declare specVersion '1.6'.");

        JsonElement components = root.GetProperty("components");
        Assert.IsGreaterThan(0, components.GetArrayLength(),
            "The declarative CBOM must contain components.");

        foreach(JsonElement component in components.EnumerateArray())
        {
            Assert.AreEqual("cryptographic-asset", component.GetProperty("type").GetString(),
                "Every CBOM component must be a cryptographic-asset.");
        }
    }


    [TestMethod]
    public void DeclarativeCbomDescribesEd25519AndP256SignatureAlgorithms()
    {
        CbomDocument document = DeclarativeCbomGenerator.Generate("2026-06-18T00:00:00Z", "1.2.3");
        string json = CbomJsonRenderer.Render(document);

        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement components = parsed.RootElement.GetProperty("components");

        JsonElement ed25519 = FindAlgorithmByName(components, "Ed25519");
        Assert.AreEqual("signature",
            ed25519.GetProperty("cryptoProperties").GetProperty("algorithmProperties").GetProperty("primitive").GetString(),
            "Ed25519 must be a signature algorithm asset.");

        JsonElement p256 = FindAlgorithmByName(components, "P-256");
        Assert.AreEqual("signature",
            p256.GetProperty("cryptoProperties").GetProperty("algorithmProperties").GetProperty("primitive").GetString(),
            "ECDSA P-256 must be a signature algorithm asset.");
        Assert.AreEqual("P-256",
            p256.GetProperty("cryptoProperties").GetProperty("algorithmProperties").GetProperty("curve").GetString(),
            "The P-256 algorithm asset must carry its curve.");
    }


    [TestMethod]
    public void DeclarativeCbomMlDsaComponentsCarryNistQuantumSecurityLevel()
    {
        CbomDocument document = DeclarativeCbomGenerator.Generate("2026-06-18T00:00:00Z", "1.2.3");
        string json = CbomJsonRenderer.Render(document);

        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement components = parsed.RootElement.GetProperty("components");

        string[] mlDsaNames = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
        foreach(string name in mlDsaNames)
        {
            JsonElement component = FindAlgorithmByName(components, name);
            JsonElement algorithmProperties =
                component.GetProperty("cryptoProperties").GetProperty("algorithmProperties");

            Assert.IsTrue(
                algorithmProperties.TryGetProperty("nistQuantumSecurityLevel", out JsonElement nistLevel),
                $"{name} must carry a nistQuantumSecurityLevel.");
            Assert.AreNotEqual(JsonValueKind.Null, nistLevel.ValueKind,
                $"{name} nistQuantumSecurityLevel must be non-null.");
            Assert.IsGreaterThan(0, nistLevel.GetInt32(),
                $"{name} nistQuantumSecurityLevel must be a positive NIST category.");
        }
    }


    [TestMethod]
    public void DeclarativeCbomComponentBomRefsAreUnique()
    {
        CbomDocument document = DeclarativeCbomGenerator.Generate("2026-06-18T00:00:00Z", "1.2.3");
        string json = CbomJsonRenderer.Render(document);

        using JsonDocument parsed = JsonDocument.Parse(json);
        JsonElement components = parsed.RootElement.GetProperty("components");

        string[] bomRefs = components.EnumerateArray()
            .Select(c => c.GetProperty("bom-ref").GetString()!)
            .ToArray();

        string[] distinctRefs = bomRefs.Distinct(System.StringComparer.Ordinal).ToArray();

        Assert.HasCount(bomRefs.Length, distinctRefs,
            "Every component bom-ref must be unique.");
    }


    private static JsonElement FindAlgorithmByName(JsonElement components, string name)
    {
        foreach(JsonElement component in components.EnumerateArray())
        {
            if(string.Equals(component.GetProperty("name").GetString(), name, System.StringComparison.Ordinal)
                && component.GetProperty("cryptoProperties").GetProperty("assetType").GetString() == "algorithm")
            {
                return component;
            }
        }

        Assert.Fail($"No algorithm component named '{name}' was found in the declarative CBOM.");
        return default;
    }
}

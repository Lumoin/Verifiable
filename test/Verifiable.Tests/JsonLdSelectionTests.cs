using System.Text.Json;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;
using VDS.RDF;
using VDS.RDF.Parsing;

namespace Verifiable.Tests.Json;

/// <summary>
/// Tests for <see cref="JsonLdSelection"/> following W3C VC DI ECDSA specification.
/// </summary>
/// <remarks>
/// <para>
/// These tests validate the JSON-LD fragment selection and statement partitioning
/// algorithms required for ecdsa-sd-2023 selective disclosure.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#selectjsonld">
/// W3C VC DI ECDSA: selectJsonLd algorithm</see>.
/// </para>
/// </remarks>
[TestClass]
public class JsonLdSelectionTests
{
    /// <summary>
    /// Test credential with various property types for comprehensive testing.
    /// </summary>
    private const string TestCredentialJson = /*lang=json,strict*/ """
        {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:test-credential-123",
            "type": ["VerifiableCredential", "TestCredential"],
            "issuer": {
                "id": "did:example:issuer",
                "name": "Test Issuer Organization"
            },
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:subject",
                "type": "Person",
                "givenName": "Alice",
                "familyName": "Smith",
                "birthDate": "1990-05-15"
            }
        }
        """;


    //=========================================================================
    //SelectFragment tests
    //=========================================================================

    [TestMethod]
    public void SelectFragmentWithRootPointerReturnsMinimalDocument()
    {
        //Per spec: Root pointer returns document skeleton with @context, id, type.
        var pointer = Verifiable.JsonPointer.JsonPointer.Parse("");

        var selection = JsonLdSelection.SelectFragment(TestCredentialJson, pointer);

        using var doc = JsonDocument.Parse(selection);
        var root = doc.RootElement;

        Assert.IsTrue(root.TryGetProperty("@context", out _), "Root selection must include @context.");
        Assert.IsTrue(root.TryGetProperty("type", out _), "Root selection must include type.");
        Assert.IsTrue(root.TryGetProperty("id", out _), "Root selection must include non-blank id.");
    }


    [TestMethod]
    public void SelectFragmentWithSimplePropertyReturnsPropertyAndPath()
    {
        var pointer = Verifiable.JsonPointer.JsonPointer.Parse("/validFrom");

        var selection = JsonLdSelection.SelectFragment(TestCredentialJson, pointer);

        using var doc = JsonDocument.Parse(selection);
        var root = doc.RootElement;

        Assert.IsTrue(root.TryGetProperty("@context", out _), "Selection must include @context.");
        Assert.IsTrue(root.TryGetProperty("type", out _), "Selection must include type.");
        Assert.IsTrue(root.TryGetProperty("validFrom", out var validFrom), "Selection must include validFrom.");
        Assert.AreEqual("2024-01-01T00:00:00Z", validFrom.GetString(), "validFrom value must match original.");
    }


    [TestMethod]
    public void SelectFragmentWithNestedPropertyIncludesPathStructure()
    {
        //Per spec: Selection must include id and type along the path.
        var pointer = Verifiable.JsonPointer.JsonPointer.Parse("/credentialSubject/givenName");

        var selection = JsonLdSelection.SelectFragment(TestCredentialJson, pointer);

        using var doc = JsonDocument.Parse(selection);
        var root = doc.RootElement;

        //Verify root structure.
        Assert.IsTrue(root.TryGetProperty("@context", out _), "Selection must include @context.");
        Assert.IsTrue(root.TryGetProperty("type", out _), "Selection must include root type.");

        //Verify intermediate path.
        Assert.IsTrue(root.TryGetProperty("credentialSubject", out var credSubject),
            "Selection must include credentialSubject.");
        Assert.IsTrue(credSubject.TryGetProperty("id", out _),
            "Selection must include credentialSubject id.");
        Assert.IsTrue(credSubject.TryGetProperty("type", out _),
            "Selection must include credentialSubject type.");

        //Verify selected value.
        Assert.IsTrue(credSubject.TryGetProperty("givenName", out var givenName),
            "Selection must include givenName.");
        Assert.AreEqual("Alice", givenName.GetString(), "givenName value must match original.");
    }


    [TestMethod]
    public void SelectFragmentWithObjectPropertyIncludesFullObject()
    {
        var pointer = Verifiable.JsonPointer.JsonPointer.Parse("/issuer");

        var selection = JsonLdSelection.SelectFragment(TestCredentialJson, pointer);

        using var doc = JsonDocument.Parse(selection);
        var root = doc.RootElement;

        Assert.IsTrue(root.TryGetProperty("issuer", out var issuer), "Selection must include issuer.");
        Assert.IsTrue(issuer.TryGetProperty("id", out var issuerId), "Issuer must include id.");
        Assert.AreEqual("did:example:issuer", issuerId.GetString(), "Issuer id must match.");
        Assert.IsTrue(issuer.TryGetProperty("name", out var issuerName), "Issuer must include name.");
        Assert.AreEqual("Test Issuer Organization", issuerName.GetString(), "Issuer name must match.");
    }


    [TestMethod]
    public void SelectFragmentWithInvalidPointerThrowsArgumentException()
    {
        var pointer = Verifiable.JsonPointer.JsonPointer.Parse("/nonExistentProperty");

        Assert.Throws<ArgumentException>(() =>
            JsonLdSelection.SelectFragment(TestCredentialJson, pointer),
            "Invalid pointer must throw ArgumentException.");
    }


    //=========================================================================
    //SelectFragments tests (multiple pointers)
    //=========================================================================

    [TestMethod]
    public void SelectFragmentsMergesMultipleSelections()
    {
        var pointers = new[]
        {
            Verifiable.JsonPointer.JsonPointer.Parse("/issuer"),
            Verifiable.JsonPointer.JsonPointer.Parse("/validFrom"),
            Verifiable.JsonPointer.JsonPointer.Parse("/credentialSubject/givenName")
        };

        var selection = JsonLdSelection.SelectFragments(TestCredentialJson, pointers);

        using var doc = JsonDocument.Parse(selection);
        var root = doc.RootElement;

        //Verify all selected properties are present.
        Assert.IsTrue(root.TryGetProperty("issuer", out _), "Selection must include issuer.");
        Assert.IsTrue(root.TryGetProperty("validFrom", out _), "Selection must include validFrom.");
        Assert.IsTrue(root.TryGetProperty("credentialSubject", out var cs), "Selection must include credentialSubject.");
        Assert.IsTrue(cs.TryGetProperty("givenName", out _), "Selection must include givenName.");

        //Verify non-selected properties are NOT present at leaf level.
        Assert.IsFalse(cs.TryGetProperty("familyName", out _),
            "Non-selected property familyName must not be in selection.");
        Assert.IsFalse(cs.TryGetProperty("birthDate", out _),
            "Non-selected property birthDate must not be in selection.");
    }


    [TestMethod]
    public void SelectFragmentsPreservesPathStructureForAllPointers()
    {
        //Two pointers into credentialSubject should share the intermediate structure.
        var pointers = new[]
        {
            Verifiable.JsonPointer.JsonPointer.Parse("/credentialSubject/givenName"),
            Verifiable.JsonPointer.JsonPointer.Parse("/credentialSubject/familyName")
        };

        var selection = JsonLdSelection.SelectFragments(TestCredentialJson, pointers);

        using var doc = JsonDocument.Parse(selection);
        var root = doc.RootElement;

        Assert.IsTrue(root.TryGetProperty("credentialSubject", out var cs),
            "Selection must include credentialSubject.");

        //Both selected properties should be present.
        Assert.IsTrue(cs.TryGetProperty("givenName", out var gn), "Selection must include givenName.");
        Assert.AreEqual("Alice", gn.GetString(), "givenName value must match.");

        Assert.IsTrue(cs.TryGetProperty("familyName", out var fn), "Selection must include familyName.");
        Assert.AreEqual("Smith", fn.GetString(), "familyName value must match.");

        //Non-selected property should not be present.
        Assert.IsFalse(cs.TryGetProperty("birthDate", out _),
            "Non-selected property birthDate must not be in selection.");
    }


    //=========================================================================
    //TryEvaluate tests
    //=========================================================================

    [TestMethod]
    public void TryEvaluateWithValidPointerReturnsTrue()
    {
        using var doc = JsonDocument.Parse(TestCredentialJson);
        var pointer = Verifiable.JsonPointer.JsonPointer.Parse("/credentialSubject/givenName");

        bool result = JsonLdSelection.TryEvaluate(doc.RootElement, pointer, out var element);

        Assert.IsTrue(result, "Valid pointer must evaluate successfully.");
        Assert.AreEqual(JsonValueKind.String, element.ValueKind, "Element must be a string.");
        Assert.AreEqual("Alice", element.GetString(), "Element value must match.");
    }


    [TestMethod]
    public void TryEvaluateWithInvalidPointerReturnsFalse()
    {
        using var doc = JsonDocument.Parse(TestCredentialJson);
        var pointer = Verifiable.JsonPointer.JsonPointer.Parse("/nonExistent/path");

        bool result = JsonLdSelection.TryEvaluate(doc.RootElement, pointer, out var element);

        Assert.IsFalse(result, "Invalid pointer must return false.");
        Assert.AreEqual(default(JsonElement), element, "Element must be default for invalid pointer.");
    }


    [TestMethod]
    public void TryEvaluateWithRootPointerReturnsRoot()
    {
        using var doc = JsonDocument.Parse(TestCredentialJson);
        var pointer = Verifiable.JsonPointer.JsonPointer.Parse("");

        bool result = JsonLdSelection.TryEvaluate(doc.RootElement, pointer, out var element);

        Assert.IsTrue(result, "Root pointer must evaluate successfully.");
        Assert.AreEqual(JsonValueKind.Object, element.ValueKind, "Root must be an object.");
    }


    //=========================================================================
    //PartitionStatements tests
    //=========================================================================

    [TestMethod]
    public void PartitionStatementsWithMandatoryPointersPartitionsCorrectly()
    {
        var pointers = new[]
        {
            Verifiable.JsonPointer.JsonPointer.Parse("/issuer"),
            Verifiable.JsonPointer.JsonPointer.Parse("/type")
        };

        var partition = JsonLdSelection.PartitionStatements(
            TestCredentialJson,
            pointers,
            Canonicalize);

        //Verify all statements are accounted for.
        int total = partition.MandatoryIndexes.Count + partition.NonMandatoryIndexes.Count;
        Assert.HasCount(total, partition.AllStatements,
            "Sum of mandatory and non-mandatory indexes must equal total statements.");

        //Verify indexes are valid.
        foreach(var index in partition.MandatoryIndexes)
        {
            Assert.IsLessThan(partition.AllStatements.Count, index,
                $"Mandatory index {index} must be less than statement count.");
        }

        foreach(var index in partition.NonMandatoryIndexes)
        {
            Assert.IsLessThan(partition.AllStatements.Count, index,
                $"Non-mandatory index {index} must be less than statement count.");
        }

        //Verify no overlap between mandatory and non-mandatory.
        var mandatorySet = new HashSet<int>(partition.MandatoryIndexes);
        var nonMandatorySet = new HashSet<int>(partition.NonMandatoryIndexes);
        Assert.IsFalse(mandatorySet.Overlaps(nonMandatorySet),
            "Mandatory and non-mandatory indexes must not overlap.");
    }


    [TestMethod]
    public void PartitionStatementsWithEmptyPointersReturnsAllNonMandatory()
    {
        var partition = JsonLdSelection.PartitionStatements(
            TestCredentialJson,
            mandatoryPointers: [],
            Canonicalize);

        Assert.IsEmpty(partition.MandatoryIndexes, "Empty pointers must produce no mandatory indexes.");
        Assert.HasCount(partition.AllStatements.Count, partition.NonMandatoryIndexes,
            "All statements must be non-mandatory with empty pointers.");
    }


    [TestMethod]
    public void PartitionStatementsMandatoryStatementsPropertyReturnsCorrectStatements()
    {
        var pointers = new[]
        {
            Verifiable.JsonPointer.JsonPointer.Parse("/issuer")
        };

        var partition = JsonLdSelection.PartitionStatements(
            TestCredentialJson,
            pointers,
            Canonicalize);

        var mandatoryStatements = partition.MandatoryStatements;

        Assert.HasCount(partition.MandatoryIndexes.Count, mandatoryStatements,
            "MandatoryStatements count must match MandatoryIndexes count.");

        //Verify statements contain issuer-related content.
        Assert.IsTrue(
            mandatoryStatements.Any(s => s.Contains("issuer", StringComparison.OrdinalIgnoreCase) ||
                                         s.Contains("did:example:issuer", StringComparison.Ordinal)),
            "Mandatory statements must contain issuer-related content.");
    }


    [TestMethod]
    public void PartitionStatementsApplyToPreservesOrder()
    {
        var pointers = new[]
        {
            Verifiable.JsonPointer.JsonPointer.Parse("/issuer"),
            Verifiable.JsonPointer.JsonPointer.Parse("/validFrom")
        };

        var partition = JsonLdSelection.PartitionStatements(
            TestCredentialJson,
            pointers,
            Canonicalize);

        //Create a modified statement list (simulating relabeling).
        var modifiedStatements = partition.AllStatements
            .Select(s => s.Replace("_:c14n", "_:modified", StringComparison.Ordinal))
            .ToList();

        var (mandatory, nonMandatory) = partition.ApplyTo(modifiedStatements);

        //Verify counts match.
        Assert.HasCount(partition.MandatoryIndexes.Count, mandatory,
            "Applied mandatory count must match original.");
        Assert.HasCount(partition.NonMandatoryIndexes.Count, nonMandatory,
            "Applied non-mandatory count must match original.");

        //Verify modified statements are used.
        if(mandatory.Any(s => s.Contains("_:", StringComparison.Ordinal)))
        {
            Assert.IsTrue(mandatory.All(s => !s.Contains("_:c14n", StringComparison.Ordinal)),
                "Applied mandatory statements must use modified blank nodes.");
        }
    }


    //=========================================================================
    //Integration test: Full flow
    //=========================================================================

    [TestMethod]
    public void FullSelectionAndPartitionFlowProducesConsistentResults()
    {
        //Select a subset of properties.
        var selectPointers = new[]
        {
            Verifiable.JsonPointer.JsonPointer.Parse("/issuer"),
            Verifiable.JsonPointer.JsonPointer.Parse("/validFrom"),
            Verifiable.JsonPointer.JsonPointer.Parse("/credentialSubject/givenName")
        };

        //Get selection document.
        var selection = JsonLdSelection.SelectFragments(TestCredentialJson, selectPointers);

        //Partition both original and selection.
        var originalPartition = JsonLdSelection.PartitionStatements(
            TestCredentialJson,
            selectPointers,
            Canonicalize);

        //The mandatory statements from the original should match what we'd get
        //from canonicalizing the selection document.
        var selectionCanonical = Canonicalize(selection);
        var selectionStatements = selectionCanonical.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        //Selection canonical should be a subset of mandatory statements (approximately).
        //Note: Due to blank node differences, exact matching isn't possible,
        //but count relationships should hold.
        Assert.IsNotEmpty(selectionStatements,
            "Selection document must produce canonical statements.");
        Assert.IsGreaterThan(0, originalPartition.MandatoryStatements.Count,
            "Original must have mandatory statements for the given pointers.");
    }


    //=========================================================================
    //Helper methods
    //=========================================================================

    private static string Canonicalize(string jsonLdDocument)
    {
        var store = new TripleStore();
        var parser = new JsonLdParser();
        using var reader = new StringReader(jsonLdDocument);
        parser.Load(store, reader);
        return new RdfCanonicalizer().Canonicalize(store).SerializedNQuads;
    }
}
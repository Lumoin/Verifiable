using CsCheck;
using System.Text.Json;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Property-based tests for <see cref="SdJwtClaimRedaction"/> using CsCheck.
/// </summary>
/// <remarks>
/// <para>
/// These tests complement the example-based <see cref="SdJwtClaimRedactionTests"/> by
/// verifying structural invariants across randomly generated payloads. Key properties:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Partition completeness:</strong> Every leaf claim appears in exactly one of
/// mandatory or disclosures, never in both, never in neither.
/// </description></item>
/// <item><description>
/// <strong>Disclosure name correctness:</strong> Each disclosure's claim name matches
/// the original property name.
/// </description></item>
/// <item><description>
/// <strong>Mandatory value preservation:</strong> Non-disclosable claims retain their
/// original values.
/// </description></item>
/// <item><description>
/// <strong>Path boundary safety:</strong> <c>/foo</c> must never match <c>/foobar</c>.
/// </description></item>
/// <item><description>
/// <strong>Nested partition correctness:</strong> Disclosable leaf paths produce disclosures
/// while sibling leaves remain in the nested mandatory object.
/// </description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class SdJwtClaimRedactionPropertyTests
{
    public TestContext TestContext { get; set; } = null!;

    private static Gen<string> GenPropertyName { get; } =
        Gen.String[Gen.Char.AlphaNumeric, 1, 12];

    private static Gen<Dictionary<string, string>> GenFlatJsonObject { get; } =
        Gen.Dictionary(GenPropertyName, Gen.String[Gen.Char.AlphaNumeric, 0, 20])[1, 10];


    [TestMethod]
    public void RedactProducesCorrectDisclosureCountForAnySubset()
    {
        (from obj in GenFlatJsonObject
         from disclosable in GenSubsetOfKeys(obj)
         select (obj, disclosable))
        .Sample((obj, disclosable) =>
        {
            var (_, disclosures) = Redact(obj, disclosable);

            Assert.HasCount(disclosable.Count, disclosures);
        });
    }


    [TestMethod]
    public void RedactPartitionsAllClaimsExactlyOnce()
    {
        (from obj in GenFlatJsonObject
         from disclosable in GenSubsetOfKeys(obj)
         select (obj, disclosable))
        .Sample((obj, disclosable) =>
        {
            var (mandatory, disclosures) = Redact(obj, disclosable);

            var disclosureNames = new HashSet<string>(disclosures.Select(d => d.ClaimName!));
            var mandatoryKeys = OriginalClaimKeys(mandatory);

            foreach(string name in disclosureNames)
            {
                Assert.DoesNotContain(name, mandatoryKeys,
                    $"Claim '{name}' appears in both mandatory and disclosures.");
            }

            foreach(string key in obj.Keys)
            {
                Assert.IsTrue(
                    mandatoryKeys.Contains(key) || disclosureNames.Contains(key),
                    $"Claim '{key}' missing from both mandatory and disclosures.");
            }
        });
    }


    [TestMethod]
    public void RedactPreservesMandatoryValues()
    {
        (from obj in GenFlatJsonObject
         from disclosable in GenSubsetOfKeys(obj)
         select (obj, disclosable))
        .Sample((obj, disclosable) =>
        {
            var disclosableSet = new HashSet<string>(disclosable);
            var (mandatory, _) = Redact(obj, disclosable);

            foreach(string key in obj.Keys)
            {
                if(!disclosableSet.Contains(key))
                {
                    Assert.IsTrue(mandatory.ContainsKey(key),
                        $"Mandatory claim '{key}' missing from payload.");
                    Assert.AreEqual(obj[key], mandatory[key]?.ToString(),
                        $"Mandatory claim '{key}' value changed.");
                }
            }
        });
    }


    [TestMethod]
    public void RedactWithEmptyDisclosableSetReturnsAllMandatory()
    {
        GenFlatJsonObject.Sample(obj =>
        {
            var (mandatory, disclosures) = Redact(obj, []);

            Assert.HasCount(0, disclosures);
            Assert.HasCount(obj.Count, mandatory);
        });
    }


    [TestMethod]
    public void RedactWithAllDisclosableReturnsNoOriginalMandatory()
    {
        GenFlatJsonObject
        .Where(obj => obj.Count > 0)
        .Sample(obj =>
        {
            var (mandatory, disclosures) = Redact(obj, new HashSet<string>(obj.Keys));

            var originalKeys = OriginalClaimKeys(mandatory);
            Assert.HasCount(0, originalKeys);
            Assert.HasCount(obj.Count, disclosures);
        });
    }


    [TestMethod]
    public void PathPrefixBoundaryNeverCausesSpuriousMatches()
    {
        (from baseName in Gen.String[Gen.Char.AlphaNumeric, 2, 5]
         from suffix in Gen.String[Gen.Char.AlphaNumeric, 1, 5]
         let shortName = baseName
         let longName = baseName + suffix
         where shortName != longName
         select (shortName, longName))
        .Sample((shortName, longName) =>
        {
            var obj = new Dictionary<string, string>
            {
                [shortName] = "short-value",
                [longName] = "long-value"
            };

            var paths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EscapeJsonPointer(shortName)}")
            };

            string json = JsonSerializer.Serialize(obj);
            var (mandatory, disclosures) = SdJwtClaimRedaction.Redact(
                json, paths, () => SaltGenerator.Create(),
                SerializeDisclosure, ComputeDigest,
                TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);

            Assert.HasCount(1, disclosures);
            Assert.AreEqual(shortName, disclosures[0].ClaimName);
            Assert.IsTrue(mandatory.ContainsKey(longName),
                $"'{longName}' should be mandatory but was not found.");
        });
    }


    [TestMethod]
    public void NestedRedactPartitionsCorrectly()
    {
        (from parentName in GenPropertyName
         from leaves in Gen.Dictionary(GenPropertyName, Gen.String[Gen.Char.AlphaNumeric, 1, 10])[2, 6]
         from disclosable in GenSubsetOfKeys(leaves)
         where disclosable.Count > 0 && disclosable.Count < leaves.Count
         select (parentName, leaves, disclosable))
        .Sample((parentName, leaves, disclosable) =>
        {
            var nested = new Dictionary<string, object> { [parentName] = leaves };
            string json = JsonSerializer.Serialize(nested);

            var paths = new HashSet<CredentialPath>(
                disclosable.Select(k => CredentialPath.FromJsonPointer(
                    $"/{EscapeJsonPointer(parentName)}/{EscapeJsonPointer(k)}")));

            var (mandatory, disclosures) = SdJwtClaimRedaction.Redact(
                json, paths, () => SaltGenerator.Create(),
                SerializeDisclosure, ComputeDigest,
                TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);

            Assert.HasCount(disclosable.Count, disclosures);

            var disclosureNames = new HashSet<string>(disclosures.Select(d => d.ClaimName!));
            foreach(string key in disclosable)
            {
                Assert.Contains(key, disclosureNames,
                    $"Expected disclosure for '{key}' not found.");
            }

            Assert.IsTrue(mandatory.ContainsKey(parentName), "Parent object missing from mandatory.");
            var mandatoryNested = (Dictionary<string, object>)mandatory[parentName]!;
            foreach(string key in leaves.Keys)
            {
                if(!disclosable.Contains(key))
                {
                    Assert.IsTrue(mandatoryNested.ContainsKey(key),
                        $"Non-disclosable leaf '{key}' missing from mandatory nested object.");
                }
            }
        });
    }


    [TestMethod]
    public void DisclosureClaimNamesMatchPathLastSegment()
    {
        (from obj in GenFlatJsonObject
         from disclosable in GenSubsetOfKeys(obj)
         where disclosable.Count > 0
         select (obj, disclosable))
        .Sample((obj, disclosable) =>
        {
            var (_, disclosures) = Redact(obj, disclosable);

            var disclosureNames = new HashSet<string>(disclosures.Select(d => d.ClaimName!));
            foreach(string key in disclosable)
            {
                Assert.Contains(key, disclosureNames,
                    $"Disclosure for '{key}' not found.");
            }
        });
    }


    //Shared redaction call for flat objects.

    private static (JwtPayload, IReadOnlyList<SdDisclosure>) Redact(
        Dictionary<string, string> obj, IEnumerable<string> disclosableKeys)
    {
        string json = JsonSerializer.Serialize(obj);
        var paths = ToCredentialPaths(disclosableKeys);

        return SdJwtClaimRedaction.Redact(
            json, paths, () => SaltGenerator.Create(),
            SerializeDisclosure, ComputeDigest,
            TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);
    }

    //Delegate wiring.

    private static string SerializeDisclosure(SdDisclosure disclosure, EncodeDelegate encoder)
    {
        return SdJwtSerializer.SerializeDisclosure(disclosure, encoder);
    }

    private static string ComputeDigest(string encodedDisclosure, EncodeDelegate encoder)
    {
        return SdJwtPathExtraction.ComputeDisclosureDigest(
            encodedDisclosure, WellKnownHashAlgorithms.Sha256Iana, encoder);
    }

    /// <summary>
    /// Returns claim keys excluding SD-JWT metadata entries.
    /// </summary>
    private static HashSet<string> OriginalClaimKeys(JwtPayload mandatory)
    {
        return new HashSet<string>(
            mandatory.Keys.Where(k =>
                k != SdConstants.SdClaimName &&
                k != SdConstants.SdAlgorithmClaimName));
    }

    /// <summary>
    /// Generates a random subset of keys from a dictionary using a boolean mask.
    /// </summary>
    private static Gen<HashSet<string>> GenSubsetOfKeys(IDictionary<string, string> obj)
    {
        if(obj.Count == 0)
        {
            return Gen.Const(new HashSet<string>());
        }

        string[] keys = [.. obj.Keys];
        return Gen.Bool.Array[keys.Length].Select(mask =>
        {
            var subset = new HashSet<string>();
            for(int i = 0; i < keys.Length; i++)
            {
                if(mask[i])
                {
                    subset.Add(keys[i]);
                }
            }

            return subset;
        });
    }

    /// <summary>
    /// Converts property names to top-level credential paths with JSON Pointer escaping.
    /// </summary>
    private static HashSet<CredentialPath> ToCredentialPaths(IEnumerable<string> propertyNames)
    {
        return new HashSet<CredentialPath>(
            propertyNames.Select(k => CredentialPath.FromJsonPointer($"/{EscapeJsonPointer(k)}")));
    }

    /// <summary>
    /// Escapes a property name for use in a JSON Pointer per RFC 6901.
    /// </summary>
    private static string EscapeJsonPointer(string segment)
    {
        return segment
            .Replace("~", "~0", StringComparison.Ordinal)
            .Replace("/", "~1", StringComparison.Ordinal);
    }
}
using System.Text.Json;
using CsCheck;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Property-based tests for SD-JWT claim redaction per
/// <see href="https://datatracker.ietf.org/doc/rfc9901/">RFC 9901</see>.
/// </summary>
/// <remarks>
/// <para>
/// These tests verify structural invariants of <see cref="SdJwtClaimRedaction.Redact"/>
/// that hold regardless of the specific claim names, values, or subset of disclosable
/// paths chosen. CsCheck generates random claim maps and path subsets, automatically
/// shrinking to minimal counterexamples on failure.
/// </para>
/// <para>
/// Invariants tested:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Partition completeness:</strong> Every leaf claim appears in exactly one of
/// mandatory or disclosures, never both, never neither.
/// </description></item>
/// <item><description>
/// <strong>Count correspondence:</strong> Disclosure count equals the number of disclosable paths.
/// </description></item>
/// <item><description>
/// <strong>Value preservation:</strong> Non-disclosable claims retain their original values.
/// </description></item>
/// <item><description>
/// <strong>Salt uniqueness:</strong> No two disclosures share the same salt bytes.
/// </description></item>
/// <item><description>
/// <strong>Path boundary safety:</strong> <c>/foo</c> must never match <c>/foobar</c>.
/// </description></item>
/// </list>
/// <para>
/// Example-based tests for the same issuance API are in
/// <see cref="SdJwtRfc9901IssuanceTests"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SdJwtRfc9901IssuancePropertyTests
{
    private static Gen<string> GenPropertyName { get; } =
        Gen.String[Gen.Char.AlphaNumeric, 1, 12];

    private static Gen<Dictionary<string, string>> GenFlatClaims { get; } =
        Gen.Dictionary(GenPropertyName, Gen.String[Gen.Char.AlphaNumeric, 0, 20])[1, 8];


    [TestMethod]
    public void DisclosureCountAlwaysEqualsPathCount()
    {
        (from claims in GenFlatClaims
         from disclosable in GenSubsetOfKeys(claims)
         select (claims, disclosable))
        .Sample((claims, disclosable) =>
        {
            string json = JsonSerializer.Serialize(claims);
            HashSet<CredentialPath> paths = ToCredentialPaths(disclosable);

            var (_, disclosures) = SdJwtClaimRedaction.Redact(json, paths, () => SaltGenerator.Create());

            Assert.HasCount(disclosable.Count, disclosures);
        });
    }


    [TestMethod]
    public void EveryClaimAppearsInExactlyOnePartition()
    {
        (from claims in GenFlatClaims
         from disclosable in GenSubsetOfKeys(claims)
         select (claims, disclosable))
        .Sample((claims, disclosable) =>
        {
            string json = JsonSerializer.Serialize(claims);
            HashSet<CredentialPath> paths = ToCredentialPaths(disclosable);

            var (mandatory, disclosures) = SdJwtClaimRedaction.Redact(json, paths, () => SaltGenerator.Create());

            var disclosureNames = new HashSet<string>(disclosures.Select(d => d.ClaimName!));
            var mandatoryKeys = new HashSet<string>(mandatory.Keys);

            foreach(string key in claims.Keys)
            {
                bool inMandatory = mandatoryKeys.Contains(key);
                bool inDisclosure = disclosureNames.Contains(key);

                Assert.IsTrue(
                    inMandatory ^ inDisclosure,
                    $"Claim '{key}' must appear in exactly one of mandatory or disclosures.");
            }
        });
    }


    [TestMethod]
    public void MandatoryValuesArePreservedUnchanged()
    {
        (from claims in GenFlatClaims
         from disclosable in GenSubsetOfKeys(claims)
         select (claims, disclosable))
        .Sample((claims, disclosable) =>
        {
            string json = JsonSerializer.Serialize(claims);
            var disclosableSet = new HashSet<string>(disclosable);
            HashSet<CredentialPath> paths = ToCredentialPaths(disclosable);

            var (mandatory, _) = SdJwtClaimRedaction.Redact(json, paths, () => SaltGenerator.Create());

            foreach(string key in claims.Keys)
            {
                if(!disclosableSet.Contains(key))
                {
                    Assert.IsTrue(mandatory.ContainsKey(key), $"Mandatory claim '{key}' is missing.");
                    Assert.AreEqual(claims[key], mandatory[key]?.ToString(), $"Value changed for '{key}'.");
                }
            }
        });
    }


    [TestMethod]
    public void EmptyDisclosableSetProducesZeroDisclosures()
    {
        GenFlatClaims.Sample(claims =>
        {
            string json = JsonSerializer.Serialize(claims);

            var (mandatory, disclosures) = SdJwtClaimRedaction.Redact(
                json, new HashSet<CredentialPath>(), () => SaltGenerator.Create());

            Assert.HasCount(0, disclosures);
            Assert.HasCount(claims.Count, mandatory);
        });
    }


    [TestMethod]
    public void AllClaimsDisclosableProducesEmptyMandatoryPayload()
    {
        GenFlatClaims
        .Where(claims => claims.Count > 0)
        .Sample(claims =>
        {
            string json = JsonSerializer.Serialize(claims);
            HashSet<CredentialPath> paths = ToCredentialPaths(new HashSet<string>(claims.Keys));

            var (mandatory, disclosures) = SdJwtClaimRedaction.Redact(json, paths, () => SaltGenerator.Create());

            Assert.HasCount(0, mandatory);
            Assert.HasCount(claims.Count, disclosures);
        });
    }


    [TestMethod]
    public void PathPrefixBoundaryDoesNotCauseSpuriousMatch()
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
            string json = JsonSerializer.Serialize(obj);

            var paths = new HashSet<CredentialPath>
            {
                CredentialPath.FromJsonPointer($"/{EscapeJsonPointer(shortName)}")
            };

            var (mandatory, disclosures) = SdJwtClaimRedaction.Redact(json, paths, () => SaltGenerator.Create());

            Assert.HasCount(1, disclosures);
            Assert.AreEqual(shortName, disclosures[0].ClaimName);
            Assert.IsTrue(mandatory.ContainsKey(longName), $"'{longName}' must remain mandatory.");
        });
    }


    [TestMethod]
    public void NestedObjectPartitionsLeafClaimsCorrectly()
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

            var (mandatory, disclosures) = SdJwtClaimRedaction.Redact(json, paths, () => SaltGenerator.Create());

            Assert.HasCount(disclosable.Count, disclosures);
            Assert.IsTrue(mandatory.ContainsKey(parentName), "Parent object must remain in mandatory.");

            var mandatoryNested = (Dictionary<string, object?>)mandatory[parentName]!;
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
    public void AllSaltsAreUniquePerDisclosure()
    {
        (from claims in GenFlatClaims
         from disclosable in GenSubsetOfKeys(claims)
         where disclosable.Count >= 2
         select (claims, disclosable))
        .Sample((claims, disclosable) =>
        {
            string json = JsonSerializer.Serialize(claims);
            HashSet<CredentialPath> paths = ToCredentialPaths(disclosable);

            var (_, disclosures) = SdJwtClaimRedaction.Redact(json, paths, () => SaltGenerator.Create());

            var saltSet = new HashSet<string>(
                disclosures.Select(d => Convert.ToHexString(d.Salt.Span)));
            Assert.HasCount(disclosures.Count, saltSet);
        });
    }


    [TestMethod]
    public void DisclosureClaimNamesMatchOriginalPropertyNames()
    {
        (from claims in GenFlatClaims
         from disclosable in GenSubsetOfKeys(claims)
         where disclosable.Count > 0
         select (claims, disclosable))
        .Sample((claims, disclosable) =>
        {
            string json = JsonSerializer.Serialize(claims);
            HashSet<CredentialPath> paths = ToCredentialPaths(disclosable);

            var (_, disclosures) = SdJwtClaimRedaction.Redact(json, paths, () => SaltGenerator.Create());

            var disclosureNames = new HashSet<string>(disclosures.Select(d => d.ClaimName!));
            foreach(string key in disclosable)
            {
                Assert.Contains(key, disclosureNames, $"Disclosure for '{key}' not found.");
            }
        });
    }


    private static Gen<HashSet<string>> GenSubsetOfKeys(IDictionary<string, string> dict)
    {
        if(dict.Count == 0)
        {
            return Gen.Const(new HashSet<string>());
        }

        string[] keys = [.. dict.Keys];
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


    private static HashSet<CredentialPath> ToCredentialPaths(IEnumerable<string> propertyNames)
    {
        return new HashSet<CredentialPath>(
            propertyNames.Select(k => CredentialPath.FromJsonPointer($"/{EscapeJsonPointer(k)}")));
    }


    private static string EscapeJsonPointer(string segment)
    {
        return segment
            .Replace("~", "~0", StringComparison.Ordinal)
            .Replace("/", "~1", StringComparison.Ordinal);
    }
}
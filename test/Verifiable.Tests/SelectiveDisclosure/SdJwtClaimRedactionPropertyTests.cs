using CsCheck;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Property-based tests using CsCheck for <see cref="SdJwtClaimRedaction.Redact"/>.
/// Verifies partition invariants hold for arbitrary JSON structures and path selections.
/// </summary>
[TestClass]
internal sealed class SdJwtClaimRedactionPropertyTests
{
    [TestMethod]
    public void RedactPartitionsClaimsCorrectly()
    {
        //Generate flat JSON objects with random string claims.
        var genClaimCount = Gen.Int[2, 8];
        var genClaimName = Gen.String[Gen.Char['a', 'z'], 3, 10];
        var genClaimValue = Gen.String[Gen.Char['a', 'z'], 1, 20];

        var genPayload = genClaimCount.SelectMany(count =>
            Gen.Select(
                genClaimName.Array[count],
                genClaimValue.Array[count],
                (names, values) => (Names: names.Distinct().ToList(), Values: values)));

        var genDisclosableRatio = Gen.Double[0.1, 0.9];

        genPayload.SelectMany(p =>
            genDisclosableRatio.Select(ratio => (p.Names, p.Values, Ratio: ratio)))
        .Sample((names, values, ratio) =>
        {
            if(names.Count == 0)
            {
                return;
            }

            var jsonProps = names.Zip(values, (n, v) => $"\"{n}\": \"{v}\"");
            string json = $"{{ {string.Join(", ", jsonProps)} }}";

            int disclosableCount = Math.Max(1, (int)(names.Count * ratio));
            var disclosablePaths = names.Take(disclosableCount)
                .Select(n => CredentialPath.FromJsonPointer($"/{n}"))
                .ToHashSet();

            var (payload, disclosures) = SdJwtClaimRedaction.Redact(json, disclosablePaths, () => SaltGenerator.Create());

            //Every disclosable path must produce a disclosure.
            Assert.HasCount(disclosableCount, disclosures);

            //No disclosable claim name must appear in the mandatory payload.
            foreach(string name in names.Take(disclosableCount))
            {
                Assert.IsFalse(payload.ContainsKey(name),
                    $"Disclosable claim '{name}' must not appear in mandatory payload.");
            }

            //Every non-disclosable claim must appear in the mandatory payload.
            foreach(string name in names.Skip(disclosableCount))
            {
                Assert.IsTrue(payload.ContainsKey(name),
                    $"Mandatory claim '{name}' must appear in payload.");
            }
        });
    }


    [TestMethod]
    public void RedactWithDigestsProducesCorrectDigestCount()
    {
        var genClaimCount = Gen.Int[2, 6];
        var genClaimName = Gen.String[Gen.Char['a', 'z'], 3, 10];
        var genClaimValue = Gen.String[Gen.Char['a', 'z'], 1, 20];

        var genPayload = genClaimCount.SelectMany(count =>
            Gen.Select(
                genClaimName.Array[count],
                genClaimValue.Array[count],
                (names, values) => (Names: names.Distinct().ToList(), Values: values)));

        genPayload.Sample((names, values) =>
        {
            if(names.Count < 2)
            {
                return;
            }

            var jsonProps = names.Zip(values, (n, v) => $"\"{n}\": \"{v}\"");
            string json = $"{{ {string.Join(", ", jsonProps)} }}";

            int disclosableCount = names.Count / 2;
            var disclosablePaths = names.Take(disclosableCount)
                .Select(n => CredentialPath.FromJsonPointer($"/{n}"))
                .ToHashSet();

            var (payload, disclosures) = SdJwtClaimRedaction.Redact(
                json, disclosablePaths, () => SaltGenerator.Create(),
                SdJwtSerializer.SerializeDisclosure,
                SdJwtPathExtraction.ComputeDisclosureDigest,
                TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);

            Assert.HasCount(disclosableCount, disclosures);

            //The _sd array at root must have exactly disclosableCount digests.
            Assert.IsTrue(payload.ContainsKey(SdConstants.SdClaimName), "Payload must contain _sd.");
            var sdArray = (List<string>)payload[SdConstants.SdClaimName];
            Assert.HasCount(disclosableCount, sdArray);
        });
    }
}
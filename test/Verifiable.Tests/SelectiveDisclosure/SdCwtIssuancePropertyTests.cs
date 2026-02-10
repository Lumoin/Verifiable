using System.Formats.Cbor;
using System.Globalization;
using CsCheck;
using Verifiable.Cbor;
using Verifiable.Cbor.Sd;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Property-based tests for SD-CWT claim redaction per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt</see>.
/// </summary>
/// <remarks>
/// <para>
/// These tests verify structural invariants of <see cref="SdCwtClaimRedaction.Redact"/>
/// using CWT integer-keyed maps with random subsets of disclosable paths.
/// </para>
/// <para>
/// Example-based tests for the same issuance API are in
/// <see cref="SdCwtIssuanceTests"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SdCwtIssuancePropertyTests
{
    /// <summary>
    /// CWT-style integer claim keys in a range that avoids collisions with
    /// registered claims (1-7) and the redacted_claim_keys sentinel.
    /// </summary>
    private static Gen<int> GenClaimKey { get; } = Gen.Int[100, 999];

    private static Gen<Dictionary<int, string>> GenCwtClaims { get; } =
        Gen.Dictionary(GenClaimKey, Gen.String[Gen.Char.AlphaNumeric, 1, 20])[1, 6];


    [TestMethod]
    public void CborDisclosureCountAlwaysEqualsPathCount()
    {
        (from claims in GenCwtClaims
         from disclosable in GenSubsetOfKeys(claims)
         select (claims, disclosable))
        .Sample((claims, disclosable) =>
        {
            byte[] cborBytes = SerializeIntStringMap(claims);
            HashSet<CredentialPath> paths = ToCwtCredentialPaths(disclosable);

            var (_, disclosures) = SdCwtClaimRedaction.Redact(
                cborBytes, paths, () => SaltGenerator.Create(),
                WellKnownHashAlgorithms.Sha256Iana);

            Assert.HasCount(disclosable.Count, disclosures);
        });
    }


    [TestMethod]
    public void CborEveryClaimAppearsInExactlyOnePartition()
    {
        (from claims in GenCwtClaims
         from disclosable in GenSubsetOfKeys(claims)
         select (claims, disclosable))
        .Sample((claims, disclosable) =>
        {
            byte[] cborBytes = SerializeIntStringMap(claims);
            HashSet<CredentialPath> paths = ToCwtCredentialPaths(disclosable);

            var (payload, disclosures) = SdCwtClaimRedaction.Redact(
                cborBytes, paths, () => SaltGenerator.Create(),
                WellKnownHashAlgorithms.Sha256Iana);

            var disclosureNames = new HashSet<string>(disclosures.Select(d => d.ClaimName!));

            foreach(int key in claims.Keys)
            {
                string keyStr = key.ToString(CultureInfo.InvariantCulture);
                bool inMandatory = payload.ContainsKey(key);
                bool inDisclosure = disclosureNames.Contains(keyStr);

                Assert.IsTrue(
                    inMandatory ^ inDisclosure,
                    $"Claim '{keyStr}' must appear in exactly one of mandatory or disclosures.");
            }
        });
    }


    [TestMethod]
    public void CborAllSaltsAreUnique()
    {
        (from claims in GenCwtClaims
         from disclosable in GenSubsetOfKeys(claims)
         where disclosable.Count >= 2
         select (claims, disclosable))
        .Sample((claims, disclosable) =>
        {
            byte[] cborBytes = SerializeIntStringMap(claims);
            HashSet<CredentialPath> paths = ToCwtCredentialPaths(disclosable);

            var (_, disclosures) = SdCwtClaimRedaction.Redact(
                cborBytes, paths, () => SaltGenerator.Create(),
                WellKnownHashAlgorithms.Sha256Iana);

            var saltSet = new HashSet<string>(
                disclosures.Select(d => Convert.ToHexString(d.Salt.Span)));
            Assert.HasCount(disclosures.Count, saltSet);
        });
    }


    [TestMethod]
    public void CborEmptyDisclosableSetProducesZeroDisclosures()
    {
        GenCwtClaims.Sample(claims =>
        {
            byte[] cborBytes = SerializeIntStringMap(claims);

            var (payload, disclosures) = SdCwtClaimRedaction.Redact(
                cborBytes, new HashSet<CredentialPath>(), () => SaltGenerator.Create(),
                WellKnownHashAlgorithms.Sha256Iana);

            Assert.HasCount(0, disclosures);
            Assert.HasCount(claims.Count, payload);
        });
    }


    [TestMethod]
    public void CborAllClaimsDisclosableProducesEmptyMandatoryPayload()
    {
        GenCwtClaims
        .Where(claims => claims.Count > 0)
        .Sample(claims =>
        {
            byte[] cborBytes = SerializeIntStringMap(claims);
            HashSet<CredentialPath> paths = ToCwtCredentialPaths(new HashSet<int>(claims.Keys));

            var (payload, disclosures) = SdCwtClaimRedaction.Redact(
                cborBytes, paths, () => SaltGenerator.Create(),
                WellKnownHashAlgorithms.Sha256Iana);

            Assert.HasCount(claims.Count, disclosures);

            foreach(int key in claims.Keys)
            {
                Assert.IsFalse(payload.ContainsKey(key),
                    $"Disclosable claim '{key}' must not remain in mandatory payload.");
            }
        });
    }


    private static Gen<HashSet<int>> GenSubsetOfKeys(IDictionary<int, string> dict)
    {
        if(dict.Count == 0)
        {
            return Gen.Const(new HashSet<int>());
        }

        int[] keys = [.. dict.Keys];
        return Gen.Bool.Array[keys.Length].Select(mask =>
        {
            var subset = new HashSet<int>();
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


    private static HashSet<CredentialPath> ToCwtCredentialPaths(IEnumerable<int> keys)
    {
        return new HashSet<CredentialPath>(
            keys.Select(k => CredentialPath.FromJsonPointer(
                $"/{k.ToString(CultureInfo.InvariantCulture)}")));
    }


    /// <summary>
    /// Property tests need direct CBOR bytes for <see cref="SdCwtClaimRedaction.Redact"/>
    /// rather than going through the full issuance pipeline. This uses a minimal
    /// <see cref="CborWriter"/> since the generated claims have only string values,
    /// not the mixed types that <see cref="CborValueConverter.WriteValue"/> handles.
    /// </summary>
    private static byte[] SerializeIntStringMap(Dictionary<int, string> claims)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(claims.Count);
        foreach(KeyValuePair<int, string> entry in claims)
        {
            writer.WriteInt32(entry.Key);
            writer.WriteTextString(entry.Value);
        }

        writer.WriteEndMap();
        return writer.Encode();
    }
}
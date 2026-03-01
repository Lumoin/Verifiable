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
/// Tests for <see cref="SdJwtClaimRedaction.Redact"/> — the redaction step only, no signing.
/// Verifies <c>_sd</c> placement at the correct nesting levels, partition correctness,
/// type preservation, and <c>_sd_alg</c> conditional logic.
/// </summary>
[TestClass]
internal sealed class SdJwtClaimRedactionTests
{
    [TestMethod]
    public void RedactTopLevelClaimsPlacesSdArrayAtRoot()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "given_name": "Erika",
            "family_name": "Mustermann"
        }
        """;

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/given_name"),
            CredentialPath.FromJsonPointer("/family_name")
        };

        var (payload, disclosures) = RedactWithDigests(json, disclosablePaths);

        Assert.HasCount(2, disclosures);
        Assert.IsTrue(payload.ContainsKey(SdConstants.SdClaimName), "Root must have _sd array.");
        Assert.IsTrue(payload.ContainsKey(SdConstants.SdAlgorithmClaimName), "Root must have _sd_alg.");
        Assert.AreEqual("https://issuer.example.com", payload[WellKnownJwtClaims.Iss]);
        Assert.IsFalse(payload.ContainsKey("given_name"), "Disclosable claim must not be in payload.");
        Assert.IsFalse(payload.ContainsKey("family_name"), "Disclosable claim must not be in payload.");
    }


    [TestMethod]
    public void RedactNestedClaimsPlacesSdArrayInsideParent()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "credentialSubject": {
                "id": "did:example:123",
                "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science"
                }
            }
        }
        """;

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/degree")
        };

        var (payload, disclosures) = RedactWithDigests(json, disclosablePaths);

        Assert.HasCount(1, disclosures);
        Assert.IsFalse(payload.ContainsKey(SdConstants.SdClaimName), "Root must not have _sd when no root claims are disclosable.");

        var credSubject = (Dictionary<string, object>)payload["credentialSubject"];
        Assert.IsTrue(credSubject.ContainsKey(SdConstants.SdClaimName), "CredentialSubject must have _sd array.");
        Assert.AreEqual("did:example:123", credSubject["id"]);
        Assert.IsFalse(credSubject.ContainsKey("degree"), "Disclosable claim must not be in credentialSubject.");
    }


    [TestMethod]
    public void RedactThreeLevelsDeepPlacesSdArrayAtLeafParent()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "level1": {
                "level2": {
                    "level3": {
                        "secret": "hidden",
                        "visible": "shown"
                    }
                }
            }
        }
        """;

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/level1/level2/level3/secret")
        };

        var (payload, disclosures) = RedactWithDigests(json, disclosablePaths);

        Assert.HasCount(1, disclosures);

        var level1 = (Dictionary<string, object>)payload["level1"];
        Assert.IsFalse(level1.ContainsKey(SdConstants.SdClaimName), "Level1 must not have _sd.");

        var level2 = (Dictionary<string, object>)level1["level2"];
        Assert.IsFalse(level2.ContainsKey(SdConstants.SdClaimName), "Level2 must not have _sd.");

        var level3 = (Dictionary<string, object>)level2["level3"];
        Assert.IsTrue(level3.ContainsKey(SdConstants.SdClaimName), "Level3 must have _sd.");
        Assert.AreEqual("shown", level3["visible"]);
        Assert.IsFalse(level3.ContainsKey("secret"), "Disclosable claim must not be in level3.");
    }


    [TestMethod]
    public void RedactMultipleLevelsPlacesSdArraysAtEachLevel()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "given_name": "Erika",
            "address": {
                "street": "Heidestrasse 17",
                "city": "Köln"
            }
        }
        """;

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/given_name"),
            CredentialPath.FromJsonPointer("/address/street")
        };

        var (payload, disclosures) = RedactWithDigests(json, disclosablePaths);

        Assert.HasCount(2, disclosures);
        Assert.IsTrue(payload.ContainsKey(SdConstants.SdClaimName), "Root must have _sd for given_name.");

        var address = (Dictionary<string, object>)payload["address"];
        Assert.IsTrue(address.ContainsKey(SdConstants.SdClaimName), "Address must have _sd for street.");
        Assert.AreEqual("Köln", address["city"]);
    }


    [TestMethod]
    public void RedactEmptyDisclosablesReturnsOriginalClaimsWithoutSdAlg()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "given_name": "Erika"
        }
        """;

        var (payload, disclosures) = RedactWithDigests(json, []);

        Assert.HasCount(0, disclosures);
        Assert.IsFalse(payload.ContainsKey(SdConstants.SdClaimName), "No _sd when nothing is disclosable.");
        Assert.IsFalse(payload.ContainsKey(SdConstants.SdAlgorithmClaimName), "No _sd_alg when nothing is disclosable.");
        Assert.AreEqual("https://issuer.example.com", payload[WellKnownJwtClaims.Iss]);
        Assert.AreEqual("Erika", payload["given_name"]);
    }


    [TestMethod]
    public void RedactPartitionWithoutDigestsProducesCorrectSplit()
    {
        string json = /*lang=json,strict*/ """
        {
            "iss": "https://issuer.example.com",
            "given_name": "Erika",
            "family_name": "Mustermann",
            "birthdate": "1964-08-12"
        }
        """;

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/given_name"),
            CredentialPath.FromJsonPointer("/family_name")
        };

        var (payload, disclosures) = SdJwtClaimRedaction.Redact(json, disclosablePaths, () => SaltGenerator.Create());

        Assert.HasCount(2, disclosures);
        Assert.AreEqual("https://issuer.example.com", payload[WellKnownJwtClaims.Iss]);
        Assert.AreEqual("1964-08-12", payload["birthdate"]);
        Assert.IsFalse(payload.ContainsKey("given_name"), "Disclosable claim must not be in mandatory payload.");
        Assert.IsFalse(payload.ContainsKey("family_name"), "Disclosable claim must not be in mandatory payload.");
    }


    [TestMethod]
    public void RedactPreservesStringTypeInDisclosure()
    {
        string json = /*lang=json,strict*/ """{ "name": "Erika" }""";

        var (_, disclosures) = SdJwtClaimRedaction.Redact(
            json, new HashSet<CredentialPath> { CredentialPath.FromJsonPointer("/name") },
            () => SaltGenerator.Create());

        Assert.HasCount(1, disclosures);
        Assert.IsInstanceOfType<string>(disclosures[0].ClaimValue);
        Assert.AreEqual("Erika", disclosures[0].ClaimValue);
    }


    [TestMethod]
    public void RedactPreservesIntegerTypeInDisclosure()
    {
        string json = /*lang=json,strict*/ """{ "age": 42 }""";

        var (_, disclosures) = SdJwtClaimRedaction.Redact(
            json, new HashSet<CredentialPath> { CredentialPath.FromJsonPointer("/age") },
            () => SaltGenerator.Create());

        Assert.HasCount(1, disclosures);
        Assert.AreEqual(42, disclosures[0].ClaimValue);
    }


    [TestMethod]
    public void RedactPreservesBooleanTypeInDisclosure()
    {
        string json = /*lang=json,strict*/ """{ "active": true }""";

        var (_, disclosures) = SdJwtClaimRedaction.Redact(
            json, new HashSet<CredentialPath> { CredentialPath.FromJsonPointer("/active") },
            () => SaltGenerator.Create());

        Assert.HasCount(1, disclosures);
        Assert.IsTrue((bool)disclosures[0].ClaimValue!);
    }


    [TestMethod]
    public void RedactWholeObjectPreservesNestedStructureInDisclosure()
    {
        string json = /*lang=json,strict*/ """
        {
            "address": {
                "street": "Heidestrasse 17",
                "city": "Köln"
            }
        }
        """;

        var (_, disclosures) = SdJwtClaimRedaction.Redact(
            json, new HashSet<CredentialPath> { CredentialPath.FromJsonPointer("/address") },
            () => SaltGenerator.Create());

        Assert.HasCount(1, disclosures);
        Assert.IsInstanceOfType<Dictionary<string, object>>(disclosures[0].ClaimValue);

        var addressValue = (Dictionary<string, object>)disclosures[0].ClaimValue!;
        Assert.AreEqual("Heidestrasse 17", addressValue["street"]);
        Assert.AreEqual("Köln", addressValue["city"]);
    }


    /// <summary>
    /// Calls the full <see cref="SdJwtClaimRedaction.Redact"/> overload with digest computation.
    /// </summary>
    private static (JwtPayload Payload, IReadOnlyList<SdDisclosure> Disclosures) RedactWithDigests(
        string json, HashSet<CredentialPath> disclosablePaths)
    {
        return SdJwtClaimRedaction.Redact(
            json, disclosablePaths, () => SaltGenerator.Create(),
            SerializeDisclosure, ComputeDigest,
            TestSetup.Base64UrlEncoder, WellKnownHashAlgorithms.Sha256Iana);
    }

    private static string SerializeDisclosure(SdDisclosure disclosure, EncodeDelegate encoder)
    {
        return SdJwtSerializer.SerializeDisclosure(disclosure, encoder);
    }

    private static string ComputeDigest(string encodedDisclosure, string algorithmName, EncodeDelegate encoder)
    {
        return SdJwtPathExtraction.ComputeDisclosureDigest(
            encodedDisclosure, algorithmName, encoder);
    }
}
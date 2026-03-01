using System.Text.Json;
using Verifiable.Core.Model.Dcql;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Roundtrip serialization tests for DCQL query types.
/// </summary>
[TestClass]
internal sealed class DcqlQuerySerializationTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void MultiFormatDcqlQueryRoundtrip()
    {
        var original = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "mdl",
                    Format = "mso_mdoc",
                    Meta = new CredentialQueryMeta
                    {
                        DoctypeValue = "org.iso.18013.5.1.mDL"
                    },
                    Claims =
                    [
                        new ClaimsQuery
                        {
                            Id = "given_name",
                            Path = DcqlClaimPattern.ForMdoc("org.iso.18013.5.1", "given_name")
                        },
                        new ClaimsQuery
                        {
                            Id = "family_name",
                            Path = DcqlClaimPattern.ForMdoc("org.iso.18013.5.1", "family_name")
                        }
                    ],
                    TrustedAuthorities =
                    [
                        new TrustedAuthoritiesQuery
                        {
                            Type = "aki",
                            Values = ["MIIBGjCBwaADAgECAgUAMD0xCzAJ"]
                        }
                    ]
                },
                new CredentialQuery
                {
                    Id = "pid",
                    Format = "dc+sd-jwt",
                    Meta = new CredentialQueryMeta
                    {
                        VctValues = ["urn:eudi:pid:1"]
                    },
                    Claims =
                    [
                        new ClaimsQuery
                        {
                            Id = "given_name",
                            Path = DcqlClaimPattern.FromKeys("given_name")
                        },
                        new ClaimsQuery
                        {
                            Id = "family_name",
                            Path = DcqlClaimPattern.FromKeys("family_name")
                        }
                    ]
                }
            ]
        };

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        string json = JsonSerializer.Serialize(original, options);
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, options)!;

        Assert.IsNotNull(deserialized.Credentials);
        Assert.HasCount(2, deserialized.Credentials);

        //Verify mso_mdoc credential.
        var mdl = deserialized.Credentials[0];
        Assert.AreEqual("mdl", mdl.Id);
        Assert.AreEqual("mso_mdoc", mdl.Format);
        Assert.AreEqual("org.iso.18013.5.1.mDL", mdl.Meta!.DoctypeValue);
        Assert.HasCount(2, mdl.Claims!);
        Assert.HasCount(1, mdl.TrustedAuthorities!);
        Assert.AreEqual("aki", mdl.TrustedAuthorities![0].Type);
        Assert.HasCount(1, mdl.TrustedAuthorities![0].Values);

        //Verify dc+sd-jwt credential.
        var pid = deserialized.Credentials[1];
        Assert.AreEqual("pid", pid.Id);
        Assert.AreEqual("dc+sd-jwt", pid.Format);
        Assert.HasCount(1, pid.Meta!.VctValues!);
        Assert.AreEqual("urn:eudi:pid:1", pid.Meta.VctValues![0]);
    }

    [TestMethod]
    public void MinimalDcqlQueryRoundtrip()
    {
        var original = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "any",
                    Format = "dc+sd-jwt"
                }
            ]
        };

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        string json = JsonSerializer.Serialize(original, options);
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, options)!;

        Assert.IsNotNull(deserialized.Credentials);
        Assert.HasCount(1, deserialized.Credentials);
        Assert.AreEqual("any", deserialized.Credentials[0].Id);
        Assert.AreEqual("dc+sd-jwt", deserialized.Credentials[0].Format);
        Assert.IsNull(deserialized.Credentials[0].Meta);
        Assert.IsNull(deserialized.Credentials[0].Claims);
        Assert.IsNull(deserialized.Credentials[0].ClaimSets);
        Assert.IsNull(deserialized.Credentials[0].TrustedAuthorities);
        Assert.IsNull(deserialized.CredentialSets);
    }

    [TestMethod]
    public void ClaimPathPreservesSegmentTypes()
    {
        var original = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "test",
                    Format = "dc+sd-jwt",
                    Claims =
                    [
                        new ClaimsQuery
                        {
                            Path = new DcqlClaimPattern(
                                PatternSegment.Key("items"),
                                PatternSegment.Index(2),
                                PatternSegment.Wildcard(),
                                PatternSegment.Key("name"))
                        }
                    ]
                }
            ]
        };

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        string json = JsonSerializer.Serialize(original, options);

        //Verify the JSON wire format contains the expected mixed-type array.
        using var doc = JsonDocument.Parse(json);
        var pathArray = doc.RootElement
            .GetProperty("credentials")[0]
            .GetProperty("claims")[0]
            .GetProperty("path");

        Assert.AreEqual(JsonValueKind.String, pathArray[0].ValueKind);
        Assert.AreEqual("items", pathArray[0].GetString());
        Assert.AreEqual(JsonValueKind.Number, pathArray[1].ValueKind);
        Assert.AreEqual(2, pathArray[1].GetInt32());
        Assert.AreEqual(JsonValueKind.Null, pathArray[2].ValueKind);
        Assert.AreEqual(JsonValueKind.String, pathArray[3].ValueKind);
        Assert.AreEqual("name", pathArray[3].GetString());

        //Verify roundtrip produces equivalent DcqlClaimPattern.
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, options)!;
        Assert.IsNotNull(deserialized.Credentials);
        Assert.IsNotNull(deserialized.Credentials[0].Claims);
        var path = deserialized.Credentials[0].Claims![0].Path;
        Assert.IsNotNull(path);
        Assert.AreEqual(4, path.Count);
        Assert.IsTrue(path[0].IsKey);
        Assert.AreEqual("items", path[0].KeyValue);
        Assert.IsTrue(path[1].IsIndex);
        Assert.AreEqual(2, path[1].IndexValue);
        Assert.IsTrue(path[2].IsWildcard);
        Assert.IsTrue(path[3].IsKey);
        Assert.AreEqual("name", path[3].KeyValue);
    }

    [TestMethod]
    public void CredentialSetsRoundtrip()
    {
        var original = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery { Id = "passport", Format = "dc+sd-jwt" },
                new CredentialQuery { Id = "visa", Format = "dc+sd-jwt" },
                new CredentialQuery { Id = "national_id", Format = "mso_mdoc" }
            ],
            CredentialSets =
            [
                new CredentialSetQuery
                {
                    Options = [["passport", "visa"], ["national_id"]],
                    Purpose = "Identity verification for border crossing."
                }
            ]
        };

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        string json = JsonSerializer.Serialize(original, options);
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, options)!;

        Assert.IsNotNull(deserialized.CredentialSets);
        Assert.HasCount(1, deserialized.CredentialSets!);

        var credentialSet = deserialized.CredentialSets![0];
        Assert.IsNotNull(credentialSet.Options);
        Assert.HasCount(2, credentialSet.Options!);
        Assert.HasCount(2, credentialSet.Options![0]);
        Assert.AreEqual("passport", credentialSet.Options![0][0]);
        Assert.AreEqual("visa", credentialSet.Options![0][1]);
        Assert.HasCount(1, credentialSet.Options![1]);
        Assert.AreEqual("national_id", credentialSet.Options![1][0]);
        Assert.AreEqual("Identity verification for border crossing.", credentialSet.Purpose);
        Assert.IsTrue(credentialSet.Required);
    }

    [TestMethod]
    public void ClaimsWithValuesRoundtrip()
    {
        var original = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "constrained",
                    Format = "dc+sd-jwt",
                    Claims =
                    [
                        new ClaimsQuery
                        {
                            Id = "age_check",
                            Path = DcqlClaimPattern.FromKeys("age_over_18"),
                            Values = [true]
                        },
                        new ClaimsQuery
                        {
                            Id = "country",
                            Path = DcqlClaimPattern.FromKeys("address", "country"),
                            Values = ["DE", "FR", "NL"]
                        }
                    ]
                }
            ]
        };

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        string json = JsonSerializer.Serialize(original, options);
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, options)!;

        Assert.IsNotNull(deserialized.Credentials);
        Assert.IsNotNull(deserialized.Credentials[0].Claims);
        var claims = deserialized.Credentials[0].Claims!;
        Assert.HasCount(2, claims);

        //Verify boolean value constraint.
        Assert.HasCount(1, claims[0].Values!);
        Assert.IsInstanceOfType<bool>(claims[0].Values![0]);
        Assert.IsTrue((bool)claims[0].Values![0]);

        //Verify string value constraints.
        Assert.HasCount(3, claims[1].Values!);
        Assert.AreEqual("DE", claims[1].Values![0]);
        Assert.AreEqual("FR", claims[1].Values![1]);
        Assert.AreEqual("NL", claims[1].Values![2]);
    }

    [TestMethod]
    public void ClaimSetsWireFormatRoundtrip()
    {
        var original = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "identity",
                    Format = "dc+sd-jwt",
                    Claims =
                    [
                        new ClaimsQuery { Id = "given_name", Path = DcqlClaimPattern.FromKeys("given_name") },
                        new ClaimsQuery { Id = "family_name", Path = DcqlClaimPattern.FromKeys("family_name") },
                        new ClaimsQuery { Id = "display_name", Path = DcqlClaimPattern.FromKeys("display_name") }
                    ],
                    ClaimSets =
                    [
                        new ClaimSetQuery
                        {
                            Options = [["given_name", "family_name"], ["display_name"]]
                        }
                    ]
                }
            ]
        };

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        string json = JsonSerializer.Serialize(original, options);

        //Verify wire format is a flat array of arrays.
        using var doc = JsonDocument.Parse(json);
        var claimSetsArray = doc.RootElement
            .GetProperty("credentials")[0]
            .GetProperty("claim_sets");
        Assert.AreEqual(JsonValueKind.Array, claimSetsArray.ValueKind);
        Assert.AreEqual(2, claimSetsArray.GetArrayLength());
        Assert.AreEqual("given_name", claimSetsArray[0][0].GetString());
        Assert.AreEqual("family_name", claimSetsArray[0][1].GetString());
        Assert.AreEqual("display_name", claimSetsArray[1][0].GetString());

        //Verify roundtrip.
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, options)!;
        Assert.IsNotNull(deserialized.Credentials);
        Assert.IsNotNull(deserialized.Credentials[0].ClaimSets);
        var claimSets = deserialized.Credentials[0].ClaimSets!;
        Assert.HasCount(1, claimSets);
        Assert.IsNotNull(claimSets[0].Options);
        Assert.HasCount(2, claimSets[0].Options!);
        Assert.HasCount(2, claimSets[0].Options![0]);
        Assert.HasCount(1, claimSets[0].Options![1]);
    }

    [TestMethod]
    public void IntentToRetainRoundtrip()
    {
        var original = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "mdl",
                    Format = "mso_mdoc",
                    Meta = new CredentialQueryMeta
                    {
                        DoctypeValue = "org.iso.18013.5.1.mDL"
                    },
                    Claims =
                    [
                        new ClaimsQuery
                        {
                            Id = "given_name",
                            Path = DcqlClaimPattern.ForMdoc("org.iso.18013.5.1", "given_name"),
                            IntentToRetain = true
                        },
                        new ClaimsQuery
                        {
                            Id = "family_name",
                            Path = DcqlClaimPattern.ForMdoc("org.iso.18013.5.1", "family_name"),
                            IntentToRetain = false
                        },
                        new ClaimsQuery
                        {
                            Id = "portrait",
                            Path = DcqlClaimPattern.ForMdoc("org.iso.18013.5.1", "portrait")
                        }
                    ]
                }
            ]
        };

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        string json = JsonSerializer.Serialize(original, options);
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, options)!;

        Assert.IsNotNull(deserialized.Credentials);
        Assert.IsNotNull(deserialized.Credentials[0].Claims);
        var claims = deserialized.Credentials[0].Claims!;
        Assert.HasCount(3, claims);
        Assert.IsTrue(claims[0].IntentToRetain!.Value);
        Assert.IsFalse(claims[1].IntentToRetain!.Value);
        Assert.IsNull(claims[2].IntentToRetain);

        //Verify wire format includes intent_to_retain only when set.
        using var doc = JsonDocument.Parse(json);
        var claimsArray = doc.RootElement
            .GetProperty("credentials")[0]
            .GetProperty("claims");
        Assert.IsTrue(claimsArray[0].TryGetProperty("intent_to_retain", out _));
        Assert.IsTrue(claimsArray[1].TryGetProperty("intent_to_retain", out _));
        Assert.IsFalse(claimsArray[2].TryGetProperty("intent_to_retain", out _));
    }

    [TestMethod]
    public void EffectiveIdUsesPathWhenIdIsNull()
    {
        var claim = new ClaimsQuery
        {
            Path = DcqlClaimPattern.FromKeys("given_name")
        };

        Assert.AreEqual(claim.Path.ToString(), claim.EffectiveId);
    }

    [TestMethod]
    public void EffectiveIdUsesExplicitId()
    {
        var claim = new ClaimsQuery
        {
            Id = "name_claim",
            Path = DcqlClaimPattern.FromKeys("given_name")
        };

        Assert.AreEqual("name_claim", claim.EffectiveId);
    }

    [TestMethod]
    public void CredentialQueryMetaHasTypeConstraints()
    {
        var withVct = new CredentialQueryMeta { VctValues = ["urn:eudi:pid:1"] };
        Assert.IsTrue(withVct.HasTypeConstraints);

        var withDoctype = new CredentialQueryMeta { DoctypeValue = "org.iso.18013.5.1.mDL" };
        Assert.IsTrue(withDoctype.HasTypeConstraints);

        var empty = new CredentialQueryMeta();
        Assert.IsFalse(empty.HasTypeConstraints);
    }

    [TestMethod]
    public void CredentialQueryMetaGetTypeConstraints()
    {
        var meta = new CredentialQueryMeta
        {
            VctValues = ["urn:eudi:pid:1", "urn:eudi:pid:2"]
        };

        var sdJwtConstraints = meta.GetTypeConstraints("dc+sd-jwt");
        Assert.IsNotNull(sdJwtConstraints);
        Assert.HasCount(2, sdJwtConstraints!);

        var mdocMeta = new CredentialQueryMeta
        {
            DoctypeValue = "org.iso.18013.5.1.mDL"
        };

        var mdocConstraints = mdocMeta.GetTypeConstraints("mso_mdoc");
        Assert.IsNotNull(mdocConstraints);
        Assert.HasCount(1, mdocConstraints!);
        Assert.AreEqual("org.iso.18013.5.1.mDL", mdocConstraints![0]);
    }

    [TestMethod]
    public void MissingCredentialsPropertyThrows()
    {
        const string json = /*lang=json,strict*/ """
            {
                "credential_sets": []
            }
            """;

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<DcqlQuery>(json, options));
    }

    [TestMethod]
    public void MissingCredentialIdThrows()
    {
        const string json = /*lang=json,strict*/ """
            {
                "credentials": [
                    {
                        "format": "dc+sd-jwt"
                    }
                ]
            }
            """;

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<DcqlQuery>(json, options));
    }

    [TestMethod]
    public void MissingClaimsPathThrows()
    {
        const string json = /*lang=json,strict*/ """
            {
                "credentials": [
                    {
                        "id": "test",
                        "format": "dc+sd-jwt",
                        "claims": [
                            {
                                "id": "no_path"
                            }
                        ]
                    }
                ]
            }
            """;

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<DcqlQuery>(json, options));
    }

    [TestMethod]
    public void CredentialSetQueryOptionCount()
    {
        var credentialSet = new CredentialSetQuery
        {
            Options = [["a", "b"], ["c"], ["d", "e", "f"]]
        };

        Assert.AreEqual(3, credentialSet.OptionCount);
    }

    [TestMethod]
    public void ClaimSetQueryOptionCount()
    {
        var claimSet = new ClaimSetQuery
        {
            Options = [["given_name", "family_name"], ["display_name"]]
        };

        Assert.AreEqual(2, claimSet.OptionCount);
    }

    [TestMethod]
    public void TrustedAuthoritiesQueryHasAuthorities()
    {
        var withValues = new TrustedAuthoritiesQuery
        {
            Type = "aki",
            Values = ["abc123"]
        };
        Assert.IsTrue(withValues.HasAuthorities);

        var empty = new TrustedAuthoritiesQuery
        {
            Type = "aki",
            Values = []
        };
        Assert.IsFalse(empty.HasAuthorities);
    }

    [TestMethod]
    public void UnknownPropertiesAreSkipped()
    {
        const string json = /*lang=json,strict*/ """
            {
                "credentials": [
                    {
                        "id": "test",
                        "format": "dc+sd-jwt",
                        "unknown_property": "should be ignored",
                        "another_unknown": 42
                    }
                ],
                "future_extension": true
            }
            """;

        var options = new JsonSerializerOptions().ApplyVerifiableDefaults();
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, options)!;

        Assert.IsNotNull(deserialized.Credentials);
        Assert.HasCount(1, deserialized.Credentials);
        Assert.AreEqual("test", deserialized.Credentials[0].Id);
        Assert.AreEqual("dc+sd-jwt", deserialized.Credentials[0].Format);
    }
}
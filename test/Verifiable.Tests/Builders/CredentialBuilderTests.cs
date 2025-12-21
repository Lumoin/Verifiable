using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Credentials;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Builders;

/// <summary>
/// Strongly-typed claims for an Alumni Credential.
/// Demonstrates type-safe credential construction as an alternative to dictionary-based claims.
/// </summary>
public sealed class AlumniCredentialClaims
{
    [JsonPropertyName("alumniOf")]
    public required string AlumniOf { get; init; }

    [JsonPropertyName("degree")]
    public string? Degree { get; init; }

    [JsonPropertyName("graduationYear")]
    public int? GraduationYear { get; init; }

    [JsonPropertyName("honors")]
    public string? Honors { get; init; }


    /// <summary>
    /// Converts the typed claims to a dictionary for use with CredentialBuilder.
    /// </summary>
    public Dictionary<string, object> ToDictionary()
    {
        var result = new Dictionary<string, object>
        {
            ["alumniOf"] = AlumniOf
        };

        if(Degree != null)
        {
            result["degree"] = Degree;
        }

        if(GraduationYear.HasValue)
        {
            result["graduationYear"] = GraduationYear.Value;
        }

        if(Honors != null)
        {
            result["honors"] = Honors;
        }

        return result;
    }


    /// <summary>
    /// Extracts typed claims from a credential subject.
    /// </summary>
    public static AlumniCredentialClaims FromCredentialSubject(CredentialSubject subject)
    {
        var additionalData = subject.AdditionalData ?? throw new InvalidOperationException("Credential subject has no claims.");

        return new AlumniCredentialClaims
        {
            AlumniOf = GetStringValue(additionalData, "alumniOf")
                ?? throw new InvalidOperationException("Missing required claim: alumniOf"),
            Degree = GetStringValue(additionalData, "degree"),
            GraduationYear = GetIntValue(additionalData, "graduationYear"),
            Honors = GetStringValue(additionalData, "honors")
        };
    }


    private static string? GetStringValue(IDictionary<string, object> data, string key)
    {
        if(!data.TryGetValue(key, out var value))
        {
            return null;
        }

        return value switch
        {
            string s => s,
            JsonElement je when je.ValueKind == JsonValueKind.String => je.GetString(),
            _ => value.ToString()
        };
    }


    private static int? GetIntValue(IDictionary<string, object> data, string key)
    {
        if(!data.TryGetValue(key, out var value))
        {
            return null;
        }

        if(value is int i)
        {
            return i;
        }

        if(value is long l)
        {
            return (int)l;
        }

        if(value is double d)
        {
            return (int)d;
        }

        if(value is JsonElement je)
        {
            if(je.ValueKind == JsonValueKind.Number)
            {
                return je.GetInt32();
            }

            if(je.ValueKind == JsonValueKind.String && int.TryParse(je.GetString(), out var parsed))
            {
                return parsed;
            }
        }

        if(value is string s && int.TryParse(s, out var parsedFromString))
        {
            return parsedFromString;
        }

        return null;
    }
}


/// <summary>
/// Tests for <see cref="CredentialBuilder"/>.
/// </summary>
[TestClass]
public sealed class CredentialBuilderTests
{
    //Test DIDs and identifiers.
    private const string IssuerDidWeb = "did:web:example.com";
    private const string IssuerDidWebUniversity = "did:web:university.example";
    private const string IssuerDidWebCustom = "did:web:custom.example";
    private const string IssuerHttps = "https://vc.example/issuers/5678";
    private const string SubjectDidExample = "did:example:subject";
    private const string SubjectDidExampleAlice = "did:example:alice";
    private const string SubjectDidExampleBob = "did:example:bob";
    private const string SubjectDidExampleAbcdefgh = "did:example:abcdefgh";
    private const string SubjectDidExample123 = "did:example:subject123";
    private const string SubjectDidExampleStudent = "did:example:student";

    //Credential identifiers.
    private const string CustomCredentialId = "https://example.com/credentials/12345";
    private const string CustomCredentialIdPrefix = "https://credentials.example/";
    private const string UrnUuidPrefix = "urn:uuid:";

    //Credential types.
    private const string AlumniCredentialType = "AlumniCredential";
    private const string UniversityDegreeCredentialType = "UniversityDegreeCredential";
    private const string MembershipCredentialType = "MembershipCredential";

    //Claim keys.
    private const string ClaimName = "name";
    private const string ClaimAlumniOf = "alumniOf";
    private const string ClaimDegree = "degree";
    private const string ClaimGraduationYear = "graduationYear";
    private const string ClaimHonors = "honors";

    //Claim values.
    private const string ClaimValueAliceSmith = "Alice Smith";
    private const string ClaimValueBobJones = "Bob Jones";
    private const string ClaimValueExampleUniversity = "Example University";
    private const string ClaimValueTheSchoolOfExamples = "The School of Examples";
    private const string ClaimValueBachelorOfScience = "Bachelor of Science";
    private const string ClaimValueMagnaCumLaude = "Magna Cum Laude";
    private const int ClaimValueGraduationYear = 2024;

    //Issuer metadata.
    private const string IssuerName = "Example University";
    private const string IssuerDescription = "A leading educational institution.";

    //Custom transformation values.
    private const string CustomCredentialName = "Custom Named Credential";

    /// <summary>
    /// The one and only (stateless) builder for Verifiable Credentials used in the tests.
    /// </summary>
    private static CredentialBuilder CredentialBuilder { get; } = new CredentialBuilder();


    [TestMethod]
    public void BuildWithSingleSubjectCreatesValidCredential()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = SubjectDidExample123,
            Claims = new Dictionary<string, object>
            {
                [ClaimName] = ClaimValueAliceSmith,
                [ClaimAlumniOf] = ClaimValueExampleUniversity
            }
        };

        var credential = CredentialBuilder.Build(issuer, subject, additionalTypes: [AlumniCredentialType]);

        Assert.IsNotNull(credential);
        Assert.IsNotNull(credential.Context);
        Assert.IsNotNull(credential.Type);
        Assert.Contains(CredentialConstants.VerifiableCredentialType, credential.Type);
        Assert.Contains(AlumniCredentialType, credential.Type);
        Assert.AreEqual(IssuerDidWeb, credential.Issuer?.Id);
        Assert.IsNotNull(credential.CredentialSubject);
        Assert.HasCount(1, credential.CredentialSubject);
        Assert.AreEqual(SubjectDidExample123, credential.CredentialSubject[0].Id);
        Assert.IsNotNull(credential.Id, "Credential ID should be auto-generated.");
        Assert.IsTrue(credential.Id.StartsWith(UrnUuidPrefix, StringComparison.Ordinal), "Default ID should be a URN UUID.");
    }


    [TestMethod]
    public void BuildWithMultipleSubjectsCreatesValidCredential()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subjects = new List<CredentialSubjectInput>
        {
            new() { Id = SubjectDidExampleAlice, Claims = new Dictionary<string, object> { [ClaimName] = ClaimValueAliceSmith } },
            new() { Id = SubjectDidExampleBob, Claims = new Dictionary<string, object> { [ClaimName] = ClaimValueBobJones } }
        };

        var credential = CredentialBuilder.Build(issuer, subjects);

        Assert.IsNotNull(credential.CredentialSubject);
        Assert.HasCount(2, credential.CredentialSubject);
        Assert.AreEqual(SubjectDidExampleAlice, credential.CredentialSubject[0].Id);
        Assert.AreEqual(SubjectDidExampleBob, credential.CredentialSubject[1].Id);
    }


    [TestMethod]
    public void BuildWithCustomIdUsesProvidedId()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput { Id = SubjectDidExample };

        var credential = CredentialBuilder.Build(issuer, subject, credentialId: CustomCredentialId);

        Assert.AreEqual(CustomCredentialId, credential.Id);
    }


    [TestMethod]
    public void BuildWithValidityPeriodSetsValidFromAndValidUntil()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput { Id = SubjectDidExample };
        var validFrom = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var validUntil = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        var credential = CredentialBuilder.Build(issuer, subject, validFrom: validFrom, validUntil: validUntil);

        Assert.AreEqual(validFrom, credential.ValidFrom);
        Assert.AreEqual(validUntil, credential.ValidUntil);
    }


    [TestMethod]
    public void BuildWithAdditionalTypesIncludesAllTypes()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput { Id = SubjectDidExample };

        var credential = CredentialBuilder.Build(
            issuer,
            subject,
            additionalTypes: [AlumniCredentialType, UniversityDegreeCredentialType]);

        Assert.IsNotNull(credential.Type);
        Assert.Contains(CredentialConstants.VerifiableCredentialType, credential.Type);
        Assert.Contains(AlumniCredentialType, credential.Type);
        Assert.Contains(UniversityDegreeCredentialType, credential.Type);
    }


    [TestMethod]
    public void BuildWithIssuerMetadataPreservesMetadata()
    {
        var issuer = new Issuer
        {
            Id = IssuerDidWeb,
            Name = IssuerName,
            Description = IssuerDescription
        };
        var subject = new CredentialSubjectInput { Id = SubjectDidExample };

        var credential = CredentialBuilder.Build(issuer, subject);

        Assert.AreEqual(IssuerDidWeb, credential.Issuer?.Id);
        Assert.AreEqual(IssuerName, credential.Issuer?.Name);
        Assert.AreEqual(IssuerDescription, credential.Issuer?.Description);
    }


    [TestMethod]
    public void BuildWithCustomIdGeneratorUsesGenerator()
    {
        var counter = 0;
        var customBuilder = new CredentialBuilder
        {
            CredentialIdGenerator = _ => $"{CustomCredentialIdPrefix}{++counter}"
        };
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput { Id = SubjectDidExample };

        var credential1 = customBuilder.Build(issuer, subject);
        var credential2 = customBuilder.Build(issuer, subject);

        Assert.AreEqual($"{CustomCredentialIdPrefix}1", credential1.Id);
        Assert.AreEqual($"{CustomCredentialIdPrefix}2", credential2.Id);
    }


    [TestMethod]
    public void BuildWithSeedCredentialUsesProvidedSeed()
    {
        const string seedName = "Seeded Credential Name";
        const string seedDescription = "Seeded description.";
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput { Id = SubjectDidExample };
        var seedCredential = new VerifiableCredential
        {
            Name = seedName,
            Description = seedDescription
        };

        var credential = CredentialBuilder.Build(seedCredential, issuer, [subject]);

        Assert.AreEqual(seedName, credential.Name);
        Assert.AreEqual(seedDescription, credential.Description);
        Assert.AreEqual(IssuerDidWeb, credential.Issuer?.Id);
    }


    [TestMethod]
    public void BuildWithNullIssuerThrowsArgumentNullException()
    {
        var subject = new CredentialSubjectInput { Id = SubjectDidExample };

        Assert.Throws<ArgumentNullException>(() => CredentialBuilder.Build(null!, subject));
    }


    [TestMethod]
    public void BuildWithNullSubjectThrowsArgumentNullException()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };

        Assert.Throws<ArgumentNullException>(() => CredentialBuilder.Build(issuer, (CredentialSubjectInput)null!));
    }


    [TestMethod]
    public void BuildWithEmptySubjectsThrowsArgumentException()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var emptySubjects = new List<CredentialSubjectInput>();

        var exception = Assert.Throws<ArgumentException>(() => CredentialBuilder.Build(issuer, emptySubjects));

        Assert.IsTrue(exception.Message.Contains("At least one credential subject is required", StringComparison.Ordinal));
    }


    [TestMethod]
    public void BuilderCanBeReusedForMultipleCredentials()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };

        var credential1 = CredentialBuilder.Build(
            issuer,
            new CredentialSubjectInput { Id = SubjectDidExampleAlice });

        var credential2 = CredentialBuilder.Build(
            issuer,
            new CredentialSubjectInput { Id = SubjectDidExampleBob });

        Assert.AreNotEqual(credential1.Id, credential2.Id, "Each credential should have a unique ID.");
        Assert.AreEqual(SubjectDidExampleAlice, credential1.CredentialSubject?[0].Id);
        Assert.AreEqual(SubjectDidExampleBob, credential2.CredentialSubject?[0].Id);
    }


    [TestMethod]
    public void BuildCreatesVc20Context()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput { Id = SubjectDidExample };

        var credential = CredentialBuilder.Build(issuer, subject);

        Assert.IsNotNull(credential.Context);
        Assert.IsNotNull(credential.Context.Contexes);
        Assert.Contains(CredentialConstants.CredentialsV2Context, credential.Context.Contexes);
    }


    [TestMethod]
    public void IssuerImplicitConversionFromStringWorks()
    {
        Issuer issuer = IssuerDidWeb;
        var subject = new CredentialSubjectInput { Id = SubjectDidExample };

        var credential = CredentialBuilder.Build(issuer, subject);

        Assert.AreEqual(IssuerDidWeb, credential.Issuer?.Id);
    }


    [TestMethod]
    public void BuildCredentialMatchesW3CTestVectorStructure()
    {
        //This test verifies the builder produces credentials structurally similar to W3C test vectors.
        var issuer = new Issuer { Id = IssuerHttps };
        var subject = new CredentialSubjectInput
        {
            Id = SubjectDidExampleAbcdefgh,
            Claims = new Dictionary<string, object>
            {
                [ClaimAlumniOf] = ClaimValueTheSchoolOfExamples
            }
        };
        var validFrom = new DateTime(2023, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        var credential = CredentialBuilder.Build(
            issuer,
            subject,
            additionalTypes: [AlumniCredentialType],
            validFrom: validFrom);

        Assert.IsNotNull(credential.Context);
        Assert.IsNotNull(credential.Type);
        Assert.Contains(CredentialConstants.VerifiableCredentialType, credential.Type);
        Assert.Contains(AlumniCredentialType, credential.Type);
        Assert.AreEqual(IssuerHttps, credential.Issuer?.Id);
        Assert.AreEqual(validFrom, credential.ValidFrom);
        Assert.IsNotNull(credential.CredentialSubject);
        Assert.AreEqual(SubjectDidExampleAbcdefgh, credential.CredentialSubject[0].Id);
    }


    [TestMethod]
    public void BuildWithExtendedBuilderAddsCustomTransformations()
    {
        var customBuilder = new CredentialBuilder()
            .With((credential, builder, state) =>
            {
                credential.Name = CustomCredentialName;
                credential.Description = $"Issued by {state.Issuer?.Id}";

                return credential;
            });

        var issuer = new Issuer { Id = IssuerDidWebCustom };
        var subject = new CredentialSubjectInput { Id = SubjectDidExample };

        var credential = customBuilder.Build(issuer, subject);

        Assert.AreEqual(CustomCredentialName, credential.Name);
        Assert.AreEqual($"Issued by {IssuerDidWebCustom}", credential.Description);
    }


    [TestMethod]
    public void JsonRoundTripPreservesAllProperties()
    {
        var issuer = new Issuer
        {
            Id = IssuerDidWebUniversity,
            Name = IssuerName
        };
        var subject = new CredentialSubjectInput
        {
            Id = SubjectDidExampleStudent,
            Claims = new Dictionary<string, object>
            {
                [ClaimDegree] = ClaimValueBachelorOfScience,
                [ClaimGraduationYear] = ClaimValueGraduationYear
            }
        };
        var validFrom = new DateTime(2024, 6, 1, 0, 0, 0, DateTimeKind.Utc);

        var originalCredential = CredentialBuilder.Build(
            issuer,
            subject,
            additionalTypes: [UniversityDegreeCredentialType],
            validFrom: validFrom);

        var json = JsonSerializer.Serialize(originalCredential, TestSetup.DefaultSerializationOptions);
        var deserializedCredential = JsonSerializer.Deserialize<VerifiableCredential>(json, TestSetup.DefaultSerializationOptions);

        Assert.IsNotNull(deserializedCredential);
        Assert.AreEqual(originalCredential.Id, deserializedCredential.Id);
        Assert.AreEqual(originalCredential.Issuer?.Id, deserializedCredential.Issuer?.Id);
        Assert.AreEqual(originalCredential.Issuer?.Name, deserializedCredential.Issuer?.Name);
        Assert.AreEqual(originalCredential.ValidFrom, deserializedCredential.ValidFrom);
        Assert.IsNotNull(deserializedCredential.Type);
        Assert.Contains(UniversityDegreeCredentialType, deserializedCredential.Type);
    }


    [TestMethod]
    public void BuildWithAnonymousSubjectOmitsSubjectId()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Claims = new Dictionary<string, object>
            {
                [MembershipCredentialType] = "Gold"
            }
        };

        var credential = CredentialBuilder.Build(issuer, subject, additionalTypes: [MembershipCredentialType]);

        Assert.IsNotNull(credential.CredentialSubject);
        Assert.HasCount(1, credential.CredentialSubject);
        Assert.IsNull(credential.CredentialSubject[0].Id, "Anonymous subject should not have an ID.");
    }


    [TestMethod]
    public void BuildWithDictionaryAndStronglyTypedClaimsProducesEquivalentCredentials()
    {
        var issuer = new Issuer { Id = IssuerDidWebUniversity, Name = IssuerName };

        //Dictionary-based claims.
        var dictionaryClaims = new Dictionary<string, object>
        {
            [ClaimAlumniOf] = ClaimValueExampleUniversity,
            [ClaimDegree] = ClaimValueBachelorOfScience,
            [ClaimGraduationYear] = ClaimValueGraduationYear,
            [ClaimHonors] = ClaimValueMagnaCumLaude
        };

        //Strongly-typed claims.
        var typedClaims = new AlumniCredentialClaims
        {
            AlumniOf = ClaimValueExampleUniversity,
            Degree = ClaimValueBachelorOfScience,
            GraduationYear = ClaimValueGraduationYear,
            Honors = ClaimValueMagnaCumLaude
        };

        var dictionarySubject = new CredentialSubjectInput { Id = SubjectDidExampleStudent, Claims = dictionaryClaims };
        var typedSubject = new CredentialSubjectInput { Id = SubjectDidExampleStudent, Claims = typedClaims.ToDictionary() };

        var credentialFromDictionary = CredentialBuilder.Build(issuer, dictionarySubject, additionalTypes: [AlumniCredentialType]);
        var credentialFromTyped = CredentialBuilder.Build(issuer, typedSubject, additionalTypes: [AlumniCredentialType]);

        //Both credentials should have equivalent structure.
        Assert.AreEqual(credentialFromDictionary.Issuer?.Id, credentialFromTyped.Issuer?.Id);
        Assert.AreEqual(credentialFromDictionary.CredentialSubject![0].Id, credentialFromTyped.CredentialSubject![0].Id);
        Assert.IsNotNull(credentialFromDictionary.CredentialSubject[0].AdditionalData);
        Assert.IsNotNull(credentialFromTyped.CredentialSubject[0].AdditionalData);

        //Dictionary claim values should match.
        var dictData = credentialFromDictionary.CredentialSubject[0].AdditionalData!;
        var typedData = credentialFromTyped.CredentialSubject[0].AdditionalData!;

        Assert.AreEqual(dictData[ClaimAlumniOf], typedData[ClaimAlumniOf]);
        Assert.AreEqual(dictData[ClaimDegree], typedData[ClaimDegree]);
        Assert.AreEqual(dictData[ClaimGraduationYear], typedData[ClaimGraduationYear]);
        Assert.AreEqual(dictData[ClaimHonors], typedData[ClaimHonors]);
    }


    [TestMethod]
    public void StronglyTypedClaimsRoundTripThroughCredentialSubject()
    {
        var issuer = new Issuer { Id = IssuerDidWebUniversity };

        var originalClaims = new AlumniCredentialClaims
        {
            AlumniOf = ClaimValueExampleUniversity,
            Degree = ClaimValueBachelorOfScience,
            GraduationYear = ClaimValueGraduationYear,
            Honors = ClaimValueMagnaCumLaude
        };

        var subject = new CredentialSubjectInput { Id = SubjectDidExampleStudent, Claims = originalClaims.ToDictionary() };
        var credential = CredentialBuilder.Build(issuer, subject, additionalTypes: [AlumniCredentialType]);

        //Serialize and deserialize to simulate storage/transmission.
        var json = JsonSerializer.Serialize(credential, TestSetup.DefaultSerializationOptions);
        var deserializedCredential = JsonSerializer.Deserialize<VerifiableCredential>(json, TestSetup.DefaultSerializationOptions);

        //Verify the AdditionalData contains expected keys.
        var additionalData = deserializedCredential!.CredentialSubject![0].AdditionalData;
        Assert.IsNotNull(additionalData, "AdditionalData should not be null after deserialization.");
        Assert.IsTrue(additionalData.ContainsKey(ClaimAlumniOf), $"AdditionalData should contain key '{ClaimAlumniOf}'.");
        Assert.IsTrue(additionalData.ContainsKey(ClaimGraduationYear), $"AdditionalData should contain key '{ClaimGraduationYear}'. Keys present: {string.Join(", ", additionalData.Keys)}");

        //Extract claims back to strongly-typed form.
        var extractedClaims = AlumniCredentialClaims.FromCredentialSubject(deserializedCredential!.CredentialSubject![0]);

        Assert.AreEqual(originalClaims.AlumniOf, extractedClaims.AlumniOf);
        Assert.AreEqual(originalClaims.Degree, extractedClaims.Degree);
        Assert.AreEqual(originalClaims.GraduationYear, extractedClaims.GraduationYear, $"GraduationYear value type after deserialization: {additionalData[ClaimGraduationYear]?.GetType().Name ?? "null"}");
        Assert.AreEqual(originalClaims.Honors, extractedClaims.Honors);
    }


    [TestMethod]
    public void StronglyTypedClaimsWithOptionalFieldsOmitsNullValues()
    {
        var issuer = new Issuer { Id = IssuerDidWebUniversity };

        //Only required field set.
        var minimalClaims = new AlumniCredentialClaims
        {
            AlumniOf = ClaimValueExampleUniversity
        };

        var subject = new CredentialSubjectInput { Id = SubjectDidExampleStudent, Claims = minimalClaims.ToDictionary() };
        var credential = CredentialBuilder.Build(issuer, subject, additionalTypes: [AlumniCredentialType]);

        var additionalData = credential.CredentialSubject![0].AdditionalData!;

        Assert.IsTrue(additionalData.ContainsKey(ClaimAlumniOf));
        Assert.IsFalse(additionalData.ContainsKey(ClaimDegree), "Null optional fields should not be included.");
        Assert.IsFalse(additionalData.ContainsKey(ClaimGraduationYear), "Null optional fields should not be included.");
        Assert.IsFalse(additionalData.ContainsKey(ClaimHonors), "Null optional fields should not be included.");
    }


    [TestMethod]
    public void FromCredentialSubjectThrowsOnMissingRequiredClaim()
    {
        var issuer = new Issuer { Id = IssuerDidWeb };
        var subject = new CredentialSubjectInput
        {
            Id = SubjectDidExample,
            Claims = new Dictionary<string, object>
            {
                [ClaimDegree] = ClaimValueBachelorOfScience
            }
        };

        var credential = CredentialBuilder.Build(issuer, subject);

        var exception = Assert.Throws<InvalidOperationException>(
            () => AlumniCredentialClaims.FromCredentialSubject(credential.CredentialSubject![0]));

        Assert.IsTrue(exception.Message.Contains("alumniOf", StringComparison.OrdinalIgnoreCase));
    }
}
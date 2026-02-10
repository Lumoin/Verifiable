using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.SelectiveDisclosure;

namespace Verifiable.Tests.Dcql;

[TestClass]
internal sealed class DcqlQueryTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string IdentityCredentialId = "identity_credential";
    private const string SdJwtFormat = "vc+sd-jwt";
    private const string IdentityVct = "https://example.com/identity";
    private const string GivenNameClaim = "given_name";
    private const string FamilyNameClaim = "family_name";
    private const string EmailClaim = "email";
    private const string BirthdateClaim = "birthdate";


    [TestMethod]
    public void PatternSegmentKeyCreatesKeySegment()
    {
        var segment = PatternSegment.Key(GivenNameClaim);
        Assert.IsTrue(segment.IsKey);
        Assert.IsFalse(segment.IsIndex);
        Assert.IsFalse(segment.IsWildcard);
        Assert.AreEqual(GivenNameClaim, segment.KeyValue);
        Assert.IsNull(segment.IndexValue);
    }


    [TestMethod]
    public void PatternSegmentIndexCreatesIndexSegment()
    {
        var segment = PatternSegment.Index(5);
        Assert.IsFalse(segment.IsKey);
        Assert.IsTrue(segment.IsIndex);
        Assert.IsFalse(segment.IsWildcard);
        Assert.IsNull(segment.KeyValue);
        Assert.AreEqual(5, segment.IndexValue);
    }


    [TestMethod]
    public void PatternSegmentWildcardCreatesWildcardSegment()
    {
        var segment = PatternSegment.Wildcard();
        Assert.IsFalse(segment.IsKey);
        Assert.IsFalse(segment.IsIndex);
        Assert.IsTrue(segment.IsWildcard);
        Assert.IsNull(segment.KeyValue);
        Assert.IsNull(segment.IndexValue);
    }


    [TestMethod]
    public void PatternSegmentKeyThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => PatternSegment.Key(null!));
    }


    [TestMethod]
    public void PatternSegmentIndexThrowsOnNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => PatternSegment.Index(-1));
    }


    [TestMethod]
    public void PatternSegmentToStringReturnsExpectedFormat()
    {
        Assert.AreEqual($"\"{GivenNameClaim}\"", PatternSegment.Key(GivenNameClaim).ToString());
        Assert.AreEqual("5", PatternSegment.Index(5).ToString());
        Assert.AreEqual("null", PatternSegment.Wildcard().ToString());
    }


    [TestMethod]
    public void ClaimPatternFromKeysCreatesPattern()
    {
        var pattern = DcqlClaimPattern.FromKeys("credentialSubject", "address", "city");
        Assert.AreEqual(3, pattern.Count);
        Assert.AreEqual("credentialSubject", pattern[0].KeyValue);
        Assert.AreEqual("address", pattern[1].KeyValue);
        Assert.AreEqual("city", pattern[2].KeyValue);
    }


    [TestMethod]
    public void ClaimPatternForMdocCreatesTwoSegmentPattern()
    {
        var pattern = DcqlClaimPattern.ForMdoc("org.iso.18013.5.1", GivenNameClaim);
        Assert.AreEqual(2, pattern.Count);
        Assert.AreEqual("org.iso.18013.5.1", pattern[0].KeyValue);
        Assert.AreEqual(GivenNameClaim, pattern[1].KeyValue);
    }


    [TestMethod]
    public void ClaimPatternFromKeysThrowsOnEmpty()
    {
        Assert.Throws<ArgumentException>(() => DcqlClaimPattern.FromKeys());
    }


    [TestMethod]
    public void ClaimPatternEqualityWorksCorrectly()
    {
        var pattern1 = DcqlClaimPattern.FromKeys(GivenNameClaim);
        var pattern2 = DcqlClaimPattern.FromKeys(GivenNameClaim);
        var pattern3 = DcqlClaimPattern.FromKeys(FamilyNameClaim);
        Assert.AreEqual(pattern1, pattern2);
        Assert.AreNotEqual(pattern1, pattern3);
    }


    [TestMethod]
    public void ClaimPatternMatchesConcreteCredentialPath()
    {
        var pattern = new DcqlClaimPattern(
            PatternSegment.Key("items"),
            PatternSegment.Wildcard(),
            PatternSegment.Key("name"));
        var concretePath = CredentialPath.FromJsonPointer("/items/0/name");
        Assert.IsTrue(pattern.Matches(concretePath));
    }


    [TestMethod]
    public void ClaimPatternDoesNotMatchDifferentLength()
    {
        var pattern = DcqlClaimPattern.FromKeys("items", "name");
        var longerPath = CredentialPath.FromJsonPointer("/items/0/name");
        Assert.IsFalse(pattern.Matches(longerPath));
    }


    [TestMethod]
    public void ClaimPatternTryResolveSucceedsForConcretePattern()
    {
        var pattern = DcqlClaimPattern.FromKeys("address", "city");
        Assert.IsTrue(pattern.TryResolve(out var credentialPath));
        Assert.AreEqual(CredentialPath.FromJsonPointer("/address/city"), credentialPath);
    }


    [TestMethod]
    public void ClaimPatternTryResolveFailsForWildcardPattern()
    {
        var pattern = new DcqlClaimPattern(
            PatternSegment.Key("items"),
            PatternSegment.Wildcard(),
            PatternSegment.Key("name"));
        Assert.IsFalse(pattern.TryResolve(out _));
    }


    [TestMethod]
    public void ClaimPatternToStringReturnsJsonArrayFormat()
    {
        var pattern = DcqlClaimPattern.FromKeys(GivenNameClaim);
        Assert.AreEqual("[\"given_name\"]", pattern.ToString());
    }


    [TestMethod]
    public void BasicIdentityCredentialQueryCanBeConstructed()
    {
        var query = CreateBasicIdentityQuery();
        Assert.IsNotNull(query.Credentials);
        Assert.HasCount(1, query.Credentials);
        Assert.AreEqual(IdentityCredentialId, query.Credentials[0].Id);
        Assert.AreEqual(SdJwtFormat, query.Credentials[0].Format);
        Assert.HasCount(3, query.Credentials[0].Claims!);
    }


    [TestMethod]
    public void QueryValidationPassesForValidQuery()
    {
        var query = CreateBasicIdentityQuery();
        var issues = query.Validate();
        Assert.IsEmpty(issues, "Expected no validation issues.");
    }


    [TestMethod]
    public void QueryValidationFailsForMissingFormat()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = IdentityCredentialId,
                    Format = ""
                }
            ]
        };
        var issues = query.Validate();
        Assert.IsNotEmpty(issues);
        var formatIssue = issues.FirstOrDefault(i => i.Contains("format", StringComparison.OrdinalIgnoreCase));
        Assert.IsNotNull(formatIssue, "Expected a validation issue mentioning format.");
    }


    [TestMethod]
    public void QueryValidationFailsForDuplicateIds()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery { Id = "duplicate", Format = SdJwtFormat },
                new CredentialQuery { Id = "duplicate", Format = SdJwtFormat }
            ]
        };
        var issues = query.Validate();
        var duplicateIssue = issues.FirstOrDefault(i => i.Contains("Duplicate", StringComparison.OrdinalIgnoreCase));
        Assert.IsNotNull(duplicateIssue, "Expected a validation issue mentioning duplicate.");
    }


    [TestMethod]
    public void GetAllRequestedPatternsReturnsAllPatterns()
    {
        var query = CreateBasicIdentityQuery();
        var patterns = query.GetAllRequestedPatterns();

        Assert.HasCount(3, patterns);
        Assert.Contains(DcqlClaimPattern.FromKeys(GivenNameClaim), patterns);
        Assert.Contains(DcqlClaimPattern.FromKeys(FamilyNameClaim), patterns);
        Assert.Contains(DcqlClaimPattern.FromKeys(EmailClaim), patterns);
    }


    [TestMethod]
    public void GetRequestedFormatsReturnsUniqueFormats()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery { Id = "cred1", Format = SdJwtFormat },
                new CredentialQuery { Id = "cred2", Format = "mso_mdoc" },
                new CredentialQuery { Id = "cred3", Format = SdJwtFormat }
            ]
        };

        var formats = query.GetRequestedFormats();
        Assert.HasCount(2, formats);
        Assert.Contains(SdJwtFormat, formats);
        Assert.Contains("mso_mdoc", formats);
    }


    [TestMethod]
    public void CoarsePredicatesExtractFormatCorrectly()
    {
        var query = CreateBasicIdentityQuery();
        var predicates = DcqlCoarsePredicates.ExtractAll(query);

        Assert.HasCount(1, predicates);
        Assert.AreEqual(SdJwtFormat, predicates[0].MustMatchFormat);
    }


    [TestMethod]
    public void CoarsePredicatesExtractVctCorrectly()
    {
        var query = CreateBasicIdentityQuery();
        var predicates = DcqlCoarsePredicates.ExtractAll(query);

        Assert.IsNotNull(predicates[0].MustMatchAnyType);
        Assert.Contains(IdentityVct, predicates[0].MustMatchAnyType!);
    }


    [TestMethod]
    public void CoarsePredicatesExtractMustHavePatternsCorrectly()
    {
        var query = CreateBasicIdentityQuery();
        var predicates = DcqlCoarsePredicates.ExtractAll(query);

        Assert.IsNotNull(predicates[0].MustHavePatterns);
        Assert.HasCount(3, predicates[0].MustHavePatterns!);
    }


    [TestMethod]
    public void CoarsePredicatesDoNotIncludeValueConstrainedPaths()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = IdentityCredentialId,
                    Format = SdJwtFormat,
                    Claims =
                    [
                        new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(GivenNameClaim) },
                        new ClaimsQuery
                        {
                            Path = DcqlClaimPattern.FromKeys("age"),
                            Values = [21, 22, 23]
                        }
                    ]
                }
            ]
        };

        var predicates = DcqlCoarsePredicates.ExtractAll(query);
        Assert.IsNotNull(predicates[0].MustHavePatterns);

        //Both paths are required with no claim_sets, so both are in coarse predicates.
        Assert.HasCount(2, predicates[0].MustHavePatterns!);
    }


    [TestMethod]
    public void PreparedQueryIsValidForValidInput()
    {
        var query = CreateBasicIdentityQuery();
        var prepared = DcqlPreparer.Prepare(query);

        Assert.IsTrue(prepared.IsValid);
        Assert.IsEmpty(prepared.ValidationIssues);
    }


    [TestMethod]
    public void PreparedQueryContainsAllRequestedPatterns()
    {
        var query = CreateBasicIdentityQuery();
        var prepared = DcqlPreparer.Prepare(query);

        Assert.HasCount(3, prepared.AllRequestedPatterns);
    }


    [TestMethod]
    public void PreparedQueryContainsCoarsePredicates()
    {
        var query = CreateBasicIdentityQuery();
        var prepared = DcqlPreparer.Prepare(query);

        Assert.HasCount(1, prepared.CoarsePredicates);
        Assert.AreEqual(IdentityCredentialId, prepared.CoarsePredicates[0].CredentialQueryId);
    }


    [TestMethod]
    public void EvaluationMatchesCredentialWithAllRequiredClaims()
    {
        var query = CreateBasicIdentityQuery();
        var prepared = DcqlPreparer.Prepare(query);
        var credential = new TestCredential
        {
            Format = SdJwtFormat,
            Type = IdentityVct,
            Claims = new Dictionary<string, object>
            {
                [GivenNameClaim] = "Bob",
                [FamilyNameClaim] = "Williams",
                [EmailClaim] = "bob.williams@example.com",
                [BirthdateClaim] = "1992-11-30"
            }
        };
        var matches = DcqlEvaluator.Evaluate(
            prepared,
            [credential],
            TestCredentialMetadataExtractor,
            TestCredentialClaimExtractor).ToList();

        Assert.HasCount(1, matches);
        Assert.AreEqual(IdentityCredentialId, matches[0].CredentialQueryId);
        Assert.HasCount(3, matches[0].MatchedPatterns);
    }


    [TestMethod]
    public void EvaluationDoesNotMatchCredentialWithMissingRequiredClaim()
    {
        var query = CreateBasicIdentityQuery();
        var prepared = DcqlPreparer.Prepare(query);
        var credential = new TestCredential
        {
            Format = SdJwtFormat,
            Type = IdentityVct,
            Claims = new Dictionary<string, object>
            {
                [GivenNameClaim] = "Bob",
                [FamilyNameClaim] = "Williams"
                //Missing email.
            }
        };

        var matches = DcqlEvaluator.Evaluate(
            prepared,
            [credential],
            TestCredentialMetadataExtractor,
            TestCredentialClaimExtractor).ToList();
        Assert.IsEmpty(matches);
    }


    [TestMethod]
    public void EvaluationDoesNotMatchCredentialWithWrongFormat()
    {
        var query = CreateBasicIdentityQuery();
        var prepared = DcqlPreparer.Prepare(query);
        var credential = new TestCredential
        {
            Format = "mso_mdoc",
            Type = IdentityVct,
            Claims = new Dictionary<string, object>
            {
                [GivenNameClaim] = "Bob",
                [FamilyNameClaim] = "Williams",
                [EmailClaim] = "bob@example.com"
            }
        };

        var matches = DcqlEvaluator.Evaluate(
            prepared,
            [credential],
            TestCredentialMetadataExtractor,
            TestCredentialClaimExtractor).ToList();
        Assert.IsEmpty(matches);
    }


    [TestMethod]
    public void EvaluationDoesNotMatchCredentialWithWrongType()
    {
        var query = CreateBasicIdentityQuery();
        var prepared = DcqlPreparer.Prepare(query);
        var credential = new TestCredential
        {
            Format = SdJwtFormat,
            Type = "https://example.com/other_credential",
            Claims = new Dictionary<string, object>
            {
                [GivenNameClaim] = "Bob",
                [FamilyNameClaim] = "Williams",
                [EmailClaim] = "bob@example.com"
            }
        };

        var matches = DcqlEvaluator.Evaluate(
            prepared,
            [credential],
            TestCredentialMetadataExtractor,
            TestCredentialClaimExtractor).ToList();
        Assert.IsEmpty(matches);
    }


    [TestMethod]
    public void EvaluationMatchesValueConstraint()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = IdentityCredentialId,
                    Format = SdJwtFormat,
                    Claims =
                    [
                        new ClaimsQuery
                        {
                            Path = DcqlClaimPattern.FromKeys("country"),
                            Values = ["US", "CA", "UK"]
                        }
                    ]
                }
            ]
        };

        var prepared = DcqlPreparer.Prepare(query);
        var matchingCredential = new TestCredential
        {
            Format = SdJwtFormat,
            Claims = new Dictionary<string, object> { ["country"] = "US" }
        };

        var nonMatchingCredential = new TestCredential
        {
            Format = SdJwtFormat,
            Claims = new Dictionary<string, object> { ["country"] = "DE" }
        };

        var matches = DcqlEvaluator.Evaluate(
            prepared,
            [matchingCredential, nonMatchingCredential],
            TestCredentialMetadataExtractor,
            TestCredentialClaimExtractor).ToList();

        Assert.HasCount(1, matches);
    }


    [TestMethod]
    public void EvaluationHandlesOptionalClaims()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = IdentityCredentialId,
                    Format = SdJwtFormat,
                    Claims =
                    [
                        new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(GivenNameClaim), Required = true },
                        new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("middle_name"), Required = false }
                    ]
                }
            ]
        };
        var prepared = DcqlPreparer.Prepare(query);
        var credential = new TestCredential
        {
            Format = SdJwtFormat,
            Claims = new Dictionary<string, object>
            {
                [GivenNameClaim] = "Bob"
                //No middle_name, but it is optional.
            }
        };

        var matches = DcqlEvaluator.Evaluate(
            prepared,
            [credential],
            TestCredentialMetadataExtractor,
            TestCredentialClaimExtractor).ToList();
        Assert.HasCount(1, matches);
    }


    [TestMethod]
    public void EvaluationReturnsMultipleMatchesForMultipleCredentials()
    {
        var query = CreateBasicIdentityQuery();
        var prepared = DcqlPreparer.Prepare(query);
        var credentials = new[]
        {
            new TestCredential
            {
                Format = SdJwtFormat,
                Type = IdentityVct,
                Claims = new Dictionary<string, object>
                {
                    [GivenNameClaim] = "Alice",
                    [FamilyNameClaim] = "Smith",
                    [EmailClaim] = "alice@example.com"
                }
            },
            new TestCredential
            {
                Format = SdJwtFormat,
                Type = IdentityVct,
                Claims = new Dictionary<string, object>
                {
                    [GivenNameClaim] = "Bob",
                    [FamilyNameClaim] = "Williams",
                    [EmailClaim] = "bob@example.com"
                }
            }
        };

        var matches = DcqlEvaluator.Evaluate(
            prepared,
            credentials,
            TestCredentialMetadataExtractor,
            TestCredentialClaimExtractor).ToList();
        Assert.HasCount(2, matches);
    }


    [TestMethod]
    public void ClaimSetIsSatisfiedByMatchingClaims()
    {
        var claimSet = new ClaimSetQuery
        {
            Options =
            [
                [GivenNameClaim, FamilyNameClaim],
                ["display_name"]
            ]
        };

        var availableClaims = new HashSet<string> { GivenNameClaim, FamilyNameClaim, EmailClaim };
        Assert.IsTrue(claimSet.IsSatisfiedBy(availableClaims));
    }


    [TestMethod]
    public void ClaimSetIsNotSatisfiedByMissingClaims()
    {
        var claimSet = new ClaimSetQuery
        {
            Options =
            [
                [GivenNameClaim, FamilyNameClaim],
                ["display_name"]
            ]
        };

        var availableClaims = new HashSet<string> { GivenNameClaim, EmailClaim };
        Assert.IsFalse(claimSet.IsSatisfiedBy(availableClaims));
    }


    [TestMethod]
    public void ClaimSetFirstSatisfyingOptionReturnsPreferredOption()
    {
        var claimSet = new ClaimSetQuery
        {
            Options =
            [
                [GivenNameClaim, FamilyNameClaim],
                ["display_name"]
            ]
        };

        var availableClaims = new HashSet<string> { GivenNameClaim, FamilyNameClaim, "display_name" };
        var satisfying = claimSet.FirstSatisfyingOption(availableClaims);

        Assert.IsNotNull(satisfying);
        Assert.HasCount(2, satisfying);
        Assert.Contains(GivenNameClaim, satisfying);
    }


    [TestMethod]
    public void CredentialSetIsSatisfiedByMatchingCredentials()
    {
        var credentialSet = new CredentialSetQuery
        {
            Options =
            [
                ["passport", "visa"],
                ["national_id"]
            ]
        };

        var availableCredentials = new HashSet<string> { "national_id" };
        Assert.IsTrue(credentialSet.IsSatisfiedBy(availableCredentials));
    }


    [TestMethod]
    public void CredentialSetRequiresBothInAnOption()
    {
        var credentialSet = new CredentialSetQuery
        {
            Options =
            [
                ["passport", "visa"]
            ]
        };

        var onlyPassport = new HashSet<string> { "passport" };
        var both = new HashSet<string> { "passport", "visa" };

        Assert.IsFalse(credentialSet.IsSatisfiedBy(onlyPassport));
        Assert.IsTrue(credentialSet.IsSatisfiedBy(both));
    }


    [TestMethod]
    public void CredentialSetGetAllReferencedCredentialIdsReturnsAll()
    {
        var credentialSet = new CredentialSetQuery
        {
            Options =
            [
                ["passport", "visa"],
                ["national_id"]
            ]
        };

        var allIds = credentialSet.GetAllReferencedCredentialIds();

        Assert.HasCount(3, allIds);
        Assert.Contains("passport", allIds);
        Assert.Contains("visa", allIds);
        Assert.Contains("national_id", allIds);
    }


    [TestMethod]
    public void TrustedAuthoritiesIsTrustedReturnsTrueForMatchingAuthority()
    {
        var authorities = new TrustedAuthoritiesQuery
        {
            Type = "aki",
            Values = ["authority1", "authority2"]
        };

        Assert.IsTrue(authorities.IsTrusted("authority1"));
        Assert.IsTrue(authorities.IsTrusted("authority2"));
        Assert.IsFalse(authorities.IsTrusted("authority3"));
    }


    private static DcqlQuery CreateBasicIdentityQuery()
    {
        return new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = IdentityCredentialId,
                    Format = SdJwtFormat,
                    Meta = new CredentialQueryMeta
                    {
                        VctValues = [IdentityVct]
                    },
                    Claims =
                    [
                        new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(GivenNameClaim) },
                        new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(FamilyNameClaim) },
                        new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(EmailClaim) }
                    ]
                }
            ]
        };
    }


    private static DcqlCredentialMetadata TestCredentialMetadataExtractor(TestCredential credential)
    {
        return new DcqlCredentialMetadata
        {
            Format = credential.Format,
            CredentialType = credential.Type,
            Issuer = credential.Issuer
        };
    }


    private static bool TestCredentialClaimExtractor(TestCredential credential, DcqlClaimPattern pattern, out object? value)
    {
        //Simple implementation for single-element concrete patterns.
        if(pattern.Count == 1 && pattern[0].IsKey)
        {
            return credential.Claims.TryGetValue(pattern[0].KeyValue!, out value);
        }

        //Handle nested paths.
        object? current = credential.Claims;
        for(int i = 0; i < pattern.Count; i++)
        {
            var segment = pattern[i];
            if(current is not IDictionary<string, object> dict)
            {
                value = null;
                return false;
            }

            if(!segment.IsKey || !dict.TryGetValue(segment.KeyValue!, out current))
            {
                value = null;
                return false;
            }
        }

        value = current;
        return true;
    }


    private sealed class TestCredential
    {
        public required string Format { get; init; }
        public string? Type { get; init; }
        public string? Issuer { get; init; }
        public required Dictionary<string, object> Claims { get; init; }
    }
}
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Tests.Dcql;

[TestClass]
internal sealed class DcqlQueryTests
{
    public TestContext TestContext { get; set; } = null!;

    private static string IdentityCredentialId { get; } = "identity_credential";

    /// <summary>
    /// The DCQL format identifier for an SD-JWT VC — the string a <c>format</c> member carries in
    /// a DCQL query, which is what every rule keyed on the format reads, rather than the credential
    /// media type of the same family.
    /// </summary>
    private static string SdJwtFormat { get; } = DcqlCredentialFormats.SdJwt;

    private static string IdentityVct { get; } = "https://example.com/identity";

    private static string GivenNameClaim { get; } = "given_name";

    private static string FamilyNameClaim { get; } = "family_name";

    private static string EmailClaim { get; } = "email";

    private static string BirthdateClaim { get; } = "birthdate";

    /// <summary>
    /// The words Section 6.1 states its <c>id</c> character class in, so a test reads a recorded
    /// validation issue against the rule's own sentence rather than a paraphrase of it.
    /// </summary>
    private static string Section61CharacterClass { get; } = "alphanumeric, underscore (_), or hyphen (-) characters";


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


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "Within the Authorization Request,
    /// the same id MUST NOT be present more than once." Two credential queries sharing an <c>id</c>
    /// make the response's own keying ambiguous, so validation records it as an issue stating the
    /// rule in Section 6.1's own words.
    /// </summary>
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
        Assert.AreEqual(IdentityCredentialId, prepared.CoarsePredicates[0].CredentialQueryId.Value);
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
        Assert.AreEqual(IdentityCredentialId, matches[0].CredentialQueryId.Value);
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
                    Meta = new CredentialQueryMeta { VctValues = [IdentityVct] },
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
            Type = IdentityVct,
            Claims = new Dictionary<string, object> { ["country"] = "US" }
        };

        var nonMatchingCredential = new TestCredential
        {
            Format = SdJwtFormat,
            Type = IdentityVct,
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
                    Meta = new CredentialQueryMeta { VctValues = [IdentityVct] },
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
            Type = IdentityVct,
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


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "A Credential is identified as
    /// a match to a Trusted Authorities Query if it matches with one of the provided values in one
    /// of the provided types." An <c>aki</c> entry (§6.1.1.1) matches when the credential's evidence
    /// carries any of the entry's AuthorityKeyIdentifier values (OR across values); evidence naming
    /// none of them does not match.
    /// </summary>
    [TestMethod]
    public void TrustedAuthoritiesMatchesReturnsTrueForAnyMatchingAkiValue()
    {
        AuthorityKeyIdentifier authority1 = new(new byte[] { 1, 2, 3 });
        AuthorityKeyIdentifier authority2 = new(new byte[] { 4, 5, 6 });
        AuthorityKeyIdentifier stranger = new(new byte[] { 7, 8, 9 });

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = DcqlTrustedAuthorityTypes.Aki,
            Values = [authority1.ToBase64Url(), authority2.ToBase64Url()]
        };

        var matchesFirst = new TrustedAuthorityEvidence { AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { authority1 } };
        var matchesSecond = new TrustedAuthorityEvidence { AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { authority2 } };
        var matchesNeither = new TrustedAuthorityEvidence { AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { stranger } };

        Assert.IsTrue(authorities.Matches(matchesFirst));
        Assert.IsTrue(authorities.Matches(matchesSecond));
        Assert.IsFalse(authorities.Matches(matchesNeither));
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "id: REQUIRED. A string
    /// identifying the Credential in the response and, if provided, the constraints in
    /// credential_sets. The value MUST be a non-empty string consisting of alphanumeric, underscore
    /// (_), or hyphen (-) characters." A credential query carrying no <c>id</c> names nothing the
    /// response can key on, so validation records the requirement in Section 6.1's own words.
    /// </summary>
    [TestMethod]
    public void QueryValidationFailsForAMissingId()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Format = SdJwtFormat,
                    Meta = new CredentialQueryMeta { VctValues = [IdentityVct] }
                }
            ]
        };

        var issues = query.Validate();
        var idIssue = issues.FirstOrDefault(i => i.Contains(Section61CharacterClass, StringComparison.Ordinal));

        Assert.IsNotNull(
            idIssue,
            "Section 6.1 makes id REQUIRED, so a credential query without one is recorded as a validation issue quoting the rule.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters." An
    /// <c>id</c> carrying a space is non-empty yet outside that class, so validation records it as
    /// an issue in Section 6.1's own words rather than passing it on as a usable identifier.
    /// </summary>
    [TestMethod]
    public void QueryValidationFailsForAnIdOutsideTheAllowedCharacterClass()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "identity credential",
                    Format = SdJwtFormat,
                    Meta = new CredentialQueryMeta { VctValues = [IdentityVct] }
                }
            ]
        };

        var issues = query.Validate();
        var idIssue = issues.FirstOrDefault(i => i.Contains(Section61CharacterClass, StringComparison.Ordinal));

        Assert.IsNotNull(
            idIssue,
            "Section 6.1 allows only alphanumeric, underscore and hyphen characters, so a space in an id is recorded as a validation issue.");
        Assert.Contains(
            "identity credential",
            idIssue,
            "The issue names the id it refused.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters." An id outside
    /// that class identifies no Credential in the response, so evaluating a single credential
    /// against such a query is refused outright instead of producing a result keyed on a value the
    /// response could never carry.
    /// </summary>
    [TestMethod]
    public void EvaluateSingleOverAnIdOutsideTheAllowedCharacterClassIsRefused()
    {
        var credentialQuery = new CredentialQuery
        {
            Id = "identity credential",
            Format = SdJwtFormat,
            Meta = new CredentialQueryMeta { VctValues = [IdentityVct] },
            Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(GivenNameClaim) }]
        };

        TestCredential credential = CreateMatchingIdentityCredential();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => DcqlEvaluator.EvaluateSingle(
                credentialQuery,
                credential,
                TestCredentialMetadataExtractor(credential),
                TestCredentialClaimExtractor),
            "Section 6.1: an id outside the allowed character class never evaluates.");

        Assert.Contains(
            "identity credential",
            exception.Message,
            "The refusal names the id it read.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters." A query whose
    /// recorded issues include such an id is not a query any credential can be evaluated against:
    /// evaluation refuses it and names the first issue, rather than answering with an empty match
    /// list a caller could read as "no credential matched".
    /// </summary>
    [TestMethod]
    public void EvaluationOverAQueryRecordingAnIdIssueIsRefused()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "identity credential",
                    Format = SdJwtFormat,
                    Meta = new CredentialQueryMeta { VctValues = [IdentityVct] },
                    Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(GivenNameClaim) }]
                }
            ]
        };

        //A Section 6.1-invalid id yields no coarse predicates to filter storage with — the
        //predicates key on the very identifier the query does not have — so the prepared shape
        //carrying the issue is stated here directly.
        var prepared = new PreparedDcqlQuery
        {
            Query = query,
            CoarsePredicates = [],
            AllRequestedPatterns = new HashSet<DcqlClaimPattern>(),
            RequestedFormats = new HashSet<string> { SdJwtFormat },
            ValidationIssues = query.Validate()
        };

        Assert.IsFalse(
            prepared.IsValid,
            "Section 6.1: a query whose id carries a space is not valid.");

        TestCredential credential = CreateMatchingIdentityCredential();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => DcqlEvaluator.Evaluate(
                prepared,
                [credential],
                TestCredentialMetadataExtractor,
                TestCredentialClaimExtractor).ToList(),
            "Section 6.1: a query recording an invalid id never evaluates.");

        Assert.Contains(
            prepared.ValidationIssues[0],
            exception.Message,
            "The refusal names the query's first recorded validation issue.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters." Preparation is
    /// the step that reports what is wrong with a query, and the query it is handed can come off the
    /// wire, so an <c>id</c> carrying a space is recorded as an issue and answered — never raised at
    /// the caller who asked what was wrong.
    /// </summary>
    [TestMethod]
    public void PreparingAQueryWhoseIdCarriesASpaceRecordsTheIssueWithoutThrowing()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "identity credential",
                    Format = SdJwtFormat,
                    Meta = new CredentialQueryMeta { VctValues = [IdentityVct] },
                    Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(GivenNameClaim) }]
                }
            ]
        };

        PreparedDcqlQuery prepared = DcqlPreparer.Prepare(query);

        Assert.IsFalse(prepared.IsValid, "Section 6.1: a query whose id carries a space is not valid.");

        string? idIssue = prepared.ValidationIssues.FirstOrDefault(i => i.Contains(Section61CharacterClass, StringComparison.Ordinal));
        Assert.IsNotNull(idIssue, "The recorded issue states Section 6.1's character class.");
        Assert.IsEmpty(
            prepared.CoarsePredicates,
            "Coarse predicates key on the identifier the query does not have, so none is extracted for the offending query.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "id: REQUIRED. A string identifying
    /// the Credential in the response and, if provided, the constraints in credential_sets." A
    /// credential query carrying no <c>id</c> at all is the same wire fault as one carrying an
    /// unusable value, so preparation records it and names the position of the entry it read, which is
    /// the only thing that distinguishes an absent id from another absent id.
    /// </summary>
    [TestMethod]
    public void PreparingAQueryWithAMissingIdRecordsTheIssueWithoutThrowing()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Format = SdJwtFormat,
                    Meta = new CredentialQueryMeta { VctValues = [IdentityVct] },
                    Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(GivenNameClaim) }]
                }
            ]
        };

        PreparedDcqlQuery prepared = DcqlPreparer.Prepare(query);

        Assert.IsFalse(prepared.IsValid, "Section 6.1 makes id REQUIRED, so a query without one is not valid.");

        string? idIssue = prepared.ValidationIssues.FirstOrDefault(i => i.Contains(Section61CharacterClass, StringComparison.Ordinal));
        Assert.IsNotNull(idIssue, "The recorded issue states Section 6.1's requirement.");
        Assert.Contains("position 0", idIssue, "The issue names the zero-based position of the credential query it read.");
        Assert.IsEmpty(prepared.CoarsePredicates, "No coarse predicates are extracted for a query with no usable identifier.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters." Handing an
    /// invalid prepared query to evaluation is a caller defect, so the refusal happens where the
    /// mistake is — at the call — rather than at whatever later point the returned sequence is first
    /// enumerated, whose stack no longer names the caller that supplied the query.
    /// </summary>
    [TestMethod]
    public void EvaluationRefusesAnInvalidPreparedQueryAtTheCallRatherThanAtEnumeration()
    {
        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "identity credential",
                    Format = SdJwtFormat,
                    Meta = new CredentialQueryMeta { VctValues = [IdentityVct] },
                    Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(GivenNameClaim) }]
                }
            ]
        };

        PreparedDcqlQuery prepared = DcqlPreparer.Prepare(query);
        TestCredential credential = CreateMatchingIdentityCredential();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => DcqlEvaluator.Evaluate(
                prepared,
                [credential],
                TestCredentialMetadataExtractor,
                TestCredentialClaimExtractor),
            "Section 6.1: the refusal is raised by the call itself, with nothing enumerated.");

        Assert.Contains(
            prepared.ValidationIssues[0],
            exception.Message,
            "The refusal names the query's first recorded validation issue.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">
    /// OpenID for Verifiable Presentations 1.0, Section 8.1</see>: "vp_token: REQUIRED. This is a
    /// JSON-encoded object containing entries where the key is the id value used for a Credential
    /// Query in the DCQL query and the value is an array of one or more Presentations that match
    /// the respective Credential Query." Every carrier of a per-query verdict — the coarse
    /// predicates, the single-query evaluation result, and the match — therefore names the query by
    /// the same identifier the response is keyed by.
    /// </summary>
    [TestMethod]
    public void EvaluationCarriesTheCredentialQueryIdOfTheMatchedQuery()
    {
        CredentialQueryId expectedCredentialQueryId = new(IdentityCredentialId);
        var query = CreateBasicIdentityQuery();
        var prepared = DcqlPreparer.Prepare(query);
        TestCredential credential = CreateMatchingIdentityCredential();

        Assert.IsNotNull(query.Credentials, "The fixture query carries one credential query.");

        CredentialQueryId predicatesCredentialQueryId = prepared.CoarsePredicates[0].CredentialQueryId;
        Assert.AreEqual(
            expectedCredentialQueryId,
            predicatesCredentialQueryId,
            "Section 8.1: the coarse predicates name the credential query by the id the response is keyed by.");

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query.Credentials[0],
            credential,
            TestCredentialMetadataExtractor(credential),
            TestCredentialClaimExtractor);

        CredentialQueryId resultCredentialQueryId = result.CredentialQueryId;
        Assert.AreEqual(
            expectedCredentialQueryId,
            resultCredentialQueryId,
            "Section 8.1: the evaluation result names the credential query by the id the response is keyed by.");

        var matches = DcqlEvaluator.Evaluate(
            prepared,
            [credential],
            TestCredentialMetadataExtractor,
            TestCredentialClaimExtractor).ToList();

        Assert.HasCount(1, matches);

        CredentialQueryId matchCredentialQueryId = matches[0].CredentialQueryId;
        Assert.AreEqual(
            expectedCredentialQueryId,
            matchCredentialQueryId,
            "Section 8.1: the match names the credential query by the id the response is keyed by.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "A string identifying the
    /// Credential in the response and, if provided, the constraints in credential_sets." The
    /// prepared query's storage-filtering predicates are looked up by that identifier: the
    /// credential query's own id finds its predicates, and an identifier no credential query in the
    /// request carries finds none.
    /// </summary>
    [TestMethod]
    public void PreparedQueryFindsThePredicatesOfACredentialQueryIdAndNoOther()
    {
        var prepared = DcqlPreparer.Prepare(CreateBasicIdentityQuery());

        DcqlCoarsePredicates? found = prepared.GetPredicatesFor(new CredentialQueryId(IdentityCredentialId));

        Assert.IsNotNull(
            found,
            "Section 6.1: the credential query's own id identifies it within the request.");
        Assert.AreEqual(
            SdJwtFormat,
            found.MustMatchFormat,
            "The predicates found are the ones extracted from that credential query.");

        Assert.IsNull(
            prepared.GetPredicatesFor(new CredentialQueryId("other_credential")),
            "Section 6.1: an identifier no credential query carries identifies nothing in the request.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "A string identifying the
    /// Credential in the response and, if provided, the constraints in credential_sets." The
    /// disclosure engine is format-agnostic — DCQL is one of the query languages feeding it — so it
    /// correlates a match by a plain requirement key, and DCQL fills that key with the credential
    /// query id's value.
    /// </summary>
    [TestMethod]
    public void DisclosureMatchCarriesTheCredentialQueryIdValueAsItsQueryRequirementId()
    {
        var prepared = DcqlPreparer.Prepare(CreateBasicIdentityQuery());
        TestCredential credential = CreateMatchingIdentityCredential();

        var matches = DcqlEvaluator.Evaluate(
            prepared,
            [credential],
            TestCredentialMetadataExtractor,
            TestCredentialClaimExtractor).ToList();

        Assert.HasCount(1, matches);

        var availablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/" + GivenNameClaim),
            CredentialPath.FromJsonPointer("/" + FamilyNameClaim),
            CredentialPath.FromJsonPointer("/" + EmailClaim)
        };

        DisclosureMatch<TestCredential> disclosureMatch = DcqlPathResolver.ToDisclosureMatch(
            matches[0],
            availablePaths,
            mandatoryPaths: null,
            format: SdJwtFormat);

        string queryRequirementId = disclosureMatch.QueryRequirementId;

        Assert.AreEqual(
            matches[0].CredentialQueryId.Value,
            queryRequirementId,
            "The engine's requirement key carries the credential query id's value.");
        Assert.AreEqual(
            IdentityCredentialId,
            queryRequirementId,
            "Section 6.1: the value identifying the Credential in the response is what the engine correlates on.");
    }


    /// <summary>
    /// A credential carrying every claim <see cref="CreateBasicIdentityQuery"/> asks for, so that a
    /// test about identifiers is never decided by a claim's absence.
    /// </summary>
    /// <returns>A credential of the query's format and type carrying all three requested claims.</returns>
    private static TestCredential CreateMatchingIdentityCredential()
    {
        return new TestCredential
        {
            Format = SdJwtFormat,
            Type = IdentityVct,
            Claims = new Dictionary<string, object>
            {
                [GivenNameClaim] = "Bob",
                [FamilyNameClaim] = "Williams",
                [EmailClaim] = "bob.williams@example.com"
            }
        };
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
            CredentialType = credential.Type
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
        public required Dictionary<string, object> Claims { get; init; }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Veritas.Cbor;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Proves <see cref="SdTokenDcqlAdapter"/> over a credential whose selectively disclosable
/// claims sit at real, nested positions: the same leaf name occurs twice at different depths,
/// an array carries element disclosures beside a decoy, and a disclosable container carries
/// disclosable members. The metadata extractor answers the credential's own type and issuer
/// evidence, and the claim extractor resolves a claims path pointer by
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
/// Verifiable Presentations 1.0, Section 7.1.1</see> over that structure.
/// </summary>
/// <remarks>
/// The credential is minted from the specifications' own example shapes — the recursive
/// <c>nationalities</c> array of
/// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 4.2.6</see>, the
/// <c>address</c> object of Section 6, and the <c>age_equal_or_over</c> object of the payload
/// example — and every expected path is the one those rules assign, computed here rather than
/// read back from the parse.
/// </remarks>
[SuppressMessage(
    "Reliability", "CA2000:Dispose objects before losing scope",
    Justification =
        "The minting helpers construct Salt instances via TestSalts.FromBytes and hand them to " +
        "the SdDisclosure factory methods, which take ownership; every such disclosure is " +
        "disposed by a using declaration in the helper that made it, and every parsed token by " +
        "a using declaration in the test. The analyzer cannot see ownership transfer through a " +
        "factory method.")]
[TestClass]
internal sealed class SdTokenDcqlAdapterPathTests
{
    /// <summary>The test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The pool every wire round trip in this class allocates its salt buffers from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The credential query identifier these tests evaluate under.</summary>
    private const string IdentityQueryId = "identity";


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see>: "vct: REQUIRED. The type of the Verifiable Digital
    /// Credential, e.g., https://credentials.example.com/identity_credential, as defined in
    /// Section 2.2.2.1."; "aka_vcts: OPTIONAL. An array of additional types of
    /// the Verifiable Digital Credential, as defined in Section 2.2.2.2." The extractor takes both
    /// from the credential's own issuer-signed claims; nothing is supplied to it beside the format.
    /// Per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>, the credential's own <c>iss</c>
    /// claim is not itself typed trust evidence — with no <see cref="TrustedAuthorityEvidenceSource{TCredential}"/>
    /// supplied, the metadata carries none.
    /// </summary>
    [TestMethod]
    public void MetadataExtractorReadsTypeAndAdditionalTypesFromTheCredentialsOwnClaims()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        DcqlCredentialMetadata metadata = SdTokenDcqlAdapter
            .CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt)(token);

        Assert.AreEqual(DcqlCredentialFormats.SdJwt, metadata.Format,
            "The metadata reports the format the extractor was built for.");
        Assert.AreEqual(NestedSdJwtVcFixtures.Vct, metadata.CredentialType,
            "SD-JWT VC Section 2.2.2.3: the credential type is the credential's own vct claim.");
        Assert.Contains(NestedSdJwtVcFixtures.DeterministicIdentityAdditionalVct, metadata.AdditionalTypes,
            "SD-JWT VC Section 2.2.2.3: aka_vcts is the additional-type evidence the credential declares.");
        Assert.HasCount(1, metadata.AdditionalTypes,
            "The credential declares exactly the one additional type its aka_vcts array carries.");
        Assert.IsNull(metadata.TrustedAuthorityEvidence,
            "No TrustedAuthorityEvidenceSource was supplied, so the metadata carries no trust evidence.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: the trust evidence a
    /// <c>trusted_authorities</c> constraint is matched against comes from the caller-supplied
    /// <see cref="TrustedAuthorityEvidenceSource{TCredential}"/> — never synthesised from the
    /// credential's own <c>iss</c> claim.
    /// </summary>
    [TestMethod]
    public void MetadataExtractorSuppliesTrustedAuthorityEvidenceFromTheSource()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();
        var expectedEvidence = new TrustedAuthorityEvidence
        {
            FederationTrustPathEntities = new HashSet<EntityIdentifier> { new(NestedSdJwtVcFixtures.Issuer) }
        };

        DcqlCredentialMetadata metadata = SdTokenDcqlAdapter
            .CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt, _ => expectedEvidence)(token);

        Assert.AreSame(expectedEvidence, metadata.TrustedAuthorityEvidence,
            "The metadata extractor supplies exactly what the TrustedAuthorityEvidenceSource returns.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 9.3</see>: "The Issuer
    /// MUST ensure that a new salt value is chosen for each claim, including when the same claim
    /// name occurs at different places in the structure of the SD-JWT." Both occurrences of
    /// <c>family_name</c> are therefore separate disclosures at separate positions, and the
    /// available-path set — what a claims path pointer per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.3</see> is resolved against — lists both full paths
    /// beside the always-disclosed claims, never one collapsed leaf name.
    /// </summary>
    [TestMethod]
    public void AvailablePathsCarryBothNamesakeFamilyNamePathsBesideTheAlwaysDisclosedClaims()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        DcqlCredentialMetadata metadata = SdTokenDcqlAdapter
            .CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt)(token);

        Assert.IsNotNull(metadata.AvailablePaths, "A parsed credential exposes the paths it can address.");
        Assert.Contains(CredentialPath.FromJsonPointer("/family_name"), metadata.AvailablePaths!,
            "The top-level family_name occupies the root object's own position.");
        Assert.Contains(CredentialPath.FromJsonPointer("/employer/family_name"), metadata.AvailablePaths!,
            "The namesake under employer occupies its parent's path plus the name, not the root's.");
        Assert.Contains(CredentialPath.FromJsonPointer("/employer"), metadata.AvailablePaths!,
            "The disclosable container is itself addressable.");
        Assert.Contains(CredentialPath.FromJsonPointer("/nationalities/1"), metadata.AvailablePaths!,
            "An array-element disclosure is addressed by its index in the issuer-signed array.");
        Assert.Contains(CredentialPath.FromJsonPointer("/vct"), metadata.AvailablePaths!,
            "The always-disclosed vct claim is addressable beside the disclosures.");
        Assert.Contains(CredentialPath.FromJsonPointer("/iss"), metadata.AvailablePaths!,
            "The always-disclosed iss claim is addressable beside the disclosures.");
        Assert.HasCount(23, metadata.AvailablePaths!,
            "The set is exactly the fourteen disclosure paths and the nine unconditionally disclosed nodes; nothing is synthesised.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see>: "vct: REQUIRED. The type of the Verifiable Digital
    /// Credential". A plain SD-JWT carries no such claim and is not an SD-JWT VC, so the extractor
    /// reports no credential type rather than inventing one — the evidence a type constraint is
    /// answered against is absent, and the evaluator decides what that means.
    /// </summary>
    [TestMethod]
    public void MetadataExtractorLeavesTheCredentialTypeNullForAnSdJwtCarryingNoVct()
    {
        using SdToken<string> token = ParsePlainSdJwt();

        DcqlCredentialMetadata metadata = SdTokenDcqlAdapter
            .CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt)(token);

        Assert.IsNull(metadata.CredentialType,
            "A credential with no vct claim declares no type; the extractor reports the absence.");
        Assert.IsEmpty(metadata.AdditionalTypes,
            "A credential with no aka_vcts claim declares no additional types.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If the component is a string, select
    /// the element in the respective key in the currently selected element(s)." Applied left to
    /// right, <c>["employer", "family_name"]</c> reaches the namesake under <c>employer</c> and
    /// returns that disclosure's value — not the top-level claim of the same name.
    /// </summary>
    [TestMethod]
    public void NestedFamilyNamePatternResolvesToTheNestedDisclosureOnly()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("employer", "family_name"), out object? value);

        Assert.IsTrue(isFound, "The credential carries a family_name under employer.");
        Assert.AreEqual(NestedSdJwtVcFixtures.EmployerFamilyName, value,
            "Section 7.1.1: the value is the one at the addressed position, not the root's namesake.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1</see>: "To address a particular claim within an
    /// object, append the key (claim name) to the array." A single-component pointer therefore
    /// addresses the root object's own <c>family_name</c>, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 9.3</see> makes a
    /// separate disclosure from the namesake nested under <c>employer</c>.
    /// </summary>
    [TestMethod]
    public void TopLevelFamilyNamePatternResolvesToTheTopLevelDisclosureOnly()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("family_name"), out object? value);

        Assert.IsTrue(isFound, "The credential carries a family_name at the root.");
        Assert.AreEqual(NestedSdJwtVcFixtures.TopLevelFamilyName, value,
            "Section 7.1: a one-component pointer addresses the root object's key, not a nested namesake.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 4.2.6</see>:
    /// "The algorithms above are compatible with 'recursive Disclosures', in which one selectively
    /// disclosed field reveals the existence of more selectively disclosable fields." A member of
    /// the disclosable <c>address</c> object is therefore addressed through its parent's path, and
    /// the claim extractor resolves it there.
    /// </summary>
    [TestMethod]
    public void RecursiveAddressMemberResolvesThroughItsParentsPath()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("address", "locality"), out object? value);

        Assert.IsTrue(isFound, "The disclosable address object carries a disclosable locality member.");
        Assert.AreEqual("Schulpforta", value,
            "RFC 9901 Section 4.2.6: a recursively disclosed member's position runs through its parent.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If the component is null, select all
    /// elements of the currently selected array(s)." The three element disclosures of
    /// <c>nationalities</c> are all selected; the decoy marker beside them resolves to no
    /// disclosure and contributes no element.
    /// </summary>
    [TestMethod]
    public void NullComponentSelectsEveryElementOfTheSelectedArray()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        var pattern = new DcqlClaimPattern(PatternSegment.Key("nationalities"), PatternSegment.Wildcard());

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(token, pattern, out object? value);

        Assert.IsTrue(isFound, "The credential carries selectively disclosable nationalities elements.");
        Assert.IsInstanceOfType<IEnumerable<object?>>(value,
            "Selecting all elements of an array yields every selected element's value.");

        var selected = ((IEnumerable<object?>)value!).ToHashSet();

        Assert.HasCount(3, selected,
            "Section 7.1.1: all three element disclosures are selected; the decoy marker is not an element.");
        Assert.Contains("DE", selected, "The element at index 0 is selected.");
        Assert.Contains("FR", selected, "The element at index 1 is selected.");
        Assert.Contains("UK", selected, "The element at index 2 is selected.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If the component is a non-negative
    /// integer, select the element at the respective index in the currently selected array(s)."
    /// The index is the element's position in the issuer-signed array, in which every marker —
    /// resolved or decoy — occupies one position.
    /// </summary>
    [TestMethod]
    public void NonNegativeIntegerComponentSelectsTheElementAtThatIndex()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        var pattern = new DcqlClaimPattern(PatternSegment.Key("nationalities"), PatternSegment.Index(1));

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(token, pattern, out object? value);

        Assert.IsTrue(isFound, "The array carries an element disclosure at index 1.");
        Assert.AreEqual("FR", value,
            "Section 7.1.1: the second element of the issuer-signed nationalities array is selected.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If any of the currently selected
    /// element(s) is not an object, abort processing and return an error." After the wildcard the
    /// selection holds the three nationality strings, so a following string component addresses
    /// nothing and the pointer does not match.
    /// </summary>
    [TestMethod]
    public void StringComponentAgainstANonObjectDoesNotMatch()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        var pattern = new DcqlClaimPattern(
            PatternSegment.Key("nationalities"), PatternSegment.Wildcard(), PatternSegment.Key("locality"));

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(token, pattern, out object? value);

        Assert.IsFalse(isFound,
            "Section 7.1.1: a string component applied to elements that are not objects aborts processing.");
        Assert.IsNull(value, "An aborted pointer yields no claim value.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If the component is null, select all
    /// elements of the currently selected array(s). If any of the currently selected element(s) is
    /// not an array, abort processing and return an error." <c>employer</c> is an object, so the
    /// wildcard aborts.
    /// </summary>
    [TestMethod]
    public void NullComponentAgainstANonArrayDoesNotMatch()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        var pattern = new DcqlClaimPattern(PatternSegment.Key("employer"), PatternSegment.Wildcard());

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(token, pattern, out object? value);

        Assert.IsFalse(isFound,
            "Section 7.1.1: a null component applied to a non-array aborts processing.");
        Assert.IsNull(value, "An aborted pointer yields no claim value.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If the key does not exist in any element
    /// currently selected, remove that element from the selection." and "If the set of elements
    /// currently selected is empty, abort processing and return an error." A first component the
    /// credential does not carry empties the selection, so the pointer does not match.
    /// </summary>
    [TestMethod]
    public void AKeyAbsentFromEverySelectedElementLeavesAnEmptySelectionAndNoMatch()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        var pattern = new DcqlClaimPattern(PatternSegment.Key("place_of_birth"), PatternSegment.Wildcard());

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(token, pattern, out object? value);

        Assert.IsFalse(isFound,
            "Section 7.1.1: the root is removed from the selection and the empty selection is an error.");
        Assert.IsNull(value, "An aborted pointer yields no claim value.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7</see>: "A claims path pointer MUST be a
    /// non-empty array of strings, nulls and non-negative integers." and Section 7.1.1: "If the
    /// component is anything else, abort processing and return an error." Both halves of that MUST
    /// are refused where a pointer is built — a component outside the three kinds, and an empty
    /// pointer — so neither ever reaches the claim extractor.
    /// </summary>
    [TestMethod]
    public void AClaimsPathComponentOutsideStringsNullsAndNonNegativeIntegersIsRefused()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => PatternSegment.Index(-1),
            "Section 7: an integer component that is not non-negative is not a claims path component.");

        Assert.ThrowsExactly<ArgumentException>(
            () => DcqlClaimPattern.FromKeys(),
            "Section 7: a claims path pointer MUST be a non-empty array, so a pointer with no components is not one.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.3</see>: "values: OPTIONAL A non-empty array of
    /// strings, integers or boolean values that specifies the expected values of the claim. If the
    /// values property is present, the Wallet SHOULD return the claim only if the type and value of
    /// the claim both match exactly for at least one of the elements in the array." The three rows
    /// are the three value types the property admits; the first two are nested claims, and the
    /// rejecting value for <c>employer.family_name</c> is the top-level namesake's value, which the
    /// constraint must not accept at the nested position.
    /// </summary>
    /// <param name="parentKey">The pointer's first component, or the empty string for a one-component pointer.</param>
    /// <param name="claimName">The pointer's last component.</param>
    /// <param name="matchingValue">The claim's own value, which the constraint accepts.</param>
    /// <param name="rejectingValue">A value of the same type the claim does not carry.</param>
    [TestMethod]
    [DataRow("employer", "family_name", NestedSdJwtVcFixtures.EmployerFamilyName, NestedSdJwtVcFixtures.TopLevelFamilyName)]
    [DataRow("age_equal_or_over", "18", true, false)]
    [DataRow("", "age_in_years", 62, 63)]
    public void ValuesMatchOnlyWhenTypeAndValueMatchExactly(
        string parentKey, string claimName, object matchingValue, object rejectingValue)
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        DcqlClaimPattern pattern = parentKey.Length == 0
            ? DcqlClaimPattern.FromKeys(claimName)
            : DcqlClaimPattern.FromKeys(parentKey, claimName);

        DcqlCredentialMetadata metadata = SdTokenDcqlAdapter
            .CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt)(token);

        DcqlEvaluationResult accepted = DcqlEvaluator.EvaluateSingle(
            BuildIdentityQuery(new ClaimsQuery { Path = pattern, Values = [matchingValue] }),
            token,
            metadata,
            SdTokenDcqlAdapter.ClaimExtractor<string>);

        DcqlEvaluationResult rejected = DcqlEvaluator.EvaluateSingle(
            BuildIdentityQuery(new ClaimsQuery { Path = pattern, Values = [rejectingValue] }),
            token,
            metadata,
            SdTokenDcqlAdapter.ClaimExtractor<string>);

        Assert.IsTrue(accepted.Matches,
            "Section 6.3: the claim's own type and value match an element of the values array exactly.");
        Assert.IsFalse(rejected.Matches,
            "Section 6.3: a value the claim does not carry at this path does not match.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.1</see>: "If both claims and claim_sets are
    /// present, the Verifier requests one combination of the claims listed in claim_sets. The order
    /// of the options conveyed in the claim_sets array expresses the Verifier's preference for what
    /// is returned; the Wallet SHOULD return the first option that it can satisfy." The first option
    /// names a nested claim the credential does not carry, so the credential is matched on the next
    /// option, whose nested path it does carry.
    /// </summary>
    [TestMethod]
    public void ClaimSetsMatchOnTheOptionOverNestedPathsTheCredentialCanSatisfy()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        CredentialQuery query = BuildIdentityQuery(
            new ClaimsQuery { Id = "birth_place", Path = DcqlClaimPattern.FromKeys("place_of_birth", "locality") },
            new ClaimsQuery { Id = "employer_name", Path = DcqlClaimPattern.FromKeys("employer", "family_name") });
        query.ClaimSets = [new ClaimSetQuery { Options = [["birth_place"], ["employer_name"]] }];

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query,
            token,
            SdTokenDcqlAdapter.CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt)(token),
            SdTokenDcqlAdapter.ClaimExtractor<string>);

        Assert.IsTrue(result.Matches,
            "Section 6.4.1: the credential satisfies an option, so it is a match for the query.");
        Assert.IsNotNull(result.MatchedPatterns, "A match reports the patterns it matched.");
        Assert.Contains(DcqlClaimPattern.FromKeys("employer", "family_name"), result.MatchedPatterns!,
            "The satisfiable option's nested path is the one the credential answers.");
        Assert.DoesNotContain(DcqlClaimPattern.FromKeys("place_of_birth", "locality"), result.MatchedPatterns!,
            "The unsatisfiable option's path addresses nothing in this credential.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.1</see>: "If the Wallet cannot satisfy any of the
    /// options, it MUST NOT return any claims." Every option names a nested path the credential
    /// does not carry, so the credential does not match the query at all.
    /// </summary>
    [TestMethod]
    public void ClaimSetsWithNoSatisfiableOptionDoNotMatch()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        CredentialQuery query = BuildIdentityQuery(
            new ClaimsQuery { Id = "birth_place", Path = DcqlClaimPattern.FromKeys("place_of_birth", "locality") },
            new ClaimsQuery { Id = "birth_country", Path = DcqlClaimPattern.FromKeys("place_of_birth", "country") });
        query.ClaimSets = [new ClaimSetQuery { Options = [["birth_place"], ["birth_country"]] }];

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query,
            token,
            SdTokenDcqlAdapter.CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt)(token),
            SdTokenDcqlAdapter.ClaimExtractor<string>);

        Assert.IsFalse(result.Matches,
            "Section 6.4.1: no option is satisfiable, so no claims are returned for this credential.");
        Assert.AreEqual(DcqlFailureReasons.RequiredClaimSetNotSatisfied, result.FailureReason,
            "The refusal names the unsatisfied claim set as its reason.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">
    /// SD-JWT VC, Section 2.2.2.3</see>'s <c>vct</c> is carried under the CWT claim key the parse
    /// assigns its position from. The extractor built for <c>dc+sd-cwt</c> reads it there.
    /// </summary>
    [TestMethod]
    public void SdCwtMetadataExtractorReadsTypeFromTheCwtClaimKeys()
    {
        using SdToken<ReadOnlyMemory<byte>> token = ParseNestedSdCwtCredential();

        DcqlCredentialMetadata metadata = SdTokenDcqlAdapter
            .CreateMetadataExtractor<ReadOnlyMemory<byte>>(DcqlCredentialFormats.SdCwt)(token);

        Assert.AreEqual(NestedSdJwtVcFixtures.Vct, metadata.CredentialType,
            "SD-JWT VC Section 2.2.2.3: the credential type is the vct claim, keyed by its CWT claim key.");
        Assert.Contains(CredentialPath.FromJsonPointer("/employer/family_name"), metadata.AvailablePaths!,
            "The nested disclosure is addressable at its own position.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If the component is a string, select the
    /// element in the respective key in the currently selected element(s)." The rule is the pointer's,
    /// not the format's, so an SD-CWT's nested disclosure resolves the same way an SD-JWT VC's does.
    /// </summary>
    [TestMethod]
    public void SdCwtNestedFamilyNamePatternResolvesToTheNestedDisclosureOnly()
    {
        using SdToken<ReadOnlyMemory<byte>> token = ParseNestedSdCwtCredential();

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(
            token, DcqlClaimPattern.FromKeys("employer", "family_name"), out object? value);

        Assert.IsTrue(isFound, "The SD-CWT carries a family_name under employer.");
        Assert.AreEqual(NestedSdJwtVcFixtures.EmployerFamilyName, value,
            "Section 7.1.1: the value is the one at the addressed position.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If the component is null, select all
    /// elements of the currently selected array(s)." The SD-CWT's redacted array elements are
    /// selected by their positions in the issuer-signed array, the decoy among them contributing none.
    /// </summary>
    [TestMethod]
    public void SdCwtNullComponentSelectsEveryElementOfTheSelectedArray()
    {
        using SdToken<ReadOnlyMemory<byte>> token = ParseNestedSdCwtCredential();

        var pattern = new DcqlClaimPattern(PatternSegment.Key("nationalities"), PatternSegment.Wildcard());

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(token, pattern, out object? value);

        Assert.IsTrue(isFound, "The SD-CWT carries selectively disclosable nationalities elements.");

        var selected = ((IEnumerable<object?>)value!).ToHashSet();

        Assert.HasCount(3, selected,
            "Section 7.1.1: all three element disclosures are selected; the decoy marker is not an element.");
        Assert.Contains("DE", selected, "The element at index 0 is selected.");
        Assert.Contains("FR", selected, "The element at index 1 is selected.");
        Assert.Contains("UK", selected, "The element at index 2 is selected.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send selectively
    /// disclosable claims that have not been selected according to the rules below." A query over
    /// the nested path yields a decision naming that path, and the selection driven by it releases
    /// that disclosure together with the disclosable parent
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 7.2</see> step 2.b
    /// requires — "The hash of the Disclosure is contained in the claim value of another selected
    /// Disclosure" — and nothing else.
    /// </summary>
    [TestMethod]
    public async Task DcqlDecisionOverTheNestedPathReleasesTheNestedDisclosureAndItsParentOnly()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        CredentialQuery query = BuildIdentityQuery(
            new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("employer", "family_name") });

        DcqlDisclosureResult<SdToken<string>> result = await DcqlDisclosure.ComputeStrategyAsync(query, token, SdTokenDcqlAdapter.CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt), SdTokenDcqlAdapter.ClaimExtractor<string>, new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.ConstraintsSatisfied,
            "The credential's own vct answers the query's type constraint.");
        Assert.HasCount(1, result.Graph.Decisions, "One credential query yields one disclosure decision.");

        CredentialDisclosureDecision<SdToken<string>> decision = result.Graph.Decisions[0];
        var employerPath = CredentialPath.FromJsonPointer("/employer");
        var nestedFamilyNamePath = CredentialPath.FromJsonPointer("/employer/family_name");

        Assert.Contains(nestedFamilyNamePath, decision.SelectedPaths,
            "The decision names the requested nested path.");
        Assert.DoesNotContain(CredentialPath.FromJsonPointer("/family_name"), decision.SelectedPaths,
            "Section 6.4: the top-level namesake was not selected, so it is not to be sent.");

        SdDisclosureSelectionResult<string> selection = token.SelectDisclosures(decision.SelectedPaths, Pool);

        using SdToken<string> presented = selection.Token;

        Assert.IsEmpty(selection.UnmatchedPaths, "Every path the decision named addresses this credential.");
        Assert.HasCount(2, presented.Disclosures,
            "RFC 9901 Section 7.2 step 2: the nested disclosure and the parent whose value carries its hash.");
        Assert.IsTrue(
            presented.DisclosurePaths.Paths.SetEquals([employerPath, nestedFamilyNamePath]),
            "Section 6.4: exactly the selected disclosure and the ancestor it depends on are released.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If the component is a string, select the
    /// element in the respective key in the currently selected element(s). If any of the currently
    /// selected element(s) is not an object, abort processing and return an error." The abort is a
    /// separate outcome from the removal the same clause defines, and only a heterogeneous
    /// selection tells them apart: the <c>evidence</c> array holds one object and one string, so
    /// removal would quietly answer with the object's member while the abort refuses the pointer.
    /// </summary>
    [TestMethod]
    public void AStringComponentOverASelectionMixingObjectsAndNonObjectsAborts()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        var pattern = new DcqlClaimPattern(
            PatternSegment.Key("evidence"), PatternSegment.Wildcard(), PatternSegment.Key("type"));

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(token, pattern, out object? value);

        Assert.IsFalse(isFound,
            "Section 7.1.1: one selected element that is not an object aborts the whole pointer, rather than being removed while the objects answer.");
        Assert.IsNull(value, "An aborted pointer yields no claim value.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 7.1.1</see>: "If the component is a non-negative
    /// integer, select the element at the respective index in the currently selected array(s). ...
    /// If the index does not exist in a selected array, remove that array from the selection." and
    /// "If the set of elements currently selected is empty, abort processing and return an error."
    /// An index past the end of the array and the index of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901, Section 4.2.5</see>'s decoy —
    /// which occupies a position but resolves to no Disclosure — both empty the selection.
    /// </summary>
    /// <param name="index">The index the pointer names.</param>
    /// <param name="because">Why that index addresses no element.</param>
    [TestMethod]
    [DataRow(9, "an index past the last position of the issuer-signed array")]
    [DataRow(3, "the position a decoy marker occupies, which resolves to no Disclosure")]
    public void AnIndexAbsentFromTheSelectedArrayLeavesAnEmptySelectionAndNoMatch(int index, string because)
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        var pattern = new DcqlClaimPattern(
            PatternSegment.Key("nationalities"), PatternSegment.Index(index), PatternSegment.Wildcard());

        bool isFound = SdTokenDcqlAdapter.ClaimExtractor(token, pattern, out object? value);

        Assert.IsFalse(isFound,
            $"Section 7.1.1: {because}, so the array is removed from the selection and the empty selection is an error.");
        Assert.IsNull(value, "An aborted pointer yields no claim value.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4</see>: "Wallets MUST NOT send selectively
    /// disclosable claims that have not been selected according to the rules below." A query whose
    /// pointer names one array element by index is answered the same way as any other pointer: the
    /// decision selects that element together with whichever ancestors are themselves Disclosures,
    /// and nothing else. Here the <c>nationalities</c> array is part of the issuer-signed structure
    /// rather than a Disclosure of its own, so the element alone is released — never the sibling
    /// elements, which an index pattern must not drag along.
    /// </summary>
    [TestMethod]
    public async Task ADecisionOverAnIndexedArrayElementReleasesThatElementAlone()
    {
        using SdToken<string> token = ParseNestedIdentityCredential();

        CredentialQuery query = BuildIdentityQuery(new ClaimsQuery
        {
            Path = new DcqlClaimPattern(PatternSegment.Key("nationalities"), PatternSegment.Index(1))
        });

        DcqlDisclosureResult<SdToken<string>> result = await DcqlDisclosure.ComputeStrategyAsync(query, token, SdTokenDcqlAdapter.CreateMetadataExtractor<string>(DcqlCredentialFormats.SdJwt), SdTokenDcqlAdapter.ClaimExtractor<string>, new FakeTimeProvider(TestClock.CanonicalEpoch), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.ConstraintsSatisfied, "The credential's own vct answers the query's type constraint.");
        Assert.HasCount(1, result.Graph.Decisions, "One credential query yields one disclosure decision.");

        SdDisclosureSelectionResult<string> selection = token.SelectDisclosures(
            result.Graph.Decisions[0].SelectedPaths, Pool);

        using SdToken<string> presented = selection.Token;

        Assert.IsTrue(
            presented.DisclosurePaths.Paths.SetEquals([CredentialPath.FromJsonPointer("/nationalities/1")]),
            $"Section 6.4: exactly the named element is released, and no sibling element of the array; released [{string.Join(", ", presented.DisclosurePaths.Paths)}].");
    }


    /// <summary>
    /// Builds the credential query these tests evaluate under: the SD-JWT VC format, a
    /// <c>vct_values</c> constraint naming the credential's own type, and the supplied claims.
    /// </summary>
    /// <param name="claims">The claims queries the credential query carries.</param>
    private static CredentialQuery BuildIdentityQuery(params ClaimsQuery[] claims) => new()
    {
        Id = IdentityQueryId,
        Format = DcqlCredentialFormats.SdJwt,
        Meta = new CredentialQueryMeta { VctValues = [NestedSdJwtVcFixtures.Vct] },
        Claims = claims
    };


    /// <summary>
    /// Parses the minted SD-JWT VC back from its wire form, which is what gives the token the
    /// disclosure positions and always-disclosed claims the adapter reads.
    /// </summary>
    private static SdToken<string> ParseNestedIdentityCredential() =>
        SdJwtSerializer.ParseToken(
            NestedSdJwtVcFixtures.MintDeterministicIdentityCredential(),
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestSalts.TestSaltTag);


    /// <summary>
    /// Parses a plain SD-JWT — one carrying neither <c>vct</c> nor <c>aka_vcts</c> — back from its
    /// wire form, the credential whose type evidence is genuinely absent.
    /// </summary>
    private static SdToken<string> ParsePlainSdJwt()
    {
        (string Encoded, string Digest) givenName = NestedSdJwtVcFixtures.EncodeProperty("salt-given-name", "given_name", "\"Erika\"");

        string payloadJson = /*lang=json,strict*/ $$"""
        {
            "_sd_alg": "sha-256",
            "iss": "{{NestedSdJwtVcFixtures.Issuer}}",
            "_sd": ["{{givenName.Digest}}"]
        }
        """;

        string wireFormat = $"{NestedSdJwtVcFixtures.CreateMinimalJwt(payloadJson)}~{givenName.Encoded}~";

        return SdJwtSerializer.ParseToken(
            wireFormat, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder, Pool, TestSalts.TestSaltTag);
    }


    /// <summary>
    /// Parses the minted SD-CWT back from its COSE_Sign1 wire form, the twin of
    /// <see cref="ParseNestedIdentityCredential"/> for the CBOR-encoded format.
    /// </summary>
    private static SdToken<ReadOnlyMemory<byte>> ParseNestedSdCwtCredential() =>
        SdCwtSerializer.ParseToken(
            NestedSdJwtVcFixtures.MintDeterministicSdCwtCredential(), TestSalts.TestSaltTag, Pool, TestSetup.Base64UrlEncoder);
}

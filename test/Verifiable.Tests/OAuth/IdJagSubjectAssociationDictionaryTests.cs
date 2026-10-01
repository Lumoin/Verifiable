using Verifiable.Core.Relations;
using Verifiable.Core.SecurityEvents;
using Verifiable.Json;
using Verifiable.OAuth.IdJag;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="IdJagSubjectAssociationDictionary"/>, the table of the Subject Identifiers a Resource
/// Authorization Server knows each validated grant subject by, whose
/// <see cref="IdJagSubjectAssociationDictionary.CompareAsync"/> is the <c>sub_id</c> rule's
/// <see cref="IdJagSubjectIdentifierRule.Association"/>.
/// </summary>
[TestClass]
internal sealed class IdJagSubjectAssociationDictionaryTests
{
    /// <summary>The MSTest context whose token every comparison rides.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The validated issuer of the grant the comparisons judge.</summary>
    private static string GrantIssuer { get; } = "https://idp.example";

    /// <summary>The validated subject of the grant the comparisons judge.</summary>
    private static string GrantSubject { get; } = "alice-at-idp";

    /// <summary>The email address the application knows the grant's End-User by.</summary>
    private static string EndUserEmail { get; } = "alice@example.com";

    /// <summary>The SAML issuer of the NameID the application knows the grant's End-User by.</summary>
    private static string SamlIssuer { get; } = "https://idp.example/saml";

    /// <summary>The SPNameQualifier the NameID the application knows the grant's End-User by is scoped to.</summary>
    private static string SamlSpNameQualifier { get; } = "https://resource-as.example/saml/sp";

    /// <summary>The validated subject of a single-tenant grant: its issuer and subject, no tenant.</summary>
    private static IdJagSubjectContext Reference { get; } = new()
    {
        Issuer = GrantIssuer,
        Subject = GrantSubject
    };


    /// <summary>
    /// An identifier the application lists under the grant's validated subject holds for a candidate that
    /// carries the same format and the same members, whether the candidate arrives from the wire or is built
    /// by a factory.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "When both sub and sub_id are present, they MUST identify the same End-User."
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>
    /// refuses a grant when "the sub_id claim is not authorized by local policy for the validated ID-JAG
    /// issuer."; a listed identifier is one the local policy authorizes.
    /// </summary>
    /// <param name="caseName">The format: <c>email</c>, <c>saml-nameid</c> or <c>iss_sub</c>.</param>
    [TestMethod]
    [DataRow("email", DisplayName = "an email identifier")]
    [DataRow("saml-nameid", DisplayName = "a SAML NameID identifier")]
    [DataRow("iss_sub", DisplayName = "an iss_sub identifier")]
    public async Task AnAssociatedIdentifierHolds(string caseName)
    {
        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [ListedIdentifier(caseName)];

        ComparisonOutcome outcome = await associations.CompareAsync(
            PresentedIdentifier(caseName), Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Holds, outcome);
    }


    /// <summary>
    /// A candidate that differs from every listed identifier in the value of one member is not authorized for
    /// the grant's validated subject: the comparison fails. Every member is compared.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "The Resource Authorization Server MUST compare every member of the SAML NameID Subject Identifier that is
    /// part of the set of identifier fields it uses for subject resolution for that SAML issuer." and "In
    /// particular, when the SAML Assertion Subject &lt;NameID&gt; is scoped to a Service Provider, the
    /// sp_name_qualifier value is part of the subject namespace."
    /// </summary>
    /// <param name="caseName">
    /// The differing member: <c>spNameQualifier</c> (another <c>sp_name_qualifier</c>) or <c>issSubSubject</c>
    /// (another <c>sub</c>).
    /// </param>
    [TestMethod]
    [DataRow("spNameQualifier", DisplayName = "another sp_name_qualifier")]
    [DataRow("issSubSubject", DisplayName = "another sub of the same issuer")]
    public async Task AnIdentifierNotListedFails(string caseName)
    {
        (string listedFormat, SubjectIdentifier presented) = caseName switch
        {
            "spNameQualifier" => ("saml-nameid", WireIdentifier(new()
            {
                ["format"] = "saml-nameid",
                ["issuer"] = SamlIssuer,
                ["nameid"] = EndUserEmail,
                ["sp_name_qualifier"] = "https://other-sp.example/saml/sp"
            })),
            "issSubSubject" => ("iss_sub", WireIdentifier(new() { ["format"] = "iss_sub", ["iss"] = GrantIssuer, ["sub"] = "another-end-user" })),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [ListedIdentifier(listedFormat)];

        ComparisonOutcome outcome = await associations.CompareAsync(
            presented, Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Fails, outcome);
    }


    /// <summary>
    /// An <c>email</c> candidate whose address differs from the listed one in letter case only fails: the
    /// dictionary compares an <c>email</c> value ordinally, without canonicalization, which is this library's
    /// rule. An application that canonicalizes an email address before comparing supplies its own
    /// <see cref="CompareDelegate{TCandidate, TReference}"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.2.1">RFC 9493 Section 3.2.2.1</see>:
    /// "While the domain portion of an email address [RFC5322] is consistently treated as case-insensitive per
    /// [RFC1034], most providers treat the local part of the email address as case-insensitive as well and
    /// consider "user@example.com", "User@example.com", and "USER@example.com" as the same email address."
    /// "Email canonicalization is not standardized, and there is no way for the event recipient to determine
    /// the mail provider's canonicalization method." "Therefore, the recipient SHOULD apply its own
    /// canonicalization algorithm to incoming events in order to reproduce the translation done by the local
    /// email system."
    /// </summary>
    /// <param name="presentedEmail">The address the candidate carries, in another letter case than the listed one.</param>
    [TestMethod]
    [DataRow("Alice@example.com", DisplayName = "the local part in another letter case")]
    [DataRow("alice@EXAMPLE.com", DisplayName = "the domain in another letter case")]
    public async Task AnEmailInAnotherLetterCaseFails(string presentedEmail)
    {
        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [ListedIdentifier("email")];

        ComparisonOutcome outcome = await associations.CompareAsync(
            WireIdentifier(new() { ["format"] = "email", ["email"] = presentedEmail }), Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Fails, outcome);
    }


    /// <summary>
    /// A candidate that holds a listed identifier's members under another format is another identifier: the
    /// comparison fails, whether the other format is one the catalog knows with the same member (the
    /// <c>uri</c> and <c>account</c> formats each carry one <c>uri</c> member) or one the catalog does not know.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST conform to a specific Identifier Format and MUST contain a "format" member whose value is
    /// the name of that Identifier Format."
    /// </summary>
    /// <param name="caseName">
    /// The pair: <c>uriForAccount</c> (an <c>account</c> listed, a <c>uri</c> presented) or
    /// <c>unknownForUri</c> (a <c>uri</c> listed, a format the catalog does not know presented).
    /// </param>
    [TestMethod]
    [DataRow("uriForAccount", DisplayName = "a uri candidate against a listed account identifier")]
    [DataRow("unknownForUri", DisplayName = "a candidate of an unknown format against a listed uri identifier")]
    public async Task ACandidateOfAnotherFormatFails(string caseName)
    {
        (SubjectIdentifier listed, string presentedFormat) = caseName switch
        {
            "uriForAccount" => (SubjectIdentifier.Account("acct:alice@example.com"), "uri"),
            "unknownForUri" => (SubjectIdentifier.Uri("acct:alice@example.com"), "urn:example:principal"),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [listed];

        ComparisonOutcome outcome = await associations.CompareAsync(
            WireIdentifier(new() { ["format"] = presentedFormat, ["uri"] = "acct:alice@example.com" }), Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Fails, outcome);
    }


    /// <summary>
    /// A candidate with one member more, or one member fewer, than the listed identifier is another identifier:
    /// a SAML NameID with an <c>sp_name_qualifier</c> fails against one listed without it, and one without it
    /// fails against one listed with it.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "The Resource Authorization Server MUST compare every member of the SAML NameID Subject Identifier that is
    /// part of the set of identifier fields it uses for subject resolution for that SAML issuer." and "In
    /// particular, when the SAML Assertion Subject &lt;NameID&gt; is scoped to a Service Provider, the
    /// sp_name_qualifier value is part of the subject namespace."
    /// </summary>
    /// <param name="caseName">
    /// The candidate against the listed identifier: <c>oneMore</c> (with <c>sp_name_qualifier</c> against one
    /// listed without it) or <c>oneFewer</c> (without it against one listed with it).
    /// </param>
    [TestMethod]
    [DataRow("oneMore", DisplayName = "the candidate holds one member more than the listed identifier")]
    [DataRow("oneFewer", DisplayName = "the candidate holds one member fewer than the listed identifier")]
    public async Task ACandidateWithAnotherNumberOfMembersFails(string caseName)
    {
        (SubjectIdentifier listed, SubjectIdentifier presented) = caseName switch
        {
            "oneMore" => (SubjectIdentifier.SamlNameId(SamlIssuer, EndUserEmail), PresentedIdentifier("saml-nameid")),
            "oneFewer" => (ListedIdentifier("saml-nameid"), WireIdentifier(new() { ["format"] = "saml-nameid", ["issuer"] = SamlIssuer, ["nameid"] = EndUserEmail })),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [listed];

        ComparisonOutcome outcome = await associations.CompareAsync(
            presented, Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Fails, outcome);
    }


    /// <summary>
    /// A validated grant subject the dictionary holds no entry for is one the application has said nothing
    /// about, so the comparison is undecided; an entry for another tenant of the same issuer and subject is an
    /// entry for another End-User. That an absent association decides nothing is this library's rule.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "A public subject identifier MUST be unique when scoped with issuer (iss+sub) for a single-tenant issuer
    /// and MUST be unique when scoped with issuer and tenant (iss+tenant+sub) for multi-tenant issuer."
    /// </summary>
    /// <param name="caseName">The dictionary: <c>empty</c> or <c>anotherTenant</c>.</param>
    [TestMethod]
    [DataRow("empty", DisplayName = "no entry at all")]
    [DataRow("anotherTenant", DisplayName = "an entry for another tenant of the same issuer and subject")]
    public async Task ASubjectWithoutAnEntryIsUndetermined(string caseName)
    {
        IdJagSubjectContext reference = Reference with { Tenant = "tenant-a" };
        IdJagSubjectAssociationDictionary associations = new();
        if(caseName == "anotherTenant")
        {
            associations[reference with { Tenant = "tenant-b" }] = [ListedIdentifier("email")];
        }

        ComparisonOutcome outcome = await associations.CompareAsync(
            PresentedIdentifier("email"), reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Indeterminate, outcome);
    }


    /// <summary>
    /// The <c>sub_id</c> profile compares a claim with the validated subject under equality only, so any other
    /// relation is undecided even for a listed identifier.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "When both sub and sub_id are present, they MUST identify the same End-User."
    /// </summary>
    /// <param name="relation">The relation asked to hold.</param>
    [TestMethod]
    [DataRow(ComparisonRelation.SubsetOf, DisplayName = "subset of")]
    [DataRow(ComparisonRelation.SupersetOf, DisplayName = "superset of")]
    [DataRow(ComparisonRelation.NotLaterThan, DisplayName = "not later than")]
    public async Task ARelationOtherThanEqualIsUndetermined(ComparisonRelation relation)
    {
        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [ListedIdentifier("email")];

        ComparisonOutcome outcome = await associations.CompareAsync(
            PresentedIdentifier("email"), Reference, relation, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Indeterminate, outcome);
    }


    /// <summary>
    /// The application changes the dictionary at any time, and each comparison reads the entry as it stands:
    /// a listed identifier holds, the same comparison after the entry is removed is undecided, and after an
    /// entry without the identifier is added it fails. That a change applies to the next comparison is this
    /// library's rule.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 9.5</see>:
    /// "The Resource Authorization Server MUST use a SAML NameID sub_id only when the validated ID-JAG issuer is
    /// explicitly associated with the SAML issuer identified by sub_id.issuer through local configuration or
    /// trusted federation metadata."
    /// </summary>
    [TestMethod]
    public async Task AChangeAppliesToTheNextComparison()
    {
        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [ListedIdentifier("saml-nameid")];
        SubjectIdentifier presented = PresentedIdentifier("saml-nameid");

        ComparisonOutcome listed = await associations.CompareAsync(
            presented, Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(associations.TryRemove(Reference, out _));
        ComparisonOutcome removed = await associations.CompareAsync(
            presented, Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);
        associations[Reference] = [SubjectIdentifier.Email("mallory@example.com")];
        ComparisonOutcome replaced = await associations.CompareAsync(
            presented, Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Holds, listed);
        Assert.AreEqual(ComparisonOutcome.Indeterminate, removed);
        Assert.AreEqual(ComparisonOutcome.Fails, replaced);
    }


    /// <summary>
    /// An <c>aliases</c> candidate is one Subject Identifier of the Aliases Identifier Format, compared as a
    /// whole: it is not expanded into its elements, so an <c>aliases</c> candidate holding a listed
    /// <c>email</c> and another identifier fails against an entry that lists the <c>email</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see>: "The
    /// Aliases Identifier Format describes a subject that is identified with a list of different Subject
    /// Identifiers." "It is intended for use when a variety of identifiers have been shared with the party that
    /// will be interpreting the Subject Identifier, and it is unknown which of those identifiers they will
    /// recognize or support." "Each Subject Identifier in the array MUST identify the same entity." Against that
    /// intent, the whole comparison is this library's reading, for this reason: an <c>aliases</c> candidate
    /// whose elements the application lists under two different grant subjects would, compared element by
    /// element, hold for either subject. An application that resolves a subject by any single alias supplies
    /// its own <see cref="CompareDelegate{TCandidate, TReference}"/>.
    /// </summary>
    [TestMethod]
    public async Task AnAliasesCandidateEqualsOnlyAsAWhole()
    {
        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [ListedIdentifier("email")];
        SubjectIdentifier presented = SubjectIdentifier.Aliases([ListedIdentifier("email"), SubjectIdentifier.PhoneNumber("+12065550100")]);

        ComparisonOutcome outcome = await associations.CompareAsync(
            presented, Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Fails, outcome);
    }


    /// <summary>
    /// An <c>aliases</c> identifier listed by the library's factory holds for a candidate read from the wire
    /// (its JSON text decoded by the library's JSON reader, then read by
    /// <see cref="SubjectIdentifier.FromWireObject"/>) whose <c>identifiers</c> array holds the same Subject
    /// Identifiers in the same order, and fails for one whose array differs in one nested value: every element
    /// and every member of each element is compared.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see>: "Subject
    /// Identifiers in this format MUST contain an "identifiers" member whose value is a JSON array containing
    /// one or more Subject Identifiers."
    /// </summary>
    /// <param name="caseName">The candidate: <c>exact</c> (the same elements) or <c>nestedValue</c> (another phone number).</param>
    /// <param name="presentedPhoneNumber">The phone number of the candidate's second element.</param>
    /// <param name="expected">The outcome the comparison answers.</param>
    [TestMethod]
    [DataRow("exact", "+12065550100", ComparisonOutcome.Holds, DisplayName = "the same elements in the same order")]
    [DataRow("nestedValue", "+12065550199", ComparisonOutcome.Fails, DisplayName = "one nested value differs")]
    public async Task AnAliasesIdentifierHoldsOnlyWhenEveryNestedValueIsEqual(string caseName, string presentedPhoneNumber, ComparisonOutcome expected)
    {
        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [SubjectIdentifier.Aliases([ListedIdentifier("email"), SubjectIdentifier.PhoneNumber("+12065550100")])];
        string presentedJson =
            $$"""{"format":"aliases","identifiers":[{"format":"email","email":"{{EndUserEmail}}"},{"format":"phone_number","phone_number":"{{presentedPhoneNumber}}"}]}""";
        Dictionary<string, object>? decoded = JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            presentedJson, TestSetup.DefaultSerializationOptions);
        Assert.IsNotNull(decoded);

        SubjectIdentifier presented = WireIdentifier(decoded);

        ComparisonOutcome outcome = await associations.CompareAsync(
            presented, Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expected, outcome, caseName);
    }


    /// <summary>
    /// An entry that lists no identifier decides against every candidate: an entry whose array is the default
    /// value and an entry holding a null element only both fail. That such an entry lists none is this
    /// library's rule.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>
    /// refuses a grant when "the sub_id claim is not authorized by local policy for the validated ID-JAG
    /// issuer."
    /// </summary>
    /// <param name="caseName">The entry: <c>defaultArray</c> or <c>nullOnly</c>.</param>
    [TestMethod]
    [DataRow("defaultArray", DisplayName = "an entry whose array is the default value")]
    [DataRow("nullOnly", DisplayName = "an entry holding a null element only")]
    public async Task AnEntryListingNoIdentifierFails(string caseName)
    {
        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = caseName switch
        {
            "defaultArray" => default,
            "nullOnly" => [null!],
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        ComparisonOutcome outcome = await associations.CompareAsync(
            PresentedIdentifier("email"), Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Fails, outcome);
    }


    /// <summary>
    /// A null element beside a listed identifier lists nothing and is passed over, so the listed identifier
    /// beside it holds. That a null element lists none is this library's rule.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "When both sub and sub_id are present, they MUST identify the same End-User."
    /// </summary>
    [TestMethod]
    public async Task ANullElementBesideAListedIdentifierIsPassedOver()
    {
        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [null!, ListedIdentifier("email")];

        ComparisonOutcome outcome = await associations.CompareAsync(
            PresentedIdentifier("email"), Reference, ComparisonRelation.Equal, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ComparisonOutcome.Holds, outcome);
    }


    /// <summary>
    /// A comparison whose token is cancelled when it is called throws <see cref="OperationCanceledException"/>
    /// and decides nothing, as a <see cref="CompareDelegate{TCandidate, TReference}"/> honours its token. No
    /// clause of the texts this class implements governs cancellation, so the row anchors no clause: the rule is
    /// this library's.
    /// </summary>
    [TestMethod]
    public async Task ACancelledComparisonThrows()
    {
        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [ListedIdentifier("email")];
        using CancellationTokenSource cancelled = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await cancelled.CancelAsync().ConfigureAwait(false);

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await associations.CompareAsync(
                PresentedIdentifier("email"), Reference, ComparisonRelation.Equal, cancelled.Token).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>
    /// The dictionary's text names the number of entries only: a grant subject and a Subject Identifier can
    /// name a person, so neither reaches a log, a trace or an exception message through the text. The rule is
    /// this library's.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.6">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 9.6</see>:
    /// "Because the ID-JAG is visible to the Client that presents it, sub_id can disclose additional user
    /// identifiers, such as email-address NameIDs or stable enterprise account identifiers, that the Client
    /// might not otherwise receive."
    /// </summary>
    [TestMethod]
    public void TheTextNamesNoSubject()
    {
        IdJagSubjectAssociationDictionary associations = new();
        associations[Reference] = [ListedIdentifier("email")];

        string text = associations.ToString();

        Assert.AreEqual("IdJagSubjectAssociationDictionary(Count=1)", text);
        Assert.DoesNotContain(GrantSubject, text, StringComparison.Ordinal);
        Assert.DoesNotContain(EndUserEmail, text, StringComparison.Ordinal);
    }


    /// <summary>
    /// The identifier the application lists under <see cref="Reference"/>, built by the library's factories.
    /// </summary>
    /// <param name="format">The format: <c>email</c>, <c>saml-nameid</c> or <c>iss_sub</c>.</param>
    /// <returns>The listed identifier.</returns>
    private static SubjectIdentifier ListedIdentifier(string format) => format switch
    {
        "email" => SubjectIdentifier.Email(EndUserEmail),
        "saml-nameid" => new SamlNameIdSubjectIdentifier
        {
            Issuer = SamlIssuer,
            NameId = EndUserEmail,
            SpNameQualifier = SamlSpNameQualifier
        }.ToSubjectIdentifier(),
        "iss_sub" => SubjectIdentifier.IssuerSubject(GrantIssuer, GrantSubject),
        _ => throw new ArgumentOutOfRangeException(nameof(format), format, null)
    };


    /// <summary>
    /// The identifier a grant presents with the values of <see cref="ListedIdentifier"/>, built separately from
    /// its wire object as a parsed <c>sub_id</c> claim arrives.
    /// </summary>
    /// <param name="format">The format: <c>email</c>, <c>saml-nameid</c> or <c>iss_sub</c>.</param>
    /// <returns>The presented identifier.</returns>
    private static SubjectIdentifier PresentedIdentifier(string format) => format switch
    {
        "email" => WireIdentifier(new() { ["format"] = "email", ["email"] = EndUserEmail }),
        "saml-nameid" => WireIdentifier(new()
        {
            ["format"] = "saml-nameid",
            ["issuer"] = SamlIssuer,
            ["nameid"] = EndUserEmail,
            ["sp_name_qualifier"] = SamlSpNameQualifier
        }),
        "iss_sub" => WireIdentifier(new() { ["format"] = "iss_sub", ["iss"] = GrantIssuer, ["sub"] = GrantSubject }),
        _ => throw new ArgumentOutOfRangeException(nameof(format), format, null)
    };


    /// <summary>
    /// Projects a wire object, in the shape the JSON layer materializes, into a Subject Identifier.
    /// </summary>
    /// <param name="wire">The wire object, its <c>format</c> member included.</param>
    /// <returns>The projected identifier.</returns>
    private static SubjectIdentifier WireIdentifier(Dictionary<string, object> wire)
    {
        SubjectIdentifier? identifier = SubjectIdentifier.FromWireObject(wire);
        Assert.IsNotNull(identifier);

        return identifier;
    }
}

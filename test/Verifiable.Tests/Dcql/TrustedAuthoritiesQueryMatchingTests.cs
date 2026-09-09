using System.Buffers.Text;
using System.Collections.Generic;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Dcql;

/// <summary>
/// Proves <see cref="TrustedAuthoritiesQuery.Matches(TrustedAuthorityEvidence)"/> dispatches on the
/// entry's <c>type</c> and compares each of the three registered
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
/// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see> types against the credential's typed
/// trust evidence: an <c>aki</c> entry against the certificate-chain AuthorityKeyIdentifiers, an
/// <c>etsi_tl</c> entry against the held Trusted List memberships, and an <c>openid_federation</c>
/// entry against the validated federation trust-path entities. Every fixture value here is a
/// Section 6.1.1 example (<c>s9tIpPmhxdiuNkHMEWNpYim8S8Y</c>, <c>https://lotl.example.com</c>,
/// <c>https://trustanchor.example.com</c>), never a value read back through the code under test.
/// </summary>
[TestClass]
internal sealed class TrustedAuthoritiesQueryMatchingTests
{
    /// <summary>The MSTest-supplied context of the currently executing test.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The <c>aki</c> example value in a padded base64url form of <see cref="DcqlFixtures.AkiExampleValue"/>'s
    /// identical bytes — the same authority, a different transport spelling.
    /// </summary>
    private const string AkiExamplePaddedValue = "s9tIpPmhxdiuNkHMEWNpYim8S8Y=";

    /// <summary>The <c>etsi_tl</c> value of the Section 6.1.1.2 non-normative example entry.</summary>
    private const string EtsiTrustedListExampleValue = "https://lotl.example.com";

    /// <summary>The <c>openid_federation</c> value of the Section 6.1.1.3 non-normative example entry.</summary>
    private const string OpenIdFederationExampleValue = "https://trustanchor.example.com";


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1.1</see>: "The raw byte representation
    /// of this element MUST match with the AuthorityKeyIdentifier element of an X.509 certificate in
    /// the certificate chain present in the Credential." An <c>aki</c> entry whose value decodes to
    /// an AuthorityKeyIdentifier present in the evidence matches.
    /// </summary>
    [TestMethod]
    public void AkiEntryMatchesEvidenceCarryingTheSameKeyIdentifier()
    {
        var evidence = new TrustedAuthorityEvidence
        {
            AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { AkiExample() }
        };

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = DcqlTrustedAuthorityTypes.Aki,
            Values = [DcqlFixtures.AkiExampleValue]
        };

        Assert.IsTrue(
            authorities.Matches(evidence),
            "Section 6.1.1.1: the raw bytes of the aki value match an AuthorityKeyIdentifier in the credential's chain evidence.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1.1</see>: the match is on "The raw byte
    /// representation of this element", so a padded base64url spelling of the same key identifier
    /// bytes matches the same authority.
    /// </summary>
    [TestMethod]
    public void AkiEntryMatchesAPaddedFormOfTheSameKeyIdentifier()
    {
        var evidence = new TrustedAuthorityEvidence
        {
            AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { AkiExample() }
        };

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = DcqlTrustedAuthorityTypes.Aki,
            Values = [AkiExamplePaddedValue]
        };

        Assert.IsTrue(
            authorities.Matches(evidence),
            "Section 6.1.1.1 compares raw bytes, so a padded base64url form of the same keyIdentifier matches.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1.1</see>: the value is "encoded as
    /// base64url". A value that is not base64url decodes to no bytes, so it identifies no authority
    /// and matches nothing — the wire value is rejected quietly, never with an exception.
    /// </summary>
    [TestMethod]
    public void AkiEntryDoesNotMatchWhenItsOnlyValueIsNotBase64Url()
    {
        var evidence = new TrustedAuthorityEvidence
        {
            AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { AkiExample() }
        };

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = DcqlTrustedAuthorityTypes.Aki,
            Values = ["not base64url $$$"]
        };

        Assert.IsFalse(
            authorities.Matches(evidence),
            "An aki value that is not base64url decodes to no key identifier, so it matches nothing and does not throw.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "A Credential is identified as a
    /// match to a Trusted Authorities Query if it matches with one of the provided values in one of
    /// the provided types." An unparseable value earlier in the array does not abort the entry; a
    /// later parseable, present value still matches.
    /// </summary>
    [TestMethod]
    public void AkiEntryMatchesWhenAnUnparseableValuePrecedesAMatchingOne()
    {
        var evidence = new TrustedAuthorityEvidence
        {
            AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { AkiExample() }
        };

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = DcqlTrustedAuthorityTypes.Aki,
            Values = ["not base64url $$$", DcqlFixtures.AkiExampleValue]
        };

        Assert.IsTrue(
            authorities.Matches(evidence),
            "Section 6.1.1: a match needs one of the provided values, so a matching value after an unparseable one still matches.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1.2</see>: an <c>etsi_tl</c> value is
    /// "The identifier of a Trusted List as specified in ETSI TS 119 612 [ETSI.TL]." The entry
    /// matches when the credential's evidence records membership of that Trusted List.
    /// </summary>
    [TestMethod]
    public void EtsiTrustedListEntryMatchesEvidenceContainingTheListIdentifier()
    {
        var evidence = new TrustedAuthorityEvidence
        {
            TrustedListMemberships = new HashSet<TrustedListIdentifier> { new(EtsiTrustedListExampleValue) }
        };

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = DcqlTrustedAuthorityTypes.EtsiTrustedList,
            Values = [EtsiTrustedListExampleValue]
        };

        Assert.IsTrue(
            authorities.Matches(evidence),
            "Section 6.1.1.2: the credential's chain is a member of the named Trusted List.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1.2</see>: the trust chain "MUST contain
    /// at least one X.509 Certificate that matches one of the entries of the Trusted List or its
    /// cascading Trusted Lists." An entry naming a different Trusted List than the one the evidence
    /// records does not match.
    /// </summary>
    [TestMethod]
    public void EtsiTrustedListEntryDoesNotMatchADifferentIdentifier()
    {
        var evidence = new TrustedAuthorityEvidence
        {
            TrustedListMemberships = new HashSet<TrustedListIdentifier> { new(EtsiTrustedListExampleValue) }
        };

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = DcqlTrustedAuthorityTypes.EtsiTrustedList,
            Values = ["https://other-list.example.com"]
        };

        Assert.IsFalse(
            authorities.Matches(evidence),
            "Section 6.1.1.2: the evidence records membership of a different Trusted List than the one named, so it does not match.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1.3</see>: an <c>openid_federation</c>
    /// value is "The Entity Identifier ... A valid trust path, including the given Entity Identifier,
    /// must be constructible from a matching credential." The entry matches when the evidence records
    /// that identifier on a validated trust path.
    /// </summary>
    [TestMethod]
    public void OpenIdFederationEntryMatchesEvidenceContainingTheEntityIdentifier()
    {
        var evidence = new TrustedAuthorityEvidence
        {
            FederationTrustPathEntities = new HashSet<EntityIdentifier> { new(OpenIdFederationExampleValue) }
        };

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = DcqlTrustedAuthorityTypes.OpenIdFederation,
            Values = [OpenIdFederationExampleValue]
        };

        Assert.IsTrue(
            authorities.Matches(evidence),
            "Section 6.1.1.3: the named Entity Identifier lies on the credential's validated federation trust path.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1.3</see>: a value that is not the Entity
    /// Identifier of any entity on the credential's validated trust path does not match.
    /// </summary>
    [TestMethod]
    public void OpenIdFederationEntryDoesNotMatchAStrangerIdentifier()
    {
        var evidence = new TrustedAuthorityEvidence
        {
            FederationTrustPathEntities = new HashSet<EntityIdentifier> { new(OpenIdFederationExampleValue) }
        };

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = DcqlTrustedAuthorityTypes.OpenIdFederation,
            Values = ["https://stranger.example.com"]
        };

        Assert.IsFalse(
            authorities.Matches(evidence),
            "Section 6.1.1.3: the named Entity Identifier is on no validated trust path in the evidence, so it does not match.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1.3</see>: the value is an Entity
    /// Identifier "as defined in Section 1 of [OpenID.Federation]", an https URL. A value that is not
    /// a well-formed https Entity Identifier identifies no entity, so it matches nothing and never
    /// throws.
    /// </summary>
    [DataRow("not-a-url", DisplayName = "A bare token is no Entity Identifier.")]
    [DataRow("http://trustanchor.example.com", DisplayName = "A non-https URL is no Entity Identifier.")]
    [DataRow("https://trustanchor.example.com/path?query=1", DisplayName = "A query-bearing URL is no Entity Identifier.")]
    [TestMethod]
    public void OpenIdFederationEntryDoesNotMatchAValueThatIsNotAnHttpsEntityIdentifier(string value)
    {
        var evidence = new TrustedAuthorityEvidence
        {
            FederationTrustPathEntities = new HashSet<EntityIdentifier> { new(OpenIdFederationExampleValue) }
        };

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = DcqlTrustedAuthorityTypes.OpenIdFederation,
            Values = [value]
        };

        Assert.IsFalse(
            authorities.Matches(evidence),
            "Section 6.1.1.3: a value that is not a well-formed https Entity Identifier matches nothing and does not throw.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "Types defined by this
    /// specification are listed below." — <c>aki</c>, <c>etsi_tl</c> and <c>openid_federation</c>.
    /// An entry whose <c>type</c> is none of those cannot be evaluated against any evidence and
    /// matches nothing, even when the evidence carries every kind of fact.
    /// </summary>
    [DataRow("x509_san_dns", DisplayName = "An unregistered type name.")]
    [DataRow("", DisplayName = "An empty type name.")]
    [TestMethod]
    public void AnEntryWhoseTypeIsUnregisteredMatchesNothing(string type)
    {
        var evidence = new TrustedAuthorityEvidence
        {
            AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { AkiExample() },
            TrustedListMemberships = new HashSet<TrustedListIdentifier> { new(EtsiTrustedListExampleValue) },
            FederationTrustPathEntities = new HashSet<EntityIdentifier> { new(OpenIdFederationExampleValue) }
        };

        var authorities = new TrustedAuthoritiesQuery
        {
            Type = type,
            Values = [DcqlFixtures.AkiExampleValue, EtsiTrustedListExampleValue, OpenIdFederationExampleValue]
        };

        Assert.IsFalse(
            authorities.Matches(evidence),
            "Section 6.1.1: an entry of an unregistered type matches nothing, whatever the evidence carries.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: a match requires "one of the
    /// provided values in one of the provided types". Evidence carrying no fact of any kind
    /// (<see cref="TrustedAuthorityEvidence.Empty"/>) matches no entry, whatever its registered type.
    /// </summary>
    [DataRow("aki", DcqlFixtures.AkiExampleValue, DisplayName = "An aki entry against empty evidence.")]
    [DataRow("etsi_tl", EtsiTrustedListExampleValue, DisplayName = "An etsi_tl entry against empty evidence.")]
    [DataRow("openid_federation", OpenIdFederationExampleValue, DisplayName = "An openid_federation entry against empty evidence.")]
    [TestMethod]
    public void EmptyEvidenceMatchesNothingForEveryType(string type, string value)
    {
        var authorities = new TrustedAuthoritiesQuery
        {
            Type = type,
            Values = [value]
        };

        Assert.IsFalse(
            authorities.Matches(TrustedAuthorityEvidence.Empty),
            "Section 6.1.1: evidence carrying no fact matches no entry of any registered type.");
    }


    /// <summary>
    /// Builds the Section 6.1.1.1 example AuthorityKeyIdentifier from its base64url spelling, decoding
    /// with the framework's own base64url reader so the fixture is the spec's example bytes rather than
    /// a value produced by the type under test.
    /// </summary>
    /// <returns>The <see cref="AuthorityKeyIdentifier"/> the example <c>aki</c> value denotes.</returns>
    private static AuthorityKeyIdentifier AkiExample()
    {
        return new AuthorityKeyIdentifier(Base64Url.DecodeFromChars(DcqlFixtures.AkiExampleValue));
    }
}

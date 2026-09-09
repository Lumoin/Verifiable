using System.Buffers.Text;
using System.Collections.Generic;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Dcql;

/// <summary>
/// Proves <see cref="DcqlEvaluator.EvaluateSingle"/> applies a credential query's
/// <c>trusted_authorities</c> constraint through the typed evidence carried on
/// <see cref="DcqlCredentialMetadata.TrustedAuthorityEvidence"/>: a present constraint against absent
/// evidence fails closed with <see cref="DcqlFailureReasons.TrustedAuthorityEvidenceAbsent"/>, present
/// evidence matching no entry fails with <see cref="DcqlFailureReasons.TrustedAuthorityUnmatched"/>,
/// a matched entry lets evaluation proceed to a match, an unmatched entry of one type and a matched
/// entry of another together match, an all-unsupported-type constraint names the type, and an absent
/// constraint is not applied at all.
/// </summary>
/// <remarks>
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4.2">
/// OpenID for Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the
/// respective constraints expressed within credentials MUST NOT be returned, i.e., they are treated
/// as if they would not exist in the Wallet."
/// </remarks>
[TestClass]
internal sealed class DcqlTrustedAuthorityEvaluationTests
{
    /// <summary>The MSTest-supplied context of the currently executing test.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The <c>etsi_tl</c> value of the Section 6.1.1.2 non-normative example entry.</summary>
    private const string EtsiTrustedListExampleValue = "https://lotl.example.com";

    /// <summary>The Credential Query identifier the queries built here carry.</summary>
    private const string CredentialQueryId = "authority-constrained";

    /// <summary>An <c>aki</c> value the queries name but no evidence below carries.</summary>
    private const string UnrelatedAkiValue = "AAECAwQFBgcICQoLDA0ODxAREhM";


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4.2">
    /// OpenID for Verifiable Presentations 1.0, Section 6.4.2</see>: a credential carrying no trust
    /// evidence at all cannot be shown to satisfy a <c>trusted_authorities</c> constraint, so it does
    /// not match, and the non-match names the absent evidence.
    /// </summary>
    [TestMethod]
    public void TrustedAuthoritiesPresentWithNoEvidenceYieldsTheAbsentEvidenceReason()
    {
        CredentialQuery query = AkiQuery(DcqlFixtures.AkiExampleValue);

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential: new object(), MdocMetadata(evidence: null), NoClaims);

        Assert.IsFalse(
            result.Matches,
            "Section 6.4.2: a credential with no trust evidence cannot be shown to satisfy the trusted_authorities constraint, so it does not match.");
        Assert.AreEqual(
            DcqlFailureReasons.TrustedAuthorityEvidenceAbsent,
            result.FailureReason,
            "The non-match names the absent evidence through DcqlFailureReasons.TrustedAuthorityEvidenceAbsent.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "A Credential is identified as a
    /// match ... if it matches with one of the provided values in one of the provided types." Evidence
    /// that is present but carries a different AuthorityKeyIdentifier than the entry names matches no
    /// entry, and the non-match names the entries as unmatched rather than absent.
    /// </summary>
    [TestMethod]
    public void TrustedAuthoritiesPresentWithEvidenceMatchingNoEntryYieldsTheUnmatchedReason()
    {
        CredentialQuery query = AkiQuery(DcqlFixtures.AkiExampleValue);
        var evidence = new TrustedAuthorityEvidence
        {
            AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { AkiFrom(UnrelatedAkiValue) }
        };

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential: new object(), MdocMetadata(evidence), NoClaims);

        Assert.IsFalse(
            result.Matches,
            "Section 6.1.1: the credential's evidence carries no value the entry names, so no entry matches.");
        Assert.AreEqual(
            DcqlFailureReasons.TrustedAuthorityUnmatched,
            result.FailureReason,
            "The non-match names the entries as unmatched: evidence was present, it simply named no listed authority.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1.1</see>: an <c>aki</c> entry whose value
    /// matches an AuthorityKeyIdentifier in the credential's evidence satisfies the
    /// <c>trusted_authorities</c> constraint, so a query constrained on nothing else matches.
    /// </summary>
    [TestMethod]
    public void TrustedAuthoritiesMatchedLetsTheEvaluationProceedToAMatch()
    {
        CredentialQuery query = AkiQuery(DcqlFixtures.AkiExampleValue);
        var evidence = new TrustedAuthorityEvidence
        {
            AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { AkiFrom(DcqlFixtures.AkiExampleValue) }
        };

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential: new object(), MdocMetadata(evidence), NoClaims);

        Assert.IsTrue(
            result.Matches,
            "Section 6.1.1.1: the aki entry matches the credential's evidence, so the trusted_authorities constraint is satisfied.");
        Assert.IsNull(
            result.FailureReason,
            "A match carries no failure reason.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "A Credential is identified as a
    /// match to a Trusted Authorities Query if it matches with one of the provided values in one of
    /// the provided types." An <c>etsi_tl</c> entry the evidence does not satisfy alongside a matched
    /// <c>aki</c> entry still matches — the array is satisfied by any one entry.
    /// </summary>
    [TestMethod]
    public void AnUnmatchedEtsiEntryAndAMatchedAkiEntryTogetherMatch()
    {
        CredentialQuery query = new()
        {
            Id = CredentialQueryId,
            Format = DcqlCredentialFormats.MsoMdoc,
            TrustedAuthorities =
            [
                new TrustedAuthoritiesQuery { Type = DcqlTrustedAuthorityTypes.EtsiTrustedList, Values = [EtsiTrustedListExampleValue] },
                new TrustedAuthoritiesQuery { Type = DcqlTrustedAuthorityTypes.Aki, Values = [DcqlFixtures.AkiExampleValue] }
            ]
        };

        var evidence = new TrustedAuthorityEvidence
        {
            AuthorityKeyIdentifiers = new HashSet<AuthorityKeyIdentifier> { AkiFrom(DcqlFixtures.AkiExampleValue) }
        };

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential: new object(), MdocMetadata(evidence), NoClaims);

        Assert.IsTrue(
            result.Matches,
            "Section 6.1.1: one matching entry in one of the provided types is enough, even though the etsi_tl entry is unsatisfied.");
        Assert.IsNull(
            result.FailureReason,
            "A match carries no failure reason.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: "Types defined by this
    /// specification are listed below." A <c>trusted_authorities</c> array all of whose entries carry
    /// an unregistered type can be evaluated against nothing, so it matches nothing and the non-match
    /// names the offending type.
    /// </summary>
    [TestMethod]
    public void AllEntriesOfAnUnsupportedTypeYieldTheReasonNamingTheType()
    {
        const string unsupportedType = "x509_san_dns";
        CredentialQuery query = new()
        {
            Id = CredentialQueryId,
            Format = DcqlCredentialFormats.MsoMdoc,
            TrustedAuthorities =
            [
                new TrustedAuthoritiesQuery { Type = unsupportedType, Values = ["verifier.example.com"] }
            ]
        };

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential: new object(), MdocMetadata(TrustedAuthorityEvidence.Empty), NoClaims);

        Assert.IsFalse(
            result.Matches,
            "Section 6.1.1: an entry of an unregistered type matches nothing, so the constraint is unsatisfied.");
        Assert.AreEqual(
            DcqlFailureReasons.TrustedAuthorityTypeUnsupported(unsupportedType),
            result.FailureReason,
            "The non-match names the unsupported type through DcqlFailureReasons.TrustedAuthorityTypeUnsupported.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "trusted_authorities: OPTIONAL. ...
    /// Every Credential returned by the Wallet SHOULD match at least one of the conditions present in
    /// the corresponding trusted_authorities array if present." A credential query carrying no
    /// <c>trusted_authorities</c> applies no such constraint, so a credential whose evidence is empty
    /// still matches on format and claims alone.
    /// </summary>
    [TestMethod]
    public void AnAbsentTrustedAuthoritiesConstraintIsNotAppliedSoEmptyEvidenceStillMatches()
    {
        CredentialQuery query = new()
        {
            Id = CredentialQueryId,
            Format = DcqlCredentialFormats.MsoMdoc
        };

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential: new object(), MdocMetadata(TrustedAuthorityEvidence.Empty), NoClaims);

        Assert.IsTrue(
            result.Matches,
            "Section 6.1: with no trusted_authorities present, the constraint is not applied and empty evidence does not withhold the credential.");
        Assert.IsNull(
            result.FailureReason,
            "A match carries no failure reason.");
    }


    /// <summary>
    /// Builds a single-entry <c>aki</c> Credential Query in the mdoc format constrained only on
    /// trusted authorities, so a trusted-authority outcome alone decides the match.
    /// </summary>
    /// <param name="akiValue">The base64url <c>aki</c> value the entry names.</param>
    /// <returns>The Credential Query the evaluation runs against.</returns>
    private static CredentialQuery AkiQuery(string akiValue)
    {
        return new CredentialQuery
        {
            Id = CredentialQueryId,
            Format = DcqlCredentialFormats.MsoMdoc,
            TrustedAuthorities =
            [
                new TrustedAuthoritiesQuery { Type = DcqlTrustedAuthorityTypes.Aki, Values = [akiValue] }
            ]
        };
    }


    /// <summary>
    /// Builds the mdoc-format credential metadata the evaluation reads, carrying the supplied trust
    /// evidence and no type constraint, so the trusted-authority check is the only one that can fail.
    /// </summary>
    /// <param name="evidence">The credential's trust evidence, or <see langword="null"/> when it carries none.</param>
    /// <returns>The credential metadata the evaluation runs against.</returns>
    private static DcqlCredentialMetadata MdocMetadata(TrustedAuthorityEvidence? evidence)
    {
        return new DcqlCredentialMetadata
        {
            Format = DcqlCredentialFormats.MsoMdoc,
            TrustedAuthorityEvidence = evidence
        };
    }


    /// <summary>
    /// Builds an <see cref="AuthorityKeyIdentifier"/> from a base64url spelling, decoding with the
    /// framework's own reader so the evidence value is spec-derived rather than produced by the code
    /// under test.
    /// </summary>
    /// <param name="base64Url">The base64url key identifier.</param>
    /// <returns>The <see cref="AuthorityKeyIdentifier"/> the value denotes.</returns>
    private static AuthorityKeyIdentifier AkiFrom(string base64Url)
    {
        return new AuthorityKeyIdentifier(Base64Url.DecodeFromChars(base64Url));
    }


    /// <summary>
    /// A claim extractor for the credential queries here, which carry no claims and so never invoke
    /// it; it reports every claim absent.
    /// </summary>
    /// <param name="credential">The credential being evaluated.</param>
    /// <param name="pattern">The claims path pointer to resolve.</param>
    /// <param name="value">Always <see langword="null"/>.</param>
    /// <returns>Always <see langword="false"/>.</returns>
    private static bool NoClaims(object credential, DcqlClaimPattern pattern, out object? value)
    {
        value = null;

        return false;
    }
}

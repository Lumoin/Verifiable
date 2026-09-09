using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Dcql;

/// <summary>
/// Proves <see cref="DcqlEvaluator"/> answers a constraint it cannot show to be satisfied with a
/// non-match carrying a named <see cref="DcqlFailureReasons"/> reason rather than passing the
/// constraint over in silence: a <c>meta.vct_values</c> constraint against a credential that
/// declares no type, and a <c>trusted_authorities</c> constraint against a credential that carries
/// no issuer evidence.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
/// Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the respective
/// constraints expressed within credentials MUST NOT be returned, i.e., they are treated as if
/// they would not exist in the Wallet."
/// </para>
/// <para>
/// Every member of <see cref="DcqlFailureReasons"/> is reached by one of these cases:
/// <see cref="DcqlFailureReasons.CredentialTypeUnknown"/>,
/// <see cref="DcqlFailureReasons.SdJwtVctValuesRequired"/>,
/// <see cref="DcqlFailureReasons.CredentialTypeNotAccepted"/>,
/// <see cref="DcqlFailureReasons.TrustedAuthorityEvidenceAbsent"/>,
/// <see cref="DcqlFailureReasons.TrustedAuthorityUnmatched"/>,
/// <see cref="DcqlFailureReasons.FormatMismatch"/>,
/// <see cref="DcqlFailureReasons.MissingRequiredClaims"/>,
/// <see cref="DcqlFailureReasons.ValueConstraintsFailed"/> and
/// <see cref="DcqlFailureReasons.RequiredClaimSetNotSatisfied"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class DcqlEvaluatorFailClosedTests
{
    /// <summary>The MSTest-supplied context of the currently executing test.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The issuing authority the trusted-authority queries below name as accepted.</summary>
    private const string PidIssuer = "https://pid-issuer.example.com";

    /// <summary>An issuing authority no trusted-authority query below names.</summary>
    private const string StrangerIssuer = "https://stranger.example.com";

    /// <summary>
    /// The type of a credential that is not a PID, held beside the PID so that two credentials
    /// both carrying <c>family_name</c> are separated by the type constraint alone.
    /// </summary>
    private const string DiplomaVct = "https://credentials.example.com/diploma";

    /// <summary>
    /// A domestic PID type that declares the base PID type among its additional types, the shape
    /// Appendix B.3.5's inheritance sentence contemplates.
    /// </summary>
    private const string DomesticPidVct = "urn:eudi:pid:de:1";

    /// <summary>The <c>family_name</c> value the credentials built here carry.</summary>
    private const string FamilyNameValue = "Mustermann";

    /// <summary>The <c>given_name</c> value the value-constraint credential carries.</summary>
    private const string GivenNameValue = "Erika";

    /// <summary>The <c>family_name</c> value the value-constraint query does not accept.</summary>
    private const string UnacceptedFamilyNameValue = "Doe";


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Appendix B.3.5</see>: "vct_values: REQUIRED. A non-empty array
    /// of strings that specifies allowed values for the type of the requested Verifiable
    /// Credential." Read with Section 6.4.2's "Credentials not matching the respective constraints
    /// expressed within credentials MUST NOT be returned", a credential that declares no type at
    /// all cannot be shown to be one of the allowed values, so it does not match — and the reason
    /// names the absent type instead of leaving the caller to guess.
    /// </summary>
    [TestMethod]
    public void ASdJwtQueryCarryingNoVctValuesMatchesNothingAndYieldsNoPresentation()
    {
        CredentialQuery query = new()
        {
            Id = DcqlFixtures.PidCredentialId,
            Format = WellKnownMediaTypes.Jwt.DcSdJwt,
            Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(EudiPid.SdJwt.FamilyName) }]
        };

        TestCredential credential = BuildCredential(EudiPid.SdJwtVct, PidIssuer);

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsFalse(
            result.Matches,
            "Appendix B.3.5 makes vct_values REQUIRED for dc+sd-jwt, so a query omitting it expresses a type constraint no credential can be shown to satisfy, and Section 6.4.2 forbids returning one.");
        Assert.AreEqual(
            DcqlFailureReasons.SdJwtVctValuesRequired,
            result.FailureReason,
            "The non-match names the absent vct_values through DcqlFailureReasons.SdJwtVctValuesRequired.");

        //Appendix B.3.5's requirement is enforced at preparation too (DcqlQueryExtensions.Validate,
        //which also carries OID4VP 1.0 §6.1's id rule): a query missing meta.vct_values never reaches
        //evaluation as a silent non-match. A query that failed preparation is refused outright for
        //every recorded issue, not only an invalid id, rather than reproducing the per-credential
        //non-match EvaluateSingle already proved above.
        PreparedDcqlQuery prepared = DcqlPreparer.Prepare(new DcqlQuery { Credentials = [query] });

        Assert.IsFalse(prepared.IsValid,
            "A dc+sd-jwt credential query with no meta.vct_values fails preparation per Appendix B.3.5.");

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => DcqlEvaluator.Evaluate(prepared, [credential], ExtractMetadata, ExtractClaim).ToList(),
            "OID4VP 1.0 §6.1: evaluating an invalid prepared query is a caller defect, never a silent empty result.");
        Assert.Contains(prepared.ValidationIssues[0], exception.Message,
            "The exception names the query's first recorded validation issue.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Appendix B.3.5</see>: "vct_values: REQUIRED. A non-empty array
    /// of strings that specifies allowed values for the type of the requested Verifiable
    /// Credential." Read with Section 6.4.2's "Credentials not matching the respective constraints
    /// expressed within credentials MUST NOT be returned", a credential that declares no type at
    /// all cannot be shown to be one of the allowed values, so it does not match — and the reason
    /// names the absent type instead of leaving the caller to guess.
    /// </summary>
    [TestMethod]
    public void TypeConstrainedQueryDoesNotMatchACredentialDeclaringNoType()
    {
        CredentialQuery query = PidFamilyNameQuery();
        TestCredential credential = BuildCredential(credentialType: null, issuer: PidIssuer);

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsFalse(
            result.Matches,
            "Appendix B.3.5's vct_values constrains the credential type and Section 6.4.2 forbids returning a credential that does not match it, so a credential declaring no type does not match.");
        Assert.AreEqual(
            DcqlFailureReasons.CredentialTypeUnknown,
            result.FailureReason,
            "The non-match names the absent type through DcqlFailureReasons.CredentialTypeUnknown.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Appendix B.3.5</see>: "vct_values: REQUIRED. A non-empty array
    /// of strings that specifies allowed values for the type of the requested Verifiable
    /// Credential." A credential whose declared type is one of those values satisfies the
    /// constraint and matches.
    /// </summary>
    [TestMethod]
    public void TypeConstrainedQueryMatchesACredentialWhoseTypeIsListed()
    {
        CredentialQuery query = PidFamilyNameQuery();
        TestCredential credential = BuildCredential(credentialType: EudiPid.SdJwtVct, issuer: PidIssuer);

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsTrue(
            result.Matches,
            "The credential's declared type is one of the allowed values Appendix B.3.5's vct_values lists.");
        Assert.IsNull(
            result.FailureReason,
            "A match carries no failure reason.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the respective
    /// constraints expressed within credentials MUST NOT be returned, i.e., they are treated as if
    /// they would not exist in the Wallet." A credential declaring a type Appendix B.3.5's
    /// <c>vct_values</c> does not list is such a credential, and the reason names the type it
    /// declared.
    /// </summary>
    [TestMethod]
    public void TypeConstrainedQueryDoesNotMatchACredentialDeclaringAnUnlistedType()
    {
        CredentialQuery query = PidFamilyNameQuery();
        TestCredential credential = BuildCredential(credentialType: DiplomaVct, issuer: PidIssuer);

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsFalse(
            result.Matches,
            "Section 6.4.2 forbids returning a credential whose declared type is not among the query's allowed values.");
        Assert.AreEqual(
            DcqlFailureReasons.CredentialTypeNotAccepted(DiplomaVct),
            result.FailureReason,
            "The non-match names the type the credential declared.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Appendix B.3.5</see>: "The Wallet MAY return Credentials that
    /// inherit from any of the specified types, following the inheritance logic defined in
    /// [I-D.ietf-oauth-sd-jwt-vc]." The credential's own
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18">SD-JWT VC,
    /// Section 2.2.2.2</see> claim — "aka_vcts: OPTIONAL. An array of additional types of the
    /// Verifiable Digital Credential" — carries that inheritance as far as the credential itself
    /// declares it, so a listed value found there is a match.
    /// </summary>
    [TestMethod]
    public void TypeConstrainedQueryMatchesACredentialWhoseAdditionalTypesCarryAListedValue()
    {
        CredentialQuery query = PidFamilyNameQuery();
        TestCredential credential = BuildCredential(
            credentialType: DomesticPidVct,
            issuer: PidIssuer,
            additionalTypes: new HashSet<string> { EudiPid.SdJwtVct });

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsTrue(
            result.Matches,
            "Appendix B.3.5 permits returning a credential that inherits from a listed type, and the credential's own aka_vcts declares that inheritance.");
        Assert.IsNull(
            result.FailureReason,
            "A match carries no failure reason.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.1</see>: "Every Credential returned by the Wallet
    /// SHOULD match at least one of the conditions present in the corresponding
    /// trusted_authorities array if present." Section 6.4.2's "Credentials not matching the
    /// respective constraints expressed within credentials MUST NOT be returned" decides the
    /// unshowable case: a credential carrying no issuer evidence at all matches no condition, and
    /// the reason names the absent evidence.
    /// </summary>
    [TestMethod]
    public void TrustedAuthoritiesQueryDoesNotMatchACredentialCarryingNoIssuerEvidence()
    {
        CredentialQuery query = PidFamilyNameTrustedAuthoritiesQuery(PidIssuer);
        TestCredential credential = BuildCredential(credentialType: EudiPid.SdJwtVct, issuer: null);

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsFalse(
            result.Matches,
            "A credential with no issuer evidence matches none of the conditions in the trusted_authorities array, so Section 6.4.2 forbids returning it.");
        Assert.AreEqual(
            DcqlFailureReasons.TrustedAuthorityEvidenceAbsent,
            result.FailureReason,
            "The non-match names the absent issuer evidence through DcqlFailureReasons.TrustedAuthorityEvidenceAbsent.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.1</see>: "Every Credential returned by the Wallet
    /// SHOULD match at least one of the conditions present in the corresponding
    /// trusted_authorities array if present." A credential whose issuer is one of the values the
    /// query lists matches that condition.
    /// </summary>
    [TestMethod]
    public void TrustedAuthoritiesQueryMatchesACredentialWhoseIssuerIsListed()
    {
        CredentialQuery query = PidFamilyNameTrustedAuthoritiesQuery(PidIssuer);
        TestCredential credential = BuildCredential(credentialType: EudiPid.SdJwtVct, issuer: PidIssuer);

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsTrue(
            result.Matches,
            "The credential's issuer is one of the conditions present in the trusted_authorities array.");
        Assert.IsNull(
            result.FailureReason,
            "A match carries no failure reason.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the respective
    /// constraints expressed within credentials MUST NOT be returned, i.e., they are treated as if
    /// they would not exist in the Wallet." A credential whose evidence names an Entity Identifier
    /// the query's <c>trusted_authorities</c> array does not list matches no entry, and the reason
    /// is <see cref="DcqlFailureReasons.TrustedAuthorityUnmatched"/> — evidence was present, just
    /// not for a listed value.
    /// </summary>
    [TestMethod]
    public void TrustedAuthoritiesQueryDoesNotMatchACredentialWhoseIssuerIsUnlisted()
    {
        CredentialQuery query = PidFamilyNameTrustedAuthoritiesQuery(PidIssuer);
        TestCredential credential = BuildCredential(credentialType: EudiPid.SdJwtVct, issuer: StrangerIssuer);

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsFalse(
            result.Matches,
            "The credential's issuer matches none of the conditions in the trusted_authorities array.");
        Assert.AreEqual(
            DcqlFailureReasons.TrustedAuthorityUnmatched,
            result.FailureReason,
            "The non-match names the entries as unmatched — the credential carried evidence, it simply named no listed authority.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the respective
    /// constraints expressed within credentials MUST NOT be returned, i.e., they are treated as if
    /// they would not exist in the Wallet." The Credential Query's <c>format</c> is such a
    /// constraint, and the reason names both the requested and the carried format.
    /// </summary>
    [TestMethod]
    public void FormatConstrainedQueryDoesNotMatchACredentialOfAnotherFormat()
    {
        CredentialQuery query = PidFamilyNameQuery();
        TestCredential credential = BuildCredential(
            credentialType: EudiPid.SdJwtVct,
            issuer: PidIssuer,
            format: DcqlCredentialFormats.MsoMdoc);

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsFalse(
            result.Matches,
            "A credential in another format does not match the Credential Query's format constraint.");
        Assert.AreEqual(
            DcqlFailureReasons.FormatMismatch(WellKnownMediaTypes.Jwt.DcSdJwt, DcqlCredentialFormats.MsoMdoc),
            result.FailureReason,
            "The non-match names the requested and the carried format.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.1</see>: "If the Wallet cannot deliver all claims
    /// requested by the Verifier according to these rules, it MUST NOT return the respective
    /// Credential." A credential holding no claim at a required claims path pointer — Section 6.3's
    /// "path: REQUIRED The value MUST be a non-empty array representing a claims path pointer that
    /// specifies the path to a claim within the Credential, as defined in Section 7." — cannot
    /// deliver that claim, so it does not match, and the reason names the pointer.
    /// </summary>
    [TestMethod]
    public void QueryDoesNotMatchACredentialMissingARequiredClaim()
    {
        CredentialQuery query = PidFamilyNameQuery();
        TestCredential credential = BuildCredential(
            credentialType: EudiPid.SdJwtVct,
            issuer: PidIssuer,
            claims: new Dictionary<string, object> { [EudiPid.SdJwt.GivenName] = GivenNameValue });

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsFalse(
            result.Matches,
            "The credential holds no claim at the required claims path pointer.");
        Assert.AreEqual(
            DcqlFailureReasons.MissingRequiredClaims([DcqlClaimPattern.FromKeys(EudiPid.SdJwt.FamilyName)]),
            result.FailureReason,
            "The non-match names the claims path pointer the credential did not satisfy.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.3</see>: "If the values property is present, the
    /// Wallet SHOULD return the claim only if the type and value of the claim both match exactly
    /// for at least one of the elements in the array." Section 6.4.1 adds that such a claim "should
    /// be treated the same as if it did not exist in the Credential", so a required claim whose
    /// value is none of the listed values leaves the query unsatisfied.
    /// </summary>
    [TestMethod]
    public void QueryDoesNotMatchACredentialWhoseClaimValueIsNotListed()
    {
        CredentialQuery query = PidFamilyNameValueConstraintQuery(FamilyNameValue);
        TestCredential credential = BuildCredential(
            credentialType: EudiPid.SdJwtVct,
            issuer: PidIssuer,
            claims: new Dictionary<string, object>
            {
                [EudiPid.SdJwt.GivenName] = GivenNameValue,
                [EudiPid.SdJwt.FamilyName] = UnacceptedFamilyNameValue
            });

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsFalse(
            result.Matches,
            "The claim's value matches none of the elements the query's values array lists.");
        Assert.AreEqual(
            DcqlFailureReasons.ValueConstraintsFailed([DcqlClaimPattern.FromKeys(EudiPid.SdJwt.FamilyName)]),
            result.FailureReason,
            "The non-match names the claims path pointer whose value constraint failed.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.3</see>: "the Wallet SHOULD return the claim only if
    /// the type and value of the claim both match exactly for at least one of the elements in the
    /// array." <c>9007199254740993</c> and <c>9007199254740992</c> (2^53+1 and 2^53) are distinct
    /// 64-bit integers that collide to the identical value once rounded through IEEE 754 double —
    /// an "exact" match carried through <see cref="double"/> would wrongly call them equal, so
    /// <see cref="DcqlEvaluator"/> compares non-floating numeric claim values through
    /// <see cref="decimal"/>, which represents both losslessly and tells them apart.
    /// </summary>
    [TestMethod]
    public void QueryDoesNotMatchAClaimValueThatOnlyCollidesUnderDoublePrecision()
    {
        const long CredentialValue = 9_007_199_254_740_993L;
        const long QueryAcceptedValue = 9_007_199_254_740_992L;

        CredentialQuery query = DcqlFixtures.PidFamilyNameValueConstraint(QueryAcceptedValue).Credentials![0];
        TestCredential credential = BuildCredential(
            credentialType: EudiPid.SdJwtVct,
            issuer: PidIssuer,
            claims: new Dictionary<string, object>
            {
                [EudiPid.SdJwt.GivenName] = GivenNameValue,
                [EudiPid.SdJwt.FamilyName] = CredentialValue
            });

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsFalse(
            result.Matches,
            "9007199254740993 and 9007199254740992 are distinct 64-bit integers a double-precision comparison cannot tell apart, so a decimal comparison must reject the match.");
        Assert.AreEqual(
            DcqlFailureReasons.ValueConstraintsFailed([DcqlClaimPattern.FromKeys(EudiPid.SdJwt.FamilyName)]),
            result.FailureReason,
            "The non-match names the claims path pointer whose value constraint failed.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.1</see>: "If both claims and claim_sets are
    /// present, the Verifier requests one combination of the claims listed in claim_sets. ... If
    /// the Wallet cannot satisfy any of the options, it MUST NOT return any claims." A credential
    /// that satisfies no option of a required claim set does not match.
    /// </summary>
    [TestMethod]
    public void QueryDoesNotMatchACredentialSatisfyingNoRequiredClaimSet()
    {
        CredentialQuery query = PidClaimSetQuery();
        TestCredential credential = BuildCredential(credentialType: EudiPid.SdJwtVct, issuer: PidIssuer);

        DcqlEvaluationResult result = DcqlEvaluator.EvaluateSingle(
            query, credential, ExtractMetadata(credential), ExtractClaim);

        Assert.IsFalse(
            result.Matches,
            "The credential satisfies no option of the query's required claim set.");
        Assert.AreEqual(
            DcqlFailureReasons.RequiredClaimSetNotSatisfied,
            result.FailureReason,
            "The non-match names the unsatisfied claim set.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the respective
    /// constraints expressed within credentials MUST NOT be returned, i.e., they are treated as if
    /// they would not exist in the Wallet." Two credentials both carry <c>family_name</c> and both
    /// hold the claim the query asks for; only the one whose declared type Appendix B.3.5's
    /// <c>vct_values</c> lists is returned.
    /// </summary>
    [TestMethod]
    public void TypeConstrainedQueryOverTwoCredentialsReturnsOnlyTheListedType()
    {
        TestCredential diploma = BuildCredential(credentialType: DiplomaVct, issuer: PidIssuer);
        TestCredential pid = BuildCredential(credentialType: EudiPid.SdJwtVct, issuer: PidIssuer);

        List<DcqlMatch<TestCredential>> matches = [.. DcqlEvaluator.Evaluate(
            DcqlFixtures.PidFamilyNamePrepared(),
            [diploma, pid],
            ExtractMetadata,
            ExtractClaim)];

        Assert.HasCount(
            1,
            matches,
            "Only the credential whose declared type the query lists matches; the other is treated as if it would not exist in the Wallet.");
        Assert.AreSame(
            pid,
            matches[0].Credential,
            "The returned credential is the one whose declared type the query's vct_values lists.");
        Assert.AreEqual(
            DcqlFixtures.PidCredentialId,
            matches[0].CredentialQueryId.Value,
            "The match names the Credential Query it satisfies.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 6.4.2</see>: "If the Wallet cannot deliver all
    /// non-optional Credentials requested by the Verifier according to these rules, it MUST NOT
    /// return any Credential(s)." Holding only the credential of the unlisted type, the wallet has
    /// nothing that satisfies the query's single non-optional Credential Query, so the evaluation
    /// yields no match to return.
    /// </summary>
    [TestMethod]
    public void TypeConstrainedQueryOverAnUnlistedCredentialAloneReturnsNothing()
    {
        TestCredential diploma = BuildCredential(credentialType: DiplomaVct, issuer: PidIssuer);

        List<DcqlMatch<TestCredential>> matches = [.. DcqlEvaluator.Evaluate(
            DcqlFixtures.PidFamilyNamePrepared(),
            [diploma],
            ExtractMetadata,
            ExtractClaim)];

        Assert.IsEmpty(
            matches,
            "The wallet cannot deliver the requested non-optional Credential, so it returns no Credential at all.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Appendix B.3.5</see>: "vct_values: REQUIRED. A non-empty array
    /// of strings that specifies allowed values for the type of the requested Verifiable
    /// Credential." A <c>dc+sd-jwt</c> Credential Query whose <c>meta</c> carries no
    /// <c>vct_values</c> omits a REQUIRED parameter, so the preparation that answers whether a
    /// query is expressible refuses it rather than handing the evaluator a type-unconstrained
    /// query.
    /// </summary>
    [TestMethod]
    public void SdJwtVcCredentialQueryWithoutVctValuesIsRefusedByThePreparer()
    {
        DcqlQuery query = new()
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = DcqlFixtures.PidCredentialId,
                    Format = WellKnownMediaTypes.Jwt.DcSdJwt,
                    Meta = new CredentialQueryMeta(),
                    Claims =
                    [
                        new ClaimsQuery { Path = DcqlClaimPattern.FromKeys(EudiPid.SdJwt.FamilyName) }
                    ]
                }
            ]
        };

        PreparedDcqlQuery prepared = DcqlPreparer.Prepare(query);

        Assert.IsFalse(
            prepared.IsValid,
            "Appendix B.3.5 makes vct_values REQUIRED in the meta parameter of a dc+sd-jwt Credential Query, so a query omitting it is not expressible.");
        Assert.IsNotEmpty(
            prepared.ValidationIssues,
            "The refusal names the omitted REQUIRED parameter.");
    }


    /// <summary>
    /// The canonical single-PID Credential Query asking for <c>family_name</c> and constraining the
    /// type through <c>meta.vct_values</c>, taken from the shared query fixtures.
    /// </summary>
    /// <returns>The Credential Query the type-constraint cases evaluate against.</returns>
    private static CredentialQuery PidFamilyNameQuery()
    {
        return DcqlFixtures.PidFamilyName().Credentials![0];
    }


    /// <summary>
    /// The single-PID Credential Query of <see cref="PidFamilyNameQuery"/> additionally carrying a
    /// <c>trusted_authorities</c> array naming <paramref name="trustedIssuer"/>.
    /// </summary>
    /// <param name="trustedIssuer">The issuing authority the query accepts.</param>
    /// <returns>The Credential Query the trusted-authority cases evaluate against.</returns>
    private static CredentialQuery PidFamilyNameTrustedAuthoritiesQuery(string trustedIssuer)
    {
        return DcqlFixtures.PidFamilyNameTrustedAuthorities(trustedIssuer).Credentials![0];
    }


    /// <summary>
    /// The single-PID Credential Query asking for <c>given_name</c> and <c>family_name</c> with a
    /// <c>values</c> constraint on <c>family_name</c>, taken from the shared query fixtures.
    /// </summary>
    /// <param name="acceptableFamilyName">The only <c>family_name</c> value the query accepts.</param>
    /// <returns>The Credential Query the value-constraint case evaluates against.</returns>
    private static CredentialQuery PidFamilyNameValueConstraintQuery(string acceptableFamilyName)
    {
        return DcqlFixtures.PidFamilyNameValueConstraint(acceptableFamilyName).Credentials![0];
    }


    /// <summary>
    /// A single-PID Credential Query whose one required claim set names a claim the credentials
    /// built here do not carry, so the claim set is the sole reason the credential does not match.
    /// </summary>
    /// <returns>The Credential Query the claim-set case evaluates against.</returns>
    private static CredentialQuery PidClaimSetQuery()
    {
        return new CredentialQuery
        {
            Id = DcqlFixtures.PidCredentialId,
            Format = WellKnownMediaTypes.Jwt.DcSdJwt,
            Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
            Claims =
            [
                new ClaimsQuery { Id = "family", Path = DcqlClaimPattern.FromKeys(EudiPid.SdJwt.FamilyName) },
                new ClaimsQuery { Id = "birth", Path = DcqlClaimPattern.FromKeys(EudiPid.SdJwt.Birthdate) }
            ],
            ClaimSets =
            [
                new ClaimSetQuery { Options = [["birth"]] }
            ]
        };
    }


    /// <summary>
    /// Builds one credential a wallet holds: its format, the type it declares, the additional types
    /// it declares it is also known by, the issuer it names, and the claims it carries.
    /// </summary>
    /// <param name="credentialType">The type the credential declares, or <see langword="null"/> when it declares none.</param>
    /// <param name="issuer">The issuer the credential names, or <see langword="null"/> when it carries no issuer evidence.</param>
    /// <param name="additionalTypes">The additional types the credential declares it is also known by; none by default.</param>
    /// <param name="format">The credential format; the SD-JWT VC format by default.</param>
    /// <param name="claims">The claims the credential carries; <c>family_name</c> alone by default.</param>
    /// <returns>The credential the evaluation runs over.</returns>
    private static TestCredential BuildCredential(
        string? credentialType,
        string? issuer,
        IReadOnlySet<string>? additionalTypes = null,
        string? format = null,
        Dictionary<string, object>? claims = null)
    {
        return new TestCredential
        {
            Format = format ?? WellKnownMediaTypes.Jwt.DcSdJwt,
            CredentialType = credentialType,
            AdditionalTypes = additionalTypes ?? new HashSet<string>(),
            Issuer = issuer,
            Claims = claims ?? new Dictionary<string, object> { [EudiPid.SdJwt.FamilyName] = FamilyNameValue }
        };
    }


    /// <summary>
    /// Projects a credential onto the metadata the evaluator matches a Credential Query against —
    /// the evidence the credential itself carries, never a value supplied beside it.
    /// </summary>
    /// <param name="credential">The credential to read.</param>
    /// <returns>The credential's DCQL metadata.</returns>
    private static DcqlCredentialMetadata ExtractMetadata(TestCredential credential)
    {
        return new DcqlCredentialMetadata
        {
            Format = credential.Format,
            CredentialType = credential.CredentialType,
            AdditionalTypes = credential.AdditionalTypes,
            //The test credential's issuer stands in for a validated OpenID Federation trust path
            //ending in that Entity Identifier — this suite unit-tests DcqlEvaluator's own
            //trusted_authorities dispatch, not federation trust-path resolution.
            TrustedAuthorityEvidence = credential.Issuer is { } issuer
                ? new TrustedAuthorityEvidence { FederationTrustPathEntities = new HashSet<EntityIdentifier> { new(issuer) } }
                : null
        };
    }


    /// <summary>
    /// Resolves a claims path pointer over a credential's claims, walking one key segment per
    /// pointer element.
    /// </summary>
    /// <param name="credential">The credential to read.</param>
    /// <param name="pattern">The claims path pointer to resolve.</param>
    /// <param name="value">The value at the pointer, when the credential holds one.</param>
    /// <returns><see langword="true"/> when the credential holds a claim at the pointer; otherwise, <see langword="false"/>.</returns>
    private static bool ExtractClaim(TestCredential credential, DcqlClaimPattern pattern, out object? value)
    {
        object? current = credential.Claims;
        for(int i = 0; i < pattern.Count; i++)
        {
            PatternSegment segment = pattern[i];
            if(current is not IDictionary<string, object> claims || !segment.IsKey)
            {
                value = null;

                return false;
            }

            if(!claims.TryGetValue(segment.KeyValue!, out current))
            {
                value = null;

                return false;
            }
        }

        value = current;

        return true;
    }


    /// <summary>
    /// One credential a wallet holds, carrying exactly the evidence a DCQL evaluation reads: the
    /// format, the declared type and additional types, the issuer and the claims.
    /// </summary>
    private sealed record TestCredential
    {
        /// <summary>The credential format the Credential Query's <c>format</c> is matched against.</summary>
        public required string Format { get; init; }

        /// <summary>The type the credential declares, or <see langword="null"/> when it declares none.</summary>
        public string? CredentialType { get; init; }

        /// <summary>The additional types the credential declares it is also known by.</summary>
        public required IReadOnlySet<string> AdditionalTypes { get; init; }

        /// <summary>The issuer the credential names, or <see langword="null"/> when it carries none.</summary>
        public string? Issuer { get; init; }

        /// <summary>The claims the credential carries, addressed by claims path pointers.</summary>
        public required Dictionary<string, object> Claims { get; init; }
    }
}

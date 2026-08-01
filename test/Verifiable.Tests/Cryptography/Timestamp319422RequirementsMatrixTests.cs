using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The requirements matrix for the time-stamping profile the preservation wave's owner flag OVR-9.2-02 points
/// at: every normative statement of
/// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf">
/// ETSI EN 319 422 V1.1.1</see> (the time-stamping protocol and time-stamp token profile), together with the
/// statements of IETF RFC 3161 clauses 2.4.1/2.4.2/2.2 that EN 319 422 clauses 4.1.1/4.2.1 pull into the
/// client's obligations whole and the
/// <see href="https://www.rfc-editor.org/rfc/rfc5816.txt">IETF RFC 5816</see> <c>ESSCertIDv2</c> update EN 319
/// 422 clause 1 puts in scope. Mirrors the rows-as-spec-cells shape of <c>CAdESRequirementsMatrixTests</c>
/// (ETSI EN 319 122-1), <c>AsicRequirementsMatrixTests</c> (ETSI EN 319 162-1/-2) and
/// <c>PreservationRequirementsMatrixTests</c> (ETSI TS 119 511/512).
/// </summary>
/// <remarks>
/// <para>
/// Every distinct normative statement of EN 319 422 is one <see cref="RequirementMatrixRow"/>, and every
/// client-binding statement of the RFC 3161/RFC 5816 deltas the profile incorporates is one more.
/// <see cref="RequirementMatrixTest"/> fails a row that has no coverage disposition — no silent gaps — and, for
/// the dispositions that name a test, resolves the cited evidence through reflection over the compiled test
/// assembly: a row citing a class or method that does not exist, or that is not itself a <c>[TestMethod]</c>,
/// fails. A renamed or deleted evidence method is therefore caught here rather than rotting into a stale
/// citation.
/// </para>
/// <para>
/// <strong>Only the rows that bind a time-stamping <em>client</em> are in this library's reach.</strong> This
/// repository ships no Time-Stamping Authority (TSA) and no Time-Stamping Unit (TSU) certificate issuer: the
/// only TSA in the tree is the independent test-side responder that plays one for the wire flows. Every clause
/// that binds the server (EN 319 422 clause 5) or the TSU certificate issuer (clause 6), and every definitional
/// annex statement carrying no RFC 2119 verb, is therefore recorded
/// <see cref="RequirementCoverageStatus.OutOfScope"/> with the reason stated in the row — enumerated in full so
/// the profile is complete and so the test-side responder can be judged against it, but not claimed as
/// implemented.
/// </para>
/// <para>
/// <strong>Two client rows deviate and say so.</strong> The token-signature-algorithm and key-length rows
/// (clauses 4.2.3/4.2.4, and RFC 3161 §2.4.2 through them) are <see cref="RequirementCoverageStatus.KnownDefect"/>:
/// the default managed CMS backend verifies RSA time-stamp signatures only as PKCS#1 v1.5 with SHA-256 over
/// 2048- or 4096-bit moduli — proven and unit-tested — but ETSI TS 119 312 V1.4.3 clause A.9 Table A.8 makes
/// RSA-with-SHA-512 a <em>shall support</em> for token requesters and Tables 9-10 recommend ≥3 000-bit moduli
/// after 2025, so a SHA-512-signing or 3072-bit TSU is refused. Widening the backend is the recorded work of
/// task #11 (managed-RSA widening), and the rows cite it. The transport rows (clause 7) are
/// <see cref="RequirementCoverageStatus.OutOfScope"/> by the owner's decision: the library ships the fetch seam
/// and deliberately delegates the HTTP/HTTPS binding and scheme policy to the host, which the delegate's own
/// documentation states.
/// </para>
/// <para>
/// <strong>The post-stage-2 client checks are cited at their rows.</strong> The requested-policy binding
/// (RFC 3161 §2.4.2, EN 319 422 clause 4.1.2 — the <c>PolicyMismatch</c> refusal), the <c>eContentType</c>
/// <c>id-ct-TSTInfo</c> comparison (RFC 3161 §2.4.2), and the <c>PKIFailureInfo</c> interpretation on a granted
/// response (RFC 3161 §2.4.2) each carry the regression test the tier-fix stage landed. The one client duty the
/// stage recorded as a bounded follow-up — reaching the <c>ESSCertID</c>/<c>ESSCertIDv2</c> certificate-identifier
/// binding at acquisition time (RFC 3161 §2.2 as amended by RFC 5816 §2.2.2) — is a
/// <see cref="RequirementCoverageStatus.KnownDefect"/> row: the binding is implemented and unit-tested by the
/// <c>SigningCertificateIdentification</c> building block on the EN 319 102-1 validation path, but the shipped
/// acquisition path does not yet reach it.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Timestamp319422RequirementsMatrixTests
{
    /// <summary>Whether a requirement row is driven by a concrete client-side test, is implemented and unit-tested at the building-block level but unreachable through the shipped composition (or supported only in part) because of an already-flagged defect, or is out of a class library's reach because it binds a server or certificate issuer this repository does not ship.</summary>
    internal enum RequirementCoverageStatus
    {
        /// <summary>No disposition has been recorded. The value of an unset field, by design: a row must never silently pass as covered.</summary>
        Untested = 0,

        /// <summary>The requirement is driven by at least one concrete, named test that calls the shipped client surface.</summary>
        Tested = 1,

        /// <summary>The requirement binds a component this library does not ship — a Time-Stamping Authority or a TSU certificate issuer — or is a definitional statement with no RFC 2119 verb, or is a client obligation the owner deliberately delegated to the host. The evidence states which.</summary>
        OutOfScope = 2,

        /// <summary>The requirement's own building block implements and unit-tests it (or the shipped backend implements part of it), but the shipped default composition cannot reach it, or cannot reach all of it, because of an already-flagged, unfixed defect. The evidence names the test proving the implemented part and the follow-up that closes the gap.</summary>
        KnownDefect = 3
    }


    /// <summary>One row of the matrix: a clause identifier, a short digest of the requirement it names, its coverage disposition, and the evidence for that disposition.</summary>
    /// <param name="ClauseId">The clause and, where applicable, field/statement identifier the requirement comes from; the RFC-delta rows carry an <c>R</c>-prefixed identifier naming their RFC 3161/RFC 5816 clause.</param>
    /// <param name="Requirement">A short digest of the normative statement, carrying its RFC 2119 verb, close enough to the specification's own wording to be checked against it.</param>
    /// <param name="Status">The coverage disposition.</param>
    /// <param name="Evidence">For <see cref="RequirementCoverageStatus.Tested"/> and <see cref="RequirementCoverageStatus.KnownDefect"/>, the asserting test's <c>ClassName.MethodName</c> (optionally followed by explanatory prose in parentheses) — the leading token is resolved through reflection. For <see cref="RequirementCoverageStatus.OutOfScope"/>, the stated reason.</param>
    internal sealed record RequirementMatrixRow(string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence);


    /// <summary>The follow-up task the two managed-RSA-narrowness rows name as the work that widens the backend.</summary>
    private const string ManagedRsaWideningTask = "task #11";

    /// <summary>The cryptographic-suites specification the token-signature-algorithm and key-length rows judge against.</summary>
    private const string CryptographicSuitesSpecification = "TS 119 312";


    /// <summary>The requirements matrix, one row per <c>object[]</c>.</summary>
    /// <returns>Every row.</returns>
    public static IEnumerable<object[]> Requirements()
    {
        foreach((string clauseId, string requirement, RequirementCoverageStatus status, string evidence) in RowData)
        {
            yield return [new RequirementMatrixRow(clauseId, requirement, status, evidence)];
        }
    }


    /// <summary>
    /// No row of the matrix may be left without a coverage disposition, and a row whose disposition names a
    /// test must resolve that name to a real, existing <c>[TestMethod]</c> in the compiled test assembly.
    /// </summary>
    /// <param name="row">The row under test.</param>
    [TestMethod]
    [DynamicData(nameof(Requirements))]
    public void RequirementMatrixTest(RequirementMatrixRow row)
    {
        Assert.AreNotEqual(RequirementCoverageStatus.Untested, row.Status, $"{row.ClauseId}: '{row.Requirement}' has no coverage disposition.");
        Assert.IsFalse(string.IsNullOrWhiteSpace(row.Evidence), $"{row.ClauseId}: '{row.Requirement}' needs a named test or a stated reason.");

        if(row.Status is RequirementCoverageStatus.Tested or RequirementCoverageStatus.KnownDefect)
        {
            AssertEvidenceNamesAShippedTestMethod(row);
        }
    }


    /// <summary>
    /// Every requirement identifier of the matrix is stated once. A duplicated identifier would let one row
    /// silently replace another's disposition in a reader's eye while both still pass.
    /// </summary>
    [TestMethod]
    public void EveryClauseIdentifierIsStatedOnce()
    {
        List<string> duplicated = [.. RowData
            .GroupBy(row => row.ClauseId, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)];

        Assert.IsEmpty(duplicated, $"These requirement identifiers appear more than once: {string.Join(", ", duplicated)}.");
    }


    /// <summary>
    /// The matrix carries the whole profile: the forty-five EN 319 422 statements and the twenty-two RFC 3161 /
    /// RFC 5816 delta statements the profile's clauses 4.1.1/4.2.1/1 incorporate. A matrix that quietly lost a
    /// row would drop a normative obligation without any test noticing.
    /// </summary>
    [TestMethod]
    public void TheMatrixEnumeratesTheWholeProfile()
    {
        List<RequirementMatrixRow> deltaRows = [.. RowData
            .Where(row => IsRfcDeltaRow(row.ClauseId))
            .Select(row => new RequirementMatrixRow(row.ClauseId, row.Requirement, row.Status, row.Evidence))];
        List<RequirementMatrixRow> profileRows = [.. RowData
            .Where(row => !IsRfcDeltaRow(row.ClauseId))
            .Select(row => new RequirementMatrixRow(row.ClauseId, row.Requirement, row.Status, row.Evidence))];

        Assert.HasCount(45, profileRows, "EN 319 422 V1.1.1 states forty-five normative rows across clauses 4-9 and its annexes.");
        Assert.HasCount(22, deltaRows, "The RFC 3161 §2.4/§2.2 and RFC 5816 client-binding deltas incorporated by clauses 4.1.1/4.2.1/1 are twenty-two rows.");
    }


    /// <summary>
    /// The two managed-RSA-narrowness rows are <see cref="RequirementCoverageStatus.KnownDefect"/> and cite both
    /// the follow-up task that widens the backend and the cryptographic-suites specification whose recommendation
    /// the current backend cannot yet meet — so the deviation is recorded where the requirement is, not hidden.
    /// </summary>
    [TestMethod]
    public void TheManagedRsaNarrownessRowsAreKnownDefectsNamingTheFollowUpTaskAndTheSuitesSpecification()
    {
        foreach(string clauseId in ManagedRsaNarrownessRowIdentifiers)
        {
            RequirementMatrixRow row = RowFor(clauseId);
            Assert.AreEqual(RequirementCoverageStatus.KnownDefect, row.Status, $"{clauseId} is the managed-RSA narrowness, an implemented-in-part defect.");
            Assert.Contains(ManagedRsaWideningTask, row.Evidence, StringComparison.Ordinal);
            Assert.Contains(CryptographicSuitesSpecification, row.Evidence, StringComparison.Ordinal);
        }
    }


    /// <summary>
    /// The transport rows record the owner's decision that the HTTP/HTTPS binding is a documented host
    /// obligation: both are <see cref="RequirementCoverageStatus.OutOfScope"/> and their evidence names the host
    /// as the party the library delegates the binding to.
    /// </summary>
    [TestMethod]
    public void TheTransportRowsRecordTheHostObligationDecision()
    {
        foreach(string clauseId in TransportRowIdentifiers)
        {
            RequirementMatrixRow row = RowFor(clauseId);
            Assert.AreEqual(RequirementCoverageStatus.OutOfScope, row.Status, $"{clauseId} is the transport binding the owner delegated to the host.");
            Assert.Contains("host", row.Evidence, StringComparison.OrdinalIgnoreCase);
        }
    }


    /// <summary>
    /// The <c>ESSCertID</c>/<c>ESSCertIDv2</c> certificate-identifier binding is recorded as the one client duty
    /// deferred by the tier-fix stage: a <see cref="RequirementCoverageStatus.KnownDefect"/> row whose evidence
    /// names the building-block test that proves the binding is implemented, and states the acquisition path does
    /// not yet reach it.
    /// </summary>
    [TestMethod]
    public void TheCertificateIdentifierBindingRowIsADeferredKnownDefect()
    {
        RequirementMatrixRow row = RowFor("R17");
        Assert.AreEqual(RequirementCoverageStatus.KnownDefect, row.Status);
        Assert.Contains("acquisition", row.Evidence, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// Every clause-5 (server) and clause-6 (TSU certificate) row is <see cref="RequirementCoverageStatus.OutOfScope"/>,
    /// because this repository ships neither a Time-Stamping Authority nor a TSU certificate issuer, and each such
    /// row states that this is why.
    /// </summary>
    [TestMethod]
    public void EveryServerAndCertificateIssuerRowIsOutOfScopeForALibrary()
    {
        List<RequirementMatrixRow> issuerRows = [.. RowData
            .Where(row => row.ClauseId.StartsWith("5.", StringComparison.Ordinal) || row.ClauseId.StartsWith("6.", StringComparison.Ordinal))
            .Select(row => new RequirementMatrixRow(row.ClauseId, row.Requirement, row.Status, row.Evidence))];

        Assert.IsNotEmpty(issuerRows);
        foreach(RequirementMatrixRow row in issuerRows)
        {
            Assert.AreEqual(RequirementCoverageStatus.OutOfScope, row.Status, $"{row.ClauseId} binds a server or certificate issuer this library does not ship.");
        }
    }


    /// <summary>
    /// Resolves the <c>ClassName.MethodName</c> token a row's evidence leads with against the compiled test
    /// assembly and asserts that it names a real <c>[TestMethod]</c>.
    /// </summary>
    /// <param name="row">The row whose evidence is being resolved.</param>
    private static void AssertEvidenceNamesAShippedTestMethod(RequirementMatrixRow row)
    {
        string token = row.Evidence.Split([' ', '('], 2, StringSplitOptions.RemoveEmptyEntries)[0];
        int separatorIndex = token.LastIndexOf('.');
        Assert.IsGreaterThan(0, separatorIndex, $"{row.ClauseId}: evidence '{row.Evidence}' must lead with a Class.Method pair.");

        string className = token[..separatorIndex];
        string methodName = token[(separatorIndex + 1)..];
        Type? evidenceType = typeof(Timestamp319422RequirementsMatrixTests).Assembly.GetTypes()
            .FirstOrDefault(candidate => string.Equals(candidate.Name, className, StringComparison.Ordinal));
        Assert.IsNotNull(evidenceType, $"{row.ClauseId}: evidence class '{className}' does not exist in the test assembly.");

        MethodInfo? evidenceMethod = evidenceType!.GetMethod(
            methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
        Assert.IsNotNull(evidenceMethod, $"{row.ClauseId}: evidence method '{className}.{methodName}' does not exist.");
        Assert.IsNotEmpty(evidenceMethod!.GetCustomAttributes(typeof(TestMethodAttribute), inherit: false),
            $"{row.ClauseId}: evidence '{className}.{methodName}' is not a [TestMethod] — the matrix must cite a real test.");
    }


    /// <summary>Finds the one row carrying a requirement identifier, failing when the matrix does not state it.</summary>
    /// <param name="clauseId">The requirement identifier to find.</param>
    /// <returns>The row.</returns>
    private static RequirementMatrixRow RowFor(string clauseId)
    {
        (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence) found =
            RowData.SingleOrDefault(row => string.Equals(row.ClauseId, clauseId, StringComparison.Ordinal));

        Assert.IsNotNull(found.ClauseId, $"The matrix states no row {clauseId}.");
        return new RequirementMatrixRow(found.ClauseId, found.Requirement, found.Status, found.Evidence);
    }


    /// <summary>Determines whether a requirement identifier names one of the incorporated RFC 3161/RFC 5816 delta statements rather than an EN 319 422 clause.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when it opens with the delta prefix.</returns>
    private static bool IsRfcDeltaRow(string clauseId) =>
        clauseId.StartsWith('R') && clauseId.Length > 1 && char.IsDigit(clauseId[1]);


    /// <summary>The two rows recording the managed-RSA narrowness deviation.</summary>
    private static string[] ManagedRsaNarrownessRowIdentifiers { get; } = ["4.2.3-sigalg", "4.2.4-keylength"];

    /// <summary>The two rows recording the transport host-obligation decision.</summary>
    private static string[] TransportRowIdentifiers { get; } = ["7-transport", "7-https"];


    /// <summary>The requirements matrix rows, in the profile's clause order followed by the incorporated RFC deltas.</summary>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] RowData { get; } =
    [
        //---- EN 319 422 clause 4 — requirements for a time-stamping client (in scope) ----
        ("4.1.1", "A time-stamping client shall support the RFC 3161 clause 2.4.1 request with the profile's amendments.",
            RequirementCoverageStatus.Tested, "TimestampRequestsTests.BuildsAWellFormedRequestTheIndependentReaderDecodesFieldByField (version, messageImprint, reqPolicy, nonce and certReq decoded field by field by an independent reader)"),
        ("4.1.2-reqpolicy", "The use of reqPolicy in the request should be supported.",
            RequirementCoverageStatus.Tested, "TimestampRequestsTests.WritesTheSuppliedReqPolicyBetweenMessageImprintAndNonce"),
        ("4.1.2-nonce", "The use of nonce in the request should be supported.",
            RequirementCoverageStatus.Tested, "TimestampRequestsTests.OmittingTheNonceOmitsTheNonceFieldEntirely (the nonce is on by default and suppressible)"),
        ("4.1.2-certreq", "The use of certReq in the request should be supported.",
            RequirementCoverageStatus.Tested, "TimestampRequestsTests.BuildsAWellFormedRequestTheIndependentReaderDecodesFieldByField (certReq is written TRUE and decoded)"),
        ("4.1.3-hash", "Hash algorithms should be as TS 119 312 clause A.9 Table A.8: a token requester shall support SHA-256.",
            RequirementCoverageStatus.Tested, "TimestampRequestsTests.BuildsARequestUnderASha384MessageImprint (SHA-2 family resolved; SHA-1 unresolvable by construction)"),
        ("4.1.3-duration", "The hash choice should take the expected duration into account (TS 119 312 clause 9.2).",
            RequirementCoverageStatus.Tested, "TimestampRequestsTests.BuildsARequestUnderASha384MessageImprint (the algorithm is a per-call parameter, so duration-driven selection is expressible)"),
        ("4.2.1", "A time-stamping client shall support the RFC 3161 clause 2.4.2 response with the profile's amendments.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReadsEveryFieldOfAMintedTimestampTokenInfo"),
        ("4.2.2-accuracy", "The accuracy field shall be supported.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReadsEveryFieldOfAMintedTimestampTokenInfo (the seconds/millis/micros interval surfaces)"),
        ("4.2.2-nonce", "The nonce field should be supported.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsANonceMismatchWhenTheTokenDoesNotEchoTheRequestsNonce"),
        ("4.2.2-ordering", "A TSU need not support ordering, hence clients should not depend on the ordering of time-stamps.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReadsEveryFieldOfAMintedTimestampTokenInfo (the accuracy and ordering flag the RFC 3161 posterior rule consumes surface from the token, so ordering is derived from accuracy rather than assumed)"),
        ("4.2.2-nonce-echo", "If a nonce is present in the request, it shall be present in the response with the same value.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsANonceMismatchWhenTheTokenDoesNotEchoTheRequestsNonce"),
        ("4.2.3-sigalg", "Token signature algorithms to be supported should be as TS 119 312 clause A.9 Table A.8: a token requester shall support RSA with SHA-256 or SHA-512.",
            RequirementCoverageStatus.KnownDefect, "CmsBackendEquivalenceTests.AllThreeBackendsVerifyAnRsaSignedDataEquivalently (the RSA PKCS#1 v1.5 with SHA-256 arm is proven and unit-tested; the RSA-with-SHA-512 arm that TS 119 312 V1.4.3 A.9 Table A.8 also mandates is not accepted by the default managed backend — the recorded managed-RSA widening of task #11)"),
        ("4.2.4-keylength", "Key lengths should be supported as TS 119 312 Tables 9 and 10: sha256-with-rsa at at least 3 000 bits after 2025.",
            RequirementCoverageStatus.KnownDefect, "CmsBackendEquivalenceTests.AllThreeBackendsVerifyAnRsaSignedDataEquivalently (2048- and 4096-bit RSA moduli are proven; a 3072-bit modulus — the natural post-2025 choice under TS 119 312 V1.4.3 Table 10 — is refused by the default managed backend, closed by the managed-RSA widening of task #11)"),

        //---- EN 319 422 clause 7 — transport (binds the client, delegated to the host by owner decision) ----
        ("7-transport", "Client and server shall support the protocol via HTTP or HTTPS as in RFC 3161 clause 3.4.",
            RequirementCoverageStatus.OutOfScope, "Owner decision: the library ships the fetch-response delegate seam and no HTTP/HTTPS binding; the transport and its content types are a documented obligation of the host that supplies the delegate. The wire flows exercise a real socket through the host-supplied transport, but the binding itself is not library code."),
        ("7-https", "HTTPS should be used instead of HTTP.",
            RequirementCoverageStatus.OutOfScope, "Owner decision: the delegate's own documentation assigns URI parsing and scheme policy to the host, so preferring HTTPS is a host obligation this library deliberately does not pre-empt."),

        //---- EN 319 422 clause 9 and the annexes ----
        ("9.1-qcstatements", "A token claimed qualified should carry one qcStatements extension in the token extension field (RFC 3739 clause 3.2.6 syntax).",
            RequirementCoverageStatus.OutOfScope, "Issuer obligation: the client ships no TSA. The authoritative EU-qualified determination this library does ship runs through the TS 119 615 trusted list, not the token extension."),
        ("9.1-qtststatement", "If present, qcStatements shall contain one esi4-qtstStatement-1.",
            RequirementCoverageStatus.OutOfScope, "Issuer obligation: no TSA is shipped, and the qualified determination runs through the TS 119 615 trusted list. The esi4-qtstStatement-1 identifier is a complementary signal, not the primary route."),
        ("9.1-noncritical", "qcStatements shall not be marked critical.",
            RequirementCoverageStatus.OutOfScope, "Issuer obligation: no TSA is shipped, so the client never writes the extension."),
        ("A-policy", "When the TSA conforms to EN 319 421, the TSTInfo.policy field shall include the EN 319 421 clause 5.2 identifier or the TSA's own (Annex A).",
            RequirementCoverageStatus.OutOfScope, "Issuer obligation: no TSA is shipped. The client surfaces the policy value verbatim and binds it to the request's reqPolicy (row R11); an application-level acceptability check is expressible but the issuer's own duty is not a library concern."),
        ("B-asn1", "The ASN.1 declarations of id-etsi-tsts / id-etsi-tsts-EuQCompliance (Annex B).",
            RequirementCoverageStatus.OutOfScope, "Definitional, no RFC 2119 verb; and issuer-side, since only a TSA emits the qualified statement this library ships no TSA for."),
        ("C-mediatype", "The media type application/vnd.etsi.timestamp-token and the file extension .tst (Annex C).",
            RequirementCoverageStatus.OutOfScope, "Definitional, no RFC 2119 verb. The .tst extension is a shipped get-only constant used across the container surfaces; the media type is a transport-layer label whose binding is the host obligation of the clause-7 rows."),

        //---- EN 319 422 clause 5 — the time-stamping server (N/A-side: no TSA is shipped) ----
        ("5.1.1", "The server shall support the RFC 3161 clause 2.4.1 request.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: this repository ships no TSA. The test-side responder that plays one is judged against this in the responder-fidelity notes, not claimed as a shipped capability."),
        ("5.1.2-reqpolicy", "The server shall support reqPolicy.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped. The test-side responder honours the requested policy so the client's policy binding can be proven, but that is test infrastructure, not a shipped server."),
        ("5.1.2-nonce", "The server shall support nonce.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped. The test-side responder echoes the nonce into the signed TSTInfo so the client's echo check can be proven."),
        ("5.1.2-certreq", "The server shall support certReq.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped. The client always sends certReq TRUE, so the certReq FALSE branch is not modelled by the test-side responder."),
        ("5.1.3-hash", "The server's hash algorithms should be as TS 119 312.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped. The test-side responder mints under the SHA-2 algorithm the request names."),
        ("5.2.1", "The server shall support the RFC 3161 clause 2.4.2 response.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped."),
        ("5.2.2-rfc3161", "RFC 3161 clause 2.4.2's own requirements shall apply to the response.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped. The client-side counterparts of these requirements are the R-prefixed delta rows below."),
        ("5.2.2-policy", "policy shall be present and shall conform to Annex A.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped. The test-side responder states its fixture policy or the one the request asked for."),
        ("5.2.2-gentime", "genTime shall have precision sufficient for the declared accuracy.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped."),
        ("5.2.2-accuracy", "accuracy shall be present; a minimum accuracy of one second shall be supported.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped. The mint oracle supports accuracy, but the wire responder does not set it, so no minted-on-the-wire token carries accuracy — a recorded test-fidelity gap, not a shipped-server claim."),
        ("5.2.2-ordering", "ordering shall not be present or shall be false.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped. The test-side responder omits ordering."),
        ("5.2.2-noncritical", "No extension shall be marked critical.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped. The test-side responder writes no extensions."),
        ("5.2.2-esscertid", "ESSCertID (RFC 3161) or ESSCertIDv2 (RFC 5816) shall be a signerInfo attribute inside SigningCertificate/SigningCertificateV2.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped. The test-side responder emits ESSCertIDv2 under SHA-256 per RFC 5816 clause 2.2.1; the client-side counterpart is row R17."),
        ("5.2.3-algs", "The server's hash and signature algorithms should be as TS 119 312.",
            RequirementCoverageStatus.OutOfScope, "Server obligation: no TSA is shipped."),

        //---- EN 319 422 clause 6 — the TSU certificate (N/A-side: no certificate issuer is shipped) ----
        ("6.1", "The TSU certificate shall meet EN 319 412-2 (natural person) or EN 319 412-3 (legal person).",
            RequirementCoverageStatus.OutOfScope, "Certificate-issuer obligation: this repository ships no TSU certificate issuer."),
        ("6.2-country", "countryName shall specify the country the TSA is established in.",
            RequirementCoverageStatus.OutOfScope, "Certificate-issuer obligation: no TSU certificate issuer is shipped."),
        ("6.2-org", "organizationName shall contain the full registered name of the TSA.",
            RequirementCoverageStatus.OutOfScope, "Certificate-issuer obligation: no TSU certificate issuer is shipped."),
        ("6.2-orgname", "That organizationName should be an officially registered name.",
            RequirementCoverageStatus.OutOfScope, "Certificate-issuer obligation: no TSU certificate issuer is shipped."),
        ("6.2-serialnumber", "For a natural-person TSA, one serialNumber attribute should be in the subject.",
            RequirementCoverageStatus.OutOfScope, "Certificate-issuer obligation: no TSU certificate issuer is shipped."),
        ("6.3-keylength", "The TSU key length should be as TS 119 312 (Tables 9-10 today).",
            RequirementCoverageStatus.OutOfScope, "Certificate-issuer obligation: no TSU certificate issuer is shipped. The relying-party consequence — the default backend cannot verify a token from a TSU following the post-2025 recommendation — is the client-side defect of rows 4.2.3-sigalg / 4.2.4-keylength."),
        ("6.4-eku", "The TSU certificate extended key usage shall be id-kp-timeStamping, the only EKU, marked critical (RFC 3161 clause 2.3).",
            RequirementCoverageStatus.OutOfScope, "Certificate-issuer obligation: no TSU certificate issuer is shipped. Checking the EKU on a relying party is EN 319 102-1 clause 5.4 territory, out of EN 319 422 scope per its clause 1."),
        ("6.4-pkup", "The private key usage period extension should be used.",
            RequirementCoverageStatus.OutOfScope, "Certificate-issuer obligation: no TSU certificate issuer is shipped."),
        ("6.5-algs", "The TSU public key and certificate signature should use TS 119 312 algorithms.",
            RequirementCoverageStatus.OutOfScope, "Certificate-issuer obligation: no TSU certificate issuer is shipped."),

        //---- EN 319 422 clause 8 — object identifiers ----
        ("8-oids", "Object identifiers are specified in TS 119 312 clause 11.",
            RequirementCoverageStatus.OutOfScope, "Definitional, no RFC 2119 verb: a pointer to the identifier registry, not an obligation on a client."),

        //---- RFC 3161 §2.4.1 / §2.4.2 / §2.2 and RFC 5816, incorporated into the client's shall by clauses 4.1.1 / 4.2.1 / 1 ----
        ("R1", "RFC 3161 §2.4.1: the messageImprint length MUST match the hash algorithm's output length.",
            RequirementCoverageStatus.Tested, "TimestampRequestsTests.RejectsAMessageImprintDigestOfTheWrongLength (enforced on the way out; the reader enforces it on the way in)"),
        ("R2", "RFC 3161 §2.4.1: the hash algorithm SHOULD be a known one-way collision-resistant function.",
            RequirementCoverageStatus.Tested, "TimestampRequestsTests.BuildsARequestUnderASha384MessageImprint (SHA-2 only; SHA-1 unresolvable by construction)"),
        ("R3", "RFC 3161 §2.4.1: if a requester uses an extension the server does not recognize, the server SHALL not issue a token.",
            RequirementCoverageStatus.Tested, "TimestampRequestsTests.BuildsAWellFormedRequestTheIndependentReaderDecodesFieldByField (the writer emits no extensions at all, the maximally interoperable choice)"),
        ("R4", "RFC 3161 §2.4.1 as amended by RFC 5816 §2.1: with certReq true, the TSA MUST return the certificate referenced by ESSCertID/ESSCertIDv2 in SignedData.certificates.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.VerifiesAGrantedResponseCarryingAMatchingToken (the default backend verifies only a token embedding its signer certificate, so the obligation is enforced end to end for the shipped composition)"),
        ("R5", "RFC 3161 §2.4.2: status 0 or 1 implies a TimeStampToken MUST be present; any other status implies it MUST NOT be.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsAGrantedResponseCarryingNoToken"),
        ("R6", "RFC 3161 §2.4.2: compliant clients MUST generate an error if PKIStatus values they do not understand are present.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsAResponseThatWasNotGranted (any status outside {0,1} throws carrying the value)"),
        ("R7", "RFC 3161 §2.4.2: compliant clients MUST generate an error if PKIFailureInfo values they do not understand are present.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsAGrantedResponseCarryingAFailInfoWithSetBits (a granted response carrying any set failInfo bit is refused)"),
        ("R8", "RFC 3161 §2.4.2: eContentType is id-ct-TSTInfo and eContent SHALL be the DER TSTInfo.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsATokenWhoseEContentTypeIsNotTstInfo (the eContentType is compared to id-ct-TSTInfo before the content is read as a TSTInfo)"),
        ("R9", "RFC 3161 §2.4.2: conforming requesters MUST recognize version 1 tokens with all the optional fields present.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReadsEveryFieldOfAMintedTimestampTokenInfo (accuracy, ordering, nonce, tsa and extensions walked in ASN.1 order)"),
        ("R10", "RFC 3161 §2.4.2: TSTInfo.messageImprint MUST equal the request's.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsAMessageImprintMismatch (algorithm OID and digest bytes compared)"),
        ("R11", "RFC 3161 §2.4.2: TSTInfo.policy MUST equal the request's reqPolicy when one was present, otherwise unacceptedPolicy MUST be returned.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.AcquireAsyncRefusesATokenWhosePolicyDiffersFromTheRequestedPolicy (the client fails closed on a policy the request did not ask for)"),
        ("R12", "RFC 3161 §2.4.2: TSTInfo.nonce MUST be present and equal when the request carried one.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsANonceMismatchWhenTheTokenDoesNotEchoTheRequestsNonce"),
        ("R13", "RFC 3161 §2.4.2: Accuracy components absent implies zero; the ordering rules follow from accuracy and ordering.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReadsEveryFieldOfAMintedTimestampTokenInfo (missing components contribute nothing to the interval)"),
        ("R14", "RFC 3161 §2.4.2 / RFC 5816 §2.2.2: the tsa field, if present, MUST correspond to a subject name of the verifying certificate; identification happens through ESSCertID/ESSCertIDv2.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReadsEveryFieldOfAMintedTimestampTokenInfo (the tsa field is decoded as a hint only; identification is not driven from it)"),
        ("R15", "RFC 3161 §2.2: the requesting entity SHALL verify the status, the token fields, and the validity of the token's digital signature.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsATokenWhoseCmsSignatureDoesNotVerify"),
        ("R16", "RFC 3161 §2.2: it SHALL verify that what was time-stamped is what was requested.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsAMessageImprintMismatch"),
        ("R17", "RFC 3161 §2.2 as amended by RFC 5816 §2.2.2: the requester SHALL verify that the token contains the correct certificate identifier of the TSA.",
            RequirementCoverageStatus.KnownDefect, "SignatureValidationBuildingBlockTests.IdentifiesTheSigningCertificateFromTheEssReference (the SigningCertificate/SigningCertificateV2 hash binding is implemented and unit-tested by the identification building block on the EN 319 102-1 validation path; the shipped acquisition path does not yet reach it — a recorded bounded follow-up of the tier-fix stage)"),
        ("R18", "RFC 3161 §2.2: the requester SHALL verify timeliness via a local trusted time reference or the nonce.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.RejectsANonceMismatchWhenTheTokenDoesNotEchoTheRequestsNonce (the nonce branch is on by default)"),
        ("R19", "RFC 3161 §2.2: the TSA certificate's revocation status SHOULD then be checked.",
            RequirementCoverageStatus.OutOfScope, "Not an acquisition-time concern in this architecture: revocation is an EN 319 102-1 clause 5 building block (OCSP/CRL) on the validation path, out of EN 319 422 scope per its clause 1."),
        ("R20", "RFC 3161 §2.2: the client application SHOULD then check the policy field for acceptability.",
            RequirementCoverageStatus.Tested, "TimestampAcquisitionTests.AcquireAsyncAcceptsATokenWhosePolicyMatchesTheRequestedPolicy (the acquisition binds the token's policy to the request's reqPolicy)"),
        ("R21", "RFC 3161 §2.4.2: serialNumber — users MUST be ready to accommodate integers up to 160 bits.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReadsEveryFieldOfAMintedTimestampTokenInfo (the serial number is read as raw INTEGER content octets with no numeric width assumption)"),
        ("R22", "RFC 3161 §2.4.2: genTime is a GeneralizedTime that MUST include seconds and MUST terminate with Z; fractional seconds allowed.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReadsEveryFieldOfAMintedTimestampTokenInfo (read under AsnEncodingRules.DER, which enforces the X.690 restrictions the clause restates)")
    ];
}

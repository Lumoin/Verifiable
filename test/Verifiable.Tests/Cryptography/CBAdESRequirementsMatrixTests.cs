using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The RFC 2119 requirements matrix for the CB-AdES vocabulary, cumulative across the wave's stages: every
/// discrete normative statement the preflight legs extracted from
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> clause 4 (general requirements), clause 5.1 (IETF-defined header parameter
/// profiling), clause 5.2 (the seven new signed header parameters — <c>x5ts</c>, <c>srCms</c>, <c>sigPl</c>,
/// <c>srAts</c>, <c>adoTst</c>, <c>sigPId</c>, <c>sigD</c>), and clause 5.4 (the <c>oId</c>/<c>pkiOb</c>/
/// <c>tstContainer</c> shared syntax) — stage 1's scope — plus clause 5.3 (<c>uHeaders</c> and the unsigned
/// components <c>sigPSt</c>, <c>sigTst</c>, <c>valData</c>, <c>arcTst</c>, and the clause 5.3.5.3 message-imprint
/// algorithm) and Annexes A (<c>refs</c>, <c>sigRTst</c>, <c>rfsTst</c>, and their own message-imprint
/// algorithms) and E (alternative long-term-availability disclosure) — stage 2's addition — per
/// <c>tempdocs/roadmap/wavecb-contract.md</c>. Mirrors the rows-as-spec-cells shape and <c>RowData</c> member
/// idiom of <c>CAdESRequirementsMatrixTests</c> (ETSI EN 319 122-1).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Requirement identifiers.</strong> Every <see cref="RequirementMatrixRow.ClauseId"/> is a
/// <c>CB-&lt;clause&gt;-&lt;seq&gt;</c> identifier exactly as one of the preflight leg reports
/// (<c>wavecb-leg-1-clause4-5p1-general-and-ietf-headers.md</c>, <c>wavecb-leg-2-clause5p2-new-signed-headers.md</c>,
/// <c>wavecb-leg-3-clause5p3-5p4-unsigned-and-shared-syntax.md</c>,
/// <c>wavecb-leg-4-clause6-baseline-levels-table14.md</c>, and
/// <c>wavecb-leg-5-annexes-a-to-f.md</c>) assigned it — no identifier here was invented for this matrix. Leg 1
/// states 68 rows (clause 4 + 5.1) and its own table has exactly 68; leg 3's clause-5.4-only slice has exactly
/// 22 (seeded in stage 1) and its clause-5.3 slice states 52 <c>CB-5.3.*</c> rows across 5.3.1 through 5.3.5.3
/// (seeded in stage 2, this addition). Leg 2's own prose states "91 discrete requirement rows" for clause 5.2,
/// but its table itself enumerates 124 distinct <c>CB-5.2.*</c> identifiers — a self-reporting discrepancy in
/// the leg document, not in this matrix; every one of the 124 rows the table actually states is seeded here;
/// none were trimmed. Leg 5's Annex A/E slice states 49 rows (<c>CB-A.1.1-01..30</c>, <c>CB-A.1.2.1-01..03</c>,
/// <c>CB-A.1.2.1.2-01..05</c>, <c>CB-A.1.2.2-01..03</c>, <c>CB-A.1.2.2.2-01..04</c>, <c>CB-E-01..04</c>) —
/// every one is seeded here in this stage-2 addition, none trimmed. Leg 4's clause 6 table states roughly 50
/// rows across Table 14's presence-per-baseline-level cells and its lettered additional requirements. wavecb S3
/// (FX-O) seeded the four rows that stage's shipped surface actually exercised (<c>CB-6.2.1-02</c>,
/// <c>CB-6.3-10</c>, <c>CB-6.3-a</c>, <c>CB-6.3-b</c>). wavecb S4 adds 30 more clause 6 rows: the clause
/// 6.1/6.2.2/6.3-standalone notation model (<c>CB-6.1-01</c>, <c>CB-6.2.2-01..11</c>, <c>CB-6.3-01/-02/-03</c>)
/// and the Table 14 rows and lettered requirements the B-T/B-LT augmentation-and-validation surface genuinely
/// reaches (<c>CB-6.3-21/-22/-23/-24/-25/-26/-27/-28</c> and additional requirements c through i) — 34 clause 6
/// rows total. The remainder (<c>CB-6.3-04..20</c>'s header-parameter cells, whose level semantics add nothing
/// this matrix's clause 5 rows do not already state; <c>CB-6.3-29</c>'s <c>arcTst</c> row and lettered
/// requirements j/k; and every conditioned-presence predicate this document defers to a later
/// validation/conclusions pass) is an explicit, recorded follow-up (an S7 candidate), not silently dropped.
/// </para>
/// <para>
/// <strong>Statuses are honest about what each stage ships.</strong> A row is
/// <see cref="RequirementCoverageStatus.Tested"/> only when an existing test in <c>CBAdESRegistryTests</c>,
/// <c>CBAdESSharedSyntaxTests</c>, <c>CBAdESSignedHeaderModelTests</c> (stage 1), or
/// <c>CBAdESUnsignedComponentTests</c>, <c>CBAdESUnsignedComponentSerializationTests</c>,
/// <c>CBAdESUnsignedHeadersTests</c>, <c>CBAdESMessageImprintTests</c> (stage 2 — all
/// <c>test/Verifiable.Tests/JCose/</c>) demonstrably exercises it. Stage 1 built the label/tag registries, the
/// clause 5.4 shared syntax, and the seven clause 5.2 signed-header component models with their CBOR codec.
/// Stage 2 adds the <c>uHeaders</c> ordered-array container, the clause 5.3 unsigned components (<c>sigPSt</c>,
/// <c>valData</c>, <c>arcTst</c>/<c>sigTst</c> as <c>tstContainer</c> aliases), Annex A's <c>refs</c>/
/// <c>sigRTst</c>/<c>rfsTst</c>, and all four message-imprint-input builders (<c>adoTst</c>, <c>arcTst</c>,
/// <c>sigRTst</c>, <c>rfsTst</c>) — nothing that composes a whole COSE_Sign/COSE_Sign1 structure, actually
/// requests a time-stamp token from a TSA, or cross-checks one component's references against another's
/// values. Every requirement that needs one of those not-yet-built pieces is
/// <see cref="RequirementCoverageStatus.OutOfScope"/>, its evidence naming the wave stage that owns it per the
/// contract's stage plan: S3 (B-B creation/validation e2e — the signature-composition orchestrator that places
/// every header in a protected/unprotected map, most of clause 5.1's placement rules, and the <c>sigD</c>
/// dereference-delegate mechanisms), S4 (B-T/B-LT augmentation, the TSA wire seam, the <c>refs</c>
/// mechanism's strip-on-upgrade transition and CB-A.1.1-30 cross-consistency), S5 (<c>arcTst</c> generation
/// orchestration per clause 5.3.5.2 and the Annex E disclosure convention), S6 (COSE_Sign + RFC 9338
/// countersignatures, the multi-signer substrate stage), or S7 (validation/conclusions, including the
/// Delta-CRL and cross-reference completeness policy checks). Clause 4's rows (the <c>uHeaders</c>-is-the-
/// sole-member rule, the COSE_Sign/COSE_Sign1 top-level shapes, attached/detached payload, integer keys/tags,
/// bstr encapsulation) are included as later-stage rows per instruction, not silently dropped because they
/// predate this stage's own component work.
/// </para>
/// <para>
/// <strong>Defect-register citations.</strong> Rows touching a preflight-recorded spec-original defect
/// (<c>wavecb-scout.md</c>'s D1-D11 register) cite it by code: D5 (5.1.9's RFC 8392/"8932" mislabelling), D10
/// (5.1.9's "may be signed or unsigned" vs. the mandatory-signed CWT-Claims container — no legal unsigned path),
/// D3 (5.2.5's <c>NotCertifiedItem</c> <c>qVals</c>/<c>encoding</c> members named in prose but absent from its
/// own CDDL — owner-flagged, carried opaque), D6 (Table 5's <c>sigPQuals</c> row mislabelled "in
/// CertifiedAttrChoice"), D7 (5.2.4's garbled <c>addressCountry</c> sentence, read permissively), D4 (5.2.8.1's
/// <c>sigD :</c> CDDL typo, read as <c>=</c>), and D11 (5.2.7.2's qualifier wire shape — one-entry maps keyed
/// per Table 6, not CBOR-tagged data items, ruled at the S1 review). Stage 2 additionally cites D1 (5.3.5.3's
/// closing sentence names "step 11)"; only step 12 yields a byte string — read as step 12, on the
/// <c>CB-5.3.5.3-*</c> imprint-output rows), D8 (Annex A.1.1's <c>responderIdByKey</c> — the raw DER
/// <c>byKey</c> bytes ride the <c>bstr</c> with no base64 transformation, the spec's "base64" wording being a
/// JAdES copy-residue, ruled in the contract), the leg-5 trap-3 reading (Annex A.1.1's <c>otherRefs</c>
/// CDDL comment is a copy-paste defect from <c>ocspRefs</c>, not evidence that <c>otherRefs</c> is OCSP-only),
/// and the leg-5 trap-4 reading (Annex A.1.2.1.2 step 4 and A.1.2.2.2 step 3 both say "signer layer" for their
/// <c>COSE_Sign1</c> branch, a copy-paste leftover from the preceding <c>COSE_Sign</c> step — read as "body
/// layer").
/// </para>
/// <para>
/// <strong>No external oracle, no vectors yet.</strong> Per the contract's recorded synthesis, no CB-AdES
/// conformance-vector source exists at this wave; every <see cref="RequirementCoverageStatus.Tested"/> row's
/// evidence is an in-house test built against an independently constructed CBOR oracle, never the codec under
/// test — the completeness this matrix claims is bounded by that caveat, not by claiming the vector gap away.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESRequirementsMatrixTests
{
    /// <summary>Whether a requirement row has been driven through a concrete test, is explicitly out of this wave stage's scope, or is implemented and unit-tested at the building-block level but not reachable through the shipped default composition because of an already-flagged, unfixed defect elsewhere in the pipeline.</summary>
    internal enum RequirementCoverageStatus
    {
        /// <summary>No disposition has been recorded. The value of an unset field, by design: a row must never silently pass as covered.</summary>
        Untested = 0,

        /// <summary>The requirement is driven by at least one concrete, named test that calls the shipped surface.</summary>
        Tested = 1,

        /// <summary>The requirement is explicitly out of this wave stage's scope — the evidence names the later stage (S2/S3/S6) that owns it, or the contract/charter reason.</summary>
        OutOfScope = 2,

        /// <summary>The requirement's own building block implements and unit-tests it, but the shipped default composition cannot reach it because of an already-flagged, unfixed defect elsewhere in the pipeline. Unused this stage — kept for shape parity with the sibling matrices.</summary>
        KnownDefect = 3
    }


    /// <summary>One row of the matrix: a requirement identifier, a short digest of the requirement it names, its coverage disposition, and the evidence for that disposition.</summary>
    /// <param name="ClauseId">The preflight leg's own <c>CB-&lt;clause&gt;-&lt;seq&gt;</c> requirement identifier, verbatim.</param>
    /// <param name="Requirement">A short digest of the normative statement, close enough to the specification's own wording to be checked against it.</param>
    /// <param name="Status">The coverage disposition.</param>
    /// <param name="Evidence">For <see cref="RequirementCoverageStatus.Tested"/>/<see cref="RequirementCoverageStatus.KnownDefect"/>, the asserting test's <c>ClassName.MethodName</c> (optionally followed by explanatory prose in parentheses) — the leading token is resolved through reflection; for <see cref="RequirementCoverageStatus.OutOfScope"/>, the owning stage or the contract/charter reason.</param>
    internal sealed record RequirementMatrixRow(string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence);


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
    /// No row of the matrix may be left without a coverage disposition, and a <see cref="RequirementCoverageStatus.Tested"/>
    /// or <see cref="RequirementCoverageStatus.KnownDefect"/> row's evidence must resolve to a real, existing
    /// <c>[TestMethod]</c> in the compiled test assembly.
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
    /// Resolves an evidence citation's leading <c>ClassName.MethodName</c> token against the compiled test
    /// assembly and fails when the class, the method, or the <c>[TestMethod]</c> attribute on it does not
    /// exist — a genuine check of the shipped test surface, not a check that a string happens to be non-empty.
    /// </summary>
    /// <param name="row">The row whose evidence is resolved.</param>
    private static void AssertEvidenceNamesAShippedTestMethod(RequirementMatrixRow row)
    {
        string token = row.Evidence.Split([' ', '('], 2, StringSplitOptions.RemoveEmptyEntries)[0];
        int separatorIndex = token.LastIndexOf('.');
        Assert.IsGreaterThan(0, separatorIndex, $"{row.ClauseId}: evidence '{row.Evidence}' must lead with a Class.Method pair.");

        string className = token[..separatorIndex];
        string methodName = token[(separatorIndex + 1)..];
        Type? evidenceType = typeof(CBAdESRequirementsMatrixTests).Assembly.GetTypes()
            .FirstOrDefault(candidate => string.Equals(candidate.Name, className, StringComparison.Ordinal));
        Assert.IsNotNull(evidenceType, $"{row.ClauseId}: evidence class '{className}' does not exist in the test assembly.");

        MethodInfo? evidenceMethod = evidenceType!.GetMethod(
            methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
        Assert.IsNotNull(evidenceMethod, $"{row.ClauseId}: evidence method '{className}.{methodName}' does not exist.");
        Assert.IsNotEmpty(evidenceMethod!.GetCustomAttributes(typeof(TestMethodAttribute), inherit: false),
            $"{row.ClauseId}: evidence '{className}.{methodName}' is not a [TestMethod] — the matrix must cite a real test.");
    }


    /// <summary>
    /// Every row of the matrix, as a plain data table. Kept as one literal so a reviewer can scan the whole
    /// stage-1 CB-AdES requirement surface — and its disposition — in one place. Rows are grouped to follow
    /// the specification's own structure: clause 4 (general requirements), clause 5.1 (IETF header profiling,
    /// by sub-clause), clause 5.2 (the seven new signed headers, by sub-clause), and clause 5.4 (the shared
    /// syntax types).
    /// </summary>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] RowData { get; } =
    [
        //Clause 4 — general requirements. Every row here needs the top-level COSE_Sign/COSE_Sign1 orchestrator
        //(S3), the uHeaders array container (S2), or the COSE_Sign multi-signer substrate (S6) — none of which
        //stage 1 builds; stage 1 ships the clause 5.2/5.4 component vocabulary only.
        ("CB-4.2-01", "CB-AdES signatures may be built on COSE_Sign (RFC 9052 clause 4.1), covering multiple signers of one COSE Payload.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 (COSE_Sign + RFC 9338 countersignatures, the substrate stage, wavecb-contract.md) — COSE_Sign is a constant only this stage (CoseTags.Sign); no multi-signer builder exists yet."),
        ("CB-4.2-02", "CB-AdES signatures may be built on COSE_Sign1 (RFC 9052 clause 4.2), one single signer.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.AttachedBaselineFlowRoundTripsAndVerifiesWithEs256 (CBAdESSignatureCreation composes Cose.SignAsync to build a single-signer COSE_Sign1 structure, round-tripped and verified from wire bytes alone; S3 coordinator ruling (1))"),
        ("CB-4.3-01", "CB-AdES signatures may be encoded untagged (COSE_Sign, COSE_Sign1).",
            RequirementCoverageStatus.Tested, "CBAdESSignatureValidationTests.ValidateAsyncSucceedsForUntaggedCoseSign1 (wavecb S3 FX-F: CBAdESSignatureSerialization.ParseCBAdESSign1 peek-gates the COSE_Sign1_Tagged read -- present it must be tag 18, absent it proceeds straight to the array -- accepting clause 4.3's untagged MAY for the COSE_Sign1 arm this stage builds; COSE_Sign's own untagged arm stays OutOfScope with CB-4.2-01, deferred to S6. Supersedes the earlier S3 coordinator ruling (7) tagged-only reading, which the wavecb S3 review found to over-read a MAY as a MUST NOT; emission stays tagged-only, per CBAdESSignatureSerialization's own class remarks.)"),
        ("CB-4.3-02", "CB-AdES signatures may be encoded tagged (COSE_Sign_Tagged, COSE_Sign1_Tagged, RFC 9052 clauses 4.1/4.2).",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.AttachedBaselineFlowRoundTripsAndVerifiesWithEs256 (CBAdESSignatureSerialization.SerializeCBAdESSign1/CoseSerialization.SerializeCoseSign1 both emit the COSE_Sign1_Tagged tag 18 prefix, and CBAdESSignatureSerialization.ParseCBAdESSign1 requires it — round-tripped end to end)"),
        ("CB-4.4-01", "The unprotected headers map (body or signer layer) shall contain only one member, uHeaders (clause 5.3), itself a CBOR array.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureValidationTests.ValidateAsyncFailsClosedWhenUnprotectedMapCarriesExtraMember (also CBAdESSignatureValidationTests.ValidateAsyncFailsClosedWhenUnprotectedMapKeyIsNotAnInteger — re-attributed from a stale S2 citation, flagged loudly at the wavecb S3 review: the rule is actually enforced by CBAdESSignatureSerialization.ParseCBAdESSign1, an S3 binding, not by S2's uHeaders model itself)"),
        ("CB-4.4-02", "COSE_Sign signatures may include protected header parameters in both the body layer and the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 — needs the COSE_Sign multi-signer structure."),
        ("CB-4.4-03", "COSE_Sign signatures shall not contain the uHeaders unprotected header parameter in the body layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 — needs both COSE_Sign (this stage's gap) and uHeaders (S2's) to distinguish body from signer layer."),
        ("CB-4.4-04", "COSE_Sign signatures may include uHeaders in the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 — same reasoning as CB-4.4-03."),
        ("CB-4.4-05", "COSE_Sign1 signatures shall include header parameters at the body layer (no signer layer exists).",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.AttachedBaselineFlowRoundTripsAndVerifiesWithEs256 (satisfied by construction — CBAdESSignatureCreation composes only COSE_Sign1, whose single protected header IS the body layer; no signer layer exists for this substrate, per CBAdESSignatureValidation's own remarks, S3 coordinator ruling (5))"),
        ("CB-4.4-06", "New header parameters this document defines, or defined elsewhere but further profiled here, shall be incorporated as specified in this document.",
            RequirementCoverageStatus.OutOfScope, "Reverted at the wavecb S3 review: the prior evidence overclaimed 'demonstrated collectively by every S3 Tested row' while several of this document's own profiled headers were still OutOfScope. Recomputed against the POST-fix tree: CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (FX-L, with content type added per this row's own FX-P note) now wire-exercises kid/x5u/x5t/content type/srCms/sigPl/srAts/adoTst end to end; FX-E wire-exercises iat (CBAdESSignatureValidationTests.ValidateAsyncReportsCwtClaimsMissingViolationWhenCwtClaimsIsAbsent's positive baseline; CBAdESSignatureCreationTests.SignedProtectedHeaderCarriesCwtClaimsIat); FX-H wire-exercises crit's tstr arm (CBAdESSignatureCreationTests.TextArmCriticalLabelAndUnprofiledHeaderRoundTripThroughCreateAndValidate, the shipped SignAsync -> ValidateAsync composition leg; also CBAdESSignatureValidationTests.ParseAcceptsIndependentlyMintedTextArmCritAndUnprofiledHeader for the independently-minted-wire-bytes leg). Still genuinely OutOfScope for the remaining named headers this document profiles: x5chain's signed-header placement (CB-5.1.8, creation-side tri-way only -- CBAdESSignatureCreationTests.CreationWithOnlyX5ChainSatisfiesTriWay asserts the in-memory aggregate, never a wire-decoded value), x5ts's signed-header placement (CB-5.2.2-01, same creation-only gap, see that row), sigPId's signed-header placement (CB-5.2.7-01, never wire-round-tripped this stage), and the whole clause 5.1.6 countersignature carrier (wholesale S6). The umbrella cannot honestly flip Tested while its own named sub-rows remain OutOfScope; deferred until those close."),
        ("CB-4.4-07", "Header parameters defined elsewhere and not further profiled by this document may also be added as signed header parameters or uHeaders elements, with unconstrained semantics.",
            RequirementCoverageStatus.OutOfScope, "Partially exercised as of wavecb S3 FX-G/FX-H: CBAdESSignatureCreationTests.UnprofiledX5BagLabelRoundTripsByteExactThroughCreateAndValidate round-trips an unprofiled SIGNED header parameter through the int arm (label 32, x5bag -- removed from CBAdESProtectedHeaders's local IsProfiledLabel switch, since ETSI TS 119 152-1 V1.1.1 never mentions x5bag anywhere); CBAdESSignatureCreationTests.TextArmCriticalLabelAndUnprofiledHeaderRoundTripThroughCreateAndValidate and CBAdESSignatureValidationTests.ParseAcceptsIndependentlyMintedTextArmCritAndUnprofiledHeader now additionally cover the tstr arm of the CDDL's int/tstr label union (RFC 9052 section 1.4/3.1, clause 4.4 NOTE 4) for both crit elements and unprofiled signed headers, byte-exact through the shipped CBAdESSignatureCreation.SignAsync -> CBAdESSignatureValidation.ValidateAsync composition AND from independently minted wire bytes. The uHeaders-element side of this row (an unprofiled header parameter carried as an UNSIGNED uHeaders array element, clause 5.3.1) remains untested -- a different wire location this stage's S2 model does not exercise for unprofiled content; still a residual test-coverage gap, not an unbuilt capability, flagged for the review wave."),
        ("CB-4.5-01", "The COSE Payload may be attached or detached.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.AttachedBaselineFlowRoundTripsAndVerifiesWithEs256 (attached arm; also CBAdESSignatureFlowTests.DetachedObjectIdByUriFlowReconstructsAndValidatesFromWireBytesOnly for the detached arm)"),
        ("CB-4.5-02", "A detached COSE Payload may be one detached object or the concatenation of more than one, per sigD (clause 5.2.8).",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.DetachedObjectIdByUriFlowReconstructsAndValidatesFromWireBytesOnly (two detached objects, order-preserving concatenation per CB-5.2.8.2.2-05, verified end to end from wire bytes)"),
        ("CB-4.6-01", "Keys of the new CBOR map pairs shall be integers.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.ObjectIdentifierRoundTripsWithAllMembers (every map key in every stage-1 model — Tables 1 through 13 — is a const int, exercised byte-exact against an independent oracle throughout CBAdESRegistryTests, CBAdESSharedSyntaxTests, and CBAdESSignedHeaderModelTests)"),
        ("CB-4.6-02", "Tags for new CBOR tagged data items shall also be integers.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S2 — this document's only new CBOR tag is uHeaders' own identifying tag (clause 5.3.1, Table 8); tag 32, reused from RFC 8949 for every URI-typed field this stage, is not a tag this document itself defines."),
        ("CB-4.7-01", "The document requires (lowercase modal) encapsulating CBOR components in CBOR byte strings.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S2 — uHeaders' element-wrapping (clause 5.3.1) is the load-bearing instance of this rule; per CBAdESSerialization's own class remarks, none of the stage-1 component values are Tag-24 bstr wrappers on the wire."),
        ("CB-4.7-02", "This encapsulation shall use the CBOR encoding restrictions of RFC 9052 clause 9.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S2 — same reasoning as CB-4.7-01."),

        //Clause 5.1 — IETF-defined header parameter profiling (alg, content type, kid, x5u, countersignature
        //carrier, x5t, x5chain, iat, crit). Every one of these is a pre-existing COSE/RFC9360/RFC8392/RFC9597
        //header, not a new CB-AdES type this stage models; the profiling this clause adds (protected-map
        //placement, layer placement in COSE_Sign, cross-field invariants with sigD/crit) is exercised once the
        //B-B creation orchestrator (S3) or the COSE_Sign substrate (S6, for the countersignature carrier and
        //every "in COSE_Sign, at the signer layer" rule) exists.
        ("CB-5.1.2-01", "alg shall be a signed header parameter that qualifies the signature.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureValidationTests.ValidateAsyncSucceedsForMinimalConformantBBMessage (alg is decoded from the protected header and equals the value creation signed; every S3 test's cryptographic verification depends on this placement)"),
        ("CB-5.1.2-02", "alg shall have the semantics specified in RFC 9052 clause 3.1.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureValidationTests.ValidateAsyncSucceedsForMinimalConformantBBMessage (alg selects the verification algorithm Cose.VerifyAsync applies; a wrong value fails the cryptographic check, exercised by every S3 positive/negative test)"),
        ("CB-5.1.2-03", "alg shall have the syntax specified in RFC 9052 clause 3.1.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureValidationTests.ValidateAsyncSucceedsForMinimalConformantBBMessage (alg round-trips as a plain CBOR integer through CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader/ParseCBAdESSign1)"),
        ("CB-5.1.2-04", "alg's value should be one of the digital-signature algorithms ETSI TS 119 312 recommends.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3 — a TS 119 312 recommended-algorithm table is a stated CBOM/PQC follow-up, mirroring the CAdES matrix's 6.2.1-ts119312-should row; no orchestrator consults it yet."),
        ("CB-5.1.2-05", "The alg identifier shall be one registered at the IANA COSE Algorithms registry.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.AttachedBaselineFlowRoundTripsAndVerifiesWithEs256 (also CBAdESSignatureFlowTests.AttachedBaselineFlowRoundTripsAndVerifiesWithEs384SecondAlgorithm — both ES256 and ES384 are IANA COSE Algorithms registry identifiers, WellKnownCoseAlgorithms)"),
        ("CB-5.1.2-06", "In COSE_Sign, alg shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 — needs the COSE_Sign multi-signer structure."),
        ("CB-5.1.3-01", "content type shall be a signed header parameter that qualifies the COSE Payload.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3."),
        ("CB-5.1.3-02", "content type shall have the semantics specified in RFC 9052 clause 3.1.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3."),
        ("CB-5.1.3-03", "content type shall not be present if sigD (clause 5.2.8) is present.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.ContentTypeAndDetachedObjectsBothPresentThrows (also CBAdESSignatureValidationTests.ValidateAsyncReportsContentTypeDetachedObjectsExclusivityViolation for the validation-side collect posture, S3 coordinator ruling (2))"),
        ("CB-5.1.3-04", "content type should not be present if the content type is implied by the COSE Payload.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3."),
        ("CB-5.1.3-05", "content type shall not be present if the COSE Payload is a (counter-signed) signature.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 — the counter-signed-payload case needs the countersignature carrier."),
        ("CB-5.1.3-06", "content type shall have the syntax specified in RFC 9052 clause 3.1.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3."),
        ("CB-5.1.3-07", "In COSE_Sign, content type shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),
        ("CB-5.1.4-01", "kid shall be a signed header parameter that qualifies the signature.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (wavecb S3 FX-L: kid is placed in the SIGNED protected headers map by CBAdESSignatureCreation/CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader and decoded back from wire bytes alone, asserted byte-exact against an independently-kept expectedKeyId; kid's non-authoritative-hint POLICY — CB-5.1.4-04, still OutOfScope — is a separate, later-stage concern this row's placement claim does not touch)"),
        ("CB-5.1.4-02", "kid shall have the semantics specified in RFC 9052 clause 3.1.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (kid round-trips as the RFC 9052 §3.1 bstr-typed key-identifier-hint member; this stage carries it opaque, per CB-5.1.4-03's own SHOULD, never runtime-interpreted)"),
        ("CB-5.1.4-03", "kid's content should be the DER-encoded IssuerSerial type of RFC 5035.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3."),
        ("CB-5.1.4-04", "kid shall be used only as a non-authoritative hint when other referencing header parameters are present.",
            RequirementCoverageStatus.OutOfScope, "Re-attributed at the wavecb S3 review: deferred to CB-AdES wave stage S4/S7, not S3 — CBAdESSignatureValidation's own remarks state this class 'does not resolve, chain, or validate the signing certificate at all;' kid's non-authoritative-hint policy is a certificate-path/trust-resolution concern those stages own."),
        ("CB-5.1.4-05", "kid shall have the syntax specified in RFC 9052 clause 3.1.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (kid round-trips as a plain CBOR byte string through CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader/ParseCBAdESSign1, byte-exact against the flow's independently-kept expectedKeyId)"),
        ("CB-5.1.4-06", "In COSE_Sign, kid shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),
        ("CB-5.1.5-01", "x5u shall be a signed header parameter that qualifies the signature.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (wavecb S3 FX-L: x5u is placed in the SIGNED protected headers map and decoded back from wire bytes alone, asserted equal to the flow's independently-kept expectedX5u; x5u's non-mandatory-hint POLICY — CB-5.1.5-03, still OutOfScope — is a separate, later-stage concern this row's placement claim does not touch)"),
        ("CB-5.1.5-02", "x5u shall have the semantics specified in RFC 9360 clause 2.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (x5u round-trips as the RFC 9360 §2 URI hint for retrieving the signing certificate, carried opaque -- this stage never resolves it, per CBAdESSignatureValidation's own certificate-path-neutral scope boundary)"),
        ("CB-5.1.5-03", "x5u shall be used as a hint, not the sole mandatory certificate-retrieval path.",
            RequirementCoverageStatus.OutOfScope, "Re-attributed at the wavecb S3 review: deferred to CB-AdES wave stage S4/S7, not S3 — same reasoning as CB-5.1.4-04; CBAdESSignatureValidation does not resolve or retrieve certificates at all, so x5u's status as a non-mandatory hint is a certificate-path/trust-resolution concern those stages own."),
        ("CB-5.1.5-04", "x5u shall have the syntax specified in RFC 9360 clause 2 (a URI).",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (x5u round-trips as a plain CBOR tag-32 URI through CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader/ParseCBAdESSign1, asserted equal to the flow's independently-kept expectedX5u)"),
        ("CB-5.1.5-05", "In COSE_Sign, x5u shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),
        ("CB-5.1.6-01", "The counter-signature CBOR component shall be an element of the uHeaders member of the unprotected headers map.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 (COSE_Sign + RFC 9338 countersignatures, the substrate stage) — the countersignature carrier is a constant only (CoseHeaderParameters.CounterSignature); no builder exists."),
        ("CB-5.1.6-02", "That uHeaders element shall be either one of the two RFC 9338 header parameters, or a CB-AdES signature as specified in this document.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),
        ("CB-5.1.6-03", "Each CBOR component for incorporating new counter signatures shall contain either one of the two RFC 9338 header parameters.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),
        ("CB-5.1.6-04", "The digital signature value of each counter signature shall be computed as specified in RFC 9338 clause 3.3.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),
        ("CB-5.1.6-05", "If the counter signature is a CB-AdES signature, its value shall be computed per RFC 9338 clause 3.3, and the context string shall be selected by its own structure.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),
        ("CB-5.1.7-01", "x5t shall have the semantics specified in RFC 9360 clause 2.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3 — x5t itself (the single-hash pre-existing RFC 9360 header, distinct from x5ts) is not modeled as a CB-AdES type this stage."),
        ("CB-5.1.7-02", "x5t shall have the syntax of COSE_CertHash, RFC 9360 clause 2.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3 — COSE_CertHash's two-field shape is incidentally proven via x5ts's per-entry type (CBAdESCertificateThumbprint, Tested under CB-5.2.2-06 below), but x5t's own header placement is not exercised this stage."),
        ("CB-5.1.7-03", "The hashAlg value shall be one of the identifiers registered in the IANA COSE Algorithms registry, or any future spec defining new digest-algorithm identifiers.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3 — same x5t-vs-x5ts distinction as CB-5.1.7-02."),
        ("CB-5.1.7-04", "In COSE_Sign, x5t shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),
        ("CB-5.1.8-01", "x5chain may be a signed or unsigned header parameter that qualifies the signature.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3 — the signed/unsigned policy choice is the orchestrator's."),
        ("CB-5.1.8-02", "If x5chain is not to be signed, it shall be included within the uHeaders CBOR array.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S2 — needs the uHeaders array container."),
        ("CB-5.1.8-03", "x5chain shall have the semantics specified in RFC 9360 clause 2.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3."),
        ("CB-5.1.8-04", "x5chain shall have the syntax of COSE_X509, RFC 9360 clause 2.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3."),
        ("CB-5.1.8-05", "If x5chain is unsigned, it shall be placed within the uHeaders CBOR array (restates CB-5.1.8-02).",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S2."),
        ("CB-5.1.8-06", "In COSE_Sign, x5chain shall be placed in the signer layer regardless of the signed/unsigned choice.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),
        ("CB-5.1.9-01", "iat may be a signed or unsigned header parameter that qualifies the signature.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SignedProtectedHeaderCarriesCwtClaimsIat (D10: the contract rules no legal unsigned path actually exists — the SIGNED path this test exercises is the only one this library implements; CBAdESProtectedHeaders's own constructor makes CwtClaims mandatory)"),
        ("CB-5.1.9-02", "iat shall have the semantics specified in RFC 8392 clause 3.1.6 (D5: the spec's own '8932' citation corrected).",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SignedProtectedHeaderCarriesCwtClaimsIat (claim key 6 within CWT Claims, RFC 8392 clause 3.1.6, decoded via an independent CborReader)"),
        ("CB-5.1.9-03", "iat's value shall specify the instant the signer claims to have performed the signing process.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SignedProtectedHeaderCarriesCwtClaimsIat (the decoded iat equals the caller-supplied claimed signing time exactly)"),
        ("CB-5.1.9-04", "iat's syntax shall be as RFC 8392 clause 3.1.6 states (D5).",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SignedProtectedHeaderCarriesCwtClaimsIat (decoded via the independent ReadCwtClaimsMember helper, never CBAdESSignatureSerialization's own decode path)"),
        ("CB-5.1.9-05", "iat's value shall be a NumericDate instance, RFC 8392 clause 2.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SignedProtectedHeaderCarriesCwtClaimsIat (also CBAdESSignatureValidationTests.ValidateAsyncSucceedsForMinimalConformantBBMessage — iat round-trips as a NumericDate whole-seconds integer)"),
        ("CB-5.1.9-06", "iat shall be incorporated within the RFC 9597 CWT-Claims container, itself incorporated as a signed header parameter.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SignedProtectedHeaderCarriesCwtClaimsIat (iat is decoded from label 15, claim key 6, within the SIGNED protected header)"),
        ("CB-5.1.9-07", "In COSE_Sign, iat (via its CWT-Claims container) shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),
        ("CB-5.1.10-01", "crit shall be a signed header parameter that qualifies the signature.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SigDPresentAutoAddsCriticalLabelAndPreservesCallerLabels (crit is decoded from the signed protected header via an independent CborReader, ReadIntArray)"),
        ("CB-5.1.10-02", "crit shall have the semantics specified in RFC 9052 clause 3.1.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SigDPresentAutoAddsCriticalLabelAndPreservesCallerLabels (crit's semantics — labels the signer marks critical for a recipient to understand — govern the sigD-implies-267 rule this same test exercises)"),
        ("CB-5.1.10-03", "crit shall have the syntax specified in RFC 9052 clause 3.1 (an array of integer labels).",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SigDPresentAutoAddsCriticalLabelAndPreservesCallerLabels (decoded as a CBOR array of integers via the independent ReadIntArray helper)"),
        ("CB-5.1.10-04", "If the signature includes sigD, crit shall also be present and shall include sigD's assigned label.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SigDPresentAutoAddsCriticalLabelAndPreservesCallerLabels (also CBAdESSignatureValidationTests.ValidateAsyncReportsDetachedObjectsCriticalLabelViolationWhenSigDLabelAbsentFromCrit for the validation-side collect posture, S3 coordinator rulings (2)/(3))"),
        ("CB-5.1.10-05", "In COSE_Sign, crit shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),

        //Clause 5.2.1 — the label registry shared by all seven new signed headers.
        ("CB-5.2.1-01", "All seven clause 5.2 signed header parameters shall be part of the protected headers map when present.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3 — placement in a real protected headers map needs the signature-composition orchestrator."),
        ("CB-5.2.1-02", "Each of the seven shall be identified by a label in the corresponding CBOR map.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3 — identification 'in the corresponding CBOR map' needs that map to exist."),
        ("CB-5.2.1-03", "That label shall be an integer.",
            RequirementCoverageStatus.Tested, "CBAdESRegistryTests.HeaderParameterLabelsMatchTable1AndTable8Assignments (every CBAdESHeaderParameters label is a const int)"),
        ("CB-5.2.1-04", "Table 1 label assignments: x5ts=261, srCms=262, sigPl=263, srAts=264, adoTst=265, sigPId=266, sigD=267.",
            RequirementCoverageStatus.Tested, "CBAdESRegistryTests.HeaderParameterLabelsMatchTable1AndTable8Assignments"),

        //Clause 5.2.2 — x5ts.
        ("CB-5.2.2-01", "x5ts shall be a signed header parameter that qualifies the signature.",
            RequirementCoverageStatus.OutOfScope, "Reconciled at the wavecb S3 review (FX-P): CBAdESSignatureCreationTests.CreationWithOnlyCertificateDigestsSatisfiesTriWay does NOT round-trip x5ts's signed-header placement -- it asserts result.Headers.CertificateDigests, the very same in-memory CBAdESCertificateThumbprints object CBAdESSignatureCreation.SignAsync's caller constructed and ownership-transferred, never a value decoded back from wire bytes through CBAdESSignatureValidation.ValidateAsync. Flow 5 deliberately excludes x5ts, per FX-L's own residue note (leaving the tri-way's other two members, x5t and x5chain, as the wire-exercised legs; x5ts and sigPId remain the two clause 5.2 signed headers with no decode-and-assert coverage this stage). Deferred as a residual wire-parse coverage gap, not an unbuilt capability -- follow-up candidate alongside CB-4.4-06 and CB-4.4-07's own residue."),
        ("CB-5.2.2-02", "x5ts label shall be 261.",
            RequirementCoverageStatus.Tested, "CBAdESRegistryTests.HeaderParameterLabelsMatchTable1AndTable8Assignments"),
        ("CB-5.2.2-03", "x5ts shall contain several certificate-path references, each a digest-algorithm identifier plus the digest value of the referenced certificate, minimum cardinality two.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeCertificateThumbprintsMatchesIndependentOracleForMultipleEntries (three-entry round trip); CBAdESSignedHeaderModelTests.ConstructingCertificateThumbprintsBelowMinimumCountThrows (the CDDL 2* minimum)"),
        ("CB-5.2.2-04", "The first reference within x5ts shall be the reference of the signing certificate.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeCertificateThumbprintsMatchesIndependentOracleForMultipleEntries (asserts SigningCertificateThumbprint equals Thumbprints[0] and every index's algorithm/digest survive the independent-oracle round trip in order)"),
        ("CB-5.2.2-05", "x5ts shall not contain any other information.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeCertificateThumbprintsMatchesIndependentOracleForMultipleEntries (satisfied by construction — CBAdESCertificateThumbprints exposes only Thumbprints, and the independent oracle's array holds exactly the two-element [hashAlg, hashValue] entries, nothing else)"),
        ("CB-5.2.2-06", "Each x5t component of x5ts shall have the semantics and syntax of COSE_CertHash, RFC 9360 clause 2, further profiled by clause 5.1.7.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeCertificateThumbprintsMatchesIndependentOracleForMultipleEntries (the two-field [hashAlg, hashValue] shape matches the independent oracle byte-exactly)"),
        ("CB-5.2.2-07", "A CB-AdES signature shall have at least one of x5t, x5ts, or x5chain in the protected headers map, protecting the signing certificate.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.CreationWithNoCertificateReferenceThrows (the D9 tri-way negative; also CBAdESSignatureCreationTests.CreationWithOnlyX5TSatisfiesTriWay, ...CreationWithOnlyCertificateDigestsSatisfiesTriWay, and ...CreationWithOnlyX5ChainSatisfiesTriWay for the three positive legs, plus CBAdESSignatureValidationTests.ValidateAsyncReportsCertificateReferenceTriWayViolationWhenNoneOfX5tX5tsX5chainIsPresent for the validation-side collect posture)"),
        ("CB-5.2.2-08", "In COSE_Sign, x5ts shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),

        //Clause 5.2.3 — srCms.
        ("CB-5.2.3-01", "srCms shall be a signed header parameter that qualifies the COSE Payload.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (wavecb S3 FX-L: srCms is placed in the SIGNED protected headers map by CBAdESSignatureCreation and decoded back from wire bytes alone, its commId asserted equal to the flow's independently-kept expectedCommitmentId; 'qualifies the COSE Payload' is satisfied by construction -- CBAdESProtectedHeaders is the body-layer aggregate the flow's attached payload is signed under)"),
        ("CB-5.2.3-02", "srCms label shall be 262.",
            RequirementCoverageStatus.Tested, "CBAdESRegistryTests.HeaderParameterLabelsMatchTable1AndTable8Assignments"),
        ("CB-5.2.3-03", "srCms shall indicate the commitment made by the signer when signing.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignerCommitmentsMatchesIndependentOracleForMultipleCommitments"),
        ("CB-5.2.3-04", "srCms shall express the commitment type with a URI.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignerCommitmentsMatchesIndependentOracleForMultipleCommitments (commId.id is Uri-typed, round-tripped through the oId codec)"),
        ("CB-5.2.3-05", "srCms may contain a sequence of qualifiers providing more information about the commitment.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignerCommitmentsMatchesIndependentOracleForMultipleCommitments (one commitment carries two qualifiers, one carries none)"),
        ("CB-5.2.3-06", "Each element of the srCms CBOR array shall indicate one commitment made by the signer, which may be further qualified.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignerCommitmentsMatchesIndependentOracleForMultipleCommitments"),
        ("CB-5.2.3-07", "The id member of oId (within commId) shall have a URI value, uniquely identifying one commitment made by the signer.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.ObjectIdentifierRoundTripsWithIdOnly (Id is Uri-typed; reused as srCms.commId by CBAdESSignedHeaderModelTests.EncodeSignerCommitmentsMatchesIndependentOracleForMultipleCommitments)"),
        ("CB-5.2.3-08", "Any specification defining a new commitment type requiring additional qualifying information shall fully define its semantics and syntax.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignerCommitmentsMatchesIndependentOracleForMultipleCommitments (this implementation's own obligation is the open commQuals extension point that a third-party spec's qualifying information would ride — the test exercises it with a mixed string/int payload)"),
        ("CB-5.2.3-09", "In COSE_Sign, srCms shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),

        //Clause 5.2.4 — sigPl.
        ("CB-5.2.4-01", "sigPl shall be a signed header parameter that qualifies the signer.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (wavecb S3 FX-L: sigPl is placed in the SIGNED protected headers map and decoded back from wire bytes alone, AddressLocality/AddressCountry asserted against the flow's independently-kept expectations)"),
        ("CB-5.2.4-02", "sigPl label shall be 263.",
            RequirementCoverageStatus.Tested, "CBAdESRegistryTests.HeaderParameterLabelsMatchTable1AndTable8Assignments"),
        ("CB-5.2.4-03", "sigPl shall specify an address associated with the signer at a particular geographical location.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignatureProductionPlaceMatchesIndependentOracleForAllMembers"),
        ("CB-5.2.4-04", "sigPl shall have at least one of its members.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignatureProductionPlaceThrowsWhenEveryMemberIsNull (encode-side guard); CBAdESSignedHeaderModelTests.TryParseSignatureProductionPlaceFailsClosedOnEmptyMap (parse-side mirror)"),
        ("CB-5.2.4-05", "The addressCountry member may contain either the country's name or its ISO 3166-1 alpha-2 code (D7: the spec's garbled 'shall contain may contain' sentence read permissively).",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignatureProductionPlaceMatchesIndependentOracleForAllMembers"),
        ("CB-5.2.4-06", "In COSE_Sign, sigPl shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),

        //Clause 5.2.5 — srAts.
        ("CB-5.2.5-01", "srAts shall be a signed header parameter that qualifies the signer.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (wavecb S3 FX-L: srAts is placed in the SIGNED protected headers map and decoded back from wire bytes alone, its claimed entry's MediaType asserted against the flow's independently-kept expectedClaimedMediaType)"),
        ("CB-5.2.5-02", "srAts label shall be 264.",
            RequirementCoverageStatus.Tested, "CBAdESRegistryTests.HeaderParameterLabelsMatchTable1AndTable8Assignments"),
        ("CB-5.2.5-03", "srAts shall encapsulate signer attributes (e.g. role).",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignerAttributesMatchesIndependentOracleForBothCertifiedArms"),
        ("CB-5.2.5-04", "srAts may encapsulate signer-claimed attributes, Attribute-Authority-certified attributes, and/or third-party-signed assertions, independently and in any combination.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignerAttributesMatchesIndependentOracleForBothCertifiedArms (certified); CBAdESSignedHeaderModelTests.TryParseSignerAttributesPreservesOpaqueQualifyingValueBytesExactly (signedAssertions)"),
        ("CB-5.2.5-05", "The certified member shall contain a non-empty array of DER-encoded X.509 or other-syntax attribute certificates.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignerAttributesMatchesIndependentOracleForBothCertifiedArms (both arms in one array); CBAdESSignedHeaderModelTests.ConstructingSignerAttributesWithEmptyCertifiedArrayThrows (the non-empty guard)"),
        ("CB-5.2.5-06", "The signedAssertions member shall contain a non-empty array of assertions signed by a third party.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.ConstructingSignerAttributesWithEmptySignedAssertionsArrayThrows (also CBAdESSignedHeaderModelTests.TryParseSignerAttributesPreservesOpaqueQualifyingValueBytesExactly for content)"),
        ("CB-5.2.5-07", "The claimed member shall contain a non-empty array of attributes claimed by the signer but neither certified nor signed.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.ConstructingSignerAttributesWithEmptyClaimedArrayThrows"),
        ("CB-5.2.5-08", "Both signedAssertions and claimed shall be instances of the AttrArrays type.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignerAttributesPreservesOpaqueQualifyingValueBytesExactly (exercises the shared CBAdESSignerAttributeNotCertifiedItem type through the SignedAssertions member; Claimed shares the identical model and codec path)"),
        ("CB-5.2.5-09", "Each instance of AttrArrays shall be a CBOR array whose elements are instances of NotCertifiedItem.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignerAttributesPreservesOpaqueQualifyingValueBytesExactly"),
        ("CB-5.2.5-10", "Each instance of NotCertifiedItem shall contain two elements: mediaType and the qualifying-values collection.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignerAttributesPreservesOpaqueQualifyingValueBytesExactly (D3: the codec's provisional two-element [mediaType, qVals-array] wire mapping — see the D3 remarks on CBAdESSignerAttributeNotCertifiedItem and CBAdESSerialization — since the CDDL itself does not name a qVals or encoding label)"),
        ("CB-5.2.5-11", "The mediaType element shall identify the media type of the signed assertions or claimed attributes present in qVals.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignerAttributesPreservesOpaqueQualifyingValueBytesExactly (asserts MediaType equals the crafted media-type string)"),
        ("CB-5.2.5-12", "The qVals member shall be a CBOR array of at least one item.",
            RequirementCoverageStatus.OutOfScope, "D3 (owner flag): qVals is not a named CDDL label in clause 5.2.5's own NotCertifiedItem production — a non-empty-array construction guard cannot be soundly built until ETSI clarifies which catch-all label values correspond to it; CBAdESSignerAttributeNotCertifiedItem.QualifyingValues documents the invariant but does not runtime-enforce it this stage."),
        ("CB-5.2.5-13", "The elements of qVals shall be the values of the signed assertions or claimed attributes, encoded as indicated within the encoding member.",
            RequirementCoverageStatus.OutOfScope, "D3 (owner flag): the encoding member is likewise absent from the CDDL; CBAdESSignerAttributeOpaqueQualifyingValueKind carries only Unspecified until ETSI clarifies the wire shape — each value is preserved as opaque bytes (CBAdESSignedHeaderModelTests.TryParseSignerAttributesPreservesOpaqueQualifyingValueBytesExactly), never decoded per a stated encoding."),
        ("CB-5.2.5-14", "Empty srAts header parameters shall not be generated.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignerAttributesThrowsWhenEveryMemberIsNull"),
        ("CB-5.2.5-15", "In COSE_Sign, srAts shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),

        //Clause 5.2.6 — adoTst.
        ("CB-5.2.6-01", "adoTst shall be a signed header parameter that qualifies the COSE Payload.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.FullHouseAttachedFlowRoundTripsAndVerifiesEveryClause5SignedHeader (wavecb S3 FX-L: adoTst is placed in the SIGNED protected headers map and decoded back from wire bytes alone, TstTokens[0].Val asserted byte-exact against the flow's independently-kept timestampTokenDerBytes; 'qualifies the COSE Payload' is satisfied by construction, same reasoning as CB-5.2.3-01)"),
        ("CB-5.2.6-02", "adoTst label shall be 265.",
            RequirementCoverageStatus.Tested, "CBAdESRegistryTests.HeaderParameterLabelsMatchTable1AndTable8Assignments"),
        ("CB-5.2.6-03", "adoTst shall encapsulate one or more electronic time-stamps generated before signature production (adoTst = tstContainer).",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodePayloadTimestampMatchesIndependentOracleForMultipleTokens"),
        ("CB-5.2.6-04", "The message-imprint computation input for each such time-stamp shall be the COSE Payload of the CB-AdES signature.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.AdoTstAttachedPayloadIsWrappedByteString (also CBAdESMessageImprintTests.AdoTstDetachedPayloadIsWrappedByteString for the detached arm) -- CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput builds exactly the COSE Payload bytes for both arms. wavecb S4 exercises this at a real use site: CBAdESLifecycleFlowTests.PayloadTimestampFlowAcquiresAdoTstOverAttachedPayloadAndValidatesImprint acquires an adoTst through CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync over the actual attached COSE Payload before signing, places it, signs, and validates the imprint from wire bytes alone."),
        ("CB-5.2.6-05", "If sigD is absent, the imprint input shall be the CBOR byte string of the payload field, or the bytes of the detached COSE Payload wrapped in one, if the payload field is absent.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.AdoTstAttachedPayloadIsWrappedByteString (payload field present, wrapped bstr) and CBAdESMessageImprintTests.AdoTstDetachedPayloadIsWrappedByteString (payload field absent, detached bytes retrieved and wrapped). wavecb S4's flow 9 (CBAdESLifecycleFlowTests.PayloadTimestampFlowAcquiresAdoTstOverAttachedPayloadAndValidatesImprint) exercises the sigD-absent, payload-field-present arm at a real use site end to end; the sigD-absent, payload-field-absent (externally detached, no sigD) arm remains unit-verified only, at CBAdESMessageImprintTests.AdoTstDetachedPayloadIsWrappedByteString -- a residual flow-coverage gap flagged for the review wave."),
        ("CB-5.2.6-06", "If sigD is present with mId ObjectIdByURI or ObjectIdByURIHash, the imprint input shall be the concatenation from processing sigD.pars per clause 5.2.8.2.2, even under the Hash mechanism.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.AdoTstSigDProcessedPayloadIsRawConcatenationWithNoByteStringWrapping -- the concatenation-with-no-wrapping shape this row states is Tested. wavecb S4's flow 10 (CBAdESLifecycleFlowTests.PayloadTimestampFlowAcquiresAdoTstOverSigDReconstructedPayloadAndValidatesImprint) closes the clause-5.2.8.2.2 pars-dereferencing gap this row's own S2 evidence flagged as deferred: an adoTst is acquired over the GENUINELY dereferenced-and-concatenated sigD payload through CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync with CBAdESSigDReferencedPayloadTimestampAcquisitionSource, and the resulting signature validates from wire bytes alone with the verifier's own independent dereference delegate instance. Wired to CB-5.2.8.2.3-07's adoTst half below."),
        ("CB-5.2.6-07", "If sigD.mId is neither of the two defined URIs, the specification defining that mId shall specify how to retrieve the COSE Payload.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.UnknownMechanismWithoutHandlerThrows (also CBAdESSignatureCreationTests.UnknownMechanismWithHandlerSignsHandlerPayload for the positive extension-point leg — re-attributed from OutOfScope, the CBAdESUnknownDetachedObjectMechanismDelegate seam this row anticipated is now built and tested); wavecb S3 FX-N extends coverage to the validation side, reaching actual dispatch (crit includes 267, no content type -- unlike the two step-b early-failing third-party-mId tests): CBAdESSignatureValidationTests.ValidateAsyncSucceedsWhenUnknownMechanismHandlerResolvesPayload (positive leg), ValidateAsyncFailsWithDetachedObjectUnresolvableWhenUnknownMechanismHandlerThrowsRoutineDereferenceException and ValidateAsyncPropagatesNonRoutineExceptionFromUnknownMechanismHandler (the wavecb S3 FX-J routine-vs-non-routine failure-contract split), and ValidateAsyncFailsWithDetachedObjectUnresolvableWhenNoUnknownMechanismHandlerIsSupplied (the no-handler leg this row's own text states). wavecb S4's flows 9/10 additionally demonstrate adoTst's own acquisition-and-validation use site for the two BUILT-IN mId arms (CBAdESLifecycleFlowTests.PayloadTimestampFlowAcquiresAdoTstOverAttachedPayloadAndValidatesImprint and ...OverSigDReconstructedPayloadAndValidatesImprint); combining adoTst acquisition with a THIRD-PARTY/unknown mId specifically is not exercised this stage -- a residual gap unrelated to this row's own claim, which concerns dispatch, not adoTst."),
        ("CB-5.2.6-08", "In COSE_Sign, adoTst shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),

        //Clause 5.2.7.1 — sigPId.
        ("CB-5.2.7-01", "sigPId shall be a signed header parameter qualifying the signature.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3."),
        ("CB-5.2.7-02", "sigPId label shall be 266.",
            RequirementCoverageStatus.Tested, "CBAdESRegistryTests.HeaderParameterLabelsMatchTable1AndTable8Assignments"),
        ("CB-5.2.7-03", "sigPId shall contain an explicit identifier of a signature policy.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignaturePolicyIdentifierMatchesIndependentOracleWithDigPSpTrueAndDocumentSpecification"),
        ("CB-5.2.7-04", "The id member shall be used for referencing the signature policy explicitly.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignaturePolicyIdentifierMatchesIndependentOracleWithDigPSpTrueAndDocumentSpecification"),
        ("CB-5.2.7-05", "The id member shall uniquely identify a specific version of the signature policy.",
            RequirementCoverageStatus.OutOfScope, "A registry/minting-process invariant across instances over time, not mechanically checkable from one value object or one unit test — mirrors CBAdESObjectIdentifier.Id's own remarks (no re-assignment of a given id) and this matrix's CB-5.4.1-04 row."),
        ("CB-5.2.7-06", "The digAlgVal component shall be a CBOR array.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignaturePolicyIdentifierMatchesIndependentOracleWithDigPSpTrueAndDocumentSpecification (the flattened [hashAlg, hashValue] pair matches the independent oracle's array byte-exactly)"),
        ("CB-5.2.7-07", "digAlgVal's first element (hashAlg) shall be a digest-algorithm identifier from the IANA COSE Algorithms registry, RFC 9053, or an amending spec.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignaturePolicyIdentifierMatchesIndependentOracleWithDigPSpTrueAndDocumentSpecification"),
        ("CB-5.2.7-08", "digAlgVal's second element (hashValue) shall be the digest of the signature policy document under the first element's algorithm.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignaturePolicyIdentifierMatchesIndependentOracleWithDigPSpTrueAndDocumentSpecification"),
        ("CB-5.2.7-09", "digPSp shall be a CBOR Boolean value.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierDefaultsDigestIsPerSpecificationToFalseWhenAbsent"),
        ("CB-5.2.7-10", "When present and true, digPSp shall indicate the digest was computed as specified in a technical specification.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeSignaturePolicyIdentifierMatchesIndependentOracleWithDigPSpTrueAndDocumentSpecification"),
        ("CB-5.2.7-11", "Absence of digPSp shall be considered as if present and set to false.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierDefaultsDigestIsPerSpecificationToFalseWhenAbsent"),
        ("CB-5.2.7-12", "If digPSp is present and true, the spDSpec qualifier shall be present and shall identify the technical specification.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.ConstructingSignaturePolicyIdentifierWithDigPSpTrueAndNoQualifiersThrows (also CBAdESSignedHeaderModelTests.ConstructingSignaturePolicyIdentifierWithDigPSpTrueAndQualifiersLackingDocumentSpecificationThrows)"),
        ("CB-5.2.7-13", "sigPQuals shall be a non-empty array of qualifiers of the signature policy.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.ConstructingSignaturePolicyIdentifierWithEmptyQualifiersListThrows"),
        ("CB-5.2.7-14", "In COSE_Sign, sigPId shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),

        //Clause 5.2.7.2 — signature-policy qualifiers.
        ("CB-5.2.7-15", "Each signature-policy qualifier shall be a CBOR tagged data item (D11: ruled — the CDDL and Table 6's own 'keys in maps' title govern; read as one-entry maps keyed per Table 6, not CBOR major-type-6 tagging).",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsUriQualifier (also the UserNotice and DocumentSpecification qualifier round trips below)"),
        ("CB-5.2.7-16", "The spURI choice's map key shall be 1 (D11).",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsUriQualifier"),
        ("CB-5.2.7-17", "The spUserNotice choice's map key shall be 2 (D11).",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsUserNoticeQualifier"),
        ("CB-5.2.7-18", "The spDSpec choice's map key shall be 3 (D11).",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsDocumentSpecificationQualifier"),
        ("CB-5.2.7-19", "The spURI qualifier shall contain a URL where a copy of the signature policy document can be obtained.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsUriQualifier"),
        ("CB-5.2.7-20", "The spUserNotice qualifier shall contain information intended for display whenever the signature is validated.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsUserNoticeQualifier"),
        ("CB-5.2.7-21", "The org member of NoticeRef shall indicate the name of the organization.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsUserNoticeQualifier"),
        ("CB-5.2.7-22", "The noticeNumbers member shall be a CBOR array of unsigned integers.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsUserNoticeQualifier"),
        ("CB-5.2.7-23", "At least one of spUserNotice's two members (noticeRef, explText) shall be present.",
            RequirementCoverageStatus.OutOfScope, "Not runtime-enforced this stage — CBAdESSignaturePolicyUserNotice's own remarks document the invariant rather than enforce it (mirroring CBAdESSignatureProductionPlace's convention, but without a codec-level guard); no ConstructingXWithNeitherMemberThrows test exists yet."),
        ("CB-5.2.7-24", "The explText member shall contain the text of the notice to be displayed.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsUserNoticeQualifier"),
        ("CB-5.2.7-25", "The noticeRef member shall name an organization and identify, by noticeNumbers, a group of textual statements prepared by it.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsUserNoticeQualifier"),
        ("CB-5.2.7-26", "The spDSpec member shall identify the technical specification defining the syntax used for producing the signature policy document.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsDocumentSpecificationQualifier"),
        ("CB-5.2.7-27", "The otherQuals member shall be a non-empty CBOR array (D11: per the ruled reading, otherQuals is the *label => value catch-all directly within sigPQuals' own SigPQual maps, not a nested array).",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsOtherQualifierWithIntegerLabel (also CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsOtherQualifierWithTextLabel)"),
        ("CB-5.2.7-28", "Each element in the otherQuals array shall be a qualifier.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsOtherQualifierWithIntegerLabel (also CBAdESSignedHeaderModelTests.TryParseSignaturePolicyIdentifierRoundTripsOtherQualifierWithTextLabel)"),

        //Clause 5.2.8.1 — sigD.
        ("CB-5.2.8-01", "sigD shall be a signed header parameter.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.DetachedObjectIdByUriFlowReconstructsAndValidatesFromWireBytesOnly (also CBAdESSignatureFlowTests.DetachedObjectIdByUriHashFlowVerifiesEveryDigestFromWireBytesOnly — sigD decodes from the signed protected header for both built-in mechanisms)"),
        ("CB-5.2.8-02", "sigD label shall be 267.",
            RequirementCoverageStatus.Tested, "CBAdESRegistryTests.HeaderParameterLabelsMatchTable1AndTable8Assignments"),
        ("CB-5.2.8-03", "sigD shall not appear in CB-AdES signatures whose COSE Payload is attached.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.DetachedObjectsWithAttachedPayloadThrows"),
        ("CB-5.2.8-04", "sigD may appear in CB-AdES signatures whose COSE Payload is detached.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.DetachedObjectIdByUriFlowReconstructsAndValidatesFromWireBytesOnly (also CBAdESSignatureFlowTests.DetachedObjectIdByUriHashFlowVerifiesEveryDigestFromWireBytesOnly)"),
        ("CB-5.2.8-05", "A CB-AdES signature shall have at most one sigD header parameter within each present protected header.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.DetachedObjectIdByUriFlowReconstructsAndValidatesFromWireBytesOnly (satisfied by construction — CBAdESProtectedHeaders.DetachedObjects is a single nullable member of the protected-headers-map aggregate; more than one sigD occurrence in one protected headers map is unrepresentable)"),
        ("CB-5.2.8-06", "sigD shall reference one or more detached data objects.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.ConstructingDetachedObjectsWithAnEmptyListThrows (also CBAdESSignedHeaderModelTests.TryParseDetachedObjectsFailsClosedOnEmptyReferencesArray)"),
        ("CB-5.2.8-07", "sigD shall specify how the referenced objects are processed into the sequence of octets that shall be the COSE Payload.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.ObjectIdByUriPayloadIsOrderPreservingConcatenation (together with CBAdESSignatureCreationTests.ObjectIdByUriHashSignsEmptyPayload and CBAdESSignatureCreationTests.UnknownMechanismWithHandlerSignsHandlerPayload, demonstrating sigD's mechanism dispatch determines exactly how referenced objects become the COSE Payload for both built-in mechanisms and the third-party extension point)"),
        ("CB-5.2.8-08", "sigD shall allow defining different mechanisms for meeting the reference and build-procedure requirements.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeDetachedObjectsMatchesIndependentOracleForObjectIdByUriMechanism (also CBAdESSignedHeaderModelTests.EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism — the mId-keyed dispatch shape, CBAdESDetachedMechanisms.IsKnownMechanism, over two distinct mechanisms); wavecb S3 FX-N additionally exercises the third-party/unknown-mId arm on the validation side: CBAdESSignatureValidationTests.ValidateAsyncSucceedsWhenUnknownMechanismHandlerResolvesPayload, ValidateAsyncFailsWithDetachedObjectUnresolvableWhenUnknownMechanismHandlerThrowsRoutineDereferenceException, ValidateAsyncPropagatesNonRoutineExceptionFromUnknownMechanismHandler, and ValidateAsyncFailsWithDetachedObjectUnresolvableWhenNoUnknownMechanismHandlerIsSupplied"),
        ("CB-5.2.8-09", "sigD shall not be present as a header parameter of a counter signature.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 — no countersignature carrier exists yet to check against."),
        ("CB-5.2.8-10", "Chaining of references shall not be allowed — only data objects directly referenced within sigD shall contribute to the COSE Payload.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.DetachedObjectIdByUriFlowReconstructsAndValidatesFromWireBytesOnly (satisfied by construction — CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync's own remarks record that it calls the dereference delegate exactly once per pars entry and never inspects fetched bytes for further references)"),
        ("CB-5.2.8-11", "If a referenced object itself contains references to other data objects, those further objects shall not contribute to the COSE Payload.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.DetachedObjectIdByUriFlowReconstructsAndValidatesFromWireBytesOnly (same construction argument as CB-5.2.8-10 — the reconstruction loop never re-inspects a fetched object's own content)"),
        ("CB-5.2.8-12", "sigD may also incorporate digest values of the referenced data objects, encapsulated within a CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism"),
        ("CB-5.2.8-13", "sigD may also incorporate any additional information required by its mechanism.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S3 — an open extension point beyond the five named CDDL members; no third-party mechanism is modeled this stage."),
        ("CB-5.2.8-14", "The mId member shall be present.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeDetachedObjectsMatchesIndependentOracleForObjectIdByUriMechanism (mId is one of the two always-written members); CBAdESSerialization.TryParseDetachedObjects's own missing-mId guard is not separately regression-tested this stage"),
        ("CB-5.2.8-15", "mId shall be a URI identifying the mechanism used for referencing and processing each referenced data object.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseDetachedObjectsFailsClosedWhenMechanismIdentifierTagIsNotUri (also CBAdESSignedHeaderModelTests.EncodeDetachedObjectsMatchesIndependentOracleForObjectIdByUriMechanism for the tag-32 encoding)"),
        ("CB-5.2.8-16", "The pars member shall be present.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseDetachedObjectsFailsClosedOnEmptyReferencesArray"),
        ("CB-5.2.8-17", "pars shall be a non-empty array of strings.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseDetachedObjectsFailsClosedOnEmptyReferencesArray (also CBAdESSignedHeaderModelTests.EncodeDetachedObjectsMatchesIndependentOracleForObjectIdByUriMechanism)"),
        ("CB-5.2.8-18", "Each element of pars shall contain a reference to one data object, as required by the mechanism identified by mId.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeDetachedObjectsMatchesIndependentOracleForObjectIdByUriMechanism"),
        ("CB-5.2.8-19", "hashM shall be a digest-algorithm identifier from the IANA COSE Algorithms registry, RFC 9053, or an amending spec.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseDetachedObjectsRoundTripsNonSha2IntegerHashAlgorithmByteExact (also CBAdESSignedHeaderModelTests.TryParseDetachedObjectsRoundTripsTextHashAlgorithmByteExact)"),
        ("CB-5.2.8-20", "The presence of hashM shall be conditional on the identification mechanism; if present, hashV shall also be present.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseDetachedObjectsFailsClosedWhenDigestAlgorithmPresentWithoutDigestValues"),
        ("CB-5.2.8-21", "hashV shall be a non-empty array of byte strings, each the digest of the pars element at the same position.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseDetachedObjectsFailsClosedWhenHashValuesLengthMismatchesReferences (also CBAdESSignedHeaderModelTests.EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism)"),
        ("CB-5.2.8-22", "The presence of hashV shall be conditional on the identification mechanism; if present, hashM shall also be present.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseDetachedObjectsFailsClosedWhenDigestAlgorithmPresentWithoutDigestValues (the codec's single symmetric guard — (hashAlgorithm is null) != (digestValues is null) — trips on either direction; this test exercises the hashM-without-hashV direction, the reverse is not separately regression-tested this stage)"),
        ("CB-5.2.8-23", "ctys shall be a non-empty array of strings, each with content-type semantics per RFC 9052 clause 3.1.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism"),
        ("CB-5.2.8-24", "There shall be as many elements within ctys as within pars.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseDetachedObjectsFailsClosedWhenContentTypesLengthMismatchesReferences"),
        ("CB-5.2.8-25", "Each ctys element shall correspond to the pars element at the same position, except an implied or counter-signed content type, for which that ctys element shall be CBOR null.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism (the first entry's ctys is CBOR null)"),
        ("CB-5.2.8-26", "In COSE_Sign, sigD shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6."),

        //Clause 5.2.8.2.1 — URI-reference dereferencing generalities for the two named sigD mechanisms.
        ("CB-5.2.8.2.1-01", "For the two URI-reference mechanisms, pars's contents shall be an array of strings.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.TryParseDetachedObjectsFailsClosedOnEmptyReferencesArray (also CBAdESSignedHeaderModelTests.EncodeDetachedObjectsMatchesIndependentOracleForObjectIdByUriMechanism — pars is a non-empty array of strings, the S1 model this row restates; re-attributed from OutOfScope now that the sigD dereference-delegate seam consuming that model is built)"),
        ("CB-5.2.8.2.1-02", "Each pars string shall be a URI-reference that, once resolved, is a locator per RFC 3986 clause 1.1.3.",
            RequirementCoverageStatus.OutOfScope, "Not a stage-deferred item — pars entries are opaque strings to this library; RFC 3986 URI-reference syntax and locator semantics are entirely the CBAdESDetachedObjectDereferenceDelegate implementer's obligation (contract R-2, per CBAdESDetachedObjectDereferenceContext's own remarks), never runtime-checked by this library at any stage."),
        ("CB-5.2.8.2.1-03", "Each URI-reference shall refer to one data object.",
            RequirementCoverageStatus.OutOfScope, "Not a stage-deferred item — same reasoning as CB-5.2.8.2.1-02; this is a producer obligation the dereference-delegate implementer relies on, not something this library validates."),
        ("CB-5.2.8.2.1-04", "When resolving a relative URI-reference, a conforming application shall set a default base HTTP-scheme URI per RFC 3986 clause 5.1.4.",
            RequirementCoverageStatus.OutOfScope, "Not a stage-deferred item — CBAdESDetachedObjectDereferenceContext.DefaultBaseUri carries the caller's default base URI opaquely; relative-reference resolution against it is entirely the dereference-delegate implementer's obligation (contract R-2, per that type's own remarks), never resolved by this library at any stage."),
        ("CB-5.2.8.2.1-05", "Dereferencing URI-references in the HTTP scheme shall be supported.",
            RequirementCoverageStatus.OutOfScope, "Not a stage-deferred item — the library ships CBAdESDetachedObjectDereferenceDelegate as the extension point (built and tested this stage); an HTTP client itself is out of scope by design (contract R-2, CBAdESDetachedObjectDereferenceContext's own remarks) and is never built by this library at any stage."),
        ("CB-5.2.8.2.1-06", "Dereferencing a URI-reference in the HTTP scheme shall comply with the Status Code Definitions of RFC 2616 clause 10.",
            RequirementCoverageStatus.OutOfScope, "Not a stage-deferred item — same reasoning as CB-5.2.8.2.1-05; an obsolete-RFC citation (RFC 2616 was superseded by RFC 7230-7235) an HTTP-implementing delegate would have to apply, which is entirely the delegate implementer's obligation (contract R-2), never this library's own concern."),
        ("CB-5.2.8.2.1-07", "Dereferencing URI-references in other locator schemes may be supported.",
            RequirementCoverageStatus.OutOfScope, "Not a stage-deferred item — CBAdESDetachedObjectDereferenceDelegate is scheme-agnostic by design, so a caller MAY implement any locator scheme; whether one does is entirely the delegate implementer's choice (contract R-2), not this library's own concern at any stage."),
        ("CB-5.2.8.2.1-08", "Dereferencing URI-references within another scheme shall be conducted as defined in that scheme's own specification.",
            RequirementCoverageStatus.OutOfScope, "Not a stage-deferred item — same reasoning as CB-5.2.8.2.1-07; conducting a non-HTTP scheme's own dereferencing rule is entirely the delegate implementer's obligation (contract R-2)."),

        //Clause 5.2.8.2.2 — the ObjectIdByURI mechanism.
        ("CB-5.2.8.2.2-01", "The URL identifying the ObjectIdByURI mechanism shall be 'http://uri.etsi.org/19152/ObjectIdByURI'.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeDetachedObjectsMatchesIndependentOracleForObjectIdByUriMechanism (CBAdESDetachedMechanisms.ObjectIdByURI encoded byte-exact against the independent oracle)"),
        ("CB-5.2.8.2.2-02", "For this mechanism, neither hashV nor hashM shall be present.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeDetachedObjectsMatchesIndependentOracleForObjectIdByUriMechanism (no digest supplied; the independent oracle's map carries no hashM/hashV members)"),
        ("CB-5.2.8.2.2-03", "Member ctys may be present for this mechanism.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism (ctys optionality is mechanism-independent in the model)"),
        ("CB-5.2.8.2.2-04", "The semantics and syntax of each ctys element shall be as specified in clause 5.2.8.1.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism"),
        ("CB-5.2.8.2.2-05", "The COSE Payload octet stream shall be the ordered concatenation of each dereferenced pars object, in order.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.ObjectIdByUriPayloadIsOrderPreservingConcatenation (also CBAdESSignatureFlowTests.DetachedObjectIdByUriFlowReconstructsAndValidatesFromWireBytesOnly for the full wire-bytes-only e2e leg, S3 coordinator ruling (4))"),

        //Clause 5.2.8.2.3 — the ObjectIdByURIHash mechanism.
        ("CB-5.2.8.2.3-01", "The URL identifying the ObjectIdByURIHash mechanism shall be 'http://uri.etsi.org/19152/ObjectIdByURIHash'.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism (CBAdESDetachedMechanisms.ObjectIdByURIHash encoded byte-exact)"),
        ("CB-5.2.8.2.3-02", "For this mechanism, hashV and hashM shall be present.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureValidationTests.ValidateAsyncReportsUriHashMechanismDigestViolationWhenHashMIsAbsent (CBAdESDetachedObjectsUriHashMechanismDigestViolation's own RequirementId cites this exact clause; also CBAdESSignatureCreationTests.ObjectIdByUriHashComputesHashVMatchingRegisteredDigest for the positive leg)"),
        ("CB-5.2.8.2.3-03", "Member ctys may be present.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism"),
        ("CB-5.2.8.2.3-04", "The semantics and syntax of hashM, hashV, and ctys shall be as specified in clause 5.2.8.1.",
            RequirementCoverageStatus.Tested, "CBAdESSignedHeaderModelTests.EncodeAndParseDetachedObjectsRoundTripReferenceDigestAndContentTypePerPositionForObjectIdByUriHashMechanism"),
        ("CB-5.2.8.2.3-05", "For computing hashV, each pars-referenced object shall be retrieved as specified in clause 5.2.8.2.1.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.ObjectIdByUriHashComputesHashVMatchingRegisteredDigest (also CBAdESSignatureFlowTests.DetachedObjectIdByUriHashFlowVerifiesEveryDigestFromWireBytesOnly for the validation-side independent re-derivation)"),
        ("CB-5.2.8.2.3-06", "When using this mechanism, the COSE Payload shall contribute as an empty stream to the COSE signature value computation.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.ObjectIdByUriHashSignsEmptyPayload (also CBAdESSignatureFlowTests.DetachedObjectIdByUriHashFlowVerifiesEveryDigestFromWireBytesOnly, S3 coordinator ruling (4))"),
        ("CB-5.2.8.2.3-07", "If the COSE Payload is required for purposes other than the COSE signature value (e.g. adoTst/arcTst), it shall be generated per clause 5.2.8.2.2.",
            RequirementCoverageStatus.Tested, "CBAdESLifecycleFlowTests.PayloadTimestampFlowAcquiresAdoTstOverSigDReconstructedPayloadAndValidatesImprint (flow 10, wavecb S4 coordinator ruling (6)): adoTst's ObjectIdByURIHash-sourced imprint input is now generated per clause 5.2.8.2.2 -- the SAME dereference-and-concatenate reconstruction CB-5.2.8.2.2-05 already proves at the primitive level -- through CBAdESSigDReferencedPayloadTimestampAcquisitionSource and CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput, and the resulting signature validates from wire bytes alone with the verifier's own independent dereference delegate instance over the shared object store. The arcTst half of this row remains deferred to CB-AdES wave stage S5 (arcTst generation orchestration per clause 5.3.5.2), unchanged from the wavecb S3 FX-Q reading."),

        //Clause 5.4.1 — oId/obId.
        ("CB-5.4.1-01", "Instances of obId shall contain a unique and permanent identifier of one data object.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.ObjectIdentifierRoundTripsWithIdOnly"),
        ("CB-5.4.1-02", "Instances of obId may contain a textual description of the nature of the identified object.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.ObjectIdentifierRoundTripsWithIdAndDesc"),
        ("CB-5.4.1-03", "Instances of obId may contain a number of references to documents describing the identified object's nature.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.ObjectIdentifierRoundTripsWithIdAndDocRefs"),
        ("CB-5.4.1-04", "The id member shall contain a permanent identifier; once assigned, it shall not be re-assigned.",
            RequirementCoverageStatus.OutOfScope, "A registry-level invariant across instances minted over time, not something a single value object or a unit test can self-enforce or falsify — CBAdESObjectIdentifier.Id's own remarks record this explicitly; no minting process exists yet this stage."),
        ("CB-5.4.1-05", "The id member's value shall be a URI; an OID identifier shall be encoded as an RFC 3061 URN.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.ObjectIdentifierRoundTripsWithIdOnly (Id is Uri-typed, accepting any well-formed URI including a urn:oid: form without special-casing)"),
        ("CB-5.4.1-06", "When both an OID and a URI identify one object, the URI value should be used in id.",
            RequirementCoverageStatus.OutOfScope, "A caller minting-policy choice, not a mechanically testable library behavior — CBAdESObjectIdentifier accepts whichever Uri the caller supplies."),
        ("CB-5.4.1-07", "The desc member shall contain a short, informal description of the identified data object.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.ObjectIdentifierRoundTripsWithIdAndDesc"),
        ("CB-5.4.1-08", "The docRefs member shall contain an arbitrary number of URI values pointing to documents fully specifying the identified object.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.ObjectIdentifierRoundTripsWithIdAndDocRefs (also CBAdESSharedSyntaxTests.ObjectIdentifierRoundTripsWithAllMembers)"),

        //Clause 5.4.2 — pkiOb.
        ("CB-5.4.2-01", "The pkiOb data type shall be used to incorporate PKI objects, which can be non-CBOR encoded, into the CB-AdES signature.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.PkiObjectRoundTripsWithValOnly"),
        ("CB-5.4.2-02", "The encoding member's value shall be a URI identifying the original PKI object's encoding, from the vocabulary of ETSI EN 319 132-1 clause 5.1.3.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.PkiObjectRoundTripsWithValAndEncoding (Encoding is Uri-typed; the EN 319 132-1 vocabulary itself is an open registry this stage does not validate against)"),
        ("CB-5.4.2-03", "If encoding is absent, val shall be DER-encoded ASN.1 data; otherwise, val shall be encoded as encoding states.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.PkiObjectRoundTripsWithValOnly (default DER reading); CBAdESSharedSyntaxTests.PkiObjectRoundTripsWithValAndEncoding (explicit-encoding case)"),
        ("CB-5.4.2-04", "The specRef member shall contain a URI identifying the specification that defines the encapsulated PKI object.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.PkiObjectRoundTripsWithValAndSpecRef"),

        //Clause 5.4.3.1 — general time-stamp container remarks.
        ("CB-5.4.3.1-01", "Electronic time-stamps within tstContainer may time-stamp isolated components or concatenations of several CB-AdES components.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithMultipleTokensInWireOrder (the container itself is content-agnostic — it carries plain token bytes with no opinion on what was imprinted, satisfying the permissive 'may' by not constraining it)"),

        //Clause 5.4.3.3 — tstContainer/TstToken.
        ("CB-5.4.3.3-01", "tstContainer shall allow encapsulating RFC 3161 electronic time-stamps as well as time-stamps in other formats.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithRfc3161StyleToken (also CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithTypedToken)"),
        ("CB-5.4.3.3-02", "tstContainer shall provide means for managing time-stamps computed on a concatenation of CB-AdES components, including a detached COSE Payload.",
            RequirementCoverageStatus.OutOfScope, "Re-attributed at the wavecb S3 review: deferred to CB-AdES wave stage S2 (the tstContainer component model, already shipped) or S4/S5 — not S3, whose creation/validation orchestrator never requests or attaches a time-stamp token at all (CBAdESProtectedHeaders.PayloadTimestamps is untouched by every S3 test); actually acquiring/attaching adoTst/sigTst/arcTst tokens is S4/S5's deliverable. tstContainer itself (Tested via CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithMultipleTokensInWireOrder) only carries the resulting token(s), never computes an imprint."),
        ("CB-5.4.3.3-03", "tstContainer shall allow encapsulating more than one time-stamp generated for the same component set, e.g. one per TSA.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithMultipleTokensInWireOrder"),
        ("CB-5.4.3.3-04", "tstContainer's tstTokens member shall contain a non-empty array of time-stamp token maps.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.ParseTimestampContainerFailsClosedOnEmptyTokensArray"),
        ("CB-5.4.3.3-05", "TstToken's type member shall identify the token's type; for an RFC 3161 token it shall not be present.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithRfc3161StyleToken (absent case); CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithTypedToken (present case)"),
        ("CB-5.4.3.3-06", "TstToken's encoding member shall identify the token's encoding by URI; for an RFC 3161 token it shall not be present.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithRfc3161StyleToken (also CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithEncodingAndSpecRef)"),
        ("CB-5.4.3.3-07", "TstToken's specRef member shall identify the defining technical specification by URI; for an RFC 3161 token it shall not be present.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithRfc3161StyleToken (also CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithEncodingAndSpecRef)"),
        ("CB-5.4.3.3-08", "TstToken's val member shall contain the encoded token itself; for an RFC 3161 token, the DER-encoded token.",
            RequirementCoverageStatus.Tested, "CBAdESSharedSyntaxTests.TimestampContainerRoundTripsWithRfc3161StyleToken"),
        ("CB-5.4.3.3-09", "Time-stamp containers within uHeaders implicitly identify what they cover by position; no further information in the container is required.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S2 — this is precisely uHeaders' own positional/implicit-coverage design (clause 5.3.1, the load-bearing 'order is semantically significant' rule); unreachable without the uHeaders array container."),

        //Clause 5.3.1 — uHeaders, the unprotected-headers-map array container (stage 2, leg 3).
        ("CB-5.3.1-01", "The uHeaders header parameter shall be a CBOR array whose elements contain CBOR values that are not signed by the CB-AdES signature.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedHeadersTests.RoundTripsMixedElementSequenceByteExactlyPreservingOrder (CBAdESUnsignedHeaders is an ordered sequence type, never a map/dictionary, encoded as a CBOR array of bstr-wrapped elements)"),
        ("CB-5.3.1-02", "The uHeaders header parameter shall contain CBOR values that qualify the CB-AdES signature itself, or the signer, or the COSE Payload.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedHeadersTests.RoundTripsMixedElementSequenceByteExactlyPreservingOrder (exercises one instance of every defined element kind -- sigTst, valData, arcTst, refs, sigRTst, rfsTst, sigPSt, x5chain -- as the closed-sum element type's cases)"),
        ("CB-5.3.1-03", "New unsigned attributes shall always be added at the end of the uHeaders header parameter, which is a CBOR array.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedHeadersTests.AppendReturnsNewInstanceLeavingOriginalUnchanged (also CBAdESUnsignedHeadersTests.PublicSurfaceExposesNoInsertRemoveOrReorderOperation for the API-shape enforcement)"),
        ("CB-5.3.1-04", "The unsigned attributes shall be encapsulated in CBOR byte strings before being placed within the uHeaders header parameter.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedHeadersTests.RoundTripsMixedElementSequenceByteExactlyPreservingOrder (also CBAdESUnsignedHeadersTests.TryParseUnsignedHeadersFailsClosedOnElementNotByteString for the negative enforcement)"),
        ("CB-5.3.1-05", "All the CBOR objects sigPSt, counter signature, sigTst, valData, arcTst, refs, sigRTst and rfsTst shall be placed within the uHeaders header parameter if they are incorporated into the CB-AdES signature.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedHeadersTests.RoundTripsMixedElementSequenceByteExactlyPreservingOrder (all seven Table 8 kinds plus the x5chain arm round-trip as uHeaders elements; the counter-signature arm, labels 11/12, remains out of scope until CB-AdES wave stage S6)"),
        ("CB-5.3.1-06", "The uHeaders CBOR array shall be assigned an identifying tag, and each unsigned attribute shall be assigned a label (Table 8: uHeaders=268, sigTst=1, valData=2, arcTst=3, refs=4, sigRTst=5, rfsTst=6, sigPSt=7).",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedHeadersTests.RoundTripsMixedElementSequenceByteExactlyPreservingOrder (labels 1 through 7 and 33 exercised byte-exact against an independent oracle; also CBAdESRegistryTests.HeaderParameterLabelsMatchTable1AndTable8Assignments for the uHeaders=268 header-parameter label itself)"),
        ("CB-5.3.1-07", "The uHeaders header parameter shall be a non-empty array.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedHeadersTests.ConstructingUnsignedHeadersWithEmptyElementsThrows (also CBAdESUnsignedHeadersTests.TryParseUnsignedHeadersFailsClosedOnEmptyArray for the parse-side mirror)"),
        ("CB-5.3.1-08", "In CB-AdES signatures supported by a COSE_Sign structure, the uHeaders header parameter shall be placed at the signer layer.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 -- needs the COSE_Sign multi-signer structure to distinguish body from signer layer; CBAdESUnsignedHeaders itself is layer-agnostic."),
        ("CB-5.3.1-09", "The uHeaders header parameter shall be incorporated as member of the unprotected header map of the CB-AdES signature.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureFlowTests.AttachedFlowWithUnsignedCertificateChainElementRoundTripsExactlyOneUHeadersElement (uHeaders round-trips as the sole unprotected-headers-map member, decoded from wire bytes alone)"),
        ("CB-5.3.1-10", "The uHeaders header parameter should be the only header parameter incorporated to the unprotected headers map.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureValidationTests.ValidateAsyncFailsClosedWhenUnprotectedMapCarriesExtraMember (also CBAdESSignatureFlowTests.AttachedFlowWithUnsignedCertificateChainElementRoundTripsExactlyOneUHeadersElement for the conformant sole-member shape — CBAdESSignatureSerialization.ParseCBAdESSign1 fails closed on any other unprotected-map member, CB-4.4-01)"),
        ("CB-5.3.1-11", "Any CBOR value that is not specified in the present document should be incorporated as an element of the uHeaders header parameter.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedHeadersTests.TryParseUnsignedHeadersRoundTripsSingleUnrecognizedIntegerLabelElementByteExactly (also CBAdESUnsignedHeadersTests.TryParseUnsignedHeadersRoundTripsSingleUnrecognizedTextLabelElementByteExactly for the tstr-labelled arm)"),

        //Clause 5.3.2 -- sigPSt (stage 2, leg 3).
        ("CB-5.3.2-01", "The sigPSt CBOR map shall contain either the signature policy document referenced in sigPId, or a URI referencing a local store where it can be retrieved.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.SignaturePolicyStoreRoundTripsWithDocumentArmAndNoSpDSpec (also CBAdESUnsignedComponentSerializationTests.ParseSignaturePolicyStoreFailsClosedWhenDocOrLocalUriHasBothArms and ...FailsClosedWhenDocOrLocalUriHasNoArms for the exclusive-choice enforcement, and CBAdESUnsignedComponentTests.ConstructingSignaturePolicyStoreWithNullContentThrows)"),
        ("CB-5.3.2-02", "The sigPolDoc member shall contain the signature policy document encapsulated within a CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.SignaturePolicyStoreRoundTripsWithDocumentArmAndNoSpDSpec"),
        ("CB-5.3.2-03", "The sigPolLocalURI member shall have as value the URI pointing to a local store where the present document can be retrieved.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.SignaturePolicyStoreRoundTripsWithLocalUriArmAndNoSpDSpec (also CBAdESUnsignedComponentSerializationTests.ParseSignaturePolicyStoreFailsClosedOnMissingTag32ForLocalUri for the tag-32 enforcement)"),
        ("CB-5.3.2-04", "The spDSpec member shall identify the technical specification that defines the syntax used for producing the signature policy document.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.SignaturePolicyStoreRoundTripsWithDocumentArmAndSpDSpec"),

        //Clause 5.3.3 -- sigTst (stage 2, leg 3).
        ("CB-5.3.3-01", "The sigTst CBOR map shall encapsulate one or more electronic time-stamps time-stamping the COSE signature value.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureAugmentationTests.AddSignatureTimestampAsync_AppendsOneConformantSigTst_VerifiesIndependentlyAndValidatesAtLevelBT (wavecb S4: sigTst now encapsulates a genuine RFC 3161 token minted by a real Time-Stamping Authority scenario, accepted by the independent BouncyCastle oracle under the authority's own certificate, appended through the shipped CBAdESSignatureAugmentation.AddSignatureTimestampAsync orchestrator, and the augmented signature validates at level B-T). Also CBAdESUnsignedComponentSerializationTests.SignatureTimestampRoundTripsThroughWrapperCodec and CBAdESUnsignedComponentTests.ConstructingSignatureTimestampWithNullContainerThrows for the container-wrapper codec itself."),
        ("CB-5.3.3-02", "The input of the message imprint computation for the time-stamp tokens encapsulated by sigTst shall be the COSE signature value present within the CB-AdES signature.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureAugmentationTests.AddSignatureTimestampAsync_AppendsOneConformantSigTst_VerifiesIndependentlyAndValidatesAtLevelBT (wavecb S4 closes the gap this row's own S2 evidence used to flag: the message-imprint input is now built and acquired over a REAL, composed COSE_Sign1 signature value CBAdESSignatureCreation.SignAsync produces, verified independently, and the resulting sigTst validates through CBAdESSignatureValidation.ValidateAsync at level B-T). The negative binding leg is Tested at CBAdESLevelValidationNegativeTests.ValidateAsyncCollectsTimestampTokenBindingViolationWhenTheTokenImprintDoesNotMatchTheSignatureValue (a token minted over unrelated octets is collected as CBAdESTimestampTokenBindingViolation with reason ImprintMismatch). The message-imprint-input builder's own byte shape remains Tested at CBAdESMessageImprintTests.SigTstMessageImprintReturnsRawSignatureValueBytesUnwrapped and CBAdESMessageImprintTests.SigTstMessageImprintReturnsEmptyBytesForEmptySignatureValue -- CBAdESMessageImprints.BuildSignatureTimestampMessageImprintInput returns exactly the literal COSE signature-value bytes (RFC 9052 clause 4.1), unwrapped and unconcatenated."),

        //Clause 5.3.4 -- valData (stage 2, leg 3).
        ("CB-5.3.4-01", "The valData CBOR map shall contain the certificates identified by xVals, or the revocation data identified by rVals, or both of them.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ValidationDataRoundTripsWithBothCertificateAndRevocationValues (also the certificate-only and revocation-only round trips in the same file)"),
        ("CB-5.3.4-02", "CB-AdES signatures shall not incorporate empty valData maps.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingValidationDataWithNeitherCertificateNorRevocationValuesThrows (also CBAdESUnsignedComponentSerializationTests.ParseValidationDataFailsClosedOnEmptyMap)"),
        ("CB-5.3.4-03", "The xVals array shall have at least one member.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingValidationDataWithEmptyCertificateValuesArrayThrows (also CBAdESUnsignedComponentSerializationTests.ParseValidationDataFailsClosedOnEmptyCertificateValuesArray)"),
        ("CB-5.3.4-04", "An x509Cert item shall contain one DER-encoded X.509 certificate encapsulated within an instance of pkiOb.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ValidationDataRoundTripsWithMultipleCertificateValuesInWireOrder"),
        ("CB-5.3.4-05", "The rVals map shall have at least one member.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingRevocationValuesWithEveryMemberAbsentThrows"),
        ("CB-5.3.4-06", "The crlVals member shall be a non-empty array of DER-encoded X.509 CRLs.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingRevocationValuesWithEmptyCrlValuesArrayThrows (also CBAdESUnsignedComponentSerializationTests.ValidationDataRoundTripsWithCrlValuesOnly and ...ParseValidationDataFailsClosedOnEmptyCrlValuesArray)"),
        ("CB-5.3.4-07", "Each element of the crlVals array shall contain one DER-encoded X.509 CRL encapsulated in a CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ValidationDataRoundTripsWithCrlValuesOnly"),
        ("CB-5.3.4-08", "If the validation data contain one or more Delta CRLs, the crlVals member shall contain the set of CRLs required to provide complete revocation lists.",
            RequirementCoverageStatus.OutOfScope, "Not runtime-enforced this stage -- a cross-CRL completeness policy check (whether a Delta CRL's base CRL is also present) needs a validation pass over the whole assembled valData graph, not a single-instance construction guard; deferred to CB-AdES wave stage S7 (validation/conclusions), alongside CB-A.1.1-18's identical reasoning."),
        ("CB-5.3.4-09", "The ocspVals member shall be a non-empty array of DER-encoded OCSP responses.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingRevocationValuesWithEmptyOcspValuesArrayThrows (also CBAdESUnsignedComponentSerializationTests.ValidationDataRoundTripsWithOcspValuesOnly for the non-empty round trip)"),
        ("CB-5.3.4-10", "Each item of the ocspVals array shall contain a DER-encoded OCSPResponse.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ValidationDataRoundTripsWithOcspValuesOnly"),

        //Clause 5.3.5.1 -- arcTst, general (stage 2, leg 3).
        ("CB-5.3.5.1-01", "The arcTst CBOR map shall encapsulate electronic time-stamps computed on the COSE Payload, the protected headers map(s), the COSE signature value, externally supplied data when present, and the uHeaders array at the time of generating each time-stamp.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle (the semantic summary this row states is precisely what the twelve-step builder assembles; see the CB-5.3.5.3 rows for the operative per-step breakdown)"),
        ("CB-5.3.5.1-02", "If the CB-AdES signature incorporates a counter signature element, all required material for validating the counter signature shall be incorporated before generating the first arcTst CBOR map.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 (needs the countersignature substrate) and S5 (arcTst generation orchestration) -- no counter-signature structure exists yet to order against."),
        ("CB-5.3.5.1-03", "The contents of the counter signature element should not be changed once it has been time-stamped by the arcTst.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 -- same reasoning as CB-5.3.5.1-02; an informative consequence of a structure not yet modeled."),
        ("CB-5.3.5.1-04", "The tstContainer member shall be as specified in clause 5.4.3.3 of the present document.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ArchiveTimestampRoundTripsThroughWrapperCodec (also CBAdESUnsignedComponentTests.ConstructingArchiveTimestampWithNullContainerThrows)"),

        //Clause 5.3.5.2 -- arcTst generation, steps 1-5 (stage 2, leg 3).
        ("CB-5.3.5.2-01", "Step 1: if the CB-AdES signature misses certificates and/or revocation data required for validating its signed objects, these shall be encapsulated within a new valData CBOR map, incorporated before generating the arcTst time-stamp(s).",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S5 (arcTst generation orchestration, per wavecb-contract.md's stage plan) -- deciding 'the signature misses validation material' and appending a gap-filling valData element is an orchestration decision over the whole assembled signature, not built this stage."),
        ("CB-5.3.5.2-02", "Step 2: compute the message imprint for the new archive time-stamp token(s), as indicated in clause 5.3.5.3.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle (the shipped message-imprint builder this step invokes; see the CB-5.3.5.3 rows)"),
        ("CB-5.3.5.2-03", "Step 3: request as many archive time-stamp token(s) as required to the corresponding time-stamp token Service Providers.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S5 (arcTst-specific request orchestration), over the TSA wire seam that lands in CB-AdES wave stage S4 -- no TSA request/response wiring exists yet for arcTst."),
        ("CB-5.3.5.2-04", "Step 4: build a new arcTst CBOR map, encapsulating the time-stamp token(s) issued in the previous step and wrap it.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ArchiveTimestampRoundTripsThroughWrapperCodec (the tstContainer-shaped arcTst wrapper this step builds)"),
        ("CB-5.3.5.2-05", "Step 5: wrap the arcTst CBOR map in a CBOR byte string and incorporate it as the last element in the uHeaders CBOR array.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedHeadersTests.AppendReturnsNewInstanceLeavingOriginalUnchanged (also CBAdESUnsignedHeadersTests.RoundTripsMixedElementSequenceByteExactlyPreservingOrder, which round-trips an arcTst element bstr-wrapped in place)"),

        //Clause 5.3.5.3 -- the arcTst message-imprint algorithm, twelve steps plus the validation variant (stage 2, leg 3; D1 ruling on the closing sentence).
        ("CB-5.3.5.3-01", "For computing the input to the message imprint computation indicated in clause 5.3.5.2 step 2, the steps listed below shall be performed.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle (a full, byte-exact run of the twelve-step algorithm against an independently assembled oracle)"),
        ("CB-5.3.5.3-02", "Step 1: initialize an empty CBOR array.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle (the array-length header of every expected oracle value is asserted byte-exact)"),
        ("CB-5.3.5.3-03", "Step 2: add a context text string, 'Signature' for COSE_Sign, 'Signature1' for COSE_Sign1, or the RFC 9338 clause 3.3 context string for a counter signature.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle ('Signature1'; also CBAdESMessageImprintTests.ArcTstGenerationCoseSignWithSignerProtectedHeaderPresentMatchesIndependentOracle for the 'Signature' arm; the RFC 9338 counter-signature arm is deferred to CB-AdES wave stage S6)"),
        ("CB-5.3.5.3-04", "Step 3: add the protected header from the body layer, encapsulated in a CBOR byte string, or a zero-length byte string if absent.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle (present; also CBAdESMessageImprintTests.ArcTstGenerationCoseSign1DetachedPayloadMatchesIndependentOracle for the zero-length sentinel)"),
        ("CB-5.3.5.3-05", "Step 4: if built on COSE_Sign, add the signer layer's protected header (or a zero-length byte string if absent); COSE_Sign1 has no explicit branch for this step.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSignWithSignerProtectedHeaderPresentMatchesIndependentOracle (also CBAdESMessageImprintTests.ArcTstGenerationCoseSignWithSignerProtectedHeaderAbsentUsesZeroLengthSentinel and ...ThrowsWhenSignerProtectedHeaderNullnessMismatchesStructure for the leg-3 step-4 trap's guard)"),
        ("CB-5.3.5.3-06", "Step 5: add the externally supplied data from the application, encapsulated in a CBOR byte string, or a zero-length byte string if none was supplied.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1DetachedPayloadMatchesIndependentOracle (present; also CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle for the zero-length sentinel)"),
        ("CB-5.3.5.3-07", "Step 6: if sigD is absent, add the CBOR byte string of the payload field, or the retrieved detached COSE Payload bytes wrapped in one if the payload field is absent.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle (payload field present; also CBAdESMessageImprintTests.ArcTstGenerationCoseSign1DetachedPayloadMatchesIndependentOracle for the detached-and-retrieved case)"),
        ("CB-5.3.5.3-08", "Step 7: if sigD is present, retrieve and concatenate the bytes resulting from processing sigD.pars per clause 5.2.8.2.2, then encapsulate the concatenation in one CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationSigDBranchConcatenatesThenEncapsulatesProcessedPars"),
        ("CB-5.3.5.3-09", "Step 8: if built on a version-2 RFC 9338 counter signature, add the other_fields CBOR array.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S6 -- needs the RFC 9338 countersignature substrate; CBAdESArchiveTimestampImprintContext.CountersignatureOtherFields exists as a field but is always null this stage (per CBAdESMessageImprintTests's own BuildArcTstContext helper)."),
        ("CB-5.3.5.3-10", "Step 9: add the CBOR byte string in the signature component.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle"),
        ("CB-5.3.5.3-11", "Step 10: if built on COSE_Sign, take the elements in the uHeaders header parameter from the signer layer, in wire order, and add them (or a zero-length byte string if the signer layer has no uHeaders).",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationAppendsMultiElementUHeadersInWireOrder (the shipped builder's own remarks record that it does not re-derive the signer-vs-body layer choice -- the same UHeadersEncodedArray-append code path serves both step 10 and step 11, differentiated only by which layer's already-encoded bytes the caller supplies; also CBAdESMessageImprintTests.ArcTstGenerationCoseSignWithSignerProtectedHeaderPresentMatchesIndependentOracle for the COSE_Sign zero-length-sentinel sub-case)"),
        ("CB-5.3.5.3-12", "Step 11: else if built on COSE_Sign1, take the elements in the uHeaders header parameter from the body layer, in wire order, and add them (or a zero-length byte string if the body layer has no uHeaders).",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationAppendsMultiElementUHeadersInWireOrder (also CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle for the zero-length-sentinel sub-case)"),
        ("CB-5.3.5.3-13", "Step 12: encode the generated CBOR array in a CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle (D1: the returned bytes ARE this final encoding, asserted byte-exact against the independent oracle, per the class's own D1/step-12 remarks)"),
        ("CB-5.3.5.3-14", "Validation variant, step 10: if COSE_Sign, take the signer-layer uHeaders elements that precede the arcTst under validation, in wire order (or a zero-length byte string if uHeaders is absent).",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstValidationAppendsOnlyElementsPrecedingTargetIndexAndDiffersFromGenerationByExcludedSuffix (the shipped validation builder does not re-derive the signer-vs-body layer choice, the same prefix-selection code path serving both this row and CB-5.3.5.3-15); the absent-uHeaders sentinel arm is Tested via CBAdESMessageImprintTests.ArcTstValidationUsesZeroLengthSentinelWhenUHeadersAbsentRegardlessOfElementIndex and the present-but-empty-prefix asymmetry via CBAdESMessageImprintTests.ArcTstValidationAtIndexZeroWithPresentUHeadersDiffersFromAbsentUHeadersBySentinelItem (D13)"),
        ("CB-5.3.5.3-15", "Validation variant, step 11: else if COSE_Sign1, take the body-layer uHeaders elements that precede the arcTst under validation, in wire order (or a zero-length byte string if uHeaders is absent).",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstValidationAppendsOnlyElementsPrecedingTargetIndexAndDiffersFromGenerationByExcludedSuffix (the same prefix-selection code path serves both this row and CB-5.3.5.3-14); the absent-uHeaders sentinel arm is Tested via CBAdESMessageImprintTests.ArcTstValidationUsesZeroLengthSentinelWhenUHeadersAbsentRegardlessOfElementIndex and the present-but-empty-prefix asymmetry via CBAdESMessageImprintTests.ArcTstValidationAtIndexZeroWithPresentUHeadersDiffersFromAbsentUHeadersBySentinelItem (D13)"),
        ("CB-5.3.5.3-16", "D1 (contract R-6, RULED): the message imprint computation input shall be the CBOR byte string resulting from step 12 -- the spec's closing sentence literally names 'step 11', which produces no byte string.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.ArcTstGenerationCoseSign1AttachedPayloadMatchesIndependentOracle (the recorded reading is documented on CBAdESMessageImprints's own D1 remarks; every expected oracle value in this test class is the fully-assembled array's own encoding, never wrapped a further time)"),

        //Clause 6 -- baseline-level presence rules and additional requirements (leg 4). wavecb S3 (FX-O) seeded
        //the four rows that stage's shipped surface actually exercised; wavecb S4 adds 30 more -- the clause
        //6.1/6.2.2/6.3-standalone notation model (data-only, cite the m1 CBAdESBaselineLevelTableTests registry
        //tests) and the Table 14 rows/lettered requirements the B-T/B-LT augmentation-and-validation surface
        //genuinely reaches. The remaining leg-4 rows (CB-6.3-04..20's header-parameter cells, CB-6.3-29's arcTst
        //row and requirements j/k, and every S7-owned conditioned-presence predicate) are an explicit follow-up
        //(an S7 candidate, recorded in the fix report), not silently dropped.
        ("CB-6.1-01", "Four CB-AdES baseline signature levels are defined, additive: B-B (signed header parameters and generation-time uHeaders components), B-T (a trusted token proving the signature existed at a date/time), B-LT (all material required to validate the signature long-term), and B-LTA (electronic time-stamps enabling validation long after generation, for long-term integrity).",
            RequirementCoverageStatus.Tested, "CBAdESLifecycleFlowTests.LifecycleFlowCreatesBBAugmentsToBTThenBLTAndValidatesAtEachStage (the four-level enumeration is exercised end to end: a B-B signature is augmented to B-T with sigTst, validated at B-T on its own wire bytes, then augmented to B-LT with valData and validated again -- each level's requirements strictly ADD to the lower level's, never replacing or removing earlier content, matching the additive relationship this row states). Also CBAdESBaselineLevelTableTests.LevelSetContainsReflectsSingleLevelMembership: CBAdESBaselineLevels.All enumerates exactly the closed four-level set B-B/B-T/B-LT/B-LTA the registry's own presence/cardinality model is keyed on."),
        ("CB-6.2.1-02", "MD5 algorithm shall not be used as digest algorithm.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.X5TWithMd5DigestThrows (the x5t site; also CBAdESSignatureCreationTests.CertificateDigestsEntryWithMd5DigestThrows for the x5ts site, CBAdESSignatureCreationTests.SignaturePolicyIdentifierDigestWithMd5DigestThrows for the sigPId site, and CBAdESSignatureCreationTests.DetachedObjectsHashAlgorithmMd5Throws for the sigD.hashM site -- all four asserted directly against CBAdESHeaderRules's shared MD5 denylist; CBAdESSignatureValidationTests.ValidateAsyncReportsMd5DigestAlgorithmViolationOnTextIdentifier covers the fifth site, the validation-side wire-decoded leg, independently minted and reporting CBAdESMd5DigestAlgorithmViolation)"),
        ("CB-6.2.2-01", "A Table 14 row either specifies requirements for a header parameter, another signature's component, or a service; a service can be provided by different mechanisms (service provision options, SPO), expressed as one row for the service's own requirement, followed by two or more SPO rows.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.ServiceRowGroupsItsTwoServiceProvisionOptionRowsWithOrSatisfactionAndValDataPreference (the one registered CBAdESTableRowKind.Service row resolves its two CBAdESTableRowKind.ServiceProvisionOption children through CBAdESBaselineLevelTable.ServiceProvisionOptionsFor). Also CBAdESBaselineLevelTableTests.RowKindCountsMatchTheDocumentedTenThirteenOneTwoSplit for the leaf/composite row-kind split across the whole registry (10 header-parameter, 13 component, 1 service, 2 service-provision-option)."),
        ("CB-6.2.2-02", "Column 1 encodes row kind by prefix: cell starting with \"Service\" is a service row; cell starting with \"SPO\" is a service-provision-option row; otherwise the cell is a plain header-parameter/component name.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.RowKindCountsMatchTheDocumentedTenThirteenOneTwoSplit (row kind is a typed CBAdESTableRowKind member the registry pre-classifies, never a runtime string-prefix parse at this layer). Also CBAdESBaselineLevelTableTests.ServiceRowGroupsItsTwoServiceProvisionOptionRowsWithOrSatisfactionAndValDataPreference for CBAdESBaselineLevelTable.IsServiceRow/IsServiceProvisionOptionRow discriminating the service row from its two SPO children."),
        ("CB-6.2.2-03", "Presence value \"shall be present\": the header parameter/component shall be incorporated into the signature, shall conform to the document referenced in the References column, further profiled by the Requirements-column references, with the cardinality in the Cardinality column.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.AlgIsMandatoryAndSingleValuedAtEveryLevel (alg's CBAdESPresence.ShallBePresent bundles mandatory inclusion, its clause 5.1.2 reference, and its exactly-one cardinality at every level, matching this presence value's three-part composition)"),
        ("CB-6.2.2-04", "Presence value \"shall not be present\": the header parameter/component shall not be incorporated into the signature.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.ShouldNotBePresentIsTypeLevelDistinguishableFromShallNotBePresent (refs's CBAdESPresence.ShallNotBePresent at B-LT/B-LTA). Also CBAdESBaselineLevelTableTests.RefsSigRTstAndRfsTstShareTheSameLevelSplitCardinalityShape for the same hard exclusion on sigRTst and rfsTst, paired with their B-LT/B-LTA cardinality collapsing to exactly zero."),
        ("CB-6.2.2-05", "Presence value \"may be present\": the header parameter/component may be incorporated, and (if incorporated) shall conform to the referenced document, profiled by the Requirements-column references, with the cardinality in the Cardinality column.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.UniformPresenceAppliesTheSameValueAtAllFourLevels (constructs and reads back CBAdESPresence.MayBePresent at every level through CBAdESRowPresence.Uniform, the shape most of Table 14's level-invariant header-parameter rows use)"),
        ("CB-6.2.2-06", "Presence value \"shall be provided\": the service named in column 1 shall be provided as further specified by its SPO rows; only appears on service rows, never on header-parameter/component rows.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.ServiceRowGroupsItsTwoServiceProvisionOptionRowsWithOrSatisfactionAndValDataPreference (the validation-data-for-time-stamps row is confirmed service-only through CBAdESBaselineLevelTable.IsServiceRow, carries a null Cardinality and null Reference -- the service row's own '-' cells -- and resolves exactly two SPO children. The registry itself assigns CBAdESPresence.ShallBeProvided at B-LT/B-LTA on this same row, per CBAdESBaselineLevelTable's own source, though this test does not assert that value by name -- a residual assertion gap flagged for the review wave)"),
        ("CB-6.2.2-07", "Presence value \"conditioned presence\": incorporation of the item in column 1 is conditioned per the Requirements-column references and the specs/clauses in the References column, with the Cardinality-column cardinality.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.X5ChainRecordsItsConditionClauseSeparatelyFromItsOwnReferenceClauseTrap2 (x5chain/x5t/x5ts's CBAdESPresence.ConditionedPresence carries its own PresenceConditionClauses pointer to clause 5.2.2, the externally-evaluated predicate this presence value requires). Also CBAdESBaselineLevelTableTests.ValDataCardinalityIsLevelInvariantDespiteLevelSplitPresence for valData's ConditionedPresence at B-LT/B-LTA."),
        ("CB-6.2.2-08", "Presence value \"*\": the header parameter/component (or service) identified in column 1 should not be incorporated (provided) at that level; upper levels may specify other requirements. Incorporating a uHeaders component marked \"*\" can make a higher level unreachable except by removing that component.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.ShouldNotBePresentIsTypeLevelDistinguishableFromShallNotBePresent (CBAdESPresence.ShouldNotBePresent is a distinct enum member from ShallNotBePresent, exactly six presence values total per CB-6.2.2-03..08). Also CBAdESBaselineLevelTableTests.SigTstPresenceIsSoftNegativeAtBBAndMandatoryFromBTOnward for the documented forward-compatibility consequence -- sigTst's own '*' at B-B becomes ShallBePresent from B-T onward, the 'upper levels may specify other requirements' case this presence value anticipates."),
        ("CB-6.2.2-09", "Cardinality tokens: 0 = shall not incorporate any instance; 1 = shall incorporate exactly one instance; 0 or 1 = shall incorporate zero or one instance; >=0 = shall incorporate zero or more instances; >=1 = shall incorporate one or more instances. If cardinality is level-invariant only these tokens appear; otherwise the cell states cardinality per level.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.SigTstReproducesTheDuplicatedD2CardinalityLineWithoutDeduplication (the level-split cell format, four stacked sub-lines including the genuine D2 duplicate). Also CBAdESBaselineLevelTableTests.RefsSigRTstAndRfsTstShareTheSameLevelSplitCardinalityShape and CBAdESBaselineLevelTableTests.ValDataCardinalityIsLevelInvariantDespiteLevelSplitPresence for the row-wide-versus-level-split cardinality distinction, and CBAdESBaselineLevelTableTests.ArcTstIsBLtaExclusiveAndMandatoryOnceReached for the CBAdESCardinality.OneOrMore token."),
        ("CB-6.2.2-10", "Column \"References\" contains either this document's clause number (own header parameters) or an external document+clause reference (other signature's components).",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.AlgIsMandatoryAndSingleValuedAtEveryLevel (alg's Reference is a CBAdESInternalClauseReference naming this document's own clause 5.1.2). Also CBAdESBaselineLevelTableTests.ReferenceIsNullOnlyForTheDocumentedDashRows for the null arm Table 14's own '-' cells require. Every registered row's Reference is a CBAdESInternalClauseReference -- Table 14 never actually points at an external document's own clause for any of the 26 rows this registry carries, so the tagged union's external-document arm exists in the type but has no row exercising it this stage, a residual coverage gap, not an unbuilt capability."),
        ("CB-6.2.2-11", "Column \"Additional requirements and notes\" contains numeric note references and/or lettered additional-requirement references, both listed below Table 14.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.AnnotationsMatchTheLegFourReportForEveryAnnotatedRow (every annotated row's lettered-requirement and note-number sets are checked against the leg-4 report, spot-checked across every annotated row plus several carrying none). Also CBAdESBaselineLevelTableTests.EveryLetteredRequirementFromAThroughKAppearsOnAtLeastOneRow for the full a-through-k coverage sweep."),
        ("CB-6.3-01", "The four CB-AdES signature levels specified in clause 6 shall be built as specified in clause 4 of the present document.",
            RequirementCoverageStatus.Tested, "CBAdESLifecycleFlowTests.LifecycleFlowCreatesBBAugmentsToBTThenBLTAndValidatesAtEachStage (satisfied by construction -- CBAdESSignatureAugmentation/CBAdESSignatureValidation never define an alternate signature-building pipeline; every level transition parses, augments, and re-serializes the SAME COSE_Sign1 structure CBAdESSignatureCreation/CoseSerialization compose per clause 4, adding per-level components on top of it, never replacing the clause-4 build)"),
        ("CB-6.3-02", "In CB-AdES baseline signatures, the components acting as electronic time-stamp containers shall encapsulate only IETF RFC 3161 (updated by RFC 5816) time-stamp tokens.",
            RequirementCoverageStatus.Tested, "CBAdESLevelValidationNegativeTests.ValidateAsyncCollectsTimestampTokenNotBaselineViolationForATypedTokenAtLevelBaseline (an independently minted sigTst token carrying a type member is collected as CBAdESTimestampTokenNotBaselineViolation, even at level B-B where sigTst's own presence is legal). Also CBAdESLevelRulesTests.Check_TimestampTokenNotBaseline_SigTstWithTypedToken_ReturnsViolation and CBAdESLevelRulesTests.Check_TimestampTokenNotBaseline_ArcTstWithEncodedToken_ReturnsViolationForArchiveTimestampKind for the shared rule surface checking both the type and encoding discriminator fields across both container kinds, and CBAdESLevelValidationNegativeTests.ValidateAsyncSucceedsForAConformantSignatureTimestampAtLevelBT for the positive leg -- one genuine, untyped RFC 3161 legacy-shape token validates."),
        ("CB-6.3-03", "Any header parameter specified in IETF RFC 9052 or IETF RFC 9360, not further profiled in clause 5.1, may be present (cardinality 0 or 1) in all four levels.",
            RequirementCoverageStatus.OutOfScope, "Not runtime-enforced this stage -- CBAdESLevelRules never inspects, caps, or rejects an unprofiled RFC 9052/9360 header at any baseline level; this row's own per-level cardinality claim (0 or 1) is untouched by the wavecb S4 level-rule surface. The signed-header placement half of the same allowance is already Tested independent of level under CB-4.4-07 (CBAdESSignatureCreationTests.UnprofiledX5BagLabelRoundTripsByteExactThroughCreateAndValidate); flagged for the review wave as a residual gap, not an unbuilt capability."),
        ("CB-6.3-10", "CWT Claims (enclosing iat) shall be present at all 4 levels; cardinality 1; ref clause 5.1.9; additional requirement (a).",
            RequirementCoverageStatus.Tested, "CBAdESSignatureValidationTests.ValidateAsyncReportsCwtClaimsMissingViolationWhenCwtClaimsIsAbsent (wavecb S3 FX-E flip: CWT Claims absence is now a rules-surface CBAdESCwtClaimsMissingViolation, not a parse-time CBAdESMalformedEncodingFailure -- an independently minted, wire-decoded message with no label-15 member reports it; also CBAdESSignatureCreationTests.MissingCwtClaimsThrowsCitingCB6310 for the creation-side guard, asserted directly against the same CBAdESHeaderRules.EnsureConformant call)"),
        ("CB-6.3-21", "sigTst: presence B-B = \"*\" (should not be present); B-T/B-LT/B-LTA = shall be present; cardinality is level-split: B-B >=0; B-T/B-LT/B-LTA >=1; B-LT/B-LTA additionally state 0 (twice, D2); ref clause 5.3.3; additional requirements c, d; note 7.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.SigTstPresenceIsSoftNegativeAtBBAndMandatoryFromBTOnward (the presence half: ShouldNotBePresent at B-B, ShallBePresent from B-T onward) and CBAdESBaselineLevelTableTests.SigTstReproducesTheDuplicatedD2CardinalityLineWithoutDeduplication (the cardinality half, D2 cited at this row per contract R-6: the genuine four-sub-line stack, including the duplicated 'B-LT, B-LTA: 0' line, reproduced verbatim rather than deduplicated). The presence rule is enforced end to end by CBAdESLifecycleFlowTests.LifecycleFlowBBBytesFailClosedWhenValidatedAtBTForMissingSignatureTimestamp and CBAdESLevelValidationNegativeTests.ValidateAsyncCollectsSignatureTimestampMissingViolationWhenSigTstIsAbsentAtLevelBT (CBAdESSignatureTimestampMissingViolation), with the positive leg at CBAdESLifecycleFlowTests.LifecycleFlowCreatesBBAugmentsToBTThenBLTAndValidatesAtEachStage and CBAdESLevelValidationNegativeTests.ValidateAsyncSucceedsForAConformantSignatureTimestampAtLevelBT. Additional requirement (c), one token per instance, is Tested through the augmentation orchestrator at CBAdESSignatureAugmentationTests.AddSignatureTimestampAsync_AppendsOneConformantSigTst_VerifiesIndependentlyAndValidatesAtLevelBT and CBAdESSignatureAugmentationTests.AddSignatureTimestampAsync_CalledTwice_AppendsTwoDistinctSigTstInstancesEachWithOneToken (multi-TSA is repeated calls appending sibling elements, never a second token folded into one instance, per Table 14 note 7), with the negative collect-posture leg at CBAdESLevelValidationNegativeTests.ValidateAsyncCollectsSignatureTimestampTokenCountViolationWhenSigTstEncapsulatesTwoTokens. Additional requirement (d), the token's genTime preceding certificate expiry/revocation, is Tested at CBAdESSignatureAugmentationTests.AddSignatureTimestampAsync_TokenGenTimeAfterCertificateExpiry_ThrowsTypedFailure_NothingAppended_MeteredPoolBalanced and CBAdESSignatureAugmentationTests.AddSignatureTimestampAsync_TokenGenTimeAtOrAfterRevocationInstant_ThrowsTypedFailure_NothingAppended_MeteredPoolBalanced."),
        ("CB-6.3-a", "Requirement for iat: the generator shall include the claimed UTC time when the signature was generated as content of the iat member of the CWT Claims header parameter.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.ConstructingCwtClaimsWithNonZeroOffsetThrowsCitingCB63a (the negative leg, added in the same wavecb S3 FX-O change: CBAdESCwtClaims's own constructor rejects a non-zero-offset DateTimeOffset before either CBAdESHeaderRules or CBAdESSignatureCreation ever run; also CBAdESSignatureCreationTests.SignedProtectedHeaderCarriesCwtClaimsIat for the positive leg -- a genuinely UTC claimed signing time is carried through to the wire's iat member -- together the full requirement, both the accepted UTC content and the rejected non-UTC content, is covered)"),
        ("CB-6.3-b", "Requirement for sigPSt: it may be incorporated only if sigPId is also incorporated and contains the digVal member with the digest value of the signature policy document; otherwise sigPSt shall not be incorporated.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureCreationTests.SignaturePolicyStoreWithoutSigPIdThrows (the negative leg -- sigPSt present, sigPId absent, asserted through the shipped CBAdESSignatureCreation.SignAsync composition; also CBAdESSignatureCreationTests.SignaturePolicyStoreWithSigPIdSucceeds for the positive leg -- sigPId's own constructor makes digVal unconditionally required, satisfying the gate's digest half by construction); creation-side-only exercise -- neither leg round-trips through CBAdESSignatureValidation.ValidateAsync from wire bytes this stage"),
        ("CB-6.3-c", "Requirement for sigTst: each sigTst shall contain only one electronic time-stamp.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureAugmentationTests.AddSignatureTimestampAsync_AppendsOneConformantSigTst_VerifiesIndependentlyAndValidatesAtLevelBT (exactly one token per sigTst instance, over a genuine RFC 3161 token). Also CBAdESSignatureAugmentationTests.AddSignatureTimestampAsync_CalledTwice_AppendsTwoDistinctSigTstInstancesEachWithOneToken (multi-TSA is repeated calls appending sibling elements, per Table 14 note 7), and CBAdESLevelValidationNegativeTests.ValidateAsyncCollectsSignatureTimestampTokenCountViolationWhenSigTstEncapsulatesTwoTokens / CBAdESLevelRulesTests.Check_SignatureTimestampTokenCount_TwoTokens_ReturnsViolationWithCount for the negative collect-posture leg."),
        ("CB-6.3-d", "Requirement for sigTst: the electronic time-stamp encapsulated within sigTst shall be created before the signing certificate has been revoked or has expired.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureAugmentationTests.AddSignatureTimestampAsync_TokenGenTimeAfterCertificateExpiry_ThrowsTypedFailure_NothingAppended_MeteredPoolBalanced (CBAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp, nothing appended, the metered pool balanced). Also CBAdESSignatureAugmentationTests.AddSignatureTimestampAsync_TokenGenTimeAtOrAfterRevocationInstant_ThrowsTypedFailure_NothingAppended_MeteredPoolBalanced (CBAdESAugmentationFailureKind.SigningCertificateRevokedBeforeTimestamp), and CBAdESSignatureAugmentationTests.CBAdESSignatureTimestampContext_EnforceValidityWithNoCertificate_IsRepresentableButRefusedLater for the enforce-without-a-certificate smoke leg."),
        ("CB-6.3-22", "valData: presence B-B/B-T = \"*\"; B-LT/B-LTA = conditioned presence; cardinality >=0 (level-invariant); ref clause 5.3.4; additional requirements e, f.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.ValDataCardinalityIsLevelInvariantDespiteLevelSplitPresence (the presence half: ShouldNotBePresent at B-B/B-T, ConditionedPresence at B-LT/B-LTA, against a single level-invariant ZeroOrMore cardinality statement). The presence transition is exercised end to end by CBAdESLifecycleFlowTests.LifecycleFlowCreatesBBAugmentsToBTThenBLTAndValidatesAtEachStage (valData placed via CBAdESSignatureAugmentation.AddValidationData at the B-T-to-B-LT transition, validated at B-LT) and CBAdESLevelValidationNegativeTests.ValidateAsyncSucceedsForAConformantBLTMessageWithValidationDataAndNoReferences. Additional requirements (e)/(f), duplicate-certificate/revocation avoidance, are Tested at CBAdESSignatureAugmentationTests.AddValidationData_DeduplicatesAgainstMaterialAlreadyPresent_AndLeavesWireBytesUnchangedWhenNothingNew (an already-present certificate is skipped on a later call, and a call offering nothing new leaves the wire bytes byte-for-byte unchanged)."),
        ("CB-6.3-23", "refs (Annex A.1.1): presence B-B/B-T = \"*\"; B-LT/B-LTA = shall not be present; cardinality level-split: B-B/B-T >=0; B-LT/B-LTA 0; ref clause A.1.1; additional requirement g.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.RefsSigRTstAndRfsTstShareTheSameLevelSplitCardinalityShape (the registry data: ShallNotBePresent and ExactlyZero at B-LT/B-LTA for refs). The forbidding rule is Tested at CBAdESLevelValidationNegativeTests.ValidateAsyncCollectsRefsFamilyForbiddenViolationWhenReferencesArePresentAtLevelBLT and CBAdESLevelRulesTests.Check_RefsFamilyForbidden_ReferencesAtLevelBLT_ReturnsViolation (CBAdESRefsFamilyForbiddenViolation, RequirementId CB-6.3-23), with the positive B-T leg at CBAdESLevelRulesTests.Check_RefsFamilyForbidden_ReferencesAtLevelBT_NoViolation. The strip-on-upgrade removal itself is Tested end to end at CBAdESLifecycleFlowTests.ReferencesFamilyFlowCreatesRefsSigRTstAndRfsTstThenUpgradesToBLTStrippingTheFamily and CBAdESSignatureAugmentationTests.StripReferencesForLongTerm_RemovesRefsFamilyElements_RetainsOthersByteExact."),
        ("CB-6.3-24", "sigRTst (Annex A.1.2.1): presence B-B/B-T = \"*\"; B-LT/B-LTA = shall not be present; cardinality level-split: B-B/B-T >=0; B-LT/B-LTA 0; ref clause A.1.2.1.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.RefsSigRTstAndRfsTstShareTheSameLevelSplitCardinalityShape (the registry data, shared shape with refs and rfsTst). The forbidding rule is Tested at CBAdESLevelRulesTests.Check_RefsFamilyForbidden_SignatureAndReferencesTimestampAtLevelBLTA_ReturnsViolation (CBAdESRefsFamilyForbiddenViolation, RequirementId CB-6.3-24). The strip-on-upgrade removal is Tested end to end at CBAdESLifecycleFlowTests.ReferencesFamilyFlowCreatesRefsSigRTstAndRfsTstThenUpgradesToBLTStrippingTheFamily and CBAdESSignatureAugmentationTests.StripReferencesForLongTerm_RemovesRefsFamilyElements_RetainsOthersByteExact."),
        ("CB-6.3-25", "rfsTst (Annex A.1.2.2): presence B-B/B-T = \"*\"; B-LT/B-LTA = shall not be present; cardinality level-split: B-B/B-T >=0; B-LT/B-LTA 0; ref clause A.1.2.2.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.RefsSigRTstAndRfsTstShareTheSameLevelSplitCardinalityShape (the registry data, shared shape with refs and sigRTst). The forbidding rule is Tested at CBAdESLevelRulesTests.Check_RefsFamilyForbidden_ReferencesTimestampAtLevelBLT_ReturnsViolation (CBAdESRefsFamilyForbiddenViolation, RequirementId CB-6.3-25). The strip-on-upgrade removal is Tested end to end at CBAdESLifecycleFlowTests.ReferencesFamilyFlowCreatesRefsSigRTstAndRfsTstThenUpgradesToBLTStrippingTheFamily and CBAdESSignatureAugmentationTests.StripReferencesForLongTerm_RemovesRefsFamilyElements_RetainsOthersByteExact (also CBAdESSignatureAugmentationTests.StripReferencesForLongTerm_WhenEveryElementIsRefsFamily_ResultCarriesNoUHeadersMember for the all-refs-family-stripped edge, and CBAdESSignatureAugmentationTests.StripReferencesForLongTerm_MeteredPoolBalancedAfterSuccessfulStrip for the ownership-transfer discipline)."),
        ("CB-6.3-26", "Service \"Incorporation of validation data for electronic time-stamps\": B-B/B-T = \"*\"; B-LT/B-LTA = shall be provided; cardinality n/a (service row); ref n/a; additional requirements h, i; note 8.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.ServiceRowGroupsItsTwoServiceProvisionOptionRowsWithOrSatisfactionAndValDataPreference (the registry data: a service-only row with two SPO children, CB-6.3-27/CB-6.3-28). The service check is Tested at CBAdESLevelRulesTests.Check_ValidationDataService_AtLevelBLTWithNeitherSpo_ReturnsViolation (CBAdESTimestampValidationDataServiceViolation when neither SPO is satisfied) and CBAdESLevelRulesTests.Check_ValidationDataService_AtLevelBT_NotEvaluated_NoViolation (the service is not evaluated below B-LT). The valData SPO satisfying the service end to end is Tested at CBAdESLifecycleFlowTests.LifecycleFlowCreatesBBAugmentsToBTThenBLTAndValidatesAtEachStage and CBAdESMultiServerWireFlowTests.CreatesAugmentsToBLTAcrossTwoKestrelHostsAndReachesLevelAwareValidSignatureWithLiveOcsp (valData placed over a genuine RFC 6960 OCSP round trip against a real Kestrel host)."),
        ("CB-6.3-27", "SPO valData: B-B/B-T = \"*\"; B-LT/B-LTA = conditioned presence; cardinality >=0; ref clause 5.3.4; no separate letter (governed by the service's h/i).",
            RequirementCoverageStatus.Tested, "CBAdESLevelRulesTests.Check_ValidationDataService_AtLevelBLTWithValidationDataElement_NoViolation (a valData element alone satisfies the service). Also CBAdESLifecycleFlowTests.LifecycleFlowCreatesBBAugmentsToBTThenBLTAndValidatesAtEachStage and CBAdESMultiServerWireFlowTests.CreatesAugmentsToBLTAcrossTwoKestrelHostsAndReachesLevelAwareValidSignatureWithLiveOcsp for the end-to-end placement over CBAdESSignatureAugmentation.AddValidationData."),
        ("CB-6.3-28", "SPO \"certificate and revocation values embedded in the electronic time-stamp itself\": B-B/B-T = \"*\"; B-LT/B-LTA = conditioned presence; cardinality >=0; ref n/a; additional requirement i.",
            RequirementCoverageStatus.Tested, "CBAdESLevelRulesTests.Check_ValidationDataService_AtLevelBLTWithEmbeddedMaterialFactOnly_NoViolation (a caller-supplied embedded-validation-material fact alone satisfies the service, with no valData element present). Unit-shaped only this stage: CBAdESLifecycleFlowTests's own class remarks document a genuine ordering catch-22 -- CBAdESSignatureAugmentation.StripReferencesForLongTerm's synchronous EnsureConformant call can never observe embedded-in-token material true (only the async validation orchestrator inspects a token's CMS content), so no augmentation flow this stage exercises this SPO through a real minted token; flagged for the review wave as a residual flow-coverage gap, not an unbuilt capability."),
        ("CB-6.3-e", "Requirement for valData: duplication of certificate values within the signature should be avoided.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureAugmentationTests.AddValidationData_DeduplicatesAgainstMaterialAlreadyPresent_AndLeavesWireBytesUnchangedWhenNothingNew (a certificate already present in an earlier valData element is skipped on a later CBAdESSignatureAugmentation.AddValidationData call; only the genuinely new candidate is placed)"),
        ("CB-6.3-f", "Requirement for valData: duplication of revocation values within the signature should be avoided.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureAugmentationTests.AddValidationData_DeduplicatesAgainstMaterialAlreadyPresent_AndLeavesWireBytesUnchangedWhenNothingNew (the same CBAdESValidationDataContext.DeduplicateAgainstExisting default covers revocation-value material identically to certificate material; this test's own fixture exercises the certificate arm only -- the crlVals/ocspVals arm is not separately regression-tested this stage, a residual coverage gap flagged for the review wave)"),
        ("CB-6.3-g", "Requirement for refs: the references to certificates (xRefs) should not include the kid member.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureAugmentationTests.CBAdESReferencesContext_Construction_OptionalListsAbsentByDefault (satisfied by construction: CBAdESReferencesContext exposes no key-identifier input member at all, so CBAdESSignatureAugmentation.AddReferencesAsync has no code path that could route a kid value into a produced CertId). Also CBAdESSignatureAugmentationTests.AddReferencesAsync_CertificateToReferenceEqualsSigningCertificate_ThrowsSigningCertificateReferenceRefused for a real refs element this exact orchestrator constructs. No test decodes a produced CertId's own KeyIdentifier member back off the wire to confirm it is absent -- flagged for the review wave as a residual assertion gap, not an unbuilt capability."),
        ("CB-6.3-h", "Requirement for the validation-data-for-TST service: the validation data for electronic time-stamps shall be present within valData OR embedded in the electronic time-stamp itself.",
            RequirementCoverageStatus.Tested, "CBAdESLevelRulesTests.Check_ValidationDataService_AtLevelBLTWithNeitherSpo_ReturnsViolation (the disjunction's failure arm: neither SPO satisfied is a violation). Also CBAdESLevelRulesTests.Check_ValidationDataService_AtLevelBLTWithValidationDataElement_NoViolation and CBAdESLevelRulesTests.Check_ValidationDataService_AtLevelBLTWithEmbeddedMaterialFactOnly_NoViolation for the two satisfying arms, confirming the check is a genuine OR over the two SPOs, never an AND."),
        ("CB-6.3-i", "Requirement for the same service: the validation data for electronic time-stamps should be included within valData.",
            RequirementCoverageStatus.Tested, "CBAdESBaselineLevelTableTests.ServiceRowGroupsItsTwoServiceProvisionOptionRowsWithOrSatisfactionAndValDataPreference (CBAdESBaselineLevelTable.ValidationDataForTimestampsService.PreferredServiceProvisionOptionRequirementId equals CB-6.3-27, the valData SPO -- recorded as registry data, not runtime-enforced as a generator preference this stage: nothing in CBAdESSignatureAugmentation chooses between the two SPOs when both are available, so this row's SHOULD is a data-level statement only)"),

        //Annex A.1.1 -- the refs CBOR map (stage 2, leg 5).
        ("CB-A.1.1-01", "refs may contain references to certificate values validating any digital signature present in any component of the CB-AdES signature, without restriction.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithMultipleCertificateReferencesIncludingKidAbsentInWireOrder (satisfied by construction -- CBAdESCertificateReference carries no target-signature restriction field, so a CertId entry is not scoped to any one signature)"),
        ("CB-A.1.1-02", "refs shall not contain the signing certificate of the CB-AdES signature itself.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureAugmentationTests.AddReferencesAsync_CertificateToReferenceEqualsSigningCertificate_ThrowsSigningCertificateReferenceRefused (the augmentation-side throw posture: CBAdESSignatureAugmentation.AddReferencesAsync refuses a candidate that byte-equals the signing certificate over a real minted certificate and a real composed baseline signature, reported as CBAdESAugmentationFailureKind.SigningCertificateReferenceRefused). Also CBAdESLevelRulesTests.Check_SigningCertificateExclusion_MatchingDigest_ReturnsViolation and CBAdESLevelRulesTests.Check_SigningCertificateExclusion_NonMatchingDigest_NoViolation for the shared rule surface's own collect-posture leg (CBAdESReferencesSigningCertificateExclusionViolation), wavecb S4 coordinator ruling (5)."),
        ("CB-A.1.1-03", "refs may contain references to the revocation value(s) of the certificate(s) supporting any signature the refs component reaches.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCertificateAndAllThreeRevocationReferenceKindsCombined (rRefs carries the same unrestricted-scope shape as xRefs)"),
        ("CB-A.1.1-04", "CB-AdES signatures shall not incorporate empty refs CBOR maps.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingReferencesWithNeitherCertificateNorRevocationReferencesThrows (also CBAdESUnsignedComponentSerializationTests.ParseReferencesFailsClosedOnEmptyMap)"),
        ("CB-A.1.1-05", "Empty xRefs shall not be incorporated.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingReferencesWithEmptyCertificateReferencesArrayThrows (also CBAdESUnsignedComponentSerializationTests.ParseReferencesFailsClosedOnEmptyCertificateReferencesArray)"),
        ("CB-A.1.1-06", "Within xRefs, the x5t member shall identify the digest algorithm and digest value computed on the DER-encoded certificate.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingCertificateReferenceWithNullThumbprintThrows (also CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCertificateReferenceKidAsIntegerAndNoLocationHint for the digest round trip)"),
        ("CB-A.1.1-07", "The content of kid should be a DER-encoded IssuerSerial wrapped in a CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCertificateReferenceKidAsBytesIssuerSerialPlaceholder"),
        ("CB-A.1.1-08", "x5u shall provide an indication of where the referenced certificate can be found.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCertificateReferenceKidAsTextAndLocationHint"),
        ("CB-A.1.1-09", "Empty rRefs shall not be incorporated.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingRevocationReferencesWithEveryMemberAbsentThrows (also CBAdESUnsignedComponentSerializationTests.ParseReferencesFailsClosedOnEmptyRevocationReferencesMap)"),
        ("CB-A.1.1-10", "crlRefs shall contain a non-empty array of references to CRLs.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingRevocationReferencesWithEmptyCrlReferencesArrayThrows (also CBAdESUnsignedComponentSerializationTests.ParseReferencesFailsClosedOnEmptyCrlReferencesArray)"),
        ("CB-A.1.1-11", "Each item within the crlRefs array shall contain one reference to one CRL.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCrlReferenceWithoutCrlId"),
        ("CB-A.1.1-12", "CRLRef.digAlgVal shall contain a digest algorithm indication and the digest value of the DER-encoded referenced CRL, wrapped in a CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingCrlReferenceWithNullHashAlgorithmThrows (also CBAdESUnsignedComponentTests.ConstructingCrlReferenceWithNullDigestThrows and CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCrlReferenceWithoutCrlId)"),
        ("CB-A.1.1-13", "crlId needs not to be present if the referenced CRL can be inferred from other information.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCrlReferenceWithoutCrlId"),
        ("CB-A.1.1-14", "crlId items shall include the issuer's name in issuer.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCrlReferenceWithCrlIdAllMembers (also CBAdESUnsignedComponentSerializationTests.ParseReferencesFailsClosedOnMissingRequiredIssuerInCrlId)"),
        ("CB-A.1.1-15", "crlId items shall include the CRL issuance time in issueTime.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCrlReferenceWithCrlIdAllMembers"),
        ("CB-A.1.1-16", "crlId items may include the CRL number in number.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCrlReferenceWithCrlIdAllMembers"),
        ("CB-A.1.1-17", "crlId.uri shall indicate one place where the referenced CRL can be found, when present.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithCrlReferenceWithCrlIdAllMembers"),
        ("CB-A.1.1-18", "If one or more identified CRLs is a Delta CRL, refs shall include references to the full set of CRLs needed for a complete revocation list.",
            RequirementCoverageStatus.OutOfScope, "Not runtime-enforced this stage -- the same cross-reference completeness policy check as CB-5.3.4-08, over the whole assembled refs graph; deferred to CB-AdES wave stage S7 (validation/conclusions)."),
        ("CB-A.1.1-19", "ocspRefs shall contain a non-empty array of references to OCSP responses.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingRevocationReferencesWithEmptyOcspReferencesArrayThrows (also CBAdESUnsignedComponentSerializationTests.ParseReferencesFailsClosedOnEmptyOcspReferencesArray)"),
        ("CB-A.1.1-20", "Each item within ocspRefs shall contain one reference to one OCSP response.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithOcspReferenceResponderByName"),
        ("CB-A.1.1-21", "ocspId items shall include an identifier of the responder wrapped in a CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingOcspIdentifierWithNullResponderThrows (also CBAdESUnsignedComponentTests.ConstructingOcspReferenceWithNullOcspIdentifierThrows)"),
        ("CB-A.1.1-22", "If the responder identifier is the digest of the server's public key, responderIdByKey shall be present.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithOcspReferenceResponderByKeyPreservesRawDerBytes"),
        ("CB-A.1.1-23", "If the responder identifier is the DER-encoded name of the responder, responderIdByName shall be present.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithOcspReferenceResponderByName"),
        ("CB-A.1.1-24", "D8 (contract R-6, RULED): when identified by public-key digest, the responderIdByKey member shall carry the raw DER byKey bytes -- the spec's own 'base64 encoding' wording is a JAdES copy-residue, not an actual base64 transformation.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithOcspReferenceResponderByKeyPreservesRawDerBytes (both assertions in this test are explicitly annotated with the D8 citation)"),
        ("CB-A.1.1-25", "ocspId items shall include the OCSP response's generation time in producedAt.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithOcspReferenceResponderByName (structurally mandatory: CBAdESOcspIdentifier.ProducedAt is a non-nullable DateTimeOffset, so an absent value cannot be represented)"),
        ("CB-A.1.1-26", "ocspId.producedAt shall indicate the same time as the referenced response's ProducedAt field.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S7 -- cross-checking the supplied producedAt against an actual decoded OCSPResponse.ProducedAt field needs OCSP DER parsing over assembled material, the same cross-component validation-pass reasoning as CB-5.3.4-08/CB-A.1.1-18; CBAdESOcspIdentifier carries the caller-supplied value opaquely this stage."),
        ("CB-A.1.1-27", "ocspId.uri shall indicate one place where the referenced OCSP response can be found.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithOcspReferenceResponderByKeyPreservesRawDerBytes"),
        ("CB-A.1.1-28", "OCSPRef.digAlgVal shall contain a digest algorithm indication and digest value of the DER-encoded OCSPResponse, wrapped in a CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentTests.ConstructingOcspReferenceWithNullHashAlgorithmThrows (also CBAdESUnsignedComponentTests.ConstructingOcspReferenceWithNullDigestThrows and CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithOcspReferenceResponderByName)"),
        ("CB-A.1.1-29", "References to alternative validation-data forms may be included via otherRefs; their semantics and syntax are out of scope of the present document.",
            RequirementCoverageStatus.Tested, "CBAdESUnsignedComponentSerializationTests.ReferencesRoundTripsWithOtherReferencesOpaqueBytes (also CBAdESUnsignedComponentTests.ConstructingRevocationReferencesWithEmptyOtherReferencesArrayThrows -- leg-5 trap-3's otherRefs-is-not-OCSP-only reading is cited in this test's own doc comment)"),
        ("CB-A.1.1-30", "If valData or arcTst is incorporated into the signature, all certificates and validation data referenced in refs shall be present elsewhere in the signature.",
            RequirementCoverageStatus.Tested, "CBAdESLevelValidationNegativeTests.ValidateAsyncCollectsReferencesValidationDataConsistencyViolationWhenACertificateReferenceDoesNotResolve (an independently minted, wire-decoded refs certificate reference whose digest resolves to nothing present in the signature's own valData is collected as CBAdESReferencesValidationDataConsistencyViolation), with the positive twin at CBAdESLevelValidationNegativeTests.ValidateAsyncSucceedsWhenACertificateReferenceResolvesToValidationData (the same shape, except the valData certificate bytes are exactly the refs digest's pre-image). Also CBAdESLifecycleFlowTests.ReferencesFamilyFlowCreatesRefsSigRTstAndRfsTstThenUpgradesToBLTStrippingTheFamily for the strip-on-upgrade leg where this check is trivially satisfied once refs no longer exists at B-LT."),

        //Annex A.1.2.1.1 -- the sigRTst CBOR map (stage 2, leg 5).
        ("CB-A.1.2.1-01", "sigRTst shall encapsulate electronic time-stamp(s) on the COSE signature value, the signature time-stamp (if present), and the CB-AdES components containing references to validation data.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.SigRTstMessageImprintFiltersToSigTstAndRefsElementsInWireOrderAfterSignatureValue (also CBAdESUnsignedComponentSerializationTests.SignatureAndReferencesTimestampRoundTripsThroughWrapperCodec for the container wrapper)"),
        ("CB-A.1.2.1-02", "The sigRTst CBOR map shall contain an electronic time-stamp that time-stamps the member encapsulating the COSE signature value, and sigTst/refs when present.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.SigRTstMessageImprintFiltersToSigTstAndRefsElementsInWireOrderAfterSignatureValue"),
        ("CB-A.1.2.1-03", "If refs is not present, the sigRTst CBOR map shall not be generated.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureAugmentationTests.AddSignatureAndReferencesTimestampAsync_NoPrecedingReferences_ThrowsReferencesElementRequired_NeverContactsAuthority (the generation-time gate refuses BEFORE any Time-Stamping Authority round trip, reported as CBAdESAugmentationFailureKind.ReferencesElementRequired, and a call-counting responder confirms zero round trips). Also CBAdESLevelRulesTests.Check_GenerationGate_SignatureAndReferencesTimestampWithNoPrecedingReferences_ReturnsViolation and CBAdESLevelRulesTests.Check_GenerationGate_SignatureAndReferencesTimestampWithPrecedingReferences_NoViolation for the shared rule surface's own collect-posture leg (CBAdESReferencesTimestampGenerationGateViolation, RequirementId CB-A.1.2.1-03)."),

        //Annex A.1.2.1.2 -- the sigRTst message-imprint computation, five steps (stage 2, leg 5; leg-5 trap 4 on step 4's COSE_Sign1 wording).
        ("CB-A.1.2.1.2-01", "Step 1: initialize an empty CBOR array.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.SigRTstMessageImprintFiltersToSigTstAndRefsElementsInWireOrderAfterSignatureValue"),
        ("CB-A.1.2.1.2-02", "Step 2: add the CBOR byte string in the signature component.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.SigRTstMessageImprintFiltersToSigTstAndRefsElementsInWireOrderAfterSignatureValue (the signature-value element leads the array; also CBAdESMessageImprintTests.RfsTstMessageImprintMatchesSigRTstMinusTheLeadingSignatureElement, which demonstrates this element's presence by its absence in rfsTst)"),
        ("CB-A.1.2.1.2-03", "Step 3: if built on COSE_Sign, take sigTst (if present) then refs (if present) from the signer layer's uHeaders, in wire order, appending a zero-length byte string if neither is present.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.SigRTstMessageImprintFiltersToSigTstAndRefsElementsInWireOrderAfterSignatureValue (the shipped builder takes no structure-context parameter at all -- the same filter-and-append code path serves both this row and CB-A.1.2.1.2-04, per leg 5's own 'one parameterized function' implication; also CBAdESMessageImprintTests.SigRTstMessageImprintUsesZeroLengthSentinelWhenUHeadersAbsent and ...CollapsesToZeroLengthSentinelWhenUHeadersPresentButNoElementsMatch for the sentinel cases)"),
        ("CB-A.1.2.1.2-04", "Step 4 (leg-5 trap 4: read 'body layer' for COSE_Sign1): if built on COSE_Sign1, take sigTst (if present) then refs (if present) from the body layer's uHeaders, in wire order, appending a zero-length byte string if neither is present.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.SigRTstMessageImprintFiltersToSigTstAndRefsElementsInWireOrderAfterSignatureValue (same structure-agnostic code path as CB-A.1.2.1.2-03; the trap-4 reading is recorded in CBAdESMessageImprints's own remarks)"),
        ("CB-A.1.2.1.2-05", "Step 5: encode the generated CBOR array in a CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.SigRTstMessageImprintFiltersToSigTstAndRefsElementsInWireOrderAfterSignatureValue"),

        //Annex A.1.2.2.1 -- the rfsTst CBOR map (stage 2, leg 5).
        ("CB-A.1.2.2-01", "rfsTst shall encapsulate electronic time-stamp(s) on the signature time-stamp (if present) and the CB-AdES components containing references to validation data, deliberately excluding the raw signature value.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.RfsTstMessageImprintMatchesSigRTstMinusTheLeadingSignatureElement (also CBAdESUnsignedComponentSerializationTests.ReferencesTimestampRoundTripsThroughWrapperCodec for the container wrapper)"),
        ("CB-A.1.2.2-02", "The rfsTst CBOR map shall contain an electronic time-stamp time-stamping the member encapsulating sigTst/refs when present.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.RfsTstMessageImprintMatchesSigRTstMinusTheLeadingSignatureElement"),
        ("CB-A.1.2.2-03", "If refs is not present, the rfsTst CBOR map shall not be generated.",
            RequirementCoverageStatus.Tested, "CBAdESSignatureAugmentationTests.AddReferencesTimestampAsync_NoPrecedingReferences_ThrowsReferencesElementRequired_NeverContactsAuthority (the same generation-time gate for rfsTst, reported as CBAdESAugmentationFailureKind.ReferencesElementRequired). Also CBAdESLevelRulesTests.Check_GenerationGate_ReferencesTimestampWithNoPrecedingReferences_ReturnsViolation for the shared rule surface's own collect-posture leg (CBAdESReferencesTimestampGenerationGateViolation, RequirementId CB-A.1.2.2-03)."),

        //Annex A.1.2.2.2 -- the rfsTst message-imprint computation, four steps (stage 2, leg 5; leg-5 trap 4 again on step 3).
        ("CB-A.1.2.2.2-01", "Step 1: initialize an empty CBOR array; no signature-value element is ever added.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.RfsTstMessageImprintMatchesSigRTstMinusTheLeadingSignatureElement (explicitly demonstrates the absent signature-value element by direct byte comparison against sigRTst's own output)"),
        ("CB-A.1.2.2.2-02", "Step 2: if built on COSE_Sign, take sigTst (if present) then refs (if present) from the signer layer's uHeaders, in wire order, appending a zero-length byte string if neither is present.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.RfsTstMessageImprintUsesZeroLengthSentinelWhenUHeadersAbsent (the shipped builder takes no structure-context parameter -- the same filter-and-append code path serves both this row and CB-A.1.2.2.2-03; also CBAdESMessageImprintTests.RfsTstMessageImprintMatchesSigRTstMinusTheLeadingSignatureElement for the matching-elements case)"),
        ("CB-A.1.2.2.2-03", "Step 3 (leg-5 trap 4: read 'body layer' for COSE_Sign1): if built on COSE_Sign1, take sigTst (if present) then refs (if present) from the body layer's uHeaders, in wire order, appending a zero-length byte string if neither is present.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.RfsTstMessageImprintMatchesSigRTstMinusTheLeadingSignatureElement (same structure-agnostic code path as CB-A.1.2.2.2-02; the trap-4 reading is recorded in CBAdESMessageImprints's own remarks)"),
        ("CB-A.1.2.2.2-04", "Step 4: encode the generated CBOR array in a CBOR byte string.",
            RequirementCoverageStatus.Tested, "CBAdESMessageImprintTests.RfsTstMessageImprintUsesZeroLengthSentinelWhenUHeadersAbsent"),

        //Annex E (normative) -- alternative long-term availability/integrity mechanisms (stage 2, leg 5).
        ("CB-E-01", "If an alternative mechanism for long-term availability/integrity of validation data is incorporated as an unsigned component, all three disclosures below shall be specified for it.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S5 -- the contract names Annex E's disclosure convention over the shipped Evidence Record extension points as an explicit S5 deliverable; no registration-record type exists yet this stage."),
        ("CB-E-02", "Item 1: the clear specification of the semantics and syntax of the component, including its unique identifier, shall be specified.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S5 -- same reasoning as CB-E-01."),
        ("CB-E-03", "Item 2: the strategy of how the mechanism guarantees that all necessary parts of the signature are protected by the component shall be specified.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S5 -- same reasoning as CB-E-01."),
        ("CB-E-04", "Item 3: the strategy of how to handle signatures containing components defined in the present document (coexistence with refs/valData/sigRTst/rfsTst/arcTst) shall be specified.",
            RequirementCoverageStatus.OutOfScope, "Deferred to CB-AdES wave stage S5 -- same reasoning as CB-E-01."),
    ];
}

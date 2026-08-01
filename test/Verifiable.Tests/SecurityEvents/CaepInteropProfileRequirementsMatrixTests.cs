using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// The RFC 2119 requirements matrix for the CAEP Interoperability Profile surface this repository
/// ships: every normative statement of §2.3-§2.8 and §3.x (plus the §2.1/§2.2/§2.7 context clauses)
/// of the
/// <see href="https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html">OpenID CAEP
/// Interoperability Profile 1.0, draft 01</see> is one <see cref="RequirementMatrixRow"/>. Mirrors the
/// DynamicData-rows-as-spec-cells shape of <c>CAdESRequirementsMatrixTests</c> (ETSI EN 319 122-1) and
/// <c>AsicRequirementsMatrixTests</c>.
/// </summary>
/// <remarks>
/// <para>
/// DRAFT STATUS. The document under review is <em>draft 01</em>, not Final: the <c>-final.html</c>
/// URL does not yet exist, and the specification is in its public review window (announced to close
/// 25 September 2026). Draft 01 is the text that becomes Final unless review comments move it. Seven of
/// its clauses are SPEC-DEFECT-CANDIDATEs raised as review comments R-1..R-7 in the cheap-tier drift
/// report; the rows for those clauses record the review-comment reference rather than treating the
/// ambiguity as this library's defect. On Final approval this matrix must be re-pointed at the Final
/// text and every draft-01 anchor re-checked.
/// </para>
/// <para>
/// <see cref="RequirementMatrixTest"/> fails a row that is neither <see cref="RequirementCoverageStatus.Tested"/>
/// nor <see cref="RequirementCoverageStatus.OutOfScope"/> nor <see cref="RequirementCoverageStatus.KnownDefect"/>
/// — no silent gaps — and, for <see cref="RequirementCoverageStatus.Tested"/>/<see cref="RequirementCoverageStatus.KnownDefect"/>
/// rows, additionally resolves the cited evidence through reflection over the compiled test assembly: a
/// row citing a class or method that does not exist, or that is not itself a <c>[TestMethod]</c>, fails.
/// This verifies the row's claim of "a real test drives this clause" against the actual shipped test
/// surface, so a renamed or deleted evidence method is caught here rather than rotting into a stale
/// citation.
/// </para>
/// <para>
/// The §2.3 metadata gaps the drift report found (the receive-side <c>spec_version</c>-<c>1_0</c>-or-greater
/// comparison and the composite Transmitter-Configuration conformance predicate) are CLOSED in this stage
/// by the new pure-function gate <see cref="Verifiable.Core.SecurityEvents.CaepInteropProfile.IsConformantTransmitterConfiguration"/>
/// and its tests (<see cref="CaepInteropProfileConfigurationTests"/>). The three gaps that turn on open
/// review comments — §2.6's exclusive <c>RS256</c> pin (R-1, and forbidden to hard-pin by this repository's
/// algorithm-agility/PQC rule), §2.5's subject-format restriction (R-2), and §2.4.4's implicit-subjects
/// Receiver assumption (R-4) — are DEFERRED as <see cref="RequirementCoverageStatus.OutOfScope"/> with the
/// review-comment reason stated verbatim, per the drift report's own adjudication that implementing a
/// clause under active review risks encoding text that changes.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CaepInteropProfileRequirementsMatrixTests
{
    /// <summary>Whether a requirement row has been driven through a concrete test, is deliberately deferred/out of scope with a stated reason, or is a documented known defect reachable through a real test.</summary>
    internal enum RequirementCoverageStatus
    {
        /// <summary>No disposition has been recorded. The value of an unset field, by design: a row must never silently pass as covered.</summary>
        Untested = 0,

        /// <summary>The requirement is driven by at least one concrete, named test that calls the shipped surface.</summary>
        Tested = 1,

        /// <summary>The requirement is deliberately deferred or out of this library's scope, per the drift report, an open review comment, or a host/deployment boundary — with the reason stated in the row's evidence.</summary>
        OutOfScope = 2,

        /// <summary>The requirement's own building block implements and unit-tests it, but the shipped default composition cannot reach it because of an already-flagged, unfixed defect elsewhere.</summary>
        KnownDefect = 3
    }


    /// <summary>One row of the matrix: a clause identifier, a short digest of the requirement it names, its coverage disposition, and the evidence for that disposition.</summary>
    /// <param name="ClauseId">The clause (and, where a review comment applies, the R-reference) the requirement comes from.</param>
    /// <param name="Requirement">A short digest of the normative statement, close enough to the specification's own wording to be checked against it.</param>
    /// <param name="Status">The coverage disposition.</param>
    /// <param name="Evidence">For <see cref="RequirementCoverageStatus.Tested"/>/<see cref="RequirementCoverageStatus.KnownDefect"/>, the asserting test's <c>ClassName.MethodName</c> (optionally followed by explanatory prose in parentheses) — the leading token is resolved through reflection; for <see cref="RequirementCoverageStatus.OutOfScope"/>, the deferral or boundary reason.</param>
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
    /// No row of the matrix may be left without a coverage disposition, and a
    /// <see cref="RequirementCoverageStatus.Tested"/> or <see cref="RequirementCoverageStatus.KnownDefect"/>
    /// row's evidence must resolve to a real, existing <c>[TestMethod]</c> in the compiled test assembly.
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
    /// Resolves an evidence citation's leading <c>ClassName.MethodName</c> token against the compiled
    /// test assembly and fails when the class, the method, or the <c>[TestMethod]</c> attribute on it
    /// does not exist — a genuine check of the shipped test surface, not a check that a string happens
    /// to be non-empty.
    /// </summary>
    /// <param name="row">The row whose evidence is resolved.</param>
    private static void AssertEvidenceNamesAShippedTestMethod(RequirementMatrixRow row)
    {
        string token = row.Evidence.Split([' ', '('], 2, StringSplitOptions.RemoveEmptyEntries)[0];
        int separatorIndex = token.LastIndexOf('.');
        Assert.IsGreaterThan(0, separatorIndex, $"{row.ClauseId}: evidence '{row.Evidence}' must lead with a Class.Method pair.");

        string className = token[..separatorIndex];
        string methodName = token[(separatorIndex + 1)..];
        Type? evidenceType = typeof(CaepInteropProfileRequirementsMatrixTests).Assembly.GetTypes()
            .FirstOrDefault(candidate => string.Equals(candidate.Name, className, StringComparison.Ordinal));
        Assert.IsNotNull(evidenceType, $"{row.ClauseId}: evidence class '{className}' does not exist in the test assembly.");

        MethodInfo? evidenceMethod = evidenceType!.GetMethod(
            methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
        Assert.IsNotNull(evidenceMethod, $"{row.ClauseId}: evidence method '{className}.{methodName}' does not exist.");
        Assert.IsNotEmpty(evidenceMethod!.GetCustomAttributes(typeof(TestMethodAttribute), inherit: false),
            $"{row.ClauseId}: evidence '{className}.{methodName}' is not a [TestMethod] — the matrix must cite a real test.");
    }


    /// <summary>
    /// Every row of the matrix, as a plain data table so a reviewer can scan the whole CAEP
    /// Interoperability Profile normative surface — and its disposition — in one place. Rows follow the
    /// specification's own §2.1..§2.8, §3.x structure.
    /// </summary>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] RowData { get; } =
    [
        ("2.1-tls", "Transmitter MUST offer TLS-protected endpoints (TLS >= 1.2, RFC 9325); Receiver MUST perform certificate signature/chain/expiry/revocation checks.",
            RequirementCoverageStatus.OutOfScope, "Transport is a host/deployment concern; the library emits no transport policy and opens no socket of its own (drift report verdict N)."),
        ("2.2-caep-1.0-events", "The profile supports CAEP events from CAEP 1.0 — the three use-case event types are carried verbatim.",
            RequirementCoverageStatus.Tested, "CaepInteropEventTests.SessionRevokedRoundTripsWithCommonClaims (with CredentialChangeRoundTripsWithEventSpecificClaims and DeviceComplianceChangeRoundTripsWithStatuses — all three CAEP 1.0 use-case URIs are built typed, issued and received)"),

        ("2.3.1-specversion-emit", "Metadata MUST include spec_version (§2.3.1) — the emit path writes it on every document.",
            RequirementCoverageStatus.Tested, "SsfJsonWritingPropertyTests.TransmitterConfigurationWriteThenStrictParseRoundTrips (the written document strict-parses with spec_version == \"1_0\")"),
        ("2.3.1-specversion-receive", "spec_version's value MUST be 1_0 or greater — the receive-side conformance gate compares it and fails closed below the floor or when absent.",
            RequirementCoverageStatus.Tested, "CaepInteropProfileConfigurationTests.AConfigurationWhoseSpecVersionIsBelowOneZeroIsNotConformant (with AConfigurationWithNoSpecVersionIsNotConformant and AConfigurationWhoseSpecVersionCarriesAnInteropDraftSuffixIsConformant — the drift report's receive-side G, closed this stage by CaepInteropProfile.IsConformantTransmitterConfiguration)"),
        ("2.3.2-delivery-methods-supported", "Metadata MUST include delivery_methods_supported — the emit path refuses rather than publish a document omitting it, and the receive-side gate rejects a document without it.",
            RequirementCoverageStatus.Tested, "SsfTransmitterMetadataProfileTests.UnsetDeliveryMethodsRefusesInsteadOfEmittingAViolatingDocument (emit-side secure default, Stage 1 D-4); CaepInteropProfileConfigurationTests.AConfigurationMissingDeliveryMethodsIsNotConformant (receive-side gate)"),
        ("2.3.3-jwks-uri", "Metadata MUST include jwks_uri resolving to the Transmitter's current signing keys.",
            RequirementCoverageStatus.Tested, "SsfHttpFlowTests.DiscoveryDocumentServedOverHttpStrictParses (jwks_uri advertised over the wire and asserted present); SsfDiscoveryParsingTests.MissingIssuerIsRejected exercises the same parser strictly"),
        ("2.3.4-configuration-endpoint", "Metadata MUST include configuration_endpoint (SSF §7.1), performing Create Stream (SSF §8.1.1).",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.StreamLifecycleOverHttpWire (the configuration endpoint creates a stream over the wire); CaepInteropProfileConfigurationTests.AConfigurationSatisfyingEveryMetadataMustIsConformant asserts its presence"),
        ("2.3.5-status-endpoint", "Metadata MUST include status_endpoint supporting Read Stream Status (SSF §8.1.2.1).",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.StreamControlEndpointsOverHttpWire (status read/update over the wire)"),
        ("2.3.6-verification-endpoint", "Metadata MUST include verification_endpoint supporting Stream Verification (SSF §8.1.4).",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.StreamControlEndpointsOverHttpWire (verification over the wire); CaepInteropProfileConfigurationTests.AConfigurationMissingTheVerificationEndpointIsNotConformant (receive-side gate rejects its absence)"),
        ("2.3.7-authorization-schemes", "Metadata MUST include authorization_schemes and its value MUST include {\"spec_urn\":\"urn:ietf:rfc:6749\"} — the emit path defaults to the spec-fixed value on silence, and the receive-side gate rejects schemes omitting OAuth 2.0.",
            RequirementCoverageStatus.Tested, "SsfTransmitterMetadataProfileTests.UnsetAuthorizationSchemesEmitsTheProfileFixedValue (with SuppliedAuthorizationSchemesAreEmittedVerbatim, Stage 1 D-4); CaepInteropProfileConfigurationTests.AConfigurationWhoseAuthorizationSchemesOmitOAuth2IsNotConformant (receive-side gate)"),
        ("2.3-config-conformance", "The full Transmitter Configuration Metadata document MUST meet every §2.3 MUST-include member together — the composite receive-side conformance predicate.",
            RequirementCoverageStatus.Tested, "CaepInteropProfileConfigurationTests.AConfigurationSatisfyingEveryMetadataMustIsConformant (the composite gate CaepInteropProfile.IsConformantTransmitterConfiguration accepts a fully-conformant document and each sibling test rejects one missing member)"),
        ("2.3.8-stream-management-api", "Transmitter MUST support all required properties/API contracts of the SSF Stream Management API.",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.StreamLifecycleOverHttpWire (create/read/replace/delete) and StreamControlEndpointsOverHttpWire (status read/update, subject add/remove, verification)"),
        ("2.3.8.1-create-delivery-method", "Transmitter MUST support Create Stream with delivery.method one of {urn:ietf:rfc:8935, urn:ietf:rfc:8936} and, on success, echo a delivery whose method is one of them. [SPEC-DEFECT-CANDIDATE R-3: \"one of\" is ambiguous between both and at-least-one, so a Poll-only Transmitter and a Push-only Receiver can each be conformant yet cannot interoperate.]",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.CreateWithPushDeliveryEchoesRequestedConfiguration (the push method is honoured and echoed; the poll alternative round-trips in SsfHttpFlowTests.PollRoundTripDeliversVerifiesAndAcknowledgesOverHttp)"),
        ("2.3.8.2-authorized-operations", "Transmitter MUST support Create / Read Config / Read Status / Verification / Delete with valid authorization.",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.ScopeEnforcementOverHttpWire (each operation is scope-gated and exercised over the wire)"),

        ("2.4.1-receiver-delivery", "Receiver MUST accept events over at least one of RFC 8935 (Push) / RFC 8936 (Poll).",
            RequirementCoverageStatus.Tested, "SsfHttpFlowTests.PushedSetOverHttpIsVerifiedAcknowledgedAndDeduplicated (push) and SsfHttpFlowTests.PollRoundTripDeliversVerifiesAndAcknowledgesOverHttp (poll)"),
        ("2.4.2-receiver-jwks", "Receiver MUST obtain signing keys via jwks_uri.",
            RequirementCoverageStatus.Tested, "SsfHttpFlowTests.DiscoveryDocumentServedOverHttpStrictParses (jwks_uri is advertised for exactly this purpose); the SET is then verified against the transmitter key in SsfHttpFlowTests.PushedSetOverHttpIsVerifiedAcknowledgedAndDeduplicated"),
        ("2.4.3-receiver-oauth", "Receiver MUST use OAuth 2.0 for Stream Management API requests.",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.ScopeEnforcementOverHttpWire (bearer-token OAuth scope gating on every management request)"),
        ("2.4.4-implicit-subjects", "Receiver MUST assume all subjects are implicitly included in a Stream, without Add Subject invocations. [SPEC-DEFECT-CANDIDATE R-4: no matching Transmitter obligation, so a Transmitter advertising default_subjects=NONE and a Receiver that never calls Add Subject are both conformant and no event is ever delivered — a silent, total interop failure.]",
            RequirementCoverageStatus.OutOfScope, "DEFERRED pending review comment R-4: a Receiver behavioural assumption with no matching Transmitter obligation in draft 01; the library models both default_subjects values and the Add/Remove Subject operations, and imposing the assumption now would encode a clause under active review. Re-evaluate on Final."),
        ("2.4.5.1-receiver-create-delivery", "Create Stream: Receiver MUST send delivery.method one of {8935, 8936} or omit delivery (omitted implies Poll).",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.CreateWithPushDeliveryEchoesRequestedConfiguration (explicit method) with SsfStreamManagementEndpointTests.StreamLifecycleOverHttpWire (an omitted delivery defaults to poll)"),
        ("2.4.5.2-receiver-invocations", "Receiver MUST be able to invoke Create / Read Config / Read Status / Verification / Delete.",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.StreamControlEndpointsOverHttpWire (every operation reached over the wire from the Receiver side)"),

        ("2.5-subject-formats", "Formats email, iss_sub and opaque (Verification event only) MUST be supported; Receivers MUST accept any of them; Transmitters MUST send at least one. [SPEC-DEFECT-CANDIDATE R-2: opaque is restricted to the Verification event yet counts toward \"at least one\", so a Transmitter supporting only opaque is conformant to §2.5 yet cannot emit a single §3 use-case event.]",
            RequirementCoverageStatus.OutOfScope, "DEFERRED pending review comment R-2: all twelve formats are modelled (SubjectIdentifierFormats), but the profile's \"at least one\" set and its opaque-only-for-Verification restriction are self-contradictory in draft 01; a gate encoding them now would pin an ambiguity under active review. Re-evaluate on Final."),

        ("2.6-rs256", "All events MUST be signed using RS256 with a minimum of 2048-bit keys. [SPEC-DEFECT-CANDIDATE R-1: exclusive RS256 forbids ES256/EdDSA/ML-DSA for the life of a Final spec with no agility path, and \"events\" are the wrong object — the SET, not each event, carries the signature.]",
            RequirementCoverageStatus.OutOfScope, "DEFERRED pending review comment R-1, and a hard RS256 pin is forbidden by this repository's proof-algorithm-agility/PQC rule (signing stays algorithm-agile via the key Tag). A registrable interop-floor predicate is the intended shape once R-1 resolves whether RS256 is exclusive or mandatory-to-implement; encoding an exclusive pin now would both violate the house rule and risk implementing a clause under active review."),

        ("2.7-oauth-roles", "Implementations MUST support OAuth 2.0 with RS = Transmitter, Client = Receiver, AS = trusted issuer.",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.ScopeEnforcementOverHttpWire (the Receiver presents a bearer token the Transmitter-as-Resource-Server validates through the authorization seam)"),
        ("2.7.1-short-lived-token", "AS MUST support client-credentials or authorization-code to issue a short-lived token (no more than 60 minutes). [SPEC-DEFECT-CANDIDATE R-8: 60 minutes is not short-lived, and the requirement binds only the AS with no Resource-Server-side check.]",
            RequirementCoverageStatus.OutOfScope, "Access-token lifetime is an AS deployment-policy default (TimingPolicy.AccessTokenLifetime defaults to 60 minutes, exactly at the boundary); the library imposes no gate stopping a deployment raising it, and §2.7.2 gives the Resource Server no matching obligation to reject a longer-lived token — an unenforceable cross-boundary constraint (drift report verdict C-boundary)."),
        ("2.7.2-bearer-token", "RS MUST accept bearer tokens per RFC 6750 §2.1; MUST NOT accept them via the RFC 6750 §2.3 query parameter; MUST verify validity/integrity/expiry/revocation/sufficiency.",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.ScopeEnforcementOverHttpWire (bearer tokens accepted from the Authorization header and rejected on insufficient scope; the query-parameter prohibition holds by construction — the library ships no query-parameter bearer extraction path)"),
        ("2.7.3-scope-lattice", "ssf. scopes reserved; AS MUST support ssf.manage and ssf.read; ssf.read implies Read Config + Get Status; ssf.manage implies ssf.read + Create + Delete + Verification.",
            RequirementCoverageStatus.Tested, "SsfScopeTests.ManageSatisfiesReadButNotTheReverse (with SsfScopeValuesAreTheProfileConstants and ExactMatchesAndGranularManagePostfixesSatisfy — the exact §2.7.3 lattice)"),
        ("2.7.3-scope-operation-table", "The §2.7.3 scope-to-operation table assigns scopes to five operations; the shipped surface additionally gates Update/Replace Stream, Update Status and Add/Remove Subject on ssf.manage. [SPEC-DEFECT-CANDIDATE R-5: the table covers only five of the ~ten SSF Stream Management operations, so the remainder have no profile-assigned authorization and every implementer must guess.]",
            RequirementCoverageStatus.Tested, "SsfStreamManagementEndpointTests.ScopeEnforcementOverHttpWire (the management operations beyond the five named accept ssf.manage, the conservative choice this library documents pending R-5)"),

        ("2.8.1-transmitter-one-event", "The events claim of the SET MUST contain only one event — the Transmitter conformance gate rejects a multi-event token. [SPEC-DEFECT-CANDIDATE R-6: §2.8.1 names no actor and silently narrows RFC 8417 §2.2's multi-event support.]",
            RequirementCoverageStatus.Tested, "CaepInteropEventTests.InteropGateRequiresNonEmptyReasonAdminAndOneEvent (a two-event token fails CaepInteropProfile.IsConformantTransmitterToken)"),
        ("2.8.1-receiver-tolerance", "Receiver side of §2.8.1: whether a Receiver MUST reject a multi-event SET is left to the actor-ambiguous reading. [SPEC-DEFECT-CANDIDATE R-6.]",
            RequirementCoverageStatus.OutOfScope, "The Receiver stays deliberately tolerant (SecurityEventTokenVerification rejects only an empty events claim, per its own remarks); imposing single-event rejection on the Receiver would encode the actor-ambiguous reading R-6 flags. The Transmitter-side single-event MUST is gated and tested (2.8.1-transmitter-one-event)."),

        ("3-at-least-one", "A conforming implementation MUST support at least one of §3.1-§3.3. [SPEC-DEFECT-CANDIDATE R-7: the profile does not say whether an implementation MAY also emit CAEP events outside the three named use cases.]",
            RequirementCoverageStatus.Tested, "CaepInteropEventTests.InteropGateRequiresNonEmptyReasonAdminAndOneEvent (all three use cases are supported; the gate accepts the three profile events and rejects a non-profile CAEP/RISC event — the conservative closed-set reading this library documents pending R-7)"),
        ("3.1-session-revoked", "MUST support session-revoked; reason_admin MUST be a non-empty object.",
            RequirementCoverageStatus.Tested, "CaepInteropEventTests.SessionRevokedRoundTripsWithCommonClaims (the round trip) with CaepInteropEventTests.InteropGateRequiresNonEmptyReasonAdminAndOneEvent (the non-empty reason_admin MUST)"),
        ("3.2-credential-change", "MUST support credential-change; Receivers MUST interpret all allowable change_type/credential_type values; reason_admin MUST be non-empty.",
            RequirementCoverageStatus.Tested, "CaepInteropEventTests.CredentialChangeRoundTripsWithEventSpecificClaims (the round trip) with CaepInteropEventTests.ProjectionsRejectValuesOutsideTheClosedSets (change_type is a closed set, credential_type an open set both handled)"),
        ("3.3-device-compliance-change", "MUST support device-compliance-change; Receivers MUST interpret all allowable previous_status/current_status; reason_admin MUST be non-empty.",
            RequirementCoverageStatus.Tested, "CaepInteropEventTests.DeviceComplianceChangeRoundTripsWithStatuses (the round trip) with CaepInteropEventTests.ProjectionsRejectValuesOutsideTheClosedSets (the compliance-status closed set)"),
    ];
}

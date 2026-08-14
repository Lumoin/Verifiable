using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The shared JAdES B-B (baseline) cross-header rule surface: every clause 5.1 and clause 5.2
/// conformance rule that <see cref="JAdESProtectedHeaders"/>'s own constructor cannot enforce by construction
/// (its own remarks name every one of these as a deferred obligation) — implemented exactly once and consumed by
/// both postures a caller needs, mirroring <see cref="CBAdESHeaderRules"/>'s identical discipline.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Two postures, one implementation.</strong> <see cref="Check"/> is the COLLECT posture — it never
/// throws on non-conformant input, returning every violation found so a validator parsing untrusted wire bytes
/// can report all of them at once. <see cref="EnsureConformant"/> is the THROW posture —
/// <see cref="JAdESSignatureCreation"/>'s trusted-caller-input guard, calling <see cref="Check"/> and raising
/// <see cref="ArgumentException"/> naming the first violated clause. Both routes run the exact same rule bodies.
/// </para>
/// <para>
/// <strong>Scope: clause 5.1 + clause 5.2 only.</strong> Table 1 (level-conditioned requirements —
/// the CB-AdES Table-14 analogue) is its own <c>JAdESLevelRules</c>, a distinct type; nothing here reaches
/// into that territory, matching how this type's own charter names exactly "every clause 5.1 + clause 5.2 B-B conformance
/// rule."
/// </para>
/// <para>
/// <strong>Soft (SHOULD/SHOULD NOT) rules are recorded, never enforced as violations.</strong> JA-5.1.3-03 ("The
/// <c>cty</c> header parameter should not be present if the <c>sigD</c> header parameter... is present") is a
/// SHOULD NOT, unlike its hard-SHALL-NOT sibling JA-5.1.3-05 below — no <see cref="JAdESRuleViolation"/> exists
/// for it, mirroring <see cref="CBAdESHeaderRules"/>'s own treatment of CB-6.3's soft additional requirement (i).
/// </para>
/// <para>
/// <strong>Mechanism-shaped <c>sigD</c> members are satisfied BY CONSTRUCTION, not checked here.</strong>
/// <see cref="JAdESHttpHeadersReference"/> structurally carries no <c>hashV</c>/<c>hashM</c>/<c>ctys</c>
/// (JA-5.2.8.2-03); <see cref="JAdESObjectIdByUriReference"/>'s constructor refuses any entry carrying a digest
/// (JA-5.2.8.3.2-02); <see cref="JAdESObjectIdByUriHashReference"/>'s constructor requires every entry to carry
/// one (JA-5.2.8.3.3-02/-04). A well-formed <see cref="JAdESDetachedDataObjectReference"/> instance cannot
/// violate any of the three — no runtime rule is needed, the same "satisfied by construction" posture
/// <see cref="CBAdESHeaderRules"/> documents for its own MD5-on-<c>Algorithm</c> case.
/// </para>
/// <para>
/// <strong><see cref="JAdESX5tForbiddenViolation"/> is a caller-attested fact, not a constructor-checkable
/// one.</strong> <see cref="JAdESProtectedHeaders"/> exposes no <c>x5t</c> property at all (JA-5.1.6-01 is
/// satisfied by construction on the CREATION side), so this rule can only ever fire from a fact the wire decoder
/// observed and this aggregate itself has nowhere to carry: <see cref="JAdESSignatureValidation"/>'s own
/// <c>DetectX5tPresence</c> seam (<see cref="JAdESProtectedHeaderJson.DetectX5tPresence"/>) inspects the raw
/// protected-header JSON for a present <c>x5t</c> member before/alongside the JAdES-typed decode and passes the
/// result through as <c>x5tWasPresentOnWire</c> on every <c>ValidateAsync</c> call. Defaults to
/// <see langword="false"/>, so a creation call (which never has wire content to inspect) never raises it.
/// </para>
/// </remarks>
public static class JAdESHeaderRules
{
    /// <summary>
    /// Evaluates every B-B cross-header rule against <paramref name="headers"/> and returns every violation
    /// found. Never throws on non-conformant content — only a <see langword="null"/> <paramref name="headers"/>
    /// itself (a caller contract violation) raises <see cref="ArgumentNullException"/>.
    /// </summary>
    /// <param name="headers">The signed-header-set aggregate to evaluate.</param>
    /// <param name="payloadIsDetached">
    /// <see langword="true"/> when the JWS Payload this signature covers is detached (JA-4-07); this aggregate
    /// carries no payload of its own, so the caller supplies the fact.
    /// </param>
    /// <param name="payloadIsCountersignedSignature">
    /// Caller-attested fact (mirroring <see cref="CBAdESHeaderRules.Check"/>'s identical parameter): whether the
    /// JWS Payload this signature covers is itself a (counter-signed) signature. Defaults to
    /// <see langword="false"/> — JA-5.1.3-05.
    /// </param>
    /// <param name="x5tWasPresentOnWire">
    /// Caller-attested fact: a decoder observed a present <c>x5t</c> member on the wire even though this
    /// well-formed aggregate cannot carry one — see the type remarks. Defaults to <see langword="false"/>.
    /// </param>
    /// <returns>Every violation found, in rule-declaration order; empty when fully B-B conformant.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="headers"/> is <see langword="null"/>.</exception>
    public static IReadOnlyList<JAdESRuleViolation> Check(
        JAdESProtectedHeaders headers,
        bool payloadIsDetached,
        bool payloadIsCountersignedSignature = false,
        bool x5tWasPresentOnWire = false)
    {
        ArgumentNullException.ThrowIfNull(headers);

        var violations = new List<JAdESRuleViolation>();

        if(x5tWasPresentOnWire)
        {
            violations.Add(new JAdESX5tForbiddenViolation());
        }

        if(headers.X5tHashS256 is null && headers.X5Chain is null && headers.X5tHashO is null && headers.SigX5ts is null)
        {
            violations.Add(new JAdESSigningCertificateIdentificationViolation());
        }

        if(headers.ContentType is not null && payloadIsCountersignedSignature)
        {
            violations.Add(new JAdESContentTypeCountersignedPayloadViolation());
        }

        if(headers.PayloadTimestamps is not null && headers.PayloadTimestamps.CanonAlg is not null)
        {
            violations.Add(new JAdESPayloadTimestampCanonAlgViolation());
        }

        if(headers.IssuedAt is null)
        {
            violations.Add(new JAdESIssuedAtMissingViolation());
        }

        if(headers.SigD is not null)
        {
            if(!payloadIsDetached)
            {
                violations.Add(new JAdESDetachedObjectReferenceAttachedPayloadViolation());
            }

            if(!ContainsCriticalLabel(headers.CriticalLabels, WellKnownJAdESHeaderNames.SigD))
            {
                violations.Add(new JAdESDetachedObjectReferenceCriticalLabelViolation());
            }

            if(headers.SigD is JAdESHttpHeadersReference httpHeaders)
            {
                if(headers.B64 is null || headers.B64.Value)
                {
                    violations.Add(new JAdESHttpHeadersMechanismB64Violation());
                }

                if(!EveryHeaderNameIsLowercase(httpHeaders.HeaderNames))
                {
                    violations.Add(new JAdESHttpHeadersParsNotLowercaseViolation());
                }
            }
        }

        return violations;

        /// <summary>Determines whether every entry of <paramref name="headerNames"/> is already lowercase (JA-5.2.8.2-04), ordinal comparison.</summary>
        static bool EveryHeaderNameIsLowercase(IReadOnlyList<string> headerNames)
        {
            for(int i = 0; i < headerNames.Count; ++i)
            {
                string name = headerNames[i];
                for(int j = 0; j < name.Length; ++j)
                {
                    if(char.IsUpper(name[j]))
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        /// <summary>Determines whether <paramref name="criticalLabels"/> contains <paramref name="label"/>.</summary>
        /// <param name="criticalLabels">The <c>crit</c> member's labels, or <see langword="null"/>.</param>
        /// <param name="label">The label to look for; compared ordinally (RFC 7515 §4).</param>
        /// <returns><see langword="true"/> when found.</returns>
        static bool ContainsCriticalLabel(IReadOnlyList<string>? criticalLabels, string label)
        {
            if(criticalLabels is null)
            {
                return false;
            }

            for(int i = 0; i < criticalLabels.Count; ++i)
            {
                if(WellKnownJAdESHeaderNames.Equals(criticalLabels[i], label))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// The creation-path throw posture: calls <see cref="Check"/> and raises <see cref="ArgumentException"/>
    /// naming the first violated clause the moment any B-B rule fails.
    /// </summary>
    /// <param name="headers">The signed-header-set aggregate to validate.</param>
    /// <param name="payloadIsDetached">See <see cref="Check"/>.</param>
    /// <param name="payloadIsCountersignedSignature">See <see cref="Check"/>.</param>
    /// <param name="x5tWasPresentOnWire">See <see cref="Check"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="headers"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">At least one B-B rule is violated; the message names the first violated clause.</exception>
    public static void EnsureConformant(
        JAdESProtectedHeaders headers,
        bool payloadIsDetached,
        bool payloadIsCountersignedSignature = false,
        bool x5tWasPresentOnWire = false)
    {
        IReadOnlyList<JAdESRuleViolation> violations = Check(headers, payloadIsDetached, payloadIsCountersignedSignature, x5tWasPresentOnWire);
        if(violations.Count == 0)
        {
            return;
        }

        JAdESRuleViolation first = violations[0];
        string suffix = violations.Count > 1
            ? $" ({violations.Count - 1} further B-B violation(s) also apply.)"
            : string.Empty;

        throw new ArgumentException($"{first.RequirementId}: {first.Message}{suffix}", nameof(headers));
    }
}


/// <summary>
/// One violated JAdES B-B cross-header rule, as reported by <see cref="JAdESHeaderRules.Check"/>. A DU-ready
/// closed sum: no external type may derive from it.
/// </summary>
[DebuggerDisplay("{RequirementId}: {Message}")]
public abstract record JAdESRuleViolation
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected JAdESRuleViolation()
    {
    }


    /// <summary>Gets the JA-* requirement identifier this violation cites.</summary>
    public abstract string RequirementId { get; }

    /// <summary>Gets a human-readable statement of what was violated.</summary>
    public abstract string Message { get; }
}


/// <summary>
/// A well-formed <see cref="JAdESProtectedHeaders"/> instance was decoded from wire content that carried an
/// <c>x5t</c> member — forbidden unconditionally (JA-5.1.6-01). See the <see cref="JAdESHeaderRules"/> remarks
/// for why this can only ever fire via the caller-attested <c>x5tWasPresentOnWire</c> fact.
/// </summary>
public sealed record JAdESX5tForbiddenViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-5.1.6-01";

    /// <inheritdoc/>
    public override string Message =>
        "JAdES signatures shall not contain the x5t header parameter specified in clause 4.1.7 of IETF RFC " +
        "7515 (ETSI TS 119 182-1 V1.2.1, clause 5.1.6).";
}


/// <summary>
/// None of <see cref="JAdESProtectedHeaders.X5tHashS256"/>, <see cref="JAdESProtectedHeaders.X5Chain"/>,
/// <see cref="JAdESProtectedHeaders.X5tHashO"/>, nor <see cref="JAdESProtectedHeaders.SigX5ts"/> is present
/// (JA-5.1.7-04: the four-way signing-certificate-identification disjunction).
/// </summary>
public sealed record JAdESSigningCertificateIdentificationViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-5.1.7-04";

    /// <inheritdoc/>
    public override string Message =>
        "A JAdES signature shall have at least one of x5t#S256, x5c, sigX5ts, or x5t#o in its JWS Protected " +
        "Header (ETSI TS 119 182-1 V1.2.1, clause 5.1.7).";
}


/// <summary>
/// <see cref="JAdESProtectedHeaders.ContentType"/> is present while the JWS Payload this signature covers is
/// caller-attested to itself be a (counter-signed) signature (JA-5.1.3-05).
/// </summary>
public sealed record JAdESContentTypeCountersignedPayloadViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-5.1.3-05";

    /// <inheritdoc/>
    public override string Message =>
        "The cty header parameter shall not be present if the JWS Payload is a (counter-signed) signature " +
        "(ETSI TS 119 182-1 V1.2.1, clause 5.1.3).";
}


/// <summary>
/// <see cref="JAdESProtectedHeaders.SigD"/> is present but the JWS Payload this signature covers is caller-
/// attested to be attached (JA-5.2.8.1-02).
/// </summary>
public sealed record JAdESDetachedObjectReferenceAttachedPayloadViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-5.2.8.1-02";

    /// <inheritdoc/>
    public override string Message =>
        "The sigD header parameter shall not appear in JAdES signatures whose JWS Payload is attached (ETSI " +
        "TS 119 182-1 V1.2.1, clause 5.2.8.1).";
}


/// <summary>
/// <see cref="JAdESProtectedHeaders.SigD"/> is present but <see cref="JAdESProtectedHeaders.CriticalLabels"/>
/// does not include <c>"sigD"</c> (JA-5.1.9-04/-05).
/// </summary>
public sealed record JAdESDetachedObjectReferenceCriticalLabelViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-5.1.9-04";

    /// <inheritdoc/>
    public override string Message =>
        "If the JAdES signature includes the sigD header parameter, the crit header parameter shall also be " +
        "present and \"sigD\" shall be one of its JSON array elements (ETSI TS 119 182-1 V1.2.1, clause 5.1.9).";
}


/// <summary>
/// <see cref="JAdESProtectedHeaders.SigD"/> selects the <c>HttpHeaders</c> mechanism
/// (<see cref="JAdESHttpHeadersReference"/>) but <see cref="JAdESProtectedHeaders.B64"/> is not present-and-
/// <see langword="false"/> (JA-5.1.10-04 / JA-5.2.8.2-02).
/// </summary>
public sealed record JAdESHttpHeadersMechanismB64Violation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-5.1.10-04";

    /// <inheritdoc/>
    public override string Message =>
        "If sigD's mId is \"http://uri.etsi.org/19182/HttpHeaders\" then the b64 header parameter shall be " +
        "present and set to \"false\" (ETSI TS 119 182-1 V1.2.1, clauses 5.1.10 and 5.2.8.2).";
}


/// <summary>
/// <see cref="JAdESProtectedHeaders.SigD"/> selects the <c>HttpHeaders</c> mechanism
/// (<see cref="JAdESHttpHeadersReference"/>) but at least one entry of
/// <see cref="JAdESHttpHeadersReference.HeaderNames"/> is not already lowercase (JA-5.2.8.2-04).
/// </summary>
public sealed record JAdESHttpHeadersParsNotLowercaseViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-5.2.8.2-04";

    /// <inheritdoc/>
    public override string Message =>
        "For the HttpHeaders referencing mechanism, the contents of the pars member shall be an array of " +
        "lowercased names of HTTP header fields (ETSI TS 119 182-1 V1.2.1, clause 5.2.8.2).";
}


/// <summary>
/// <see cref="JAdESProtectedHeaders.PayloadTimestamps"/> is present and carries a non-null <c>canonAlg</c>
/// member (JA-5.2.6-08).
/// </summary>
public sealed record JAdESPayloadTimestampCanonAlgViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-5.2.6-08";

    /// <inheritdoc/>
    public override string Message =>
        "The adoTst header parameter shall not contain the canonAlg member (ETSI TS 119 182-1 V1.2.1, clause 5.2.6).";
}


/// <summary>
/// <see cref="JAdESProtectedHeaders.IssuedAt"/> is absent: the
/// <c>iat</c>/<c>sigT</c> mandatory-optional flip date (2025-07-15T00:00:00Z) has passed, so <c>iat</c> is
/// mandatory from the outset for every conformance evaluation this rule surface performs (JA-5.1.11-08).
/// </summary>
public sealed record JAdESIssuedAtMissingViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-5.1.11-08";

    /// <inheritdoc/>
    public override string Message =>
        "Starting at 2025-07-15T00:00:00Z, the iat header parameter shall be incorporated in new JAdES " +
        "signatures (ETSI TS 119 182-1 V1.2.1, clause 5.1.11).";
}


/// <summary>
/// No <c>sigTst</c> instance is present in <c>etsiU</c> at the declared level B-T or above (<see cref="JAdESLevelRules"/>).
/// </summary>
public sealed record JAdESSignatureTimestampMissingViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-6.3-26";

    /// <inheritdoc/>
    public override string Message =>
        "At least one sigTst instance shall be present in etsiU from level B-T onward, cumulatively (ETSI TS " +
        "119 182-1 V1.2.1, clause 6.3, Table 1).";
}


/// <summary>
/// A <c>sigTst</c> instance's encapsulated <c>tstContainer</c> holds a number of electronic time-stamp tokens
/// other than exactly one (<see cref="JAdESLevelRules"/>, letter c).
/// </summary>
/// <param name="TokenCount">The number of tokens actually found.</param>
public sealed record JAdESSignatureTimestampTokenCountViolation(int TokenCount) : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-6.3-c";

    /// <inheritdoc/>
    public override string Message =>
        $"Each sigTst instance shall contain only one electronic time-stamp (ETSI TS 119 182-1 V1.2.1, clause " +
        $"6.3, additional requirement c); found {TokenCount}.";
}


/// <summary>
/// Which <c>tstContainer</c>-bearing element kind a <see cref="JAdESTimestampTokenNotBaselineViolation"/> was
/// found on.
/// </summary>
public enum JAdESTimestampContainerKind
{
    /// <summary>The <c>adoTst</c> signed header parameter (clause 5.2.6) — carried outside <c>etsiU</c>.</summary>
    PayloadTimestamp,

    /// <summary>The <c>sigTst</c> element (clause 5.3.4).</summary>
    SignatureTimestamp,

    /// <summary>The <c>arcTst</c> element (clause 5.3.6.2).</summary>
    ArchiveTimestamp,

    /// <summary>The <c>sigRTst</c> element (Annex A.1.5.1).</summary>
    SignatureAndReferencesTimestamp,

    /// <summary>The <c>rfsTst</c> element (Annex A.1.5.2).</summary>
    ReferencesTimestamp
}


/// <summary>
/// An electronic time-stamp token carried by a <c>tstContainer</c>-shaped component is not the IETF RFC
/// 3161(+5816) legacy shape (<c>type</c>/<c>encoding</c>/<c>specRef</c> all absent) — JAdES baseline signatures
/// encapsulate only that shape (<see cref="JAdESLevelRules"/>, JA-6.3-03).
/// </summary>
/// <param name="Kind">Which <c>tstContainer</c>-bearing element kind the non-baseline token was found on.</param>
public sealed record JAdESTimestampTokenNotBaselineViolation(JAdESTimestampContainerKind Kind) : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-6.3-03";

    /// <inheritdoc/>
    public override string Message =>
        $"In JAdES baseline signatures the components that act as electronic time-stamps containers shall " +
        $"encapsulate only IETF RFC 3161 updated by IETF RFC 5816 time-stamp tokens (ETSI TS 119 182-1 " +
        $"V1.2.1, clause 6.3, JA-6.3-03); a typed token was found in {Kind}.";
}


/// <summary>
/// No <c>arcTst</c> instance is present in <c>etsiU</c> at the declared level B-LTA (<see cref="JAdESLevelRules"/>).
/// </summary>
public sealed record JAdESArchiveTimestampMissingViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-6.3-42";

    /// <inheritdoc/>
    public override string Message =>
        "At least one arcTst instance shall be present in etsiU at the declared level B-LTA (ETSI TS 119 182-1 " +
        "V1.2.1, clause 6.3, Table 1).";
}


/// <summary>
/// Which <c>refs</c>-family <c>etsiU</c> element kind a <see cref="JAdESRefsFamilyForbiddenViolation"/> found
/// present at level B-LT or above.
/// </summary>
public enum JAdESRefsFamilyKind
{
    /// <summary>The <c>xRefs</c> element (Annex A.1.1, JA-6.3-29).</summary>
    CertificateReferences,

    /// <summary>The <c>rRefs</c> element (Annex A.1.2, JA-6.3-33).</summary>
    RevocationReferences,

    /// <summary>The <c>axRefs</c> element (Annex A.1.3, JA-6.3-31).</summary>
    AttributeCertificateReferences,

    /// <summary>The <c>arRefs</c> element (Annex A.1.4, JA-6.3-35).</summary>
    AttributeRevocationReferences,

    /// <summary>The <c>sigRTst</c> element (Annex A.1.5.1, JA-6.3-36).</summary>
    SignatureAndReferencesTimestamp,

    /// <summary>The <c>rfsTst</c> element (Annex A.1.5.2, JA-6.3-37).</summary>
    ReferencesTimestamp
}


/// <summary>
/// A <c>refs</c>-family <c>etsiU</c> element (<c>xRefs</c>, <c>rRefs</c>, <c>axRefs</c>, <c>arRefs</c>,
/// <c>sigRTst</c>, or <c>rfsTst</c>) is present at level B-LT or above, where Table 1 hard-forbids the whole
/// family (<see cref="JAdESLevelRules"/>).
/// </summary>
/// <param name="Kind">Which of the six <c>refs</c>-family kinds was found.</param>
public sealed record JAdESRefsFamilyForbiddenViolation(JAdESRefsFamilyKind Kind) : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Kind switch
    {
        JAdESRefsFamilyKind.CertificateReferences => "JA-6.3-29",
        JAdESRefsFamilyKind.RevocationReferences => "JA-6.3-33",
        JAdESRefsFamilyKind.AttributeCertificateReferences => "JA-6.3-31",
        JAdESRefsFamilyKind.AttributeRevocationReferences => "JA-6.3-35",
        JAdESRefsFamilyKind.SignatureAndReferencesTimestamp => "JA-6.3-36",
        JAdESRefsFamilyKind.ReferencesTimestamp => "JA-6.3-37",
        _ => throw new NotSupportedException($"Unknown {nameof(JAdESRefsFamilyKind)} value '{Kind}'.")
    };

    /// <inheritdoc/>
    public override string Message =>
        $"{Kind} shall not be present at level B-LT or above (ETSI TS 119 182-1 V1.2.1, clause 6.3, Table 1, " +
        $"{RequirementId}).";
}


/// <summary>
/// Which of <c>sigRTst</c>/<c>rfsTst</c> a <see cref="JAdESReferencesTimestampGenerationGateViolation"/> found
/// generated with no <c>refs</c>-family component present.
/// </summary>
public enum JAdESReferencesTimestampGenerationKind
{
    /// <summary>The <c>sigRTst</c> element (Annex A.1.5.1.1).</summary>
    SignatureAndReferences,

    /// <summary>The <c>rfsTst</c> element (Annex A.1.5.2.1).</summary>
    ReferencesOnly
}


/// <summary>
/// A <c>sigRTst</c> or <c>rfsTst</c> element is present in <c>etsiU</c> while none of <c>xRefs</c>/<c>rRefs</c>/
/// <c>axRefs</c>/<c>arRefs</c> is present anywhere in the same container — the generation gate both time-stamp
/// kinds share (<see cref="JAdESLevelRules"/>, JA-A.1.5.1.1-04/JA-A.1.5.2.1-04).
/// </summary>
/// <param name="Kind">Which of the two time-stamp kinds failed the gate.</param>
public sealed record JAdESReferencesTimestampGenerationGateViolation(JAdESReferencesTimestampGenerationKind Kind) : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Kind switch
    {
        JAdESReferencesTimestampGenerationKind.SignatureAndReferences => "JA-A.1.5.1.1-04",
        JAdESReferencesTimestampGenerationKind.ReferencesOnly => "JA-A.1.5.2.1-04",
        _ => throw new NotSupportedException($"Unknown {nameof(JAdESReferencesTimestampGenerationKind)} value '{Kind}'.")
    };

    /// <inheritdoc/>
    public override string Message =>
        $"If none of xRefs/rRefs/axRefs/arRefs is present, this time-stamp element shall not be generated " +
        $"(ETSI TS 119 182-1 V1.2.1, {RequirementId}); kind={Kind}.";
}


/// <summary>
/// The decoded <c>etsiU</c> set carries a <c>sigPSt</c> element but <see cref="JAdESProtectedHeaders.SignaturePolicyIdentifier"/>
/// is absent, or present without its <c>digVal</c> member — <c>sigPSt</c> may be incorporated only when
/// <c>sigPId</c> is also incorporated and carries the signature policy document's digest (<see cref="JAdESLevelRules"/>,
/// letter b).
/// </summary>
public sealed record JAdESSignaturePolicyStoreGateViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-6.3-b";

    /// <inheritdoc/>
    public override string Message =>
        "sigPSt may be incorporated only if sigPId is also incorporated and contains the digest of the " +
        "signature policy document; otherwise sigPSt shall not be incorporated (ETSI TS 119 182-1 V1.2.1, " +
        "clause 6.3, additional requirement b).";
}


/// <summary>
/// Which of <c>axRefs</c>/<c>arRefs</c> a <see cref="JAdESAttributeReferencesGateViolation"/> found present with
/// no attribute certificate or signed assertion incorporated.
/// </summary>
public enum JAdESAttributeReferencesKind
{
    /// <summary>The <c>axRefs</c> element (Annex A.1.3, JA-6.3-31).</summary>
    AttributeCertificateReferences,

    /// <summary>The <c>arRefs</c> element (Annex A.1.4, JA-6.3-35).</summary>
    AttributeRevocationReferences
}


/// <summary>
/// An <c>axRefs</c> or <c>arRefs</c> element is present while <see cref="JAdESProtectedHeaders.SignerAttributes"/>
/// carries neither a certified attribute certificate nor a signed assertion (<see cref="JAdESLevelRules"/>,
/// letter h: "may be used when at least an attribute certificate or a signed assertion is incorporated ...
/// Otherwise, axRefs and arRefs shall not be used").
/// </summary>
/// <param name="Kind">Which of the two kinds failed the gate.</param>
public sealed record JAdESAttributeReferencesGateViolation(JAdESAttributeReferencesKind Kind) : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-6.3-h";

    /// <inheritdoc/>
    public override string Message =>
        $"{Kind} may be used only when at least an attribute certificate or a signed assertion is incorporated " +
        $"into the JAdES signature; otherwise it shall not be used (ETSI TS 119 182-1 V1.2.1, clause 6.3, " +
        $"additional requirement h).";
}


/// <summary>
/// At level B-LT or above, none of <c>tstVD</c>, <c>anyValData</c>, or a caller-attested embedded-in-token fact
/// satisfies the "Incorporation of validation data for electronic time-stamps" service (<see cref="JAdESLevelRules"/>,
/// letter j).
/// </summary>
public sealed record JAdESTimestampValidationDataServiceViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-6.3-j";

    /// <inheritdoc/>
    public override string Message =>
        "At level B-LT or above, validation data for electronic time-stamps shall be present within tstVD, " +
        "within anyValData, or embedded in the electronic time-stamp itself (ETSI TS 119 182-1 V1.2.1, clause " +
        "6.3, additional requirement j); none of the three is satisfied.";
}


/// <summary>
/// An <c>xRefs</c> element contains a certificate reference whose digest matches a caller-supplied digest of the
/// JAdES signature's own signing certificate (<see cref="JAdESLevelRules"/>, JA-A.1.1-02).
/// </summary>
public sealed record JAdESReferencesSigningCertificateExclusionViolation : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-A.1.1-02";

    /// <inheritdoc/>
    public override string Message =>
        "xRefs shall not contain the reference to the signing certificate (ETSI TS 119 182-1 V1.2.1, Annex " +
        "A.1.1, JA-A.1.1-02).";
}


/// <summary>
/// Which <c>refs</c>-family digest-algorithm-identifier surface a <see cref="JAdESRefsFamilyMd5DigestAlgorithmViolation"/>
/// names MD5 on.
/// </summary>
public enum JAdESRefsFamilyDigestSurface
{
    /// <summary>An <c>xRefs</c>/<c>CertId.digAlg</c> entry (Annex A.1.1).</summary>
    CertificateReferences,

    /// <summary>An <c>axRefs</c>/<c>CertId.digAlg</c> entry (Annex A.1.3).</summary>
    AttributeCertificateReferences,

    /// <summary>An <c>rRefs</c>/<c>CRLRef.digAlg</c> or <c>OCSPRef.digAlg</c> entry (Annex A.1.2).</summary>
    RevocationReferences,

    /// <summary>An <c>arRefs</c>/<c>CRLRef.digAlg</c> or <c>OCSPRef.digAlg</c> entry (Annex A.1.4).</summary>
    AttributeRevocationReferences
}


/// <summary>
/// A <c>refs</c>-family digest-algorithm-identifier surface names MD5 — refused independent of any algorithm
/// policy (fail-closed parsing), mirroring <see cref="CBAdESRefsFamilyMd5DigestAlgorithmViolation"/>'s identical
/// posture (<see cref="JAdESLevelRules"/>, JA-6.2.1-02).
/// </summary>
/// <param name="Surface">Which digest-algorithm-identifier surface named MD5.</param>
public sealed record JAdESRefsFamilyMd5DigestAlgorithmViolation(JAdESRefsFamilyDigestSurface Surface) : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-6.2.1-02";

    /// <inheritdoc/>
    public override string Message =>
        $"MD5 shall not be used as digest algorithm (ETSI TS 119 182-1 V1.2.1, clause 6.2.1, JA-6.2.1-02); " +
        $"named at {Surface}.";
}


/// <summary>
/// Which electronic time-stamp token kind a <see cref="JAdESTimestampTokenBindingViolation"/> concerns
/// (<see cref="JAdESSignatureValidation"/>'s level-aware async per-instance token-imprint verification).
/// </summary>
public enum JAdESTimestampTokenBindingKind
{
    /// <summary>A <c>sigTst</c> token — time-stamps the base64url-encoded JWS Signature Value (clause 5.3.4, JA-5.3.4-04).</summary>
    SignatureTimestamp,

    /// <summary>
    /// An <c>arcTst</c> token — time-stamps the payload contribution, the JWS Protected Header, the JWS
    /// Signature Value, and every <c>etsiU</c> element that precedes its own <c>arcTst</c> instance (clause
    /// 5.3.6.2.3's steps, validation variant, bound only to elements preceding this instance).
    /// </summary>
    ArchiveTimestamp,

    /// <summary>A <c>sigRTst</c> token — time-stamps the signature value plus <c>sigTst</c>/<c>refs</c> (Annex A.1.5.1, bound only to elements preceding this instance).</summary>
    SignatureAndReferencesTimestamp,

    /// <summary>A <c>rfsTst</c> token — time-stamps <c>refs</c> only (Annex A.1.5.2, bound only to elements preceding this instance).</summary>
    ReferencesTimestamp
}


/// <summary>
/// Why a <see cref="JAdESTimestampTokenBindingViolation"/> was reported.
/// </summary>
public enum JAdESTimestampTokenBindingFailureReason
{
    /// <summary>
    /// <see cref="Verifiable.Cryptography.Pki.TimestampTokenInfo.ReadFromTokenAsync"/> returned a status other
    /// than <see cref="Verifiable.Cryptography.Pki.TimestampTokenInfoStatus.Read"/> — the token's DER is
    /// malformed, its message-imprint algorithm is unresolvable, or its own CMS signature did not verify.
    /// </summary>
    TokenNotRead,

    /// <summary>
    /// The token read successfully, but <see cref="Verifiable.Cryptography.Pki.TimestampTokenInfo.VerifyMessageImprintAsync"/>
    /// returned <see langword="false"/> against the expected message-imprint input.
    /// </summary>
    ImprintMismatch,

    /// <summary>
    /// The message-imprint INPUT itself could not be built — <see cref="JAdESMessageImprints"/>'s validation
    /// builder rejected the instance's own structural linkage (a mismatched <c>canonAlg</c>, or the element at
    /// the stated position is not the expected arm), or the <c>arcTst</c> payload contribution could not be
    /// resolved.
    /// </summary>
    ImprintInputUnresolvable
}


/// <summary>
/// An electronic time-stamp token could not be opened/CMS-verified, or its message imprint does not bind the
/// data it is claimed to time-stamp (<see cref="JAdESSignatureValidation"/>'s level-aware async pass).
/// Reported by that ASYNC pass, never <see cref="JAdESLevelRules.Check"/>, since opening a token requires the
/// registered CMS verification seam and computing/comparing a digest requires the registered digest delegate.
/// </summary>
/// <param name="Kind">Which token kind failed.</param>
/// <param name="Reason">Why it failed.</param>
/// <param name="Detail">A human-readable statement of the specific failure.</param>
/// <param name="InstanceOrdinal">
/// The owning <c>etsiU</c> element's own zero-based position, attributing WHICH instance of a repeated kind
/// failed (Table 1 NOTE 7 legalizes repeated <c>sigTst</c>; the same holds for <c>arcTst</c>/<c>sigRTst</c>/
/// <c>rfsTst</c>) — without it, two failing instances of the SAME <see cref="Kind"/> and <see cref="Reason"/>
/// are indistinguishable (the same precedent CB-AdES uses).
/// </param>
/// <param name="TokenOrdinal">
/// The failing token's own zero-based position within its instance's <c>tstContainer</c> (letter l: <c>arcTst</c>
/// may carry more than one token, one per configured Time-Stamping Authority leg). <c>-1</c> when the failure is
/// at the CONTAINER level, before any specific token was opened (an unresolvable message-imprint input, for
/// instance).
/// </param>
[DebuggerDisplay("JAdESTimestampTokenBindingViolation: {Kind}/{Reason} (instance #{InstanceOrdinal}, token #{TokenOrdinal})")]
public sealed record JAdESTimestampTokenBindingViolation(
    JAdESTimestampTokenBindingKind Kind,
    JAdESTimestampTokenBindingFailureReason Reason,
    string Detail,
    int InstanceOrdinal,
    int TokenOrdinal) : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Kind switch
    {
        JAdESTimestampTokenBindingKind.SignatureTimestamp => "JA-5.3.4-04",
        JAdESTimestampTokenBindingKind.ArchiveTimestamp => "JA-5.3.6.2.3",
        JAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp => "JA-A.1.5.1.2",
        JAdESTimestampTokenBindingKind.ReferencesTimestamp => "JA-A.1.5.2.2",
        _ => throw new NotSupportedException($"Unknown {nameof(JAdESTimestampTokenBindingKind)} value '{Kind}'.")
    };

    /// <inheritdoc/>
    public override string Message =>
        $"{Kind} token binding failed ({Reason}) (ETSI TS 119 182-1 V1.2.1, {RequirementId}): {Detail} " +
        $"[instance #{InstanceOrdinal}, token #{TokenOrdinal}]";
}


/// <summary>
/// Why a <see cref="JAdESCounterSignatureVerificationViolation"/> was reported (the cSig verb pair
/// <see cref="JAdESCounterSign"/> composes).
/// </summary>
public enum JAdESCounterSignatureVerificationFailureReason
{
    /// <summary>
    /// The <c>cSig</c> element's own wire text did not decode into a well-formed nested JWS/JAdES message
    /// (clause 5.3.2, JA-5.3.2-03: "the <c>cSig</c> JSON object contains one JSON Web Signature").
    /// </summary>
    DecodeFailed,

    /// <summary>
    /// <see cref="JAdESLevelRuleContext"/>'s caller-supplied countersigner public-key resolver returned no key
    /// for the decoded countersignature — verification cannot proceed without one.
    /// </summary>
    KeyUnresolved,

    /// <summary>
    /// The decoded countersignature's JWS Payload does not byte-equal the embedding JAdES signature's own JWS
    /// Signature Value (JA-5.3.2-03: the countersignature "signs the JWS Signature Value of the embedding JAdES
    /// signature" — a payload naming anything else is not a countersignature of THIS signature, regardless of
    /// whether its own cryptographic signature checks out).
    /// </summary>
    PayloadBindingMismatch,

    /// <summary>The countersignature's own cryptographic signature did not verify.</summary>
    CryptographicVerificationFailed
}


/// <summary>
/// A <c>cSig</c> element's countersignature failed to verify — <see cref="JAdESLevelRules.CheckCounterSignaturesAsync"/>'s
/// own async pass, never <see cref="JAdESLevelRules.Check"/>, since decoding and cryptographically verifying a
/// nested JWS needs the registered verification seam, unavailable to the purely-structural, synchronous rule
/// surface (mirroring <see cref="JAdESTimestampTokenBindingViolation"/>'s identical split rationale).
/// </summary>
/// <param name="Reason">Why the countersignature failed.</param>
/// <param name="InstanceOrdinal">
/// The failing <c>cSig</c> element's own zero-based position within <c>etsiU</c> — a signature may carry more
/// than one countersignature (Table 1 places no upper bound on <c>cSig</c> cardinality), so this attributes
/// WHICH one failed.
/// </param>
[DebuggerDisplay("JAdESCounterSignatureVerificationViolation: {Reason} (instance #{InstanceOrdinal})")]
public sealed record JAdESCounterSignatureVerificationViolation(
    JAdESCounterSignatureVerificationFailureReason Reason,
    int InstanceOrdinal) : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-5.3.2-03";

    /// <inheritdoc/>
    public override string Message =>
        $"cSig element #{InstanceOrdinal} failed countersignature verification ({Reason}) (ETSI TS 119 182-1 " +
        "V1.2.1, clause 5.3.2, JA-5.3.2-03).";
}


/// <summary>
/// Which kind of validation-data material a <see cref="JAdESReferencesValidationDataConsistencyViolation"/>
/// could not resolve.
/// </summary>
public enum JAdESReferenceMaterialKind
{
    /// <summary>A certificate reference could not be resolved to any candidate certificate.</summary>
    Certificate,

    /// <summary>A CRL reference could not be resolved to any candidate CRL.</summary>
    Crl,

    /// <summary>An OCSP response reference could not be resolved to any candidate OCSP response.</summary>
    Ocsp
}


/// <summary>
/// A <c>refs</c>-family entry (<c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/<c>arRefs</c>) does not resolve to any
/// candidate material present elsewhere in the signature — <see cref="JAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/>'s
/// own async pass (JA-A.1.1-12/JA-A.1.2-35/JA-A.1.3-08/JA-A.1.4-10, the CB-A.1.1-30 analog), never
/// <see cref="JAdESLevelRules.Check"/>, since resolution needs the registered digest delegate.
/// </summary>
/// <param name="Surface">Which <c>refs</c>-family element carried the unresolved entry.</param>
/// <param name="MaterialKind">Which kind of material the entry names.</param>
[DebuggerDisplay("JAdESReferencesValidationDataConsistencyViolation: {Surface}/{MaterialKind}")]
public sealed record JAdESReferencesValidationDataConsistencyViolation(
    JAdESRefsFamilyDigestSurface Surface,
    JAdESReferenceMaterialKind MaterialKind) : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Surface switch
    {
        JAdESRefsFamilyDigestSurface.CertificateReferences => "JA-A.1.1-12",
        JAdESRefsFamilyDigestSurface.RevocationReferences => "JA-A.1.2-35",
        JAdESRefsFamilyDigestSurface.AttributeCertificateReferences => "JA-A.1.3-08",
        JAdESRefsFamilyDigestSurface.AttributeRevocationReferences => "JA-A.1.4-10",
        _ => throw new NotSupportedException($"Unknown {nameof(JAdESRefsFamilyDigestSurface)} value '{Surface}'.")
    };

    /// <inheritdoc/>
    public override string Message =>
        $"A {Surface} entry's referenced {MaterialKind} material was not found present elsewhere in the " +
        $"signature (ETSI TS 119 182-1 V1.2.1, {RequirementId}).";
}


/// <summary>
/// An <c>etsiU</c> catch-all <c>JAdESUnsignedHeaderElementUnknown</c> element's own kind carries no Annex D
/// disclosure in the caller's opt-in <see cref="JAdESLevelRuleContext.AlternativeMechanismDisclosures"/> registry
/// (clause 6.1 NOTE 4's "Annex C" mis-citation read as Annex D). Reported only
/// when the caller supplies a non-<see langword="null"/> registry — see
/// <see cref="Verifiable.Cryptography.Pki.JAdESAlternativeMechanismDisclosureRegistry"/>'s own remarks for why an
/// opted-out caller never sees this violation.
/// </summary>
/// <param name="Kind">The undisclosed catch-all element's own <c>etsiU</c> JSON key.</param>
[DebuggerDisplay("JAdESUndisclosedAlternativeMechanismViolation: {Kind}")]
public sealed record JAdESUndisclosedAlternativeMechanismViolation(string Kind) : JAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "JA-D-02";

    /// <inheritdoc/>
    public override string Message =>
        $"The unsigned component '{Kind}' is not one this document defines and carries no registered Annex D " +
        "disclosure (ETSI TS 119 182-1 V1.2.1, Annex D, JA-D-02).";
}

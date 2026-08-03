using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The shared CB-AdES B-B (baseline) rule surface: every cross-header conformance rule Table 14 (clause 6.3)
/// of <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> imposes over a <see cref="CBAdESProtectedHeaders"/> instance, implemented
/// exactly once and consumed by both postures a caller needs (wavecb-contract.md ruling R-1(c)/R-2, S3
/// coordinator ruling (2)):
/// </summary>
/// <remarks>
/// <para>
/// <strong>Two postures, one implementation.</strong> <see cref="Check"/> is the COLLECT posture — it never
/// throws on malformed or non-conformant input (R-5), returning every violation found so a validator parsing
/// untrusted wire bytes can report all of them at once. <see cref="EnsureConformant"/> is the THROW posture —
/// the creation path's trusted-caller-input guard, calling <see cref="Check"/> and raising
/// <see cref="ArgumentException"/> naming the first violated clause the moment any rule fails. Both routes
/// through the exact same rule bodies, so a rule can never drift between what creation refuses to produce and
/// what validation refuses to accept.
/// </para>
/// <para>
/// <strong><see cref="CBAdESProtectedHeaders"/> itself stays non-null; <see cref="CBAdESProtectedHeaders.CwtClaims"/>
/// does not (wavecb S3 FX-E).</strong> This surface operates on an already-constructed
/// <see cref="CBAdESProtectedHeaders"/> instance — <paramref name="headers"/> itself is refused with
/// <see cref="ArgumentNullException"/> when null (below), a caller-contract violation, not a conformance
/// judgment — but that type's own constructor no longer enforces <see cref="CBAdESProtectedHeaders.CwtClaims"/>
/// non-null: a parsed message whose CWT Claims header (label 15) is absent entirely, or present with no
/// <c>iat</c> member, decodes with a <see langword="null"/> <see cref="CBAdESProtectedHeaders.CwtClaims"/>
/// rather than failing the parse (see <see cref="Verifiable.Cbor.CBAdESSignatureSerialization.ParseCBAdESSign1"/>'s
/// own remarks). <see cref="Check"/> therefore reports <see cref="CBAdESCwtClaimsMissingViolation"/>
/// (CB-6.3-10/CB-6.3-a, D10) as a genuinely LIVE rule, reachable from untrusted wire content exactly like every
/// other violation this method collects — not the structurally-unreachable placeholder an earlier revision of
/// this file recorded before <see cref="CBAdESProtectedHeaders.CwtClaims"/> became nullable.
/// </para>
/// <para>
/// <strong>The tri-way counts PROTECTED headers only (S3 coordinator ruling (2)).</strong> CB-5.2.2-07's
/// wording is "in the protected headers map"; <see cref="CBAdESProtectedHeaders.X5T"/>,
/// <see cref="CBAdESProtectedHeaders.CertificateDigests"/>, and <see cref="CBAdESProtectedHeaders.X5Chain"/>
/// are already, exclusively, the signed occurrences of those three components by this aggregate's own shape
/// (the unsigned <c>x5chain</c> occurrence is a distinct type, <see cref="CBAdESUnsignedHeaderElementCertificateChain"/>,
/// unreachable through <see cref="CBAdESProtectedHeaders"/>) — so <see cref="Check"/> satisfies "protected
/// headers only" by construction, with no separate signedness test needed.
/// </para>
/// </remarks>
public static class CBAdESHeaderRules
{
    /// <summary>
    /// Evaluates every B-B rule against <paramref name="headers"/> and returns every violation found. Never
    /// throws on non-conformant content (R-5) — only a <see langword="null"/> <paramref name="headers"/>
    /// itself (a caller contract violation, not a conformance judgment) raises
    /// <see cref="ArgumentNullException"/>.
    /// </summary>
    /// <param name="headers">The signed-header-set aggregate to evaluate.</param>
    /// <param name="payloadIsDetached">
    /// <see langword="true"/> when the COSE Payload this signature covers is detached (clause 4.5); this
    /// aggregate carries no payload of its own, so the caller supplies the fact.
    /// </param>
    /// <param name="unsignedHeaders">
    /// The decoded <c>uHeaders</c> unsigned-header set this signature carries, or <see langword="null"/> when
    /// absent (CB-5.3.1-07: <c>uHeaders</c> either does not exist at all, or is non-empty — never
    /// exists-but-empty). Consulted only for the CB-6.3-b <c>sigPSt</c> gate.
    /// </param>
    /// <returns>Every violation found, in rule-declaration order; empty when <paramref name="headers"/> is fully B-B conformant.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="headers"/> is <see langword="null"/>.</exception>
    public static IReadOnlyList<CBAdESRuleViolation> Check(
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        CBAdESUnsignedHeaders? unsignedHeaders)
    {
        ArgumentNullException.ThrowIfNull(headers);

        var violations = new List<CBAdESRuleViolation>();

        if(headers.X5T is null && headers.CertificateDigests is null && headers.X5Chain is null)
        {
            violations.Add(new CBAdESCertificateReferenceTriWayViolation());
        }

        if(headers.CwtClaims is null)
        {
            violations.Add(new CBAdESCwtClaimsMissingViolation());
        }

        if(headers.ContentType is not null && headers.DetachedObjects is not null)
        {
            violations.Add(new CBAdESContentTypeDetachedObjectsExclusivityViolation());
        }

        if(headers.DetachedObjects is not null)
        {
            if(!ContainsCriticalLabel(headers.CriticalLabels, CBAdESHeaderParameters.SigD))
            {
                violations.Add(new CBAdESDetachedObjectsCriticalLabelViolation());
            }

            if(!payloadIsDetached)
            {
                violations.Add(new CBAdESDetachedObjectsAttachedPayloadViolation());
            }

            if(CBAdESDetachedMechanisms.IsObjectIdByURI(headers.DetachedObjects.MechanismIdentifier)
                && headers.DetachedObjects.HashAlgorithm is not null)
            {
                violations.Add(new CBAdESDetachedObjectsUriMechanismDigestViolation());
            }

            if(CBAdESDetachedMechanisms.IsObjectIdByURIHash(headers.DetachedObjects.MechanismIdentifier)
                && headers.DetachedObjects.HashAlgorithm is null)
            {
                violations.Add(new CBAdESDetachedObjectsUriHashMechanismDigestViolation());
            }
        }

        if(HasSignaturePolicyStore(unsignedHeaders) && headers.SignaturePolicyIdentifier is null)
        {
            violations.Add(new CBAdESSignaturePolicyStoreGateViolation());
        }

        CollectMd5Violations(headers, violations);

        return violations;

        /// <summary>
        /// Determines whether <paramref name="criticalLabels"/> contains the <see cref="CoseHeaderIntegerLabel"/>
        /// equal to <paramref name="label"/> — record equality, per wavecb S3 FX-H's widened
        /// <see cref="CoseHeaderLabel"/> union (a <see cref="CoseHeaderTextLabel"/> entry never matches, since
        /// <paramref name="label"/> is always one of this document's own integer-assigned labels).
        /// </summary>
        /// <param name="criticalLabels">The <c>crit</c> member's labels, or <see langword="null"/>.</param>
        /// <param name="label">The integer label to look for.</param>
        /// <returns><see langword="true"/> when found.</returns>
        static bool ContainsCriticalLabel(IReadOnlyList<CoseHeaderLabel>? criticalLabels, int label)
        {
            if(criticalLabels is null)
            {
                return false;
            }

            var candidate = new CoseHeaderIntegerLabel(label);
            for(int i = 0; i < criticalLabels.Count; ++i)
            {
                if(criticalLabels[i].Equals(candidate))
                {
                    return true;
                }
            }

            return false;
        }


        /// <summary>Determines whether <paramref name="candidate"/> carries a <c>sigPSt</c> element.</summary>
        /// <param name="candidate">The decoded <c>uHeaders</c> set, or <see langword="null"/>.</param>
        /// <returns><see langword="true"/> when a <c>sigPSt</c> element is present.</returns>
        static bool HasSignaturePolicyStore(CBAdESUnsignedHeaders? candidate)
        {
            if(candidate is null)
            {
                return false;
            }

            for(int i = 0; i < candidate.Count; ++i)
            {
                if(candidate[i] is CBAdESUnsignedHeaderElementSignaturePolicyStore)
                {
                    return true;
                }
            }

            return false;
        }


        /// <summary>
        /// Appends one <see cref="CBAdESMd5DigestAlgorithmViolation"/> to <paramref name="collected"/> for
        /// every digest-algorithm-identifier surface of <paramref name="candidate"/> that names MD5
        /// (CB-6.2.1-02).
        /// </summary>
        /// <param name="candidate">The signed-header-set aggregate to scan.</param>
        /// <param name="collected">The violation list to append to.</param>
        /// <remarks>
        /// <see cref="CBAdESProtectedHeaders.Algorithm"/> is deliberately NOT scanned here: it is
        /// <see langword="int"/>-only by that member's own documented design decision, and the
        /// <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms
        /// registry</see> has never assigned MD5 an integer identifier (verified against every identifier this
        /// library's own <see cref="WellKnownCoseAlgorithms"/>/<see cref="CBAdESDigestAlgorithmIdentifier"/>
        /// surfaces recognize) — no value <see cref="CBAdESProtectedHeaders.Algorithm"/> can hold encodes an
        /// MD5 claim, so its hard-denylist coverage is satisfied BY CONSTRUCTION (the type cannot represent
        /// the violation) rather than by a runtime comparison that could only ever evaluate false. Every other
        /// surface below carries a <see cref="CBAdESDigestAlgorithmIdentifier"/> — the CDDL's <c>int / tstr</c>
        /// union, whose <c>tstr</c> arm a non-conformant or malicious producer can still populate with the
        /// literal text <c>"MD5"</c> even though IANA never registered it — so those surfaces get a real
        /// runtime check via <see cref="IsMd5"/>.
        /// </remarks>
        static void CollectMd5Violations(CBAdESProtectedHeaders candidate, List<CBAdESRuleViolation> collected)
        {
            if(candidate.X5T is not null && IsMd5(candidate.X5T.HashAlgorithm))
            {
                collected.Add(new CBAdESMd5DigestAlgorithmViolation(CBAdESMd5DigestAlgorithmSurface.CertificateThumbprint));
            }

            if(candidate.CertificateDigests is not null)
            {
                for(int i = 0; i < candidate.CertificateDigests.Thumbprints.Count; ++i)
                {
                    if(IsMd5(candidate.CertificateDigests.Thumbprints[i].HashAlgorithm))
                    {
                        collected.Add(new CBAdESMd5DigestAlgorithmViolation(CBAdESMd5DigestAlgorithmSurface.CertificateDigests));
                        break;
                    }
                }
            }

            if(candidate.SignaturePolicyIdentifier is not null && IsMd5(candidate.SignaturePolicyIdentifier.HashAlgorithm))
            {
                collected.Add(new CBAdESMd5DigestAlgorithmViolation(CBAdESMd5DigestAlgorithmSurface.SignaturePolicyIdentifier));
            }

            if(candidate.DetachedObjects is not null && IsMd5(candidate.DetachedObjects.HashAlgorithm))
            {
                collected.Add(new CBAdESMd5DigestAlgorithmViolation(CBAdESMd5DigestAlgorithmSurface.DetachedObjectsHashAlgorithm));
            }
        }


        /// <summary>
        /// Determines whether <paramref name="identifier"/> names MD5 — the <c>tstr</c> arm compared
        /// case-insensitively against <c>"MD5"</c>; the <c>int</c> arm never matches, since no IANA COSE
        /// Algorithms registry entry names MD5 (see the <see cref="CollectMd5Violations"/> remarks).
        /// </summary>
        /// <param name="identifier">The digest-algorithm identifier to test, or <see langword="null"/>.</param>
        /// <returns><see langword="true"/> when <paramref name="identifier"/> names MD5.</returns>
        static bool IsMd5(CBAdESDigestAlgorithmIdentifier? identifier) => identifier switch
        {
            CBAdESDigestAlgorithmTextIdentifier text => string.Equals(text.Value, "MD5", StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }


    /// <summary>
    /// The creation-path throw posture: calls <see cref="Check"/> and raises <see cref="ArgumentException"/>
    /// naming the first violated clause the moment any B-B rule fails. Trusted-caller-input semantics — a
    /// creation call site that reaches a violation has a defect in the caller, not in untrusted wire content,
    /// so a hard failure at the point of misuse is preferable to producing a silently non-conformant signature.
    /// </summary>
    /// <param name="headers">The signed-header-set aggregate to validate.</param>
    /// <param name="payloadIsDetached">See <see cref="Check"/>.</param>
    /// <param name="unsignedHeaders">See <see cref="Check"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="headers"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">At least one B-B rule is violated; the message names the first violated clause.</exception>
    public static void EnsureConformant(
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        CBAdESUnsignedHeaders? unsignedHeaders)
    {
        IReadOnlyList<CBAdESRuleViolation> violations = Check(headers, payloadIsDetached, unsignedHeaders);
        if(violations.Count == 0)
        {
            return;
        }

        CBAdESRuleViolation first = violations[0];
        string suffix = violations.Count > 1
            ? $" ({violations.Count - 1} further B-B violation(s) also apply.)"
            : string.Empty;

        throw new ArgumentException($"{first.RequirementId}: {first.Message}{suffix}", nameof(headers));
    }
}


/// <summary>
/// One violated CB-AdES B-B rule, as reported by <see cref="CBAdESHeaderRules.Check"/>. A DU-ready closed sum:
/// no external type may derive from it.
/// </summary>
[DebuggerDisplay("{RequirementId}: {Message}")]
public abstract record CBAdESRuleViolation
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESRuleViolation()
    {
    }


    /// <summary>Gets the CB-* requirement identifier this violation cites.</summary>
    public abstract string RequirementId { get; }

    /// <summary>Gets a human-readable statement of what was violated.</summary>
    public abstract string Message { get; }
}


/// <summary>
/// Neither <see cref="CBAdESProtectedHeaders.X5T"/>, <see cref="CBAdESProtectedHeaders.CertificateDigests"/>,
/// nor <see cref="CBAdESProtectedHeaders.X5Chain"/> is present in the protected headers map (D9: the tri-way
/// condition, implemented once and shared by all three Table 14 rows it governs).
/// </summary>
public sealed record CBAdESCertificateReferenceTriWayViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-5.2.2-07";

    /// <inheritdoc/>
    public override string Message =>
        "At least one of x5t, x5ts, or x5chain shall be present in the protected headers map (ETSI TS 119 " +
        "152-1 V1.1.1, clause 5.2.2).";
}


/// <summary>
/// <see cref="CBAdESProtectedHeaders.CwtClaims"/> is absent — a legal, non-conformant parsed state (wavecb S3
/// FX-E: <see cref="CBAdESProtectedHeaders.CwtClaims"/> is nullable, covering both a wire message with no CWT
/// Claims header at all and one whose CWT Claims map carries no <c>iat</c> member) reported here rather than
/// failing the parse; see the <see cref="CBAdESHeaderRules"/> remarks.
/// </summary>
public sealed record CBAdESCwtClaimsMissingViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-6.3-10";

    /// <inheritdoc/>
    public override string Message =>
        "The CWT Claims header parameter (carrying iat) shall be present at every Table 14 level (ETSI TS " +
        "119 152-1 V1.1.1, clause 6.3, Table 14; clause 6.3, additional requirement (a), CB-6.3-a).";
}


/// <summary>
/// Both <see cref="CBAdESProtectedHeaders.ContentType"/> and <see cref="CBAdESProtectedHeaders.DetachedObjects"/>
/// are present — the two are mutually exclusive.
/// </summary>
public sealed record CBAdESContentTypeDetachedObjectsExclusivityViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-5.1.3-03";

    /// <inheritdoc/>
    public override string Message =>
        "content type shall not be present when sigD is present (ETSI TS 119 152-1 V1.1.1, clause 5.1.3).";
}


/// <summary>
/// <see cref="CBAdESProtectedHeaders.DetachedObjects"/> is present but <see cref="CBAdESProtectedHeaders.CriticalLabels"/>
/// does not include <c>sigD</c>'s assigned label (267).
/// </summary>
public sealed record CBAdESDetachedObjectsCriticalLabelViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-5.1.10-04";

    /// <inheritdoc/>
    public override string Message =>
        "When sigD is present, crit shall also be present and shall include sigD's assigned label (267) " +
        "(ETSI TS 119 152-1 V1.1.1, clause 5.1.10).";
}


/// <summary>
/// <see cref="CBAdESProtectedHeaders.DetachedObjects"/> is present but the COSE Payload is attached rather
/// than detached.
/// </summary>
public sealed record CBAdESDetachedObjectsAttachedPayloadViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-5.2.8-03";

    /// <inheritdoc/>
    public override string Message =>
        "sigD shall not appear in a signature with an attached COSE Payload (ETSI TS 119 152-1 V1.1.1, " +
        "clause 5.2.8.1).";
}


/// <summary>
/// <see cref="CBAdESProtectedHeaders.DetachedObjects"/> selects the <c>ObjectIdByURI</c> mechanism
/// (<see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/>) but carries a <c>hashM</c> digest algorithm — that
/// mechanism carries neither <c>hashM</c> nor <c>hashV</c>.
/// </summary>
public sealed record CBAdESDetachedObjectsUriMechanismDigestViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-5.2.8.2.2-02";

    /// <inheritdoc/>
    public override string Message =>
        "Under the ObjectIdByURI mechanism, neither hashM nor hashV shall be present (ETSI TS 119 152-1 " +
        "V1.1.1, clause 5.2.8.2.2).";
}


/// <summary>
/// <see cref="CBAdESProtectedHeaders.DetachedObjects"/> selects the <c>ObjectIdByURIHash</c> mechanism
/// (<see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/>) but carries no <c>hashM</c> digest algorithm —
/// that mechanism requires both <c>hashM</c> and <c>hashV</c>.
/// </summary>
public sealed record CBAdESDetachedObjectsUriHashMechanismDigestViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-5.2.8.2.3-02";

    /// <inheritdoc/>
    public override string Message =>
        "Under the ObjectIdByURIHash mechanism, both hashM and hashV shall be present (ETSI TS 119 152-1 " +
        "V1.1.1, clause 5.2.8.2.3).";
}


/// <summary>
/// The decoded <c>uHeaders</c> set carries a <c>sigPSt</c> element but
/// <see cref="CBAdESProtectedHeaders.SignaturePolicyIdentifier"/> is absent — <c>sigPSt</c> may be
/// incorporated only when <c>sigPId</c> is also incorporated and carries its digest
/// (<see cref="CBAdESSignaturePolicyIdentifier.Digest"/> is a required member, so any non-null
/// <see cref="CBAdESProtectedHeaders.SignaturePolicyIdentifier"/> already satisfies the digest half of this
/// gate).
/// </summary>
public sealed record CBAdESSignaturePolicyStoreGateViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-6.3-b";

    /// <inheritdoc/>
    public override string Message =>
        "sigPSt may be incorporated only if sigPId is also incorporated and contains the digest of the " +
        "signature policy document; otherwise sigPSt shall not be incorporated (ETSI TS 119 152-1 V1.1.1, " +
        "clause 6.3, additional requirement (b)).";
}


/// <summary>
/// Which digest-algorithm-identifier surface of a <see cref="CBAdESProtectedHeaders"/> instance a
/// <see cref="CBAdESMd5DigestAlgorithmViolation"/> names MD5 on.
/// </summary>
public enum CBAdESMd5DigestAlgorithmSurface
{
    /// <summary><see cref="CBAdESProtectedHeaders.X5T"/>'s hash algorithm.</summary>
    CertificateThumbprint,

    /// <summary>An entry of <see cref="CBAdESProtectedHeaders.CertificateDigests"/>.</summary>
    CertificateDigests,

    /// <summary><see cref="CBAdESProtectedHeaders.SignaturePolicyIdentifier"/>'s digest pair.</summary>
    SignaturePolicyIdentifier,

    /// <summary><see cref="CBAdESProtectedHeaders.DetachedObjects"/>'s <c>hashM</c> member.</summary>
    DetachedObjectsHashAlgorithm
}


/// <summary>
/// A digest-algorithm-identifier surface of a <see cref="CBAdESProtectedHeaders"/> instance names MD5 —
/// refused independent of any algorithm policy (R-5, wavecb-contract.md).
/// </summary>
/// <param name="Surface">Which surface named MD5 — see <see cref="CBAdESMd5DigestAlgorithmSurface"/>.</param>
public sealed record CBAdESMd5DigestAlgorithmViolation(CBAdESMd5DigestAlgorithmSurface Surface) : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-6.2.1-02";

    /// <inheritdoc/>
    public override string Message =>
        $"MD5 shall not be used as a digest algorithm (ETSI TS 119 152-1 V1.1.1, clause 6.2.1); named at {Surface}.";
}


/// <summary>
/// No <c>sigTst</c> instance is present in <c>uHeaders</c> at level B-T or above (<see cref="CBAdESLevelRules"/>,
/// wavecb S4).
/// </summary>
/// <remarks>
/// CB-6.3-21's Table 14 cardinality cell is level-split: <c>B-B: &gt;=0</c>; <c>B-T, B-LT, B-LTA: &gt;=1</c>,
/// then a duplicated <c>B-LT, B-LTA: 0</c> sub-line (D2, wavecb-contract.md R-6, reproduced verbatim per the
/// register — the duplicate could not be resolved to two distinct meanings from the source text). This
/// violation enforces the cumulative <c>&gt;=1</c> reading: once level B-T is reached, at least one <c>sigTst</c>
/// instance shall be present in <c>uHeaders</c> and (append-only, CB-5.3.1-03) shall remain present at every
/// higher level; the duplicated <c>B-LT, B-LTA: 0</c> sub-line is read as "zero NEW instances required" at
/// those levels, not "zero total" — a distinct, non-enforceable-from-one-snapshot fact this record's doc
/// comment records rather than checks (a before/after-augmentation comparison, not a single-snapshot
/// invariant, would be needed to enforce the "zero new" half; that is the augmenting orchestrator's own
/// concern, not this collect-posture rule's).
/// </remarks>
public sealed record CBAdESSignatureTimestampMissingViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-6.3-21";

    /// <inheritdoc/>
    public override string Message =>
        "At least one sigTst instance shall be present in uHeaders from level B-T onward, cumulatively " +
        "(ETSI TS 119 152-1 V1.1.1, clause 6.3, Table 14).";
}


/// <summary>
/// A <c>sigTst</c> instance's encapsulated <c>tstContainer</c> holds a number of electronic time-stamp
/// tokens other than exactly one (<see cref="CBAdESLevelRules"/>, wavecb S4).
/// </summary>
/// <param name="TokenCount">The actual number of tokens found in the offending <c>sigTst</c> instance.</param>
/// <remarks>
/// Additional requirement (c): "Each <c>sigTst</c> shall contain only one electronic time-stamp." Distinct
/// from <see cref="CBAdESSignatureTimestampMissingViolation"/>'s Table 14 cardinality (the COUNT of
/// <c>sigTst</c> INSTANCES): multiple TSAs are achieved via multiple <c>sigTst</c> instances (Table 14 note
/// 7), never via multiple tokens inside one instance's <c>tstContainer</c>.
/// </remarks>
public sealed record CBAdESSignatureTimestampTokenCountViolation(int TokenCount) : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-6.3-c";

    /// <inheritdoc/>
    public override string Message =>
        $"Each sigTst instance shall contain only one electronic time-stamp (ETSI TS 119 152-1 V1.1.1, " +
        $"clause 6.3, additional requirement (c)); found {TokenCount}.";
}


/// <summary>
/// Which <c>tstContainer</c>-bearing <c>uHeaders</c> element kind a <see cref="CBAdESTimestampTokenNotBaselineViolation"/>
/// was found on.
/// </summary>
public enum CBAdESTimestampContainerKind
{
    /// <summary>The <c>sigTst</c> element (Table 8, label 1).</summary>
    SignatureTimestamp,

    /// <summary>The <c>arcTst</c> element (Table 8, label 3).</summary>
    ArchiveTimestamp,

    /// <summary>The <c>sigRTst</c> element (Table 8, label 5, Annex A.1.2.1).</summary>
    SignatureAndReferencesTimestamp,

    /// <summary>The <c>rfsTst</c> element (Table 8, label 6, Annex A.1.2.2).</summary>
    ReferencesTimestamp
}


/// <summary>
/// A <c>TstToken</c> carries a <c>type</c>, <c>encoding</c>, or <c>specRef</c> member — the explicitly-typed
/// token shape clause 5.4.3.3 defines for non-RFC-3161 formats — where CB-AdES baseline conformance narrows
/// every time-stamp-token container to the legacy RFC 3161(+5816) shape only
/// (<see cref="CBAdESLevelRules"/>, wavecb S4).
/// </summary>
/// <param name="Kind">Which container kind the offending token was found in.</param>
/// <remarks>
/// CB-6.3-02: "In CB-AdES baseline signatures, the components acting as electronic time-stamp containers
/// shall encapsulate only IETF RFC 3161 (updated by RFC 5816) time-stamp tokens" — for an RFC 3161 token,
/// <c>type</c>/<c>encoding</c>/<c>specRef</c> shall all be absent (clause 5.4.3.3, CB-5.4.3.3-05/06/07). This
/// is a baseline-wide statement, not level-specific, so this rule scans every <c>sigTst</c>/<c>arcTst</c>/
/// <c>sigRTst</c>/<c>rfsTst</c> element found in <c>uHeaders</c> regardless of the current level.
/// </remarks>
public sealed record CBAdESTimestampTokenNotBaselineViolation(CBAdESTimestampContainerKind Kind) : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-6.3-02";

    /// <inheritdoc/>
    public override string Message =>
        $"Every electronic time-stamp token shall be the IETF RFC 3161(+5816) legacy shape (type/encoding/" +
        $"specRef absent) in CB-AdES baseline signatures (ETSI TS 119 152-1 V1.1.1, clause 6.3, CB-6.3-02); " +
        $"a typed token was found in {Kind}.";
}


/// <summary>
/// Which <c>refs</c>-family <c>uHeaders</c> element kind a <see cref="CBAdESRefsFamilyForbiddenViolation"/>
/// found present at level B-LT or above.
/// </summary>
public enum CBAdESRefsFamilyKind
{
    /// <summary>The <c>refs</c> element (Annex A.1.1, Table 8 label 4).</summary>
    References,

    /// <summary>The <c>sigRTst</c> element (Annex A.1.2.1, Table 8 label 5).</summary>
    SignatureAndReferencesTimestamp,

    /// <summary>The <c>rfsTst</c> element (Annex A.1.2.2, Table 8 label 6).</summary>
    ReferencesTimestamp
}


/// <summary>
/// A <c>refs</c>-family <c>uHeaders</c> element (<c>refs</c>, <c>sigRTst</c>, or <c>rfsTst</c>) is present at
/// level B-LT or above, where Table 14 hard-forbids the whole family (<see cref="CBAdESLevelRules"/>, wavecb
/// S4).
/// </summary>
/// <param name="Kind">Which family member was found present.</param>
/// <remarks>
/// CB-6.3-23 (<c>refs</c>), CB-6.3-24 (<c>sigRTst</c>), CB-6.3-25 (<c>rfsTst</c>): all three carry presence
/// <c>"*"</c> (should-not) at B-B/B-T and <c>shall not be present</c> at B-LT/B-LTA, with cardinality <c>0</c>
/// hard-enforced at those two levels. A level-upgrade to B-LT must strip every pre-existing instance of the
/// three (the augmenting orchestrator's own concern, not this collect-posture rule's, which only reports
/// what it finds).
/// </remarks>
public sealed record CBAdESRefsFamilyForbiddenViolation(CBAdESRefsFamilyKind Kind) : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Kind switch
    {
        CBAdESRefsFamilyKind.References => "CB-6.3-23",
        CBAdESRefsFamilyKind.SignatureAndReferencesTimestamp => "CB-6.3-24",
        CBAdESRefsFamilyKind.ReferencesTimestamp => "CB-6.3-25",
        _ => throw new NotSupportedException($"Unknown {nameof(CBAdESRefsFamilyKind)} value '{Kind}'.")
    };

    /// <inheritdoc/>
    public override string Message =>
        $"{Kind} shall not be present at level B-LT or above (ETSI TS 119 152-1 V1.1.1, clause 6.3, Table 14, " +
        $"{RequirementId}).";
}


/// <summary>
/// Which <c>refs</c>-family time-stamp element kind a <see cref="CBAdESReferencesTimestampGenerationGateViolation"/>
/// was generated for without a preceding <c>refs</c> element.
/// </summary>
public enum CBAdESReferencesTimestampGenerationKind
{
    /// <summary>The <c>sigRTst</c> element (Annex A.1.2.1).</summary>
    SignatureAndReferences,

    /// <summary>The <c>rfsTst</c> element (Annex A.1.2.2).</summary>
    ReferencesOnly
}


/// <summary>
/// A <c>sigRTst</c> or <c>rfsTst</c> element is present in <c>uHeaders</c> with no <c>refs</c> element
/// preceding it in wire order — the generation gate both time-stamp kinds share
/// (<see cref="CBAdESLevelRules"/>, wavecb S4).
/// </summary>
/// <param name="Kind">Which of the two time-stamp kinds failed the gate.</param>
/// <remarks>
/// CB-A.1.2.1-03: "If the component <c>refs</c> is not present, the <c>sigRTst</c> CBOR map shall not be
/// generated." CB-A.1.2.2-03: the identical gate for <c>rfsTst</c>. Because <c>uHeaders</c> is append-only
/// (CB-5.3.1-03), "present at generation time" is checked positionally: a <c>refs</c> element shall appear
/// at some position strictly before the <c>sigRTst</c>/<c>rfsTst</c> element under check
/// (<see cref="Verifiable.Cryptography.Pki.CBAdESUnsignedHeaders.ElementsBefore(int)"/>).
/// </remarks>
public sealed record CBAdESReferencesTimestampGenerationGateViolation(CBAdESReferencesTimestampGenerationKind Kind) : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Kind switch
    {
        CBAdESReferencesTimestampGenerationKind.SignatureAndReferences => "CB-A.1.2.1-03",
        CBAdESReferencesTimestampGenerationKind.ReferencesOnly => "CB-A.1.2.2-03",
        _ => throw new NotSupportedException($"Unknown {nameof(CBAdESReferencesTimestampGenerationKind)} value '{Kind}'.")
    };

    /// <inheritdoc/>
    public override string Message =>
        $"A refs element shall precede this time-stamp element in uHeaders wire order (ETSI TS 119 152-1 " +
        $"V1.1.1, Annex A.1.2.1.1/A.1.2.2.1, {RequirementId}); kind={Kind}.";
}


/// <summary>
/// At level B-LT or above, neither a <c>valData</c> element is present in <c>uHeaders</c> nor does any
/// electronic time-stamp token carry its own embedded certificate/revocation validation material — the
/// validation-data-for-time-stamps service (CB-6.3-26) is unsatisfied by either of its two SPOs
/// (<see cref="CBAdESLevelRules"/>, wavecb S4).
/// </summary>
/// <remarks>
/// <para>
/// Additional requirement (h): "The validation data for electronic time-stamps shall be present within
/// <c>valData</c> OR embedded in the electronic time-stamp itself." A disjunctive hard requirement — this
/// violation is reported only when BOTH SPOs fail, never when just one does.
/// </para>
/// <para>
/// Additional requirement (i) (a SHOULD, not enforced as a violation, recorded here only): "The validation
/// data for electronic time-stamps should be included within <c>valData</c>" — a soft preference for the
/// <c>valData</c> SPO over the embedded-in-token SPO when a generator has a genuine choice between them.
/// </para>
/// </remarks>
public sealed record CBAdESTimestampValidationDataServiceViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-6.3-26";

    /// <inheritdoc/>
    public override string Message =>
        "At level B-LT or above, validation data for electronic time-stamps shall be present within valData " +
        "or embedded in the electronic time-stamp itself (ETSI TS 119 152-1 V1.1.1, clause 6.3, Table 14, " +
        "additional requirement (h)); neither SPO is satisfied.";
}


/// <summary>
/// A <c>refs</c> element's <c>xRefs</c> (certificate references) contains a reference whose digest matches
/// a digest of the CB-AdES signature's own signing certificate (<see cref="CBAdESLevelRules"/>, wavecb S4).
/// </summary>
/// <remarks>
/// CB-A.1.1-02: "The <c>refs</c> CBOR map shall not contain the signing certificate of the CB-AdES signature
/// itself." Detected by byte-comparing every <c>CertId.x5t</c> digest against every caller-supplied signing-
/// certificate digest (the caller supplies these because this rule surface cannot itself derive the signing
/// certificate from a <c>uHeaders</c> snapshot alone).
/// </remarks>
public sealed record CBAdESReferencesSigningCertificateExclusionViolation : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-A.1.1-02";

    /// <inheritdoc/>
    public override string Message =>
        "refs shall not contain the signing certificate of the CB-AdES signature itself (ETSI TS 119 152-1 " +
        "V1.1.1, Annex A.1.1, CB-A.1.1-02).";
}


/// <summary>
/// Which <c>refs</c>-family digest-algorithm-identifier surface a <see cref="CBAdESRefsFamilyMd5DigestAlgorithmViolation"/>
/// names MD5 on.
/// </summary>
public enum CBAdESRefsFamilyDigestSurface
{
    /// <summary>A <c>CertId.x5t</c> digest pair (Annex A.1.1).</summary>
    CertificateReferenceThumbprint,

    /// <summary>A <c>CRLRef.digAlgVal</c> digest pair (Annex A.1.1).</summary>
    CrlReferenceDigest,

    /// <summary>An <c>OCSPRef.digAlgVal</c> digest pair (Annex A.1.1).</summary>
    OcspReferenceDigest
}


/// <summary>
/// A <c>refs</c>-family digest-algorithm-identifier surface names MD5 — refused independent of any algorithm
/// policy (R-5, wavecb-contract.md), mirroring <see cref="CBAdESMd5DigestAlgorithmViolation"/>'s S3
/// mechanism for the Annex A.1.1 surfaces this stage (wavecb S4, <see cref="CBAdESLevelRules"/>) introduces.
/// A distinct sibling record (rather than a new <see cref="CBAdESMd5DigestAlgorithmSurface"/> case) keeps
/// the S3 B-B rule surface's own closed enum untouched, per this stage's edit scope.
/// </summary>
/// <param name="Surface">Which surface named MD5.</param>
public sealed record CBAdESRefsFamilyMd5DigestAlgorithmViolation(CBAdESRefsFamilyDigestSurface Surface) : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-6.2.1-02";

    /// <inheritdoc/>
    public override string Message =>
        $"MD5 shall not be used as a digest algorithm (ETSI TS 119 152-1 V1.1.1, clause 6.2.1); named at {Surface}.";
}


/// <summary>
/// Which kind of referenced material a <see cref="CBAdESReferencesValidationDataConsistencyViolation"/>
/// failed to resolve to <c>valData</c>.
/// </summary>
public enum CBAdESReferenceMaterialKind
{
    /// <summary>A <c>CertId</c> entry (Annex A.1.1, <c>xRefs</c>).</summary>
    Certificate,

    /// <summary>A <c>CRLRef</c> entry (Annex A.1.1, <c>rRefs.crlRefs</c>).</summary>
    Crl,

    /// <summary>An <c>OCSPRef</c> entry (Annex A.1.1, <c>rRefs.ocspRefs</c>).</summary>
    Ocsp
}


/// <summary>
/// A <c>refs</c> entry does not resolve to any material actually present in <c>valData</c> — the
/// cross-component consistency check CB-A.1.1-30 imposes when both <c>refs</c> and <c>valData</c> are
/// present (<see cref="CBAdESLevelRules"/>, wavecb S4). Reported by the ASYNC
/// <see cref="CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/>, never the sync
/// <see cref="CBAdESLevelRules.Check"/>, since resolution requires digesting <c>valData</c> candidates
/// through the registered digest delegate.
/// </summary>
/// <param name="Kind">Which reference kind failed to resolve.</param>
/// <remarks>
/// CB-A.1.1-30: "If at least one of the following: <c>valData</c> or the <c>arcTst</c>, is incorporated into
/// the signature, all the certificates and validation data referenced in <c>refs</c> shall be present
/// elsewhere in the signature." This wave checks <c>valData</c> resolution only — the <c>arcTst</c>-reachable
/// half of the disjunction is an S5 extension point (S5 must additionally resolve against <c>arcTst</c>'s own
/// protected material once that stage's generation lands).
/// </remarks>
public sealed record CBAdESReferencesValidationDataConsistencyViolation(CBAdESReferenceMaterialKind Kind) : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => "CB-A.1.1-30";

    /// <inheritdoc/>
    public override string Message =>
        $"Every reference in refs shall resolve to material present in valData when valData is incorporated " +
        $"(ETSI TS 119 152-1 V1.1.1, Annex A.1.1, CB-A.1.1-30); a {Kind} reference did not resolve.";
}


/// <summary>
/// Which electronic time-stamp token kind a <see cref="CBAdESTimestampTokenBindingViolation"/> concerns
/// (wavecb S4, <see cref="CBAdESSignatureValidation"/>'s async token-imprint verification).
/// </summary>
public enum CBAdESTimestampTokenBindingKind
{
    /// <summary>A <c>sigTst</c> token — time-stamps the COSE signature value (clause 5.3.3, CB-5.3.3-02).</summary>
    SignatureTimestamp,

    /// <summary>An <c>adoTst</c> token — time-stamps the COSE Payload (clause 5.2.6, CB-5.2.6-04).</summary>
    PayloadTimestamp,

    /// <summary>
    /// An <c>arcTst</c> token — this stage only opens/CMS-verifies it (its message-imprint binding is the
    /// clause 5.3.5.3 12-step algorithm, deferred to wavecb S5 once <c>arcTst</c> generation lands; see
    /// <see cref="CBAdESLevelRules"/>'s own remarks for the identical deferral on CB-A.1.1-30's <c>arcTst</c>-
    /// reachable half).
    /// </summary>
    ArchiveTimestamp,

    /// <summary>A <c>sigRTst</c> token — time-stamps the signature value plus <c>sigTst</c>/<c>refs</c> (Annex A.1.2.1, CB-A.1.2.1-02).</summary>
    SignatureAndReferencesTimestamp,

    /// <summary>A <c>rfsTst</c> token — time-stamps <c>sigTst</c>/<c>refs</c> (Annex A.1.2.2, CB-A.1.2.2-02).</summary>
    ReferencesTimestamp
}


/// <summary>
/// Why a <see cref="CBAdESTimestampTokenBindingViolation"/> was reported.
/// </summary>
public enum CBAdESTimestampTokenBindingFailureReason
{
    /// <summary>
    /// <see cref="Verifiable.Cryptography.Pki.TimestampTokenInfo.ReadFromTokenAsync"/> returned a status other
    /// than <see cref="Verifiable.Cryptography.Pki.TimestampTokenInfoStatus.Read"/> — the token's DER is
    /// malformed, its message-imprint algorithm is unresolvable (CB-6.2.1-02's MD5 denylist is satisfied BY
    /// CONSTRUCTION here: <see cref="Verifiable.Cryptography.Pki.PkiDigestAlgorithm.FromOid"/> never resolves
    /// MD5's OID, so an MD5-imprint token reaches this reason as
    /// <see cref="Verifiable.Cryptography.Pki.TimestampTokenInfoStatus.UnsupportedMessageImprintAlgorithm"/>,
    /// mirroring <see cref="CBAdESMd5DigestAlgorithmViolation"/>'s own by-construction reasoning for
    /// <see cref="CBAdESProtectedHeaders.Algorithm"/>), or its own CMS signature did not verify.
    /// </summary>
    TokenNotRead,

    /// <summary>
    /// The token read successfully, but <see cref="Verifiable.Cryptography.Pki.TimestampTokenInfo.VerifyMessageImprintAsync"/>
    /// returned <see langword="false"/> against the expected message-imprint input.
    /// </summary>
    ImprintMismatch,

    /// <summary>
    /// The message-imprint INPUT itself could not be reconstructed from the wire bytes — a <c>sigD</c>
    /// dereference failed while resolving the <c>adoTst</c> payload contribution, no out-of-band detached
    /// payload was supplied, or the raw captured <c>uHeaders</c> bytes a <c>sigRTst</c>/<c>rfsTst</c> builder
    /// needs were absent or rejected as malformed.
    /// </summary>
    ImprintInputUnresolvable
}


/// <summary>
/// An electronic time-stamp token could not be opened/CMS-verified, or its message imprint does not bind the
/// data it is claimed to time-stamp (wavecb S4, <see cref="CBAdESSignatureValidation"/>). Reported by the
/// ASYNC token-imprint verification pass, never <see cref="CBAdESLevelRules.Check"/>, since opening a token
/// requires the registered CMS verification seam and computing/comparing a digest requires the registered
/// digest delegate.
/// </summary>
/// <param name="Kind">Which token kind failed.</param>
/// <param name="Reason">Why it failed.</param>
/// <param name="Detail">A human-readable statement of the specific failure (e.g. the observed <see cref="Verifiable.Cryptography.Pki.TimestampTokenInfoStatus"/>, or the unresolvable dereference's reason).</param>
[DebuggerDisplay("CBAdESTimestampTokenBindingViolation: {Kind}/{Reason}")]
public sealed record CBAdESTimestampTokenBindingViolation(
    CBAdESTimestampTokenBindingKind Kind,
    CBAdESTimestampTokenBindingFailureReason Reason,
    string Detail) : CBAdESRuleViolation
{
    /// <inheritdoc/>
    public override string RequirementId => Kind switch
    {
        CBAdESTimestampTokenBindingKind.SignatureTimestamp => "CB-5.3.3-02",
        CBAdESTimestampTokenBindingKind.PayloadTimestamp => "CB-5.2.6-04",
        CBAdESTimestampTokenBindingKind.ArchiveTimestamp => "CB-5.4.3.3",
        CBAdESTimestampTokenBindingKind.SignatureAndReferencesTimestamp => "CB-A.1.2.1-02",
        CBAdESTimestampTokenBindingKind.ReferencesTimestamp => "CB-A.1.2.2-02",
        _ => throw new NotSupportedException($"Unknown {nameof(CBAdESTimestampTokenBindingKind)} value '{Kind}'.")
    };

    /// <inheritdoc/>
    public override string Message =>
        $"{Kind} token binding failed ({Reason}) (ETSI TS 119 152-1 V1.1.1, {RequirementId}): {Detail}";
}

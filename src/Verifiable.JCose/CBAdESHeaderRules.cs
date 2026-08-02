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

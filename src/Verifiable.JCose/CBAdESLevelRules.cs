using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The shared CB-AdES B-T/B-LT/B-LTA level-scoped rule surface: every level-dependent conformance rule
/// Table 14 (clause 6.3) and Annex A.1.1/A.1.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> impose OVER AND ABOVE the B-B rule surface (<see cref="CBAdESHeaderRules"/>),
/// implemented exactly once and consumed by both postures a caller needs.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Two postures, one implementation, exactly like <see cref="CBAdESHeaderRules"/>.</strong>
/// <see cref="Check"/> and <see cref="CheckReferencesResolveToValidationDataAsync"/> are the COLLECT
/// postures — they never throw on malformed or non-conformant content, returning every violation found.
/// <see cref="EnsureConformant"/> and <see cref="EnsureReferencesResolveToValidationDataAsync"/> are the
/// THROW postures — the augmentation path's trusted-caller-input guard. Every violation this file's rules can
/// report is a <see cref="CBAdESRuleViolation"/> sibling appended to the SAME closed sum
/// <see cref="CBAdESHeaderRules"/> already declares (this file adds no violation type of its own — see that
/// file for the sealed records this class constructs).
/// </para>
/// <para>
/// <strong>Sync/async split, load-bearing.</strong> Eight of the nine level rules
/// this surface adds are pure, synchronous predicates over an already-decoded <see cref="CBAdESUnsignedHeaders"/>
/// snapshot plus a small set of caller-supplied facts (<see cref="Check"/>) — one of the eight, CB-6.3-02's
/// baseline-token-shape narrowing, additionally reaches <see cref="CBAdESLevelRuleContext.PayloadTimestamps"/>,
/// the one caller-supplied fact this surface takes from outside <c>uHeaders</c> entirely (
/// <c>adoTst</c> is a SIGNED header parameter, never a <c>uHeaders</c> element). The ninth — CB-A.1.1-30's
/// cross-component consistency check — must digest candidate <c>valData</c> material through the REGISTERED
/// digest delegate (<see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, System.Threading.CancellationToken)"/>)
/// to compare against each <c>refs</c> entry's stored digest, so it is its own <see cref="ValueTask"/>-returning
/// pair (<see cref="CheckReferencesResolveToValidationDataAsync"/>/<see cref="EnsureReferencesResolveToValidationDataAsync"/>),
/// composed separately by the augmentation/validation orchestrators (matching the "Token-imprint verification
/// is async composition in the validation orchestrator" ruling).
/// </para>
/// <para>
/// <strong>Level model: <see cref="AdESBaselineLevel"/>.</strong>
/// <see cref="CBAdESLevelRuleContext.Level"/> carries the level a caller is either augmenting TO
/// (augmentation) or the level the caller believes a parsed signature CLAIMS to be at (validation — this
/// rule surface does not itself classify a signature's level; level classification is
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> conclusion work, out of this rule surface's scope, which stays
/// certificate-path-neutral. A validator
/// wanting the strictest read evaluates this surface once per candidate level and reports accordingly).
/// </para>
/// <para>
/// <strong>CB-A.1.1-30 triggers on either disjunction arm; resolves against <c>valData</c> only.</strong>
/// <see cref="CheckReferencesResolveToValidationDataAsync"/> now fires whenever
/// <c>refs</c> is present AND at least one of <c>valData</c> OR <c>arcTst</c> is also incorporated ("all the
/// certificates and validation data referenced in <c>refs</c> shall be present elsewhere in the signature"),
/// but the RESOLUTION candidate set stays <c>valData</c>'s own certificate/CRL/OCSP values only — resolving
/// against material embedded inside an <c>arcTst</c> instance's own timestamp tokens is a further extension
/// not yet built, recorded here loudly rather than silently dropped (see that method's own
/// remarks).
/// </para>
/// <para>
/// <strong>Per-token coverage rule.</strong>
/// <see cref="IsTimestampTokenSignerCertificateResolvedAsync"/> is the tenth level rule, composed by the
/// validation orchestrator while a timestamp token is still open (unlike every rule above, it needs
/// <see cref="TimestampTokenInfo"/> facts a decoded <c>uHeaders</c> snapshot alone cannot supply) — see that
/// method's own remarks for the letter-h disjunction it checks.
/// </para>
/// </remarks>
public static class CBAdESLevelRules
{
    /// <summary>
    /// Evaluates every SYNCHRONOUS level rule against <paramref name="context"/> and returns every violation
    /// found. Never throws on non-conformant content — only a missing REQUIRED context field (an
    /// <see langword="ArgumentException"/> on an invalid <paramref name="context"/>) is a caller-contract
    /// violation, not a conformance judgment.
    /// </summary>
    /// <param name="context">The level-rule inputs; see <see cref="CBAdESLevelRuleContext"/>.</param>
    /// <returns>Every violation found, in rule-declaration order; empty when fully conformant.</returns>
    public static IReadOnlyList<CBAdESRuleViolation> Check(CBAdESLevelRuleContext context)
    {
        var violations = new List<CBAdESRuleViolation>();

        int signatureTimestampCount = 0;
        int archiveTimestampCount = 0;
        bool validationDataPresent = false;

        CBAdESUnsignedHeaders? unsignedHeaders = context.UnsignedHeaders;
        if(unsignedHeaders is not null)
        {
            for(int i = 0; i < unsignedHeaders.Count; ++i)
            {
                CBAdESUnsignedHeaderElement element = unsignedHeaders[i];
                switch(element)
                {
                    case CBAdESUnsignedHeaderElementSignatureTimestamp sigTst:
                        ++signatureTimestampCount;
                        CheckTokenCount(sigTst.SignatureTimestamp.TimestampContainer, violations);
                        CheckBaselineTokenShape(sigTst.SignatureTimestamp.TimestampContainer, CBAdESTimestampContainerKind.SignatureTimestamp, violations);
                        break;

                    case CBAdESUnsignedHeaderElementArchiveTimestamp arcTst:
                        //CB-6.3-j: the tstContainer plurality allowance is never narrowed for
                        //arcTst the way CheckTokenCount narrows it for sigTst -- an arcTst instance may
                        //legitimately carry any number of tokens, so only the baseline-shape check runs here.
                        ++archiveTimestampCount;
                        CheckBaselineTokenShape(arcTst.ArchiveTimestamp.TimestampContainer, CBAdESTimestampContainerKind.ArchiveTimestamp, violations);
                        break;

                    case CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp sigRTst:
                        CheckBaselineTokenShape(sigRTst.SignatureAndReferencesTimestamp.TimestampContainer, CBAdESTimestampContainerKind.SignatureAndReferencesTimestamp, violations);
                        if(context.Level >= AdESBaselineLevel.BLT)
                        {
                            violations.Add(new CBAdESRefsFamilyForbiddenViolation(CBAdESRefsFamilyKind.SignatureAndReferencesTimestamp));
                        }
                        else if(!HasReferencesBefore(unsignedHeaders, i))
                        {
                            violations.Add(new CBAdESReferencesTimestampGenerationGateViolation(CBAdESReferencesTimestampGenerationKind.SignatureAndReferences));
                        }
                        break;

                    case CBAdESUnsignedHeaderElementReferencesTimestamp rfsTst:
                        CheckBaselineTokenShape(rfsTst.ReferencesTimestamp.TimestampContainer, CBAdESTimestampContainerKind.ReferencesTimestamp, violations);
                        if(context.Level >= AdESBaselineLevel.BLT)
                        {
                            violations.Add(new CBAdESRefsFamilyForbiddenViolation(CBAdESRefsFamilyKind.ReferencesTimestamp));
                        }
                        else if(!HasReferencesBefore(unsignedHeaders, i))
                        {
                            violations.Add(new CBAdESReferencesTimestampGenerationGateViolation(CBAdESReferencesTimestampGenerationKind.ReferencesOnly));
                        }
                        break;

                    case CBAdESUnsignedHeaderElementReferences refsElement:
                        if(context.Level >= AdESBaselineLevel.BLT)
                        {
                            violations.Add(new CBAdESRefsFamilyForbiddenViolation(CBAdESRefsFamilyKind.References));
                        }

                        CheckSigningCertificateExclusion(refsElement.References, context.SigningCertificateDigests, violations);
                        CheckRefsFamilyMd5(refsElement.References, violations);
                        break;

                    case CBAdESUnsignedHeaderElementValidationData:
                        validationDataPresent = true;
                        break;

                    case CBAdESUnsignedHeaderElementFullCounterSignature:
                    case CBAdESUnsignedHeaderElementAbbreviatedCounterSignature:
                        //CB-6.3-30: the Table 14 "counter signature" row is level-invariant
                        //may-be-present with no lettered additional requirement -- presence is NEVER a violation
                        //at any level; only decode/shape/crypto violations apply, and those are
                        //CBAdESSignatureValidation's concern (cryptographic verification needs the
                        //countersignature substrate's own delegate seams, unavailable to this purely-structural,
                        //synchronous rule surface). An explicit no-op arm, not a silent fall-through.
                        break;

                    case CBAdESUnsignedHeaderElementUnknown unknown:
                        CheckAlternativeMechanismDisclosed(unknown, context.AlternativeMechanismDisclosures, violations);
                        break;
                }
            }
        }

        //CB-6.3-21: cumulative >=1 sigTst instance from B-T onward (the duplicated "B-LT, B-LTA: 0"
        //Table 14 sub-line is read as zero NEW instances required at those levels, not zero total -- see
        //CBAdESSignatureTimestampMissingViolation's own remarks for why that half is documented, not checked,
        //from a single uHeaders snapshot).
        AdESLevelRuleEngine.CheckRow(CBAdESBaselineLevelTable.SigTst, signatureTimestampCount, context.Level, includeCardinality: false, CBAdESRowFinding, violations);

        //CB-6.3-29: arcTst is the soft "*" (should-not) at B-B/B-T/B-LT -- no violation
        //below B-LTA, read-tolerantly -- and becomes hard-mandatory, one-or-more INSTANCES, only at the
        //declared B-LTA. Instance count, never token count (CB-6.2.2-09); see the arcTst switch arm above.
        AdESLevelRuleEngine.CheckRow(CBAdESBaselineLevelTable.ArcTst, archiveTimestampCount, context.Level, includeCardinality: false, CBAdESRowFinding, violations);

        //CB-6.3-26/h: the validation-data-for-time-stamps service, evaluated only from B-LT onward (it is "*"
        //-- should-not-be-provided -- at B-B/B-T). Additional requirement (i)'s SHOULD-level preference for
        //the valData SPO over the embedded-in-token SPO is documented on the violation record, never enforced
        //as a hard rule here.
        if(context.Level >= AdESBaselineLevel.BLT)
        {
            bool serviceSatisfied = validationDataPresent || context.AnyTimestampTokenCarriesEmbeddedValidationMaterial;
            if(!serviceSatisfied)
            {
                violations.Add(new CBAdESTimestampValidationDataServiceViolation());
            }
        }

        //CB-6.3-02: the baseline token-shape narrowing is baseline-wide, not level-gated, and
        //reaches adoTst exactly like the four uHeaders-carried kinds above -- adoTst is a SIGNED header
        //parameter (CBAdESProtectedHeaders.PayloadTimestamps), never a uHeaders element, so it cannot be
        //reached by the loop over UnsignedHeaders and is checked here unconditionally instead.
        if(context.PayloadTimestamps is not null)
        {
            CheckBaselineTokenShape(context.PayloadTimestamps.TimestampContainer, CBAdESTimestampContainerKind.PayloadTimestamp, violations);
        }

        return violations;

        /// <summary>
        /// Determines whether <paramref name="unsignedHeaders"/> carries a <c>refs</c> element at some
        /// position strictly before <paramref name="index"/> (CB-A.1.2.1-03/CB-A.1.2.2-03's generation gate,
        /// read positionally over the append-only array).
        /// </summary>
        /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set.</param>
        /// <param name="index">The exclusive upper bound — the position of the time-stamp element under check.</param>
        /// <returns><see langword="true"/> when a <c>refs</c> element precedes <paramref name="index"/>.</returns>
        static bool HasReferencesBefore(CBAdESUnsignedHeaders unsignedHeaders, int index)
        {
            IReadOnlyList<CBAdESUnsignedHeaderElement> before = unsignedHeaders.ElementsBefore(index);
            for(int i = 0; i < before.Count; ++i)
            {
                if(before[i] is CBAdESUnsignedHeaderElementReferences)
                {
                    return true;
                }
            }

            return false;
        }


        /// <summary>
        /// Appends a <see cref="CBAdESSignatureTimestampTokenCountViolation"/> when <paramref name="container"/>
        /// does not encapsulate exactly one electronic time-stamp (CB-6.3-c).
        /// </summary>
        /// <param name="container">The <c>sigTst</c> instance's encapsulated <c>tstContainer</c>.</param>
        /// <param name="collected">The violation list to append to.</param>
        static void CheckTokenCount(AdESTimestampContainer container, List<CBAdESRuleViolation> collected)
        {
            if(container.TstTokens.Count != 1)
            {
                collected.Add(new CBAdESSignatureTimestampTokenCountViolation(container.TstTokens.Count));
            }
        }


        /// <summary>
        /// Appends one <see cref="CBAdESTimestampTokenNotBaselineViolation"/> per token in
        /// <paramref name="container"/> that is not the RFC 3161(+5816) legacy shape (CB-6.3-02: <c>type</c>/
        /// <c>encoding</c>/<c>specRef</c> all absent).
        /// </summary>
        /// <param name="container">The <c>tstContainer</c> to scan.</param>
        /// <param name="kind">Which <c>uHeaders</c> element kind <paramref name="container"/> belongs to.</param>
        /// <param name="collected">The violation list to append to.</param>
        static void CheckBaselineTokenShape(AdESTimestampContainer container, CBAdESTimestampContainerKind kind, List<CBAdESRuleViolation> collected)
        {
            for(int t = 0; t < container.TstTokens.Count; ++t)
            {
                AdESTimestampToken token = container.TstTokens[t];
                if(token.Type is not null || token.Encoding is not null || token.SpecRef is not null)
                {
                    collected.Add(new CBAdESTimestampTokenNotBaselineViolation(kind));
                }
            }
        }


        /// <summary>
        /// Appends a <see cref="CBAdESReferencesSigningCertificateExclusionViolation"/> when any
        /// <paramref name="refs"/> certificate reference's digest byte-matches any entry of
        /// <paramref name="signingCertificateDigests"/> (CB-A.1.1-02).
        /// </summary>
        /// <param name="refs">The <c>refs</c> element to scan.</param>
        /// <param name="signingCertificateDigests">The caller-supplied signing-certificate digest facts, or <see langword="null"/>.</param>
        /// <param name="collected">The violation list to append to.</param>
        static void CheckSigningCertificateExclusion(
            CBAdESReferences refs,
            IReadOnlyList<DigestValue>? signingCertificateDigests,
            List<CBAdESRuleViolation> collected)
        {
            if(signingCertificateDigests is null || signingCertificateDigests.Count == 0 || refs.CertificateReferences is null)
            {
                return;
            }

            for(int i = 0; i < refs.CertificateReferences.Count; ++i)
            {
                DigestValue candidate = refs.CertificateReferences[i].Thumbprint.Digest;
                for(int j = 0; j < signingCertificateDigests.Count; ++j)
                {
                    if(candidate.AsReadOnlySpan().SequenceEqual(signingCertificateDigests[j].AsReadOnlySpan()))
                    {
                        collected.Add(new CBAdESReferencesSigningCertificateExclusionViolation());
                        return;
                    }
                }
            }
        }


        /// <summary>
        /// Appends one <see cref="CBAdESRefsFamilyMd5DigestAlgorithmViolation"/> per <paramref name="refs"/>
        /// digest-algorithm-identifier surface (<c>x5t</c>/<c>digAlgVal</c> pairs) that names MD5 (CB-6.2.1-02).
        /// </summary>
        /// <param name="refs">The <c>refs</c> element to scan.</param>
        /// <param name="collected">The violation list to append to.</param>
        static void CheckRefsFamilyMd5(CBAdESReferences refs, List<CBAdESRuleViolation> collected)
        {
            if(refs.CertificateReferences is not null)
            {
                for(int i = 0; i < refs.CertificateReferences.Count; ++i)
                {
                    if(IsMd5(refs.CertificateReferences[i].Thumbprint.HashAlgorithm))
                    {
                        collected.Add(new CBAdESRefsFamilyMd5DigestAlgorithmViolation(CBAdESRefsFamilyDigestSurface.CertificateReferenceThumbprint));
                        break;
                    }
                }
            }

            if(refs.RevocationReferences?.CrlReferences is not null)
            {
                for(int i = 0; i < refs.RevocationReferences.CrlReferences.Count; ++i)
                {
                    if(IsMd5(refs.RevocationReferences.CrlReferences[i].HashAlgorithm))
                    {
                        collected.Add(new CBAdESRefsFamilyMd5DigestAlgorithmViolation(CBAdESRefsFamilyDigestSurface.CrlReferenceDigest));
                        break;
                    }
                }
            }

            if(refs.RevocationReferences?.OcspReferences is not null)
            {
                for(int i = 0; i < refs.RevocationReferences.OcspReferences.Count; ++i)
                {
                    if(IsMd5(refs.RevocationReferences.OcspReferences[i].HashAlgorithm))
                    {
                        collected.Add(new CBAdESRefsFamilyMd5DigestAlgorithmViolation(CBAdESRefsFamilyDigestSurface.OcspReferenceDigest));
                        break;
                    }
                }
            }
        }


        /// <summary>
        /// Determines whether <paramref name="identifier"/> names MD5 — the <c>tstr</c> arm compared
        /// case-insensitively against <c>"MD5"</c>; the <c>int</c> arm never matches, mirroring
        /// <c>CBAdESHeaderRules.Check</c>'s own local <c>IsMd5</c> helper (duplicated here rather than shared,
        /// since that one is private to its own method — the S2 imprint-builder classifier precedent).
        /// </summary>
        /// <param name="identifier">The digest-algorithm identifier to test.</param>
        /// <returns><see langword="true"/> when <paramref name="identifier"/> names MD5.</returns>
        static bool IsMd5(AdESDigestAlgorithmIdentifier identifier) => identifier switch
        {
            AdESDigestAlgorithmTextIdentifier text => string.Equals(text.Value, "MD5", StringComparison.OrdinalIgnoreCase),
            _ => false
        };


        /// <summary>
        /// Appends a <see cref="CBAdESUndisclosedAlternativeMechanismViolation"/> when <paramref name="registry"/>
        /// is supplied AND carries no disclosure for <paramref name="unknown"/>'s own label (CB-E-01).
        /// A <see langword="null"/> <paramref name="registry"/> performs no check at
        /// all — the caller never opted in.
        /// </summary>
        /// <param name="unknown">The unknown-label <c>uHeaders</c> catch-all element under check.</param>
        /// <param name="registry">The caller's opt-in Annex E registry, or <see langword="null"/> to skip this check.</param>
        /// <param name="collected">The violation list to append to.</param>
        static void CheckAlternativeMechanismDisclosed(
            CBAdESUnsignedHeaderElementUnknown unknown,
            CBAdESAlternativeMechanismDisclosureRegistry? registry,
            List<CBAdESRuleViolation> collected)
        {
            if(registry is null)
            {
                return;
            }

            if(!registry.TryGetDisclosure(unknown.Label, out _))
            {
                collected.Add(new CBAdESUndisclosedAlternativeMechanismViolation(unknown.Label));
            }
        }
    }


    /// <summary>
    /// Projects a fired <c>sigTst</c>/<c>arcTst</c> row check to its own zero-argument
    /// <see cref="CBAdESRuleViolation"/>, keyed off <paramref name="row"/>'s canonical
    /// <see cref="AdESTableRow.RequirementId"/> — never a violation's own self-reported id.
    /// </summary>
    /// <param name="row">The violated row (always <see cref="CBAdESBaselineLevelTable.SigTst"/> or <see cref="CBAdESBaselineLevelTable.ArcTst"/> here).</param>
    /// <param name="level">The baseline level the finding was evaluated at. Unused: both rows' violations carry no level of their own.</param>
    /// <param name="kind">Which presence/cardinality outcome fired. Unused: neither row's table cell can produce anything but <see cref="AdESRowCheckKind.MissingRequired"/> at the caller's own <c>includeCardinality: false</c> call sites.</param>
    /// <param name="cardinalityExpected">Unused: CBAdES declares no cardinality violation type, doubly forced by the duplicate-cardinality hazard on <see cref="CBAdESBaselineLevelTable.SigTst"/>.</param>
    /// <param name="actualCount">Unused: neither violation carries the observed count.</param>
    /// <returns>The row's own missing-instance violation.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="row"/> is neither <see cref="CBAdESBaselineLevelTable.SigTst"/> nor <see cref="CBAdESBaselineLevelTable.ArcTst"/>.</exception>
    private static CBAdESRuleViolation CBAdESRowFinding(AdESTableRow row, AdESBaselineLevel level, AdESRowCheckKind kind, AdESCardinality? cardinalityExpected, int actualCount) => row.RequirementId switch
    {
        "CB-6.3-21" => new CBAdESSignatureTimestampMissingViolation(),
        "CB-6.3-29" => new CBAdESArchiveTimestampMissingViolation(),
        _ => throw new ArgumentOutOfRangeException(nameof(row), row.RequirementId, "Unknown CB-AdES level-rule row requirement identifier.")
    };


    /// <summary>
    /// The augmentation-path throw posture: calls <see cref="Check"/> and raises <see cref="ArgumentException"/>
    /// naming the first violated clause the moment any level rule fails. Trusted-caller-input semantics —
    /// mirrors <see cref="CBAdESHeaderRules.EnsureConformant"/> exactly.
    /// </summary>
    /// <param name="context">The level-rule inputs.</param>
    /// <exception cref="ArgumentException">At least one level rule is violated; the message names the first violated clause.</exception>
    public static void EnsureConformant(CBAdESLevelRuleContext context)
    {
        IReadOnlyList<CBAdESRuleViolation> violations = Check(context);
        if(violations.Count == 0)
        {
            return;
        }

        CBAdESRuleViolation first = violations[0];
        string suffix = violations.Count > 1
            ? $" ({violations.Count - 1} further level violation(s) also apply.)"
            : string.Empty;

        throw new ArgumentException($"{first.RequirementId}: {first.Message}{suffix}", nameof(context));
    }


    /// <summary>
    /// Evaluates the CB-A.1.1-30 cross-component consistency check: when <paramref name="unsignedHeaders"/>
    /// carries a <c>refs</c> element and EITHER at least one <c>valData</c> element OR at least one
    /// <c>arcTst</c> element is also present, every <c>CertId</c>/<c>CRLRef</c>/<c>OCSPRef</c> entry in
    /// <c>refs</c> must resolve to material actually present in <c>valData</c> — checked by digesting each
    /// candidate <c>valData</c> cert/CRL/OCSP entry under the reference's own algorithm through the registered
    /// digest delegate and comparing <see cref="DigestValue"/> equality. Never throws for a resolution failure;
    /// only a missing REQUIRED parameter is a caller-contract violation.
    /// </summary>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="pool">The memory pool transient digest buffers rent from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// Every unresolved reference, as a <see cref="CBAdESReferencesValidationDataConsistencyViolation"/>;
    /// empty when <paramref name="unsignedHeaders"/> is <see langword="null"/>, carries no <c>refs</c>
    /// element, carries neither a <c>valData</c> nor an <c>arcTst</c> element (this rule applies only when
    /// <c>refs</c> AND at least one of the trigger's two arms are present), or every reference resolves.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// <strong>The trigger fires on EITHER arm.</strong>
    /// CB-A.1.1-30's own disjunction ("if at least one of the following: <c>valData</c> or the <c>arcTst</c>,
    /// is incorporated into the signature..."). The RESOLUTION candidate set widens to match: <c>valData</c>'s
    /// own certificate/CRL values, PLUS every certificate/CRL embedded in the signature's own <c>arcTst</c>
    /// instances' timestamp tokens (via <see cref="TimestampTokenInfo.EmbeddedCertificates"/>/
    /// <see cref="TimestampTokenInfo.EmbeddedCrls"/>, a managed re-parse) — a conformant
    /// <c>refs</c>+<c>arcTst</c> signature whose <c>refs</c> entries resolve only to token-embedded material,
    /// never populating <c>valData</c> at all, therefore validates. Custody: every token opened to harvest this
    /// material is disposed once the resolution loop below is done reading from it (the borrowed-candidate
    /// idiom <see cref="IsTimestampTokenSignerCertificateResolvedAsync"/>'s own callers already follow) — the
    /// <see cref="AdESPkiObject"/> wrappers built over a token's embedded material are borrowed views, never
    /// copies, so they are only valid while the owning <see cref="TimestampTokenInfo"/> stays open.
    /// </remarks>
    public static async ValueTask<IReadOnlyList<CBAdESRuleViolation>> CheckReferencesResolveToValidationDataAsync(
        CBAdESUnsignedHeaders? unsignedHeaders,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var violations = new List<CBAdESRuleViolation>();
        if(unsignedHeaders is null)
        {
            return violations;
        }

        var refsElements = new List<CBAdESReferences>();
        var certificateCandidates = new List<AdESPkiObject>();
        var crlCandidates = new List<AdESPkiObject>();
        var ocspCandidates = new List<AdESPkiObject>();
        var archiveTimestampContainers = new List<AdESTimestampContainer>();

        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            switch(unsignedHeaders[i])
            {
                case CBAdESUnsignedHeaderElementReferences refsElement:
                    refsElements.Add(refsElement.References);
                    break;

                case CBAdESUnsignedHeaderElementValidationData valDataElement:
                    CollectValidationDataCandidates(valDataElement.ValidationData, certificateCandidates, crlCandidates, ocspCandidates);
                    break;

                case CBAdESUnsignedHeaderElementArchiveTimestamp arcTstElement:
                    archiveTimestampContainers.Add(arcTstElement.ArchiveTimestamp.TimestampContainer);
                    break;
            }
        }

        //CB-A.1.1-30 fires when refs is present AND at least one of the disjunction's two arms holds: a
        //valData element carrying candidate material, OR an arcTst element incorporated.
        bool anyValidationDataCandidates = certificateCandidates.Count > 0 || crlCandidates.Count > 0 || ocspCandidates.Count > 0;
        if(refsElements.Count == 0 || !(anyValidationDataCandidates || archiveTimestampContainers.Count > 0))
        {
            return violations;
        }

        var openedArchiveTimestampTokens = new List<TimestampTokenInfo>();
        try
        {
            //Widen the candidate set with every certificate/CRL the signature's own arcTst instances'
            //tokens embed, before resolving a single refs entry below -- the same candidate set the trigger's
            //arcTst arm already promised to check against.
            for(int c = 0; c < archiveTimestampContainers.Count; ++c)
            {
                AdESTimestampContainer container = archiveTimestampContainers[c];
                for(int t = 0; t < container.TstTokens.Count; ++t)
                {
                    using PkiCertificateMemory tokenMemory = CBAdESSignatureValidation.RentTimestampTokenMemory(container.TstTokens[t].Val, pool);
                    TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(tokenMemory, pool, cancellationToken).ConfigureAwait(false);
                    openedArchiveTimestampTokens.Add(tokenInfo);

                    if(!tokenInfo.IsRead)
                    {
                        continue;
                    }

                    for(int e = 0; e < tokenInfo.EmbeddedCertificates.Count; ++e)
                    {
                        certificateCandidates.Add(new AdESPkiObject { Val = tokenInfo.EmbeddedCertificates[e].AsReadOnlyMemory() });
                    }

                    for(int e = 0; e < tokenInfo.EmbeddedCrls.Count; ++e)
                    {
                        crlCandidates.Add(new AdESPkiObject { Val = tokenInfo.EmbeddedCrls[e].AsReadOnlyMemory() });
                    }
                }
            }

            //One digest-keyed index per candidate list, built ONCE and reused across every refs
            //element (O(refs x candidates) -> O(candidates) per distinct algorithm plus one dictionary lookup
            //per reference) -- the CB-AdES twin of XAdESLevelRules' own CandidateDigestIndex fix.
            var certificateIndex = new CandidateDigestIndex(certificateCandidates, pool);
            var crlIndex = new CandidateDigestIndex(crlCandidates, pool);
            var ocspIndex = new CandidateDigestIndex(ocspCandidates, pool);

            for(int r = 0; r < refsElements.Count; ++r)
            {
                CBAdESReferences refs = refsElements[r];

                if(refs.CertificateReferences is not null)
                {
                    for(int i = 0; i < refs.CertificateReferences.Count; ++i)
                    {
                        AdESCertificateThumbprint thumbprint = refs.CertificateReferences[i].Thumbprint;
                        bool resolved = await certificateIndex.ResolveAsync(thumbprint.HashAlgorithm, thumbprint.Digest, cancellationToken).ConfigureAwait(false);
                        if(!resolved)
                        {
                            violations.Add(new CBAdESReferencesValidationDataConsistencyViolation(CBAdESReferenceMaterialKind.Certificate));
                        }
                    }
                }

                if(refs.RevocationReferences?.CrlReferences is not null)
                {
                    for(int i = 0; i < refs.RevocationReferences.CrlReferences.Count; ++i)
                    {
                        CBAdESCrlReference crlRef = refs.RevocationReferences.CrlReferences[i];
                        bool resolved = await crlIndex.ResolveAsync(crlRef.HashAlgorithm, crlRef.Digest, cancellationToken).ConfigureAwait(false);
                        if(!resolved)
                        {
                            violations.Add(new CBAdESReferencesValidationDataConsistencyViolation(CBAdESReferenceMaterialKind.Crl));
                        }
                    }
                }

                if(refs.RevocationReferences?.OcspReferences is not null)
                {
                    for(int i = 0; i < refs.RevocationReferences.OcspReferences.Count; ++i)
                    {
                        CBAdESOcspReference ocspRef = refs.RevocationReferences.OcspReferences[i];
                        bool resolved = await ocspIndex.ResolveAsync(ocspRef.HashAlgorithm, ocspRef.Digest, cancellationToken).ConfigureAwait(false);
                        if(!resolved)
                        {
                            violations.Add(new CBAdESReferencesValidationDataConsistencyViolation(CBAdESReferenceMaterialKind.Ocsp));
                        }
                    }
                }
            }

            return violations;
        }
        finally
        {
            for(int i = 0; i < openedArchiveTimestampTokens.Count; ++i)
            {
                openedArchiveTimestampTokens[i].Dispose();
            }
        }

        /// <summary>
        /// Collects every certificate/CRL/OCSP <see cref="AdESPkiObject"/> reachable through
        /// <paramref name="validationData"/> into the caller's aggregation lists — <c>otherCert</c>/
        /// <c>otherVals</c> entries are opaque-format placeholders (CB-5.3.4's own extensibility notes) and
        /// are not collected, since CB-A.1.1-30 resolution is defined over DER-encoded X.509/CRL/OCSP material.
        /// </summary>
        /// <param name="validationData">The decoded <c>valData</c> element.</param>
        /// <param name="certificates">Receives every <c>x509Cert</c> entry's <see cref="AdESPkiObject"/>.</param>
        /// <param name="crls">Receives every <c>crlVals</c> entry.</param>
        /// <param name="ocsps">Receives every <c>ocspVals</c> entry.</param>
        static void CollectValidationDataCandidates(
            CBAdESValidationData validationData,
            List<AdESPkiObject> certificates,
            List<AdESPkiObject> crls,
            List<AdESPkiObject> ocsps)
        {
            if(validationData.CertificateValues is not null)
            {
                for(int i = 0; i < validationData.CertificateValues.Count; ++i)
                {
                    if(validationData.CertificateValues[i] is CBAdESX509Certificate x509)
                    {
                        certificates.Add(x509.Certificate);
                    }
                }
            }

            if(validationData.RevocationValues?.CrlValues is not null)
            {
                crls.AddRange(validationData.RevocationValues.CrlValues);
            }

            if(validationData.RevocationValues?.OcspValues is not null)
            {
                ocsps.AddRange(validationData.RevocationValues.OcspValues);
            }
        }
    }


    /// <summary>
    /// A digest-value-keyed lookup over one <c>valData</c> candidate list, built lazily and cached per distinct
    /// digest output length (the three resolvable algorithms — SHA-256/384/512 — produce distinct, non-colliding
    /// output lengths, so the length alone is a safe cache key) — the CB-AdES twin of
    /// <c>XAdESLevelRules</c>' own <c>CandidateDigestIndex</c>: turns what was one full candidate-list digest
    /// pass PER reference (O(references x candidates)) into one candidate-list digest pass PER distinct
    /// algorithm plus one dictionary lookup per reference (O(references + candidates)).
    /// </summary>
    private sealed class CandidateDigestIndex(IReadOnlyList<AdESPkiObject> candidates, BaseMemoryPool pool)
    {
        private readonly Dictionary<int, HashSet<string>> digestsByOutputLength = [];

        /// <summary>
        /// Determines whether <paramref name="referenceDigest"/> (declared under <paramref name="algorithm"/>)
        /// resolves to any candidate — building and caching that output length's candidate-digest set on first
        /// use, fails closed (returns <see langword="false"/>, never throws) when <paramref name="algorithm"/>
        /// is not one this method can map to a <see cref="Tag"/> carrying a
        /// <see cref="System.Security.Cryptography.HashAlgorithmName"/> — an unresolvable algorithm means
        /// resolution cannot be confirmed, so it is reported as unresolved.
        /// </summary>
        /// <param name="algorithm">The reference's own digest-algorithm identifier.</param>
        /// <param name="referenceDigest">The reference's stored digest value.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns><see langword="true"/> when at least one candidate's digest matches <paramref name="referenceDigest"/>.</returns>
        public async ValueTask<bool> ResolveAsync(AdESDigestAlgorithmIdentifier algorithm, DigestValue referenceDigest, CancellationToken cancellationToken)
        {
            if(ResolveDigestTag(algorithm) is not Tag tag)
            {
                return false;
            }

            int outputLength = referenceDigest.Length;
            if(!digestsByOutputLength.TryGetValue(outputLength, out HashSet<string>? digests))
            {
                digests = await BuildIndexAsync(tag, outputLength, cancellationToken).ConfigureAwait(false);
                digestsByOutputLength[outputLength] = digests;
            }

            return digests.Contains(Convert.ToHexStringLower(referenceDigest.AsReadOnlySpan()));
        }


        private async ValueTask<HashSet<string>> BuildIndexAsync(Tag tag, int outputLength, CancellationToken cancellationToken)
        {
            var digests = new HashSet<string>(candidates.Count, StringComparer.Ordinal);
            for(int i = 0; i < candidates.Count; ++i)
            {
                using DigestValue candidateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                    candidates[i].Val, outputLength, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                digests.Add(Convert.ToHexStringLower(candidateDigest.AsReadOnlySpan()));
            }

            return digests;
        }


        /// <summary>
        /// Maps <paramref name="identifier"/> to the <see cref="Tag"/> the registered digest delegate needs
        /// to select the same hash function — recognizing only the three IANA COSE Algorithms integer
        /// identifiers this library carries a named <see cref="CryptoTags"/> entry for. Returns
        /// <see langword="null"/> for every other identifier (the CDDL's <c>tstr</c> arm, or an <c>int</c>
        /// identifier this library has no named mapping for) — CB-A.1.1-30 resolution cannot be confirmed
        /// without knowing which hash function to run, so the caller reports the reference as unresolved
        /// rather than guessing.
        /// </summary>
        /// <param name="identifier">The digest-algorithm identifier to resolve.</param>
        /// <returns>The resolved tag, or <see langword="null"/> when unrecognized.</returns>
        private static Tag? ResolveDigestTag(AdESDigestAlgorithmIdentifier identifier) => identifier switch
        {
            AdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha256 } => CryptoTags.Sha256Digest,
            AdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha384 } => CryptoTags.Sha384Digest,
            AdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha512 } => CryptoTags.Sha512Digest,
            _ => null
        };
    }


    /// <summary>
    /// The augmentation/validation throw posture for CB-A.1.1-30: calls
    /// <see cref="CheckReferencesResolveToValidationDataAsync"/> and raises <see cref="ArgumentException"/>
    /// naming the first unresolved reference.
    /// </summary>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="pool">The memory pool transient digest buffers rent from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">At least one <c>refs</c> entry fails to resolve.</exception>
    public static async ValueTask EnsureReferencesResolveToValidationDataAsync(
        CBAdESUnsignedHeaders? unsignedHeaders,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<CBAdESRuleViolation> violations = await CheckReferencesResolveToValidationDataAsync(unsignedHeaders, pool, cancellationToken).ConfigureAwait(false);
        if(violations.Count == 0)
        {
            return;
        }

        CBAdESRuleViolation first = violations[0];
        string suffix = violations.Count > 1
            ? $" ({violations.Count - 1} further unresolved reference(s) also apply.)"
            : string.Empty;

        throw new ArgumentException($"{first.RequirementId}: {first.Message}{suffix}", nameof(unsignedHeaders));
    }


    /// <summary>
    /// Collects every certificate <paramref name="unsignedHeaders"/>'s own <c>valData</c> element(s) carry —
    /// the candidate set <see cref="IsTimestampTokenSignerCertificateResolvedAsync"/>'s per-token coverage
    /// check identity-matches against (issuer-and-serial-number or subject-key-identifier, never a
    /// digest). A minimal, cert-only sibling of <c>CheckReferencesResolveToValidationDataAsync</c>'s own
    /// (CRL/OCSP-inclusive) local collection, since the coverage rule cares only about signer certificates.
    /// </summary>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <returns>Every <c>x509Cert</c> entry found across every <c>valData</c> element; empty when none exist.</returns>
    public static IReadOnlyList<AdESPkiObject> CollectValidationDataCertificateCandidates(CBAdESUnsignedHeaders? unsignedHeaders)
    {
        var certificates = new List<AdESPkiObject>();
        if(unsignedHeaders is null)
        {
            return certificates;
        }

        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            if(unsignedHeaders[i] is CBAdESUnsignedHeaderElementValidationData valDataElement
                && valDataElement.ValidationData.CertificateValues is not null)
            {
                for(int c = 0; c < valDataElement.ValidationData.CertificateValues.Count; ++c)
                {
                    if(valDataElement.ValidationData.CertificateValues[c] is CBAdESX509Certificate x509)
                    {
                        certificates.Add(x509.Certificate);
                    }
                }
            }
        }

        return certificates;
    }


    /// <summary>
    /// Determines whether <paramref name="tokenInfo"/>'s signer certificate is resolvable per additional
    /// requirement (h)'s disjunction: embedded in the token itself, or
    /// present among <paramref name="validationDataCertificates"/> and matched by the token's OWN signer
    /// identity. Never throws for an unresolved token; only a missing REQUIRED parameter is a
    /// caller-contract violation.
    /// </summary>
    /// <param name="tokenInfo">
    /// The already-opened token, read via <see cref="TimestampTokenInfo.ReadFromTokenAsync"/> so
    /// <see cref="TimestampTokenInfo.SignerCertificate"/>/<see cref="TimestampTokenInfo.IsSignerCertificate"/>
    /// reflect a genuine parse of the token's own bytes.
    /// </param>
    /// <param name="validationDataCertificates">
    /// The signature's own <c>valData</c> certificate candidates, from <see cref="CollectValidationDataCertificateCandidates"/>.
    /// </param>
    /// <param name="pool">
    /// The memory pool this method's own callers rent the token and digest buffers from; retained for
    /// parity with that composition even though an identity comparison allocates nothing of its own.
    /// </param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// <see langword="false"/> when <paramref name="tokenInfo"/> was not successfully read, when its embedded
    /// material could not be read (<see cref="TimestampTokenInfoStatus.Read"/> with
    /// <see cref="CmsEmbeddedMaterialStatus.Malformed"/> embedded material — an unresolvable signer identity is
    /// NOT resolved), or when neither disjunct below matches; otherwise <see langword="true"/> when the token's
    /// own <c>SignerInfo</c> already identifies one of its embedded certificates as the signer (letter h's
    /// "embedded in the electronic time-stamp itself" disjunct), or when the token's own signer identity
    /// (issuer-and-serial-number or subject-key-identifier, RFC 5652 §5.3) matches one of
    /// <paramref name="validationDataCertificates"/> (letter h's <c>valData</c> disjunct).
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="tokenInfo"/>, <paramref name="validationDataCertificates"/>, or <paramref name="pool"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// The <c>valData</c> disjunct is an IDENTITY comparison (<see cref="TimestampTokenInfo.IsSignerCertificate"/>),
    /// never a digest match against every certificate the token happens to embed — matching an unrelated
    /// embedded certificate (a decoy, or an intermediate CA certificate the token also carries) against
    /// something present in <paramref name="validationDataCertificates"/> would resolve the check without ever
    /// establishing that the ACTUAL signer's certificate is present anywhere, which is the letter-h fact this
    /// check exists to confirm. Full chain/revocation completeness beyond this bounded, identity-confirmable
    /// check is caller-attested, consistent with the no-chain-building/no-HTTP library doctrine (mirroring
    /// <see cref="CheckReferencesResolveToValidationDataAsync"/>'s own honesty). The <c>valData</c> disjunct is
    /// independently reachable through any correctly-implemented <see cref="VerifyCmsSignedDataDelegate"/> that
    /// resolves a signer's key by a means other than the token's own embedded <c>certificates</c> field (a
    /// registered external-trust backend, for instance) — see the tests covering a token whose own
    /// <c>certificates</c> field is empty resolving purely by identity against <paramref name="validationDataCertificates"/>.
    /// </remarks>
    public static ValueTask<bool> IsTimestampTokenSignerCertificateResolvedAsync(
        TimestampTokenInfo tokenInfo,
        IReadOnlyList<AdESPkiObject> validationDataCertificates,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tokenInfo);
        ArgumentNullException.ThrowIfNull(validationDataCertificates);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        if(!tokenInfo.IsRead)
        {
            return ValueTask.FromResult(false);
        }

        if(tokenInfo.SignerCertificate is not null)
        {
            return ValueTask.FromResult(true);
        }

        for(int i = 0; i < validationDataCertificates.Count; ++i)
        {
            if(tokenInfo.IsSignerCertificate(validationDataCertificates[i].Val))
            {
                return ValueTask.FromResult(true);
            }
        }

        return ValueTask.FromResult(false);
    }
}


/// <summary>
/// The explicit, per-call inputs <see cref="CBAdESLevelRules.Check"/>/<see cref="CBAdESLevelRules.EnsureConformant"/>
/// need — grouped into one context because the rule set spans several unrelated fact sources (the decoded
/// <c>uHeaders</c> snapshot, the target/claimed baseline level, and two caller-computed facts neither this
/// rule surface nor the decoded model can derive on their own). No closure capture: every input travels
/// through this value, never through a captured outer variable.
/// </summary>
[DebuggerDisplay("CBAdESLevelRuleContext(Level={Level})")]
public readonly record struct CBAdESLevelRuleContext
{
    /// <summary>
    /// Gets the <see cref="AdESBaselineLevel"/> this evaluation targets — the level an augmentation call is
    /// producing, or the level a validation caller is checking a parsed signature against.
    /// </summary>
    public required AdESBaselineLevel Level { get; init; }

    /// <summary>
    /// Gets the decoded <c>uHeaders</c> set, or <see langword="null"/> when absent (CB-5.3.1-07: <c>uHeaders</c>
    /// either does not exist at all, or is non-empty).
    /// </summary>
    public CBAdESUnsignedHeaders? UnsignedHeaders { get; init; }

    /// <summary>
    /// Gets the caller-supplied digest(s) of the CB-AdES signature's own signing certificate, used only by
    /// the CB-A.1.1-02 exclusion check (<see cref="CBAdESReferencesSigningCertificateExclusionViolation"/>).
    /// This rule surface cannot itself derive the signing certificate from a <c>uHeaders</c> snapshot alone,
    /// so the caller supplies whichever digest(s) it already holds (e.g. under every algorithm the
    /// signature's own <c>x5t</c>/<c>x5ts</c> headers use) — a byte-comparison match under ANY supplied
    /// digest is reported, regardless of which algorithm produced it. <see langword="null"/> or empty skips
    /// this check entirely (never a false positive from an absent fact).
    /// </summary>
    public IReadOnlyList<DigestValue>? SigningCertificateDigests { get; init; }

    /// <summary>
    /// Gets whether at least one electronic time-stamp token elsewhere in the signature carries its own
    /// embedded certificate/revocation validation material — the CB-6.3-26/h "embedded in the electronic
    /// time-stamp itself" SPO. This rule surface never inspects a token's own encoding (an RFC 3161 token's
    /// embedded CMS <c>SignedData</c>, if any) to derive this fact itself; the caller (the validation
    /// orchestrator, per its own CMS-probe extension point) computes it,
    /// reduced via OR across every token the caller inspected, and supplies the single aggregate here.
    /// Defaults to <see langword="false"/>.
    /// </summary>
    public bool AnyTimestampTokenCarriesEmbeddedValidationMaterial { get; init; }

    /// <summary>
    /// Gets the decoded <c>adoTst</c> SIGNED header parameter (<see cref="CBAdESProtectedHeaders.PayloadTimestamps"/>),
    /// or <see langword="null"/> when absent. Unlike every other member of this context,
    /// <c>adoTst</c> is never reachable through <see cref="UnsignedHeaders"/> — it is carried signed, outside
    /// <c>uHeaders</c> entirely (clause 5.2.6) — so this rule surface cannot derive it from
    /// <see cref="UnsignedHeaders"/> alone; the caller supplies it from the signature's own protected-header
    /// aggregate. Consulted only by the CB-6.3-02 baseline-token-shape narrowing (<see cref="Check"/>), which
    /// applies to it exactly as it does to <c>sigTst</c>/<c>arcTst</c>/<c>sigRTst</c>/<c>rfsTst</c>.
    /// </summary>
    public CBAdESPayloadTimestamp? PayloadTimestamps { get; init; }

    /// <summary>
    /// Gets the caller's opt-in Annex E registry — when non-<see langword="null"/>, every unknown-label
    /// <c>uHeaders</c> catch-all element (CB-5.3.1-11) with no disclosure registered against its own
    /// <see cref="CBAdESUnsignedHeaderElement.Label"/> collects a
    /// <see cref="CBAdESUndisclosedAlternativeMechanismViolation"/> (CB-E-01).
    /// <see langword="null"/> (the default) means the caller never asked, so <see cref="Check"/> performs no
    /// Annex E disclosure check at all — this rule surface never invents a caller-opt-in registry of its own,
    /// mirroring how <see cref="SigningCertificateDigests"/> and <see cref="AnyTimestampTokenCarriesEmbeddedValidationMaterial"/>
    /// already skip their own checks when the caller supplies nothing. Populate-at-composition, read-only
    /// thereafter (<see cref="CBAdESAlternativeMechanismDisclosureRegistry"/>'s own remarks record the full
    /// threading contract); this context never mutates the registry it was handed.
    /// </summary>
    public CBAdESAlternativeMechanismDisclosureRegistry? AlternativeMechanismDisclosures { get; init; }
}

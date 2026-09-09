using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The shared JAdES B-T/B-LT/B-LTA level-scoped rule surface: every level-dependent conformance rule Table 1
/// (clause 6.3) and Annex A of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see> impose OVER AND ABOVE the B-B rule surface (<see cref="JAdESHeaderRules"/>),
/// implemented exactly once and consumed by both postures a caller needs, mirroring
/// <see cref="CBAdESLevelRules"/>'s identical discipline.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Two postures, one implementation, exactly like <see cref="JAdESHeaderRules"/>.</strong>
/// <see cref="Check"/> is the COLLECT posture — it never throws on malformed or non-conformant content,
/// returning every violation found. <see cref="EnsureConformant"/> is the THROW posture — the augmentation
/// path's trusted-caller-input guard. Every violation this file's rules can report is a
/// <see cref="JAdESRuleViolation"/> sibling appended to the SAME closed sum <see cref="JAdESHeaderRules"/>
/// already declares (this file adds no violation type of its own — see that file for the sealed records this
/// class constructs), mirroring <see cref="CBAdESLevelRules"/>'s own reuse of <see cref="CBAdESHeaderRules"/>'s
/// closed sum.
/// </para>
/// <para>
/// <strong>Write-strict/read-tolerant.</strong> A soft-negative ("*"/<see cref="AdESPresence.ShouldNotBePresent"/>)
/// presence is never reported as a violation on read — it only records that upper levels may specify other
/// requirements. Only <see cref="AdESPresence.ShallBePresent"/> (absent) and
/// <see cref="AdESPresence.ShallNotBePresent"/> (present) failures, plus the structurally-checkable lettered
/// obligations below, are ever reported.
/// </para>
/// <para>
/// <strong>Dual-mode carriage narrows what is structurally checkable.</strong> Every <c>etsiU</c> element
/// modeled here is dual-mode (<see cref="JAdESUnsignedValue{TValue}"/>): a base64url-opaque carriage
/// carries no decoded value to inspect. Every rule below that needs a decoded shape (token count, token-format
/// narrowing, MD5 naming, signing-certificate exclusion) checks only clear-mode carriages
/// (<see cref="JAdESClearUnsignedValue{TValue}"/>) and is silently skipped — never reported as a violation — for
/// an opaque one, the same "cannot check, so no violation" posture <see cref="JAdESLevelRuleContext"/>'s own
/// caller-attested facts already use for what this surface cannot derive on its own.
/// </para>
/// <para>
/// <strong>Letter a) (<c>iat</c>/<c>sigT</c>) already enforced elsewhere; not re-implemented here.</strong> See
/// <see cref="JAdESBaselineLevelTable"/>'s own remarks: the SHALL-from-2025-07-15 half is live at
/// <see cref="JAdESHeaderRules.Check"/> (<see cref="JAdESIssuedAtMissingViolation"/>); this library's ruled reading
/// of the SHOULD-NOT half (read as <c>sigT</c>) is moot for any current-time evaluation now that the cutover has
/// passed, so no live check exists for it on either side.
/// </para>
/// <para>
/// <strong>Letters d), e), i), k), l), m) are disclosed, not enforced.</strong> Letter d) (a time-stamp created
/// before the signing certificate is revoked/expired) needs a validation-time chain/revocation check this
/// structural surface does not perform. Letters e)/i) (duplicate-avoidance for certificate/revocation values)
/// and k) (prefer <c>tstVD</c>/<c>anyValData</c> over the embedded-in-token option) are SHOULD/SHOULD-NOT, never
/// enforced as violations, mirroring <see cref="CBAdESLevelRules"/>'s identical soft-rule posture. Letter l) is
/// purely permissive (<c>arcTst</c> MAY hold more than one token) — nothing to check. Letter m)'s
/// full-validation-material-refresh obligation is owned by the augmentation orchestrator, not this data-facing
/// surface (mirroring <see cref="JAdESBaselineLevelTable.ArcTst"/>'s own remarks).
/// </para>
/// <para>
/// <strong>Annex D disclosure, opt-in.</strong> Mirroring <see cref="CBAdESLevelRules"/>'s
/// Annex-E <see cref="CBAdESUndisclosedAlternativeMechanismViolation"/> check: when a caller supplies a
/// non-<see langword="null"/> <see cref="JAdESLevelRuleContext.AlternativeMechanismDisclosures"/> registry,
/// <see cref="Check"/> reports a <see cref="JAdESUndisclosedAlternativeMechanismViolation"/> for every
/// <see cref="JAdESUnsignedHeaderElementUnknown"/> whose own kind carries no registered disclosure. A
/// <see langword="null"/> registry (the default) performs no check at all — the caller never opted in.
/// </para>
/// <para>
/// <strong>Level model: <see cref="AdESBaselineLevel"/>.</strong> <see cref="JAdESLevelRuleContext.Level"/>
/// carries the level a caller is either augmenting TO or the level a caller believes a parsed signature CLAIMS
/// to be at — this rule surface does not itself classify a signature's level.
/// </para>
/// <para>
/// <strong>Two async resolution classes, mirroring <see cref="CBAdESLevelRules"/>'s own sync/async
/// split rationale.</strong> <see cref="CheckReferencesResolveToValidationDataAsync"/> (the JA-A.1.1-12/
/// JA-A.1.2-35/JA-A.1.3-08/JA-A.1.4-10 cross-component "all referenced material is present elsewhere" family,
/// the CB-A.1.1-30 analog) and <see cref="CheckCounterSignaturesAsync"/> (a failing <c>cSig</c> countersignature)
/// each need the registered digest/verification seams a decoded <c>etsiU</c> snapshot alone cannot supply, so
/// both are their own <see cref="ValueTask"/>-returning Check/Ensure pairs, composed separately by the
/// augmentation/validation orchestrators — never folded into the synchronous <see cref="Check"/>.
/// </para>
/// </remarks>
/// <summary>
/// Resolves the countersigner's public key for verifying one decoded <c>cSig</c> element's nested
/// message, discovered by <see cref="JAdESLevelRules.CheckCounterSignaturesAsync"/> during a level-aware
/// validation pass, or <see langword="null"/> when the caller does not trust or cannot resolve a key
/// for it — mirroring <c>CBAdESResolveCounterSignaturePublicKeyDelegate</c>'s identical certificate-path-neutral
/// posture one document removed.
/// </summary>
/// <remarks>
/// Synchronous, matching the CB-AdES precedent: resolving WHICH key to trust (certificate-chain material
/// completeness) is out of this delegate's contract; it only asks the caller for a key once it already has a
/// decoded countersignature to try one against. Returning <see langword="null"/> is reported as
/// <see cref="JAdESCounterSignatureVerificationFailureReason.KeyUnresolved"/> rather than silently skipped:
/// JA-5.3.2-01 obligates a PRESENT <c>cSig</c> element to "contain one counter signature of the JAdES signature
/// where <c>cSig</c> is incorporated" — once present, its content is asserted, so a caller that cannot resolve
/// a key for it cannot confirm that assertion, and this surface reports the gap rather than treating an
/// unresolvable key the same as a conformant, unverifiable-by-policy absence.
/// </remarks>
/// <param name="counterSignature">
/// The decoded nested message to resolve a key for. BORROWED for the duration of this call only — the caller
/// retains ownership; an implementation must not dispose it or retain a reference past the call returning.
/// </param>
/// <returns>The verification key, or <see langword="null"/> when none can be resolved.</returns>
public delegate PublicKeyMemory? ResolveJAdESCounterSignaturePublicKeyDelegate(UnverifiedJAdESMessage counterSignature);


public static class JAdESLevelRules
{
    /// <summary>
    /// Evaluates every level rule against <paramref name="context"/> and returns every violation found. Never
    /// throws on non-conformant content — only a missing REQUIRED context field (an
    /// <see langword="ArgumentException"/> on an invalid <paramref name="context"/>) is a caller-contract
    /// violation, not a conformance judgment.
    /// </summary>
    /// <param name="context">The level-rule inputs; see <see cref="JAdESLevelRuleContext"/>.</param>
    /// <returns>Every violation found, in rule-declaration order; empty when fully conformant.</returns>
    public static IReadOnlyList<JAdESRuleViolation> Check(JAdESLevelRuleContext context)
    {
        var violations = new List<JAdESRuleViolation>();

        int signatureTimestampCount = 0;
        int archiveTimestampCount = 0;
        bool timestampValidationDataPresent = false;

        JAdESUnsignedHeaders? unsignedHeaders = context.UnsignedHeaders;
        bool referencesFamilyPresentAnywhere = AnyReferencesFamilyElementPresent(unsignedHeaders);
        bool hasAttributeCertificateOrSignedAssertion = HasAttributeCertificateOrSignedAssertion(context.ProtectedHeaders);

        if(unsignedHeaders is not null)
        {
            for(int i = 0; i < unsignedHeaders.Count; ++i)
            {
                JAdESUnsignedHeaderElement element = unsignedHeaders[i];
                switch(element)
                {
                    case JAdESUnsignedHeaderElementSignatureTimestamp sigTst:
                        ++signatureTimestampCount;
                        CheckTokenCount(sigTst.Carriage, violations);
                        CheckBaselineTokenShape(sigTst.Carriage, JAdESTimestampContainerKind.SignatureTimestamp, violations);
                        break;

                    case JAdESUnsignedHeaderElementArchiveTimestamp arcTst:
                        ++archiveTimestampCount;
                        CheckBaselineTokenShape(arcTst.Carriage, JAdESTimestampContainerKind.ArchiveTimestamp, violations);
                        break;

                    case JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp sigRTst:
                        CheckBaselineTokenShape(sigRTst.Carriage, JAdESTimestampContainerKind.SignatureAndReferencesTimestamp, violations);
                        if(context.Level >= AdESBaselineLevel.BLT)
                        {
                            violations.Add(new JAdESRefsFamilyForbiddenViolation(JAdESRefsFamilyKind.SignatureAndReferencesTimestamp));
                        }
                        else if(!referencesFamilyPresentAnywhere)
                        {
                            violations.Add(new JAdESReferencesTimestampGenerationGateViolation(JAdESReferencesTimestampGenerationKind.SignatureAndReferences));
                        }
                        break;

                    case JAdESUnsignedHeaderElementReferencesTimestamp rfsTst:
                        CheckBaselineTokenShape(rfsTst.Carriage, JAdESTimestampContainerKind.ReferencesTimestamp, violations);
                        if(context.Level >= AdESBaselineLevel.BLT)
                        {
                            violations.Add(new JAdESRefsFamilyForbiddenViolation(JAdESRefsFamilyKind.ReferencesTimestamp));
                        }
                        else if(!referencesFamilyPresentAnywhere)
                        {
                            violations.Add(new JAdESReferencesTimestampGenerationGateViolation(JAdESReferencesTimestampGenerationKind.ReferencesOnly));
                        }
                        break;

                    case JAdESUnsignedHeaderElementCertificateReferences xRefs:
                        if(context.Level >= AdESBaselineLevel.BLT)
                        {
                            violations.Add(new JAdESRefsFamilyForbiddenViolation(JAdESRefsFamilyKind.CertificateReferences));
                        }

                        CheckSigningCertificateExclusion(xRefs.Carriage, context.SigningCertificateDigests, violations);
                        CheckCertificateReferencesMd5(xRefs.Carriage, JAdESRefsFamilyDigestSurface.CertificateReferences, violations);
                        break;

                    case JAdESUnsignedHeaderElementRevocationReferences rRefs:
                        if(context.Level >= AdESBaselineLevel.BLT)
                        {
                            violations.Add(new JAdESRefsFamilyForbiddenViolation(JAdESRefsFamilyKind.RevocationReferences));
                        }

                        CheckRevocationReferencesMd5(rRefs.Carriage, JAdESRefsFamilyDigestSurface.RevocationReferences, violations);
                        break;

                    case JAdESUnsignedHeaderElementAttributeCertificateReferences axRefs:
                        if(context.Level >= AdESBaselineLevel.BLT)
                        {
                            violations.Add(new JAdESRefsFamilyForbiddenViolation(JAdESRefsFamilyKind.AttributeCertificateReferences));
                        }

                        if(!hasAttributeCertificateOrSignedAssertion)
                        {
                            violations.Add(new JAdESAttributeReferencesGateViolation(JAdESAttributeReferencesKind.AttributeCertificateReferences));
                        }

                        CheckCertificateReferencesMd5(axRefs.Carriage, JAdESRefsFamilyDigestSurface.AttributeCertificateReferences, violations);
                        break;

                    case JAdESUnsignedHeaderElementAttributeRevocationReferences arRefs:
                        if(context.Level >= AdESBaselineLevel.BLT)
                        {
                            violations.Add(new JAdESRefsFamilyForbiddenViolation(JAdESRefsFamilyKind.AttributeRevocationReferences));
                        }

                        if(!hasAttributeCertificateOrSignedAssertion)
                        {
                            violations.Add(new JAdESAttributeReferencesGateViolation(JAdESAttributeReferencesKind.AttributeRevocationReferences));
                        }

                        CheckRevocationReferencesMd5(arRefs.Carriage, JAdESRefsFamilyDigestSurface.AttributeRevocationReferences, violations);
                        break;

                    case JAdESUnsignedHeaderElementSignaturePolicyStore:
                        if(!SignaturePolicyIdentifierCarriesDigest(context.ProtectedHeaders))
                        {
                            violations.Add(new JAdESSignaturePolicyStoreGateViolation());
                        }
                        break;

                    case JAdESUnsignedHeaderElementTimestampValidationData:
                    case JAdESUnsignedHeaderElementAnyValidationData:
                        timestampValidationDataPresent = true;
                        break;

                    case JAdESUnsignedHeaderElementCounterSignature:
                        //JA-6.3-23 (cSig): level-invariant may-be-present with no lettered additional
                        //requirement -- presence is NEVER a violation at any level; only decode/shape/crypto
                        //violations apply, and those need the countersignature substrate's own delegate seams,
                        //unavailable to this purely-structural, synchronous rule surface. An explicit no-op
                        //arm, not a silent fall-through.
                        break;

                    case JAdESUnsignedHeaderElementUnknown unknown:
                        CheckAlternativeMechanismDisclosed(unknown, context.AlternativeMechanismDisclosures, violations);
                        break;
                }
            }
        }

        //JA-6.3-26: cumulative >=1 sigTst instance from B-T onward.
        AdESLevelRuleEngine.CheckRow(JAdESBaselineLevelTable.SigTst, signatureTimestampCount, context.Level, includeCardinality: false, JAdESRowFinding, violations);

        //JA-6.3-42: arcTst is the soft "*" (should-not) at B-B/B-T/B-LT -- no violation below B-LTA, and
        //becomes hard-mandatory, one-or-more instances, only at the declared B-LTA.
        AdESLevelRuleEngine.CheckRow(JAdESBaselineLevelTable.ArcTst, archiveTimestampCount, context.Level, includeCardinality: false, JAdESRowFinding, violations);

        //JA-6.3-38/j: the validation-data-for-time-stamps service, evaluated only from B-LT onward.
        if(context.Level >= AdESBaselineLevel.BLT)
        {
            bool serviceSatisfied = timestampValidationDataPresent || context.AnyTimestampTokenCarriesEmbeddedValidationMaterial;
            if(!serviceSatisfied)
            {
                violations.Add(new JAdESTimestampValidationDataServiceViolation());
            }
        }

        //JA-6.3-03: the baseline token-shape narrowing is baseline-wide, not level-gated, and reaches adoTst
        //too -- adoTst is a SIGNED header parameter (JAdESProtectedHeaders.PayloadTimestamps), never an etsiU
        //element, so it cannot be reached by the loop above and is checked here unconditionally instead.
        if(context.ProtectedHeaders?.PayloadTimestamps is not null)
        {
            CheckBaselineTokenShape(context.ProtectedHeaders.PayloadTimestamps, JAdESTimestampContainerKind.PayloadTimestamp, violations);
        }

        return violations;
    }


    /// <summary>
    /// Projects a fired <c>sigTst</c>/<c>arcTst</c> row check to its own zero-argument
    /// <see cref="JAdESRuleViolation"/>, keyed off <paramref name="row"/>'s canonical
    /// <see cref="AdESTableRow.RequirementId"/> — never the violation's own self-reported id (JA-6.3-38's
    /// <see cref="JAdESTimestampValidationDataServiceViolation"/> reports itself under "JA-6.3-j", a pre-existing
    /// drift the Service check does not route through the engine, so it never reaches this delegate).
    /// </summary>
    /// <param name="row">The violated row (always <see cref="JAdESBaselineLevelTable.SigTst"/> or <see cref="JAdESBaselineLevelTable.ArcTst"/> here).</param>
    /// <param name="level">The baseline level the finding was evaluated at. Unused: both rows' violations carry no level of their own.</param>
    /// <param name="kind">Which presence/cardinality outcome fired. Unused: neither row's table cell can produce anything but <see cref="AdESRowCheckKind.MissingRequired"/> at the caller's own <c>includeCardinality: false</c> call sites.</param>
    /// <param name="cardinalityExpected">Unused: JAdES declares no cardinality violation type.</param>
    /// <param name="actualCount">Unused: neither violation carries the observed count.</param>
    /// <returns>The row's own missing-instance violation.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="row"/> is neither <see cref="JAdESBaselineLevelTable.SigTst"/> nor <see cref="JAdESBaselineLevelTable.ArcTst"/>.</exception>
    private static JAdESRuleViolation JAdESRowFinding(AdESTableRow row, AdESBaselineLevel level, AdESRowCheckKind kind, AdESCardinality? cardinalityExpected, int actualCount) => row.RequirementId switch
    {
        "JA-6.3-26" => new JAdESSignatureTimestampMissingViolation(),
        "JA-6.3-42" => new JAdESArchiveTimestampMissingViolation(),
        _ => throw new ArgumentOutOfRangeException(nameof(row), row.RequirementId, "Unknown JAdES level-rule row requirement identifier.")
    };


    /// <summary>
    /// The augmentation-path throw posture: calls <see cref="Check"/> and raises <see cref="ArgumentException"/>
    /// naming the first violated clause the moment any level rule fails. Trusted-caller-input semantics —
    /// mirrors <see cref="JAdESHeaderRules.EnsureConformant"/> exactly.
    /// </summary>
    /// <param name="context">The level-rule inputs.</param>
    /// <exception cref="ArgumentException">At least one level rule is violated; the message names the first violated clause.</exception>
    public static void EnsureConformant(JAdESLevelRuleContext context)
    {
        IReadOnlyList<JAdESRuleViolation> violations = Check(context);
        if(violations.Count == 0)
        {
            return;
        }

        JAdESRuleViolation first = violations[0];
        string suffix = violations.Count > 1
            ? $" ({violations.Count - 1} further level violation(s) also apply.)"
            : string.Empty;

        throw new ArgumentException($"{first.RequirementId}: {first.Message}{suffix}", nameof(context));
    }


    /// <summary>
    /// Determines whether <paramref name="unsignedHeaders"/> carries at least one of the four <c>refs</c>-family
    /// value elements (<c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/<c>arRefs</c>) anywhere in the container
    /// (JA-A.1.5.1.1-04/JA-A.1.5.2.1-04's own text: "is present", with no positional qualifier — unlike the
    /// message-imprint INPUT selection, the generation gate itself is not stated as position-scoped).
    /// </summary>
    /// <param name="unsignedHeaders">The decoded <c>etsiU</c> set, or <see langword="null"/> when absent.</param>
    /// <returns><see langword="true"/> when at least one of the four kinds is present.</returns>
    private static bool AnyReferencesFamilyElementPresent(JAdESUnsignedHeaders? unsignedHeaders)
    {
        if(unsignedHeaders is null)
        {
            return false;
        }

        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            switch(unsignedHeaders[i])
            {
                case JAdESUnsignedHeaderElementCertificateReferences:
                case JAdESUnsignedHeaderElementRevocationReferences:
                case JAdESUnsignedHeaderElementAttributeCertificateReferences:
                case JAdESUnsignedHeaderElementAttributeRevocationReferences:
                    return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Determines whether <paramref name="headers"/> carries at least one certified attribute certificate or
    /// signed assertion (letter h's own trigger: "at least an attribute certificate or a signed assertion is
    /// incorporated into the JAdES signature"). Signer-CLAIMED attributes alone (<see cref="AdESSignerAttributes.Claimed"/>)
    /// do not satisfy this — letter h names only certificates and signed assertions.
    /// </summary>
    /// <param name="headers">The signed-header-set aggregate, or <see langword="null"/> when unavailable.</param>
    /// <returns><see langword="true"/> when at least one certified attribute or signed assertion is present.</returns>
    private static bool HasAttributeCertificateOrSignedAssertion(JAdESProtectedHeaders? headers) =>
        headers?.SignerAttributes is { } attributes && (attributes.Certified is not null || attributes.SignedAssertions is not null);


    /// <summary>
    /// Determines whether <paramref name="headers"/> carries a <see cref="JAdESProtectedHeaders.SignaturePolicyIdentifier"/>
    /// whose <see cref="AdESSignaturePolicyIdentifier.Digest"/> is present (letter b's gate).
    /// </summary>
    /// <param name="headers">The signed-header-set aggregate, or <see langword="null"/> when unavailable.</param>
    /// <returns><see langword="true"/> when <c>sigPId</c> is present and carries a <c>digVal</c> digest.</returns>
    private static bool SignaturePolicyIdentifierCarriesDigest(JAdESProtectedHeaders? headers) =>
        headers?.SignaturePolicyIdentifier?.Digest is not null;


    /// <summary>
    /// Appends a <see cref="JAdESSignatureTimestampTokenCountViolation"/> when <paramref name="carriage"/> is a
    /// clear-mode carriage whose decoded container does not encapsulate exactly one electronic time-stamp
    /// (letter c). Skipped for an opaque-mode carriage — nothing decoded, nothing to check.
    /// </summary>
    /// <param name="carriage">The <c>sigTst</c> instance's dual-mode carriage.</param>
    /// <param name="collected">The violation list to append to.</param>
    private static void CheckTokenCount(JAdESUnsignedValue<AdESTimestampContainer> carriage, List<JAdESRuleViolation> collected)
    {
        if(carriage is JAdESClearUnsignedValue<AdESTimestampContainer> clear && clear.Value.TstTokens.Count != 1)
        {
            collected.Add(new JAdESSignatureTimestampTokenCountViolation(clear.Value.TstTokens.Count));
        }
    }


    /// <summary>
    /// Appends one <see cref="JAdESTimestampTokenNotBaselineViolation"/> per token in <paramref name="carriage"/>'s
    /// decoded container that is not the RFC 3161(+5816) legacy shape (JA-6.3-03: <c>type</c>/<c>encoding</c>/
    /// <c>specRef</c> all absent). Skipped for an opaque-mode carriage.
    /// </summary>
    /// <param name="carriage">The dual-mode carriage to inspect.</param>
    /// <param name="kind">Which <c>etsiU</c> element kind <paramref name="carriage"/> belongs to.</param>
    /// <param name="collected">The violation list to append to.</param>
    private static void CheckBaselineTokenShape(JAdESUnsignedValue<AdESTimestampContainer> carriage, JAdESTimestampContainerKind kind, List<JAdESRuleViolation> collected)
    {
        if(carriage is not JAdESClearUnsignedValue<AdESTimestampContainer> clear)
        {
            return;
        }

        CheckBaselineTokenShape(clear.Value, kind, collected);
    }


    /// <summary>
    /// Appends one <see cref="JAdESTimestampTokenNotBaselineViolation"/> per token in <paramref name="container"/>
    /// that is not the RFC 3161(+5816) legacy shape (JA-6.3-03). Used directly for <c>adoTst</c>
    /// (<see cref="JAdESProtectedHeaders.PayloadTimestamps"/>), which carries an already-decoded
    /// <see cref="AdESTimestampContainer"/> with no dual-mode wrapper (it is a SIGNED header parameter).
    /// </summary>
    /// <param name="container">The decoded <c>tstContainer</c> to scan.</param>
    /// <param name="kind">Which kind <paramref name="container"/> belongs to.</param>
    /// <param name="collected">The violation list to append to.</param>
    private static void CheckBaselineTokenShape(AdESTimestampContainer container, JAdESTimestampContainerKind kind, List<JAdESRuleViolation> collected)
    {
        for(int t = 0; t < container.TstTokens.Count; ++t)
        {
            AdESTimestampToken token = container.TstTokens[t];
            if(token.Type is not null || token.Encoding is not null || token.SpecRef is not null)
            {
                collected.Add(new JAdESTimestampTokenNotBaselineViolation(kind));
            }
        }
    }


    /// <summary>
    /// Appends a <see cref="JAdESReferencesSigningCertificateExclusionViolation"/> when <paramref name="carriage"/>
    /// is a clear-mode carriage whose decoded <c>xRefs</c> certificate references include a digest byte-matching
    /// any of <paramref name="signingCertificateDigests"/> (JA-A.1.1-02). Skipped for an opaque-mode carriage.
    /// </summary>
    /// <param name="carriage">The <c>xRefs</c> element's dual-mode carriage.</param>
    /// <param name="signingCertificateDigests">The caller-supplied signing-certificate digest facts, or <see langword="null"/>.</param>
    /// <param name="collected">The violation list to append to.</param>
    private static void CheckSigningCertificateExclusion(
        JAdESUnsignedValue<JAdESCertificateReferenceCollection> carriage,
        IReadOnlyList<DigestValue>? signingCertificateDigests,
        List<JAdESRuleViolation> collected)
    {
        if(signingCertificateDigests is null || signingCertificateDigests.Count == 0)
        {
            return;
        }

        if(carriage is not JAdESClearUnsignedValue<JAdESCertificateReferenceCollection> clear)
        {
            return;
        }

        IReadOnlyList<AdESCertificateThumbprint> items = clear.Value.Items;
        for(int i = 0; i < items.Count; ++i)
        {
            DigestValue candidate = items[i].Digest;
            for(int j = 0; j < signingCertificateDigests.Count; ++j)
            {
                if(candidate.AsReadOnlySpan().SequenceEqual(signingCertificateDigests[j].AsReadOnlySpan()))
                {
                    collected.Add(new JAdESReferencesSigningCertificateExclusionViolation());
                    return;
                }
            }
        }
    }


    /// <summary>
    /// Appends a <see cref="JAdESRefsFamilyMd5DigestAlgorithmViolation"/> when <paramref name="carriage"/> is a
    /// clear-mode carriage whose decoded certificate references name MD5 as their digest algorithm
    /// (JA-6.2.1-02). Skipped for an opaque-mode carriage.
    /// </summary>
    /// <param name="carriage">The <c>xRefs</c>/<c>axRefs</c> element's dual-mode carriage.</param>
    /// <param name="surface">Which surface to cite if a violation is found.</param>
    /// <param name="collected">The violation list to append to.</param>
    private static void CheckCertificateReferencesMd5(
        JAdESUnsignedValue<JAdESCertificateReferenceCollection> carriage,
        JAdESRefsFamilyDigestSurface surface,
        List<JAdESRuleViolation> collected)
    {
        if(carriage is not JAdESClearUnsignedValue<JAdESCertificateReferenceCollection> clear)
        {
            return;
        }

        IReadOnlyList<AdESCertificateThumbprint> items = clear.Value.Items;
        for(int i = 0; i < items.Count; ++i)
        {
            if(IsMd5(items[i].HashAlgorithm))
            {
                collected.Add(new JAdESRefsFamilyMd5DigestAlgorithmViolation(surface));
                return;
            }
        }
    }


    /// <summary>
    /// Appends a <see cref="JAdESRefsFamilyMd5DigestAlgorithmViolation"/> when <paramref name="carriage"/> is a
    /// clear-mode carriage whose decoded CRL/OCSP references name MD5 as their digest algorithm (JA-6.2.1-02).
    /// Skipped for an opaque-mode carriage.
    /// </summary>
    /// <param name="carriage">The <c>rRefs</c>/<c>arRefs</c> element's dual-mode carriage.</param>
    /// <param name="surface">Which surface to cite if a violation is found.</param>
    /// <param name="collected">The violation list to append to.</param>
    private static void CheckRevocationReferencesMd5(
        JAdESUnsignedValue<JAdESRevocationReferenceCollection> carriage,
        JAdESRefsFamilyDigestSurface surface,
        List<JAdESRuleViolation> collected)
    {
        if(carriage is not JAdESClearUnsignedValue<JAdESRevocationReferenceCollection> clear)
        {
            return;
        }

        IReadOnlyList<AdESCertificateThumbprint> crlReferences = clear.Value.CrlReferences;
        for(int i = 0; i < crlReferences.Count; ++i)
        {
            if(IsMd5(crlReferences[i].HashAlgorithm))
            {
                collected.Add(new JAdESRefsFamilyMd5DigestAlgorithmViolation(surface));
                return;
            }
        }

        IReadOnlyList<AdESCertificateThumbprint> ocspReferences = clear.Value.OcspReferences;
        for(int i = 0; i < ocspReferences.Count; ++i)
        {
            if(IsMd5(ocspReferences[i].HashAlgorithm))
            {
                collected.Add(new JAdESRefsFamilyMd5DigestAlgorithmViolation(surface));
                return;
            }
        }
    }


    /// <summary>
    /// Determines whether <paramref name="hashAlgorithm"/> names MD5 — compared case-insensitively against
    /// <c>"MD5"</c>, mirroring <c>CBAdESLevelRules</c>'s own local <c>IsMd5</c> helper. JAdES's digest-algorithm
    /// identifiers are always <see langword="string"/> (the IANA "Named Information Hash Algorithm Registry",
    /// JA-A.1.1-08), unlike CB-AdES's own <c>int</c>-or-<c>tstr</c> CBOR union.
    /// </summary>
    /// <param name="hashAlgorithm">The digest-algorithm identifier to test.</param>
    /// <returns><see langword="true"/> when <paramref name="hashAlgorithm"/> names MD5.</returns>
    private static bool IsMd5(string hashAlgorithm) => string.Equals(hashAlgorithm, "MD5", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Tells whether a reference's digest algorithm names MD5 (JA-6.2.1-02). A JAdES <c>digAlg</c> is a textual
    /// IANA Named Information Hash Algorithm Registry identifier riding
    /// <see cref="AdESDigestAlgorithmTextIdentifier"/>; an integer-arm identifier is never a JAdES
    /// <c>digAlg</c> and so never matches.
    /// </summary>
    /// <param name="hashAlgorithm">The digest-algorithm identifier the reference states.</param>
    /// <returns><see langword="true"/> when the identifier's text names MD5.</returns>
    private static bool IsMd5(AdESDigestAlgorithmIdentifier hashAlgorithm) =>
        hashAlgorithm is AdESDigestAlgorithmTextIdentifier text && IsMd5(text.Value);


    /// <summary>
    /// Appends a <see cref="JAdESUndisclosedAlternativeMechanismViolation"/> when <paramref name="registry"/> is
    /// supplied AND carries no disclosure for <paramref name="unknown"/>'s own kind (JA-D-02). A
    /// <see langword="null"/> <paramref name="registry"/> performs no check at all — the caller never opted in.
    /// </summary>
    /// <param name="unknown">The unknown-kind <c>etsiU</c> catch-all element under check.</param>
    /// <param name="registry">The caller's opt-in Annex D registry, or <see langword="null"/> to skip this check.</param>
    /// <param name="collected">The violation list to append to.</param>
    private static void CheckAlternativeMechanismDisclosed(
        JAdESUnsignedHeaderElementUnknown unknown,
        JAdESAlternativeMechanismDisclosureRegistry? registry,
        List<JAdESRuleViolation> collected)
    {
        if(registry is null)
        {
            return;
        }

        if(!registry.TryGetDisclosure(unknown.Kind, out _))
        {
            collected.Add(new JAdESUndisclosedAlternativeMechanismViolation(unknown.Kind));
        }
    }


    /// <summary>
    /// Evaluates every <c>cSig</c> countersignature in <paramref name="unsignedHeaders"/> (clause 5.3.2):
    /// decodes each element (<paramref name="tryDecodeCounterSignature"/>), resolves its countersigner public
    /// key (<paramref name="resolvePublicKey"/>), and cryptographically verifies it against
    /// <paramref name="embeddingSignatureValue"/> (<see cref="JAdESCounterSign.VerifyAsync(UnverifiedJwsMessage, ReadOnlyMemory{byte}, EncodeDelegate, PublicKeyMemory, BaseMemoryPool, CancellationToken)"/>).
    /// Never throws for a verification failure; only a missing REQUIRED parameter is a caller-contract
    /// violation.
    /// </summary>
    /// <param name="unsignedHeaders">The decoded <c>etsiU</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="mode">The container's own whole-array incorporation mode (JA-5.3.1-04).</param>
    /// <param name="embeddingSignatureValue">The embedding JAdES signature's own JWS Signature Value octets (JA-5.3.2-03).</param>
    /// <param name="tryDecodeCounterSignature">The <c>cSig</c> decode-for-inspection seam.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url-decoding.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="resolvePublicKey">Resolves the countersigner's public key from the decoded nested message.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// Every unresolved/failed countersignature, as a <see cref="JAdESCounterSignatureVerificationViolation"/>;
    /// empty when <paramref name="unsignedHeaders"/> is <see langword="null"/>, carries no <c>cSig</c> element,
    /// or every <c>cSig</c> element verifies.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="tryDecodeCounterSignature"/>, <paramref name="base64UrlDecoder"/>,
    /// <paramref name="base64UrlEncoder"/>, <paramref name="resolvePublicKey"/>, or <paramref name="pool"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// <strong>Manual disposal, not a <see langword="using"/> declaration.</strong> <c>decoded</c> is bound
    /// through <paramref name="tryDecodeCounterSignature"/>'s <see langword="out"/> parameter inside the
    /// loop's own <see langword="try"/> (a <see langword="using"/> declaration accepts only a single simple
    /// declaration, never an <see langword="out"/>-parameter target); the <see langword="finally"/> disposes
    /// it once per iteration regardless of outcome.
    /// </remarks>
    public static async ValueTask<IReadOnlyList<JAdESRuleViolation>> CheckCounterSignaturesAsync(
        JAdESUnsignedHeaders? unsignedHeaders,
        JAdESEtsiUIncorporationMode mode,
        ReadOnlyMemory<byte> embeddingSignatureValue,
        TryDecodeJAdESCounterSignatureDelegate tryDecodeCounterSignature,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        ResolveJAdESCounterSignaturePublicKeyDelegate resolvePublicKey,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tryDecodeCounterSignature);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(resolvePublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        var violations = new List<JAdESRuleViolation>();
        if(unsignedHeaders is null)
        {
            return violations;
        }

        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            if(unsignedHeaders[i] is not JAdESUnsignedHeaderElementCounterSignature cSig)
            {
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();

            UnverifiedJAdESMessage? decoded = null;
            try
            {
                if(!tryDecodeCounterSignature(cSig, mode, base64UrlDecoder, pool, out decoded) || decoded is null)
                {
                    violations.Add(new JAdESCounterSignatureVerificationViolation(JAdESCounterSignatureVerificationFailureReason.DecodeFailed, i));
                    continue;
                }

                PublicKeyMemory? publicKey = resolvePublicKey(decoded);
                if(publicKey is null)
                {
                    violations.Add(new JAdESCounterSignatureVerificationViolation(JAdESCounterSignatureVerificationFailureReason.KeyUnresolved, i));
                    continue;
                }

                bool verified = await JAdESCounterSign.VerifyAsync(
                    decoded.Wire, embeddingSignatureValue, base64UrlEncoder, publicKey, pool, cancellationToken).ConfigureAwait(false);

                if(!verified)
                {
                    violations.Add(new JAdESCounterSignatureVerificationViolation(JAdESCounterSignatureVerificationFailureReason.CryptographicVerificationFailed, i));
                }
            }
            finally
            {
                decoded?.Dispose();
            }
        }

        return violations;
    }


    /// <summary>
    /// The throw posture for <see cref="CheckCounterSignaturesAsync"/>: raises <see cref="ArgumentException"/>
    /// naming the first failing <c>cSig</c> element.
    /// </summary>
    /// <exception cref="ArgumentException">At least one <c>cSig</c> element fails to decode or verify.</exception>
    public static async ValueTask EnsureCounterSignaturesVerifiedAsync(
        JAdESUnsignedHeaders? unsignedHeaders,
        JAdESEtsiUIncorporationMode mode,
        ReadOnlyMemory<byte> embeddingSignatureValue,
        TryDecodeJAdESCounterSignatureDelegate tryDecodeCounterSignature,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        ResolveJAdESCounterSignaturePublicKeyDelegate resolvePublicKey,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<JAdESRuleViolation> violations = await CheckCounterSignaturesAsync(
            unsignedHeaders, mode, embeddingSignatureValue, tryDecodeCounterSignature, base64UrlDecoder,
            base64UrlEncoder, resolvePublicKey, pool, cancellationToken).ConfigureAwait(false);

        if(violations.Count == 0)
        {
            return;
        }

        JAdESRuleViolation first = violations[0];
        string suffix = violations.Count > 1
            ? $" ({violations.Count - 1} further countersignature violation(s) also apply.)"
            : string.Empty;

        throw new ArgumentException($"{first.RequirementId}: {first.Message}{suffix}", nameof(unsignedHeaders));
    }


    /// <summary>
    /// Evaluates the JA-A.1.1-12/JA-A.1.2-35/JA-A.1.3-08/JA-A.1.4-10 cross-component consistency family (the
    /// CB-A.1.1-30 analog): for <c>xRefs</c>/<c>axRefs</c>, when at least one of <c>xVals</c>, <c>axVals</c>, or
    /// <c>arcTst</c> is also incorporated, every referenced certificate must be present in <c>xVals</c>/
    /// <c>axVals</c> or embedded in an <c>arcTst</c> instance's own time-stamp tokens; symmetrically for
    /// <c>rRefs</c>/<c>arRefs</c> against <c>rVals</c>/<c>arVals</c>/<c>arcTst</c>-embedded CRLs (OCSP
    /// candidates are never token-widened — <c>arcTst</c>'s tokens embed certificates/CRLs, never OCSP
    /// responses, mirroring the CB-AdES precedent's identical asymmetry). Checked via the registered digest
    /// delegate; never throws for a resolution failure, only for a missing REQUIRED parameter.
    /// </summary>
    /// <remarks>
    /// <strong>Clear-JSON mode only.</strong> Resolving a digest requires the decoded shape every
    /// <c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/<c>arRefs</c>/<c>xVals</c>/<c>rVals</c>/<c>axVals</c>/<c>arVals</c>/
    /// <c>arcTst</c> carriage carries only under <see cref="JAdESEtsiUIncorporationMode.ClearJson"/> (the
    /// whole-array duality is container-wide, JA-5.3.1-10/-11) — a <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>
    /// container returns no violations at all from this check (nothing decoded, nothing to check; "cannot
    /// check, so no violation", the same posture <see cref="Check"/> already applies per-element).
    /// </remarks>
    /// <param name="unsignedHeaders">The decoded <c>etsiU</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="pool">The memory pool transient digest buffers rent from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>Every unresolved reference, as a <see cref="JAdESReferencesValidationDataConsistencyViolation"/>; empty when every trigger's candidate resolves or no trigger fires.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<IReadOnlyList<JAdESRuleViolation>> CheckReferencesResolveToValidationDataAsync(
        JAdESUnsignedHeaders? unsignedHeaders,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var violations = new List<JAdESRuleViolation>();
        if(unsignedHeaders is null || unsignedHeaders.Mode != JAdESEtsiUIncorporationMode.ClearJson)
        {
            return violations;
        }

        var xRefsList = new List<JAdESCertificateReferenceCollection>();
        var axRefsList = new List<JAdESCertificateReferenceCollection>();
        var rRefsList = new List<JAdESRevocationReferenceCollection>();
        var arRefsList = new List<JAdESRevocationReferenceCollection>();
        var certCandidates = new List<ReadOnlyMemory<byte>>();
        var crlCandidates = new List<ReadOnlyMemory<byte>>();
        var ocspCandidates = new List<ReadOnlyMemory<byte>>();
        var archiveTimestampContainers = new List<AdESTimestampContainer>();

        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            switch(unsignedHeaders[i])
            {
                case JAdESUnsignedHeaderElementCertificateReferences { Carriage: JAdESClearUnsignedValue<JAdESCertificateReferenceCollection> clear }:
                    xRefsList.Add(clear.Value);
                    break;

                case JAdESUnsignedHeaderElementAttributeCertificateReferences { Carriage: JAdESClearUnsignedValue<JAdESCertificateReferenceCollection> clear }:
                    axRefsList.Add(clear.Value);
                    break;

                case JAdESUnsignedHeaderElementRevocationReferences { Carriage: JAdESClearUnsignedValue<JAdESRevocationReferenceCollection> clear }:
                    rRefsList.Add(clear.Value);
                    break;

                case JAdESUnsignedHeaderElementAttributeRevocationReferences { Carriage: JAdESClearUnsignedValue<JAdESRevocationReferenceCollection> clear }:
                    arRefsList.Add(clear.Value);
                    break;

                case JAdESUnsignedHeaderElementCertificateValues { Carriage: JAdESClearUnsignedValue<JAdESCertificateValues> clear }:
                    CollectCertificateCandidates(clear.Value, certCandidates);
                    break;

                case JAdESUnsignedHeaderElementAttributeCertificateValues { Carriage: JAdESClearUnsignedValue<JAdESCertificateValues> clear }:
                    CollectCertificateCandidates(clear.Value, certCandidates);
                    break;

                case JAdESUnsignedHeaderElementRevocationValues { Carriage: JAdESClearUnsignedValue<JAdESRevocationValues> clear }:
                    CollectRevocationCandidates(clear.Value, crlCandidates, ocspCandidates);
                    break;

                case JAdESUnsignedHeaderElementAttributeRevocationValues { Carriage: JAdESClearUnsignedValue<JAdESRevocationValues> clear }:
                    CollectRevocationCandidates(clear.Value, crlCandidates, ocspCandidates);
                    break;

                case JAdESUnsignedHeaderElementArchiveTimestamp { Carriage: JAdESClearUnsignedValue<AdESTimestampContainer> clear }:
                    archiveTimestampContainers.Add(clear.Value);
                    break;
            }
        }

        bool certificateTrigger = certCandidates.Count > 0 || archiveTimestampContainers.Count > 0;
        bool revocationTrigger = crlCandidates.Count > 0 || ocspCandidates.Count > 0 || archiveTimestampContainers.Count > 0;

        bool anyCertificateRefs = (xRefsList.Count > 0 || axRefsList.Count > 0) && certificateTrigger;
        bool anyRevocationRefs = (rRefsList.Count > 0 || arRefsList.Count > 0) && revocationTrigger;
        if(!anyCertificateRefs && !anyRevocationRefs)
        {
            return violations;
        }

        var openedTokens = new List<TimestampTokenInfo>();
        try
        {
            //Widen the candidate set with every certificate/CRL the signature's own arcTst instances' tokens
            //embed (mirroring CB-A.1.1-30's identical precedent) -- an arcTst-only trigger with no valData
            //element at all still resolves against token-embedded material alone.
            for(int c = 0; c < archiveTimestampContainers.Count; ++c)
            {
                AdESTimestampContainer container = archiveTimestampContainers[c];
                for(int t = 0; t < container.TstTokens.Count; ++t)
                {
                    using PkiCertificateMemory tokenMemory = JAdESSignatureValidation.RentTimestampTokenMemory(container.TstTokens[t].Val, pool);
                    TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(tokenMemory, pool, cancellationToken).ConfigureAwait(false);
                    openedTokens.Add(tokenInfo);

                    if(!tokenInfo.IsRead)
                    {
                        continue;
                    }

                    for(int e = 0; e < tokenInfo.EmbeddedCertificates.Count; ++e)
                    {
                        certCandidates.Add(tokenInfo.EmbeddedCertificates[e].AsReadOnlyMemory());
                    }

                    for(int e = 0; e < tokenInfo.EmbeddedCrls.Count; ++e)
                    {
                        crlCandidates.Add(tokenInfo.EmbeddedCrls[e].AsReadOnlyMemory());
                    }
                }
            }

            if(anyCertificateRefs)
            {
                await ResolveCertificateReferencesAsync(xRefsList, certCandidates, JAdESRefsFamilyDigestSurface.CertificateReferences, violations, pool, cancellationToken).ConfigureAwait(false);
                await ResolveCertificateReferencesAsync(axRefsList, certCandidates, JAdESRefsFamilyDigestSurface.AttributeCertificateReferences, violations, pool, cancellationToken).ConfigureAwait(false);
            }

            if(anyRevocationRefs)
            {
                await ResolveRevocationReferencesAsync(rRefsList, crlCandidates, ocspCandidates, JAdESRefsFamilyDigestSurface.RevocationReferences, violations, pool, cancellationToken).ConfigureAwait(false);
                await ResolveRevocationReferencesAsync(arRefsList, crlCandidates, ocspCandidates, JAdESRefsFamilyDigestSurface.AttributeRevocationReferences, violations, pool, cancellationToken).ConfigureAwait(false);
            }

            return violations;
        }
        finally
        {
            for(int i = 0; i < openedTokens.Count; ++i)
            {
                openedTokens[i].Dispose();
            }
        }
    }


    /// <summary>
    /// The augmentation/validation throw posture for the JA-A.1.1-12/JA-A.1.2-35/JA-A.1.3-08/JA-A.1.4-10 family:
    /// calls <see cref="CheckReferencesResolveToValidationDataAsync"/> and raises <see cref="ArgumentException"/>
    /// naming the first unresolved reference.
    /// </summary>
    /// <param name="unsignedHeaders">The decoded <c>etsiU</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="pool">The memory pool transient digest buffers rent from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">At least one <c>refs</c>-family entry fails to resolve.</exception>
    public static async ValueTask EnsureReferencesResolveToValidationDataAsync(
        JAdESUnsignedHeaders? unsignedHeaders,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<JAdESRuleViolation> violations = await CheckReferencesResolveToValidationDataAsync(unsignedHeaders, pool, cancellationToken).ConfigureAwait(false);
        if(violations.Count == 0)
        {
            return;
        }

        JAdESRuleViolation first = violations[0];
        string suffix = violations.Count > 1
            ? $" ({violations.Count - 1} further unresolved reference(s) also apply.)"
            : string.Empty;

        throw new ArgumentException($"{first.RequirementId}: {first.Message}{suffix}", nameof(unsignedHeaders));
    }


    /// <summary>
    /// Collects every <c>x509Cert</c> entry's raw octets reachable through <paramref name="certificateValues"/>
    /// into <paramref name="candidates"/> — <c>otherCert</c> entries are opaque-format placeholders and are not
    /// collected, mirroring the CB-AdES precedent's identical <c>otherCert</c>/<c>otherVals</c> exclusion.
    /// </summary>
    /// <param name="certificateValues">The decoded <c>xVals</c>/<c>axVals</c> element.</param>
    /// <param name="candidates">Receives every <c>x509Cert</c> entry's raw octets.</param>
    private static void CollectCertificateCandidates(JAdESCertificateValues certificateValues, List<ReadOnlyMemory<byte>> candidates)
    {
        for(int i = 0; i < certificateValues.Items.Count; ++i)
        {
            if(certificateValues.Items[i] is JAdESX509Certificate x509)
            {
                candidates.Add(x509.Certificate.Val);
            }
        }
    }


    /// <summary>
    /// Collects every <c>crlVals</c>/<c>ocspVals</c> entry's raw octets reachable through
    /// <paramref name="revocationValues"/> into <paramref name="crlCandidates"/>/<paramref name="ocspCandidates"/>
    /// — <c>otherVals</c> entries are opaque-format placeholders and are not collected.
    /// </summary>
    /// <param name="revocationValues">The decoded <c>rVals</c>/<c>arVals</c> element.</param>
    /// <param name="crlCandidates">Receives every <c>crlVals</c> entry's raw octets.</param>
    /// <param name="ocspCandidates">Receives every <c>ocspVals</c> entry's raw octets.</param>
    private static void CollectRevocationCandidates(
        JAdESRevocationValues revocationValues, List<ReadOnlyMemory<byte>> crlCandidates, List<ReadOnlyMemory<byte>> ocspCandidates)
    {
        if(revocationValues.CrlValues is not null)
        {
            for(int i = 0; i < revocationValues.CrlValues.Count; ++i)
            {
                crlCandidates.Add(revocationValues.CrlValues[i].Val);
            }
        }

        if(revocationValues.OcspValues is not null)
        {
            for(int i = 0; i < revocationValues.OcspValues.Count; ++i)
            {
                ocspCandidates.Add(revocationValues.OcspValues[i].Val);
            }
        }
    }


    /// <summary>
    /// Resolves every entry of every collection in <paramref name="collections"/> against
    /// <paramref name="candidates"/>, appending a <see cref="JAdESReferencesValidationDataConsistencyViolation"/>
    /// citing <paramref name="surface"/> for each that does not resolve.
    /// </summary>
    private static async ValueTask ResolveCertificateReferencesAsync(
        List<JAdESCertificateReferenceCollection> collections,
        List<ReadOnlyMemory<byte>> candidates,
        JAdESRefsFamilyDigestSurface surface,
        List<JAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        //One digest-keyed index built ONCE over candidates, reused across every collection/item, rather
        //than re-digesting the whole candidate list per item (O(items x candidates) -> O(candidates) per
        //distinct algorithm plus one dictionary lookup per item) -- the JAdES twin of XAdESLevelRules' own
        //CandidateDigestIndex fix.
        var index = new CandidateDigestIndex(candidates, pool);
        for(int c = 0; c < collections.Count; ++c)
        {
            IReadOnlyList<AdESCertificateThumbprint> items = collections[c].Items;
            for(int i = 0; i < items.Count; ++i)
            {
                bool resolved = await index.ResolveAsync(items[i].HashAlgorithm, items[i].Digest, cancellationToken).ConfigureAwait(false);
                if(!resolved)
                {
                    violations.Add(new JAdESReferencesValidationDataConsistencyViolation(surface, JAdESReferenceMaterialKind.Certificate));
                }
            }
        }
    }


    /// <summary>
    /// Resolves every CRL/OCSP entry of every collection in <paramref name="collections"/> against
    /// <paramref name="crlCandidates"/>/<paramref name="ocspCandidates"/> respectively, appending a
    /// <see cref="JAdESReferencesValidationDataConsistencyViolation"/> citing <paramref name="surface"/> for
    /// each that does not resolve.
    /// </summary>
    private static async ValueTask ResolveRevocationReferencesAsync(
        List<JAdESRevocationReferenceCollection> collections,
        List<ReadOnlyMemory<byte>> crlCandidates,
        List<ReadOnlyMemory<byte>> ocspCandidates,
        JAdESRefsFamilyDigestSurface surface,
        List<JAdESRuleViolation> violations,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        //(See ResolveCertificateReferencesAsync's identical rationale): one index per candidate list,
        //built once, reused across every collection/item of that list.
        var crlIndex = new CandidateDigestIndex(crlCandidates, pool);
        var ocspIndex = new CandidateDigestIndex(ocspCandidates, pool);
        for(int c = 0; c < collections.Count; ++c)
        {
            IReadOnlyList<AdESCertificateThumbprint> crlReferences = collections[c].CrlReferences;
            for(int i = 0; i < crlReferences.Count; ++i)
            {
                bool resolved = await crlIndex.ResolveAsync(crlReferences[i].HashAlgorithm, crlReferences[i].Digest, cancellationToken).ConfigureAwait(false);
                if(!resolved)
                {
                    violations.Add(new JAdESReferencesValidationDataConsistencyViolation(surface, JAdESReferenceMaterialKind.Crl));
                }
            }

            IReadOnlyList<AdESCertificateThumbprint> ocspReferences = collections[c].OcspReferences;
            for(int i = 0; i < ocspReferences.Count; ++i)
            {
                bool resolved = await ocspIndex.ResolveAsync(ocspReferences[i].HashAlgorithm, ocspReferences[i].Digest, cancellationToken).ConfigureAwait(false);
                if(!resolved)
                {
                    violations.Add(new JAdESReferencesValidationDataConsistencyViolation(surface, JAdESReferenceMaterialKind.Ocsp));
                }
            }
        }
    }


    /// <summary>
    /// A digest-value-keyed lookup over one candidate list, built lazily and cached per distinct digest output
    /// length (the three resolvable algorithms — SHA-256/384/512 — produce distinct, non-colliding output
    /// lengths, so the length alone is a safe cache key) — the JAdES twin of <c>XAdESLevelRules</c>'
    /// own <c>CandidateDigestIndex</c>: turns what was one full candidate-list digest pass PER reference
    /// (O(references x candidates)) into one candidate-list digest pass PER distinct algorithm plus one
    /// dictionary lookup per reference (O(references + candidates)).
    /// </summary>
    private sealed class CandidateDigestIndex(IReadOnlyList<ReadOnlyMemory<byte>> candidates, BaseMemoryPool pool)
    {
        private Dictionary<int, HashSet<string>> DigestsByOutputLength { get; } = [];

        /// <summary>
        /// Determines whether <paramref name="referenceDigest"/> (declared under <paramref name="algorithm"/>)
        /// resolves to any candidate — building and caching that output length's candidate-digest set on first
        /// use, fails closed (returns <see langword="false"/>, never throws) when <paramref name="algorithm"/>
        /// is not a textual identifier this method can map to a <see cref="Tag"/> — a JAdES <c>digAlg</c> is a
        /// textual IANA Named Information Hash Algorithm Registry identifier riding
        /// <see cref="AdESDigestAlgorithmTextIdentifier"/>, so an integer-arm identifier never resolves.
        /// </summary>
        /// <param name="algorithm">The reference's own digest-algorithm identifier (JA-5.2.2.2-06).</param>
        /// <param name="referenceDigest">The reference's stored digest value.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns><see langword="true"/> when at least one candidate's digest matches <paramref name="referenceDigest"/>.</returns>
        public async ValueTask<bool> ResolveAsync(AdESDigestAlgorithmIdentifier algorithm, DigestValue referenceDigest, CancellationToken cancellationToken)
        {
            if(algorithm is not AdESDigestAlgorithmTextIdentifier textIdentifier)
            {
                return false;
            }

            if(ResolveDigestTag(textIdentifier.Value) is not Tag tag)
            {
                return false;
            }

            int outputLength = referenceDigest.Length;
            if(!DigestsByOutputLength.TryGetValue(outputLength, out HashSet<string>? digests))
            {
                digests = await BuildIndexAsync(tag, outputLength, cancellationToken).ConfigureAwait(false);
                DigestsByOutputLength[outputLength] = digests;
            }

            return digests.Contains(Convert.ToHexStringLower(referenceDigest.AsReadOnlySpan()));
        }


        private async ValueTask<HashSet<string>> BuildIndexAsync(Tag tag, int outputLength, CancellationToken cancellationToken)
        {
            var digests = new HashSet<string>(candidates.Count, StringComparer.Ordinal);
            for(int i = 0; i < candidates.Count; ++i)
            {
                using DigestValue candidateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                    candidates[i], outputLength, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                digests.Add(Convert.ToHexStringLower(candidateDigest.AsReadOnlySpan()));
            }

            return digests;
        }
    }


    /// <summary>
    /// Maps <paramref name="identifier"/> to the <see cref="Tag"/> the registered digest delegate needs to
    /// select the same hash function — recognizing only the three IANA "Named Information Hash Algorithm
    /// Registry" (<see href="https://www.rfc-editor.org/rfc/rfc6920">RFC 6920</see>) names this library carries
    /// a <see cref="CryptoTags"/> entry for, compared case-insensitively (mirroring <see cref="IsMd5"/>'s own
    /// case-insensitive convention for the same registry). Returns <see langword="null"/> for every other
    /// identifier — resolution cannot be confirmed without knowing which hash function to run, so the caller
    /// reports the reference as unresolved rather than guessing.
    /// </summary>
    /// <param name="identifier">The digest-algorithm identifier to resolve.</param>
    /// <returns>The resolved tag, or <see langword="null"/> when unrecognized.</returns>
    private static Tag? ResolveDigestTag(string identifier) => identifier switch
    {
        string sha256 when string.Equals(sha256, "sha-256", StringComparison.OrdinalIgnoreCase) => CryptoTags.Sha256Digest,
        string sha384 when string.Equals(sha384, "sha-384", StringComparison.OrdinalIgnoreCase) => CryptoTags.Sha384Digest,
        string sha512 when string.Equals(sha512, "sha-512", StringComparison.OrdinalIgnoreCase) => CryptoTags.Sha512Digest,
        _ => null
    };
}


/// <summary>
/// The explicit, per-call inputs <see cref="JAdESLevelRules.Check"/>/<see cref="JAdESLevelRules.EnsureConformant"/>
/// need — grouped into one context because the rule set spans several unrelated fact sources (the decoded
/// <c>etsiU</c> snapshot, the signed-header-set aggregate, the target/claimed baseline level, and caller-computed
/// facts neither this rule surface nor the decoded models can derive on their own). No closure capture: every
/// input travels through this value, never through a captured outer variable.
/// </summary>
[DebuggerDisplay("JAdESLevelRuleContext(Level={Level})")]
public readonly record struct JAdESLevelRuleContext
{
    /// <summary>
    /// Gets the <see cref="AdESBaselineLevel"/> this evaluation targets — the level an augmentation call is
    /// producing, or the level a validation caller is checking a parsed signature against.
    /// </summary>
    public required AdESBaselineLevel Level { get; init; }

    /// <summary>
    /// Gets the decoded <c>etsiU</c> set, or <see langword="null"/> when absent (JA-5.3.1-07: <c>etsiU</c>
    /// either does not exist at all, or is non-empty — never exists-but-empty).
    /// </summary>
    public JAdESUnsignedHeaders? UnsignedHeaders { get; init; }

    /// <summary>
    /// Gets the decoded signed-header-set aggregate, or <see langword="null"/> when unavailable. Consulted by
    /// the letter-b <c>sigPSt</c> gate (<see cref="JAdESProtectedHeaders.SignaturePolicyIdentifier"/>), the
    /// letter-h <c>axRefs</c>/<c>arRefs</c> gate (<see cref="JAdESProtectedHeaders.SignerAttributes"/>), and the
    /// JA-6.3-03 baseline token-shape narrowing over <see cref="JAdESProtectedHeaders.PayloadTimestamps"/>
    /// (<c>adoTst</c> is a SIGNED header parameter, never an <c>etsiU</c> element).
    /// </summary>
    public JAdESProtectedHeaders? ProtectedHeaders { get; init; }

    /// <summary>
    /// Gets the caller-supplied digest(s) of the JAdES signature's own signing certificate, used only by the
    /// JA-A.1.1-02 exclusion check (<see cref="JAdESReferencesSigningCertificateExclusionViolation"/>). This
    /// rule surface cannot itself derive the signing certificate from an <c>etsiU</c> snapshot alone, so the
    /// caller supplies whichever digest(s) it already holds — a byte-comparison match under ANY supplied digest
    /// is reported, regardless of which algorithm produced it. <see langword="null"/> or empty skips this check
    /// entirely (never a false positive from an absent fact).
    /// </summary>
    public IReadOnlyList<DigestValue>? SigningCertificateDigests { get; init; }

    /// <summary>
    /// Gets whether at least one electronic time-stamp token elsewhere in the signature carries its own
    /// embedded certificate/revocation validation material — the JA-6.3-38/j "embedded in the electronic
    /// time-stamp itself" SPO. This rule surface never inspects a token's own encoding to derive this fact
    /// itself; the caller (the validation orchestrator) computes it, reduced via OR across every token the
    /// caller inspected, and supplies the single aggregate here. Defaults to <see langword="false"/>.
    /// </summary>
    public bool AnyTimestampTokenCarriesEmbeddedValidationMaterial { get; init; }

    /// <summary>
    /// Gets the caller's opt-in Annex D alternative-mechanism disclosure registry, or <see langword="null"/> to
    /// skip the <see cref="JAdESUndisclosedAlternativeMechanismViolation"/> check entirely (mirrors
    /// <c>CBAdESLevelRuleContext.AlternativeMechanismDisclosures</c>). Populated once at composition and
    /// treated as read-only thereafter — see <see cref="JAdESAlternativeMechanismDisclosureRegistry"/>'s own
    /// threading contract.
    /// </summary>
    public JAdESAlternativeMechanismDisclosureRegistry? AlternativeMechanismDisclosures { get; init; }
}

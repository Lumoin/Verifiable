using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The shared CB-AdES B-T/B-LT/B-LTA level-scoped rule surface: every level-dependent conformance rule
/// Table 14 (clause 6.3) and Annex A.1.1/A.1.2 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> impose OVER AND ABOVE the B-B rule surface (<see cref="CBAdESHeaderRules"/>),
/// implemented exactly once and consumed by both postures a caller needs (wavecb-contract.md ruling R-1(c)/
/// R-2; S3 coordinator ruling (2), extended level-scoped by S4 coordinator ruling (5)).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Two postures, one implementation, exactly like <see cref="CBAdESHeaderRules"/>.</strong>
/// <see cref="Check"/> and <see cref="CheckReferencesResolveToValidationDataAsync"/> are the COLLECT
/// postures — they never throw on malformed or non-conformant content (R-5), returning every violation found.
/// <see cref="EnsureConformant"/> and <see cref="EnsureReferencesResolveToValidationDataAsync"/> are the
/// THROW postures — the augmentation path's trusted-caller-input guard. Every violation this file's rules can
/// report is a <see cref="CBAdESRuleViolation"/> sibling appended to the SAME closed sum
/// <see cref="CBAdESHeaderRules"/> already declares (this file adds no violation type of its own — see that
/// file for the sealed records this class constructs).
/// </para>
/// <para>
/// <strong>Sync/async split, load-bearing (S4 coordinator ruling (5)).</strong> Eight of the nine level rules
/// this stage adds are pure, synchronous predicates over an already-decoded <see cref="CBAdESUnsignedHeaders"/>
/// snapshot plus a small set of caller-supplied facts (<see cref="Check"/>). The ninth — CB-A.1.1-30's
/// cross-component consistency check — must digest candidate <c>valData</c> material through the REGISTERED
/// digest delegate (<see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, System.Threading.CancellationToken)"/>)
/// to compare against each <c>refs</c> entry's stored digest, so it is its own <see cref="ValueTask"/>-returning
/// pair (<see cref="CheckReferencesResolveToValidationDataAsync"/>/<see cref="EnsureReferencesResolveToValidationDataAsync"/>),
/// composed separately by the augmentation/validation orchestrators (matching the "Token-imprint verification
/// is async composition in the validation orchestrator" ruling).
/// </para>
/// <para>
/// <strong>Level model: <see cref="CBAdESBaselineLevel"/> (m1's Pki model, wavecb S4).</strong>
/// <see cref="CBAdESLevelRuleContext.Level"/> carries the level a caller is either augmenting TO
/// (augmentation) or the level the caller believes a parsed signature CLAIMS to be at (validation — this
/// rule surface does not itself classify a signature's level; that is S7's EN 319 102-1 conclusion work, per
/// the S4 coordinator ruling (5)'s "S4 validation stays certificate-path-neutral" scope note. A validator
/// wanting the strictest read evaluates this surface once per candidate level and reports accordingly).
/// </para>
/// <para>
/// <strong>Scope: this stage checks <c>valData</c> resolution only (CB-A.1.1-30).</strong> The <c>arcTst</c>-
/// reachable half of CB-A.1.1-30's disjunction ("all the certificates and validation data referenced in
/// <c>refs</c> shall be present elsewhere in the signature" when EITHER <c>valData</c> OR <c>arcTst</c> is
/// incorporated) is explicitly deferred to wavecb S5, once <c>arcTst</c> generation lands and its own
/// protected-material extraction exists to resolve against — recorded here loudly per the task's explicit
/// instruction, not silently dropped.
/// </para>
/// </remarks>
public static class CBAdESLevelRules
{
    /// <summary>
    /// Evaluates every SYNCHRONOUS level rule against <paramref name="context"/> and returns every violation
    /// found. Never throws on non-conformant content (R-5) — only a missing REQUIRED context field (an
    /// <see langword="ArgumentException"/> on an invalid <paramref name="context"/>) is a caller-contract
    /// violation, not a conformance judgment.
    /// </summary>
    /// <param name="context">The level-rule inputs; see <see cref="CBAdESLevelRuleContext"/>.</param>
    /// <returns>Every violation found, in rule-declaration order; empty when fully conformant.</returns>
    public static IReadOnlyList<CBAdESRuleViolation> Check(CBAdESLevelRuleContext context)
    {
        var violations = new List<CBAdESRuleViolation>();

        int signatureTimestampCount = 0;
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
                        CheckBaselineTokenShape(arcTst.ArchiveTimestamp.TimestampContainer, CBAdESTimestampContainerKind.ArchiveTimestamp, violations);
                        break;

                    case CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp sigRTst:
                        CheckBaselineTokenShape(sigRTst.SignatureAndReferencesTimestamp.TimestampContainer, CBAdESTimestampContainerKind.SignatureAndReferencesTimestamp, violations);
                        if(context.Level >= CBAdESBaselineLevel.BLT)
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
                        if(context.Level >= CBAdESBaselineLevel.BLT)
                        {
                            violations.Add(new CBAdESRefsFamilyForbiddenViolation(CBAdESRefsFamilyKind.ReferencesTimestamp));
                        }
                        else if(!HasReferencesBefore(unsignedHeaders, i))
                        {
                            violations.Add(new CBAdESReferencesTimestampGenerationGateViolation(CBAdESReferencesTimestampGenerationKind.ReferencesOnly));
                        }
                        break;

                    case CBAdESUnsignedHeaderElementReferences refsElement:
                        if(context.Level >= CBAdESBaselineLevel.BLT)
                        {
                            violations.Add(new CBAdESRefsFamilyForbiddenViolation(CBAdESRefsFamilyKind.References));
                        }

                        CheckSigningCertificateExclusion(refsElement.References, context.SigningCertificateDigests, violations);
                        CheckRefsFamilyMd5(refsElement.References, violations);
                        break;

                    case CBAdESUnsignedHeaderElementValidationData:
                        validationDataPresent = true;
                        break;
                }
            }
        }

        //CB-6.3-21: cumulative >=1 sigTst instance from B-T onward (D2: the duplicated "B-LT, B-LTA: 0"
        //Table 14 sub-line is read as zero NEW instances required at those levels, not zero total -- see
        //CBAdESSignatureTimestampMissingViolation's own remarks for why that half is documented, not checked,
        //from a single uHeaders snapshot).
        if(context.Level >= CBAdESBaselineLevel.BT && signatureTimestampCount == 0)
        {
            violations.Add(new CBAdESSignatureTimestampMissingViolation());
        }

        //CB-6.3-26/h: the validation-data-for-time-stamps service, evaluated only from B-LT onward (it is "*"
        //-- should-not-be-provided -- at B-B/B-T). Additional requirement (i)'s SHOULD-level preference for
        //the valData SPO over the embedded-in-token SPO is documented on the violation record, never enforced
        //as a hard rule here.
        if(context.Level >= CBAdESBaselineLevel.BLT)
        {
            bool serviceSatisfied = validationDataPresent || context.AnyTimestampTokenCarriesEmbeddedValidationMaterial;
            if(!serviceSatisfied)
            {
                violations.Add(new CBAdESTimestampValidationDataServiceViolation());
            }
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
        static void CheckTokenCount(CBAdESTimestampContainer container, List<CBAdESRuleViolation> collected)
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
        static void CheckBaselineTokenShape(CBAdESTimestampContainer container, CBAdESTimestampContainerKind kind, List<CBAdESRuleViolation> collected)
        {
            for(int t = 0; t < container.TstTokens.Count; ++t)
            {
                CBAdESTimestampToken token = container.TstTokens[t];
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
        static bool IsMd5(CBAdESDigestAlgorithmIdentifier identifier) => identifier switch
        {
            CBAdESDigestAlgorithmTextIdentifier text => string.Equals(text.Value, "MD5", StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }


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
    /// carries both a <c>refs</c> element and at least one <c>valData</c> element, every <c>CertId</c>/
    /// <c>CRLRef</c>/<c>OCSPRef</c> entry in <c>refs</c> must resolve to material actually present in
    /// <c>valData</c> — checked by digesting each candidate <c>valData</c> cert/CRL/OCSP entry under the
    /// reference's own algorithm through the registered digest delegate and comparing
    /// <see cref="DigestValue"/> equality. Never throws for a resolution failure (R-5); only a missing
    /// REQUIRED parameter is a caller-contract violation.
    /// </summary>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="pool">The memory pool transient digest buffers rent from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// Every unresolved reference, as a <see cref="CBAdESReferencesValidationDataConsistencyViolation"/>;
    /// empty when <paramref name="unsignedHeaders"/> is <see langword="null"/>, carries no <c>refs</c>
    /// element, carries no <c>valData</c> element (this rule applies ONLY when both are present — the
    /// <c>arcTst</c>-reachable half of CB-A.1.1-30's disjunction is deferred to wavecb S5, see the class
    /// remarks), or every reference resolves.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
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
        var certificateCandidates = new List<CBAdESPkiObject>();
        var crlCandidates = new List<CBAdESPkiObject>();
        var ocspCandidates = new List<CBAdESPkiObject>();

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
            }
        }

        //CB-A.1.1-30 fires only when refs is present AND at least one valData element is also present -- the
        //stated trigger condition ("If at least one of the following: valData or the arcTst, is incorporated
        //...", valData half only, this stage's scope per the class remarks).
        if(refsElements.Count == 0 || (certificateCandidates.Count == 0 && crlCandidates.Count == 0 && ocspCandidates.Count == 0))
        {
            return violations;
        }

        for(int r = 0; r < refsElements.Count; ++r)
        {
            CBAdESReferences refs = refsElements[r];

            if(refs.CertificateReferences is not null)
            {
                for(int i = 0; i < refs.CertificateReferences.Count; ++i)
                {
                    CBAdESCertificateThumbprint thumbprint = refs.CertificateReferences[i].Thumbprint;
                    bool resolved = await ResolvesAsync(thumbprint.HashAlgorithm, thumbprint.Digest, certificateCandidates, pool, cancellationToken).ConfigureAwait(false);
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
                    bool resolved = await ResolvesAsync(crlRef.HashAlgorithm, crlRef.Digest, crlCandidates, pool, cancellationToken).ConfigureAwait(false);
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
                    bool resolved = await ResolvesAsync(ocspRef.HashAlgorithm, ocspRef.Digest, ocspCandidates, pool, cancellationToken).ConfigureAwait(false);
                    if(!resolved)
                    {
                        violations.Add(new CBAdESReferencesValidationDataConsistencyViolation(CBAdESReferenceMaterialKind.Ocsp));
                    }
                }
            }
        }

        return violations;

        /// <summary>
        /// Collects every certificate/CRL/OCSP <see cref="CBAdESPkiObject"/> reachable through
        /// <paramref name="validationData"/> into the caller's aggregation lists — <c>otherCert</c>/
        /// <c>otherVals</c> entries are opaque-format placeholders (CB-5.3.4's own extensibility notes) and
        /// are not collected, since CB-A.1.1-30 resolution is defined over DER-encoded X.509/CRL/OCSP material.
        /// </summary>
        /// <param name="validationData">The decoded <c>valData</c> element.</param>
        /// <param name="certificates">Receives every <c>x509Cert</c> entry's <see cref="CBAdESPkiObject"/>.</param>
        /// <param name="crls">Receives every <c>crlVals</c> entry.</param>
        /// <param name="ocsps">Receives every <c>ocspVals</c> entry.</param>
        static void CollectValidationDataCandidates(
            CBAdESValidationData validationData,
            List<CBAdESPkiObject> certificates,
            List<CBAdESPkiObject> crls,
            List<CBAdESPkiObject> ocsps)
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


        /// <summary>
        /// Determines whether <paramref name="referenceDigest"/> (computed under <paramref name="algorithm"/>)
        /// resolves to any of <paramref name="candidates"/> — digesting each candidate under the SAME
        /// algorithm through the registered digest delegate and comparing byte-for-byte. Fails closed
        /// (returns <see langword="false"/>, never throws) when <paramref name="algorithm"/> is not one this
        /// method can map to a <see cref="Tag"/> carrying a <see cref="System.Security.Cryptography.HashAlgorithmName"/>
        /// — an unresolvable algorithm means resolution cannot be confirmed, so it is reported as unresolved.
        /// </summary>
        /// <param name="algorithm">The reference's own digest-algorithm identifier.</param>
        /// <param name="referenceDigest">The reference's stored digest value.</param>
        /// <param name="candidates">The candidate <c>valData</c> material to digest and compare against.</param>
        /// <param name="pool">The memory pool transient digest buffers rent from.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns><see langword="true"/> when at least one candidate's digest matches <paramref name="referenceDigest"/>.</returns>
        static async ValueTask<bool> ResolvesAsync(
            CBAdESDigestAlgorithmIdentifier algorithm,
            DigestValue referenceDigest,
            List<CBAdESPkiObject> candidates,
            BaseMemoryPool pool,
            CancellationToken cancellationToken)
        {
            Tag? tag = ResolveDigestTag(algorithm);
            if(tag is null)
            {
                return false;
            }

            for(int i = 0; i < candidates.Count; ++i)
            {
                using DigestValue candidateDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                    candidates[i].Val, referenceDigest.Length, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                if(candidateDigest.AsReadOnlySpan().SequenceEqual(referenceDigest.AsReadOnlySpan()))
                {
                    return true;
                }
            }

            return false;
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
        static Tag? ResolveDigestTag(CBAdESDigestAlgorithmIdentifier identifier) => identifier switch
        {
            CBAdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha256 } => CryptoTags.Sha256Digest,
            CBAdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha384 } => CryptoTags.Sha384Digest,
            CBAdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha512 } => CryptoTags.Sha512Digest,
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
    /// Gets the <see cref="CBAdESBaselineLevel"/> this evaluation targets — the level an augmentation call is
    /// producing, or the level a validation caller is checking a parsed signature against.
    /// </summary>
    public required CBAdESBaselineLevel Level { get; init; }

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
    /// orchestrator, per the CMS-probe extension point the S4 coordinator ruling (5) flags) computes it,
    /// reduced via OR across every token the caller inspected, and supplies the single aggregate here.
    /// Defaults to <see langword="false"/>.
    /// </summary>
    public bool AnyTimestampTokenCarriesEmbeddedValidationMaterial { get; init; }
}

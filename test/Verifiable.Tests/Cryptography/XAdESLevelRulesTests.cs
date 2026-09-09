using System.Buffers;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Proofs of <see cref="XAdESLevelRules"/> against clause 6.3, Table 2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> — the table-driven MUST-level engine over hand-built <see
/// cref="XAdESQualifyingPropertiesFacts"/> instances (no XML parsing needed: the engine's own input is
/// already the format-neutral facts shape the seam produces).
/// </summary>
[TestClass]
internal sealed class XAdESLevelRulesTests
{
    public TestContext TestContext { get; set; } = null!;


    private static XAdESValidationDataCounts EmptyValidationData { get; } = new();


    /// <summary>
    /// Builds a fact set defaulting to a minimal, B-B-conformant shape (<c>SigningTime</c>/<c>SigningCertificateV2</c>
    /// once each signed, one <c>SignatureTimeStamp</c> unsigned, empty validation-data counts) — every parameter
    /// overrides exactly one dimension the caller's own test needs to vary, keeping every other row at its
    /// harmless default.
    /// </summary>
    private static XAdESQualifyingPropertiesFacts BuildFacts(
        Dictionary<string, int>? signed = null,
        Dictionary<string, int>? unsigned = null,
        XAdESValidationDataCounts? validationData = null,
        AdESSignerAttributes? signerRole = null,
        IReadOnlyList<string>? unknownPropertyObservations = null,
        IReadOnlyList<string>? deprecatedPropertyObservations = null,
        IReadOnlyList<PkiCertificateMemory>? embeddedCertificates = null,
        IReadOnlyList<PkiCertificateMemory>? embeddedCrls = null,
        IReadOnlyList<PkiCertificateMemory>? embeddedOcsp = null,
        IReadOnlyList<XAdESCertificateReferenceDigestFact>? completeCertificateRefs = null,
        IReadOnlyList<XAdESCertificateReferenceDigestFact>? attributeCertificateRefs = null,
        IReadOnlyList<XAdESCrlReferenceFact>? completeRevocationCrlRefs = null,
        IReadOnlyList<XAdESOcspReferenceFact>? completeRevocationOcspRefs = null,
        IReadOnlyList<XAdESCrlReferenceFact>? attributeRevocationCrlRefs = null,
        IReadOnlyList<XAdESOcspReferenceFact>? attributeRevocationOcspRefs = null,
        bool certificateValidationDataTriggered = false,
        bool revocationValidationDataTriggered = false,
        XAdESDiscoveryFact? discovery = null,
        bool isDataObjectFormatCoverageSatisfied = true,
        bool? validationDataForTimestampsHasContent = null,
        IReadOnlyList<XAdESTimestampContainerMetadata>? timestampContainers = null,
        XAdESSignaturePolicyFact? signaturePolicy = null,
        IReadOnlyList<XAdESSigningCertificateDigestFact>? signingCertificateDigests = null) => new()
    {
        SigningCertificateDigests = signingCertificateDigests ?? [],
        Discovery = discovery ?? new XAdESDiscoveryFact
        {
            HasQualifyingProperties = true,
            TargetResolvedToSignature = true,
            SignedPropertiesReferencePresent = true,
            SignedPropertiesReferenceResolvedToDiscoveredNode = true
        },
        IsDataObjectFormatCoverageSatisfied = isDataObjectFormatCoverageSatisfied,
        SignaturePolicy = signaturePolicy,
        ValidationData = validationData ?? EmptyValidationData,
        ValidationDataForTimestampsHasContent = validationDataForTimestampsHasContent
            ?? (validationData ?? EmptyValidationData) is { TimeStampValidationDataCount: > 0 } or { AnyValidationDataCount: > 0 },
        TimestampContainers = timestampContainers ?? [],
        SignedPropertyOccurrenceCounts = signed ?? new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [XAdESBaselineLevelTable.SigningTime.Name] = 1,
            [XAdESBaselineLevelTable.SigningCertificateV2.Name] = 1
        },
        UnsignedPropertyOccurrenceCounts = unsigned ?? new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [XAdESBaselineLevelTable.SignatureTimeStamp.Name] = 1
        },
        SignerRole = signerRole,
        UnknownPropertyObservations = unknownPropertyObservations ?? [],
        DeprecatedPropertyObservations = deprecatedPropertyObservations ?? [],
        EmbeddedCertificates = embeddedCertificates ?? [],
        EmbeddedCertificateRevocationLists = embeddedCrls ?? [],
        EmbeddedOcspResponses = embeddedOcsp ?? [],
        CompleteCertificateRefs = completeCertificateRefs ?? [],
        AttributeCertificateRefs = attributeCertificateRefs ?? [],
        CompleteRevocationCrlRefs = completeRevocationCrlRefs ?? [],
        CompleteRevocationOcspRefs = completeRevocationOcspRefs ?? [],
        AttributeRevocationCrlRefs = attributeRevocationCrlRefs ?? [],
        AttributeRevocationOcspRefs = attributeRevocationOcspRefs ?? [],
        CertificateValidationDataTriggered = certificateValidationDataTriggered,
        RevocationValidationDataTriggered = revocationValidationDataTriggered
    };


    /// <summary>
    /// Proves a hand-built B-B-conformant fact set (mandatory <c>SigningTime</c>/<c>SigningCertificateV2</c>
    /// present once each, nothing else) produces zero violations at B-B.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, rows XA-6.3-t05/t06.
    /// </summary>
    [TestMethod]
    public void MinimalConformantSignatureHasNoViolationsAtBB()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts();
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };

        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);

        Assert.IsEmpty(violations);
    }


    /// <summary>
    /// Proves a hand-built B-LTA-conformant fact set (mandatory rows present, the validation-data service
    /// satisfied via <c>TimeStampValidationData</c>) produces exactly one violation at B-LTA — the mandatory
    /// <c>ArchiveTimeStamp</c> row (XA-6.3-t44) this fixture deliberately omits.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t44.
    /// </summary>
    [TestMethod]
    public void MinimalFactsAtBLTAOnlyViolateTheOmittedArchiveTimeStampRow()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts(validationData: EmptyValidationData with { TimeStampValidationDataCount = 1 });
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLTA, Facts = facts };

        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);

        Assert.ContainsSingle(v => v is XAdESRowPresenceViolation { IsMissing: true } p && p.Row.RequirementId == "XA-6.3-t44", violations);
        Assert.HasCount(1, violations);
    }


    /// <summary>
    /// Proves the absence of the mandatory <c>SigningTime</c>/<c>SigningCertificateV2</c> rows (XA-6.3-t05/t06)
    /// each produces its own <see cref="XAdESRowPresenceViolation"/> with <see cref="XAdESRowPresenceViolation.IsMissing"/>
    /// <see langword="true"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, rows XA-6.3-t05/t06.
    /// </summary>
    [TestMethod]
    public void MissingMandatoryRowsEachProduceTheirOwnPresenceViolation()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts(
            signed: new Dictionary<string, int>(StringComparer.Ordinal),
            unsigned: new Dictionary<string, int>(StringComparer.Ordinal));
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };

        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);

        Assert.Contains(v => v is XAdESRowPresenceViolation { IsMissing: true } p && p.Row.RequirementId == "XA-6.3-t05", violations);
        Assert.Contains(v => v is XAdESRowPresenceViolation { IsMissing: true } p && p.Row.RequirementId == "XA-6.3-t06", violations);
    }


    /// <summary>
    /// Proves a row pinned <see cref="AdESPresence.ShallNotBePresent"/> at a level (<c>CompleteCertificateRefsV2</c>,
    /// XA-6.3-t27, at B-LT) produces a <see cref="XAdESRowPresenceViolation"/> with <see cref="XAdESRowPresenceViolation.IsMissing"/>
    /// <see langword="false"/> when the inventory reports at least one occurrence.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t27.
    /// </summary>
    [TestMethod]
    public void ForbiddenRowPresentAtALevelProducesAPresenceViolation()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts(unsigned: new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [XAdESBaselineLevelTable.SignatureTimeStamp.Name] = 1,
            [XAdESBaselineLevelTable.CompleteCertificateRefsV2.Name] = 1
        });
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, Facts = facts };

        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);

        Assert.Contains(v => v is XAdESRowPresenceViolation { IsMissing: false } p && p.Row.RequirementId == "XA-6.3-t27", violations);
    }


    /// <summary>
    /// Proves a row's own <see cref="AdESCardinality.ExactlyOne"/> bound (<c>SigningCertificateV2</c>,
    /// XA-6.3-t06) is violated when the inventory reports two occurrences — the presence check alone (item
    /// present) does not subsume the cardinality check.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t06.
    /// </summary>
    [TestMethod]
    public void CardinalityViolationWhenAnExactlyOneRowAppearsTwice()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts(signed: new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [XAdESBaselineLevelTable.SigningTime.Name] = 1,
            [XAdESBaselineLevelTable.SigningCertificateV2.Name] = 2
        });
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };

        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);

        Assert.Contains(v => v is XAdESRowCardinalityViolation c && c.Row.RequirementId == "XA-6.3-t06" && c.ActualCount == 2, violations);
    }


    /// <summary>
    /// The wrapping BLOCKER: proves <see cref="XAdESLevelRules.Check"/> reports a
    /// <see cref="XAdESQualifyingPropertiesBindingViolation"/> for each clause 4.3.1/4.4.1/4.4.2 binding pin
    /// <see cref="XAdESDiscoveryFact"/> reports failed, and reports none when every pin holds — the gate that
    /// makes the wrapping-attack facts (a document whose SignedProperties reference does not bind to the
    /// discovered container) unclassifiable, closing the gap where <see cref="XAdESLevelRules.Check"/> never
    /// read <see cref="XAdESQualifyingPropertiesFacts.Discovery"/> at all.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clauses 4.3.1 and 4.4.2.
    /// </summary>
    [TestMethod]
    public void QualifyingPropertiesBindingFailuresEachProduceTheirOwnViolation()
    {
        using XAdESQualifyingPropertiesFacts unbound = BuildFacts(discovery: new XAdESDiscoveryFact
        {
            HasQualifyingProperties = true,
            TargetResolvedToSignature = false,
            SignedPropertiesReferencePresent = true,
            SignedPropertiesReferenceResolvedToDiscoveredNode = false
        });
        IReadOnlyList<XAdESRuleViolation> unboundViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = unbound });

        Assert.Contains(v => v is XAdESQualifyingPropertiesBindingViolation b && b.Failure == XAdESQualifyingPropertiesBindingFailure.TargetNotBoundToSignature, unboundViolations);
        Assert.Contains(v => v is XAdESQualifyingPropertiesBindingViolation b && b.Failure == XAdESQualifyingPropertiesBindingFailure.SignedPropertiesReferenceNotBoundToDiscoveredNode, unboundViolations);
        Assert.DoesNotContain(v => v is XAdESQualifyingPropertiesBindingViolation b && b.Failure == XAdESQualifyingPropertiesBindingFailure.NoDirectlyIncorporatedQualifyingProperties, unboundViolations);
        Assert.DoesNotContain(v => v is XAdESQualifyingPropertiesBindingViolation b && b.Failure == XAdESQualifyingPropertiesBindingFailure.SignedPropertiesReferenceMissing, unboundViolations);

        using XAdESQualifyingPropertiesFacts none = BuildFacts(discovery: new XAdESDiscoveryFact
        {
            HasQualifyingProperties = false,
            TargetResolvedToSignature = false,
            SignedPropertiesReferencePresent = false,
            SignedPropertiesReferenceResolvedToDiscoveredNode = false
        });
        IReadOnlyList<XAdESRuleViolation> noneViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = none });

        Assert.Contains(v => v is XAdESQualifyingPropertiesBindingViolation b && b.Failure == XAdESQualifyingPropertiesBindingFailure.NoDirectlyIncorporatedQualifyingProperties, noneViolations);
        Assert.Contains(v => v is XAdESQualifyingPropertiesBindingViolation b && b.Failure == XAdESQualifyingPropertiesBindingFailure.SignedPropertiesReferenceMissing, noneViolations);

        using XAdESQualifyingPropertiesFacts bound = BuildFacts();
        IReadOnlyList<XAdESRuleViolation> boundViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = bound });
        Assert.DoesNotContain(v => v is XAdESQualifyingPropertiesBindingViolation, boundViolations);
    }


    /// <summary>
    /// Proves <see cref="XAdESLevelRules.Check"/> reports a
    /// <see cref="XAdESIndirectIncorporationViolation"/> when <see cref="XAdESDiscoveryFact.QualifyingPropertiesReferenceCount"/>
    /// is nonzero, and none when it is zero.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, XA-6.3-02.
    /// </summary>
    [TestMethod]
    public void IndirectIncorporationProducesAViolationOnlyWhenReferencesArePresent()
    {
        using XAdESQualifyingPropertiesFacts indirect = BuildFacts(discovery: new XAdESDiscoveryFact
        {
            HasQualifyingProperties = true,
            TargetResolvedToSignature = true,
            SignedPropertiesReferencePresent = true,
            SignedPropertiesReferenceResolvedToDiscoveredNode = true,
            QualifyingPropertiesReferenceCount = 2
        });
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = indirect });
        Assert.Contains(v => v is XAdESIndirectIncorporationViolation i && i.QualifyingPropertiesReferenceCount == 2, violations);

        using XAdESQualifyingPropertiesFacts direct = BuildFacts();
        Assert.DoesNotContain(v => v is XAdESIndirectIncorporationViolation, XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = direct }));
    }


    /// <summary>
    /// Clause 6.3's XA-6.3-04 and letter n): proves <see cref="XAdESLevelRules.Check"/> reports a
    /// <see cref="XAdESTimestampContainerNotRfc3161OnlyViolation"/> for a container whose
    /// <see cref="XAdESTimestampContainerMetadata.CarriesOnlyRfc3161Tokens"/> is <see langword="false"/>, and a
    /// <see cref="XAdESSignatureTimeStampCardinalityViolation"/> for a <c>SignatureTimeStamp</c> occurrence
    /// whose own <see cref="XAdESTimestampContainerMetadata.TokenCount"/> is not exactly one.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, XA-6.3-04, and Table 2, row XA-6.3-t24, letter n.
    /// </summary>
    [TestMethod]
    public void TimestampContainerChecksReportNonRfc3161ContentAndWrongCardinality()
    {
        var xmlTimeStampOnly = new XAdESTimestampContainerMetadata
        {
            Kind = XAdESTimestampContainerKind.SignatureTimeStamp,
            TokenCount = 0,
            HasInclude = false,
            IncludeCount = 0,
            CarriesOnlyRfc3161Tokens = false
        };
        using XAdESQualifyingPropertiesFacts xmlOnly = BuildFacts(timestampContainers: [xmlTimeStampOnly]);
        IReadOnlyList<XAdESRuleViolation> xmlOnlyViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BT, Facts = xmlOnly });
        Assert.Contains(v => v is XAdESTimestampContainerNotRfc3161OnlyViolation r && r.Kind == XAdESTimestampContainerKind.SignatureTimeStamp, xmlOnlyViolations);
        Assert.Contains(v => v is XAdESSignatureTimeStampCardinalityViolation c && c.TokenCount == 0, xmlOnlyViolations);

        var twoTokens = new XAdESTimestampContainerMetadata
        {
            Kind = XAdESTimestampContainerKind.SignatureTimeStamp,
            TokenCount = 2,
            HasInclude = false,
            IncludeCount = 0,
            CarriesOnlyRfc3161Tokens = true
        };
        using XAdESQualifyingPropertiesFacts doubled = BuildFacts(timestampContainers: [twoTokens]);
        IReadOnlyList<XAdESRuleViolation> doubledViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BT, Facts = doubled });
        Assert.DoesNotContain(v => v is XAdESTimestampContainerNotRfc3161OnlyViolation, doubledViolations);
        Assert.Contains(v => v is XAdESSignatureTimeStampCardinalityViolation c && c.TokenCount == 2, doubledViolations);

        var conformant = new XAdESTimestampContainerMetadata
        {
            Kind = XAdESTimestampContainerKind.SignatureTimeStamp,
            TokenCount = 1,
            HasInclude = false,
            IncludeCount = 0,
            CarriesOnlyRfc3161Tokens = true
        };
        using XAdESQualifyingPropertiesFacts single = BuildFacts(timestampContainers: [conformant]);
        IReadOnlyList<XAdESRuleViolation> singleViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BT, Facts = single });
        Assert.DoesNotContain(v => v is XAdESTimestampContainerNotRfc3161OnlyViolation, singleViolations);
        Assert.DoesNotContain(v => v is XAdESSignatureTimeStampCardinalityViolation, singleViolations);
    }


    /// <summary>
    /// Letter m): proves <see cref="XAdESLevelRules.Check"/> reports a
    /// <see cref="XAdESSignaturePolicyStoreLegalityViolation"/> when a <c>SignaturePolicyStore</c> occurrence
    /// is present while <see cref="XAdESQualifyingPropertiesFacts.SignaturePolicy"/> is either absent or the
    /// <c>SignaturePolicyImplied</c> arm, and none when the explicit <c>SignaturePolicyId</c> arm is present.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t23, letter m.
    /// </summary>
    [TestMethod]
    public async Task SignaturePolicyStoreLegalityFiresOnlyWithoutAnExplicitSignaturePolicyId()
    {
        using XAdESQualifyingPropertiesFacts absent = BuildFacts(validationData: EmptyValidationData with { SignaturePolicyStoreCount = 1 });
        Assert.Contains(v => v is XAdESSignaturePolicyStoreLegalityViolation, XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = absent }));

        using XAdESQualifyingPropertiesFacts implied = BuildFacts(
            validationData: EmptyValidationData with { SignaturePolicyStoreCount = 1 },
            signaturePolicy: new XAdESSignaturePolicyFact { IsImplied = true });
        Assert.Contains(v => v is XAdESSignaturePolicyStoreLegalityViolation, XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = implied }));

        //Ownership transfers into 'legal' below (XAdESQualifyingPropertiesFacts.Dispose cascades through
        //SignaturePolicy.Dispose), mirroring CheckSignaturePolicyDocumentDigestAsyncComparesAgainstTheSignedSigPolicyHash's
        //own inline-Hash-assignment precedent -- no separate 'using' on the digest itself.
        DigestValue hash = await ComputeAndCopyDigestAsync(new byte[] { 0x70, 0x71 }).ConfigureAwait(false);
        using XAdESQualifyingPropertiesFacts legal = BuildFacts(
            validationData: EmptyValidationData with { SignaturePolicyStoreCount = 1 },
            signaturePolicy: new XAdESSignaturePolicyFact { IsImplied = false, Id = new AdESObjectIdentifier("urn:oid:1.2.3.4", null), HashAlgorithm = AlgorithmIdentifier.Sha256, Hash = hash });
        Assert.DoesNotContain(v => v is XAdESSignaturePolicyStoreLegalityViolation, XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = legal }));
    }


    /// <summary>
    /// Letter k): proves <see cref="XAdESLevelRules.Check"/> reports a
    /// <see cref="XAdESDataObjectFormatCoverageViolation"/> when <see cref="XAdESQualifyingPropertiesFacts.IsDataObjectFormatCoverageSatisfied"/>
    /// is <see langword="false"/>, and none when it is <see langword="true"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t08, letter k.
    /// </summary>
    [TestMethod]
    public void DataObjectFormatCoverageViolationTracksTheFactDirectly()
    {
        using XAdESQualifyingPropertiesFacts uncovered = BuildFacts(isDataObjectFormatCoverageSatisfied: false);
        Assert.Contains(v => v is XAdESDataObjectFormatCoverageViolation, XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = uncovered }));

        using XAdESQualifyingPropertiesFacts covered = BuildFacts();
        Assert.DoesNotContain(v => v is XAdESDataObjectFormatCoverageViolation, XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = covered }));
    }


    /// <summary>
    /// Letter x): proves the validation-data-for-time-stamps service (XA-6.3-t40) is measured on
    /// CONTENT, not container presence — <c>TimeStampValidationDataCount</c> nonzero with
    /// <see cref="XAdESQualifyingPropertiesFacts.ValidationDataForTimestampsHasContent"/> <see langword="false"/>
    /// (an empty container) still violates the service at B-LT.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, XA-6.3-t40, letter x, and clause 6.1 c).
    /// </summary>
    [TestMethod]
    public void EmptyValidationDataContainerDoesNotSatisfyTheServiceDespiteBeingPresent()
    {
        using XAdESQualifyingPropertiesFacts empty = BuildFacts(
            validationData: EmptyValidationData with { TimeStampValidationDataCount = 1 },
            validationDataForTimestampsHasContent: false);
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, Facts = empty });

        Assert.Contains(v => v is XAdESValidationDataServiceViolation, violations);
    }


    /// <summary>
    /// Proves <see cref="XAdESLevelRules.Check"/> reports a <see cref="XAdESUnknownQualifyingPropertyPresentViolation"/>
    /// for a <see cref="XAdESQualifyingPropertiesFacts.SignedPropertyOccurrenceCounts"/>/<see cref="XAdESQualifyingPropertiesFacts.UnsignedPropertyOccurrenceCounts"/>
    /// dictionary key that names no <see cref="XAdESBaselineLevelTable"/> row, rather than silently ignoring it.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 (Table 2's own closed row vocabulary).
    /// </summary>
    [TestMethod]
    public void UnrecognizedOccurrenceDictionaryKeyProducesAViolation()
    {
        using XAdESQualifyingPropertiesFacts signedKey = BuildFacts(signed: new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [XAdESBaselineLevelTable.SigningTime.Name] = 1,
            [XAdESBaselineLevelTable.SigningCertificateV2.Name] = 1,
            ["NotARealRow"] = 1
        });
        Assert.Contains(v => v is XAdESUnknownQualifyingPropertyPresentViolation u && u.Name == "NotARealRow", XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = signedKey }));

        using XAdESQualifyingPropertiesFacts unsignedKey = BuildFacts(unsigned: new Dictionary<string, int>(StringComparer.Ordinal)
        {
            [XAdESBaselineLevelTable.SignatureTimeStamp.Name] = 1,
            ["AlsoNotARealRow"] = 1
        });
        Assert.Contains(v => v is XAdESUnknownQualifyingPropertyPresentViolation u && u.Name == "AlsoNotARealRow", XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = unsignedKey }));
    }


    /// <summary>
    /// Proves letters x)/y)'s satisfied-by-any-SPO logic: the validation-data service (XA-6.3-t40) is satisfied
    /// at B-LT by <c>TimeStampValidationData</c> alone, by <c>AnyValidationData</c> alone, and by the
    /// caller-supplied embedded-in-token fact alone — three independent ways to satisfy the SAME service, never
    /// a conjunction.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t40, letters x/y.
    /// </summary>
    [TestMethod]
    public void ServiceRowIsSatisfiedByAnySingleServiceProvisionOption()
    {
        AssertServiceSatisfied(EmptyValidationData with { TimeStampValidationDataCount = 1 }, embeddedInToken: false);
        AssertServiceSatisfied(EmptyValidationData with { AnyValidationDataCount = 1 }, embeddedInToken: false);
        AssertServiceSatisfied(EmptyValidationData, embeddedInToken: true);

        static void AssertServiceSatisfied(XAdESValidationDataCounts validationData, bool embeddedInToken)
        {
            using XAdESQualifyingPropertiesFacts facts = BuildFacts(validationData: validationData);
            var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, Facts = facts, AnyTimestampTokenCarriesEmbeddedValidationMaterial = embeddedInToken };

            IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);

            Assert.DoesNotContain(v => v is XAdESValidationDataServiceViolation, violations);
        }
    }


    /// <summary>
    /// Proves the validation-data service (XA-6.3-t40) is VIOLATED at B-LT when none of its three
    /// service-provision options is satisfied, and NOT evaluated at all at B-B/B-T (the "*" soft-negative is
    /// never enforced on read).
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t40, letters x/y.
    /// </summary>
    [TestMethod]
    public void ServiceRowIsViolatedAtBLTWhenUnsatisfiedButNotEvaluatedAtBBOrBT()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts();

        IReadOnlyList<XAdESRuleViolation> atBLT = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, Facts = facts });
        Assert.Contains(v => v is XAdESValidationDataServiceViolation, atBLT);

        IReadOnlyList<XAdESRuleViolation> atBB = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts });
        Assert.DoesNotContain(v => v is XAdESValidationDataServiceViolation, atBB);
    }


    /// <summary>
    /// Proves this library's own "unclassifiable as baseline" posture (<see cref="XAdESUnknownQualifyingPropertyPresentViolation.RequirementId"/>'s own remarks): an unrecognized <c>##other</c> unsigned property observation becomes a <see cref="XAdESUnknownQualifyingPropertyPresentViolation"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 4.3.6.
    /// </summary>
    [TestMethod]
    public void UnknownPropertyObservationBecomesAViolation()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts(unknownPropertyObservations: ["ForeignFuturePropertyXyz"]);
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };

        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);

        Assert.Contains(v => v is XAdESUnknownQualifyingPropertyPresentViolation u && u.Name == "ForeignFuturePropertyXyz", violations);
    }


    /// <summary>
    /// Proves the deprecated-property arm on the engine side: a (hand-simulated) deprecated-property observation becomes a <see cref="XAdESDeprecatedQualifyingPropertyPresentViolation"/>. Defense-in-depth only — a real parse never populates <see
    /// cref="XAdESQualifyingPropertiesFacts.DeprecatedPropertyObservations"/>, since the reader refuses deprecated content at read time. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2 (the eight always-<c>ExactlyZero</c> deprecated rows).
    /// </summary>
    [TestMethod]
    public void DeprecatedPropertyObservationBecomesAViolation()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts(deprecatedPropertyObservations: ["RenewedDigests"]);
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };

        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);

        Assert.Contains(v => v is XAdESDeprecatedQualifyingPropertyPresentViolation d && d.Name == "RenewedDigests", violations);
    }


    /// <summary>
    /// Proves letters r)/s)/w)'s attribute-material gate: <c>AttrAuthoritiesCertValues</c> (letter r) present
    /// with no attribute certificate or signed assertion incorporated is a
    /// <see cref="XAdESAttributeMaterialGateViolation"/>; the SAME fact set with a certified attribute present
    /// on <c>SignerRoleV2</c> is not.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t29, letter r.
    /// </summary>
    [TestMethod]
    public void AttributeMaterialGateFiresOnlyWithoutAttributeMaterial()
    {
        using XAdESQualifyingPropertiesFacts gated = BuildFacts(validationData: EmptyValidationData with { AttrAuthoritiesCertValuesCount = 1 });
        IReadOnlyList<XAdESRuleViolation> gatedViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = gated });
        Assert.Contains(v => v is XAdESAttributeMaterialGateViolation g && g.Row.RequirementId == "XA-6.3-t29", gatedViolations);

        var certified = new AdESSignerAttributes(certified: [new AdESX509AttributeCertificate(new AdESPkiObject { Val = ReadOnlyMemory<byte>.Empty })]);
        using XAdESQualifyingPropertiesFacts ungated = BuildFacts(validationData: EmptyValidationData with { AttrAuthoritiesCertValuesCount = 1 }, signerRole: certified);
        IReadOnlyList<XAdESRuleViolation> ungatedViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = ungated });
        Assert.DoesNotContain(v => v is XAdESAttributeMaterialGateViolation, ungatedViolations);
    }


    /// <summary>
    /// Proves the gate reaches all four attribute-shaped rows letters r)/s)/w) name —
    /// <c>AttrAuthoritiesCertValues</c> (r, XA-6.3-t29), <c>AttributeCertificateRefsV2</c> (s, XA-6.3-t30),
    /// <c>AttributeRevocationRefs</c> (s, XA-6.3-t35), <c>AttributeRevocationValues</c> (w, XA-6.3-t34) — each
    /// present with no attribute material produces its own <see cref="XAdESAttributeMaterialGateViolation"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, rows XA-6.3-t29/t30/t34/t35, letters r/s/w.
    /// </summary>
    [TestMethod]
    public void AttributeMaterialGateReachesAllFourGatedRows()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts(validationData: EmptyValidationData with
        {
            AttrAuthoritiesCertValuesCount = 1,
            AttributeCertificateRefsV2Count = 1,
            AttributeRevocationRefsCount = 1,
            AttributeRevocationValuesCount = 1
        });
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts });

        Assert.Contains(v => v is XAdESAttributeMaterialGateViolation g && g.Row.RequirementId == "XA-6.3-t29", violations);
        Assert.Contains(v => v is XAdESAttributeMaterialGateViolation g && g.Row.RequirementId == "XA-6.3-t30", violations);
        Assert.Contains(v => v is XAdESAttributeMaterialGateViolation g && g.Row.RequirementId == "XA-6.3-t35", violations);
        Assert.Contains(v => v is XAdESAttributeMaterialGateViolation g && g.Row.RequirementId == "XA-6.3-t34", violations);
    }


    /// <summary>
    /// Proves <see cref="XAdESLevelRules.EnsureConformant"/> throws naming the first violated requirement, and
    /// does not throw over a conformant fact set.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3.
    /// </summary>
    [TestMethod]
    public void EnsureConformantThrowsNamingTheFirstViolationAndOtherwiseDoesNotThrow()
    {
        using XAdESQualifyingPropertiesFacts incomplete = BuildFacts(
            signed: new Dictionary<string, int>(StringComparer.Ordinal),
            unsigned: new Dictionary<string, int>(StringComparer.Ordinal));
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => XAdESLevelRules.EnsureConformant(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = incomplete }));
        Assert.Contains("XA-6.3-t05", exception.Message, StringComparison.Ordinal);

        using XAdESQualifyingPropertiesFacts conformant = BuildFacts();
        XAdESLevelRules.EnsureConformant(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = conformant });
    }


    /// <summary>
    /// The rewritten negative twin of the pre-reconciliation decoupling proof: a bare <see
    /// cref="SignatureCryptographicVerification"/> carrying only <see
    /// cref="SignatureCryptographicOutcome.Verified"/> and no carried signing certificate — the exact recipe
    /// that, before <see cref="XAdESLevelRules.Promote"/> required a gate-produced <see
    /// cref="BoundProvenance"/>, minted a <see cref="Verified{T}"/> whose <see cref="KeyId"/> was an arbitrary
    /// caller-supplied label never checked against anything — cannot even reach <see
    /// cref="XAdESLevelRules.Promote"/> now: <see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>, the
    /// ONLY producer able to satisfy <see cref="XAdESLevelRules.Promote"/>'s required parameter, refuses a
    /// cryptographic outcome that carries no signing certificate, so there is no provenance to pass it.
    /// </summary>
    [TestMethod]
    public async Task BareCryptographicOutcomeWithNoCarriedCertificateCannotProduceAProvenanceToPromoteWith()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts();
        var bareOutcome = new SignatureCryptographicVerification { Outcome = SignatureCryptographicOutcome.Verified };

        BoundProvenance? binding = await BoundProvenance.TryBindByCertificateDigestAsync(
            [], bareOutcome, facts, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(binding, "A cryptographic outcome carrying no signing certificate must refuse to bind, regardless of Table 2 conformance -- there is no gate-produced BoundProvenance left to mint the old decoupled recipe with.");
    }


    /// <summary>
    /// A <see cref="BoundProvenance"/> established purely to satisfy <see cref="XAdESLevelRules.Promote"/>'s
    /// required parameter when a test is proving a DIFFERENT gating axis (the cryptographic outcome, or Table 2
    /// conformance) still refuses minting independently of identity binding — witnesses <paramref name="subject"/>
    /// so <see cref="Verified{T}.TryCreateBound"/>'s own witness check never itself becomes the reason a test
    /// refuses. Never used where a genuine certificate-digest binding is the point.
    /// </summary>
    private static BoundProvenance WitnessOnlyBinding(object subject) =>
        BoundProvenance.TryBindByResolvedMethod(new KeyId("witness-only"), "witness-only", VerificationRelationship.SignerCertificate, subject)!;


    /// <summary>
    /// Proves <see cref="XAdESLevelRules.Promote"/> refuses to mint a <see cref="Verified{T}"/> when the cryptographic-verification outcome is anything other than <see
    /// cref="SignatureCryptographicOutcome.Verified"/> — Table 2 conformance alone (a fully-conformant fact set here) never substitutes for a checked <c>ds:SignatureValue</c>, even given a
    /// validly-witnessed <see cref="BoundProvenance"/>: Promote's own outcome gating stays independent of the gate's identity gating. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">ETSI EN 319 102-1 V1.4.1</see> clause 5.2.7.4 (the cryptographic-verification half) and <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3 (the Table 2 conformance half).
    /// </summary>
    [TestMethod]
    public void PromoteReturnsNullWhenCryptographicOutcomeIsNotVerified()
    {
        using XAdESQualifyingPropertiesFacts facts = BuildFacts();
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };
        BoundProvenance binding = WitnessOnlyBinding(facts);

        SignatureCryptographicOutcome[] unverifiedOutcomes =
        [
            SignatureCryptographicOutcome.NotVerified,
            SignatureCryptographicOutcome.HashFailure,
            SignatureCryptographicOutcome.SignatureValueFailure,
            SignatureCryptographicOutcome.SignedDataNotFound
        ];

        foreach(SignatureCryptographicOutcome outcome in unverifiedOutcomes)
        {
            Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(
                context, new SignatureCryptographicVerification { Outcome = outcome }, binding);
            Assert.IsFalse(promoted.HasValue, $"Outcome {outcome} must not promote.");
        }
    }


    /// <summary>
    /// Proves <see cref="XAdESLevelRules.Promote"/> refuses to mint a <see cref="Verified{T}"/> when
    /// <see cref="XAdESLevelRules.Check"/> reports at least one violation, even though the cryptographic
    /// verification itself concluded <see cref="SignatureCryptographicOutcome.Verified"/> and a validly-witnessed
    /// <see cref="BoundProvenance"/> is supplied — a cryptographically sound, identity-bound signature over a
    /// Table-2-non-conformant qualifying-properties set is not proof of BASELINE conformance.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">ETSI EN 319 102-1 V1.4.1</see>
    /// clause 5.2.7.4 (the cryptographic-verification half) and <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see>
    /// clause 6.3 (the Table 2 conformance half).
    /// </summary>
    [TestMethod]
    public void PromoteReturnsNullWhenLevelRulesAreViolatedEvenIfCryptographicallyVerified()
    {
        using XAdESQualifyingPropertiesFacts incomplete = BuildFacts(
            signed: new Dictionary<string, int>(StringComparer.Ordinal),
            unsigned: new Dictionary<string, int>(StringComparer.Ordinal));
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = incomplete };
        var verifiedCrypto = new SignatureCryptographicVerification { Outcome = SignatureCryptographicOutcome.Verified };
        BoundProvenance binding = WitnessOnlyBinding(incomplete);

        Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(context, verifiedCrypto, binding);

        Assert.IsFalse(promoted.HasValue);
    }


    /// <summary>
    /// Builds a REAL signer-reference/certificate pair from a caller-supplied real certificate's own DER
    /// encoding: a <see cref="XAdESSigningCertificateDigestFact"/> committing the certificate's own SHA-256
    /// digest as a signer reference, plus a <see cref="PkiCertificateMemory"/> carrier of the SAME certificate
    /// bytes — the two halves <see cref="BoundProvenance.TryBindByCertificateDigestAsync"/> compares.
    /// </summary>
    private static async Task<(PkiCertificateMemory Certificate, XAdESSigningCertificateDigestFact SignerReference)> BuildRealSignerMaterialAsync(
        byte[] certificateDer, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            certificateDer, 32, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        IMemoryOwner<byte> digestOwner = pool.Rent(digest.Length);
        digest.AsReadOnlySpan().CopyTo(digestOwner.Memory.Span);

        var signerReference = new XAdESSigningCertificateDigestFact
        {
            Reference = new SigningCertificateReference
            {
                DigestAlgorithm = AlgorithmIdentifier.Sha256,
                CertificateDigest = new DigestValue(digestOwner, CryptoTags.Sha256Digest),
                IsSignerReference = true
            }
        };

        IMemoryOwner<byte> certificateOwner = pool.Rent(certificateDer.Length);
        certificateDer.CopyTo(certificateOwner.Memory.Span);
        var certificate = new PkiCertificateMemory(certificateOwner, PkiCertificateTags.X509Certificate);

        return (certificate, signerReference);
    }


    /// <summary>
    /// The contract's single most load-bearing forgery proof (per-site table): a signer reference
    /// committing certificate X's own digest, paired with a cryptographic-verification outcome that carries
    /// certificate Y — a DIFFERENT, real certificate the signature never committed to. <see
    /// cref="BoundProvenance.TryBindByCertificateDigestAsync"/> recomputes Y's digest, compares it against the
    /// reference's own stored digest(X), and refuses: no <see cref="BoundProvenance"/> is produced, so there is
    /// nothing to satisfy <see cref="XAdESLevelRules.Promote"/>'s required parameter. Built from two REAL
    /// certificates minted by the shared test PKI (<see cref="X509ChainTestRing"/>), never hand-mocked digests.
    /// </summary>
    [TestMethod]
    public async Task GateRefusesBindingWhenTheCryptographicOutcomeCarriesADifferentCertificateThanTheSignedReferenceCommitsTo()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
        using X509ChainTestRingNode certificateX = X509ChainTestRing.CreateLeaf(root, "x.example.com", timeProvider);
        using X509ChainTestRingNode certificateY = X509ChainTestRing.CreateLeaf(root, "y.example.com", timeProvider);

        (PkiCertificateMemory carrierX, XAdESSigningCertificateDigestFact signerReferenceToX) =
            await BuildRealSignerMaterialAsync(certificateX.Certificate.RawData, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using(carrierX)
        using(XAdESQualifyingPropertiesFacts facts = BuildFacts(signingCertificateDigests: [signerReferenceToX]))
        {
            IMemoryOwner<byte> certificateYOwner = pool.Rent(certificateY.Certificate.RawData.Length);
            certificateY.Certificate.RawData.CopyTo(certificateYOwner.Memory.Span);
            using var carrierY = new PkiCertificateMemory(certificateYOwner, PkiCertificateTags.X509Certificate);

            var forgedOutcome = new SignatureCryptographicVerification { Outcome = SignatureCryptographicOutcome.Verified, SigningCertificate = carrierY };

            BoundProvenance? binding = await BoundProvenance.TryBindByCertificateDigestAsync(
                [signerReferenceToX.Reference], forgedOutcome, facts, pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNull(binding, "A cryptographic outcome carrying certificate Y must refuse to bind against a signer reference committing certificate X's own digest.");
        }
    }


    /// <summary>
    /// The positive counterpart of the forgery proof: a signer reference whose committed digest matches the SAME
    /// certificate the cryptographic-verification outcome carries — the gate binds, naming <see
    /// cref="ResolutionSource.CertificateDigest"/>/<see cref="VerificationRelationship.SignerCertificate"/>, and
    /// <see cref="XAdESLevelRules.Promote"/> mints a <see cref="Verified{T}"/> whose <see
    /// cref="Verified{T}.IsIdentityBound"/> is <see langword="true"/>. The witness half: the SAME <see
    /// cref="BoundProvenance"/>, established for THIS facts instance, refuses to mint over a DIFFERENT <see
    /// cref="XAdESQualifyingPropertiesFacts"/> instance via <see cref="Verified{T}.TryCreateBound"/> — a
    /// legitimate binding for one signature can never be paired with another signature's facts. Built from a REAL
    /// certificate minted by the shared test PKI (<see cref="X509ChainTestRing"/>).
    /// </summary>
    [TestMethod]
    public async Task GateBindsAndPromoteMintsAnIdentityBoundInstanceWhoseBindingRefusesADifferentFactsInstance()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
        using X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, "signer.example.com", timeProvider);

        (PkiCertificateMemory carrier, XAdESSigningCertificateDigestFact signerReference) =
            await BuildRealSignerMaterialAsync(signer.Certificate.RawData, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using(carrier)
        using(XAdESQualifyingPropertiesFacts facts = BuildFacts(signingCertificateDigests: [signerReference]))
        {
            var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };
            var verifiedCrypto = new SignatureCryptographicVerification { Outcome = SignatureCryptographicOutcome.Verified, SigningCertificate = carrier };

            BoundProvenance? binding = await BoundProvenance.TryBindByCertificateDigestAsync(
                [signerReference.Reference], verifiedCrypto, facts, pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsNotNull(binding, "A signer reference whose committed digest matches the carried certificate must bind.");
            Assert.AreEqual(ResolutionSource.CertificateDigest, binding!.Source);
            Assert.AreEqual(VerificationRelationship.SignerCertificate, binding.Relationship);

            Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(context, verifiedCrypto, binding);
            Assert.IsNotNull(promoted, "Promote must mint when the gate binds and Table 2/crypto both hold.");
            Assert.IsTrue(promoted!.Value.IsIdentityBound, "The minted Verified<T> must be identity-bound, not merely asserted.");
            Assert.AreSame(binding, promoted.Value.Provenance);

            using XAdESQualifyingPropertiesFacts differentFacts = BuildFacts();
            Verified<XAdESQualifyingPropertiesFacts>? witnessMismatch = Verified<XAdESQualifyingPropertiesFacts>.TryCreateBound(differentFacts, binding);
            Assert.IsNull(witnessMismatch, "A BoundProvenance established for one facts instance must refuse to mint over a different instance.");
        }
    }


    private static PkiCertificateMemory Certificate(byte value, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(1);
        owner.Memory.Span[0] = value;

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// Proves letter q): two byte-identical entries in <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificates"/>
    /// produce a <see cref="XAdESCertificateValueDuplicationObservation"/> (an advisory <see cref="XAdESRuleObservation"/>,
    /// never a <see cref="XAdESRuleViolation"/>); pairwise-distinct entries produce none.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t25, letter q.
    /// </summary>
    [TestMethod]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each Certificate(...) rental's ownership transfers into the BuildFacts(...) record's own EmbeddedCertificates/EmbeddedCertificateRevocationLists/EmbeddedOcspResponses list, disposed by that record's own using block below -- Roslyn's dataflow does not follow ownership transfer through a collection-expression argument into a record's Dispose().")]
    public void DuplicateCertificateValuesProduceAnAdvisoryObservation()
    {
        using(XAdESQualifyingPropertiesFacts duplicated = BuildFacts(embeddedCertificates:
            [Certificate(0x01, PkiCertificateTags.X509Certificate), Certificate(0x01, PkiCertificateTags.X509Certificate)]))
        {
            Assert.ContainsSingle(o => o is XAdESCertificateValueDuplicationObservation, XAdESLevelRules.CheckValidationDataDuplication(duplicated));
        }

        using(XAdESQualifyingPropertiesFacts distinct = BuildFacts(embeddedCertificates:
            [Certificate(0x01, PkiCertificateTags.X509Certificate), Certificate(0x02, PkiCertificateTags.X509Certificate)]))
        {
            Assert.IsEmpty(XAdESLevelRules.CheckValidationDataDuplication(distinct));
        }
    }


    /// <summary>
    /// Proves letter v): two byte-identical entries in <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificateRevocationLists"/>
    /// (CRLs) and, separately, in <see cref="XAdESQualifyingPropertiesFacts.EmbeddedOcspResponses"/> (OCSP
    /// responses) each produce a <see cref="XAdESRevocationValueDuplicationObservation"/> with the matching
    /// <see cref="XAdESRevocationValueDuplicationObservation.IsCrl"/> flag.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t32, letter v.
    /// </summary>
    [TestMethod]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each Certificate(...) rental's ownership transfers into the BuildFacts(...) record's own EmbeddedCertificates/EmbeddedCertificateRevocationLists/EmbeddedOcspResponses list, disposed by that record's own using block below -- Roslyn's dataflow does not follow ownership transfer through a collection-expression argument into a record's Dispose().")]
    public void DuplicateRevocationValuesProduceAnAdvisoryObservationTaggedByKind()
    {
        using(XAdESQualifyingPropertiesFacts crlDuplicated = BuildFacts(embeddedCrls:
            [Certificate(0x03, PkiCertificateTags.X509Crl), Certificate(0x03, PkiCertificateTags.X509Crl)]))
        {
            Assert.ContainsSingle(o => o is XAdESRevocationValueDuplicationObservation { IsCrl: true }, XAdESLevelRules.CheckValidationDataDuplication(crlDuplicated));
        }

        using(XAdESQualifyingPropertiesFacts ocspDuplicated = BuildFacts(embeddedOcsp:
            [Certificate(0x04, PkiCertificateTags.OcspResponse), Certificate(0x04, PkiCertificateTags.OcspResponse)]))
        {
            Assert.ContainsSingle(o => o is XAdESRevocationValueDuplicationObservation { IsCrl: false }, XAdESLevelRules.CheckValidationDataDuplication(ocspDuplicated));
        }
    }


    /// <summary>
    /// Proves letter a)'s binding half (NOTE 7): the candidate certificate's own computed SHA-256 digest
    /// matches the <c>SigningCertificateV2</c> signer reference's stored digest, and a mismatched candidate
    /// (or a fact set carrying no signer reference at all) is a <see cref="XAdESSigningCertificateBindingViolation"/>.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t01, letter a, NOTE 7.
    /// </summary>
    [TestMethod]
    public async Task CheckSigningCertificateBindingAsyncMatchesTheSignerReferenceDigest()
    {
        byte[] candidate = [0x10, 0x20, 0x30];
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            candidate, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        IMemoryOwner<byte> digestOwner = BaseMemoryPool.Shared.Rent(digest.Length);
        digest.AsReadOnlySpan().CopyTo(digestOwner.Memory.Span);

        var signerReference = new XAdESSigningCertificateDigestFact
        {
            Reference = new SigningCertificateReference
            {
                DigestAlgorithm = AlgorithmIdentifier.Sha256,
                CertificateDigest = new DigestValue(digestOwner, CryptoTags.Sha256Digest),
                IsSignerReference = true
            }
        };
        using(signerReference)
        {
            IReadOnlyList<XAdESRuleViolation> matched = await XAdESLevelRules.CheckSigningCertificateBindingAsync(
                [signerReference], candidate, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsEmpty(matched);

            byte[] wrongCandidate = [0xFF, 0xFF, 0xFF];
            IReadOnlyList<XAdESRuleViolation> mismatched = await XAdESLevelRules.CheckSigningCertificateBindingAsync(
                [signerReference], wrongCandidate, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.ContainsSingle(v => v is XAdESSigningCertificateBindingViolation, mismatched);
        }

        IReadOnlyList<XAdESRuleViolation> noSignerReference = await XAdESLevelRules.CheckSigningCertificateBindingAsync(
            [], candidate, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.ContainsSingle(v => v is XAdESSigningCertificateBindingViolation, noSignerReference);
    }


    /// <summary>
    /// Proves letter o)'s expiry half: a <c>SignatureTimeStamp</c> token generated within the signing
    /// certificate's validity window produces no violation; one generated after <c>notAfter</c> does.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t24, letter o.
    /// </summary>
    [TestMethod]
    public void SignatureTimeStampWithinValidityProducesNoViolationButAfterExpiryDoes()
    {
        var validity = new CertificateValidityPeriod
        {
            NotBefore = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
            NotAfter = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero)
        };

        IReadOnlyList<XAdESRuleViolation> withinValidity = XAdESLevelRules.CheckSignatureTimeStampsWithinSigningCertificateValidity(
            [new DateTimeOffset(2024, 6, 1, 0, 0, 0, TimeSpan.Zero)], validity);
        Assert.IsEmpty(withinValidity);

        IReadOnlyList<XAdESRuleViolation> afterExpiry = XAdESLevelRules.CheckSignatureTimeStampsWithinSigningCertificateValidity(
            [new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero)], validity);
        Assert.ContainsSingle(v => v is XAdESSignatureTimeStampCertificateValidityViolation, afterExpiry);
    }


    /// <summary>
    /// Proves letter o)'s revocation half fires only when the caller supplies a known revocation instant, and a
    /// token generated before that instant is unaffected.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, row XA-6.3-t24, letter o.
    /// </summary>
    [TestMethod]
    public void SignatureTimeStampAtOrAfterKnownRevocationInstantIsAViolationOnlyWhenSupplied()
    {
        var validity = new CertificateValidityPeriod
        {
            NotBefore = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
            NotAfter = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero)
        };
        var revokedAt = new DateTimeOffset(2024, 6, 1, 0, 0, 0, TimeSpan.Zero);

        IReadOnlyList<XAdESRuleViolation> revokedUnknown = XAdESLevelRules.CheckSignatureTimeStampsWithinSigningCertificateValidity(
            [new DateTimeOffset(2024, 7, 1, 0, 0, 0, TimeSpan.Zero)], validity);
        Assert.IsEmpty(revokedUnknown);

        IReadOnlyList<XAdESRuleViolation> afterRevocation = XAdESLevelRules.CheckSignatureTimeStampsWithinSigningCertificateValidity(
            [new DateTimeOffset(2024, 7, 1, 0, 0, 0, TimeSpan.Zero)], validity, revokedAt);
        Assert.ContainsSingle(v => v is XAdESSignatureTimeStampCertificateRevokedViolation, afterRevocation);

        IReadOnlyList<XAdESRuleViolation> beforeRevocation = XAdESLevelRules.CheckSignatureTimeStampsWithinSigningCertificateValidity(
            [new DateTimeOffset(2024, 3, 1, 0, 0, 0, TimeSpan.Zero)], validity, revokedAt);
        Assert.DoesNotContain(v => v is XAdESSignatureTimeStampCertificateRevokedViolation, beforeRevocation);
    }


    private async Task<DigestValue> ComputeAndCopyDigestAsync(ReadOnlyMemory<byte> content)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            content, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(digest.Length);
        digest.AsReadOnlySpan().CopyTo(owner.Memory.Span);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    private static PkiCertificateMemory CopyBytes(ReadOnlySpan<byte> bytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// Proves Annex A.1.1/A.1.2's own closing conditional-<c>shall</c> paragraph, both halves wired together: a
    /// <c>CompleteCertificateRefsV2</c> digest resolving to a byte-identical candidate in
    /// <see cref="XAdESQualifyingPropertiesFacts.EmbeddedCertificates"/> produces no violation; a non-resolving
    /// one produces a <see cref="XAdESReferencesValidationDataConsistencyViolation"/>; the SAME non-resolving
    /// digest produces NO violation when <see cref="XAdESQualifyingPropertiesFacts.CertificateValidationDataTriggered"/>
    /// is <see langword="false"/> — the antecedent gate.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1.
    /// </summary>
    [TestMethod]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each fact's/candidate's ownership transfers into the BuildFacts(...) record's own CompleteCertificateRefs/EmbeddedCertificates list, disposed by that record's own using block below.")]
    public async Task CheckReferencesResolveToValidationDataAsyncGatesOnTheAntecedentAndResolvesByDigest()
    {
        byte[] candidateCertBytes = [0x10, 0x20, 0x30];
        var matchingRef = new XAdESCertificateReferenceDigestFact { DigestAlgorithm = AlgorithmIdentifier.Sha256, Digest = await ComputeAndCopyDigestAsync(candidateCertBytes).ConfigureAwait(false) };
        PkiCertificateMemory matchingCandidate = CopyBytes(candidateCertBytes, PkiCertificateTags.X509Certificate);
        using(XAdESQualifyingPropertiesFacts resolved = BuildFacts(completeCertificateRefs: [matchingRef], embeddedCertificates: [matchingCandidate], certificateValidationDataTriggered: true))
        {
            IReadOnlyList<XAdESRuleViolation> violations = await XAdESLevelRules.CheckReferencesResolveToValidationDataAsync(resolved, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsEmpty(violations);
        }

        var unmatchedRef = new XAdESCertificateReferenceDigestFact { DigestAlgorithm = AlgorithmIdentifier.Sha256, Digest = await ComputeAndCopyDigestAsync(new byte[] { 0xFF, 0xFF, 0xFF }).ConfigureAwait(false) };
        PkiCertificateMemory otherCandidate = CopyBytes(candidateCertBytes, PkiCertificateTags.X509Certificate);
        using(XAdESQualifyingPropertiesFacts unresolved = BuildFacts(completeCertificateRefs: [unmatchedRef], embeddedCertificates: [otherCandidate], certificateValidationDataTriggered: true))
        {
            IReadOnlyList<XAdESRuleViolation> violations = await XAdESLevelRules.CheckReferencesResolveToValidationDataAsync(unresolved, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.ContainsSingle(v => v is XAdESReferencesValidationDataConsistencyViolation c
                && c.Surface == XAdESRefsFamilyDigestSurface.CompleteCertificateRefs && c.MaterialKind == XAdESReferenceMaterialKind.Certificate, violations);
        }

        var untriggeredRef = new XAdESCertificateReferenceDigestFact { DigestAlgorithm = AlgorithmIdentifier.Sha256, Digest = await ComputeAndCopyDigestAsync(new byte[] { 0xFF, 0xFF, 0xFF }).ConfigureAwait(false) };
        using(XAdESQualifyingPropertiesFacts untriggered = BuildFacts(completeCertificateRefs: [untriggeredRef], certificateValidationDataTriggered: false))
        {
            IReadOnlyList<XAdESRuleViolation> violations = await XAdESLevelRules.CheckReferencesResolveToValidationDataAsync(untriggered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsEmpty(violations);
        }
    }


    /// <summary>
    /// Proves the revocation family of the same closing conditional-<c>shall</c>: a resolving <c>CRLRef</c>
    /// produces no violation; an <c>OCSPRef</c> without a <c>DigestAlgAndValue</c> (A.1.2's own "should be
    /// included") is silently skipped — "cannot check, so no violation" — while one WITH a non-resolving digest
    /// produces a <see cref="XAdESReferencesValidationDataConsistencyViolation"/> citing
    /// <see cref="XAdESReferenceMaterialKind.Ocsp"/> on the <c>AttributeRevocationRefs</c> surface.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2, A.1.4.
    /// </summary>
    [TestMethod]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each fact's/candidate's ownership transfers into the BuildFacts(...) record's own refs/embedded lists, disposed by that record's own using block below.")]
    public async Task CheckReferencesResolveToValidationDataAsyncCoversCrlAndSkipsUndigestedOcspRefs()
    {
        byte[] candidateCrlBytes = [0x40, 0x41, 0x42];
        var resolvingCrlRef = new XAdESCrlReferenceFact { DigestAlgorithm = AlgorithmIdentifier.Sha256, Digest = await ComputeAndCopyDigestAsync(candidateCrlBytes).ConfigureAwait(false) };
        PkiCertificateMemory crlCandidate = CopyBytes(candidateCrlBytes, PkiCertificateTags.X509Crl);
        var undigestedOcspRef = new XAdESOcspReferenceFact { HasDigestAlgAndValue = false, ResponderKind = XAdESOcspResponderIdKind.ByName, ProducedAtLexical = "2024-01-01T00:00:00Z" };
        var unresolvingOcspRef = new XAdESOcspReferenceFact
        {
            HasDigestAlgAndValue = true,
            DigestAlgorithm = AlgorithmIdentifier.Sha256,
            Digest = await ComputeAndCopyDigestAsync(new byte[] { 0xFF, 0xFF, 0xFF }).ConfigureAwait(false),
            ResponderKind = XAdESOcspResponderIdKind.ByName,
            ProducedAtLexical = "2024-01-01T00:00:00Z"
        };

        using XAdESQualifyingPropertiesFacts facts = BuildFacts(
            completeRevocationCrlRefs: [resolvingCrlRef],
            attributeRevocationOcspRefs: [undigestedOcspRef, unresolvingOcspRef],
            embeddedCrls: [crlCandidate],
            revocationValidationDataTriggered: true);

        IReadOnlyList<XAdESRuleViolation> violations = await XAdESLevelRules.CheckReferencesResolveToValidationDataAsync(facts, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.ContainsSingle(v => v is XAdESReferencesValidationDataConsistencyViolation c
            && c.Surface == XAdESRefsFamilyDigestSurface.AttributeRevocationRefs && c.MaterialKind == XAdESReferenceMaterialKind.Ocsp, violations);
        Assert.HasCount(1, violations);
    }


    /// <summary>
    /// Proves Annex A.1.2's "shall indicate the same time as the referenced OCSP response's own <c>ProducedAt</c>
    /// field" (via <see cref="OcspResponseVerification.TryReadProducedAt"/>): a resolved <c>OCSPRef</c> whose own
    /// <c>ProducedAt</c> agrees with the candidate response's decoded <c>producedAt</c> produces no violation; a
    /// disagreeing one produces a <see cref="XAdESOcspProducedAtConsistencyViolation"/>; an unresolvable-by-
    /// design entry (no <c>DigestAlgAndValue</c>) is silently skipped.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.2.
    /// </summary>
    [TestMethod]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each response's ownership transfers into the BuildFacts(...) record's own EmbeddedOcspResponses list, disposed by that record's own using block below.")]
    public async Task CheckOcspProducedAtConsistencyAsyncComparesAgainstTheResolvedResponsesOwnProducedAt()
    {
        var producedAt = new DateTimeOffset(2024, 6, 1, 12, 0, 0, TimeSpan.Zero);
        PkiCertificateMemory agreeingResponse = OcspTestFixtures.BuildMinimalOcspResponseWithProducedAt(producedAt);
        byte[] responseBytes = agreeingResponse.AsReadOnlySpan().ToArray();
        var agreeingRef = new XAdESOcspReferenceFact
        {
            HasDigestAlgAndValue = true,
            DigestAlgorithm = AlgorithmIdentifier.Sha256,
            Digest = await ComputeAndCopyDigestAsync(responseBytes).ConfigureAwait(false),
            ResponderKind = XAdESOcspResponderIdKind.ByKey,
            ProducedAtLexical = "2024-06-01T12:00:00Z",
            ProducedAt = producedAt
        };
        using(XAdESQualifyingPropertiesFacts agreeing = BuildFacts(completeRevocationOcspRefs: [agreeingRef], embeddedOcsp: [agreeingResponse]))
        {
            IReadOnlyList<XAdESRuleViolation> violations = await XAdESLevelRules.CheckOcspProducedAtConsistencyAsync(agreeing, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsEmpty(violations);
        }

        PkiCertificateMemory disagreeingResponse = OcspTestFixtures.BuildMinimalOcspResponseWithProducedAt(producedAt);
        var disagreeingRef = new XAdESOcspReferenceFact
        {
            HasDigestAlgAndValue = true,
            DigestAlgorithm = AlgorithmIdentifier.Sha256,
            Digest = await ComputeAndCopyDigestAsync(responseBytes).ConfigureAwait(false),
            ResponderKind = XAdESOcspResponderIdKind.ByKey,
            ProducedAtLexical = "2024-06-02T12:00:00Z",
            ProducedAt = producedAt.AddDays(1)
        };
        using(XAdESQualifyingPropertiesFacts disagreeing = BuildFacts(completeRevocationOcspRefs: [disagreeingRef], embeddedOcsp: [disagreeingResponse]))
        {
            IReadOnlyList<XAdESRuleViolation> violations = await XAdESLevelRules.CheckOcspProducedAtConsistencyAsync(disagreeing, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.ContainsSingle(v => v is XAdESOcspProducedAtConsistencyViolation c && c.Surface == XAdESRefsFamilyDigestSurface.CompleteRevocationRefs && c.Ordinal == 0, violations);
        }

        var undigestedRef = new XAdESOcspReferenceFact { HasDigestAlgAndValue = false, ResponderKind = XAdESOcspResponderIdKind.ByName, ProducedAtLexical = "2034-01-01T00:00:00Z", ProducedAt = producedAt.AddYears(10) };
        using(XAdESQualifyingPropertiesFacts undigested = BuildFacts(attributeRevocationOcspRefs: [undigestedRef]))
        {
            IReadOnlyList<XAdESRuleViolation> violations = await XAdESLevelRules.CheckOcspProducedAtConsistencyAsync(undigested, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsEmpty(violations);
        }
    }


    /// <summary>
    /// Proves clause 5.2.9 NOTE 3: a caller-supplied policy document whose digest, taken under the signed
    /// <c>SigPolicyHash</c>'s own algorithm, matches the signed value produces no violation; a mismatching
    /// document produces a <see cref="XAdESSignaturePolicyDocumentDigestViolation"/>; an absent or
    /// <c>SignaturePolicyImplied</c> policy has nothing to check.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.9 NOTE 3.
    /// </summary>
    [TestMethod]
    public async Task CheckSignaturePolicyDocumentDigestAsyncComparesAgainstTheSignedSigPolicyHash()
    {
        byte[] policyDocument = [0x50, 0x51, 0x52];
        using var policy = new XAdESSignaturePolicyFact { IsImplied = false, HashAlgorithm = AlgorithmIdentifier.Sha256, Hash = await ComputeAndCopyDigestAsync(policyDocument).ConfigureAwait(false) };

        IReadOnlyList<XAdESRuleViolation> agreeing = await XAdESLevelRules.CheckSignaturePolicyDocumentDigestAsync(policy, policyDocument, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(agreeing);

        IReadOnlyList<XAdESRuleViolation> disagreeing = await XAdESLevelRules.CheckSignaturePolicyDocumentDigestAsync(policy, new byte[] { 0xFF, 0xFF, 0xFF }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.ContainsSingle(v => v is XAdESSignaturePolicyDocumentDigestViolation, disagreeing);

        using var impliedPolicy = new XAdESSignaturePolicyFact { IsImplied = true };
        IReadOnlyList<XAdESRuleViolation> impliedIsSkipped = await XAdESLevelRules.CheckSignaturePolicyDocumentDigestAsync(
            impliedPolicy, policyDocument, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(impliedIsSkipped);

        IReadOnlyList<XAdESRuleViolation> absentIsSkipped = await XAdESLevelRules.CheckSignaturePolicyDocumentDigestAsync(
            null, policyDocument, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(absentIsSkipped);
    }


    /// <summary>
    /// Proves clause 5.5.3's XA-5.5.3-13 step 2)'s digest-VALUE-addressed lookup: an <c>OriginalRefDigest</c>
    /// resolving to a byte-identical candidate <c>ds:Reference</c> digest-input produces no violation; a
    /// non-resolving one produces a <see cref="XAdESRenewedDigestsV2ReferenceUnresolvedViolation"/> naming its
    /// own ordinal.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.5.3, XA-5.5.3-13.
    /// </summary>
    [TestMethod]
    public async Task CheckRenewedDigestsV2ReferenceLookupAsyncResolvesByDigestValue()
    {
        byte[] candidateReferenceInput = [0x60, 0x61, 0x62];
        using DigestValue matchingDigest = await ComputeAndCopyDigestAsync(candidateReferenceInput).ConfigureAwait(false);
        IReadOnlyList<XAdESRuleViolation> resolved = await XAdESLevelRules.CheckRenewedDigestsV2ReferenceLookupAsync(
            [(AlgorithmIdentifier.Sha256, matchingDigest)], [candidateReferenceInput], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(resolved);

        using DigestValue unmatchedDigest = await ComputeAndCopyDigestAsync(new byte[] { 0xFF, 0xFF, 0xFF }).ConfigureAwait(false);
        IReadOnlyList<XAdESRuleViolation> unresolved = await XAdESLevelRules.CheckRenewedDigestsV2ReferenceLookupAsync(
            [(AlgorithmIdentifier.Sha256, unmatchedDigest)], [candidateReferenceInput], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.ContainsSingle(v => v is XAdESRenewedDigestsV2ReferenceUnresolvedViolation u && u.Ordinal == 0, unresolved);
    }


    /// <summary>
    /// Proves letter y)'s own SHOULD: the validation-data-for-time-stamps service satisfied ONLY via the
    /// embedded-in-time-stamp option produces a <see cref="XAdESValidationDataServicePreferenceObservation"/>;
    /// satisfaction via <c>TimeStampValidationData</c> (even alongside the embedded option), an unsatisfied
    /// service, and a level below B-LT all produce none.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, XA-6.3-t40, letter y.
    /// </summary>
    [TestMethod]
    public void CheckValidationDataServicePreferenceObservesOnlyWhenSatisfiedSolelyByTheEmbeddedOption()
    {
        using XAdESQualifyingPropertiesFacts embeddedOnly = BuildFacts();
        Assert.ContainsSingle(o => o is XAdESValidationDataServicePreferenceObservation,
            XAdESLevelRules.CheckValidationDataServicePreference(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, Facts = embeddedOnly, AnyTimestampTokenCarriesEmbeddedValidationMaterial = true }));

        using XAdESQualifyingPropertiesFacts preferred = BuildFacts(validationData: EmptyValidationData with { TimeStampValidationDataCount = 1 });
        Assert.IsEmpty(XAdESLevelRules.CheckValidationDataServicePreference(
            new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, Facts = preferred, AnyTimestampTokenCarriesEmbeddedValidationMaterial = true }));

        using XAdESQualifyingPropertiesFacts unsatisfied = BuildFacts();
        Assert.IsEmpty(XAdESLevelRules.CheckValidationDataServicePreference(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, Facts = unsatisfied }));

        using XAdESQualifyingPropertiesFacts belowBLT = BuildFacts();
        Assert.IsEmpty(XAdESLevelRules.CheckValidationDataServicePreference(
            new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = belowBLT, AnyTimestampTokenCarriesEmbeddedValidationMaterial = true }));
    }


    private static DigestValue NonResolvingDigest(int distinguisher)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        owner.Memory.Span.Fill(0xFF);
        BitConverter.TryWriteBytes(owner.Memory.Span[28..], distinguisher);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    /// <summary>
    /// Cost hardening, counted: <see cref="XAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/> resolves references against candidates through a digest-value-keyed index built
    /// ONCE per distinct algorithm (<c>CandidateDigestIndex</c>), not by re-digesting the whole candidate list for every reference — O(references + candidates), not O(references &#215;
    /// candidates). The discriminator is a rent count observed on a <see cref="MeteredHousePool"/>, not a wall-clock ceiling: at the shipped per-element ceilings
    /// (<c>XAdESCompleteRevocationRefs.MaximumRevocationRefEntryCount</c>/<c>XAdESCertificateValues.MaximumEntryCount</c>, both 4096), the memoized shape rents exactly one 32-octet digest per
    /// candidate — <c>count</c> rents, the index built once for the one triggered SHA-256 algorithm — while the unmemoized O(references &#215; candidates) shape (re-digesting the whole candidate
    /// list for every reference) would rent <c>count &#215; count == 16,777,216</c> 32-octet digests instead: a factor-of-<c>count</c> signal that discriminates a regression unconditionally,
    /// independent of machine speed. Anchored to <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> Annex A.1.1.
    /// </summary>
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsyncResolvesReferencesWithOneDigestPerCandidate()
    {
        const int count = 4096;
        var refs = new List<XAdESCertificateReferenceDigestFact>(count);
        var candidates = new List<PkiCertificateMemory>(count);
        for(int i = 0; i < count; ++i)
        {
            candidates.Add(CopyBytes(BitConverter.GetBytes(i), PkiCertificateTags.X509Certificate));

            //A digest that cannot resolve against ANY real SHA-256 candidate digest -- the all-0xFF fill with
            //an embedded distinguisher mirrors this file's own established "deliberately non-matching" idiom
            //(the 0xFF candidates/digests used throughout the tests above); a hand-crafted 32-byte value
            //colliding with a genuine SHA-256 output is cryptographically negligible.
            refs.Add(new XAdESCertificateReferenceDigestFact { DigestAlgorithm = AlgorithmIdentifier.Sha256, Digest = NonResolvingDigest(i) });
        }

        using XAdESQualifyingPropertiesFacts facts = BuildFacts(completeCertificateRefs: refs, embeddedCertificates: candidates, certificateValidationDataTriggered: true);

        using var meteredPool = new MeteredHousePool();
        IReadOnlyList<XAdESRuleViolation> violations = await XAdESLevelRules.CheckReferencesResolveToValidationDataAsync(facts, meteredPool.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(count, violations, $"Every one of the {count} non-resolving references must produce its own violation.");
        Assert.AreEqual(count, meteredPool.RentedCountOfSize(32),
            $"The memoized CandidateDigestIndex digests each of the {count} candidates exactly once for the one triggered algorithm; the unmemoized O(references x candidates) shape would rent {count}*{count} == {(long)count * count:N0} 32-octet digests instead.");
        Assert.AreEqual(0L, meteredPool.OutstandingCount, "The index's per-candidate digest rentals must all be returned before the rule returns.");
    }


    /// <summary>
    /// Pins the invariant <see cref="XAdESLevelRules"/>'s private <c>CheckPresenceAndCardinality</c> relies on to
    /// treat a zero occurrence count as safe to skip once <see cref="AdESPresence.ShallBePresent"/> has already
    /// been checked: at every level, every <see cref="AdESTableRow"/> in <see cref="XAdESBaselineLevelTable.Rows"/>
    /// whose cardinality at that level includes <see cref="AdESCardinality.ExactlyOne"/>,
    /// <see cref="AdESCardinality.OneOrMore"/>, or <see cref="AdESCardinality.AtLeastTwo"/> (every token whose
    /// value space excludes zero) is ALSO <see cref="AdESPresence.ShallBePresent"/> at that level, with exactly
    /// ONE documented exception: <see cref="XAdESBaselineLevelTable.ArchiveTimeStamp"/> (XA-6.3-t44) states
    /// cardinality <see cref="AdESCardinality.OneOrMore"/> level-invariant against a "*" soft-negative presence
    /// at B-B/B-T/B-LT — Table 2's own design, not a defect (see that row's own remarks) — so the zero-count
    /// early return is what implements the B-B/B-T/B-LT tolerance there. A future row reintroducing this shape
    /// without being this exact, reviewed exception would make the zero-count early return silently skip its
    /// own cardinality floor.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2.
    /// </summary>
    [TestMethod]
    public void CardinalityFloorsAboveZeroAreAlwaysPairedWithShallBePresentExceptTheDocumentedArchiveTimeStampCarveOut()
    {
        AdESCardinality[] floorsAboveZero = [AdESCardinality.ExactlyOne, AdESCardinality.OneOrMore, AdESCardinality.AtLeastTwo];
        foreach(AdESTableRow row in XAdESBaselineLevelTable.Rows)
        {
            if(row.Cardinality is null)
            {
                continue;
            }

            foreach(AdESBaselineLevel level in new[] { AdESBaselineLevel.BB, AdESBaselineLevel.BT, AdESBaselineLevel.BLT, AdESBaselineLevel.BLTA })
            {
                IReadOnlyList<AdESCardinality> valuesAtLevel = row.Cardinality.ValuesAt(level);
                bool hasFloorAboveZero = valuesAtLevel.Any(floorsAboveZero.Contains);
                if(!hasFloorAboveZero || row.Presence.At(level) == AdESPresence.ShallBePresent)
                {
                    continue;
                }

                Assert.AreEqual("XA-6.3-t44", row.RequirementId,
                    $"Row '{row.RequirementId}' ({row.Name}) states a >=1 cardinality floor at {level} but is not ShallBePresent there, and is not the one documented exception (XA-6.3-t44); the zero-count early return would silently admit a violating zero count.");
            }
        }
    }
}

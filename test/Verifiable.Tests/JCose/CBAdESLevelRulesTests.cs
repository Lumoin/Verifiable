using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the wavecb S4 CB-AdES level-scoped rule surface (<see cref="CBAdESLevelRules"/>) in both
/// postures, the raw-<c>uHeaders</c> wire-bytes capture <see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/>
/// gained (<see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/>), and the three new message-imprint-input
/// seam adapters (<see cref="CBAdESLevelMessageImprintAdapters"/>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 6.3 (Table 14) and Annex A.1.1/A.1.2.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Independent oracle.</strong> Every fixture is built directly from the model constructors this
/// wave's own S1/S2 agents shipped (never re-implementing a parsed-value assertion against the rule surface's
/// own internals), and every raw-wire-bytes test assembles its CBOR independently with a fresh
/// <see cref="CborWriter"/> in canonical mode, citing spec-table literal integers in comments — never the
/// model's own <c>*Key</c>/label constants — matching <c>CBAdESUnsignedComponentSerializationTests</c>'s own
/// convention.
/// </para>
/// <para>
/// <strong>Digest fixtures.</strong> Every <see cref="DigestValue"/> a fixture carries is a real SHA-256
/// digest computed through the registered <see cref="CryptographicKeyEvents"/> digest delegate seam (via
/// <see cref="CreateDigestAsync"/>), never a hand-rolled hash — matching <c>CBAdESUnsignedComponentTests</c>'s
/// own convention.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESLevelRulesTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    // ------------------------------------------------------------------------------------------------------
    // CB-6.3-21: sigTst presence at B-T+.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>CB-6.3-21: at level B-T with no <c>sigTst</c> element anywhere in <c>uHeaders</c>, <see cref="CBAdESLevelRules.Check"/> reports a violation.</summary>
    [TestMethod]
    public async Task Check_SignatureTimestampMissing_AtLevelBTWithNoSigTst_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<CBAdESSignatureTimestampMissingViolation>(violations));
    }


    /// <summary>CB-6.3-21: at level B-B, the absence of <c>sigTst</c> is legal ("*" — should-not, not shall-not) — no violation.</summary>
    [TestMethod]
    public async Task Check_SignatureTimestampMissing_AtLevelBBWithNoSigTst_NoViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESSignatureTimestampMissingViolation>(violations));
    }


    /// <summary>CB-6.3-21: at level B-T with a conformant single-token <c>sigTst</c> present, no violation.</summary>
    [TestMethod]
    public void Check_SignatureTimestampPresent_AtLevelBT_NoViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.AreEqual(0, violations.Count);
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-6.3-c: exactly one token per sigTst instance.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>CB-6.3-c: a <c>sigTst</c> instance encapsulating two tokens violates the one-token rule.</summary>
    [TestMethod]
    public void Check_SignatureTimestampTokenCount_TwoTokens_ReturnsViolationWithCount()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(2)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESSignatureTimestampTokenCountViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(2, violation!.TokenCount);
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-6.3-02: baseline TstToken narrowing (RFC 3161 legacy shape only).
    // ------------------------------------------------------------------------------------------------------

    /// <summary>CB-6.3-02: a <c>sigTst</c> token carrying a <c>type</c> member is not the RFC 3161 legacy shape.</summary>
    [TestMethod]
    public void Check_TimestampTokenNotBaseline_SigTstWithTypedToken_ReturnsViolation()
    {
        var container = new CBAdESTimestampContainer
        {
            TstTokens = [new CBAdESTimestampToken { Val = new byte[] { 0x01 }, Type = "other-format" }]
        };
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(container))]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESTimestampTokenNotBaselineViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESTimestampContainerKind.SignatureTimestamp, violation!.Kind);
    }


    /// <summary>CB-6.3-02: an <c>arcTst</c> token carrying an <c>encoding</c> member is checked too, even though <c>arcTst</c> generation is out of this stage's scope.</summary>
    [TestMethod]
    public void Check_TimestampTokenNotBaseline_ArcTstWithEncodedToken_ReturnsViolationForArchiveTimestampKind()
    {
        var container = new CBAdESTimestampContainer
        {
            TstTokens = [new CBAdESTimestampToken { Val = new byte[] { 0x02 }, Encoding = new Uri("https://example.org/enc") }]
        };
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementArchiveTimestamp(new CBAdESArchiveTimestamp(container))]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BLTA, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESTimestampTokenNotBaselineViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESTimestampContainerKind.ArchiveTimestamp, violation!.Kind);
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-6.3-23/-24/-25: refs family forbidden at B-LT/B-LTA.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>CB-6.3-23: a <c>refs</c> element present at B-LT is forbidden.</summary>
    [TestMethod]
    public async Task Check_RefsFamilyForbidden_ReferencesAtLevelBLT_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyForbiddenViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyKind.References, violation!.Kind);
        Assert.AreEqual("CB-6.3-23", violation.RequirementId);
    }


    /// <summary>CB-6.3-24: a <c>sigRTst</c> element present at B-LTA is forbidden.</summary>
    [TestMethod]
    public void Check_RefsFamilyForbidden_SignatureAndReferencesTimestampAtLevelBLTA_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new CBAdESSignatureAndReferencesTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BLTA, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyForbiddenViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyKind.SignatureAndReferencesTimestamp, violation!.Kind);
        Assert.AreEqual("CB-6.3-24", violation.RequirementId);
    }


    /// <summary>CB-6.3-25: a <c>rfsTst</c> element present at B-LT is forbidden.</summary>
    [TestMethod]
    public void Check_RefsFamilyForbidden_ReferencesTimestampAtLevelBLT_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferencesTimestamp(new CBAdESReferencesTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyForbiddenViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyKind.ReferencesTimestamp, violation!.Kind);
        Assert.AreEqual("CB-6.3-25", violation.RequirementId);
    }


    /// <summary>CB-6.3-23: a <c>refs</c> element present at B-T is legal ("*" — should-not, not shall-not).</summary>
    [TestMethod]
    public async Task Check_RefsFamilyForbidden_ReferencesAtLevelBT_NoViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESRefsFamilyForbiddenViolation>(violations));
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-A.1.2.1-03/CB-A.1.2.2-03: sigRTst/rfsTst generation gate.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>CB-A.1.2.1-03: a <c>sigRTst</c> element with no preceding <c>refs</c> element violates the generation gate.</summary>
    [TestMethod]
    public void Check_GenerationGate_SignatureAndReferencesTimestampWithNoPrecedingReferences_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new CBAdESSignatureAndReferencesTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESReferencesTimestampGenerationGateViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESReferencesTimestampGenerationKind.SignatureAndReferences, violation!.Kind);
        Assert.AreEqual("CB-A.1.2.1-03", violation.RequirementId);
    }


    /// <summary>CB-A.1.2.1-03: a <c>sigRTst</c> element preceded by a <c>refs</c> element satisfies the generation gate.</summary>
    [TestMethod]
    public async Task Check_GenerationGate_SignatureAndReferencesTimestampWithPrecedingReferences_NoViolation()
    {
        using CBAdESReferences references = await BuildMinimalReferencesAsync();
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new CBAdESSignatureAndReferencesTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESReferencesTimestampGenerationGateViolation>(violations));
    }


    /// <summary>CB-A.1.2.2-03: a <c>rfsTst</c> element with no preceding <c>refs</c> element violates the generation gate.</summary>
    [TestMethod]
    public void Check_GenerationGate_ReferencesTimestampWithNoPrecedingReferences_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferencesTimestamp(new CBAdESReferencesTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESReferencesTimestampGenerationGateViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESReferencesTimestampGenerationKind.ReferencesOnly, violation!.Kind);
        Assert.AreEqual("CB-A.1.2.2-03", violation.RequirementId);
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-6.3-26/h: the validation-data-for-time-stamps service (valData OR embedded-in-token).
    // ------------------------------------------------------------------------------------------------------

    /// <summary>CB-6.3-26: at B-LT with neither SPO satisfied, the service is unfulfilled.</summary>
    [TestMethod]
    public void Check_ValidationDataService_AtLevelBLTWithNeitherSpo_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<CBAdESTimestampValidationDataServiceViolation>(violations));
    }


    /// <summary>CB-6.3-26: at B-LT with a <c>valData</c> element present, the <c>valData</c> SPO satisfies the service.</summary>
    [TestMethod]
    public async Task Check_ValidationDataService_AtLevelBLTWithValidationDataElement_NoViolation()
    {
        var validationData = new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new CBAdESPkiObject { Val = new byte[] { 0x30, 0x01 } })]);
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementValidationData(validationData)]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESTimestampValidationDataServiceViolation>(violations));
        await Task.CompletedTask;
    }


    /// <summary>CB-6.3-26: at B-LT with no <c>valData</c> element but the caller-supplied embedded-material fact set, the embedded-in-token SPO satisfies the service.</summary>
    [TestMethod]
    public void Check_ValidationDataService_AtLevelBLTWithEmbeddedMaterialFactOnly_NoViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext
        {
            Level = CBAdESBaselineLevel.BLT,
            UnsignedHeaders = unsignedHeaders,
            AnyTimestampTokenCarriesEmbeddedValidationMaterial = true
        };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESTimestampValidationDataServiceViolation>(violations));
    }


    /// <summary>CB-6.3-26: the service is not evaluated below B-LT ("*" at B-B/B-T) — no violation even with neither SPO.</summary>
    [TestMethod]
    public void Check_ValidationDataService_AtLevelBT_NotEvaluated_NoViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESTimestampValidationDataServiceViolation>(violations));
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-A.1.1-02: refs shall not reference the signature's own signing certificate.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>CB-A.1.1-02: a <c>refs</c> certificate reference whose digest matches the caller-supplied signing-certificate digest violates the exclusion rule.</summary>
    [TestMethod]
    public async Task Check_SigningCertificateExclusion_MatchingDigest_ReturnsViolation()
    {
        DigestValue signingCertDigest = await CreateDigestAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken);
        DigestValue referenceDigest = await CreateDigestAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementReferences(references)]);

        using(signingCertDigest)
        {
            var context = new CBAdESLevelRuleContext
            {
                Level = CBAdESBaselineLevel.BT,
                UnsignedHeaders = unsignedHeaders,
                SigningCertificateDigests = [signingCertDigest]
            };

            IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

            Assert.IsTrue(HasViolation<CBAdESReferencesSigningCertificateExclusionViolation>(violations));
        }
    }


    /// <summary>CB-A.1.1-02: a <c>refs</c> certificate reference whose digest differs from the signing-certificate digest does not violate the exclusion rule.</summary>
    [TestMethod]
    public async Task Check_SigningCertificateExclusion_NonMatchingDigest_NoViolation()
    {
        DigestValue signingCertDigest = await CreateDigestAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken);
        DigestValue referenceDigest = await CreateDigestAsync("some other certificate"u8.ToArray(), TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementReferences(references)]);

        using(signingCertDigest)
        {
            var context = new CBAdESLevelRuleContext
            {
                Level = CBAdESBaselineLevel.BT,
                UnsignedHeaders = unsignedHeaders,
                SigningCertificateDigests = [signingCertDigest]
            };

            IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

            Assert.IsFalse(HasViolation<CBAdESReferencesSigningCertificateExclusionViolation>(violations));
        }
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-6.2.1-02 (refs family surfaces): MD5 hard denylist.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>CB-6.2.1-02: an <c>xRefs</c> entry naming MD5 (the CDDL <c>tstr</c> arm) is refused.</summary>
    [TestMethod]
    public async Task Check_RefsFamilyMd5_CertificateReferenceThumbprint_ReturnsViolation()
    {
        DigestValue digest = await CreateDigestAsync("md5 surface"u8.ToArray(), TestContext.CancellationToken);
        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmTextIdentifier("MD5"), digest))
        ]);
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementReferences(references)]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyMd5DigestAlgorithmViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyDigestSurface.CertificateReferenceThumbprint, violation!.Surface);
    }


    /// <summary>CB-6.2.1-02: a <c>crlRefs</c> entry naming MD5 is refused.</summary>
    [TestMethod]
    public async Task Check_RefsFamilyMd5_CrlReferenceDigest_ReturnsViolation()
    {
        DigestValue digest = await CreateDigestAsync("crl md5"u8.ToArray(), TestContext.CancellationToken);
        using CBAdESReferences references = new(revocationReferences: new CBAdESRevocationReferences(crlReferences:
        [
            new CBAdESCrlReference(new CBAdESDigestAlgorithmTextIdentifier("MD5"), digest)
        ]));
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementReferences(references)]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyMd5DigestAlgorithmViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyDigestSurface.CrlReferenceDigest, violation!.Surface);
    }


    /// <summary>CB-6.2.1-02: an <c>ocspRefs</c> entry naming MD5 is refused.</summary>
    [TestMethod]
    public async Task Check_RefsFamilyMd5_OcspReferenceDigest_ReturnsViolation()
    {
        DigestValue digest = await CreateDigestAsync("ocsp md5"u8.ToArray(), TestContext.CancellationToken);
        var ocspIdentifier = new CBAdESOcspIdentifier(new CBAdESOcspResponderIdentifierByName(new byte[] { 0x01 }), DateTimeOffset.UnixEpoch);
        using CBAdESReferences references = new(revocationReferences: new CBAdESRevocationReferences(ocspReferences:
        [
            new CBAdESOcspReference(new CBAdESDigestAlgorithmTextIdentifier("MD5"), digest, ocspIdentifier)
        ]));
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementReferences(references)]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyMd5DigestAlgorithmViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyDigestSurface.OcspReferenceDigest, violation!.Surface);
    }


    // ------------------------------------------------------------------------------------------------------
    // EnsureConformant (throw posture, sync rules).
    // ------------------------------------------------------------------------------------------------------

    /// <summary>EnsureConformant does not throw when <see cref="CBAdESLevelRules.Check"/> reports no violations.</summary>
    [TestMethod]
    public void EnsureConformant_FullyConformant_DoesNotThrow()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        CBAdESLevelRules.EnsureConformant(context);
    }


    /// <summary>EnsureConformant throws, naming the first violated clause, when at least one level rule fails.</summary>
    [TestMethod]
    public async Task EnsureConformant_WithViolations_ThrowsNamingFirstViolatedClause()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();
        var context = new CBAdESLevelRuleContext { Level = CBAdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => CBAdESLevelRules.EnsureConformant(context));
        Assert.IsTrue(exception.Message.Contains("CB-", StringComparison.Ordinal));
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-A.1.1-30: refs-to-valData cross-component consistency (async).
    // ------------------------------------------------------------------------------------------------------

    /// <summary>CB-A.1.1-30 does not fire when <c>uHeaders</c> is absent.</summary>
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_NullUnsignedHeaders_ReturnsEmpty()
    {
        IReadOnlyList<CBAdESRuleViolation> violations = await CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            null, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.AreEqual(0, violations.Count);
    }


    /// <summary>CB-A.1.1-30 does not fire when <c>refs</c> is present but no <c>valData</c> element exists — the <c>arcTst</c>-reachable half of the disjunction is deferred to wavecb S5 (this stage's documented scope).</summary>
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_ReferencesWithoutValidationData_ReturnsEmpty()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();

        IReadOnlyList<CBAdESRuleViolation> violations = await CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.AreEqual(0, violations.Count);
    }


    /// <summary>CB-A.1.1-30: a certificate reference whose digest matches a <c>valData</c> certificate resolves — no violation.</summary>
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_CertificateResolves_ReturnsEmpty()
    {
        byte[] certificateBytes = [0x30, 0x82, 0x01, 0x0A];
        DigestValue referenceDigest = await CreateDigestAsync(certificateBytes, TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        var validationData = new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new CBAdESPkiObject { Val = certificateBytes })]);
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementValidationData(validationData)
        ]);

        IReadOnlyList<CBAdESRuleViolation> violations = await CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.AreEqual(0, violations.Count);
    }


    /// <summary>CB-A.1.1-30: a certificate reference whose digest matches nothing in <c>valData</c> fails to resolve.</summary>
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_CertificateDoesNotResolve_ReturnsViolation()
    {
        DigestValue referenceDigest = await CreateDigestAsync([0x30, 0x82, 0x01, 0x0A], TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        var validationData = new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new CBAdESPkiObject { Val = new byte[] { 0x30, 0x00 } })]);
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementValidationData(validationData)
        ]);

        IReadOnlyList<CBAdESRuleViolation> violations = await CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken);

        var violation = FindViolation<CBAdESReferencesValidationDataConsistencyViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESReferenceMaterialKind.Certificate, violation!.Kind);
    }


    /// <summary>CB-A.1.1-30: an OCSP reference whose digest matches nothing in <c>valData.rVals.ocspVals</c> fails to resolve.</summary>
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_OcspDoesNotResolve_ReturnsViolation()
    {
        DigestValue referenceDigest = await CreateDigestAsync("expected ocsp response"u8.ToArray(), TestContext.CancellationToken);
        var ocspIdentifier = new CBAdESOcspIdentifier(new CBAdESOcspResponderIdentifierByName(new byte[] { 0x01 }), DateTimeOffset.UnixEpoch);

        using CBAdESReferences references = new(revocationReferences: new CBAdESRevocationReferences(ocspReferences:
        [
            new CBAdESOcspReference(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest, ocspIdentifier)
        ]));
        var validationData = new CBAdESValidationData(revocationValues: new CBAdESRevocationValues(ocspValues: [new CBAdESPkiObject { Val = "actual ocsp response"u8.ToArray() }]));
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementValidationData(validationData)
        ]);

        IReadOnlyList<CBAdESRuleViolation> violations = await CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken);

        var violation = FindViolation<CBAdESReferencesValidationDataConsistencyViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESReferenceMaterialKind.Ocsp, violation!.Kind);
    }


    /// <summary>CB-A.1.1-30: a CRL reference under an algorithm this method cannot map to a <see cref="Tag"/> fails closed as unresolved, never throwing.</summary>
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_UnknownAlgorithm_FailsClosedAsUnresolved()
    {
        DigestValue referenceDigest = await CreateDigestAsync("crl bytes"u8.ToArray(), TestContext.CancellationToken);

        using CBAdESReferences references = new(revocationReferences: new CBAdESRevocationReferences(crlReferences:
        [
            new CBAdESCrlReference(new CBAdESDigestAlgorithmIntegerIdentifier(-999999), referenceDigest)
        ]));
        var validationData = new CBAdESValidationData(revocationValues: new CBAdESRevocationValues(crlValues: [new CBAdESPkiObject { Val = "crl bytes"u8.ToArray() }]));
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementValidationData(validationData)
        ]);

        IReadOnlyList<CBAdESRuleViolation> violations = await CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken);

        var violation = FindViolation<CBAdESReferencesValidationDataConsistencyViolation>(violations);
        Assert.IsNotNull(violation, "An unrecognized digest algorithm must fail closed as unresolved, not silently pass.");
        Assert.AreEqual(CBAdESReferenceMaterialKind.Crl, violation!.Kind);
    }


    /// <summary>EnsureReferencesResolveToValidationDataAsync does not throw when every reference resolves.</summary>
    [TestMethod]
    public async Task EnsureReferencesResolveToValidationDataAsync_AllResolve_DoesNotThrow()
    {
        byte[] certificateBytes = [0x30, 0x01];
        DigestValue referenceDigest = await CreateDigestAsync(certificateBytes, TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        var validationData = new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new CBAdESPkiObject { Val = certificateBytes })]);
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementValidationData(validationData)
        ]);

        await CBAdESLevelRules.EnsureReferencesResolveToValidationDataAsync(unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken);
    }


    /// <summary>EnsureReferencesResolveToValidationDataAsync throws, naming CB-A.1.1-30, when a reference fails to resolve.</summary>
    [TestMethod]
    public async Task EnsureReferencesResolveToValidationDataAsync_UnresolvedReference_ThrowsNamingClause()
    {
        DigestValue referenceDigest = await CreateDigestAsync([0x30, 0x82], TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        var validationData = new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new CBAdESPkiObject { Val = new byte[] { 0x30, 0x00 } })]);
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementValidationData(validationData)
        ]);

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await CBAdESLevelRules.EnsureReferencesResolveToValidationDataAsync(unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.IsTrue(exception.Message.Contains("CB-A.1.1-30", StringComparison.Ordinal));
    }


    // ------------------------------------------------------------------------------------------------------
    // Raw-uHeaders wire-bytes capture (CBAdESSignatureSerialization.ParseCBAdESSign1 / CBAdESSign1ParseResult).
    // ------------------------------------------------------------------------------------------------------

    /// <summary>
    /// A successfully parsed CB-AdES <c>COSE_Sign1</c> carrying <c>uHeaders</c> exposes
    /// <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/> byte-exact against the independently
    /// <see cref="CborWriter"/>-assembled <c>uHeaders</c> array bytes the wire message carried — never a
    /// re-encoding of the decoded model.
    /// </summary>
    [TestMethod]
    public void ParseCBAdESSign1_WithUHeaders_CapturesRawUnsignedHeadersByteExact()
    {
        byte[] uHeadersArrayBytes = BuildMinimalUHeadersArrayBytes();
        byte[] wireBytes = BuildCoseSign1WireBytes(uHeadersArrayBytes);

        CBAdESSign1ParseResult result = CBAdESSignatureSerialization.ParseCBAdESSign1(wireBytes, BaseMemoryPool.Shared);
        using(result)
        {
            Assert.IsTrue(result.IsSuccess);
            Assert.IsNotNull(result.RawUnsignedHeaders);
            Assert.IsTrue(uHeadersArrayBytes.AsSpan().SequenceEqual(result.RawUnsignedHeaders!.AsReadOnlySpan()),
                "RawUnsignedHeaders must reproduce the wire uHeaders array bytes exactly.");
        }
    }


    /// <summary>A parsed CB-AdES <c>COSE_Sign1</c> with no <c>uHeaders</c> member carries a <see langword="null"/> <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/>.</summary>
    [TestMethod]
    public void ParseCBAdESSign1_WithoutUHeaders_RawUnsignedHeadersIsNull()
    {
        byte[] wireBytes = BuildCoseSign1WireBytes(uHeadersArrayBytes: null);

        CBAdESSign1ParseResult result = CBAdESSignatureSerialization.ParseCBAdESSign1(wireBytes, BaseMemoryPool.Shared);
        using(result)
        {
            Assert.IsTrue(result.IsSuccess);
            Assert.IsNull(result.RawUnsignedHeaders);
            Assert.IsNull(result.UnsignedHeaders);
        }
    }


    /// <summary>A malformed <c>uHeaders</c> value fails the whole parse closed (R-5) — <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/> is disposed and not surfaced on the failed result.</summary>
    [TestMethod]
    public void ParseCBAdESSign1_MalformedUHeaders_FailsClosedWithNoRawCapture()
    {
        //An empty array violates CB-5.3.1-07 (uHeaders shall be non-empty) -- TryParseUnsignedHeaders rejects
        //it, so the whole parse fails closed per contract R-5.
        var emptyArrayWriter = new CborWriter(CborConformanceMode.Canonical);
        emptyArrayWriter.WriteStartArray(0);
        emptyArrayWriter.WriteEndArray();
        byte[] malformedUHeadersBytes = emptyArrayWriter.Encode();

        byte[] wireBytes = BuildCoseSign1WireBytes(malformedUHeadersBytes);

        CBAdESSign1ParseResult result = CBAdESSignatureSerialization.ParseCBAdESSign1(wireBytes, BaseMemoryPool.Shared);
        using(result)
        {
            Assert.IsFalse(result.IsSuccess);
            Assert.IsNull(result.RawUnsignedHeaders);
        }
    }


    // ------------------------------------------------------------------------------------------------------
    // Adapter-equivalence: the three new imprint-input seams over CBAdESLevelMessageImprintAdapters.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>The <c>adoTst</c> seam's attached-payload arm produces bytes byte-identical to a direct call into <see cref="CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput"/>.</summary>
    [TestMethod]
    public void BuildPayloadTimestampMessageImprintInput_AttachedArm_ByteIdenticalToDirectBuilderCall()
    {
        byte[] payload = [0xAA, 0xBB, 0xCC, 0xDD];

        using PooledMemory direct = CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput(new CBAdESAttachedPayloadImprintSource(payload), BaseMemoryPool.Shared);
        using PooledMemory viaSeam = CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput(new CBAdESAttachedPayloadTimestampImprintSource(payload), BaseMemoryPool.Shared);

        Assert.IsTrue(direct.AsReadOnlySpan().SequenceEqual(viaSeam.AsReadOnlySpan()));
    }


    /// <summary>The <c>adoTst</c> seam's detached arm produces bytes byte-identical to a direct builder call.</summary>
    [TestMethod]
    public void BuildPayloadTimestampMessageImprintInput_DetachedArm_ByteIdenticalToDirectBuilderCall()
    {
        byte[] payload = [0x01, 0x02];

        using PooledMemory direct = CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput(new CBAdESDetachedPayloadImprintSource(payload), BaseMemoryPool.Shared);
        using PooledMemory viaSeam = CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput(new CBAdESDetachedPayloadTimestampImprintSource(payload), BaseMemoryPool.Shared);

        Assert.IsTrue(direct.AsReadOnlySpan().SequenceEqual(viaSeam.AsReadOnlySpan()));
    }


    /// <summary>The <c>adoTst</c> seam's <c>sigD</c>-processed arm produces bytes byte-identical to a direct builder call.</summary>
    [TestMethod]
    public void BuildPayloadTimestampMessageImprintInput_SigDProcessedArm_ByteIdenticalToDirectBuilderCall()
    {
        ReadOnlyMemory<byte>[] segments = [new byte[] { 0x01 }, new byte[] { 0x02, 0x03 }];

        using PooledMemory direct = CBAdESMessageImprints.BuildPayloadTimestampMessageImprintInput(new CBAdESSigDProcessedPayloadImprintSource(segments), BaseMemoryPool.Shared);
        using PooledMemory viaSeam = CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput(new CBAdESSigDProcessedPayloadTimestampImprintSource(segments), BaseMemoryPool.Shared);

        Assert.IsTrue(direct.AsReadOnlySpan().SequenceEqual(viaSeam.AsReadOnlySpan()));
    }


    /// <summary>The <c>sigRTst</c> seam produces bytes byte-identical to a direct call into <see cref="CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput"/>.</summary>
    [TestMethod]
    public void TryBuildSignatureAndReferencesTimestampMessageImprintInput_ByteIdenticalToDirectBuilderCall()
    {
        byte[] signatureValue = [0x10, 0x20, 0x30];

        bool directBuilt = CBAdESMessageImprints.TryBuildSignatureAndReferencesTimestampMessageImprintInput(signatureValue, null, uHeadersSliceBound: null, BaseMemoryPool.Shared, out PooledMemory? direct);
        bool seamBuilt = CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput(signatureValue, null, uHeadersSliceBound: null, BaseMemoryPool.Shared, out PooledMemory? viaSeam);

        Assert.IsTrue(directBuilt);
        Assert.IsTrue(seamBuilt);
        using(direct)
        using(viaSeam)
        {
            Assert.IsTrue(direct!.AsReadOnlySpan().SequenceEqual(viaSeam!.AsReadOnlySpan()));
        }
    }


    /// <summary>The <c>rfsTst</c> seam produces bytes byte-identical to a direct call into <see cref="CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput"/>.</summary>
    [TestMethod]
    public void TryBuildReferencesOnlyTimestampMessageImprintInput_ByteIdenticalToDirectBuilderCall()
    {
        bool directBuilt = CBAdESMessageImprints.TryBuildReferencesOnlyTimestampMessageImprintInput(null, uHeadersSliceBound: null, BaseMemoryPool.Shared, out PooledMemory? direct);
        bool seamBuilt = CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput(null, uHeadersSliceBound: null, BaseMemoryPool.Shared, out PooledMemory? viaSeam);

        Assert.IsTrue(directBuilt);
        Assert.IsTrue(seamBuilt);
        using(direct)
        using(viaSeam)
        {
            Assert.IsTrue(direct!.AsReadOnlySpan().SequenceEqual(viaSeam!.AsReadOnlySpan()));
        }
    }


    // ------------------------------------------------------------------------------------------------------
    // Shared fixture helpers.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>Builds a conformant, single-token RFC 3161-shaped <see cref="CBAdESTimestampContainer"/> with <paramref name="tokenCount"/> tokens (repeats the same fixture value for every token to exercise CB-6.3-c independent of token content).</summary>
    /// <param name="tokenCount">The number of tokens to encapsulate.</param>
    /// <returns>The built container.</returns>
    private static CBAdESTimestampContainer BuildBaselineContainer(int tokenCount)
    {
        var tokens = new List<CBAdESTimestampToken>(tokenCount);
        for(int i = 0; i < tokenCount; ++i)
        {
            tokens.Add(new CBAdESTimestampToken { Val = new byte[] { (byte)(0x10 + i) } });
        }

        return new CBAdESTimestampContainer { TstTokens = tokens };
    }


    /// <summary>Builds a minimal <see cref="CBAdESReferences"/> instance (one certificate reference) for generation-gate fixtures.</summary>
    /// <returns>The built <c>refs</c> element.</returns>
    private static async ValueTask<CBAdESReferences> BuildMinimalReferencesAsync()
    {
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>("minimal refs fixture"u8.ToArray()), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared).ConfigureAwait(false);

        return new CBAdESReferences(certificateReferences:
        [
            new CBAdESCertificateReference(new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest))
        ]);
    }


    /// <summary>Builds a one-element <see cref="CBAdESUnsignedHeaders"/> carrying only a <c>refs</c> element — the shared fixture behind the "refs present with no sigTst" scenarios.</summary>
    /// <returns>The built <c>uHeaders</c> set. Owned by the caller.</returns>
    private static async ValueTask<CBAdESUnsignedHeaders> BuildReferencesOnlyUnsignedHeadersAsync()
    {
        CBAdESReferences references = await BuildMinimalReferencesAsync().ConfigureAwait(false);
        return new CBAdESUnsignedHeaders([new CBAdESUnsignedHeaderElementReferences(references)]);
    }


    /// <summary>
    /// Independently assembles a minimal, well-formed <c>uHeaders</c> array's wire bytes — one <c>sigPSt</c>
    /// element carrying the <c>sigPolLocalURI</c> choice arm — via a fresh <see cref="CborWriter"/>, citing
    /// Table 8/Table 9 literal keys in comments rather than any model constant, for the raw-capture tests.
    /// </summary>
    /// <returns>The encoded <c>uHeaders</c> array bytes.</returns>
    private static byte[] BuildMinimalUHeadersArrayBytes()
    {
        //DocOrLocalURI group, sigPolLocalURI arm: {2: #6.32(tstr)} (Table 9).
        var docOrLocalUriWriter = new CborWriter(CborConformanceMode.Canonical);
        docOrLocalUriWriter.WriteStartMap(1);
        docOrLocalUriWriter.WriteInt32(2);
        docOrLocalUriWriter.WriteTag((CborTag)32);
        docOrLocalUriWriter.WriteTextString("https://policy.example.org/sp");
        docOrLocalUriWriter.WriteEndMap();
        byte[] docOrLocalUriBytes = docOrLocalUriWriter.Encode();

        //sigPSt map: {1: DocOrLocalURI} (Table 9).
        var sigPStWriter = new CborWriter(CborConformanceMode.Canonical);
        sigPStWriter.WriteStartMap(1);
        sigPStWriter.WriteInt32(1);
        sigPStWriter.WriteEncodedValue(docOrLocalUriBytes);
        sigPStWriter.WriteEndMap();
        byte[] sigPStBytes = sigPStWriter.Encode();

        //UHeaderInstance one-entry map: {7: sigPSt} (Table 8, sigPSt label 7).
        var uHeaderInstanceWriter = new CborWriter(CborConformanceMode.Canonical);
        uHeaderInstanceWriter.WriteStartMap(1);
        uHeaderInstanceWriter.WriteInt32(7);
        uHeaderInstanceWriter.WriteEncodedValue(sigPStBytes);
        uHeaderInstanceWriter.WriteEndMap();
        byte[] uHeaderInstanceBytes = uHeaderInstanceWriter.Encode();

        //uHeaders = [+bstr .cbor UHeaderInstance] (clause 5.3.1).
        var uHeadersWriter = new CborWriter(CborConformanceMode.Canonical);
        uHeadersWriter.WriteStartArray(1);
        uHeadersWriter.WriteByteString(uHeaderInstanceBytes);
        uHeadersWriter.WriteEndArray();

        return uHeadersWriter.Encode();
    }


    /// <summary>
    /// Independently assembles a minimal, well-formed, tagged CB-AdES <c>COSE_Sign1</c> wire message via a
    /// fresh <see cref="CborWriter"/> — a one-member protected header (<c>alg</c>, label 1), an unprotected
    /// map carrying <paramref name="uHeadersArrayBytes"/> as the <c>uHeaders</c> member (label 268) when
    /// supplied, and fixed literal payload/signature bytes.
    /// </summary>
    /// <param name="uHeadersArrayBytes">The encoded <c>uHeaders</c> array bytes to embed, or <see langword="null"/> to omit the unprotected member entirely.</param>
    /// <returns>The encoded <c>COSE_Sign1</c> wire bytes.</returns>
    private static byte[] BuildCoseSign1WireBytes(byte[]? uHeadersArrayBytes)
    {
        var protectedHeaderWriter = new CborWriter(CborConformanceMode.Canonical);
        protectedHeaderWriter.WriteStartMap(1);
        protectedHeaderWriter.WriteInt32(1); //alg (RFC 9052 section 3.1, label 1).
        protectedHeaderWriter.WriteInt32(-7); //an arbitrary IANA COSE Algorithms identifier (ES256).
        protectedHeaderWriter.WriteEndMap();
        byte[] protectedHeaderBytes = protectedHeaderWriter.Encode();

        var messageWriter = new CborWriter(CborConformanceMode.Canonical);
        messageWriter.WriteTag((CborTag)18); //COSE_Sign1_Tagged (RFC 9052 section 2, clause 4.3).
        messageWriter.WriteStartArray(4);
        messageWriter.WriteByteString(protectedHeaderBytes);

        if(uHeadersArrayBytes is not null)
        {
            messageWriter.WriteStartMap(1);
            messageWriter.WriteInt32(268); //uHeaders (clause 5.3.1, Table 8).
            messageWriter.WriteEncodedValue(uHeadersArrayBytes);
            messageWriter.WriteEndMap();
        }
        else
        {
            messageWriter.WriteStartMap(0);
            messageWriter.WriteEndMap();
        }

        messageWriter.WriteByteString(new byte[] { 0xAA, 0xBB }); //payload, attached.
        messageWriter.WriteByteString(new byte[] { 0x01, 0x02, 0x03, 0x04 }); //signature.
        messageWriter.WriteEndArray();

        return messageWriter.Encode();
    }


    /// <summary>Determines whether <paramref name="violations"/> contains at least one instance of <typeparamref name="TViolation"/>.</summary>
    /// <typeparam name="TViolation">The violation type to look for.</typeparam>
    /// <param name="violations">The collected violations.</param>
    /// <returns><see langword="true"/> when at least one entry is of type <typeparamref name="TViolation"/>.</returns>
    private static bool HasViolation<TViolation>(IReadOnlyList<CBAdESRuleViolation> violations) where TViolation : CBAdESRuleViolation =>
        FindViolation<TViolation>(violations) is not null;


    /// <summary>Returns the first entry of <paramref name="violations"/> that is of type <typeparamref name="TViolation"/>, or <see langword="null"/>.</summary>
    /// <typeparam name="TViolation">The violation type to look for.</typeparam>
    /// <param name="violations">The collected violations.</param>
    /// <returns>The first matching violation, or <see langword="null"/>.</returns>
    private static TViolation? FindViolation<TViolation>(IReadOnlyList<CBAdESRuleViolation> violations) where TViolation : CBAdESRuleViolation
    {
        for(int i = 0; i < violations.Count; ++i)
        {
            if(violations[i] is TViolation match)
            {
                return match;
            }
        }

        return null;
    }


    /// <summary>
    /// Computes a real SHA-256 digest over <paramref name="input"/> through the registered digest delegate,
    /// tagged with <see cref="CryptoTags.Sha256Digest"/> — matching <c>CBAdESUnsignedComponentTests</c>'s own
    /// convention, never a hand-rolled hash.
    /// </summary>
    /// <param name="input">The bytes to digest.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The owned digest.</returns>
    private static async ValueTask<DigestValue> CreateDigestAsync(byte[] input, CancellationToken cancellationToken) =>
        await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(input), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
}

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Veritas.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the CB-AdES level-scoped rule surface (<see cref="CBAdESLevelRules"/>) in both
/// postures, the raw-<c>uHeaders</c> wire-bytes capture <see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/>
/// gained (<see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/>), and the three new message-imprint-input
/// seam adapters (<see cref="CBAdESLevelMessageImprintAdapters"/>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 6.3 (Table 14) and Annex A.1.1/A.1.2.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Independent oracle.</strong> Every fixture is built directly from the shipped model constructors
/// (never re-implementing a parsed-value assertion against the rule surface's
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


    // CB-6.3-21: sigTst presence at B-T+.

    /// <summary>CB-6.3-21: at level B-T with no <c>sigTst</c> element anywhere in <c>uHeaders</c>, <see cref="CBAdESLevelRules.Check"/> reports a violation.</summary>
    [TestMethod]
    public async Task Check_SignatureTimestampMissing_AtLevelBTWithNoSigTst_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<CBAdESSignatureTimestampMissingViolation>(violations));
    }


    /// <summary>CB-6.3-21: at level B-B, the absence of <c>sigTst</c> is legal ("*" — should-not, not shall-not) — no violation.</summary>
    [TestMethod]
    public async Task Check_SignatureTimestampMissing_AtLevelBBWithNoSigTst_NoViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESSignatureTimestampMissingViolation>(violations));
    }


    /// <summary>CB-6.3-21: at level B-T with a conformant single-token <c>sigTst</c> present, no violation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are constructor arguments passed straight into the enclosing " +
            "'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_SignatureTimestampPresent_AtLevelBT_NoViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsEmpty(violations);
    }


    // CB-6.3-c: exactly one token per sigTst instance.

    /// <summary>CB-6.3-c: a <c>sigTst</c> instance encapsulating two tokens violates the one-token rule.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are constructor arguments passed straight into the enclosing " +
            "'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_SignatureTimestampTokenCount_TwoTokens_ReturnsViolationWithCount()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(2)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESSignatureTimestampTokenCountViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(2, violation!.TokenCount);
    }


    // CB-6.3-02: baseline TstToken narrowing (RFC 3161 legacy shape only).

    /// <summary>CB-6.3-02: a <c>sigTst</c> token carrying a <c>type</c> member is not the RFC 3161 legacy shape.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged AdESTimestampContainer/CBAdESUnsignedHeaderElementSignatureTimestamp " +
            "constructions are constructor arguments passed straight into the enclosing 'using " +
            "CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_TimestampTokenNotBaseline_SigTstWithTypedToken_ReturnsViolation()
    {
        var container = new AdESTimestampContainer(
            [new AdESTimestampToken { Val = new byte[] { 0x01 }, Type = "other-format" }]);
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(container))]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESTimestampTokenNotBaselineViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESTimestampContainerKind.SignatureTimestamp, violation!.Kind);
    }


    /// <summary>CB-6.3-02: an <c>arcTst</c> token carrying an <c>encoding</c> member is checked too, even though <c>arcTst</c> generation is out of scope for this rule surface.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged AdESTimestampContainer/CBAdESUnsignedHeaderElementArchiveTimestamp " +
            "constructions are constructor arguments passed straight into the enclosing 'using " +
            "CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_TimestampTokenNotBaseline_ArcTstWithEncodedToken_ReturnsViolationForArchiveTimestampKind()
    {
        var container = new AdESTimestampContainer(
            [new AdESTimestampToken { Val = new byte[] { 0x02 }, Encoding = "https://example.org/enc" }]);
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementArchiveTimestamp(new CBAdESArchiveTimestamp(container))]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BLTA, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESTimestampTokenNotBaselineViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESTimestampContainerKind.ArchiveTimestamp, violation!.Kind);
    }


    /// <summary>
    /// CB-6.3-02: an <c>adoTst</c> token carrying a <c>specRef</c> member is checked too,
    /// even though <c>adoTst</c> is a SIGNED header parameter never reachable through <c>UnsignedHeaders</c> —
    /// <see cref="CBAdESLevelRuleContext.PayloadTimestamps"/> is the caller-supplied fact this rule reads it
    /// from, checked UNCONDITIONALLY (baseline-wide), independent of <see cref="CBAdESLevelRuleContext.Level"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged AdESTimestampContainer construction is a constructor argument passed " +
            "straight into the enclosing 'using var payloadTimestamps' aggregate's own construction; ownership " +
            "passes to payloadTimestamps, which the local using disposes.")]
    [TestMethod]
    public void Check_TimestampTokenNotBaseline_AdoTstWithSpecRefToken_ReturnsViolationForPayloadTimestampKind()
    {
        var container = new AdESTimestampContainer(
            [new AdESTimestampToken { Val = new byte[] { 0x03 }, SpecRef = "https://example.org/spec" }]);
        using var payloadTimestamps = new CBAdESPayloadTimestamp(container);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BB, PayloadTimestamps = payloadTimestamps };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESTimestampTokenNotBaselineViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESTimestampContainerKind.PayloadTimestamp, violation!.Kind);
    }


    /// <summary>CB-6.3-02 positive twin: a conformant, untyped (RFC 3161 legacy shape) <c>adoTst</c> token raises no violation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged BuildBaselineContainer construction is a constructor argument passed " +
            "straight into the enclosing 'using var payloadTimestamps' aggregate's own construction; ownership " +
            "passes to payloadTimestamps, which the local using disposes.")]
    [TestMethod]
    public void Check_TimestampTokenNotBaseline_AdoTstWithUntypedToken_NoViolation()
    {
        using var payloadTimestamps = new CBAdESPayloadTimestamp(BuildBaselineContainer(1));
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BB, PayloadTimestamps = payloadTimestamps };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESTimestampTokenNotBaselineViolation>(violations));
    }


    // CB-6.3-23/-24/-25: refs family forbidden at B-LT/B-LTA.

    /// <summary>CB-6.3-23: a <c>refs</c> element present at B-LT is forbidden.</summary>
    [TestMethod]
    public async Task Check_RefsFamilyForbidden_ReferencesAtLevelBLT_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyForbiddenViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyKind.References, violation!.Kind);
        Assert.AreEqual("CB-6.3-23", violation.RequirementId);
    }


    /// <summary>CB-6.3-24: a <c>sigRTst</c> element present at B-LTA is forbidden.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are constructor arguments passed straight into the enclosing " +
            "'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_RefsFamilyForbidden_SignatureAndReferencesTimestampAtLevelBLTA_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new CBAdESSignatureAndReferencesTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BLTA, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyForbiddenViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyKind.SignatureAndReferencesTimestamp, violation!.Kind);
        Assert.AreEqual("CB-6.3-24", violation.RequirementId);
    }


    /// <summary>CB-6.3-25: a <c>rfsTst</c> element present at B-LT is forbidden.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are constructor arguments passed straight into the enclosing " +
            "'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_RefsFamilyForbidden_ReferencesTimestampAtLevelBLT_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferencesTimestamp(new CBAdESReferencesTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

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
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESRefsFamilyForbiddenViolation>(violations));
    }


    // CB-A.1.2.1-03/CB-A.1.2.2-03: sigRTst/rfsTst generation gate.

    /// <summary>CB-A.1.2.1-03: a <c>sigRTst</c> element with no preceding <c>refs</c> element violates the generation gate.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are constructor arguments passed straight into the enclosing " +
            "'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_GenerationGate_SignatureAndReferencesTimestampWithNoPrecedingReferences_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new CBAdESSignatureAndReferencesTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESReferencesTimestampGenerationGateViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESReferencesTimestampGenerationKind.SignatureAndReferences, violation!.Kind);
        Assert.AreEqual("CB-A.1.2.1-03", violation.RequirementId);
    }


    /// <summary>CB-A.1.2.1-03: a <c>sigRTst</c> element preceded by a <c>refs</c> element satisfies the generation gate.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESUnsignedHeaderElementReferences/CBAdESSignatureAndReferencesTimestamp " +
            "constructions (including the already-using-scoped 'references') are constructor arguments passed " +
            "straight into the enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own " +
            "construction; ownership passes to unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public async Task Check_GenerationGate_SignatureAndReferencesTimestampWithPrecedingReferences_NoViolation()
    {
        using CBAdESReferences references = await BuildMinimalReferencesAsync();
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new CBAdESSignatureAndReferencesTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESReferencesTimestampGenerationGateViolation>(violations));
    }


    /// <summary>CB-A.1.2.2-03: a <c>rfsTst</c> element with no preceding <c>refs</c> element violates the generation gate.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are constructor arguments passed straight into the enclosing " +
            "'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_GenerationGate_ReferencesTimestampWithNoPrecedingReferences_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferencesTimestamp(new CBAdESReferencesTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESReferencesTimestampGenerationGateViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESReferencesTimestampGenerationKind.ReferencesOnly, violation!.Kind);
        Assert.AreEqual("CB-A.1.2.2-03", violation.RequirementId);
    }


    // CB-6.3-26/h: the validation-data-for-time-stamps service (valData OR embedded-in-token).

    /// <summary>CB-6.3-26: at B-LT with neither SPO satisfied, the service is unfulfilled.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are constructor arguments passed straight into the enclosing " +
            "'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_ValidationDataService_AtLevelBLTWithNeitherSpo_ReturnsViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<CBAdESTimestampValidationDataServiceViolation>(violations));
    }


    /// <summary>CB-6.3-26: at B-LT with a <c>valData</c> element present, the <c>valData</c> SPO satisfies the service.</summary>
    [TestMethod]
    public async Task Check_ValidationDataService_AtLevelBLTWithValidationDataElement_NoViolation()
    {
        var validationData = new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new AdESPkiObject { Val = new byte[] { 0x30, 0x01 } })]);
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementValidationData(validationData)]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESTimestampValidationDataServiceViolation>(violations));
        await Task.CompletedTask;
    }


    /// <summary>CB-6.3-26: at B-LT with no <c>valData</c> element but the caller-supplied embedded-material fact set, the embedded-in-token SPO satisfies the service.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are constructor arguments passed straight into the enclosing " +
            "'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_ValidationDataService_AtLevelBLTWithEmbeddedMaterialFactOnly_NoViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext
        {
            Level = AdESBaselineLevel.BLT,
            UnsignedHeaders = unsignedHeaders,
            AnyTimestampTokenCarriesEmbeddedValidationMaterial = true
        };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESTimestampValidationDataServiceViolation>(violations));
    }


    /// <summary>CB-6.3-26: the service is not evaluated below B-LT ("*" at B-B/B-T) — no violation even with neither SPO.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are constructor arguments passed straight into the enclosing " +
            "'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_ValidationDataService_AtLevelBT_NotEvaluated_NoViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESTimestampValidationDataServiceViolation>(violations));
    }


    /// <summary>
    /// CB-E-01: with a caller-supplied <see cref="CBAdESAlternativeMechanismDisclosureRegistry"/>
    /// that carries no disclosure for an unknown-label <c>uHeaders</c> element's own label,
    /// <see cref="CBAdESLevelRules.Check"/> collects <see cref="CBAdESUndisclosedAlternativeMechanismViolation"/>
    /// naming that exact label.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESUnsignedHeaderElementUnknown construction is a constructor argument " +
            "passed straight into the enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own " +
            "construction; ownership passes to unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_AlternativeMechanismDisclosure_RegistrySuppliedWithNoDisclosureRegistered_ReturnsViolation()
    {
        var label = new CBAdESUnsignedHeaderElementIntegerLabel(90210);
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementUnknown(label, new byte[] { 0x01 })
        ]);
        var registry = new CBAdESAlternativeMechanismDisclosureRegistry();
        var context = new CBAdESLevelRuleContext
        {
            Level = AdESBaselineLevel.BB,
            UnsignedHeaders = unsignedHeaders,
            AlternativeMechanismDisclosures = registry
        };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        CBAdESUndisclosedAlternativeMechanismViolation? violation = FindViolation<CBAdESUndisclosedAlternativeMechanismViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(label, violation.Label);
        Assert.AreEqual("CB-E-01", violation.RequirementId);
    }


    /// <summary>
    /// CB-E-01: the SAME unknown-label element with a disclosure genuinely registered
    /// against its own label collects no violation.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESUnsignedHeaderElementUnknown construction is a constructor argument " +
            "passed straight into the enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own " +
            "construction; ownership passes to unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_AlternativeMechanismDisclosure_RegistrySuppliedWithDisclosureRegistered_NoViolation()
    {
        var label = new CBAdESUnsignedHeaderElementIntegerLabel(90210);
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementUnknown(label, new byte[] { 0x01 })
        ]);
        var registry = new CBAdESAlternativeMechanismDisclosureRegistry();
        registry.Register(label, new CBAdESAlternativeMechanismDisclosure("id", "ref", "protection", "coexistence"));
        var context = new CBAdESLevelRuleContext
        {
            Level = AdESBaselineLevel.BB,
            UnsignedHeaders = unsignedHeaders,
            AlternativeMechanismDisclosures = registry
        };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESUndisclosedAlternativeMechanismViolation>(violations));
    }


    /// <summary>
    /// CB-E-01: an ABSENT registry (the default, caller never opted in) performs no
    /// Annex E disclosure check at all, even though the same unknown-label element carries no disclosure
    /// anywhere.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESUnsignedHeaderElementUnknown construction is a constructor argument " +
            "passed straight into the enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own " +
            "construction; ownership passes to unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void Check_AlternativeMechanismDisclosure_RegistryAbsent_NoViolation()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementUnknown(new CBAdESUnsignedHeaderElementIntegerLabel(90210), new byte[] { 0x01 })
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<CBAdESUndisclosedAlternativeMechanismViolation>(violations));
    }


    // CB-A.1.1-02: refs shall not reference the signature's own signing certificate.

    /// <summary>CB-A.1.1-02: a <c>refs</c> certificate reference whose digest matches the caller-supplied signing-certificate digest violates the exclusion rule.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESCertificateReference/AdESCertificateThumbprint constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task Check_SigningCertificateExclusion_MatchingDigest_ReturnsViolation()
    {
        DigestValue signingCertDigest = await CreateDigestAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken);
        DigestValue referenceDigest = await CreateDigestAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementReferences(references)]);

        using(signingCertDigest)
        {
            var context = new CBAdESLevelRuleContext
            {
                Level = AdESBaselineLevel.BT,
                UnsignedHeaders = unsignedHeaders,
                SigningCertificateDigests = [signingCertDigest]
            };

            IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

            Assert.IsTrue(HasViolation<CBAdESReferencesSigningCertificateExclusionViolation>(violations));
        }
    }


    /// <summary>CB-A.1.1-02: a <c>refs</c> certificate reference whose digest differs from the signing-certificate digest does not violate the exclusion rule.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESCertificateReference/AdESCertificateThumbprint constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task Check_SigningCertificateExclusion_NonMatchingDigest_NoViolation()
    {
        DigestValue signingCertDigest = await CreateDigestAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken);
        DigestValue referenceDigest = await CreateDigestAsync("some other certificate"u8.ToArray(), TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementReferences(references)]);

        using(signingCertDigest)
        {
            var context = new CBAdESLevelRuleContext
            {
                Level = AdESBaselineLevel.BT,
                UnsignedHeaders = unsignedHeaders,
                SigningCertificateDigests = [signingCertDigest]
            };

            IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

            Assert.IsFalse(HasViolation<CBAdESReferencesSigningCertificateExclusionViolation>(violations));
        }
    }


    // CB-6.2.1-02 (refs family surfaces): MD5 hard denylist.

    /// <summary>CB-6.2.1-02: an <c>xRefs</c> entry naming MD5 (the CDDL <c>tstr</c> arm) is refused.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESCertificateReference/AdESCertificateThumbprint constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task Check_RefsFamilyMd5_CertificateReferenceThumbprint_ReturnsViolation()
    {
        DigestValue digest = await CreateDigestAsync("md5 surface"u8.ToArray(), TestContext.CancellationToken);
        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("MD5"), digest))
        ]);
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementReferences(references)]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyMd5DigestAlgorithmViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyDigestSurface.CertificateReferenceThumbprint, violation!.Surface);
    }


    /// <summary>CB-6.2.1-02: a <c>crlRefs</c> entry naming MD5 is refused.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESRevocationReferences/CBAdESCrlReference constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task Check_RefsFamilyMd5_CrlReferenceDigest_ReturnsViolation()
    {
        DigestValue digest = await CreateDigestAsync("crl md5"u8.ToArray(), TestContext.CancellationToken);
        using CBAdESReferences references = new(revocationReferences: new CBAdESRevocationReferences(crlReferences:
        [
            new CBAdESCrlReference(new AdESDigestAlgorithmTextIdentifier("MD5"), digest)
        ]));
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementReferences(references)]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyMd5DigestAlgorithmViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyDigestSurface.CrlReferenceDigest, violation!.Surface);
    }


    /// <summary>CB-6.2.1-02: an <c>ocspRefs</c> entry naming MD5 is refused.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESRevocationReferences/CBAdESOcspReference constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task Check_RefsFamilyMd5_OcspReferenceDigest_ReturnsViolation()
    {
        DigestValue digest = await CreateDigestAsync("ocsp md5"u8.ToArray(), TestContext.CancellationToken);
        var ocspIdentifier = new CBAdESOcspIdentifier(new CBAdESOcspResponderIdentifierByName(new byte[] { 0x01 }), DateTimeOffset.UnixEpoch);
        using CBAdESReferences references = new(revocationReferences: new CBAdESRevocationReferences(ocspReferences:
        [
            new CBAdESOcspReference(new AdESDigestAlgorithmTextIdentifier("MD5"), digest, ocspIdentifier)
        ]));
        using CBAdESUnsignedHeaders unsignedHeaders = new([new CBAdESUnsignedHeaderElementReferences(references)]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<CBAdESRuleViolation> violations = CBAdESLevelRules.Check(context);

        var violation = FindViolation<CBAdESRefsFamilyMd5DigestAlgorithmViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(CBAdESRefsFamilyDigestSurface.OcspReferenceDigest, violation!.Surface);
    }


    // EnsureConformant (throw posture, sync rules).

    /// <summary>EnsureConformant does not throw when <see cref="CBAdESLevelRules.Check"/> reports no violations.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are constructor arguments passed straight into the enclosing " +
            "'using CBAdESUnsignedHeaders unsignedHeaders' aggregate's own construction; ownership passes to " +
            "unsignedHeaders, which the local using disposes.")]
    [TestMethod]
    public void EnsureConformant_FullyConformant_DoesNotThrow()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildBaselineContainer(1)))
        ]);
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        CBAdESLevelRules.EnsureConformant(context);
    }


    /// <summary>EnsureConformant throws, naming the first violated clause, when at least one level rule fails.</summary>
    [TestMethod]
    public async Task EnsureConformant_WithViolations_ThrowsNamingFirstViolatedClause()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();
        var context = new CBAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => CBAdESLevelRules.EnsureConformant(context));
        Assert.IsTrue(exception.Message.Contains("CB-", StringComparison.Ordinal));
    }


    // CB-A.1.1-30: refs-to-valData cross-component consistency (async).

    /// <summary>CB-A.1.1-30 does not fire when <c>uHeaders</c> is absent.</summary>
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_NullUnsignedHeaders_ReturnsEmpty()
    {
        IReadOnlyList<CBAdESRuleViolation> violations = await CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            null, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsEmpty(violations);
    }


    /// <summary>CB-A.1.1-30 does not fire when <c>refs</c> is present but no <c>valData</c> element exists — the <c>arcTst</c>-reachable half of the disjunction is covered separately in <c>CBAdESLevelValidationNegativeTests</c>.</summary>
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_ReferencesWithoutValidationData_ReturnsEmpty()
    {
        using CBAdESUnsignedHeaders unsignedHeaders = await BuildReferencesOnlyUnsignedHeadersAsync();

        IReadOnlyList<CBAdESRuleViolation> violations = await CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsEmpty(violations);
    }


    /// <summary>CB-A.1.1-30: a certificate reference whose digest matches a <c>valData</c> certificate resolves — no violation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESCertificateReference/AdESCertificateThumbprint constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_CertificateResolves_ReturnsEmpty()
    {
        byte[] certificateBytes = [0x30, 0x82, 0x01, 0x0A];
        DigestValue referenceDigest = await CreateDigestAsync(certificateBytes, TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        var validationData = new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new AdESPkiObject { Val = certificateBytes })]);
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementValidationData(validationData)
        ]);

        IReadOnlyList<CBAdESRuleViolation> violations = await CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsEmpty(violations);
    }


    /// <summary>CB-A.1.1-30: a certificate reference whose digest matches nothing in <c>valData</c> fails to resolve.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESCertificateReference/AdESCertificateThumbprint constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_CertificateDoesNotResolve_ReturnsViolation()
    {
        DigestValue referenceDigest = await CreateDigestAsync([0x30, 0x82, 0x01, 0x0A], TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        var validationData = new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new AdESPkiObject { Val = new byte[] { 0x30, 0x00 } })]);
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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESRevocationReferences/CBAdESOcspReference constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_OcspDoesNotResolve_ReturnsViolation()
    {
        DigestValue referenceDigest = await CreateDigestAsync("expected ocsp response"u8.ToArray(), TestContext.CancellationToken);
        var ocspIdentifier = new CBAdESOcspIdentifier(new CBAdESOcspResponderIdentifierByName(new byte[] { 0x01 }), DateTimeOffset.UnixEpoch);

        using CBAdESReferences references = new(revocationReferences: new CBAdESRevocationReferences(ocspReferences:
        [
            new CBAdESOcspReference(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest, ocspIdentifier)
        ]));
        var validationData = new CBAdESValidationData(revocationValues: new CBAdESRevocationValues(ocspValues: [new AdESPkiObject { Val = "actual ocsp response"u8.ToArray() }]));
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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESRevocationReferences/CBAdESCrlReference constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_UnknownAlgorithm_FailsClosedAsUnresolved()
    {
        DigestValue referenceDigest = await CreateDigestAsync("crl bytes"u8.ToArray(), TestContext.CancellationToken);

        using CBAdESReferences references = new(revocationReferences: new CBAdESRevocationReferences(crlReferences:
        [
            new CBAdESCrlReference(new AdESDigestAlgorithmIntegerIdentifier(-999999), referenceDigest)
        ]));
        var validationData = new CBAdESValidationData(revocationValues: new CBAdESRevocationValues(crlValues: [new AdESPkiObject { Val = "crl bytes"u8.ToArray() }]));
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
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESCertificateReference/AdESCertificateThumbprint constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task EnsureReferencesResolveToValidationDataAsync_AllResolve_DoesNotThrow()
    {
        byte[] certificateBytes = [0x30, 0x01];
        DigestValue referenceDigest = await CreateDigestAsync(certificateBytes, TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        var validationData = new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new AdESPkiObject { Val = certificateBytes })]);
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementValidationData(validationData)
        ]);

        await CBAdESLevelRules.EnsureReferencesResolveToValidationDataAsync(unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken);
    }


    /// <summary>EnsureReferencesResolveToValidationDataAsync throws, naming CB-A.1.1-30, when a reference fails to resolve.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESCertificateReference/AdESCertificateThumbprint constructions are " +
            "constructor arguments passed straight into the enclosing 'using CBAdESReferences references' " +
            "aggregate's own construction, which the local using disposes; the flagged " +
            "CBAdESUnsignedHeaderElementReferences(references) wraps that already-using-scoped instance for the " +
            "enclosing 'using CBAdESUnsignedHeaders unsignedHeaders' aggregate (idempotent Dispose makes the " +
            "double ownership safe).")]
    [TestMethod]
    public async Task EnsureReferencesResolveToValidationDataAsync_UnresolvedReference_ThrowsNamingClause()
    {
        DigestValue referenceDigest = await CreateDigestAsync([0x30, 0x82], TestContext.CancellationToken);

        using CBAdESReferences references = new(certificateReferences:
        [
            new CBAdESCertificateReference(new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest))
        ]);
        var validationData = new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new AdESPkiObject { Val = new byte[] { 0x30, 0x00 } })]);
        using CBAdESUnsignedHeaders unsignedHeaders = new(
        [
            new CBAdESUnsignedHeaderElementReferences(references),
            new CBAdESUnsignedHeaderElementValidationData(validationData)
        ]);

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await CBAdESLevelRules.EnsureReferencesResolveToValidationDataAsync(unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.IsTrue(exception.Message.Contains("CB-A.1.1-30", StringComparison.Ordinal));
    }


    // Raw-uHeaders wire-bytes capture (CBAdESSignatureSerialization.ParseCBAdESSign1 / CBAdESSign1ParseResult).

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


    /// <summary>A malformed <c>uHeaders</c> value fails the whole parse closed — <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/> is disposed and not surfaced on the failed result.</summary>
    [TestMethod]
    public void ParseCBAdESSign1_MalformedUHeaders_FailsClosedWithNoRawCapture()
    {
        //An empty array violates CB-5.3.1-07 (uHeaders shall be non-empty) -- TryParseUnsignedHeaders rejects
        //it, so the whole parse fails closed.
        var emptyArrayWriterBuffer = new ArrayBufferWriter<byte>();
        var emptyArrayWriter = new CborWriter(emptyArrayWriterBuffer, CborOptions.RfcCanonical);
        emptyArrayWriter.WriteStartArray(0);
        emptyArrayWriter.WriteEndArray();
        byte[] malformedUHeadersBytes = emptyArrayWriterBuffer.WrittenSpan.ToArray();

        byte[] wireBytes = BuildCoseSign1WireBytes(malformedUHeadersBytes);

        CBAdESSign1ParseResult result = CBAdESSignatureSerialization.ParseCBAdESSign1(wireBytes, BaseMemoryPool.Shared);
        using(result)
        {
            Assert.IsFalse(result.IsSuccess);
            Assert.IsNull(result.RawUnsignedHeaders);
        }
    }


    // Adapter-equivalence: the three new imprint-input seams over CBAdESLevelMessageImprintAdapters.

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


    /// <summary>Builds a conformant, single-token RFC 3161-shaped <see cref="AdESTimestampContainer"/> with <paramref name="tokenCount"/> tokens (repeats the same fixture value for every token to exercise CB-6.3-c independent of token content).</summary>
    /// <param name="tokenCount">The number of tokens to encapsulate.</param>
    /// <returns>The built container.</returns>
    private static AdESTimestampContainer BuildBaselineContainer(int tokenCount)
    {
        var tokens = new List<AdESTimestampToken>(tokenCount);
        for(int i = 0; i < tokenCount; ++i)
        {
            tokens.Add(new AdESTimestampToken { Val = new byte[] { (byte)(0x10 + i) } });
        }

        return new AdESTimestampContainer(tokens);
    }


    /// <summary>Builds a minimal <see cref="CBAdESReferences"/> instance (one certificate reference) for generation-gate fixtures.</summary>
    /// <returns>The built <c>refs</c> element.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESCertificateReference/AdESCertificateThumbprint constructions are " +
            "constructor arguments passed straight into the returned CBAdESReferences aggregate's own " +
            "construction; ownership transfers to the returned value, which the caller disposes.")]
    private static async ValueTask<CBAdESReferences> BuildMinimalReferencesAsync()
    {
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>("minimal refs fixture"u8.ToArray()), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared).ConfigureAwait(false);

        return new CBAdESReferences(certificateReferences:
        [
            new CBAdESCertificateReference(new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest))
        ]);
    }


    /// <summary>Builds a one-element <see cref="CBAdESUnsignedHeaders"/> carrying only a <c>refs</c> element — the shared fixture behind the "refs present with no sigTst" scenarios.</summary>
    /// <returns>The built <c>uHeaders</c> set. Owned by the caller.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged CBAdESUnsignedHeaderElementReferences construction is a constructor " +
            "argument passed straight into the returned CBAdESUnsignedHeaders aggregate's own construction; " +
            "ownership transfers to the returned value, which the caller disposes.")]
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
        var docOrLocalUriWriterBuffer = new ArrayBufferWriter<byte>();
        var docOrLocalUriWriter = new CborWriter(docOrLocalUriWriterBuffer, CborOptions.RfcCanonical);
        docOrLocalUriWriter.WriteStartMap(1);
        docOrLocalUriWriter.WriteInt32(2);
        docOrLocalUriWriter.WriteTag(new CborTag((ulong)32));
        docOrLocalUriWriter.WriteTextString("https://policy.example.org/sp");
        docOrLocalUriWriter.WriteEndMap();
        byte[] docOrLocalUriBytes = docOrLocalUriWriterBuffer.WrittenSpan.ToArray();

        //sigPSt map: {1: DocOrLocalURI} (Table 9).
        var sigPStWriterBuffer = new ArrayBufferWriter<byte>();
        var sigPStWriter = new CborWriter(sigPStWriterBuffer, CborOptions.RfcCanonical);
        sigPStWriter.WriteStartMap(1);
        sigPStWriter.WriteInt32(1);
        sigPStWriter.WriteEncodedValue(docOrLocalUriBytes);
        sigPStWriter.WriteEndMap();
        byte[] sigPStBytes = sigPStWriterBuffer.WrittenSpan.ToArray();

        //UHeaderInstance one-entry map: {7: sigPSt} (Table 8, sigPSt label 7).
        var uHeaderInstanceWriterBuffer = new ArrayBufferWriter<byte>();
        var uHeaderInstanceWriter = new CborWriter(uHeaderInstanceWriterBuffer, CborOptions.RfcCanonical);
        uHeaderInstanceWriter.WriteStartMap(1);
        uHeaderInstanceWriter.WriteInt32(7);
        uHeaderInstanceWriter.WriteEncodedValue(sigPStBytes);
        uHeaderInstanceWriter.WriteEndMap();
        byte[] uHeaderInstanceBytes = uHeaderInstanceWriterBuffer.WrittenSpan.ToArray();

        //uHeaders = [+bstr .cbor UHeaderInstance] (clause 5.3.1).
        var uHeadersWriterBuffer = new ArrayBufferWriter<byte>();
        var uHeadersWriter = new CborWriter(uHeadersWriterBuffer, CborOptions.RfcCanonical);
        uHeadersWriter.WriteStartArray(1);
        uHeadersWriter.WriteByteString(uHeaderInstanceBytes);
        uHeadersWriter.WriteEndArray();

        return uHeadersWriterBuffer.WrittenSpan.ToArray();
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
        var protectedHeaderWriterBuffer = new ArrayBufferWriter<byte>();
        var protectedHeaderWriter = new CborWriter(protectedHeaderWriterBuffer, CborOptions.RfcCanonical);
        protectedHeaderWriter.WriteStartMap(1);
        protectedHeaderWriter.WriteInt32(1); //alg (RFC 9052 section 3.1, label 1).
        protectedHeaderWriter.WriteInt32(-7); //an arbitrary IANA COSE Algorithms identifier (ES256).
        protectedHeaderWriter.WriteEndMap();
        byte[] protectedHeaderBytes = protectedHeaderWriterBuffer.WrittenSpan.ToArray();

        var messageWriterBuffer = new ArrayBufferWriter<byte>();
        var messageWriter = new CborWriter(messageWriterBuffer, CborOptions.RfcCanonical);
        messageWriter.WriteTag(new CborTag((ulong)18)); //COSE_Sign1_Tagged (RFC 9052 section 2, clause 4.3).
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

        return messageWriterBuffer.WrittenSpan.ToArray();
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

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the JAdES level-scoped rule surface (<see cref="JAdESLevelRules"/>) in both postures, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 6.3 (Table 1) and Annex A.
/// </summary>
/// <remarks>
/// Every fixture is built directly from the shipped model constructors, never re-implementing a
/// parsed-value assertion against the rule surface's own internals. Every <see cref="DigestValue"/> a fixture
/// carries is a real, pool-owned digest buffer, mirroring <c>JAdESMessageImprintTests</c>'s own convention.
/// Fixture-builder helpers hand every disposable construction straight to the caller's own <c>using</c> chain
/// (elements into a <c>using JAdESUnsignedHeaders</c> container, headers/digests into a caller-owned local) —
/// CA2000 is suppressed at each such helper/test with a justification naming the transfer, mirroring the
/// convention <c>JAdESUnsignedHeaderElementTests</c>/<c>CBAdESLevelRulesTests</c> already use.
/// </remarks>
[TestClass]
internal sealed class JAdESLevelRulesTests
{
    // JA-6.3-26: sigTst presence at B-T+.

    /// <summary>JA-6.3-26: at level B-T with no <c>sigTst</c> element anywhere in <c>etsiU</c>, <see cref="JAdESLevelRules.Check"/> reports a violation.</summary>
    [TestMethod]
    public void Check_SignatureTimestampMissing_AtLevelBTWithNoSigTst_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = BuildUnknownOnlyUnsignedHeaders();
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<JAdESSignatureTimestampMissingViolation>(violations));
    }


    /// <summary>JA-6.3-26: at level B-B, the absence of <c>sigTst</c> is legal ("*" — should-not, not shall-not) — no violation.</summary>
    [TestMethod]
    public void Check_SignatureTimestampMissing_AtLevelBBWithNoSigTst_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = BuildUnknownOnlyUnsignedHeaders();
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESSignatureTimestampMissingViolation>(violations));
    }


    /// <summary>JA-6.3-26: at level B-T with a conformant single-token <c>sigTst</c> present, no violation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeSigTstElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_SignatureTimestampPresent_AtLevelBT_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeSigTstElement(tokenCount: 1)]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsEmpty(violations);
    }


    // Letter c: exactly one token per sigTst instance.

    /// <summary>Letter c: a <c>sigTst</c> instance encapsulating two tokens violates the one-token rule.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-c.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeSigTstElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_SignatureTimestampTokenCount_TwoTokens_ReturnsViolationWithCount()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeSigTstElement(tokenCount: 2)]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        var violation = FindViolation<JAdESSignatureTimestampTokenCountViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(2, violation!.TokenCount);
    }


    /// <summary>
    /// This structural rule surface pattern-matches only the clear arm (<see cref="JAdESClearUnsignedValue{TValue}"/>)
    /// for token-count/shape checks, so an opaque-mode <c>sigTst</c> carriage's token-count rule is silently
    /// skipped — read-tolerant, never a false violation — regardless of what its own decoded view now holds
    /// (the decode-for-inspection view is consulted by <c>JAdESSignatureValidation</c>'s CMS+imprint pass, not
    /// this purely-structural surface).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element/carriage constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_SignatureTimestampTokenCount_OpaqueCarriage_NeverChecked()
    {
        using PooledMemory wireText = PooledMemory.FromBytes([0x01, 0x02, 0x03], BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement);
        using var element = new JAdESUnsignedHeaderElementSignatureTimestamp(new JAdESOpaqueUnsignedValue<AdESTimestampContainer>(wireText, default!));
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.Base64Url, [element]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESSignatureTimestampTokenCountViolation>(violations));
        Assert.IsFalse(HasViolation<JAdESTimestampTokenNotBaselineViolation>(violations));
    }


    // JA-6.3-03: baseline TstToken narrowing (RFC 3161 legacy shape only).

    /// <summary>JA-6.3-03: a <c>sigTst</c> token carrying a <c>type</c> member is not the RFC 3161 legacy shape.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged container/element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_TimestampTokenNotBaseline_SigTstWithTypedToken_ReturnsViolation()
    {
        var container = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x01 }, Type = "other-format" }]);
        using var element = new JAdESUnsignedHeaderElementSignatureTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(container));
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [element]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        var violation = FindViolation<JAdESTimestampTokenNotBaselineViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(JAdESTimestampContainerKind.SignatureTimestamp, violation!.Kind);
    }


    /// <summary>JA-6.3-03: <c>adoTst</c> (the SIGNED payload time-stamp) is checked too, even though it is unreachable through the <c>etsiU</c> loop.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-24.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged AdESTimestampContainer/JAdESProtectedHeaders constructions are handed to the caller's own local variable, which the test's own short lifetime does not require disposing (matching this file's fixture-scoped convention elsewhere).")]
    [TestMethod]
    public void Check_TimestampTokenNotBaseline_AdoTstWithEncodingMember_ReturnsViolation()
    {
        var container = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x01 }, Encoding = "base64" }]);
        var headers = MakeProtectedHeaders(payloadTimestamps: container);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, ProtectedHeaders = headers };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        var violation = FindViolation<JAdESTimestampTokenNotBaselineViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(JAdESTimestampContainerKind.PayloadTimestamp, violation!.Kind);
    }


    // JA-6.3-42: arcTst presence at B-LTA.

    /// <summary>JA-6.3-42: at level B-LTA with no <c>arcTst</c> instance, <see cref="JAdESLevelRules.Check"/> reports a violation.</summary>
    [TestMethod]
    public void Check_ArchiveTimestampMissing_AtLevelBLTAWithNoArcTst_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = BuildUnknownOnlyUnsignedHeaders();
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BLTA, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<JAdESArchiveTimestampMissingViolation>(violations));
    }


    /// <summary>JA-6.3-42: below B-LTA, the absence of <c>arcTst</c> is legal — no violation.</summary>
    [TestMethod]
    public void Check_ArchiveTimestampMissing_AtLevelBLTWithNoArcTst_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = BuildUnknownOnlyUnsignedHeaders();
        var context = new JAdESLevelRuleContext
        {
            Level = AdESBaselineLevel.BLT,
            UnsignedHeaders = unsignedHeaders,
            AnyTimestampTokenCarriesEmbeddedValidationMaterial = true
        };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESArchiveTimestampMissingViolation>(violations));
    }


    // The refs family: hard-forbidden from B-LT onward.

    /// <summary>An <c>xRefs</c> element present at B-LT is forbidden (JA-6.3-29).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-33.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeClearXRefsElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_RefsFamilyForbidden_XRefsAtBLT_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeClearXRefsElement()]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        var violation = FindViolation<JAdESRefsFamilyForbiddenViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(JAdESRefsFamilyKind.CertificateReferences, violation!.Kind);
        Assert.AreEqual("JA-6.3-29", violation.RequirementId);
    }


    /// <summary>An <c>xRefs</c> element at B-T is legal — no forbidden violation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeClearXRefsElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_RefsFamilyForbidden_XRefsAtBT_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeClearXRefsElement()]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESRefsFamilyForbiddenViolation>(violations));
    }


    /// <summary>An <c>arRefs</c> element present at B-LTA is forbidden (JA-6.3-35).</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeClearArRefsElement's result is a constructor argument passed into the enclosing 'using JAdESUnsignedHeaders' container; MakeProtectedHeaders's result is handed to a caller-owned local, matching this file's fixture-scoped convention.")]
    [TestMethod]
    public void Check_RefsFamilyForbidden_ArRefsAtBLTA_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeClearArRefsElement()]);
        var headers = MakeProtectedHeaders(withAttributeCertificate: true);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BLTA, UnsignedHeaders = unsignedHeaders, ProtectedHeaders = headers };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        var violation = FindViolation<JAdESRefsFamilyForbiddenViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(JAdESRefsFamilyKind.AttributeRevocationReferences, violation!.Kind);
    }


    // JA-A.1.5.1.1-04/JA-A.1.5.2.1-04: sigRTst/rfsTst generation gate.

    /// <summary>A <c>sigRTst</c> element with no <c>refs</c>-family element anywhere in <c>etsiU</c> violates the generation gate.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-36.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeSigRTstElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_ReferencesTimestampGenerationGate_SigRTstWithNoRefsFamily_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeSigRTstElement()]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        var violation = FindViolation<JAdESReferencesTimestampGenerationGateViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(JAdESReferencesTimestampGenerationKind.SignatureAndReferences, violation!.Kind);
    }


    /// <summary>A <c>rfsTst</c> element with an <c>xRefs</c> element present anywhere in <c>etsiU</c> satisfies the generation gate.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-37.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeRfsTstElement/MakeClearXRefsElement's results are constructor arguments passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_ReferencesTimestampGenerationGate_RfsTstWithXRefsPresent_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeRfsTstElement(), MakeClearXRefsElement()]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESReferencesTimestampGenerationGateViolation>(violations));
    }


    // Letter b: sigPSt gate.

    /// <summary>Letter b: a <c>sigPSt</c> element with no <c>sigPId</c> at all violates the gate.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-25, JA-6.3-b2.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeSigPStElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_SignaturePolicyStoreGate_NoSigPId_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeSigPStElement()]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<JAdESSignaturePolicyStoreGateViolation>(violations));
    }


    /// <summary>Letter b: a <c>sigPSt</c> element with a <c>sigPId</c> present but lacking <c>digVal</c> violates the gate.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeSigPStElement's result is a constructor argument passed into the enclosing 'using JAdESUnsignedHeaders' container; MakeProtectedHeaders's result is handed to a caller-owned local, matching this file's fixture-scoped convention.")]
    [TestMethod]
    public void Check_SignaturePolicyStoreGate_SigPIdWithoutDigest_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeSigPStElement()]);
        var headers = MakeProtectedHeaders(signaturePolicyIdentifierDigest: null);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders, ProtectedHeaders = headers };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<JAdESSignaturePolicyStoreGateViolation>(violations));
    }


    /// <summary>Letter b: a <c>sigPSt</c> element with a <c>sigPId</c> carrying <c>digVal</c> satisfies the gate.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-22, JA-6.3-b1.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeSigPStElement's result is a constructor argument passed into the enclosing 'using JAdESUnsignedHeaders' container; MakeDigestValue/MakeProtectedHeaders's results are handed to caller-owned locals, matching this file's fixture-scoped convention.")]
    [TestMethod]
    public void Check_SignaturePolicyStoreGate_SigPIdWithDigest_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeSigPStElement()]);
        var headers = MakeProtectedHeaders(signaturePolicyIdentifierDigest: MakeDigestValue([0x01]));
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders, ProtectedHeaders = headers };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESSignaturePolicyStoreGateViolation>(violations));
    }


    // Letter h: axRefs/arRefs gate.

    /// <summary>Letter h: an <c>axRefs</c> element with no attribute certificate/signed assertion incorporated violates the gate.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-31, JA-6.3-h2.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeClearAxRefsElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_AttributeReferencesGate_NoAttributeCertificateOrSignedAssertion_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeClearAxRefsElement()]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        var violation = FindViolation<JAdESAttributeReferencesGateViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(JAdESAttributeReferencesKind.AttributeCertificateReferences, violation!.Kind);
    }


    /// <summary>Letter h: signer-CLAIMED attributes alone do not satisfy the gate — only certified attribute certificates/signed assertions do.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeClearAxRefsElement's result is a constructor argument passed into the enclosing 'using JAdESUnsignedHeaders' container; MakeProtectedHeaders's result is handed to a caller-owned local, matching this file's fixture-scoped convention.")]
    [TestMethod]
    public void Check_AttributeReferencesGate_OnlyClaimedAttributes_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeClearAxRefsElement()]);
        var headers = MakeProtectedHeaders(withClaimedAttributeOnly: true);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders, ProtectedHeaders = headers };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<JAdESAttributeReferencesGateViolation>(violations));
    }


    /// <summary>Letter h: an <c>axRefs</c> element with a certified attribute certificate incorporated satisfies the gate.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-h1.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeClearAxRefsElement's result is a constructor argument passed into the enclosing 'using JAdESUnsignedHeaders' container; MakeProtectedHeaders's result is handed to a caller-owned local, matching this file's fixture-scoped convention.")]
    [TestMethod]
    public void Check_AttributeReferencesGate_WithAttributeCertificate_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeClearAxRefsElement()]);
        var headers = MakeProtectedHeaders(withAttributeCertificate: true);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BB, UnsignedHeaders = unsignedHeaders, ProtectedHeaders = headers };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESAttributeReferencesGateViolation>(violations));
    }


    // Letter j: the validation-data-for-time-stamps service, evaluated from B-LT onward.

    /// <summary>Letter j: at B-LT with none of <c>tstVD</c>/<c>anyValData</c>/embedded satisfied, the service violates.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-38, JA-6.3-j.
    /// </remarks>
    [TestMethod]
    public void Check_TimestampValidationDataService_AtBLTWithNoneSatisfied_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = BuildUnknownOnlyUnsignedHeaders();
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<JAdESTimestampValidationDataServiceViolation>(violations));
    }


    /// <summary>Letter j: an <c>anyValData</c> element anywhere in <c>etsiU</c> satisfies the service.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-28.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeAnyValDataElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_TimestampValidationDataService_AtBLTWithAnyValData_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeAnyValDataElement()]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESTimestampValidationDataServiceViolation>(violations));
    }


    //Check_TimestampValidationDataService_AtBLTWithEmbeddedFlag_NoViolation is RETIRED (the letter-j
    //inversion): a hand-set
    //AnyTimestampTokenCarriesEmbeddedValidationMaterial flag was, before the both-modes fix, the ONLY
    //path in the whole suite proving the embedded-in-token SPO could satisfy JA-6.3-38/j at all -- a real
    //base64url-mode signature could never reach it (the validation loop never ran under Base64Url), so this
    //isolated rule-surface unit test masked rather than proved the letter-j service. JAdESLifecycleFlowTests'
    //own AddSignatureTimestampBase64UrlModeThenValidatesAtBTRelyingSolelyOnEmbeddedCertificates now proves the
    //SAME fact end-to-end, from wire bytes, with a REAL CMS-embedded-certificate token in base64url mode.


    /// <summary>Letter j: below B-LT, the service is not evaluated at all.</summary>
    [TestMethod]
    public void Check_TimestampValidationDataService_AtBT_NeverEvaluated()
    {
        using JAdESUnsignedHeaders unsignedHeaders = BuildUnknownOnlyUnsignedHeaders();
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESTimestampValidationDataServiceViolation>(violations));
    }


    // JA-A.1.1-02: the signing-certificate exclusion.

    /// <summary>JA-A.1.1-02: an <c>xRefs</c> entry whose digest matches a caller-supplied signing-certificate digest is excluded.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeClearXRefsElement's result is a constructor argument passed into the enclosing 'using JAdESUnsignedHeaders' container; the signing-certificate DigestValue has its own local 'using'.")]
    [TestMethod]
    public void Check_ReferencesSigningCertificateExclusion_MatchingDigest_ReturnsViolation()
    {
        byte[] signingCertificateDigestBytes = [0xAA, 0xBB, 0xCC];
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeClearXRefsElement(digestBytes: signingCertificateDigestBytes)]);
        using DigestValue signingCertificateDigest = MakeDigestValue(signingCertificateDigestBytes);
        var context = new JAdESLevelRuleContext
        {
            Level = AdESBaselineLevel.BT,
            UnsignedHeaders = unsignedHeaders,
            SigningCertificateDigests = [signingCertificateDigest]
        };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsTrue(HasViolation<JAdESReferencesSigningCertificateExclusionViolation>(violations));
    }


    /// <summary>JA-A.1.1-02: a non-matching <c>xRefs</c> entry does not violate the exclusion.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeClearXRefsElement's result is a constructor argument passed into the enclosing 'using JAdESUnsignedHeaders' container; the signing-certificate DigestValue has its own local 'using'.")]
    [TestMethod]
    public void Check_ReferencesSigningCertificateExclusion_NonMatchingDigest_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeClearXRefsElement(digestBytes: [0x01, 0x02, 0x03])]);
        using DigestValue signingCertificateDigest = MakeDigestValue([0xFF, 0xFF, 0xFF]);
        var context = new JAdESLevelRuleContext
        {
            Level = AdESBaselineLevel.BT,
            UnsignedHeaders = unsignedHeaders,
            SigningCertificateDigests = [signingCertificateDigest]
        };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESReferencesSigningCertificateExclusionViolation>(violations));
    }


    // JA-6.2.1-02: MD5 is refused as a digest algorithm across the refs family.

    /// <summary>JA-6.2.1-02: an <c>xRefs</c> entry naming MD5 (case-insensitively) is refused.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeClearXRefsElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_RefsFamilyMd5_XRefsNamesMd5CaseInsensitively_ReturnsViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeClearXRefsElement(hashAlgorithm: "md5")]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        var violation = FindViolation<JAdESRefsFamilyMd5DigestAlgorithmViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(JAdESRefsFamilyDigestSurface.CertificateReferences, violation!.Surface);
    }


    /// <summary>JA-6.2.1-02: a <c>rRefs</c> CRL reference naming MD5 is refused.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged thumbprint/values/element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_RefsFamilyMd5_RRefsCrlReferenceNamesMd5_ReturnsViolation()
    {
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("MD5"), MakeDigestValue([0x01]));
        var values = new JAdESRevocationReferenceCollection(crlReferences: [thumbprint]);
        using var element = new JAdESUnsignedHeaderElementRevocationReferences(new JAdESClearUnsignedValue<JAdESRevocationReferenceCollection>(values));
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [element]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        var violation = FindViolation<JAdESRefsFamilyMd5DigestAlgorithmViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(JAdESRefsFamilyDigestSurface.RevocationReferences, violation!.Surface);
    }


    /// <summary>A SHA-256-named <c>xRefs</c> entry does not trigger the MD5 refusal.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeClearXRefsElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_RefsFamilyMd5_Sha256Named_NoViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeClearXRefsElement(hashAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256")]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);

        Assert.IsFalse(HasViolation<JAdESRefsFamilyMd5DigestAlgorithmViolation>(violations));
    }


    // cSig / unknown: explicit no-op arms.

    /// <summary>A <c>cSig</c> element is never itself a level violation, at any level.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-23.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeCSigElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void Check_CounterSignaturePresent_AtEveryLevel_NeverAViolationOnItsOwnAccount()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.Base64Url,
            [MakeCSigElement()]);

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            var context = new JAdESLevelRuleContext
            {
                Level = level,
                UnsignedHeaders = unsignedHeaders,
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = true
            };

            IReadOnlyList<JAdESRuleViolation> violations = JAdESLevelRules.Check(context);
            bool triggersOwnAccountViolation = violations.Any(v => v is JAdESRefsFamilyForbiddenViolation or JAdESAttributeReferencesGateViolation);

            Assert.IsFalse(triggersOwnAccountViolation, $"cSig's own presence must never itself trigger a level violation at {level}.");
        }
    }


    /// <summary><see cref="JAdESLevelRules.EnsureConformant"/> is silent when <see cref="JAdESLevelRules.Check"/> finds nothing.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MakeSigTstElement's result is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void EnsureConformant_FullyConformantContext_DoesNotThrow()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeSigTstElement(tokenCount: 1)]);
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BT, UnsignedHeaders = unsignedHeaders };

        JAdESLevelRules.EnsureConformant(context);
    }


    /// <summary><see cref="JAdESLevelRules.EnsureConformant"/> raises <see cref="ArgumentException"/> naming the first violated clause, with a further-violations suffix when more than one applies.</summary>
    [TestMethod]
    public void EnsureConformant_NonConformantContext_ThrowsNamingFirstViolation()
    {
        using JAdESUnsignedHeaders unsignedHeaders = BuildUnknownOnlyUnsignedHeaders();
        var context = new JAdESLevelRuleContext { Level = AdESBaselineLevel.BLTA, UnsignedHeaders = unsignedHeaders };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => JAdESLevelRules.EnsureConformant(context));

        Assert.Contains("JA-6.3-26", exception.Message, "sigTst is the first-declared missing-instance rule.");
    }


    /// <summary>Whether <paramref name="violations"/> contains at least one instance of <typeparamref name="TViolation"/>.</summary>
    private static bool HasViolation<TViolation>(IReadOnlyList<JAdESRuleViolation> violations)
        where TViolation : JAdESRuleViolation =>
        violations.Any(v => v is TViolation);


    /// <summary>Finds the first instance of <typeparamref name="TViolation"/> in <paramref name="violations"/>, or <see langword="null"/>.</summary>
    private static TViolation? FindViolation<TViolation>(IReadOnlyList<JAdESRuleViolation> violations)
        where TViolation : JAdESRuleViolation =>
        violations.OfType<TViolation>().FirstOrDefault();


    /// <summary>Builds a minimal, non-empty <c>etsiU</c> container carrying only the unknown catch-all — a baseline fixture no rule in this file reacts to on its own.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element is a constructor argument passed straight into the enclosing 'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, which the caller's local using disposes.")]
    private static JAdESUnsignedHeaders BuildUnknownOnlyUnsignedHeaders()
    {
        using PooledMemory wireText = PooledMemory.FromBytes([0x01], BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement);
        return new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, [new JAdESUnsignedHeaderElementUnknown("x-unused", wireText)]);
    }


    /// <summary>Builds a clear-mode <c>sigTst</c> element with <paramref name="tokenCount"/> tokens, never carrying <c>canonAlg</c> (JA-5.3.4-05).</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged container/carriage constructions are passed straight into the returned element's own construction; ownership passes to that element, which every caller places into a 'using JAdESUnsignedHeaders' container.")]
    private static JAdESUnsignedHeaderElementSignatureTimestamp MakeSigTstElement(int tokenCount)
    {
        var tokens = new AdESTimestampToken[tokenCount];
        for(int i = 0; i < tokenCount; ++i)
        {
            tokens[i] = new AdESTimestampToken { Val = new byte[] { (byte)i } };
        }

        var container = new AdESTimestampContainer(tokens);
        return new JAdESUnsignedHeaderElementSignatureTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(container));
    }


    /// <summary>Builds a clear-mode <c>sigRTst</c> element, carrying <c>canonAlg</c> (required under a ClearJson container, JA-5.3.1-14).</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged container/carriage constructions are passed straight into the returned element's own construction; ownership passes to that element, which every caller places into a 'using JAdESUnsignedHeaders' container.")]
    private static JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp MakeSigRTstElement()
    {
        var container = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x01 } }], canonAlg: "http://example.org/canon");
        return new JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(container));
    }


    /// <summary>Builds a clear-mode <c>rfsTst</c> element, carrying <c>canonAlg</c> (required under a ClearJson container, JA-5.3.1-14).</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged container/carriage constructions are passed straight into the returned element's own construction; ownership passes to that element, which every caller places into a 'using JAdESUnsignedHeaders' container.")]
    private static JAdESUnsignedHeaderElementReferencesTimestamp MakeRfsTstElement()
    {
        var container = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x01 } }], canonAlg: "http://example.org/canon");
        return new JAdESUnsignedHeaderElementReferencesTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(container));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged thumbprint/values/carriage constructions are passed straight into the returned element's own construction; ownership passes to that element, which every caller places into a 'using JAdESUnsignedHeaders' container.")]
    private static JAdESUnsignedHeaderElementCertificateReferences MakeClearXRefsElement(byte[]? digestBytes = null, string hashAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256")
    {
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier(hashAlgorithm), MakeDigestValue(digestBytes ?? [0x01, 0x02, 0x03]));
        var values = new JAdESCertificateReferenceCollection([thumbprint]);
        return new JAdESUnsignedHeaderElementCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(values));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged thumbprint/values/carriage constructions are passed straight into the returned element's own construction; ownership passes to that element, which every caller places into a 'using JAdESUnsignedHeaders' container.")]
    private static JAdESUnsignedHeaderElementAttributeCertificateReferences MakeClearAxRefsElement()
    {
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("http://www.w3.org/2001/04/xmlenc#sha256"), MakeDigestValue([0x04, 0x05, 0x06]));
        var values = new JAdESCertificateReferenceCollection([thumbprint]);
        return new JAdESUnsignedHeaderElementAttributeCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(values));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged thumbprint/values/carriage constructions are passed straight into the returned element's own construction; ownership passes to that element, which every caller places into a 'using JAdESUnsignedHeaders' container.")]
    private static JAdESUnsignedHeaderElementAttributeRevocationReferences MakeClearArRefsElement()
    {
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("http://www.w3.org/2001/04/xmlenc#sha256"), MakeDigestValue([0x07, 0x08, 0x09]));
        var values = new JAdESRevocationReferenceCollection(crlReferences: [thumbprint]);
        return new JAdESUnsignedHeaderElementAttributeRevocationReferences(new JAdESClearUnsignedValue<JAdESRevocationReferenceCollection>(values));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged content/store/carriage constructions are passed straight into the returned element's own construction; ownership passes to that element, which every caller places into a 'using JAdESUnsignedHeaders' container.")]
    private static JAdESUnsignedHeaderElementSignaturePolicyStore MakeSigPStElement()
    {
        var content = new JAdESSignaturePolicyStoreLocalUri(new Uri("file:///policy.der"));
        var store = new JAdESSignaturePolicyStore(content);
        return new JAdESUnsignedHeaderElementSignaturePolicyStore(new JAdESClearUnsignedValue<JAdESSignaturePolicyStore>(store));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged values/carriage constructions are passed straight into the returned element's own construction; ownership passes to that element, which every caller places into a 'using JAdESUnsignedHeaders' container.")]
    private static JAdESUnsignedHeaderElementAnyValidationData MakeAnyValDataElement()
    {
        var certificate = new JAdESX509Certificate(new AdESPkiObject { Val = new byte[] { 0x01, 0x02 } });
        var values = new JAdESValidationData(certificateValues: new JAdESCertificateValues([certificate]));
        return new JAdESUnsignedHeaderElementAnyValidationData(new JAdESClearUnsignedValue<JAdESValidationData>(values));
    }


    private static JAdESUnsignedHeaderElementCounterSignature MakeCSigElement() =>
        new(PooledMemory.FromBytes([0x01], BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement));


    /// <summary>
    /// Builds a minimal <see cref="JAdESProtectedHeaders"/> fixture, populating only the members a given test
    /// needs.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions (thumbprints, digests, attribute lists) are constructor " +
            "arguments passed straight into the returned JAdESProtectedHeaders instance's own construction; " +
            "ownership passes to that instance, which the caller's local variable is responsible for.")]
    private static JAdESProtectedHeaders MakeProtectedHeaders(
        DigestValue? signaturePolicyIdentifierDigest = null,
        bool withAttributeCertificate = false,
        bool withClaimedAttributeOnly = false,
        AdESTimestampContainer? payloadTimestamps = null)
    {
        AdESSignaturePolicyIdentifier? signaturePolicyIdentifier = null;
        if(signaturePolicyIdentifierDigest is not null)
        {
            signaturePolicyIdentifier = new AdESSignaturePolicyIdentifier(
                new AdESObjectIdentifier("urn:example:policy"),
                hashAlgorithm: new AdESDigestAlgorithmTextIdentifier("http://www.w3.org/2001/04/xmlenc#sha256"),
                digest: signaturePolicyIdentifierDigest);
        }

        AdESSignerAttributes? signerAttributes = null;
        if(withAttributeCertificate)
        {
            var certificate = new AdESX509AttributeCertificate(new AdESPkiObject { Val = new byte[] { 0x0A } });
            signerAttributes = new AdESSignerAttributes(certified: [certificate]);
        }
        else if(withClaimedAttributeOnly)
        {
            var claimed = new JAdESQualifyingAttribute("application/json", "utf-8", ["value"]);
            signerAttributes = new AdESSignerAttributes(claimed: [claimed]);
        }

        DigestValue? digestForCertificateIdentification = signaturePolicyIdentifierDigest is null && payloadTimestamps is null
            ? MakeDigestValue([0x00])
            : null;

        return new JAdESProtectedHeaders(
            algorithm: WellKnownJwaValues.Es256,
            x5tHashS256: digestForCertificateIdentification,
            signaturePolicyIdentifier: signaturePolicyIdentifier,
            signerAttributes: signerAttributes,
            payloadTimestamps: payloadTimestamps);
    }


    private static DigestValue MakeDigestValue(byte[] bytes)
    {
        var owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }
}

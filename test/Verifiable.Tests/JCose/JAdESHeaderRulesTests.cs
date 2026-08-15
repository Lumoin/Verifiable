using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Coverage for <see cref="JAdESHeaderRules"/> — the JAdES B-B cross-header rule surface over clause 5.1
/// and clause 5.2, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>.
/// </summary>
[TestClass]
internal sealed class JAdESHeaderRulesTests
{
    /// <summary>A minimal, fully B-B-conformant header set (attached payload, no <c>sigD</c>) reports no violation.</summary>
    [TestMethod]
    public void FullyConformantHeadersReportNoViolation()
    {
        using JAdESProtectedHeaders headers = ConformantHeaders();

        IReadOnlyList<JAdESRuleViolation> violations = JAdESHeaderRules.Check(headers, payloadIsDetached: false);

        Assert.IsEmpty(violations);
        JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: false);
    }


    /// <summary>None of the four signing-certificate-identification options present throws citing JA-5.1.7-04.</summary>
    [TestMethod]
    public void NoSigningCertificateIdentificationThrows()
    {
        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch));

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: false));

        Assert.Contains("JA-5.1.7-04", exception.Message);
    }


    /// <summary>A present <c>cty</c> with a caller-attested countersigned-signature payload throws citing JA-5.1.3-05.</summary>
    [TestMethod]
    public void ContentTypeWithCountersignedPayloadThrows()
    {
        using JAdESProtectedHeaders headers = ConformantHeaders(contentType: "application/jose");

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: false, payloadIsCountersignedSignature: true));

        Assert.Contains("JA-5.1.3-05", exception.Message);
    }


    /// <summary><c>sigD</c> present with an attached payload throws citing JA-5.2.8.1-02.</summary>
    [TestMethod]
    public void DetachedObjectReferenceWithAttachedPayloadThrows()
    {
        using JAdESProtectedHeaders headers = ConformantHeaders(
            sigD: new JAdESHttpHeadersReference(["digest"]),
            criticalLabels: ["sigD"],
            b64: false);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: false));

        Assert.Contains("JA-5.2.8.1-02", exception.Message);
    }


    /// <summary><c>sigD</c> present without <c>"sigD"</c> in <c>crit</c> throws citing JA-5.1.9-04.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.1.9-05.
    /// </remarks>
    [TestMethod]
    public void DetachedObjectReferenceWithoutCriticalLabelThrows()
    {
        using JAdESProtectedHeaders headers = ConformantHeaders(
            sigD: new JAdESHttpHeadersReference(["digest"]),
            b64: false);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: true));

        Assert.Contains("JA-5.1.9-04", exception.Message);
    }


    /// <summary>The <c>HttpHeaders</c> mechanism without <c>b64:false</c> throws citing JA-5.1.10-04.</summary>
    [TestMethod]
    public void HttpHeadersMechanismWithoutB64FalseThrows()
    {
        using JAdESProtectedHeaders headers = ConformantHeaders(
            sigD: new JAdESHttpHeadersReference(["digest"]),
            criticalLabels: ["sigD"]);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: true));

        Assert.Contains("JA-5.1.10-04", exception.Message);
    }


    /// <summary>
    /// A regression: the <c>HttpHeaders</c> mechanism with a non-lowercase <c>pars</c> entry throws
    /// citing JA-5.2.8.2-04, in COLLECT posture too.
    /// </summary>
    [TestMethod]
    public void HttpHeadersMechanismWithNonLowercaseParsEntryThrows()
    {
        using JAdESProtectedHeaders headers = ConformantHeaders(
            sigD: new JAdESHttpHeadersReference(["Content-Type"]),
            criticalLabels: ["sigD"],
            b64: false);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: true));

        Assert.Contains("JA-5.2.8.2-04", exception.Message);

        IReadOnlyList<JAdESRuleViolation> violations = JAdESHeaderRules.Check(headers, payloadIsDetached: true);
        Assert.Contains(static (JAdESRuleViolation v) => v is JAdESHttpHeadersParsNotLowercaseViolation, violations);
    }


    /// <summary><c>adoTst</c> carrying a non-null <c>canonAlg</c> throws citing JA-5.2.6-08.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The inline AdESTimestampContainer's ownership transfers into ConformantHeaders's " +
            "returned JAdESProtectedHeaders, disposed via the outer 'using headers' declaration; Roslyn cannot " +
            "trace ownership across the ConformantHeaders call boundary.")]
    [TestMethod]
    public void PayloadTimestampWithCanonAlgThrows()
    {
        using JAdESProtectedHeaders headers = ConformantHeaders(
            payloadTimestamps: new AdESTimestampContainer(
                [new AdESTimestampToken { Val = new byte[] { 0x01 } }],
                canonAlg: "http://example.org/canon"));

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: false));

        Assert.Contains("JA-5.2.6-08", exception.Message);
    }


    /// <summary>A decoder-attested present <c>x5t</c> throws citing JA-5.1.6-01 — a read-side forward obligation.</summary>
    [TestMethod]
    public void X5tPresentOnWireThrows()
    {
        using JAdESProtectedHeaders headers = ConformantHeaders();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: false, x5tWasPresentOnWire: true));

        Assert.Contains("JA-5.1.6-01", exception.Message);
    }


    /// <summary>An absent <c>iat</c> throws citing JA-5.1.11-08.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-12, JA-6.3-a3.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TestDigest()'s ownership transfers into the JAdESProtectedHeaders constructed here, " +
            "disposed via the outer 'using headers' declaration.")]
    [TestMethod]
    public void IssuedAtMissingThrows()
    {
        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            x5tHashS256: TestDigest());

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => JAdESHeaderRules.EnsureConformant(headers, payloadIsDetached: false));

        Assert.Contains("JA-5.1.11-08", exception.Message);
    }


    /// <summary>
    /// <see cref="JAdESHeaderRules.Check"/> collects every violation in one pass and never throws — the untrusted-
    /// wire-content posture a validator needs.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.1.11-08.
    /// </remarks>
    [TestMethod]
    public void CheckCollectsEveryViolationWithoutThrowing()
    {
        using var headers = new JAdESProtectedHeaders(WellKnownJwaValues.Es256);

        IReadOnlyList<JAdESRuleViolation> violations = JAdESHeaderRules.Check(headers, payloadIsDetached: false);

        Assert.IsGreaterThanOrEqualTo(2, violations.Count);
        Assert.Contains("JA-5.1.7-04", GetRequirementIds(violations));
        Assert.Contains("JA-5.1.11-08", GetRequirementIds(violations));
    }


    /// <summary>A <see langword="null"/> <c>headers</c> argument raises <see cref="ArgumentNullException"/>, never a rule violation.</summary>
    [TestMethod]
    public void NullHeadersRaisesArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => JAdESHeaderRules.Check(null!, payloadIsDetached: false));
    }


    private static List<string> GetRequirementIds(IReadOnlyList<JAdESRuleViolation> violations)
    {
        var ids = new List<string>(violations.Count);
        foreach(JAdESRuleViolation violation in violations)
        {
            ids.Add(violation.RequirementId);
        }

        return ids;
    }


    /// <summary>Builds a header set satisfying every rule this suite does not itself target, so each negative test isolates exactly one violation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TestDigest()'s ownership transfers into the returned JAdESProtectedHeaders; every " +
            "caller disposes that return value via its own 'using' declaration.")]
    private static JAdESProtectedHeaders ConformantHeaders(
        string? contentType = null,
        JAdESDetachedDataObjectReference? sigD = null,
        IReadOnlyList<string>? criticalLabels = null,
        bool? b64 = null,
        AdESTimestampContainer? payloadTimestamps = null) =>
        new(
            WellKnownJwaValues.Es256,
            contentType: contentType,
            criticalLabels: criticalLabels,
            b64: b64,
            issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch),
            x5tHashS256: TestDigest(),
            payloadTimestamps: payloadTimestamps,
            sigD: sigD);


    private static DigestValue TestDigest()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[32].CopyTo(owner.Memory);
        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }
}

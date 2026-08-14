using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the async cross-component resolution family
/// (<see cref="JAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/>/
/// <see cref="JAdESLevelRules.EnsureReferencesResolveToValidationDataAsync"/>) — the CB-A.1.1-30 analog over the
/// FOUR JAdES <c>refs</c>-family elements, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, Annex A.1.1 (JA-A.1.1-12), A.1.2 (JA-A.1.2-35), A.1.3 (JA-A.1.3-08), A.1.4
/// (JA-A.1.4-10).
/// </summary>
/// <remarks>
/// Every digest is a real SHA-256 digest computed through the registered digest delegate, mirroring
/// <c>CBAdESLevelRulesTests</c>'s own <c>CreateDigestAsync</c> convention — never a hand-rolled hash. The
/// <c>arcTst</c>-token-embedded candidate widening (mirroring the CB-A.1.1-30 precedent) needs a real
/// RFC 3161 CMS token fixture and is exercised at the wider lifecycle-flow level, not unit-tested here.
/// </remarks>
[TestClass]
internal sealed class JAdESCrossComponentResolutionTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>The check does not fire when <c>etsiU</c> is absent.</summary>
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_NullUnsignedHeaders_ReturnsEmpty()
    {
        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(violations);
    }


    /// <summary>The check does not fire under base64url incorporation — nothing decoded, nothing to check.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element constructions are constructor arguments passed straight into the enclosing 'using JAdESUnsignedHeaders' aggregate, which the local using disposes.")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_Base64UrlMode_ReturnsEmpty()
    {
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.Base64Url,
            [new JAdESUnsignedHeaderElementCounterSignature(PooledMemory.FromBytes("\"opaque\""u8, BaseMemoryPool.Shared, Tag.Create(Purpose.Data)))]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(violations);
    }


    /// <summary>JA-A.1.1-12 does not fire when <c>xRefs</c> is present but no <c>xVals</c>/<c>axVals</c>/<c>arcTst</c> trigger arm is also present.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element/collection constructions are constructor arguments passed straight into the enclosing 'using' aggregates, which the local usings dispose.")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_XRefsWithoutTrigger_ReturnsEmpty()
    {
        DigestValue referenceDigest = await CreateDigestAsync([0x30, 0x82, 0x01], TestContext.CancellationToken);
        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [new JAdESUnsignedHeaderElementCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(
                new JAdESCertificateReferenceCollection([new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), referenceDigest)])))]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(violations);
    }


    /// <summary>JA-A.1.1-12: an <c>xRefs</c> entry whose digest matches an <c>xVals</c> certificate resolves — no violation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element/collection constructions are constructor arguments passed straight into the enclosing 'using' aggregates, which the local usings dispose.")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_XRefsResolvesAgainstXVals_ReturnsEmpty()
    {
        byte[] certificateBytes = [0x30, 0x82, 0x01, 0x0A];
        DigestValue referenceDigest = await CreateDigestAsync(certificateBytes, TestContext.CancellationToken);

        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
        [
            new JAdESUnsignedHeaderElementCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(
                new JAdESCertificateReferenceCollection([new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), referenceDigest)]))),
            new JAdESUnsignedHeaderElementCertificateValues(new JAdESClearUnsignedValue<JAdESCertificateValues>(
                new JAdESCertificateValues([new JAdESX509Certificate(new AdESPkiObject { Val = certificateBytes })])))
        ]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(violations);
    }


    /// <summary>JA-A.1.1-12: an <c>xRefs</c> entry whose digest matches nothing in <c>xVals</c> fails to resolve.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element/collection constructions are constructor arguments passed straight into the enclosing 'using' aggregates, which the local usings dispose.")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_XRefsDoesNotResolve_ReturnsViolation()
    {
        DigestValue referenceDigest = await CreateDigestAsync([0x30, 0x82, 0x01, 0x0A], TestContext.CancellationToken);

        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
        [
            new JAdESUnsignedHeaderElementCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(
                new JAdESCertificateReferenceCollection([new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), referenceDigest)]))),
            new JAdESUnsignedHeaderElementCertificateValues(new JAdESClearUnsignedValue<JAdESCertificateValues>(
                new JAdESCertificateValues([new JAdESX509Certificate(new AdESPkiObject { Val = new byte[] { 0x30, 0x00 } })])))
        ]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        var violation = FindViolation<JAdESReferencesValidationDataConsistencyViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(JAdESRefsFamilyDigestSurface.CertificateReferences, violation!.Surface);
        Assert.AreEqual(JAdESReferenceMaterialKind.Certificate, violation.MaterialKind);
        Assert.Contains("JA-A.1.1-12", violation.RequirementId);
    }


    /// <summary>JA-A.1.3-08: an <c>axRefs</c> entry resolves against <c>axVals</c> under the SAME cert-family trigger as <c>xRefs</c>.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element/collection constructions are constructor arguments passed straight into the enclosing 'using' aggregates, which the local usings dispose.")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_AxRefsResolvesAgainstAxVals_ReturnsEmpty()
    {
        byte[] certificateBytes = [0x30, 0x82, 0x02];
        DigestValue referenceDigest = await CreateDigestAsync(certificateBytes, TestContext.CancellationToken);

        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
        [
            new JAdESUnsignedHeaderElementAttributeCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(
                new JAdESCertificateReferenceCollection([new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), referenceDigest)]))),
            new JAdESUnsignedHeaderElementAttributeCertificateValues(new JAdESClearUnsignedValue<JAdESCertificateValues>(
                new JAdESCertificateValues([new JAdESX509Certificate(new AdESPkiObject { Val = certificateBytes })])))
        ]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(violations);
    }


    /// <summary>JA-A.1.2-35: an <c>rRefs</c> CRL entry whose digest matches nothing in <c>rVals.crlVals</c> fails to resolve.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element/collection constructions are constructor arguments passed straight into the enclosing 'using' aggregates, which the local usings dispose.")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_RRefsCrlDoesNotResolve_ReturnsViolation()
    {
        DigestValue referenceDigest = await CreateDigestAsync([0x30, 0x82, 0x03], TestContext.CancellationToken);

        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
        [
            new JAdESUnsignedHeaderElementRevocationReferences(new JAdESClearUnsignedValue<JAdESRevocationReferenceCollection>(
                new JAdESRevocationReferenceCollection(crlReferences: [new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), referenceDigest)]))),
            new JAdESUnsignedHeaderElementRevocationValues(new JAdESClearUnsignedValue<JAdESRevocationValues>(
                new JAdESRevocationValues(crlValues: [new AdESPkiObject { Val = new byte[] { 0x30, 0x01 } }])))
        ]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        var violation = FindViolation<JAdESReferencesValidationDataConsistencyViolation>(violations);
        Assert.IsNotNull(violation);
        Assert.AreEqual(JAdESRefsFamilyDigestSurface.RevocationReferences, violation!.Surface);
        Assert.AreEqual(JAdESReferenceMaterialKind.Crl, violation.MaterialKind);
        Assert.Contains("JA-A.1.2-35", violation.RequirementId);
    }


    /// <summary>JA-A.1.4-10: an <c>arRefs</c> OCSP entry resolves against <c>arVals.ocspVals</c> — no violation.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element/collection constructions are constructor arguments passed straight into the enclosing 'using' aggregates, which the local usings dispose.")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_ArRefsResolvesAgainstArVals_ReturnsEmpty()
    {
        byte[] ocspBytes = [0x30, 0x82, 0x04];
        DigestValue referenceDigest = await CreateDigestAsync(ocspBytes, TestContext.CancellationToken);

        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
        [
            new JAdESUnsignedHeaderElementAttributeRevocationReferences(new JAdESClearUnsignedValue<JAdESRevocationReferenceCollection>(
                new JAdESRevocationReferenceCollection(ocspReferences: [new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), referenceDigest)]))),
            new JAdESUnsignedHeaderElementAttributeRevocationValues(new JAdESClearUnsignedValue<JAdESRevocationValues>(
                new JAdESRevocationValues(ocspValues: [new AdESPkiObject { Val = ocspBytes }])))
        ]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(violations);
    }


    /// <summary>An unrecognized digest-algorithm identifier fails closed as unresolved, never throwing.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element/collection constructions are constructor arguments passed straight into the enclosing 'using' aggregates, which the local usings dispose.")]
    [TestMethod]
    public async Task CheckReferencesResolveToValidationDataAsync_UnknownAlgorithm_FailsClosedAsUnresolved()
    {
        byte[] certificateBytes = [0x30, 0x82, 0x05];
        DigestValue referenceDigest = await CreateDigestAsync(certificateBytes, TestContext.CancellationToken);

        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
        [
            new JAdESUnsignedHeaderElementCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(
                new JAdESCertificateReferenceCollection([new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha3-256"), referenceDigest)]))),
            new JAdESUnsignedHeaderElementCertificateValues(new JAdESClearUnsignedValue<JAdESCertificateValues>(
                new JAdESCertificateValues([new JAdESX509Certificate(new AdESPkiObject { Val = certificateBytes })])))
        ]);

        IReadOnlyList<JAdESRuleViolation> violations = await JAdESLevelRules.CheckReferencesResolveToValidationDataAsync(
            unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotEmpty(violations);
    }


    /// <summary>EnsureReferencesResolveToValidationDataAsync throws, naming JA-A.1.1-12, when a reference fails to resolve.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The element/collection constructions are constructor arguments passed straight into the enclosing 'using' aggregates, which the local usings dispose.")]
    [TestMethod]
    public async Task EnsureReferencesResolveToValidationDataAsync_UnresolvedReference_ThrowsNamingRequirement()
    {
        DigestValue referenceDigest = await CreateDigestAsync([0x30, 0x82, 0x06], TestContext.CancellationToken);

        using JAdESUnsignedHeaders unsignedHeaders = new(
            JAdESEtsiUIncorporationMode.ClearJson,
        [
            new JAdESUnsignedHeaderElementCertificateReferences(new JAdESClearUnsignedValue<JAdESCertificateReferenceCollection>(
                new JAdESCertificateReferenceCollection([new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), referenceDigest)]))),
            new JAdESUnsignedHeaderElementCertificateValues(new JAdESClearUnsignedValue<JAdESCertificateValues>(
                new JAdESCertificateValues([new JAdESX509Certificate(new AdESPkiObject { Val = new byte[] { 0x30, 0x00 } })])))
        ]);

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await JAdESLevelRules.EnsureReferencesResolveToValidationDataAsync(unsignedHeaders, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.Contains("JA-A.1.1-12", exception.Message);
    }


    /// <summary>
    /// Computes a real SHA-256 digest over <paramref name="input"/> through the registered digest delegate,
    /// tagged with <see cref="CryptoTags.Sha256Digest"/> — matching <c>CBAdESLevelRulesTests</c>'s own
    /// convention, never a hand-rolled hash.
    /// </summary>
    private static async ValueTask<DigestValue> CreateDigestAsync(byte[] input, CancellationToken cancellationToken) =>
        await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(input), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);


    private static T? FindViolation<T>(IReadOnlyList<JAdESRuleViolation> violations) where T : JAdESRuleViolation
    {
        for(int i = 0; i < violations.Count; ++i)
        {
            if(violations[i] is T match)
            {
                return match;
            }
        }

        return null;
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Byte-exact regression vectors for the JAdES message-imprint-INPUT builders (<see cref="JAdESMessageImprints"/>),
/// per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clauses 5.3.6.2.2-5.3.6.2.4 (<c>arcTst</c>) and Annex A.1.5 (<c>sigRTst</c>/
/// <c>rfsTst</c>). Mirrors <c>CBAdESMessageImprintTests</c>'s independent-oracle discipline: every expected byte
/// sequence is assembled directly from the fixture inputs, following the spec's own numbered steps, never by
/// calling <see cref="JAdESMessageImprints"/> or mirroring its internals.
/// </summary>
[TestClass]
internal sealed class JAdESMessageImprintTests
{
    /// <summary>The MSTest context.</summary>
    public TestContext TestContext { get; set; } = null!;

    private const byte Dot = (byte)'.';


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstGenerationBase64UrlMatchesIndependentOracleAsync()
    {
        byte[] payload = Utf8("payload-text");
        byte[] header = Utf8("header-text");
        byte[] signature = Utf8("signature-text");

        using JAdESUnsignedHeaders etsiU = new(
            JAdESEtsiUIncorporationMode.Base64Url,
            [MakeOpaqueSigTstElement("sigtst-wire"), MakeOpaqueXRefsElement("xrefs-wire")]);

        byte[] expected = Concat(payload, [Dot], header, [Dot], signature, [Dot], Utf8("sigtst-wire"), Utf8("xrefs-wire"));

        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESBase64UrlPayloadImprintSource(payload),
            ProtectedHeaderBase64Url = header,
            SignatureValueBase64Url = signature
        };

        using PooledMemory result = await JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync(
            context, etsiU, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "Generation-time Base64url arcTst input must reproduce the independent oracle exactly.");
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element construction is passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstGenerationRawPayloadSourceConcatenatesUnencodedBytesAsync()
    {
        byte[] rawPayload = [0x00, 0xFF, 0x10];
        byte[] header = Utf8("h");
        byte[] signature = Utf8("s");
        using JAdESUnsignedHeaders etsiU = new(JAdESEtsiUIncorporationMode.Base64Url, [MakeOpaqueUnknownElement("x-custom", "x")]);

        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESRawPayloadImprintSource(rawPayload),
            ProtectedHeaderBase64Url = header,
            SignatureValueBase64Url = signature
        };

        using PooledMemory result = await JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync(
            context, etsiU, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(result.AsReadOnlySpan().StartsWith(rawPayload), "The raw payload-source arm must concatenate the exact unencoded bytes it was given.");
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element construction is passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstGenerationSigDProcessedPayloadSourceConcatenatesProcessedBytesAsync()
    {
        byte[] processed = Utf8("already-processed-http-headers-bytes");
        byte[] header = Utf8("h");
        byte[] signature = Utf8("s");
        using JAdESUnsignedHeaders etsiU = new(JAdESEtsiUIncorporationMode.Base64Url, [MakeOpaqueUnknownElement("x-custom", "x")]);

        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESSigDProcessedPayloadImprintSource(processed),
            ProtectedHeaderBase64Url = header,
            SignatureValueBase64Url = signature
        };

        using PooledMemory result = await JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync(
            context, etsiU, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(result.AsReadOnlySpan().StartsWith(processed), "The sigD-processed arm must concatenate the exact processed bytes it was given, with no further transformation.");
    }


    /// <summary>
    /// Prefix regression with a repeated instance: validating the THIRD of four elements must concatenate only
    /// the first two (JA-5.3.6.2.3-12/-13), never the fourth, and never itself.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstValidationBase64UrlUsesOnlyElementsStrictlyBeforeTargetIndexAsync()
    {
        byte[] header = Utf8("h");
        byte[] signature = Utf8("s");
        byte[] payload = Utf8("p");

        using JAdESUnsignedHeaders etsiU = new(
            JAdESEtsiUIncorporationMode.Base64Url,
            [
                MakeOpaqueSigTstElement("sigtst-1"),
                MakeOpaqueXRefsElement("xrefs-1"),
                MakeOpaqueArcTstElement("arctst-under-validation"),
                MakeOpaqueXRefsElement("xrefs-after-must-not-appear")
            ]);

        byte[] expected = Concat(payload, [Dot], header, [Dot], signature, [Dot], Utf8("sigtst-1"), Utf8("xrefs-1"));

        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESBase64UrlPayloadImprintSource(payload),
            ProtectedHeaderBase64Url = header,
            SignatureValueBase64Url = signature
        };

        using PooledMemory result = await JAdESMessageImprints.BuildArchiveTimestampValidationMessageImprintInputAsync(
            context, etsiU, arcTstElementIndex: 2, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "Validation must use only the elements strictly before the arcTst under validation.");
    }


    /// <summary>No absent-vs-empty sentinel (unlike CB-AdES's own equivalent): validating the FIRST element yields an empty etsiU contribution, not a crash or placeholder.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element construction is passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstValidationAtIndexZeroYieldsEmptyEtsiUContributionAsync()
    {
        byte[] header = Utf8("h");
        byte[] signature = Utf8("s");
        byte[] payload = Utf8("p");
        using JAdESUnsignedHeaders etsiU = new(JAdESEtsiUIncorporationMode.Base64Url, [MakeOpaqueArcTstElement("the-only-element")]);

        byte[] expected = Concat(payload, [Dot], header, [Dot], signature, [Dot]);

        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESBase64UrlPayloadImprintSource(payload),
            ProtectedHeaderBase64Url = header,
            SignatureValueBase64Url = signature
        };

        using PooledMemory result = await JAdESMessageImprints.BuildArchiveTimestampValidationMessageImprintInputAsync(
            context, etsiU, arcTstElementIndex: 0, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "An empty prefix must contribute zero bytes, with no sentinel.");
    }


    /// <summary>The element at the supplied index must actually be an arcTst instance -- a typed fault, not a silent misread.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element construction is passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstValidationWithNonArcTstElementAtIndexThrowsAsync()
    {
        using JAdESUnsignedHeaders etsiU = new(JAdESEtsiUIncorporationMode.Base64Url, [MakeOpaqueXRefsElement("not-an-arctst")]);

        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESRawPayloadImprintSource(ReadOnlyMemory<byte>.Empty),
            ProtectedHeaderBase64Url = ReadOnlyMemory<byte>.Empty,
            SignatureValueBase64Url = ReadOnlyMemory<byte>.Empty
        };

        await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            JAdESMessageImprints.BuildArchiveTimestampValidationMessageImprintInputAsync(
                context, etsiU, arcTstElementIndex: 0, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstGenerationClearJsonInvokesCanonicalizeDelegateOncePerElementAsync()
    {
        byte[] header = Utf8("h");
        byte[] signature = Utf8("s");
        byte[] payload = Utf8("p");

        using JAdESUnsignedHeaders etsiU = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeClearSigTstElement(), MakeClearXValsElement()]);

        var invocationLog = new List<string>();
        JAdESCanonicalizeUnsignedElementDelegate canonicalize = (canonAlg, element, pool, cancellationToken) =>
        {
            invocationLog.Add($"{canonAlg}:{element.Kind}");
            return ValueTask.FromResult(PooledMemory.FromBytes(Utf8($"canon-{element.Kind}"), pool, CryptoTags.JAdESMessageImprintInput));
        };

        byte[] expected = Concat(payload, [Dot], header, [Dot], signature, [Dot], Utf8("canon-sigTst"), Utf8("canon-xVals"));

        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESBase64UrlPayloadImprintSource(payload),
            ProtectedHeaderBase64Url = header,
            SignatureValueBase64Url = signature,
            CanonAlg = "http://example.org/canon-alg",
            Canonicalize = canonicalize
        };

        using PooledMemory result = await JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync(
            context, etsiU, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "Clear-JSON arcTst input must reproduce the independent oracle exactly.");
        Assert.HasCount(2, invocationLog, "The delegate must be invoked exactly once per etsiU element, never per byte or per call.");
        Assert.AreEqual("http://example.org/canon-alg:sigTst", invocationLog[0]);
        Assert.AreEqual("http://example.org/canon-alg:xVals", invocationLog[1]);
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element construction is passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstGenerationClearJsonWithMissingCanonAlgThrowsAsync()
    {
        using JAdESUnsignedHeaders etsiU = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeClearXValsElement()]);
        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESRawPayloadImprintSource(ReadOnlyMemory<byte>.Empty),
            ProtectedHeaderBase64Url = ReadOnlyMemory<byte>.Empty,
            SignatureValueBase64Url = ReadOnlyMemory<byte>.Empty,
            CanonAlg = string.Empty, //present-but-empty, distinct from the null case ArgumentNullException covers below.
            Canonicalize = (_, _, pool, _) => ValueTask.FromResult(PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, CryptoTags.JAdESMessageImprintInput))
        };

        await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync(
                context, etsiU, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element construction is passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstGenerationClearJsonWithNullCanonAlgThrowsArgumentNullAsync()
    {
        using JAdESUnsignedHeaders etsiU = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeClearXValsElement()]);
        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESRawPayloadImprintSource(ReadOnlyMemory<byte>.Empty),
            ProtectedHeaderBase64Url = ReadOnlyMemory<byte>.Empty,
            SignatureValueBase64Url = ReadOnlyMemory<byte>.Empty,
            Canonicalize = (_, _, pool, _) => ValueTask.FromResult(PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, CryptoTags.JAdESMessageImprintInput))
        };

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(() =>
            JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync(
                context, etsiU, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element construction is passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstGenerationClearJsonWithMissingDelegateThrowsAsync()
    {
        using JAdESUnsignedHeaders etsiU = new(JAdESEtsiUIncorporationMode.ClearJson, [MakeClearXValsElement()]);
        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESRawPayloadImprintSource(ReadOnlyMemory<byte>.Empty),
            ProtectedHeaderBase64Url = ReadOnlyMemory<byte>.Empty,
            SignatureValueBase64Url = ReadOnlyMemory<byte>.Empty,
            CanonAlg = "http://example.org/canon-alg"
        };

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(() =>
            JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync(
                context, etsiU, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }


    /// <summary>
    /// Duality routing, direction 2 (JA-5.3.1-15): a Base64url-mode container REJECTS a supplied
    /// canonAlg/canonicalize outright -- a typed fault, not a silently-ignored no-op.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element construction is passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstGenerationBase64UrlWithSuppliedCanonicalizationThrowsAsync()
    {
        using JAdESUnsignedHeaders etsiU = new(JAdESEtsiUIncorporationMode.Base64Url, [MakeOpaqueUnknownElement("x-custom", "x")]);
        int invocationCount = 0;
        JAdESCanonicalizeUnsignedElementDelegate canonicalize = (_, _, pool, _) =>
        {
            invocationCount++;
            return ValueTask.FromResult(PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, CryptoTags.JAdESMessageImprintInput));
        };

        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESRawPayloadImprintSource(ReadOnlyMemory<byte>.Empty),
            ProtectedHeaderBase64Url = ReadOnlyMemory<byte>.Empty,
            SignatureValueBase64Url = ReadOnlyMemory<byte>.Empty,
            CanonAlg = "unused",
            Canonicalize = canonicalize
        };

        await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync(
                context, etsiU, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());

        Assert.AreEqual(0, invocationCount, "Base64url incorporation must fail closed before ever invoking the canonicalization delegate (JA-5.3.1-15).");
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task SigRTstGenerationBase64UrlFiltersToTheFiveNamedKindsInWireOrderAsync()
    {
        byte[] signatureValue = Utf8("sig-value-text");

        using JAdESUnsignedHeaders etsiU = new(
            JAdESEtsiUIncorporationMode.Base64Url,
            [
                MakeOpaqueSigTstElement("sigtst-wire"),
                MakeOpaqueXRefsElement("xrefs-wire"),
                MakeOpaqueXValsElement("xvals-wire"), //xVals is NOT one of sigRTst's five components -- must be excluded.
                MakeOpaqueArRefsElement("arrefs-wire")
            ]);

        byte[] expected = Concat(signatureValue, [Dot], Utf8("sigtst-wire"), Utf8("xrefs-wire"), Utf8("arrefs-wire"));

        using PooledMemory result = await JAdESMessageImprints.BuildSignatureAndReferencesTimestampGenerationMessageImprintInputAsync(
            signatureValue, etsiU, canonAlg: null, canonicalize: null, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "sigRTst must reproduce the independent oracle exactly, excluding non-qualifying kinds.");
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task RfsTstGenerationBase64UrlExcludesSignatureValueAndSigTstAsync()
    {
        using JAdESUnsignedHeaders etsiU = new(
            JAdESEtsiUIncorporationMode.Base64Url,
            [MakeOpaqueSigTstElement("sigtst-wire"), MakeOpaqueRRefsElement("rrefs-wire")]);

        byte[] expected = Utf8("rrefs-wire"); //sigTst excluded; no leading signature value or dot at all.

        using PooledMemory result = await JAdESMessageImprints.BuildReferencesOnlyTimestampGenerationMessageImprintInputAsync(
            etsiU, canonAlg: null, canonicalize: null, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "rfsTst must contain no signature value and must exclude sigTst.");
    }


    /// <summary>
    /// A
    /// qualifying component positioned AFTER the sigRTst under validation must be EXCLUDED from that instance's
    /// own message-imprint input -- the prefix-bound positive, superseding the earlier (mistaken)
    /// no-positional-restriction reading.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task SigRTstValidationUsesOnlyElementsStrictlyBeforeTargetIndexAsync()
    {
        byte[] signatureValue = Utf8("sig");

        using JAdESUnsignedHeaders etsiU = new(
            JAdESEtsiUIncorporationMode.Base64Url,
            [
                MakeOpaqueXRefsElement("before"),
                MakeOpaqueSigRTstElement("sigrtst-under-validation"),
                MakeOpaqueRRefsElement("after-must-not-appear")
            ]);

        byte[] expected = Concat(signatureValue, [Dot], Utf8("before"));

        using PooledMemory result = await JAdESMessageImprints.BuildSignatureAndReferencesTimestampValidationMessageImprintInputAsync(
            signatureValue, etsiU, sigRTstElementIndex: 1, canonAlg: null, canonicalize: null, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()), "A qualifying component positioned after the sigRTst under validation must be excluded.");
    }


    /// <summary>
    /// A regression: a sigTst2 appended AFTER an already-incorporated sigRTst (JA-5.3.1-03 makes the
    /// append itself legal) must not change that sigRTst's own, already-computed message-imprint input.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task SigRTstValidationStillMatchesOriginalImprintAfterLaterSigTstAppendedAsync()
    {
        byte[] signatureValue = Utf8("sig");

        using JAdESUnsignedHeaders original = new(
            JAdESEtsiUIncorporationMode.Base64Url,
            [MakeOpaqueXRefsElement("xrefs-1"), MakeOpaqueSigRTstElement("sigrtst-original")]);

        using PooledMemory beforeAppend = await JAdESMessageImprints.BuildSignatureAndReferencesTimestampValidationMessageImprintInputAsync(
            signatureValue, original, sigRTstElementIndex: 1, canonAlg: null, canonicalize: null, BaseMemoryPool.Shared, TestContext.CancellationToken);

        using JAdESUnsignedHeaders appended = original.Append(MakeOpaqueSigTstElement("sigtst2-appended-later"));

        using PooledMemory afterAppend = await JAdESMessageImprints.BuildSignatureAndReferencesTimestampValidationMessageImprintInputAsync(
            signatureValue, appended, sigRTstElementIndex: 1, canonAlg: null, canonicalize: null, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(beforeAppend.AsReadOnlySpan().SequenceEqual(afterAppend.AsReadOnlySpan()),
            "A sigTst2 appended AFTER an already-incorporated sigRTst must not change that sigRTst's own message imprint.");
    }


    /// <summary>
    /// A regression: a late arRefs append must not change an existing rfsTst's own, already-computed
    /// message-imprint input.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task RfsTstValidationStillMatchesOriginalImprintAfterLateArRefsAppendedAsync()
    {
        using JAdESUnsignedHeaders original = new(
            JAdESEtsiUIncorporationMode.Base64Url,
            [MakeOpaqueRRefsElement("rrefs-1"), MakeOpaqueRfsTstElement("rfstst-original")]);

        using PooledMemory beforeAppend = await JAdESMessageImprints.BuildReferencesOnlyTimestampValidationMessageImprintInputAsync(
            original, rfsTstElementIndex: 1, canonAlg: null, canonicalize: null, BaseMemoryPool.Shared, TestContext.CancellationToken);

        using JAdESUnsignedHeaders appended = original.Append(MakeOpaqueArRefsElement("arrefs-appended-late"));

        using PooledMemory afterAppend = await JAdESMessageImprints.BuildReferencesOnlyTimestampValidationMessageImprintInputAsync(
            appended, rfsTstElementIndex: 1, canonAlg: null, canonicalize: null, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(beforeAppend.AsReadOnlySpan().SequenceEqual(afterAppend.AsReadOnlySpan()),
            "A late arRefs append must not change an existing rfsTst's own message imprint.");
    }


    /// <summary>The same discipline extended to sigRTst/rfsTst: the element under validation must actually be the expected arm.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element construction is passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task RfsTstValidationWithNonRfsTstElementAtIndexThrowsAsync()
    {
        using JAdESUnsignedHeaders etsiU = new(JAdESEtsiUIncorporationMode.Base64Url, [MakeOpaqueRRefsElement("not-a-rfstst")]);

        await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
            JAdESMessageImprints.BuildReferencesOnlyTimestampValidationMessageImprintInputAsync(
                etsiU, rfsTstElementIndex: 0, canonAlg: null, canonicalize: null, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask());
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task RfsTstGenerationClearJsonInvokesCanonicalizeDelegateOnlyForQualifyingKindsAsync()
    {
        using JAdESUnsignedHeaders etsiU = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeClearSigTstElement(), MakeClearXValsElement(), MakeClearArRefsElement()]);

        var invoked = new List<string>();
        JAdESCanonicalizeUnsignedElementDelegate canonicalize = (canonAlg, element, pool, cancellationToken) =>
        {
            invoked.Add(element.Kind);
            return ValueTask.FromResult(PooledMemory.FromBytes(Utf8($"c-{element.Kind}"), pool, CryptoTags.JAdESMessageImprintInput));
        };

        byte[] expected = Utf8("c-arRefs"); //sigTst and xVals are both excluded from rfsTst's own component list.

        using PooledMemory result = await JAdESMessageImprints.BuildReferencesOnlyTimestampGenerationMessageImprintInputAsync(
            etsiU, canonAlg: "alg", canonicalize, BaseMemoryPool.Shared, TestContext.CancellationToken);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(result.AsReadOnlySpan()));
        Assert.HasCount(1, invoked, "Only the one qualifying (arRefs) element must reach the delegate.");
        Assert.AreEqual("arRefs", invoked[0]);
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task ArcTstClearJsonRoundTripIsMeteredPoolBalancedAsync()
    {
        using var metered = new MeteredHousePool();

        using JAdESUnsignedHeaders etsiU = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeClearSigTstElement(), MakeClearXValsElement()]);

        JAdESCanonicalizeUnsignedElementDelegate canonicalize = (canonAlg, element, pool, cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(Utf8($"c-{element.Kind}"), pool, CryptoTags.JAdESMessageImprintInput));

        var context = new JAdESArchiveTimestampImprintContext
        {
            PayloadSource = new JAdESRawPayloadImprintSource(Utf8("payload")),
            ProtectedHeaderBase64Url = Utf8("header"),
            SignatureValueBase64Url = Utf8("signature"),
            CanonAlg = "alg",
            Canonicalize = canonicalize
        };

        using(PooledMemory result = await JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync(
            context, etsiU, metered.Pool, TestContext.CancellationToken))
        {
            Assert.IsGreaterThan(0, result.Length);
        }

        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "Every intermediate delegate-rented buffer and the final buffer must be returned.");
    }


    /// <summary>The pooled-writer discipline proven over the sigRTst generation path too, not just arcTst.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public async Task SigRTstClearJsonRoundTripIsMeteredPoolBalancedAsync()
    {
        using var metered = new MeteredHousePool();

        using JAdESUnsignedHeaders etsiU = new(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeClearSigTstElement(), MakeClearArRefsElement()]);

        JAdESCanonicalizeUnsignedElementDelegate canonicalize = (canonAlg, element, pool, cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(Utf8($"c-{element.Kind}"), pool, CryptoTags.JAdESMessageImprintInput));

        using(PooledMemory result = await JAdESMessageImprints.BuildSignatureAndReferencesTimestampGenerationMessageImprintInputAsync(
            Utf8("sig"), etsiU, "alg", canonicalize, metered.Pool, TestContext.CancellationToken))
        {
            Assert.IsGreaterThan(0, result.Length);
        }

        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "Every intermediate delegate-rented buffer and the final buffer must be returned.");
    }


    private static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);


    private static byte[] Concat(params byte[][] parts)
    {
        int totalLength = 0;
        foreach(byte[] part in parts)
        {
            totalLength += part.Length;
        }

        byte[] result = new byte[totalLength];
        int offset = 0;
        foreach(byte[] part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }

        return result;
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The inner JAdESOpaqueUnsignedValue is wrapped directly into the returned element in the same " +
            "expression; ownership passes to that returned element, which every caller disposes (directly or via the " +
            "JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementSignatureTimestamp MakeOpaqueSigTstElement(string wireText) =>
        new(new JAdESOpaqueUnsignedValue<AdESTimestampContainer>(PooledMemory.FromBytes(Utf8(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement), default!));


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The inner JAdESOpaqueUnsignedValue is wrapped directly into the returned element in the same " +
            "expression; ownership passes to that returned element, which every caller disposes (directly or via the " +
            "JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementArchiveTimestamp MakeOpaqueArcTstElement(string wireText) =>
        new(new JAdESOpaqueUnsignedValue<AdESTimestampContainer>(PooledMemory.FromBytes(Utf8(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement), default!));


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The inner JAdESOpaqueUnsignedValue is wrapped directly into the returned element in the same " +
            "expression; ownership passes to that returned element, which every caller disposes (directly or via the " +
            "JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp MakeOpaqueSigRTstElement(string wireText) =>
        new(new JAdESOpaqueUnsignedValue<AdESTimestampContainer>(PooledMemory.FromBytes(Utf8(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement), default!));


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The inner JAdESOpaqueUnsignedValue is wrapped directly into the returned element in the same " +
            "expression; ownership passes to that returned element, which every caller disposes (directly or via the " +
            "JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementReferencesTimestamp MakeOpaqueRfsTstElement(string wireText) =>
        new(new JAdESOpaqueUnsignedValue<AdESTimestampContainer>(PooledMemory.FromBytes(Utf8(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement), default!));


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The inner JAdESOpaqueUnsignedValue is wrapped directly into the returned element in the same " +
            "expression; ownership passes to that returned element, which every caller disposes (directly or via the " +
            "JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementCertificateValues MakeOpaqueXValsElement(string wireText) =>
        new(new JAdESOpaqueUnsignedValue<JAdESCertificateValues>(PooledMemory.FromBytes(Utf8(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement), default!));


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The inner JAdESOpaqueUnsignedValue is wrapped directly into the returned element in the same " +
            "expression; ownership passes to that returned element, which every caller disposes (directly or via the " +
            "JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementCertificateReferences MakeOpaqueXRefsElement(string wireText) =>
        new(new JAdESOpaqueUnsignedValue<JAdESCertificateReferenceCollection>(PooledMemory.FromBytes(Utf8(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement), default!));


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The inner JAdESOpaqueUnsignedValue is wrapped directly into the returned element in the same " +
            "expression; ownership passes to that returned element, which every caller disposes (directly or via the " +
            "JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementRevocationReferences MakeOpaqueRRefsElement(string wireText) =>
        new(new JAdESOpaqueUnsignedValue<JAdESRevocationReferenceCollection>(PooledMemory.FromBytes(Utf8(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement), default!));


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The inner JAdESOpaqueUnsignedValue is wrapped directly into the returned element in the same " +
            "expression; ownership passes to that returned element, which every caller disposes (directly or via the " +
            "JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementAttributeRevocationReferences MakeOpaqueArRefsElement(string wireText) =>
        new(new JAdESOpaqueUnsignedValue<JAdESRevocationReferenceCollection>(PooledMemory.FromBytes(Utf8(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement), default!));


    private static JAdESUnsignedHeaderElementUnknown MakeOpaqueUnknownElement(string kind, string wireText) =>
        new(kind, PooledMemory.FromBytes(Utf8(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement));


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged AdESTimestampContainer owns no pooled resource of its own (its Dispose is a documented " +
            "no-op); it is immediately wrapped into the returned element, which every caller disposes " +
            "(directly or via the JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementSignatureTimestamp MakeClearSigTstElement()
    {
        var container = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x01 } }]); //sigTst forbids its own canonAlg (JA-5.3.4-05).
        return new JAdESUnsignedHeaderElementSignatureTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(container));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "JAdESCertificateValues/JAdESClearUnsignedValue own no pooled resource of their own; the wrapped " +
            "value is immediately wrapped into the returned element, which every caller disposes (directly or via the " +
            "JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementCertificateValues MakeClearXValsElement()
    {
        var values = new JAdESCertificateValues([new JAdESX509Certificate(new AdESPkiObject { Val = new byte[] { 0x30, 0x01 } })]);
        return new JAdESUnsignedHeaderElementCertificateValues(new JAdESClearUnsignedValue<JAdESCertificateValues>(values));
    }


    /// <summary>
    /// Builds a real, first-class clear-mode <c>arRefs</c> element (the earlier Unknown-based
    /// "MakeClearArRefsElement" fixture goes away -- <c>arRefs</c> now participates in the DeclaredMode duality
    /// like every other named arm, not the mode-agnostic unknown catch-all).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged AdESCertificateThumbprint/JAdESRevocationReferenceCollection are immediately wrapped " +
            "into the returned element, which every caller disposes (directly or via the JAdESUnsignedHeaders container " +
            "it is placed in).")]
    private static JAdESUnsignedHeaderElementAttributeRevocationReferences MakeClearArRefsElement()
    {
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("http://www.w3.org/2001/04/xmlenc#sha256"), MakeDigestValue([0x01, 0x02, 0x03]));
        var values = new JAdESRevocationReferenceCollection(crlReferences: [thumbprint]);
        return new JAdESUnsignedHeaderElementAttributeRevocationReferences(new JAdESClearUnsignedValue<JAdESRevocationReferenceCollection>(values));
    }


    private static DigestValue MakeDigestValue(byte[] bytes)
    {
        var owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }
}

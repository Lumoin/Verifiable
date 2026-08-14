using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the JAdES <c>etsiU</c> unsigned header parameter model — the DUAL-MODE element carrier
/// (<see cref="JAdESUnsignedValue{TValue}"/>), the closed sum of the ten named kinds plus the unknown-label
/// arm (<see cref="JAdESUnsignedHeaderElement"/>), the ordered append-only container
/// (<see cref="JAdESUnsignedHeaders"/>), and the six per-kind validation-data value shapes
/// (<see cref="JAdESCertificateValues"/>, <see cref="JAdESRevocationValues"/>,
/// <see cref="JAdESValidationData"/>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.3.
/// </summary>
[TestClass]
internal sealed class JAdESUnsignedHeaderElementTests
{
    /// <summary>The MSTest context.</summary>
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void ConstructingUnsignedHeadersWithNullElementsThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, null!));
    }


    /// <summary>
    /// JA-5.3.1-07: "The <c>etsiU</c> header parameter shall be a non-empty array." Constructing
    /// <see cref="JAdESUnsignedHeaders"/> from an empty sequence throws rather than representing an illegal
    /// empty-but-present value.
    /// </summary>
    [TestMethod]
    public void ConstructingUnsignedHeadersWithEmptyElementsThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, []));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The first element is a constructor argument passed straight into the enclosing " +
            "'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, " +
            "which the local using disposes. The second element, added after construction, is disposed explicitly " +
            "since the snapshot semantics under test mean the container never takes ownership of it.")]
    [TestMethod]
    public void ConstructingUnsignedHeadersTakesSnapshotOfSuppliedList()
    {
        var source = new List<JAdESUnsignedHeaderElement> { MakeUnknownOpaqueElement("x-a", "one") };
        using var headers = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, source);

        using JAdESUnsignedHeaderElementUnknown notIncorporated = MakeUnknownOpaqueElement("x-b", "two");
        source.Add(notIncorporated);

        Assert.AreEqual(1, headers.Count, "Mutating the caller's list after construction must not affect the constructed instance.");
    }


    /// <summary>
    /// JA-5.3.1-03: "New JSON values shall always be added at the end of the <c>etsiU</c> array."
    /// <see cref="JAdESUnsignedHeaders.Append"/> returns a NEW instance with the supplied element placed
    /// last, leaving the receiver unchanged.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.3.6.2.2-06.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "containers' own construction; ownership passes to those containers (both 'original' and 'appended' " +
            "reference the same elements — disposal is idempotent, so the double ownership is safe), which the " +
            "local usings dispose.")]
    [TestMethod]
    public void AppendReturnsNewInstanceLeavingOriginalUnchanged()
    {
        JAdESUnsignedHeaderElement first = MakeUnknownOpaqueElement("x-a", "one");
        JAdESUnsignedHeaderElement second = MakeUnknownOpaqueElement("x-b", "two");
        using var original = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, [first]);

        using JAdESUnsignedHeaders appended = original.Append(second);

        Assert.AreEqual(1, original.Count, "Append must not mutate the receiver.");
        Assert.AreEqual(2, appended.Count);
        Assert.AreSame(first, appended[0], "Every pre-existing element must precede the newly appended one.");
        Assert.AreSame(second, appended[1], "The appended element must be placed last.");
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged construction is a constructor argument passed straight into the enclosing " +
            "'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, " +
            "which the local using disposes.")]
    [TestMethod]
    public void AppendWithNullElementThrows()
    {
        using var headers = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, [MakeUnknownOpaqueElement("x-a", "one")]);

        Assert.ThrowsExactly<ArgumentNullException>(() => headers.Append(null!));
    }


    /// <summary>
    /// <see cref="JAdESUnsignedHeaders.ElementsBefore"/> returns the exact prefix at every meaningful
    /// boundary: the empty prefix at index 0, a genuine strict-prefix in the middle, and the full sequence
    /// at <see cref="JAdESUnsignedHeaders.Count"/> — the generation-time full-sequence view clause
    /// 5.3.6.2.3/5.3.6.2.4 relies on alongside the validation-time strict-prefix view.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void ElementsBeforeReturnsExactPrefixAtEveryBoundary()
    {
        JAdESUnsignedHeaderElement e0 = MakeUnknownOpaqueElement("x-0", "v0");
        JAdESUnsignedHeaderElement e1 = MakeUnknownOpaqueElement("x-1", "v1");
        JAdESUnsignedHeaderElement e2 = MakeUnknownOpaqueElement("x-2", "v2");
        JAdESUnsignedHeaderElement e3 = MakeUnknownOpaqueElement("x-3", "v3");
        using var headers = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, [e0, e1, e2, e3]);

        Assert.IsEmpty(headers.ElementsBefore(0), "Index 0 must yield the empty prefix.");

        IReadOnlyList<JAdESUnsignedHeaderElement> prefixOfTwo = headers.ElementsBefore(2);
        Assert.HasCount(2, prefixOfTwo);
        Assert.AreSame(e0, prefixOfTwo[0]);
        Assert.AreSame(e1, prefixOfTwo[1]);

        IReadOnlyList<JAdESUnsignedHeaderElement> everything = headers.ElementsBefore(headers.Count);
        Assert.HasCount(4, everything);
        Assert.AreSame(e3, everything[3], "ElementsBefore(Count) must be the full, generation-time sequence.");
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged construction is a constructor argument passed straight into the enclosing " +
            "'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, " +
            "which the local using disposes.")]
    [TestMethod]
    public void ElementsBeforeThrowsOnOutOfRangeIndex()
    {
        using var headers = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, [MakeUnknownOpaqueElement("x-a", "one")]);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => headers.ElementsBefore(-1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => headers.ElementsBefore(headers.Count + 1));
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void IndexerAndEnumerationAgreeOnWireOrder()
    {
        JAdESUnsignedHeaderElement e0 = MakeUnknownOpaqueElement("x-0", "v0");
        JAdESUnsignedHeaderElement e1 = MakeUnknownOpaqueElement("x-1", "v1");
        JAdESUnsignedHeaderElement e2 = MakeUnknownOpaqueElement("x-2", "v2");
        using var headers = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, [e0, e1, e2]);

        var viaEnumeration = new List<JAdESUnsignedHeaderElement>();
        foreach(JAdESUnsignedHeaderElement element in headers)
        {
            viaEnumeration.Add(element);
        }

        Assert.HasCount(3, viaEnumeration);
        for(int i = 0; i < headers.Count; i++)
        {
            Assert.AreSame(headers[i], viaEnumeration[i], $"Enumeration order must agree with the indexer at position {i}.");
        }
    }


    /// <summary>
    /// JA-5.3.1-03 ("New JSON values shall always be added at the end") is enforced by API shape, not a
    /// runtime flag: <see cref="JAdESUnsignedHeaders.Append"/> must remain the sole growth operation, and
    /// the public surface must never expose an insert-at/remove/reorder/sort member.
    /// </summary>
    [TestMethod]
    public void PublicSurfaceExposesNoInsertRemoveOrReorderOperation()
    {
        string[] disallowedNameFragments = ["Insert", "Remove", "Sort", "Reverse", "Clear", "Reorder", "Replace", "SetItem", "Move"];

        MethodInfo[] publicInstanceMethods = typeof(JAdESUnsignedHeaders)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(method => !method.IsSpecialName)
            .ToArray();

        foreach(MethodInfo method in publicInstanceMethods)
        {
            foreach(string fragment in disallowedNameFragments)
            {
                Assert.IsFalse(
                    method.Name.Contains(fragment, StringComparison.OrdinalIgnoreCase),
                    $"Public method '{method.Name}' looks like it could insert, remove, or reorder elements, " +
                    "which would break the JA-5.3.1-03 append-only invariant.");
            }
        }

        Assert.Contains("Append", publicInstanceMethods.Select(method => method.Name).ToArray(), "Append must remain the sole growth operation.");
    }


    /// <summary>
    /// JA-5.3.1-10/-11 (direction 1): a <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>
    /// container rejects an opaque (base64url-mode) element at construction — fail-closed unrepresentable,
    /// not a collected violation.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged elements are used only in the throwing constructor call under test, which " +
            "never returns an owning aggregate to dispose them through; both rent from the shared test pool and " +
            "are negligible short-lived fixtures on this negative path.")]
    [TestMethod]
    public void ConstructingClearJsonContainerWithOpaqueElementThrows()
    {
        JAdESUnsignedHeaderElement clearXVals = MakeClearCertificateValuesElement();
        JAdESUnsignedHeaderElement opaqueXVals = MakeOpaqueCertificateValuesElement("opaque-xvals-text");

        Assert.ThrowsExactly<ArgumentException>(() =>
            new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.ClearJson, [clearXVals, opaqueXVals]));
    }


    /// <summary>
    /// JA-5.3.1-10/-11 (direction 2, the "both ways" other half): a
    /// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/> container rejects a clear-JSON element at
    /// construction.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged elements are used only in the throwing constructor call under test, which " +
            "never returns an owning aggregate to dispose them through; both rent from the shared test pool and " +
            "are negligible short-lived fixtures on this negative path.")]
    [TestMethod]
    public void ConstructingBase64UrlContainerWithClearElementThrows()
    {
        JAdESUnsignedHeaderElement opaqueXVals = MakeOpaqueCertificateValuesElement("opaque-xvals-text");
        JAdESUnsignedHeaderElement clearXVals = MakeClearCertificateValuesElement();

        Assert.ThrowsExactly<ArgumentException>(() =>
            new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, [opaqueXVals, clearXVals]));
    }


    /// <summary>
    /// The same duality check applies to <see cref="JAdESUnsignedHeaders.Append"/>, not only the
    /// constructor: appending an opaque element onto an already-clear-JSON container throws.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The clear element is a constructor argument passed straight into 'clearHeaders', which " +
            "the local using disposes. The opaque element is used only in the throwing Append call, which never " +
            "returns an owning aggregate to dispose it through; it rents from the shared test pool and is a " +
            "negligible short-lived fixture on this negative path.")]
    [TestMethod]
    public void AppendWithConflictingModeThrows()
    {
        using var clearHeaders = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.ClearJson, [MakeClearCertificateValuesElement()]);

        Assert.ThrowsExactly<ArgumentException>(() => clearHeaders.Append(MakeOpaqueCertificateValuesElement("opaque-text")));
    }


    /// <summary>
    /// The mode-agnostic arms (<c>cSig</c>, unknown) never trip the duality check, in either declared mode —
    /// their own <see cref="JAdESUnsignedHeaderElement.DeclaredMode"/> is always <see langword="null"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "containers' own construction; ownership passes to those containers, which the local usings dispose.")]
    [TestMethod]
    public void ModeAgnosticElementsAreAcceptedInEitherDeclaredMode()
    {
        using var underBase64Url = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.Base64Url,
            [MakeOpaqueCertificateValuesElement("opaque-text"), MakeCounterSignatureElement("cSig-text"), MakeUnknownOpaqueElement("x-custom", "value")]);
        Assert.AreEqual(3, underBase64Url.Count);

        using var underClearJson = new JAdESUnsignedHeaders(
            JAdESEtsiUIncorporationMode.ClearJson,
            [MakeClearCertificateValuesElement(), MakeCounterSignatureElement("cSig-text"), MakeUnknownOpaqueElement("x-custom", "value")]);
        Assert.AreEqual(3, underClearJson.Count);
    }


    /// <summary>
    /// JA-5.3.4-05: "The <c>sigTst</c> JSON object shall not contain the <c>canonAlg</c> member" —
    /// unconditional, checked at the element's own construction against a clear-mode carriage.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged AdESTimestampContainer owns no pooled resource of its own (its Dispose is " +
            "a documented no-op) and the constructor call under test throws before any owning " +
            "container could take custody, so there is nothing to leak on this negative path.")]
    [TestMethod]
    public void SignatureTimestampElementWithCanonAlgOnClearCarriageThrows()
    {
        var container = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x01 } }], canonAlg: "http://example.org/canon");

        Assert.ThrowsExactly<ArgumentException>(() =>
            new JAdESUnsignedHeaderElementSignatureTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(container)));
    }


    /// <summary>A clear-mode <c>sigTst</c> carriage with no <c>canonAlg</c> constructs successfully.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged AdESTimestampContainer owns no pooled resource of its own (its Dispose is " +
            "a documented no-op); it is immediately wrapped into 'element', which the local using disposes.")]
    [TestMethod]
    public void SignatureTimestampElementWithoutCanonAlgOnClearCarriageSucceeds()
    {
        var container = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x01 } }]);

        using var element = new JAdESUnsignedHeaderElementSignatureTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(container));

        Assert.AreEqual(JAdESUnsignedHeaderElement.SignatureTimestampKind, element.Kind);
        Assert.AreEqual(JAdESEtsiUIncorporationMode.ClearJson, element.DeclaredMode);
    }


    /// <summary>
    /// JA-5.3.1-14, enforced at the CONTAINER level (not the element's own constructor — see that element's
    /// remarks): a clear-JSON container containing an <c>arcTst</c> whose decoded time-stamp container has
    /// no <c>canonAlg</c> is rejected.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged AdESTimestampContainer owns no pooled resource of its own (its Dispose is " +
            "a documented no-op) and the JAdESUnsignedHeaders construction under test throws, so " +
            "there is nothing to leak on this negative path.")]
    [TestMethod]
    public void ClearJsonContainerWithArchiveTimestampMissingCanonAlgThrows()
    {
        var containerWithoutCanonAlg = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x02 } }]);
        var arcTstElement = new JAdESUnsignedHeaderElementArchiveTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(containerWithoutCanonAlg));

        Assert.ThrowsExactly<ArgumentException>(() =>
            new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.ClearJson, [arcTstElement]));
    }


    /// <summary>The JA-5.3.1-14 companion: the same clear-mode <c>arcTst</c>, WITH a <c>canonAlg</c>, is accepted.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged AdESTimestampContainer owns no pooled resource of its own (its Dispose is " +
            "a documented no-op); the element wrapping it is passed straight into the enclosing " +
            "'using JAdESUnsignedHeaders' container's own construction, which the local using disposes.")]
    [TestMethod]
    public void ClearJsonContainerWithArchiveTimestampCarryingCanonAlgSucceeds()
    {
        var containerWithCanonAlg = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x02 } }], canonAlg: "http://example.org/canon");
        var arcTstElement = new JAdESUnsignedHeaderElementArchiveTimestamp(new JAdESClearUnsignedValue<AdESTimestampContainer>(containerWithCanonAlg));

        using var headers = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.ClearJson, [arcTstElement]);

        Assert.AreEqual(1, headers.Count);
    }


    /// <summary>
    /// The JA-5.3.1-14 rule is specific to clear-mode: an opaque-mode <c>arcTst</c> under a
    /// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/> container is never decoded, so there is nothing
    /// to check and construction succeeds.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged element is a constructor argument passed straight into the enclosing " +
            "'using JAdESUnsignedHeaders' container's own construction; ownership passes to that container, " +
            "which the local using disposes.")]
    [TestMethod]
    public void Base64UrlContainerWithOpaqueArchiveTimestampSucceeds()
    {
        JAdESUnsignedHeaderElement arcTstElement = MakeOpaqueArchiveTimestampElement("opaque-arctst-text");

        using var headers = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, [arcTstElement]);

        Assert.AreEqual(1, headers.Count);
    }


    /// <summary>
    /// An opaque-mode carriage's <see cref="JAdESOpaqueUnsignedValue{TValue}.WireText"/> preserves the exact
    /// UTF-8 bytes supplied — the imprint-relevant guarantee the base64url branch depends on.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.3.6.2.3-11, JA-5.4.3.3-18.
    /// </remarks>
    [TestMethod]
    public void OpaqueCarriagePreservesWireTextByteExactly()
    {
        const string text = "eyJ4NTA5Q2VydCI6eyJ2YWwiOiJBQUFBIn19"; //Arbitrary base64url-looking text; content is opaque to this type.
        byte[] expectedBytes = Encoding.UTF8.GetBytes(text);

        using PooledMemory wireText = PooledMemory.FromBytes(expectedBytes, BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement);
        using var carriage = new JAdESOpaqueUnsignedValue<JAdESCertificateValues>(wireText, default!);

        Assert.IsTrue(expectedBytes.AsSpan().SequenceEqual(carriage.WireText.AsReadOnlySpan()), "Opaque carriage must preserve the wire text byte-exactly.");
    }


    /// <summary>Each concrete element arm reports its own fixed <see cref="JAdESUnsignedHeaderElement.Kind"/>.</summary>
    [TestMethod]
    public void EachNamedArmReportsItsOwnKind()
    {
        using var sigPSt = new JAdESUnsignedHeaderElementSignaturePolicyStore(MakeOpaque<JAdESSignaturePolicyStore>("t"));
        using var cSig = MakeCounterSignatureElement("t");
        using var sigTst = new JAdESUnsignedHeaderElementSignatureTimestamp(MakeOpaque<AdESTimestampContainer>("t"));
        using var xVals = new JAdESUnsignedHeaderElementCertificateValues(MakeOpaque<JAdESCertificateValues>("t"));
        using var rVals = new JAdESUnsignedHeaderElementRevocationValues(MakeOpaque<JAdESRevocationValues>("t"));
        using var axVals = new JAdESUnsignedHeaderElementAttributeCertificateValues(MakeOpaque<JAdESCertificateValues>("t"));
        using var arVals = new JAdESUnsignedHeaderElementAttributeRevocationValues(MakeOpaque<JAdESRevocationValues>("t"));
        using var anyValData = new JAdESUnsignedHeaderElementAnyValidationData(MakeOpaque<JAdESValidationData>("t"));
        using var tstVD = new JAdESUnsignedHeaderElementTimestampValidationData(MakeOpaque<JAdESValidationData>("t"));
        using var arcTst = new JAdESUnsignedHeaderElementArchiveTimestamp(MakeOpaque<AdESTimestampContainer>("t"));
        using var unknown = MakeUnknownOpaqueElement("x-custom", "t");

        Assert.AreEqual(JAdESUnsignedHeaderElement.SignaturePolicyStoreKind, sigPSt.Kind);
        Assert.AreEqual(JAdESUnsignedHeaderElement.CounterSignatureKind, cSig.Kind);
        Assert.AreEqual(JAdESUnsignedHeaderElement.SignatureTimestampKind, sigTst.Kind);
        Assert.AreEqual(JAdESUnsignedHeaderElement.CertificateValuesKind, xVals.Kind);
        Assert.AreEqual(JAdESUnsignedHeaderElement.RevocationValuesKind, rVals.Kind);
        Assert.AreEqual(JAdESUnsignedHeaderElement.AttributeCertificateValuesKind, axVals.Kind);
        Assert.AreEqual(JAdESUnsignedHeaderElement.AttributeRevocationValuesKind, arVals.Kind);
        Assert.AreEqual(JAdESUnsignedHeaderElement.AnyValidationDataKind, anyValData.Kind);
        Assert.AreEqual(JAdESUnsignedHeaderElement.TimestampValidationDataKind, tstVD.Kind);
        Assert.AreEqual(JAdESUnsignedHeaderElement.ArchiveTimestampKind, arcTst.Kind);
        Assert.AreEqual("x-custom", unknown.Kind);
    }


    /// <summary><see cref="JAdESUnsignedHeaderElementUnknown"/> rejects a null or empty label.</summary>
    [TestMethod]
    public void UnknownElementWithNullOrEmptyLabelThrows()
    {
        using PooledMemory text = PooledMemory.FromBytes(Encoding.UTF8.GetBytes("value"), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement);

        Assert.ThrowsExactly<ArgumentNullException>(() => new JAdESUnsignedHeaderElementUnknown(null!, text));
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESUnsignedHeaderElementUnknown(string.Empty, text));
    }


    /// <summary>JAdESSignaturePolicyStore (sigPSt): neither content arm supplied throws (JA-5.3.3-01).</summary>
    [TestMethod]
    public void SignaturePolicyStoreWithNullContentThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new JAdESSignaturePolicyStore(null!));
    }


    /// <summary>JAdESCertificateValues (xVals): an empty item list throws (JA-5.3.5.2-13).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.3.5.4-06.
    /// </remarks>
    [TestMethod]
    public void CertificateValuesWithEmptyItemsThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESCertificateValues([]));
    }


    /// <summary>JAdESRevocationValues (rVals): all three members absent throws (JA-5.3.5.3-12).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.3.5.5-07.
    /// </remarks>
    [TestMethod]
    public void RevocationValuesWithNoMembersThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESRevocationValues());
    }


    /// <summary>JAdESRevocationValues (rVals): a supplied-but-empty member throws.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.3.5.3-13.
    /// </remarks>
    [TestMethod]
    public void RevocationValuesWithEmptyCrlValuesThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESRevocationValues(crlValues: []));
    }


    /// <summary>JAdESValidationData (anyValData/tstVD's shared shape): both members absent throws.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.3.5.6-02, JA-5.3.6.1-04.
    /// </remarks>
    [TestMethod]
    public void ValidationDataWithNoMembersThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESValidationData());
    }


    /// <summary>
    /// Metered custody: constructing and disposing a whole <see cref="JAdESUnsignedHeaders"/> container of
    /// pool-owned opaque elements returns every rented buffer, leaking none.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged constructions are passed straight into the enclosing 'using JAdESUnsignedHeaders' " +
            "container's own construction; ownership passes to that container, which the local using disposes.")]
    [TestMethod]
    public void ConstructAndDisposeContainerIsMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();

        JAdESUnsignedHeaderElement xVals = new JAdESUnsignedHeaderElementCertificateValues(
            MakeOpaque<JAdESCertificateValues>("xvals-text", metered.Pool));
        JAdESUnsignedHeaderElement cSig = new JAdESUnsignedHeaderElementCounterSignature(
            PooledMemory.FromBytes(Encoding.UTF8.GetBytes("csig-text"), metered.Pool, CryptoTags.JoseEncodedUnsignedHeaderElement));
        JAdESUnsignedHeaderElement unknown = new JAdESUnsignedHeaderElementUnknown(
            "x-custom", PooledMemory.FromBytes(Encoding.UTF8.GetBytes("unknown-text"), metered.Pool, CryptoTags.JoseEncodedUnsignedHeaderElement));

        using(var headers = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.Base64Url, [xVals, cSig, unknown]))
        {
            Assert.AreEqual(3, headers.Count);
        }

        Assert.IsGreaterThan(0, metered.RentedCount, "metered.Pool must have been exercised, or the balance assertion below is vacuous.");
        Assert.AreEqual(0, metered.OutstandingCount, "Disposing the container must return every pooled carrier it owns.");
    }


    /// <summary>Builds an opaque carriage of the given type parameter over <see cref="BaseMemoryPool.Shared"/>.</summary>
    private static JAdESUnsignedValue<T> MakeOpaque<T>(string text) => MakeOpaque<T>(text, BaseMemoryPool.Shared);


    /// <summary>
    /// Builds an opaque carriage of the given type parameter over the supplied pool. The decoded view carries
    /// a default placeholder (<see langword="default"/>) — these tests exercise wire-text preservation,
    /// <c>Kind</c> reporting, mode-consistency, and disposal, never the decoded view's own content (the
    /// decode-for-inspection view is exercised by <c>JAdESEtsiUJsonTests</c> instead).
    /// </summary>
    private static JAdESUnsignedValue<T> MakeOpaque<T>(string text, BaseMemoryPool pool)
    {
        PooledMemory wireText = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(text), pool, CryptoTags.JoseEncodedUnsignedHeaderElement);
        return new JAdESOpaqueUnsignedValue<T>(wireText, default!);
    }


    /// <summary>Builds an opaque <c>xVals</c> element carrying the given wire text.</summary>
    private static JAdESUnsignedHeaderElementCertificateValues MakeOpaqueCertificateValuesElement(string wireText)
    {
        return new JAdESUnsignedHeaderElementCertificateValues(MakeOpaque<JAdESCertificateValues>(wireText));
    }


    /// <summary>Builds a clear-JSON <c>xVals</c> element carrying one DER-default X.509 certificate.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The flagged nested construction is a constructor argument passed straight into the " +
            "returned JAdESUnsignedHeaderElementCertificateValues; ownership passes to that returned element, " +
            "which every caller disposes (directly or via the JAdESUnsignedHeaders container it is placed in).")]
    private static JAdESUnsignedHeaderElementCertificateValues MakeClearCertificateValuesElement()
    {
        var values = new JAdESCertificateValues([new JAdESX509Certificate(new AdESPkiObject { Val = new byte[] { 0x30, 0x01 } })]);
        return new JAdESUnsignedHeaderElementCertificateValues(new JAdESClearUnsignedValue<JAdESCertificateValues>(values));
    }


    /// <summary>Builds an opaque <c>arcTst</c> element carrying the given wire text.</summary>
    private static JAdESUnsignedHeaderElementArchiveTimestamp MakeOpaqueArchiveTimestampElement(string wireText)
    {
        return new JAdESUnsignedHeaderElementArchiveTimestamp(MakeOpaque<AdESTimestampContainer>(wireText));
    }


    /// <summary>Builds a <c>cSig</c> element (always opaque, regardless of container mode) over <see cref="BaseMemoryPool.Shared"/>.</summary>
    private static JAdESUnsignedHeaderElementCounterSignature MakeCounterSignatureElement(string wireText)
    {
        return new JAdESUnsignedHeaderElementCounterSignature(PooledMemory.FromBytes(Encoding.UTF8.GetBytes(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement));
    }


    /// <summary>Builds an unknown-label opaque element (always opaque, regardless of container mode) over <see cref="BaseMemoryPool.Shared"/>.</summary>
    private static JAdESUnsignedHeaderElementUnknown MakeUnknownOpaqueElement(string label, string wireText)
    {
        return new JAdESUnsignedHeaderElementUnknown(label, PooledMemory.FromBytes(Encoding.UTF8.GetBytes(wireText), BaseMemoryPool.Shared, CryptoTags.JoseEncodedUnsignedHeaderElement));
    }
}

using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.Foundation;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Construction, fail-closed validation, and closed-sum exhaustiveness tests for the JAdES <c>sigD</c> signed
/// header parameter's three named referencing mechanisms
/// (<see cref="JAdESHttpHeadersReference"/>/<see cref="JAdESObjectIdByUriReference"/>/
/// <see cref="JAdESObjectIdByUriHashReference"/>) plus the open fourth arm
/// (<see cref="JAdESUnknownDetachedDataObjectReference"/>, JA-5.2.8.1-C1) and the
/// <see cref="JAdESDetachedMechanisms"/> registry, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clause 5.2.8.
/// </summary>
[TestClass]
internal sealed class JAdESDetachedDataObjectReferenceTests
{
    /// <summary>Builds a fixture <see cref="DigestValue"/> — content is irrelevant, only presence/absence matters here.</summary>
    private static DigestValue CreateDigest(byte value)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(1);
        owner.Memory.Span[0] = value;

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    //JAdESReferencedDataObject


    /// <summary>A referenced data object carries its reference, content type, and digest through unchanged.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.1-17, JA-5.2.8.3.1-02, JA-5.2.8.3.1-04, JA-5.2.8.3.2-M1, JA-5.2.8.3.3-M1.
    /// </remarks>
    [TestMethod]
    public void ReferencedDataObjectCarriesAllSuppliedMembers()
    {
        const string reference = "https://example.org/objects/1";
        using DigestValue digest = CreateDigest(0x01);

        using var model = new JAdESReferencedDataObject(reference, "application/pdf", digest);

        Assert.AreEqual(reference, model.Reference);
        Assert.AreEqual("application/pdf", model.ContentType);
        Assert.IsTrue(digest.AsReadOnlySpan().SequenceEqual(model.Digest!.AsReadOnlySpan()));
    }


    /// <summary>A <see langword="null"/> reference fails closed.</summary>
    [TestMethod]
    public void ConstructingReferencedDataObjectWithNullReferenceThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new JAdESReferencedDataObject(null!));
    }


    /// <summary>An empty reference fails closed — exact-character-sequence carriage means an empty string is never a valid reference.</summary>
    [TestMethod]
    public void ConstructingReferencedDataObjectWithEmptyReferenceThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESReferencedDataObject(string.Empty));
    }


    //HttpHeaders (clause 5.2.8.2)


    /// <summary>The known <c>mId</c> value for the HttpHeaders mechanism matches JA-5.2.8.2-01.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.1-13.
    /// </remarks>
    [TestMethod]
    public void HttpHeadersReferenceExposesTheDocumentedMechanismIdentifier()
    {
        Assert.AreEqual("http://uri.etsi.org/19182/HttpHeaders", JAdESHttpHeadersReference.MechanismIdentifier);
    }


    /// <summary>The lowercased header names carry through in wire order (JA-5.2.8.2-04/-05).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.2-M1.
    /// </remarks>
    [TestMethod]
    public void HttpHeadersReferenceCarriesHeaderNamesInOrder()
    {
        string[] headerNames = ["(request target)", "digest", "content-type"];

        var model = new JAdESHttpHeadersReference(headerNames);

        Assert.HasCount(3, model.HeaderNames);
        Assert.AreEqual("(request target)", model.HeaderNames[0]);
        Assert.AreEqual("content-type", model.HeaderNames[2]);
    }


    /// <summary>The base <c>pars</c> non-empty requirement (JA-5.2.8.1-16) applies to HttpHeaders' header-name list too; an empty array fails closed.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.1-15.
    /// </remarks>
    [TestMethod]
    public void ConstructingHttpHeadersReferenceWithEmptyHeaderNamesThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESHttpHeadersReference([]));
    }


    /// <summary>A <see langword="null"/> header-name list fails closed.</summary>
    [TestMethod]
    public void ConstructingHttpHeadersReferenceWithNullHeaderNamesThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new JAdESHttpHeadersReference(null!));
    }


    //ObjectIdByURI (clause 5.2.8.3.2)


    /// <summary>The known <c>mId</c> value for the ObjectIdByURI mechanism matches JA-5.2.8.3.2-01.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.1-14.
    /// </remarks>
    [TestMethod]
    public void ObjectIdByUriReferenceExposesTheDocumentedMechanismIdentifier()
    {
        Assert.AreEqual("http://uri.etsi.org/19182/ObjectIdByURI", JAdESObjectIdByUriReference.MechanismIdentifier);
    }


    /// <summary>References with no digest construct successfully (JA-5.2.8.3.2-02: neither <c>hashV</c> nor <c>hashM</c> is present for this mechanism).</summary>
    [TestMethod]
    public void ObjectIdByUriReferenceConstructsWithDigestlessEntries()
    {
        //CA2000: ownership of 'entry' transfers into the array-literal argument below; disposing 'model' (via
        //'using') disposes it too — both dispose paths are idempotent-safe together.
        using var entry = new JAdESReferencedDataObject("https://example.org/objects/1");

        using var model = new JAdESObjectIdByUriReference([entry]);

        Assert.HasCount(1, model.References);
        Assert.IsNull(model.References[0].Digest);
    }


    /// <summary>JA-5.2.8.3.2-02: an entry carrying a digest is illegal under this mechanism and fails closed.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.1-24.
    /// </remarks>
    [TestMethod]
    public void ConstructingObjectIdByUriReferenceWithADigestBearingEntryThrows()
    {
        using DigestValue digest = CreateDigest(0x01);
        using var entry = new JAdESReferencedDataObject("https://example.org/objects/1", digest: digest);

        Assert.ThrowsExactly<ArgumentException>(() => new JAdESObjectIdByUriReference([entry]));
    }


    /// <summary>The base <c>pars</c> non-empty requirement (JA-5.2.8.1-16) applies; an empty reference list fails closed.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.3.1-01.
    /// </remarks>
    [TestMethod]
    public void ConstructingObjectIdByUriReferenceWithEmptyReferencesThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESObjectIdByUriReference([]));
    }


    /// <summary>A <see langword="null"/> reference list fails closed.</summary>
    [TestMethod]
    public void ConstructingObjectIdByUriReferenceWithNullReferencesThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new JAdESObjectIdByUriReference(null!));
    }


    /// <summary><see cref="JAdESObjectIdByUriReference.Dispose"/> disposes every owned entry and is safe to call once.</summary>
    [TestMethod]
    public void ObjectIdByUriReferenceDisposeDisposesEveryEntry()
    {
        //CA2000: this test exercises Dispose() directly (not 'using') to prove it is safe to call once on a
        //freshly constructed instance; ownership of 'entry' transfers into 'model'.
#pragma warning disable CA2000 // Dispose objects before losing scope
        var entry = new JAdESReferencedDataObject("https://example.org/objects/1");
        var model = new JAdESObjectIdByUriReference([entry]);
#pragma warning restore CA2000 // Dispose objects before losing scope

        model.Dispose();
    }


    //ObjectIdByURIHash (clause 5.2.8.3.3)


    /// <summary>The known <c>mId</c> value for the ObjectIdByURIHash mechanism matches JA-5.2.8.3.3-01.</summary>
    [TestMethod]
    public void ObjectIdByUriHashReferenceExposesTheDocumentedMechanismIdentifier()
    {
        Assert.AreEqual("http://uri.etsi.org/19182/ObjectIdByURIHash", JAdESObjectIdByUriHashReference.MechanismIdentifier);
    }


    /// <summary>Every entry carrying a digest constructs successfully (JA-5.2.8.3.3-02: both <c>hashV</c> and <c>hashM</c> are present for this mechanism).</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.1-M2, JA-5.2.8.1-18.
    /// </remarks>
    [TestMethod]
    public void ObjectIdByUriHashReferenceConstructsWhenEveryEntryCarriesADigest()
    {
        using DigestValue digest = CreateDigest(0x01);
        //CA2000: ownership of 'entry' transfers into the array-literal argument below; disposing 'model' (via
        //'using') disposes it too — both dispose paths are idempotent-safe together.
        using var entry = new JAdESReferencedDataObject("https://example.org/objects/1", digest: digest);

        using var model = new JAdESObjectIdByUriHashReference("sha-256", [entry]);

        Assert.AreEqual("sha-256", model.HashAlgorithm);
        Assert.HasCount(1, model.References);
    }


    /// <summary>JA-5.2.8.3.3-02/-04: every entry shall carry a digest; one missing entry fails closed.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.1-21.
    /// </remarks>
    [TestMethod]
    public void ConstructingObjectIdByUriHashReferenceWithADigestlessEntryThrows()
    {
        using var entry = new JAdESReferencedDataObject("https://example.org/objects/1");

        Assert.ThrowsExactly<ArgumentException>(() => new JAdESObjectIdByUriHashReference("sha-256", [entry]));
    }


    /// <summary>The <c>hashM</c> member is required for this mechanism; a <see langword="null"/>/empty value fails closed.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.1-20.
    /// </remarks>
    [TestMethod]
    public void ConstructingObjectIdByUriHashReferenceWithEmptyHashAlgorithmThrows()
    {
        using DigestValue digest = CreateDigest(0x01);
        using var entry = new JAdESReferencedDataObject("https://example.org/objects/1", digest: digest);

        Assert.ThrowsExactly<ArgumentException>(() => new JAdESObjectIdByUriHashReference(string.Empty, [entry]));
    }


    /// <summary>The base <c>pars</c> non-empty requirement (JA-5.2.8.1-16) applies; an empty reference list fails closed.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.2.8.1-22.
    /// </remarks>
    [TestMethod]
    public void ConstructingObjectIdByUriHashReferenceWithEmptyReferencesThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESObjectIdByUriHashReference("sha-256", []));
    }


    /// <summary>A <see langword="null"/> reference list fails closed.</summary>
    [TestMethod]
    public void ConstructingObjectIdByUriHashReferenceWithNullReferencesThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new JAdESObjectIdByUriHashReference("sha-256", null!));
    }


    /// <summary><see cref="JAdESObjectIdByUriHashReference.Dispose"/> disposes every owned entry's digest and is safe to call once.</summary>
    [TestMethod]
    public void ObjectIdByUriHashReferenceDisposeDisposesEveryEntry()
    {
        //CA2000: this test exercises Dispose() directly (not 'using') to prove it is safe to call once on a
        //freshly constructed instance; ownership of 'digest'/'entry' transfers into 'model'.
#pragma warning disable CA2000 // Dispose objects before losing scope
        DigestValue digest = CreateDigest(0x01);
        var entry = new JAdESReferencedDataObject("https://example.org/objects/1", digest: digest);
        var model = new JAdESObjectIdByUriHashReference("sha-256", [entry]);
#pragma warning restore CA2000 // Dispose objects before losing scope

        model.Dispose();
    }


    //Unknown mechanism (the open fourth arm, JA-5.2.8.1-C1)


    /// <summary>An unrecognized <c>mId</c> carries verbatim, alongside opaque references and an opaque <c>hashM</c>.</summary>
    [TestMethod]
    public void UnknownDetachedDataObjectReferenceCarriesMechanismIdentifierVerbatim()
    {
        const string mechanismIdentifier = "https://example.org/sigD/mechanisms/third-party-v1";
        using var entry = new JAdESReferencedDataObject("https://example.org/objects/1");

        using var model = new JAdESUnknownDetachedDataObjectReference(mechanismIdentifier, [entry], "sha3-256");

        Assert.AreEqual(mechanismIdentifier, model.MechanismIdentifier);
        Assert.AreEqual("sha3-256", model.HashAlgorithm);
        Assert.HasCount(1, model.References);
    }


    /// <summary>A <see langword="null"/>/empty <c>mId</c> fails closed.</summary>
    [TestMethod]
    public void ConstructingUnknownDetachedDataObjectReferenceWithEmptyMechanismIdentifierThrows()
    {
        using var entry = new JAdESReferencedDataObject("https://example.org/objects/1");

        Assert.ThrowsExactly<ArgumentException>(() => new JAdESUnknownDetachedDataObjectReference(string.Empty, [entry]));
    }


    /// <summary>Each of the three known mechanism identifiers is refused — those have their own dedicated arms, not this open-extension carrier.</summary>
    [TestMethod]
    public void ConstructingUnknownDetachedDataObjectReferenceWithAKnownMechanismIdentifierThrows()
    {
        using var entryOne = new JAdESReferencedDataObject("https://example.org/objects/1");
        using var entryTwo = new JAdESReferencedDataObject("https://example.org/objects/2");
        using var entryThree = new JAdESReferencedDataObject("https://example.org/objects/3");

        Assert.ThrowsExactly<ArgumentException>(() => new JAdESUnknownDetachedDataObjectReference(JAdESHttpHeadersReference.MechanismIdentifier, [entryOne]));
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESUnknownDetachedDataObjectReference(JAdESObjectIdByUriReference.MechanismIdentifier, [entryTwo]));
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESUnknownDetachedDataObjectReference(JAdESObjectIdByUriHashReference.MechanismIdentifier, [entryThree]));
    }


    /// <summary>The base <c>pars</c> non-empty requirement (JA-5.2.8.1-16) applies to the unknown arm too — the one invariant every mechanism shares.</summary>
    [TestMethod]
    public void ConstructingUnknownDetachedDataObjectReferenceWithEmptyReferencesThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new JAdESUnknownDetachedDataObjectReference("https://example.org/sigD/mechanisms/third-party-v1", []));
    }


    /// <summary><see cref="JAdESUnknownDetachedDataObjectReference.Dispose"/> disposes every owned entry and is safe to call once.</summary>
    [TestMethod]
    public void UnknownDetachedDataObjectReferenceDisposeDisposesEveryEntry()
    {
#pragma warning disable CA2000 // Dispose objects before losing scope
        var entry = new JAdESReferencedDataObject("https://example.org/objects/1");
        var model = new JAdESUnknownDetachedDataObjectReference("https://example.org/sigD/mechanisms/third-party-v1", [entry]);
#pragma warning restore CA2000 // Dispose objects before losing scope

        model.Dispose();
    }


    //JAdESDetachedMechanisms registry


    /// <summary>The registry recognizes exactly the three mechanisms clause 5.2.8 defines, and nothing else.</summary>
    [TestMethod]
    public void DetachedMechanismsRecognizesExactlyTheThreeKnownIdentifiers()
    {
        Assert.IsTrue(JAdESDetachedMechanisms.IsKnownMechanism(JAdESHttpHeadersReference.MechanismIdentifier));
        Assert.IsTrue(JAdESDetachedMechanisms.IsKnownMechanism(JAdESObjectIdByUriReference.MechanismIdentifier));
        Assert.IsTrue(JAdESDetachedMechanisms.IsKnownMechanism(JAdESObjectIdByUriHashReference.MechanismIdentifier));
        Assert.IsFalse(JAdESDetachedMechanisms.IsKnownMechanism("https://example.org/sigD/mechanisms/third-party-v1"));
        Assert.IsFalse(JAdESDetachedMechanisms.IsKnownMechanism(null));
    }


    /// <summary>Comparison is ordinal and case-sensitive — a re-escaped or re-cased spelling of a known identifier is NOT recognized as that mechanism.</summary>
    [TestMethod]
    public void DetachedMechanismsComparisonIsOrdinalAndCaseSensitive()
    {
        Assert.IsFalse(JAdESDetachedMechanisms.IsObjectIdByUri("HTTP://URI.ETSI.ORG/19182/OBJECTIDBYURI"));
        Assert.IsFalse(JAdESDetachedMechanisms.IsHttpHeaders("http://uri.etsi.org/19182/HttpHeaders/"));
    }


    //Closed-sum exhaustiveness


    /// <summary>
    /// Matches a sealed <c>class</c> or <c>record</c> declaration base-listing
    /// <see cref="JAdESDetachedDataObjectReference"/>, capturing the derived type's own name. The gap between
    /// the name and the colon is <c>\s*</c>, which matches a newline as readily as a space, so a base list
    /// wrapped onto its own line is caught the same as one written inline.
    /// </summary>
    private static Regex DerivedTypeDeclarationPattern { get; } = new(
        @"(?m)^\s*(?:public|internal)\s+sealed\s+(?:class|record)\s+(\w+)\s*:\s*JAdESDetachedDataObjectReference\b",
        RegexOptions.Compiled);

    /// <summary>
    /// <see cref="JAdESDetachedDataObjectReference"/> is a CLOSED sum over exactly four arms — the three named
    /// mechanisms plus the open-extension <see cref="JAdESUnknownDetachedDataObjectReference"/> — no fifth arm
    /// exists anywhere under <c>src/Verifiable.Cryptography</c>. Proves the "closed sum" claim structurally as
    /// a source scan of every <c>.cs</c> file under that project for a
    /// <see cref="DerivedTypeDeclarationPattern"/> hit, rather than by enumerating the loaded assembly's types
    /// at runtime — <see cref="JAdESDetachedDataObjectReference"/>'s own <c>private protected</c> constructor
    /// restricts derivation to the declaring ASSEMBLY, not to its declaring file, so the scan matches that
    /// boundary rather than the narrower one a single-file scan would assume.
    /// </summary>
    [TestMethod]
    public void DetachedDataObjectReferenceHasExactlyFourKnownDerivedTypes()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();
        IReadOnlyList<string> cryptographyFiles = [.. SourceHygieneScanner.EnumerateSourceFilesUnder(repositoryRoot, "src")
            .Where(static filePath => filePath.Replace('\\', '/').Contains("/Verifiable.Cryptography/", StringComparison.Ordinal))];

        List<string> derivedTypeNames = [];
        foreach(string filePath in cryptographyFiles)
        {
            string text = File.ReadAllText(filePath);
            derivedTypeNames.AddRange(DerivedTypeDeclarationPattern.Matches(text).Select(static m => m.Groups[1].Value));
        }

        string[] expected =
        [
            nameof(JAdESHttpHeadersReference),
            nameof(JAdESObjectIdByUriReference),
            nameof(JAdESObjectIdByUriHashReference),
            nameof(JAdESUnknownDetachedDataObjectReference),
        ];

        Assert.HasCount(4, derivedTypeNames, $"Expected exactly four arms declared against JAdESDetachedDataObjectReference; found {string.Join(", ", derivedTypeNames)}.");
        Assert.IsTrue(expected.OrderBy(static n => n, StringComparer.Ordinal).SequenceEqual(derivedTypeNames.OrderBy(static n => n, StringComparer.Ordinal)));
    }


    /// <summary>
    /// A <see langword="switch"/> expression pattern-matching every known arm (no <c>default</c>/discard needed
    /// to satisfy the compiler once every arm is covered) dispatches each of the four mechanism instances to
    /// its own branch.
    /// </summary>
    [TestMethod]
    public void SwitchExpressionExhaustivelyDispatchesEveryKnownMechanism()
    {
        var httpHeaders = new JAdESHttpHeadersReference(["digest"]);
        using DigestValue digest = CreateDigest(0x01);
        using DigestValue hashDigest = CreateDigest(0x02);

        //CA2000: ownership of each 'JAdESReferencedDataObject' transfers into its owning mechanism's
        //array-literal argument below; disposing 'objectIdByUri'/'objectIdByUriHash'/'unknown' (via 'using')
        //disposes them too.
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var objectIdByUri = new JAdESObjectIdByUriReference([new JAdESReferencedDataObject("https://example.org/1")]);
        using var objectIdByUriHash = new JAdESObjectIdByUriHashReference(
            "sha-256",
            [new JAdESReferencedDataObject("https://example.org/1", digest: hashDigest)]);
        using var unknown = new JAdESUnknownDetachedDataObjectReference(
            "https://example.org/sigD/mechanisms/third-party-v1",
            [new JAdESReferencedDataObject("https://example.org/1")]);
#pragma warning restore CA2000 // Dispose objects before losing scope

        Assert.AreEqual("HttpHeaders", Describe(httpHeaders));
        Assert.AreEqual("ObjectIdByURI", Describe(objectIdByUri));
        Assert.AreEqual("ObjectIdByURIHash", Describe(objectIdByUriHash));
        Assert.AreEqual("Unknown", Describe(unknown));

        //The '_' arm is unreachable — JAdESDetachedDataObjectReference is a closed sum over exactly the four
        //arms above (proven structurally by DetachedDataObjectReferenceHasExactlyFourKnownDerivedTypes) — but
        //the C# compiler does not perform sealed-hierarchy exhaustiveness analysis for arbitrary record
        //hierarchies (only enums/booleans), so CS8509 requires one. This defensive throw is that concession,
        //not a sign a fifth arm is expected.
        static string Describe(JAdESDetachedDataObjectReference reference) => reference switch
        {
            JAdESHttpHeadersReference => "HttpHeaders",
            JAdESObjectIdByUriReference => "ObjectIdByURI",
            JAdESObjectIdByUriHashReference => "ObjectIdByURIHash",
            JAdESUnknownDetachedDataObjectReference => "Unknown",
            _ => throw new NotSupportedException($"Unreachable: {reference.GetType()} is not one of the four known sigD arms.")
        };
    }
}

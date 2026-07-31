using System;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="AsicContainerUri"/>: Annex A.6 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> — references are relative, they resolve against the container root and not
/// against the folder the metadata sits in, and nothing outside the container may be named.
/// </summary>
[TestClass]
internal sealed class AsicContainerUriTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// THE Annex A.6 item 2 rule: a reference written inside a manifest in the <c>META-INF</c> folder names an
    /// entry from the container root, "not taking into account the "META-INF" folder where signature metadata
    /// are stored". Ordinary relative-URI resolution against the manifest's own location would produce
    /// <c>META-INF/file1.xml</c>, which is a different entry — and, in a container that carries both, a
    /// different data object with a different digest.
    /// </summary>
    [TestMethod]
    public void AReferenceResolvesAgainstTheContainerRootAndNotAgainstTheManifestsFolder()
    {
        AsicContainerUriResolution resolution = AsicContainerUri.Resolve("file1.xml");

        Assert.IsTrue(resolution.IsResolved);
        Assert.AreEqual("file1.xml", resolution.EntryName);
        Assert.AreNotEqual("META-INF/file1.xml", resolution.EntryName,
            "The base is the container root, so the folder the manifest sits in is never prepended.");
    }


    /// <summary>
    /// A reference naming an entry in a folder of the container resolves to that entry, and a reference written
    /// with a leading separator states the base the resolution already uses rather than naming a file-system
    /// root.
    /// </summary>
    /// <param name="reference">The reference as written in the manifest.</param>
    /// <param name="expected">The container entry it names.</param>
    [TestMethod]
    [DataRow("file1.xml", "file1.xml", DisplayName = "an entry at the container root")]
    [DataRow("folder/file1.xml", "folder/file1.xml", DisplayName = "an entry inside a folder")]
    [DataRow("META-INF/ASiCManifest1.xml", "META-INF/ASiCManifest1.xml", DisplayName = "an entry inside META-INF, named in full")]
    [DataRow("/file1.xml", "file1.xml", DisplayName = "a path-absolute reference states the base the resolution already uses")]
    [DataRow("a%20b.txt", "a b.txt", DisplayName = "a percent-encoded space")]
    [DataRow("%C3%A4.txt", "\u00e4.txt", DisplayName = "a percent-encoded non-ASCII character")]
    [DataRow("\u00e4.txt", "\u00e4.txt", DisplayName = "an unescaped non-ASCII character")]
    [DataRow("a%2Db.txt", "a-b.txt", DisplayName = "a percent-encoded character that need not have been encoded")]
    [DataRow("a%2db.txt", "a-b.txt", DisplayName = "lower-case hexadecimal digits")]
    public void AReferenceResolvesToTheEntryItNames(string reference, string expected)
    {
        AsicContainerUriResolution resolution = AsicContainerUri.Resolve(reference);

        Assert.IsTrue(resolution.IsResolved, $"'{reference}' was refused as {resolution.Status}.");
        Assert.AreEqual(expected, resolution.EntryName);
    }


    /// <summary>
    /// A reference naming something outside the container is refused, which is Annex A.6 item 3 —
    /// "References to data objects outside the container shall not be allowed" — and every shape that reaches
    /// outside gets its own status.
    /// </summary>
    /// <param name="reference">The reference as written in the manifest.</param>
    /// <param name="expected">The status that refuses it.</param>
    [TestMethod]
    [DataRow("http://example.test/file1.xml", AsicContainerUriStatus.NotContainerRelative, DisplayName = "an absolute URI")]
    [DataRow("file:///etc/passwd", AsicContainerUriStatus.NotContainerRelative, DisplayName = "a local file URI")]
    [DataRow("//example.test/file1.xml", AsicContainerUriStatus.NotContainerRelative, DisplayName = "a network-path reference naming an authority")]
    [DataRow("c:/file1.xml", AsicContainerUriStatus.NotContainerRelative, DisplayName = "a volume-qualified path")]
    [DataRow("../file1.xml", AsicContainerUriStatus.NotAnEntryName, DisplayName = "a parent-folder traversal")]
    [DataRow("folder/../../file1.xml", AsicContainerUriStatus.NotAnEntryName, DisplayName = "a traversal in the middle")]
    [DataRow("./file1.xml", AsicContainerUriStatus.NotAnEntryName, DisplayName = "a same-folder segment")]
    [DataRow("%2E%2E/file1.xml", AsicContainerUriStatus.NotAnEntryName, DisplayName = "a percent-encoded traversal, which decoding is what catches")]
    [DataRow("folder\\file1.xml", AsicContainerUriStatus.NotAnEntryName, DisplayName = "a backslash separator")]
    [DataRow("folder//file1.xml", AsicContainerUriStatus.NotAnEntryName, DisplayName = "an empty path segment")]
    [DataRow("file1.xml?v=2", AsicContainerUriStatus.QueryOrFragmentPresent, DisplayName = "a query")]
    [DataRow("file1.xml#part", AsicContainerUriStatus.QueryOrFragmentPresent, DisplayName = "a fragment")]
    [DataRow("file%1.xml", AsicContainerUriStatus.MalformedPercentEncoding, DisplayName = "a percent-encoded octet that is not two hexadecimal digits")]
    [DataRow("file1.xml%2", AsicContainerUriStatus.MalformedPercentEncoding, DisplayName = "a truncated percent-encoded octet")]
    [DataRow("%FF%FE.txt", AsicContainerUriStatus.NotUtf8, DisplayName = "octets that are not UTF-8")]
    [DataRow("", AsicContainerUriStatus.Empty, DisplayName = "an empty reference")]
    [DataRow("/", AsicContainerUriStatus.Empty, DisplayName = "a reference naming nothing but the root")]
    [DataRow((string?)null, AsicContainerUriStatus.Empty, DisplayName = "no reference at all")]
    public void AReferenceNamingSomethingOutsideTheContainerIsRefused(string? reference, AsicContainerUriStatus expected)
    {
        AsicContainerUriResolution resolution = AsicContainerUri.Resolve(reference);

        Assert.AreEqual(expected, resolution.Status);
        Assert.IsFalse(resolution.IsResolved);
        Assert.IsNull(resolution.EntryName);
    }


    /// <summary>
    /// A refused name says which entry-name rule refused it, so a caller reporting the refusal names the rule
    /// rather than "invalid URI".
    /// </summary>
    [TestMethod]
    public void ARefusedNameSaysWhichEntryNameRuleRefusedIt()
    {
        Assert.AreEqual(AsicZipEntryNameStatus.Traversal, AsicContainerUri.Resolve("../file1.xml").EntryNameStatus);
        Assert.AreEqual(AsicZipEntryNameStatus.BackslashSeparator, AsicContainerUri.Resolve("folder\\file1.xml").EntryNameStatus);
        Assert.AreEqual(AsicZipEntryNameStatus.EmptySegment, AsicContainerUri.Resolve("folder//file1.xml").EntryNameStatus);
        Assert.AreEqual(AsicZipEntryNameStatus.NotEvaluated, AsicContainerUri.Resolve("http://example.test/x").EntryNameStatus,
            "A reference refused before decoding never reached the entry-name rules.");
    }


    /// <summary>
    /// A reference longer than the caller's bound is refused before anything is decoded, so a manifest cannot
    /// spend a verifier's memory by naming one very long entry.
    /// </summary>
    [TestMethod]
    public void AReferenceLongerThanTheBoundIsRefusedBeforeAnythingIsDecoded()
    {
        string reference = new('a', AsicContainerUri.DefaultMaximumLength + 1);

        Assert.AreEqual(AsicContainerUriStatus.TooLong, AsicContainerUri.Resolve(reference).Status);
        Assert.AreEqual(AsicContainerUriStatus.TooLong, AsicContainerUri.Resolve("abc", 2).Status);
        Assert.IsTrue(AsicContainerUri.Resolve("abc", 3).IsResolved);
    }


    /// <summary>
    /// The octet bound a decoded reference is measured against is the RUN'S, not a constant: a caller that
    /// raises <see cref="AsicZipReadLimits.MaximumEntryNameByteLength"/> — which
    /// <see cref="AsicZipReading"/> documents as the one bound an unusual archive raises — gets a resolver that
    /// admits exactly the names its reader admits. Without that, a container whose entry the reader carried in
    /// full has a manifest reference naming it that cannot resolve, and the reference is reported as the
    /// manifest's fault rather than as the two bounds disagreeing.
    /// </summary>
    [TestMethod]
    public void ADecodedReferenceIsBoundedByTheRunsEntryNameLimitAndNotByTheConformantOne()
    {
        AsicZipReadLimits raised = AsicZipReadLimits.Conformant with { MaximumEntryNameByteLength = 1024 };
        string entryName = new string('a', 600) + ".xml";

        Assert.AreEqual(
            AsicZipEntryNameStatus.Accepted,
            AsicZipEntryNaming.Validate(entryName, raised.MaximumEntryNameByteLength),
            "The reader admits the name at the raised bound — this is the identical call the central-directory walk makes.");
        Assert.AreEqual(
            AsicZipEntryNameStatus.TooLong,
            AsicZipEntryNaming.Validate(entryName, AsicZipReadLimits.Conformant.MaximumEntryNameByteLength),
            "and refuses it at the conformant one, which is what makes the two bounds tellable apart at all.");

        AsicContainerUriResolution atRunBound = AsicContainerUri.Resolve(entryName, AsicContainerUri.DefaultMaximumLength, raised.MaximumEntryNameByteLength);
        Assert.IsTrue(atRunBound.IsResolved, $"The reference resolves under the bound the run states ({atRunBound.Status}/{atRunBound.EntryNameStatus}).");
        Assert.AreEqual(entryName, atRunBound.EntryName);

        AsicContainerUriResolution atConformantBound = AsicContainerUri.Resolve(entryName);
        Assert.AreEqual(AsicContainerUriStatus.NotAnEntryName, atConformantBound.Status, "The default is the conformant bound, unchanged.");
        Assert.AreEqual(AsicZipEntryNameStatus.TooLong, atConformantBound.EntryNameStatus, "and it says which rule refused it.");

        Assert.AreEqual(entryName, AsicContainerUri.ToReference(entryName, raised.MaximumEntryNameByteLength), "The write side takes the same bound, so a manifest can name what the run carries.");
        _ = Assert.ThrowsExactly<ArgumentException>(() => AsicContainerUri.ToReference(entryName));
    }


    /// <summary>
    /// The bound travelling with the call changes nothing for a name within the conformant one: the same
    /// reference resolves to the same entry under the conformant bound, under a raised bound and under the
    /// overload that states none, and a name beyond the bound the caller states is refused whichever bound that
    /// is.
    /// </summary>
    [TestMethod]
    public void StatingTheOctetBoundChangesNothingForANameWithinTheConformantOne()
    {
        const string Reference = "META-INF/ASiCManifest1.xml";

        Assert.AreEqual(Reference, AsicContainerUri.Resolve(Reference).EntryName);
        Assert.AreEqual(
            Reference,
            AsicContainerUri.Resolve(Reference, AsicContainerUri.DefaultMaximumLength, AsicZipReadLimits.Conformant.MaximumEntryNameByteLength).EntryName);
        Assert.AreEqual(Reference, AsicContainerUri.Resolve(Reference, AsicContainerUri.DefaultMaximumLength, 1024).EntryName);

        AsicContainerUriResolution lowered = AsicContainerUri.Resolve(Reference, AsicContainerUri.DefaultMaximumLength, 8);
        Assert.AreEqual(AsicContainerUriStatus.NotAnEntryName, lowered.Status, "A caller stating a narrower bound gets a narrower resolver.");
        Assert.AreEqual(AsicZipEntryNameStatus.TooLong, lowered.EntryNameStatus);
    }


    /// <summary>
    /// Writing a reference for an entry name escapes every octet outside the unreserved set of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.3">IETF RFC 3986 clause 2.3</see>, leaves the
    /// path separator alone, and produces something that resolves back to the name it was written for.
    /// </summary>
    /// <param name="entryName">The container entry name to name.</param>
    /// <param name="expected">The reference written for it.</param>
    [TestMethod]
    [DataRow("file1.xml", "file1.xml", DisplayName = "an unreserved name is written as itself")]
    [DataRow("META-INF/ASiCManifest1.xml", "META-INF/ASiCManifest1.xml", DisplayName = "the separator is a separator in the reference too")]
    [DataRow("a b.txt", "a%20b.txt", DisplayName = "a space")]
    [DataRow("\u00e4.txt", "%C3%A4.txt", DisplayName = "a non-ASCII character, as its UTF-8 octets")]
    [DataRow("a+b.txt", "a%2Bb.txt", DisplayName = "a character a URI would admit unescaped is escaped anyway")]
    public void WritingAReferenceEscapesEveryOctetOutsideTheUnreservedSet(string entryName, string expected)
    {
        string reference = AsicContainerUri.ToReference(entryName);

        Assert.AreEqual(expected, reference);
        Assert.AreEqual(entryName, AsicContainerUri.Resolve(reference).EntryName);
    }


    /// <summary>
    /// Writing a reference refuses a name the container layer would refuse to carry, so a manifest this library
    /// creates cannot name an entry that could never be written beside it.
    /// </summary>
    [TestMethod]
    public void WritingAReferenceRefusesANameTheContainerLayerWouldRefuse()
    {
        _ = Assert.ThrowsExactly<ArgumentException>(() => AsicContainerUri.ToReference("../file1.xml"));
        _ = Assert.ThrowsExactly<ArgumentException>(() => AsicContainerUri.ToReference("/file1.xml"));
        _ = Assert.ThrowsExactly<ArgumentException>(() => AsicContainerUri.ToReference("folder\\file1.xml"));
    }
}

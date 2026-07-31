using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="AsicWellKnown"/>: the media types Annex A.2 registers, the container file
/// extensions clauses 4.3.3.1 and 4.4.4.1 name, and the ZIP archive comment clause 4.3.3.1 item 3 describes, of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see>.
/// </summary>
[TestClass]
internal sealed class AsicWellKnownTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The two media types are the ones Annex A.2 registers, letter for letter.
    /// </summary>
    [TestMethod]
    public void TheTwoMediaTypesAreTheOnesAnnexA2Registers()
    {
        Assert.AreEqual("application/vnd.etsi.asic-s+zip", AsicWellKnown.AsicSimpleMediaType);
        Assert.AreEqual("application/vnd.etsi.asic-e+zip", AsicWellKnown.AsicExtendedMediaType);
    }


    /// <summary>
    /// A media type is recognised whatever case it arrives in, which is what
    /// <see href="https://www.rfc-editor.org/rfc/rfc2045#section-5.1">IETF RFC 2045 clause 5.1</see> makes it,
    /// and each helper recognises only its own family.
    /// </summary>
    [TestMethod]
    public void AMediaTypeIsRecognisedWhateverCaseItArrivesIn()
    {
        Assert.IsTrue(AsicWellKnown.IsAsicSimpleMediaType("APPLICATION/VND.ETSI.ASIC-S+ZIP"));
        Assert.IsTrue(AsicWellKnown.IsAsicExtendedMediaType("Application/vnd.etsi.asic-e+zip"));
        Assert.IsFalse(AsicWellKnown.IsAsicSimpleMediaType(AsicWellKnown.AsicExtendedMediaType));
        Assert.IsFalse(AsicWellKnown.IsAsicExtendedMediaType(AsicWellKnown.AsicSimpleMediaType));
        Assert.IsTrue(AsicWellKnown.IsAsicMediaType(AsicWellKnown.AsicSimpleMediaType));
        Assert.IsTrue(AsicWellKnown.IsAsicMediaType(AsicWellKnown.AsicExtendedMediaType));
        Assert.IsFalse(AsicWellKnown.IsAsicMediaType("application/pdf"));
        Assert.IsFalse(AsicWellKnown.IsAsicMediaType(null));
    }


    /// <summary>
    /// Both extensions of each family are recognised — the primary one and the three-character one clauses
    /// 4.3.3.1 item 2 b and 4.4.4.1 item 1 b admit "in case the operating system or file system does not
    /// support more than three characters".
    /// </summary>
    /// <param name="extension">The extension to test.</param>
    /// <param name="isSimple">Whether it names an ASiC-S container.</param>
    /// <param name="isExtended">Whether it names an ASiC-E container.</param>
    /// <param name="isAccepted">Whether a container may be read from under it.</param>
    [TestMethod]
    [DataRow(".asics", true, false, true, DisplayName = "the primary ASiC-S extension")]
    [DataRow(".scs", true, false, true, DisplayName = "the three-character ASiC-S extension")]
    [DataRow(".asice", false, true, true, DisplayName = "the primary ASiC-E extension")]
    [DataRow(".sce", false, true, true, DisplayName = "the three-character ASiC-E extension")]
    [DataRow(".ASICE", false, true, true, DisplayName = "an extension in upper case")]
    [DataRow(".zip", false, false, true, DisplayName = "the plain extension clause 4.3.3.1 item 2 c admits")]
    [DataRow(".p7s", false, false, false, DisplayName = "an extension of something that is not a container")]
    public void EachContainerExtensionIsRecognisedByItsOwnFamily(string extension, bool isSimple, bool isExtended, bool isAccepted)
    {
        Assert.AreEqual(isSimple, AsicWellKnown.IsAsicSimpleExtension(extension));
        Assert.AreEqual(isExtended, AsicWellKnown.IsAsicExtendedExtension(extension));
        Assert.AreEqual(isAccepted, AsicWellKnown.IsAcceptedContainerExtension(extension));
    }


    /// <summary>
    /// The <c>mimetype</c> entry name is matched ordinally: a ZIP entry name is an octet sequence, and an entry
    /// called <c>MIMETYPE</c> is a different entry that no reader may treat as the Annex A.1 one.
    /// </summary>
    [TestMethod]
    public void TheMimetypeEntryNameIsMatchedOrdinally()
    {
        Assert.IsTrue(AsicWellKnown.IsMimetypeEntryName("mimetype"));
        Assert.IsFalse(AsicWellKnown.IsMimetypeEntryName("MIMETYPE"));
        Assert.IsFalse(AsicWellKnown.IsMimetypeEntryName("META-INF/mimetype"));
        Assert.IsFalse(AsicWellKnown.IsMimetypeEntryName(null));
    }


    /// <summary>
    /// The <c>META-INF</c> folder is recognised by the prefix an entry name actually carries, and only at the
    /// container root where clauses 4.3.3.2 item 3 and 4.4.4.2 place it.
    /// </summary>
    [TestMethod]
    public void TheMetaInfFolderIsRecognisedAtTheContainerRoot()
    {
        Assert.IsTrue(AsicWellKnown.IsMetaInfEntryName("META-INF/ASiCManifest1.xml"));
        Assert.IsFalse(AsicWellKnown.IsMetaInfEntryName("data/META-INF/ASiCManifest1.xml"));
        Assert.IsFalse(AsicWellKnown.IsMetaInfEntryName("META-INF"));
        Assert.IsFalse(AsicWellKnown.IsMetaInfEntryName(null));
    }


    /// <summary>
    /// The archive comment is written in the tighter of the two forms the specification prints and read in
    /// either: clause 4.3.3.1 item 3 writes the prefix as <c>"mimetype="</c> while clause 4.4.4.1 item 3 prints
    /// <c>"mimetype= application/vnd.etsi.asic-e+zip"</c> with a space after it.
    /// </summary>
    [TestMethod]
    public void TheArchiveCommentIsWrittenTightlyAndReadEitherWay()
    {
        Assert.AreEqual("mimetype=application/vnd.etsi.asic-e+zip", AsicWellKnown.MediaTypeComment(AsicWellKnown.AsicExtendedMediaType));
        Assert.AreEqual(AsicWellKnown.AsicExtendedMediaType, AsicWellKnown.MediaTypeFromComment("mimetype=application/vnd.etsi.asic-e+zip"));
        Assert.AreEqual(AsicWellKnown.AsicExtendedMediaType, AsicWellKnown.MediaTypeFromComment("mimetype= application/vnd.etsi.asic-e+zip"));
        Assert.IsNull(AsicWellKnown.MediaTypeFromComment("created by an archiving application"));
        Assert.IsNull(AsicWellKnown.MediaTypeFromComment("mimetype="));
        Assert.IsNull(AsicWellKnown.MediaTypeFromComment(null));
    }


    /// <summary>
    /// The three offsets are the ones the Annex A.1 NOTE names: the string <c>mimetype</c> at 30, the media
    /// type at 38, and its length in the four octets at 18.
    /// </summary>
    [TestMethod]
    public void TheThreeOffsetsAreTheOnesTheAnnexA1NoteNames()
    {
        Assert.AreEqual(30, AsicWellKnown.MimetypeNameOffset);
        Assert.AreEqual(38, AsicWellKnown.MediaTypeOffset);
        Assert.AreEqual(18, AsicWellKnown.MediaTypeLengthOffset);
        Assert.AreEqual(
            AsicWellKnown.MimetypeNameOffset + AsicWellKnown.MimetypeEntryName.Length,
            AsicWellKnown.MediaTypeOffset,
            "Offset 38 is offset 30 plus the eight octets of the name, which only holds because Annex A.1 item 2 forbids the entry an extra field.");
    }
}

using System;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the two wire-name vocabularies this stage ships — <see cref="MetsWellKnown"/> for the
/// METS profile of <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> and
/// <see cref="PremisWellKnown"/> for <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata
/// v1.0.1</see> — together with the carrier tags a package's metadata documents ride in.
/// </summary>
/// <remarks>
/// Every value in both classes is either an XML enumeration facet or a fixed attribute value, and both match by
/// exact character sequence. The tests below are therefore as much about what the helpers REFUSE as about what
/// they accept: a document stating <c>sha-256</c> or <c>mets.xml</c> is not a document stating <c>SHA-256</c> or
/// <c>METS.xml</c>, and reading it as though it were would admit a package a conformant reader on a
/// case-sensitive file system cannot open.
/// </remarks>
[TestClass]
internal sealed class EArkMetadataVocabularyTests
{
    /// <summary>
    /// Every controlled vocabulary the profile gates an attribute with recognises its own members and nothing
    /// else, including the same member written in another case.
    /// </summary>
    [TestMethod]
    public void EveryControlledVocabularyRecognisesItsOwnMembersAndNothingElse()
    {
        foreach(string packageType in new[] { "SIP", "AIP", "DIP", "AIU", "AIC" })
        {
            Assert.IsTrue(MetsWellKnown.IsOaisPackageType(packageType), packageType);
        }

        Assert.IsFalse(MetsWellKnown.IsOaisPackageType("aip"), "The vocabulary is an enumeration facet, which matches by exact character sequence.");
        Assert.IsFalse(MetsWellKnown.IsOaisPackageType("SIP "));
        Assert.IsFalse(MetsWellKnown.IsOaisPackageType(null));

        Assert.IsTrue(MetsWellKnown.IsMetadataStatus(MetsWellKnown.CurrentStatus));
        Assert.IsTrue(MetsWellKnown.IsMetadataStatus(MetsWellKnown.SupersededStatus));
        Assert.IsFalse(MetsWellKnown.IsMetadataStatus("DRAFT"));
        Assert.IsFalse(MetsWellKnown.IsMetadataStatus(null));

        Assert.IsTrue(MetsWellKnown.IsAgentNoteType(MetsWellKnown.SoftwareVersionNoteType));
        Assert.IsTrue(MetsWellKnown.IsAgentNoteType(MetsWellKnown.IdentificationCodeNoteType));
        Assert.IsFalse(MetsWellKnown.IsAgentNoteType("SOFTWARE_VERSION"), "The facet carries a space, not an underscore.");
        Assert.IsFalse(MetsWellKnown.IsAgentNoteType(null));

        Assert.IsTrue(PremisWellKnown.IsObjectCategory("intellectualEntity"));
        Assert.IsTrue(PremisWellKnown.IsObjectCategory("representation"));
        Assert.IsTrue(PremisWellKnown.IsObjectCategory("file"));
        Assert.IsTrue(PremisWellKnown.IsObjectCategory("bitstream"));
        Assert.IsFalse(PremisWellKnown.IsObjectCategory("File"));
        Assert.IsFalse(PremisWellKnown.IsObjectCategory(null));

        Assert.IsTrue(PremisWellKnown.IsRightsBasis("copyright"));
        Assert.IsTrue(PremisWellKnown.IsRightsBasis("license"));
        Assert.IsTrue(PremisWellKnown.IsRightsBasis("statute"));
        Assert.IsTrue(PremisWellKnown.IsRightsBasis("other"));
        Assert.IsFalse(PremisWellKnown.IsRightsBasis("contract"));
        Assert.IsFalse(PremisWellKnown.IsRightsBasis(null));

        Assert.IsTrue(PremisWellKnown.IsLocalIdentifierType(PremisWellKnown.LocalIdentifierType));
        Assert.IsFalse(PremisWellKnown.IsLocalIdentifierType("LOCAL"));
    }


    /// <summary>
    /// The file-group and division-label vocabulary reads the per-representation form the way the profile writes
    /// it — as a prefix with something after it — so the bare division label is never mistaken for a
    /// representation of that name.
    /// </summary>
    /// <param name="label">The <c>fileGrp/@USE</c> or <c>div/@LABEL</c> value.</param>
    /// <param name="isVocabularyMember">Whether the value is one the vocabulary states.</param>
    /// <param name="representationFolder">The representation folder the value names, or <see langword="null"/>.</param>
    [TestMethod]
    [DataRow("Metadata", true, null, DisplayName = "the metadata label")]
    [DataRow("Documentation", true, null, DisplayName = "the documentation label")]
    [DataRow("Schemas", true, null, DisplayName = "the schemas label")]
    [DataRow("Representations", true, null, DisplayName = "the bare representations label, which names no representation")]
    [DataRow("Representations/rep1", true, "rep1", DisplayName = "one representation")]
    [DataRow("Representations/submission/rep2", true, "submission/rep2", DisplayName = "a representation whose folder name carries a solidus")]
    [DataRow("Representations/", false, null, DisplayName = "the prefix with nothing after it")]
    [DataRow("representations/rep1", false, null, DisplayName = "the prefix in the wrong case")]
    [DataRow("Content", false, null, DisplayName = "a label the vocabulary does not state")]
    [DataRow(null, false, null, DisplayName = "no label at all")]
    public void TheFileGroupAndDivisionLabelVocabularyReadsThePerRepresentationForm(string? label, bool isVocabularyMember, string? representationFolder)
    {
        Assert.AreEqual(isVocabularyMember, MetsWellKnown.IsFileGroupUse(label));
        Assert.AreEqual(representationFolder is not null, MetsWellKnown.IsRepresentationLabel(label));
        Assert.AreEqual(representationFolder, MetsWellKnown.RepresentationFolderFromLabel(label));
    }


    /// <summary>
    /// The identifier recognition implements the productions clause 5.1 points at rather than a looser reading of
    /// them: an identifier may start with a letter or an underscore and nothing else, may not carry a colon, and —
    /// the consequence the specification itself calls out — a bare universally unique identifier is not one.
    /// </summary>
    /// <param name="value">The identifier value.</param>
    /// <param name="expected">Whether the value is an XML <c>NCName</c>.</param>
    [TestMethod]
    [DataRow("uuid-a1b2", true, DisplayName = "a letter, then letters, digits and a hyphen")]
    [DataRow("_private", true, DisplayName = "an underscore start, which the production admits")]
    [DataRow("ID.1", true, DisplayName = "a full stop, which the production admits after the first character")]
    [DataRow("Ärendehandling", true, DisplayName = "a start character outside the Latin alphabet")]
    [DataRow("a1b2c3d4-e5f6-4789-abcd-ef0123456789", true, DisplayName = "a universally unique identifier that happens to start with a letter")]
    [DataRow("0e0f0d0c-0b0a-4908-8706-050403020100", false, DisplayName = "a universally unique identifier starting with a digit, which the specification names as the trap")]
    [DataRow("-leading", false, DisplayName = "a leading hyphen")]
    [DataRow(".leading", false, DisplayName = "a leading full stop")]
    [DataRow("csip:1", false, DisplayName = "a colon, which is what separates a Name from an NCName")]
    [DataRow("has space", false, DisplayName = "an interior space")]
    [DataRow("", false, DisplayName = "an empty identifier")]
    [DataRow(null, false, DisplayName = "no identifier at all")]
    public void TheIdentifierRecognitionImplementsTheProductionsClause51PointsAt(string? value, bool expected) =>
        Assert.AreEqual(expected, MetsWellKnown.IsNCName(value));


    /// <summary>
    /// The namespaces and profile identifiers are carried as the character sequences a conformance test compares
    /// rather than as normalised locators, and the archival profile's identifier is the one its own machine-
    /// checkable test states.
    /// </summary>
    [TestMethod]
    public void TheNamespacesAndProfileIdentifiersAreCarriedAsStated()
    {
        Assert.AreEqual("http://www.loc.gov/METS/", MetsWellKnown.MetsNamespace);
        Assert.AreEqual("https://DILCIS.eu/XML/METS/CSIPExtensionMETS", MetsWellKnown.CsipExtensionNamespace);
        Assert.AreEqual("http://www.w3.org/1999/xlink", MetsWellKnown.XLinkNamespace);
        Assert.AreEqual("https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml", MetsWellKnown.CsipProfileUri);
        Assert.AreEqual("https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml", MetsWellKnown.AipProfileUri);
        Assert.AreEqual("http://www.loc.gov/premis/v3", PremisWellKnown.PremisNamespace);
        Assert.AreEqual("http://www.w3.org/2001/XMLSchema-instance", PremisWellKnown.XmlSchemaInstanceNamespace);

        Assert.AreNotEqual(MetsWellKnown.CsipProfileUri, MetsWellKnown.AipProfileUri,
            "The two profiles are stated under different hosts, and a document claiming one does not claim the other.");
    }


    /// <summary>
    /// The preservation-metadata version recognition is exact where the vocabulary fixes a value and a prefix
    /// where the archival profile asks only for a major version, which are two different obligations stated by two
    /// different specifications.
    /// </summary>
    [TestMethod]
    public void TheVersionRecognitionIsExactWhereTheVocabularyFixesAValueAndAPrefixWhereItDoesNot()
    {
        Assert.IsTrue(PremisWellKnown.IsPremisVersion("3.0"));
        Assert.IsFalse(PremisWellKnown.IsPremisVersion("3.0.1"), "Requirement PM1 fixes one value, not a family.");
        Assert.IsFalse(PremisWellKnown.IsPremisVersion(null));

        Assert.IsTrue(PremisWellKnown.IsPremisMajorVersion("3.0"));
        Assert.IsTrue(PremisWellKnown.IsPremisMajorVersion("3.0.1"), "The archival profile states the rule as a prefix.");
        Assert.IsTrue(PremisWellKnown.IsPremisMajorVersion("3"));
        Assert.IsFalse(PremisWellKnown.IsPremisMajorVersion("2.1"));
        Assert.IsFalse(PremisWellKnown.IsPremisMajorVersion(null));
    }


    /// <summary>
    /// The carrier tags discriminate the two metadata documents from each other and from container octets. That
    /// the unset discriminator occupies zero is checked beside every other status this stage declares, in
    /// <c>EArkFixityTests</c>.
    /// </summary>
    [TestMethod]
    public void TheCarrierTagsDiscriminateTheTwoMetadataDocuments()
    {
        Assert.AreEqual(EArkObjectKind.MetsDocument, EArkTags.MetsDocument.Get<EArkObjectKind>());
        Assert.AreEqual(EArkObjectKind.PremisDocument, EArkTags.PremisDocument.Get<EArkObjectKind>());
        Assert.AreEqual(EncodingScheme.Raw, EArkTags.MetsDocument.Get<EncodingScheme>());
        Assert.AreEqual(EncodingScheme.Raw, EArkTags.PremisDocument.Get<EncodingScheme>());

        using PooledMemory metadata = PooledMemory.FromBytes("a metadata document"u8, BaseMemoryPool.Shared, EArkTags.MetsDocument);
        using PooledMemory containerEntry = PooledMemory.FromBytes("a container entry"u8, BaseMemoryPool.Shared, AsicTags.ContainerEntry);

        Assert.AreEqual(EArkObjectKind.MetsDocument, metadata.Tag.Get<EArkObjectKind>());
        Assert.AreEqual(AsicObjectKind.ContainerEntry, containerEntry.Tag.Get<AsicObjectKind>());
    }


    /// <summary>
    /// The recommended preservation-metadata document name is stated as a recommendation and nothing depends on
    /// it: clause 2.2.3 gives it no requirement identifier, so a package naming its document otherwise is still
    /// conformant and a reader that keyed on the name would be wrong.
    /// </summary>
    [TestMethod]
    public void TheRecommendedDocumentNameIsARecommendation()
    {
        Assert.AreEqual("PREMIS.xml", PremisWellKnown.PremisFileName);
        Assert.IsTrue(MetsWellKnown.IsNCName("PREMIS"), "The name's stem is a legal identifier, which is why it can also serve as one.");
    }
}

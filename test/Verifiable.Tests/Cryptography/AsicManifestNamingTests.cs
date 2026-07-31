using System.Collections.Generic;
using System.Globalization;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="AsicManifestNaming"/>: the file-name patterns clauses 4.4.3.2, 4.4.4.2 and
/// Annex A.7 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> dispatch on, and the collision-avoiding names this library creates for them.
/// </summary>
[TestClass]
internal sealed class AsicManifestNamingTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Each of the three roles is recognised from the name the specification prints for it, and a name that
    /// carries none of the three tokens is not a manifest at all.
    /// </summary>
    /// <param name="entryName">The container entry name to classify.</param>
    /// <param name="expected">The role the name carries.</param>
    [TestMethod]
    [DataRow("META-INF/ASiCManifest.xml", AsicManifestRole.Signature, DisplayName = "the unsuffixed ASiCManifest of clause 4.4.4.2 item 2")]
    [DataRow("META-INF/ASiCManifest1.xml", AsicManifestRole.Signature, DisplayName = "a suffixed ASiCManifest")]
    [DataRow("META-INF/ASiCArchiveManifest.xml", AsicManifestRole.Archive, DisplayName = "the fixed name Annex A.7 item 1 c a) states")]
    [DataRow("META-INF/ASiCArchiveManifest1.xml", AsicManifestRole.Archive, DisplayName = "a renamed archive manifest per Annex A.7 item 2 a)")]
    [DataRow("META-INF/oldASiCArchiveManifest.xml", AsicManifestRole.Archive, DisplayName = "the leading wildcard Annex A.7 item 2 a) writes")]
    [DataRow("META-INF/ASiCEvidenceRecordManifest.xml", AsicManifestRole.EvidenceRecord, DisplayName = "the unsuffixed Evidence Record manifest of clause 4.4.3.2 item 4")]
    [DataRow("META-INF/ASiCEvidenceRecordManifest2.xml", AsicManifestRole.EvidenceRecord, DisplayName = "a suffixed Evidence Record manifest")]
    [DataRow("META-INF/signature.p7s", AsicManifestRole.NotAManifest, DisplayName = "a CAdES object is not a manifest")]
    [DataRow("META-INF/manifest.xml", AsicManifestRole.NotAManifest, DisplayName = "a name carrying none of the three tokens")]
    [DataRow("mimetype", AsicManifestRole.NotAManifest, DisplayName = "the media type entry")]
    [DataRow((string?)null, AsicManifestRole.NotAManifest, DisplayName = "no name at all")]
    public void EachRoleIsRecognisedFromTheNameTheSpecificationPrintsForIt(string? entryName, AsicManifestRole expected)
    {
        Assert.AreEqual(expected, AsicManifestNaming.RoleFromEntryName(entryName));
    }


    /// <summary>
    /// The three tokens are disjoint on every name the specification prints, which is what lets one file name
    /// carry exactly one role: an archive manifest does not read as an <c>ASiCManifest</c>, and neither does an
    /// Evidence Record manifest.
    /// </summary>
    [TestMethod]
    public void TheThreeTokensAreDisjointOnTheNamesTheSpecificationPrints()
    {
        Assert.IsFalse(AsicManifestNaming.IsSignatureManifestEntryName("META-INF/ASiCArchiveManifest.xml"));
        Assert.IsFalse(AsicManifestNaming.IsSignatureManifestEntryName("META-INF/ASiCEvidenceRecordManifest.xml"));
        Assert.IsFalse(AsicManifestNaming.IsArchiveManifestEntryName("META-INF/ASiCManifest1.xml"));
        Assert.IsFalse(AsicManifestNaming.IsArchiveManifestEntryName("META-INF/ASiCEvidenceRecordManifest.xml"));
        Assert.IsFalse(AsicManifestNaming.IsEvidenceRecordManifestEntryName("META-INF/ASiCManifest1.xml"));
        Assert.IsFalse(AsicManifestNaming.IsEvidenceRecordManifestEntryName("META-INF/ASiCArchiveManifest.xml"));
    }


    /// <summary>
    /// A name that matches two of the three patterns at once is refused rather than resolved by precedence: the
    /// specification states three patterns and no ordering between them, so a producer able to steer a file into
    /// two roles is a producer a validator can disagree with.
    /// </summary>
    [TestMethod]
    public void ANameCarryingTwoTokensAtOnceIsAmbiguousRatherThanResolvedByPrecedence()
    {
        Assert.AreEqual(AsicManifestRole.Ambiguous, AsicManifestNaming.RoleFromEntryName("META-INF/ASiCManifestASiCArchiveManifest.xml"));
        Assert.AreEqual(AsicManifestRole.Ambiguous, AsicManifestNaming.RoleFromEntryName("META-INF/ASiCEvidenceRecordManifestASiCArchiveManifest.xml"));
        Assert.IsFalse(AsicManifestNaming.IsSignatureManifestEntryName("META-INF/ASiCManifestASiCArchiveManifest.xml"));
        Assert.IsFalse(AsicManifestNaming.IsArchiveManifestEntryName("META-INF/ASiCManifestASiCArchiveManifest.xml"));
    }


    /// <summary>
    /// Matching is case-sensitive, and that is what keeps an <c>ASiCEvidenceRecordManifest</c> file out of the
    /// clause 4.4.4.2 item 4 b Evidence Record dispatch: <c>META-INF/*evidencerecord*.xml</c> would match every
    /// one of them the moment case is ignored, and each would then be handed to an Evidence Record verifier
    /// instead of being read as the manifest that names one.
    /// </summary>
    [TestMethod]
    public void MatchingIsCaseSensitiveWhichKeepsAManifestOutOfTheEvidenceRecordDispatch()
    {
        Assert.IsFalse(AsicManifestNaming.IsXmlEvidenceRecordEntryName("META-INF/ASiCEvidenceRecordManifest1.xml"),
            "The manifest naming an Evidence Record is not itself an Evidence Record.");
        Assert.IsTrue(AsicManifestNaming.IsXmlEvidenceRecordEntryName("META-INF/evidencerecord1.xml"));
        Assert.AreEqual(AsicManifestRole.NotAManifest, AsicManifestNaming.RoleFromEntryName("META-INF/asicmanifest1.xml"),
            "A lower-cased spelling is a different entry name, not the same one.");
    }


    /// <summary>
    /// A manifest lives directly inside the <c>META-INF</c> folder: a name at the container root, or one naming
    /// a folder below <c>META-INF</c>, matches no pattern of clause 4.4.4.2, each of which is written as the
    /// folder prefix followed by a pattern carrying no separator.
    /// </summary>
    [TestMethod]
    public void AManifestLivesDirectlyInsideTheMetaInfFolder()
    {
        Assert.AreEqual(AsicManifestRole.NotAManifest, AsicManifestNaming.RoleFromEntryName("ASiCManifest1.xml"));
        Assert.AreEqual(AsicManifestRole.NotAManifest, AsicManifestNaming.RoleFromEntryName("META-INF/nested/ASiCManifest1.xml"));
        Assert.AreEqual(AsicManifestRole.NotAManifest, AsicManifestNaming.RoleFromEntryName("other/META-INF/ASiCManifest1.xml"));
        Assert.AreEqual(AsicManifestRole.NotAManifest, AsicManifestNaming.RoleFromEntryName("META-INF/"));
    }


    /// <summary>
    /// The three non-manifest file kinds are recognised from the wildcard patterns clause 4.4.4.2 items 3 and 4
    /// state, and each recognises only its own extension.
    /// </summary>
    /// <param name="entryName">The container entry name to classify.</param>
    /// <param name="isSignature">Whether the name is a CAdES object.</param>
    /// <param name="isTimestamp">Whether the name is a time-stamp token.</param>
    /// <param name="isBinaryEvidenceRecord">Whether the name is an RFC 4998 Evidence Record.</param>
    /// <param name="isXmlEvidenceRecord">Whether the name is an RFC 6283 Evidence Record.</param>
    [TestMethod]
    [DataRow("META-INF/signature.p7s", true, false, false, false, DisplayName = "the unsuffixed CAdES object of clause 4.3.3.2 item 4 b")]
    [DataRow("META-INF/mysignature1.p7s", true, false, false, false, DisplayName = "the wildcard on both sides of clause 4.4.4.2 item 3 a")]
    [DataRow("META-INF/timestamp.tst", false, true, false, false, DisplayName = "the unsuffixed time-stamp token")]
    [DataRow("META-INF/atimestampb.tst", false, true, false, false, DisplayName = "the wildcard on both sides of clause 4.4.4.2 item 3 b")]
    [DataRow("META-INF/evidencerecord.ers", false, false, true, false, DisplayName = "an RFC 4998 Evidence Record")]
    [DataRow("META-INF/evidencerecord1.xml", false, false, false, true, DisplayName = "an RFC 6283 Evidence Record")]
    [DataRow("META-INF/signature.tst", false, false, false, false, DisplayName = "the token of one kind with the extension of another")]
    [DataRow("META-INF/other.p7s", false, false, false, false, DisplayName = "the right extension without the token")]
    [DataRow("signature.p7s", false, false, false, false, DisplayName = "outside the META-INF folder")]
    public void EachNonManifestFileKindIsRecognisedFromItsOwnPattern(
        string entryName,
        bool isSignature,
        bool isTimestamp,
        bool isBinaryEvidenceRecord,
        bool isXmlEvidenceRecord)
    {
        Assert.AreEqual(isSignature, AsicManifestNaming.IsSignatureEntryName(entryName));
        Assert.AreEqual(isTimestamp, AsicManifestNaming.IsTimestampEntryName(entryName));
        Assert.AreEqual(isBinaryEvidenceRecord, AsicManifestNaming.IsBinaryEvidenceRecordEntryName(entryName));
        Assert.AreEqual(isXmlEvidenceRecord, AsicManifestNaming.IsXmlEvidenceRecordEntryName(entryName));
    }


    /// <summary>
    /// A created name carries the numeric suffix this library adopted, sits inside <c>META-INF</c>, and reads
    /// back as the kind it was created for.
    /// </summary>
    /// <param name="fileKind">The kind of file the name is created for.</param>
    /// <param name="expected">The name the empty container produces.</param>
    [TestMethod]
    [DataRow(AsicContainerFileKind.SignatureManifest, "META-INF/ASiCManifest1.xml", DisplayName = "an ASiCManifest")]
    [DataRow(AsicContainerFileKind.ArchiveManifest, "META-INF/ASiCArchiveManifest1.xml", DisplayName = "a renamed archive manifest")]
    [DataRow(AsicContainerFileKind.EvidenceRecordManifest, "META-INF/ASiCEvidenceRecordManifest1.xml", DisplayName = "an Evidence Record manifest")]
    [DataRow(AsicContainerFileKind.Signature, "META-INF/signature1.p7s", DisplayName = "a CAdES object")]
    [DataRow(AsicContainerFileKind.Timestamp, "META-INF/timestamp1.tst", DisplayName = "a time-stamp token")]
    [DataRow(AsicContainerFileKind.BinaryEvidenceRecord, "META-INF/evidencerecord1.ers", DisplayName = "an RFC 4998 Evidence Record")]
    [DataRow(AsicContainerFileKind.XmlEvidenceRecord, "META-INF/evidencerecord1.xml", DisplayName = "an RFC 6283 Evidence Record")]
    public void ACreatedNameCarriesTheNumericSuffixThisLibraryAdopted(AsicContainerFileKind fileKind, string expected)
    {
        Assert.AreEqual(expected, AsicManifestNaming.CreateEntryName(fileKind, []));
    }


    /// <summary>
    /// Creation avoids every name already present, which is what "avoiding any name collision with other
    /// elements already present in the container" of Annex A.7 item 1 c c) requires — including a gap in the
    /// middle of the sequence, which the lowest-free rule fills rather than skipping past.
    /// </summary>
    [TestMethod]
    public void CreationAvoidsEveryNameAlreadyPresentAndFillsGaps()
    {
        string[] existing =
        [
            "mimetype",
            "META-INF/ASiCManifest1.xml",
            "META-INF/ASiCManifest3.xml"
        ];

        Assert.AreEqual("META-INF/ASiCManifest2.xml", AsicManifestNaming.CreateEntryName(AsicContainerFileKind.SignatureManifest, existing));

        var grown = new List<string>(existing) { "META-INF/ASiCManifest2.xml" };
        Assert.AreEqual("META-INF/ASiCManifest4.xml", AsicManifestNaming.CreateEntryName(AsicContainerFileKind.SignatureManifest, grown));
    }


    /// <summary>
    /// A created name never collides with the one name the specification fixes: Annex A.7 item 1 c a) states
    /// <c>ASiCArchiveManifest.xml</c> for the newest archive manifest, and the numeric suffix starts at one so
    /// that the unsuffixed form is never produced.
    /// </summary>
    [TestMethod]
    public void ACreatedNameNeverCollidesWithTheNameAnnexA7Fixes()
    {
        string created = AsicManifestNaming.CreateEntryName(AsicContainerFileKind.ArchiveManifest, []);

        Assert.AreNotEqual(AsicManifestNaming.FixedArchiveManifestEntryName, created);
        Assert.AreEqual("META-INF/ASiCArchiveManifest.xml", AsicManifestNaming.FixedArchiveManifestEntryName);
        Assert.AreEqual(AsicManifestRole.Archive, AsicManifestNaming.RoleFromEntryName(created));
        Assert.AreEqual(AsicManifestRole.Archive, AsicManifestNaming.RoleFromEntryName(AsicManifestNaming.FixedArchiveManifestEntryName));
    }


    /// <summary>
    /// The fixed archive manifest name is refused while the previous one still occupies it, because Annex A.7
    /// item 2 a) makes renaming that file the first step of every subsequent addition and overwriting it would
    /// break the time-stamp token already committed to its octets.
    /// </summary>
    [TestMethod]
    public void TheFixedArchiveManifestNameIsRefusedWhileThePreviousOneStillOccupiesIt()
    {
        Assert.AreEqual(
            AsicManifestNaming.FixedArchiveManifestEntryName,
            AsicManifestNaming.CreateFixedArchiveManifestEntryName(["META-INF/ASiCArchiveManifest1.xml"]));

        var exception = Assert.ThrowsExactly<AsicManifestNamingException>(
            () => AsicManifestNaming.CreateFixedArchiveManifestEntryName([AsicManifestNaming.FixedArchiveManifestEntryName]));

        Assert.AreEqual(AsicManifestNamingFailureKind.FixedNameAlreadyPresent, exception.FailureKind);
    }


    /// <summary>
    /// A file kind that names nothing is refused with its own failure kind rather than producing a name whose
    /// pattern no clause states.
    /// </summary>
    [TestMethod]
    public void AFileKindThatNamesNothingIsRefused()
    {
        var exception = Assert.ThrowsExactly<AsicManifestNamingException>(
            () => AsicManifestNaming.CreateEntryName(AsicContainerFileKind.NotEvaluated, []));

        Assert.AreEqual(AsicManifestNamingFailureKind.UnsupportedFileKind, exception.FailureKind);
    }


    /// <summary>
    /// The suffix space is bounded rather than searched forever: a container that has taken every suffix gets a
    /// refusal naming what was exhausted.
    /// </summary>
    [TestMethod]
    public void TheSuffixSpaceIsBoundedRatherThanSearchedForever()
    {
        var taken = new List<string>(AsicManifestNaming.MaximumNameSuffix);
        for(int suffix = 1; suffix <= AsicManifestNaming.MaximumNameSuffix; ++suffix)
        {
            taken.Add(string.Create(CultureInfo.InvariantCulture, $"META-INF/timestamp{suffix}.tst"));
        }

        var exception = Assert.ThrowsExactly<AsicManifestNamingException>(
            () => AsicManifestNaming.CreateEntryName(AsicContainerFileKind.Timestamp, taken));

        Assert.AreEqual(AsicManifestNamingFailureKind.SuffixSpaceExhausted, exception.FailureKind);
    }
}

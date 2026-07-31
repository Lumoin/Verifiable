using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the evidence self-description convention: the one content model of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> requirement <c>OVR-6.5-09</c>, the one identity it is named by, and its passage
/// through each of the three extension points the three shipped formats already have — the <c>attributes [1]</c>
/// field of an <c>ArchiveTimeStamp</c> (<see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.1">IETF RFC
/// 4998 clause 4.1</see>), the <c>unsignedAttrs</c> field of a <c>SignerInfo</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">IETF RFC 5652 clause 5.3</see>), and an
/// <c>Extension</c> of a container manifest
/// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2).
/// </summary>
/// <remarks>
/// <para>
/// What the carrier tests establish is that <em>one</em> value travels three ways: the octets a signer's unsigned
/// attribute carries, the octets an archive time-stamp's attribute carries and the octets a manifest extension
/// carries in base 64 are asserted to be the same octets, because R-6's whole point is one design rather than
/// three. The attribute encodings are read back with an independent reader written here rather than with the
/// surface that produced them.
/// </para>
/// <para>
/// Every artifact is minted by the shipped surfaces against a Time-Stamping Authority that signs real tokens, and
/// requirement <c>OVR-9.2-05</c>'s "cryptographically protected" is asserted in both states for both attribute
/// carriers — before the structure that covers it exists, and after.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkEvidenceSelfDescriptionTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The data object the Evidence Records of this class prove.</summary>
    private static string ArchivedContent { get; } = "the archived provenance document";

    /// <summary>The content the Signed Data Objects of this class cover.</summary>
    private static string SignedContent { get; } = "the signed provenance document";

    /// <summary>The arc a universally unique identifier is mapped into the object-identifier tree under.</summary>
    private static string UuidArc { get; } = "2.25";


    /// <summary>
    /// The convention has one identity spelled twice, and the object-identifier spelling is really the universally
    /// unique identifier read as a single integer under the arc
    /// <see href="https://www.itu.int/rec/T-REC-X.667">ITU-T Recommendation X.667</see> reserves for them —
    /// recomputed here from the identifier's own text rather than restated from the allocation.
    /// </summary>
    [TestMethod]
    public void TheConventionHasOneIdentitySpelledTwice()
    {
        var parsed = Guid.ParseExact(EArkEvidenceWellKnown.ConventionUuid, "D");
        Span<byte> bigEndian = stackalloc byte[16];
        Assert.IsTrue(parsed.TryWriteBytes(bigEndian, bigEndian: true, out int written));
        Assert.AreEqual(16, written);

        var asInteger = new BigInteger(bigEndian, isUnsigned: true, isBigEndian: true);
        string recomputed = string.Create(CultureInfo.InvariantCulture, $"{UuidArc}.{asInteger}");

        Assert.AreEqual(recomputed, EArkEvidenceWellKnown.SelfDescriptionAttributeType,
            "The object identifier is the universally unique identifier read as one integer under the arc X.667 reserves.");

        Assert.AreEqual("urn:uuid:" + EArkEvidenceWellKnown.ConventionUuid, EArkEvidenceWellKnown.ConventionIdentifier,
            "The uniform resource name spelling is the same identifier under the name space RFC 4122 clause 3 states.");

        Assert.AreEqual(EArkEvidenceWellKnown.ConventionIdentifier, EArkEvidenceWellKnown.SelfDescriptionElementNamespace,
            "One identity, so the XML name space of the container carrier is that same value and not a second one.");

        Assert.AreEqual(
            new AsicManifestExtensionName(EArkEvidenceWellKnown.SelfDescriptionElementNamespace, EArkEvidenceWellKnown.SelfDescriptionElementName),
            EArkEvidenceWellKnown.SelfDescriptionExtensionName);
    }


    /// <summary>
    /// The canonical encoding round-trips whichever of the three items of <c>OVR-6.5-09</c> a producer states,
    /// and an absent item comes back absent rather than as an empty value.
    /// </summary>
    /// <param name="service">The preservation service identifier, or <see langword="null"/>.</param>
    /// <param name="policy">The evidence policy identifier, or <see langword="null"/>.</param>
    /// <param name="profile">The preservation profile identifier, or <see langword="null"/>.</param>
    [TestMethod]
    [DataRow("urn:example:service", "urn:example:policy", "urn:example:profile", DisplayName = "all three items")]
    [DataRow("urn:example:service", null, null, DisplayName = "item a) alone")]
    [DataRow(null, "urn:example:policy", null, DisplayName = "item b) alone")]
    [DataRow(null, null, "urn:example:profile", DisplayName = "item c) alone")]
    [DataRow("urn:example:service", null, "urn:example:profile", DisplayName = "items a) and c), the middle one absent")]
    public void TheCanonicalEncodingRoundTripsWhicheverItemsAProducerStates(string? service, string? policy, string? profile)
    {
        var stated = new EArkEvidenceSelfDescription
        {
            PreservationServiceIdentifier = service,
            EvidencePolicyIdentifier = policy,
            PreservationProfileIdentifier = profile,
        };

        using PooledMemory encoded = stated.EncodeValue(BaseMemoryPool.Shared);
        Assert.IsTrue(EArkEvidenceSelfDescription.TryDecodeValue(encoded.AsReadOnlyMemory(), out EArkEvidenceSelfDescription? read));

        Assert.AreEqual(service, read.PreservationServiceIdentifier);
        Assert.AreEqual(policy, read.EvidencePolicyIdentifier);
        Assert.AreEqual(profile, read.PreservationProfileIdentifier);
        Assert.AreEqual(stated, read, "The value is a record, so a round trip that lost nothing compares equal.");

        using PooledMemory reEncoded = read.EncodeValue(BaseMemoryPool.Shared);
        Assert.AreSequenceEqual(encoded.AsReadOnlySpan().ToArray(), reEncoded.AsReadOnlySpan().ToArray(),
            "The encoding is canonical, so writing what was read produces the octets that were read.");
    }


    /// <summary>
    /// A self-description stating nothing is a generator fault and refuses to be written, and octets that decode
    /// to one are refused on the way back in — the requirement asks an evidence to say something.
    /// </summary>
    [TestMethod]
    public void ASelfDescriptionStatingNothingIsNeitherWrittenNorRead()
    {
        var nothing = new EArkEvidenceSelfDescription();
        Assert.IsFalse(nothing.IsStated);

        _ = Assert.Throws<InvalidOperationException>(() => nothing.EncodeValue(BaseMemoryPool.Shared));
        _ = Assert.Throws<InvalidOperationException>(() => nothing.ToAttribute(BaseMemoryPool.Shared));
        _ = Assert.Throws<InvalidOperationException>(() => nothing.ToExtensionText(BaseMemoryPool.Shared));

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PopSequence();
        Assert.IsFalse(EArkEvidenceSelfDescription.TryDecodeValue(writer.Encode(), out EArkEvidenceSelfDescription? read));
        Assert.IsNull(read);
    }


    /// <summary>
    /// An identifier longer than this library reads back is refused where it is written, so a package this
    /// library produces is always one it can read; the same value arriving from elsewhere is refused on the way
    /// in rather than truncated.
    /// </summary>
    [TestMethod]
    public void AnIdentifierOverTheBoundIsRefusedBothWays()
    {
        string overTheBound = new('a', EArkEvidenceSelfDescription.MaximumIdentifierByteLength + 1);
        var stated = new EArkEvidenceSelfDescription { EvidencePolicyIdentifier = overTheBound };

        _ = Assert.Throws<InvalidOperationException>(() => stated.EncodeValue(BaseMemoryPool.Shared));

        //The same value written without this library's bound, which is what an arbitrary producer may send.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, overTheBound, new Asn1Tag(TagClass.ContextSpecific, 1));
        }

        Assert.IsFalse(EArkEvidenceSelfDescription.TryDecodeValue(writer.Encode(), out EArkEvidenceSelfDescription? read));
        Assert.IsNull(read, "Nothing partially populated is produced, so a caller acting on true acts on a whole value.");

        string atTheBound = new('a', EArkEvidenceSelfDescription.MaximumIdentifierByteLength);
        var atBound = new EArkEvidenceSelfDescription { EvidencePolicyIdentifier = atTheBound };
        using PooledMemory encoded = atBound.EncodeValue(BaseMemoryPool.Shared);
        Assert.IsTrue(EArkEvidenceSelfDescription.TryDecodeValue(encoded.AsReadOnlyMemory(), out EArkEvidenceSelfDescription? atBoundRead));
        Assert.AreEqual(atTheBound, atBoundRead.EvidencePolicyIdentifier, "The bound is inclusive.");
    }


    /// <summary>
    /// Octets a producer wrote that are not exactly one self-description answer <see langword="false"/> rather
    /// than throwing or producing something half read.
    /// </summary>
    /// <param name="shape">Which malformed shape to build.</param>
    [TestMethod]
    [DataRow("empty", DisplayName = "no octets at all")]
    [DataRow("not-asn1", DisplayName = "octets that are not a DER value")]
    [DataRow("trailing", DisplayName = "a whole self-description followed by more octets")]
    [DataRow("out-of-order", DisplayName = "the three fields in the wrong order")]
    [DataRow("repeated", DisplayName = "one field stated twice")]
    [DataRow("not-a-sequence", DisplayName = "a value that is not the outer SEQUENCE")]
    [DataRow("unknown-field", DisplayName = "a fourth context tag the model does not state")]
    [DataRow("over-the-value-bound", DisplayName = "a value longer than the whole self-description is read with")]
    public void OctetsThatAreNotOneSelfDescriptionAreRefused(string shape)
    {
        byte[] octets = MalformedValue(shape);

        Assert.IsFalse(EArkEvidenceSelfDescription.TryDecodeValue(octets, out EArkEvidenceSelfDescription? read));
        Assert.IsNull(read);
    }


    /// <summary>
    /// The three carriers hold the same octets: the attribute-shaped ones carry the canonical encoding verbatim
    /// as the single <c>AttributeValue</c>, and the container one carries those same octets in base 64. One
    /// design, three carriers — which is what R-6 asks for by name.
    /// </summary>
    [TestMethod]
    public void TheThreeCarriersHoldTheSameOctets()
    {
        EArkEvidenceSelfDescription stated = EArkEvidenceSource.SelfDescription;

        using PooledMemory canonical = stated.EncodeValue(BaseMemoryPool.Shared);
        using CmsAttribute attribute = stated.ToAttribute(BaseMemoryPool.Shared);
        string extensionText = stated.ToExtensionText(BaseMemoryPool.Shared);

        (string attributeType, byte[] attributeValue) = ReadAttribute(attribute.AsReadOnlySpan());
        Assert.AreEqual(EArkEvidenceWellKnown.SelfDescriptionAttributeType, attributeType);
        Assert.AreSequenceEqual(canonical.AsReadOnlySpan().ToArray(), attributeValue,
            "The attribute carries the canonical encoding verbatim as its single value.");

        Assert.AreSequenceEqual(canonical.AsReadOnlySpan().ToArray(), Convert.FromBase64String(extensionText),
            "The container carrier differs only in that the same octets travel through a text node.");

        Assert.IsTrue(EArkEvidenceSelfDescription.TryReadExtensionText(extensionText, BaseMemoryPool.Shared, out EArkEvidenceSelfDescription? fromText));
        Assert.AreEqual(stated, fromText);

        Assert.IsTrue(EArkEvidenceSelfDescription.TryReadFromAttributes([attribute.AsReadOnlyMemory()], out EArkEvidenceSelfDescription? fromAttributes));
        Assert.AreEqual(stated, fromAttributes);
    }


    /// <summary>
    /// An Evidence Record carries the self-description in the <c>attributes</c> field of its archive time-stamp,
    /// and carrying it costs the evidence nothing: the record still proves the data object it was created over.
    /// </summary>
    /// <returns>A task that completes when the record has been read back and verified.</returns>
    [TestMethod]
    public async Task AnEvidenceRecordCarriesTheSelfDescriptionInItsArchiveTimeStampAttributes()
    {
        byte[] archived = Encoding.UTF8.GetBytes(ArchivedContent);
        using EvidenceRecord described = await EArkEvidenceSource.MintEvidenceRecordAsync(
            [archived], EArkEvidenceSource.SelfDescription, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(EArkEvidenceSelfDescription.TryReadFromEvidenceRecord(described, out EArkEvidenceSelfDescription? read));
        Assert.AreEqual(EArkEvidenceSource.SelfDescription, read);

        EArkEvidenceArtifactFacts facts = EArkEvidencePlacement.StateEvidenceRecordFacts(
            described, EArkEvidenceSource.EntryNameFor(EArkEvidenceKind.EvidenceRecord), [ArchivedContent]);

        Assert.AreEqual(EArkEvidenceKind.EvidenceRecord, facts.Kind);
        Assert.AreEqual(EArkEvidenceSelfDescriptionCarrier.ArchiveTimeStampAttributes, facts.SelfDescriptionCarrier);
        Assert.IsTrue(facts.HasSelfDescription);
        Assert.IsFalse(facts.SelfDescriptionIsProtected,
            "Clause 3.1's cryptoInfos is protected by nothing and one chain of archive time-stamps proves nothing about its own attributes: only a later chain does.");

        using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = described, DataObject = archived },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status,
            "The attributes field sits outside the reduced hash tree and outside the time-stamp's imprint, so writing into it leaves the proof intact.");
    }


    /// <summary>
    /// A Hash-Tree Renewal is what makes an Evidence Record's self-description cryptographically protected, which
    /// is what <c>OVR-9.2-05</c> asks of an embedded policy reference: clause 5.2 hashes the whole encoded
    /// <c>ArchiveTimeStampSequence</c>, so an attribute in a chain a later chain follows is inside what that
    /// later chain proves.
    /// </summary>
    /// <returns>A task that completes when the renewed record has been read back and verified.</returns>
    [TestMethod]
    public async Task AHashTreeRenewalIsWhatProtectsAnEvidenceRecordsSelfDescription()
    {
        byte[] archived = Encoding.UTF8.GetBytes(ArchivedContent);
        using EvidenceRecord described = await EArkEvidenceSource.MintEvidenceRecordAsync(
            [archived], EArkEvidenceSource.SelfDescription, TestContext.CancellationToken).ConfigureAwait(false);

        using EvidenceRecord renewed = await EArkEvidenceSource.RenewHashTreeAsync(
            described, [archived], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, renewed.ArchiveTimeStampSequence.Chains);
        Assert.AreSequenceEqual(
            described.ArchiveTimeStampSequence.Chains[0].Encoding.ToArray(),
            renewed.ArchiveTimeStampSequence.Chains[0].Encoding.ToArray(),
            "The renewal carries the earlier chain forward octet for octet, which is what makes it prove that chain's attributes.");

        EArkEvidenceArtifactFacts facts = EArkEvidencePlacement.StateEvidenceRecordFacts(
            renewed, EArkEvidenceSource.EntryNameFor(EArkEvidenceKind.EvidenceRecord), [ArchivedContent]);

        Assert.IsTrue(facts.HasSelfDescription);
        Assert.IsTrue(facts.SelfDescriptionIsProtected, "A later chain exists, which is exactly the answer the requirement asks for.");
        Assert.AreEqual(EArkEvidenceSelfDescriptionCarrier.ArchiveTimeStampAttributes, facts.SelfDescriptionCarrier);

        using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = renewed, DataObject = archived },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
    }


    /// <summary>
    /// A Signed Data Object carries the self-description as an unsigned attribute of its signer, and an archive
    /// time-stamp attached afterwards is what protects it — an unsigned attribute is outside the signature by
    /// definition, so the answer the convention computes is "an archive time-stamp attribute follows this one".
    /// </summary>
    /// <returns>A task that completes when both states have been read back.</returns>
    [TestMethod]
    public async Task ASignedDataObjectCarriesTheSelfDescriptionAsAnUnsignedAttributeAnArchiveTimeStampProtects()
    {
        byte[] content = Encoding.UTF8.GetBytes(SignedContent);
        string entryName = EArkEvidenceSource.EntryNameFor(EArkEvidenceKind.SignedDataObject);

        using(CmsSignedData unprotected = await EArkEvidenceSource.MintSignedDataObjectAsync(
            content, EArkEvidenceSource.SelfDescription, withArchiveTimestamp: false, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsTrue(EArkEvidenceSelfDescription.TryReadFromSignedData(unprotected, 0, out EArkEvidenceSelfDescription? read));
            Assert.AreEqual(EArkEvidenceSource.SelfDescription, read);

            EArkEvidenceArtifactFacts facts = EArkEvidencePlacement.StateSignedDataObjectFacts(unprotected, 0, entryName, [SignedContent]);
            Assert.AreEqual(EArkEvidenceKind.SignedDataObject, facts.Kind);
            Assert.AreEqual(EArkEvidenceSelfDescriptionCarrier.UnsignedAttribute, facts.SelfDescriptionCarrier);
            Assert.IsFalse(facts.SelfDescriptionIsProtected, "Nothing has been added after it, so nothing covers it.");
        }

        using CmsSignedData covered = await EArkEvidenceSource.MintSignedDataObjectAsync(
            content, EArkEvidenceSource.SelfDescription, withArchiveTimestamp: true, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(EArkEvidenceSelfDescription.TryReadFromSignedData(covered, 0, out EArkEvidenceSelfDescription? readAgain));
        Assert.AreEqual(EArkEvidenceSource.SelfDescription, readAgain);

        EArkEvidenceArtifactFacts coveredFacts = EArkEvidencePlacement.StateSignedDataObjectFacts(covered, 0, entryName, [SignedContent]);
        Assert.IsTrue(coveredFacts.SelfDescriptionIsProtected,
            "Clause 5.5.2's hash index holds one entry per unsigned attribute value present when the archive time-stamp ran, so an attribute before it is covered.");
    }


    /// <summary>
    /// A Signed Data Object carrying no self-description states none rather than something empty, which is what
    /// makes the absence readable as an absence.
    /// </summary>
    /// <returns>A task that completes when the signature has been read.</returns>
    [TestMethod]
    public async Task ASignedDataObjectCarryingNoSelfDescriptionStatesNone()
    {
        byte[] content = Encoding.UTF8.GetBytes(SignedContent);
        using CmsSignedData plain = await EArkEvidenceSource.MintSignedDataObjectAsync(
            content, selfDescription: null, withArchiveTimestamp: false, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(EArkEvidenceSelfDescription.TryReadFromSignedData(plain, 0, out EArkEvidenceSelfDescription? read));
        Assert.IsNull(read);

        EArkEvidenceArtifactFacts facts = EArkEvidencePlacement.StateSignedDataObjectFacts(
            plain, 0, EArkEvidenceSource.EntryNameFor(EArkEvidenceKind.SignedDataObject), [SignedContent]);

        Assert.IsFalse(facts.HasSelfDescription);
        Assert.AreEqual(EArkEvidenceSelfDescriptionCarrier.NotEvaluated, facts.SelfDescriptionCarrier);
        Assert.IsFalse(facts.SelfDescriptionIsProtected, "Nothing was carried, so nothing is protected.");
    }


    /// <summary>
    /// A container manifest carries the self-description as an <c>Extension</c>, and it survives the whole way
    /// through the serialisation seam: written into a manifest, encoded to a document, parsed back and read.
    /// </summary>
    /// <returns>A task that completes when the manifest has been round-tripped.</returns>
    [TestMethod]
    public async Task AContainerManifestCarriesTheSelfDescriptionThroughItsExtensionPoint()
    {
        string extensionText = EArkEvidenceSource.SelfDescription.ToExtensionText(BaseMemoryPool.Shared);

        using AsicManifest manifest = await BuildManifestAsync(extensionText).ConfigureAwait(false);
        using AsicManifestEncodeResult encoded = await Verifiable.Cryptography.Pki.Xml.AsicManifestXmlBinding.EncodeAsync(
            new AsicManifestEncodeContext { Manifest = manifest }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicManifestEncodeStatus.Encoded, encoded.Status, encoded.FailureReason);

        using AsicManifestParseResult parsed = await Verifiable.Cryptography.Pki.Xml.AsicManifestXmlBinding.ParseAsync(
            new AsicManifestParseContext { Document = encoded.Document! }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);
        Assert.HasCount(1, parsed.Manifest!.Extensions);

        AsicManifestExtension carried = parsed.Manifest!.Extensions[0];
        Assert.AreEqual(EArkEvidenceWellKnown.SelfDescriptionExtensionName, carried.Name);

        string? recovered = EArkEvidenceSource.ReadSelfDescriptionText(carried);
        Assert.AreEqual(extensionText, recovered, "The text survives the seam, which is what makes the octets survive it.");

        EArkEvidenceArtifactFacts facts = EArkEvidencePlacement.StateContainerFacts(
            recovered,
            EArkEvidenceSource.EntryNameFor(EArkEvidenceKind.Container),
            [ArchivedContent],
            BaseMemoryPool.Shared,
            isManifestProtected: true);

        Assert.AreEqual(EArkEvidenceKind.Container, facts.Kind);
        Assert.AreEqual(EArkEvidenceSelfDescriptionCarrier.ManifestExtension, facts.SelfDescriptionCarrier);
        Assert.AreEqual(EArkEvidenceSource.SelfDescription, facts.SelfDescription);
        Assert.IsTrue(facts.SelfDescriptionIsProtected,
            "Only the container's own reader knows which signature references the manifest, so this one is the caller's statement.");
    }


    /// <summary>
    /// The container extension is written non-critical, so a consumer that never heard of this convention still
    /// validates a container carrying it — which is the whole reason the criticality default is what it is.
    /// </summary>
    [TestMethod]
    public void TheContainerExtensionIsWrittenNonCriticalSoAStrangerStillValidates()
    {
        string extensionText = EArkEvidenceSource.SelfDescription.ToExtensionText(BaseMemoryPool.Shared);
        using AsicManifestExtension extension = EArkEvidenceSource.BuildSelfDescriptionExtension(extensionText);

        Assert.IsFalse(EArkEvidenceWellKnown.SelfDescriptionExtensionIsCritical);
        Assert.IsFalse(extension.Critical);
        Assert.IsTrue(AsicManifestExtensionPolicy.Strict.Evaluate([extension]).IsAccepted,
            "A consumer that recognises nothing of this convention accepts the container it is carried in.");

        var recognising = new AsicManifestExtensionPolicy
        {
            RecognizedExtensions = [EArkEvidenceWellKnown.SelfDescriptionExtensionName]
        };
        Assert.IsTrue(recognising.Evaluate([extension]).IsAccepted, "And so does one that does recognise it.");
    }


    /// <summary>
    /// A carrier holding an attribute of this convention's type whose value is not one this library reads answers
    /// <see langword="false"/> rather than reading part of it, and an attribute of some other type is passed over
    /// rather than misread.
    /// </summary>
    [TestMethod]
    public void AnAttributeOfTheConventionsTypeCarryingSomethingElseIsRefused()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString("not a self-description"u8);
        using CmsAttribute wrongValue = CmsAttribute.Create(
            EArkEvidenceWellKnown.SelfDescriptionAttributeType, writer.Encode(), BaseMemoryPool.Shared);

        Assert.IsFalse(EArkEvidenceSelfDescription.TryReadFromAttributes([wrongValue.AsReadOnlyMemory()], out EArkEvidenceSelfDescription? refused));
        Assert.IsNull(refused);

        var other = new AsnWriter(AsnEncodingRules.DER);
        other.WriteOctetString("a value of some other attribute"u8);
        using CmsAttribute otherType = CmsAttribute.Create(
            CAdESSignatureFacts.SignatureTimestampAttributeOid, other.Encode(), BaseMemoryPool.Shared);

        using CmsAttribute ours = EArkEvidenceSource.SelfDescription.ToAttribute(BaseMemoryPool.Shared);
        Assert.IsTrue(
            EArkEvidenceSelfDescription.TryReadFromAttributes(
                [otherType.AsReadOnlyMemory(), ours.AsReadOnlyMemory()], out EArkEvidenceSelfDescription? found),
            "An attribute of another type is passed over, not misread and not treated as an absence.");

        Assert.AreEqual(EArkEvidenceSource.SelfDescription, found);
    }


    /// <summary>
    /// Text that is not base 64, or is base 64 of something that is not a self-description, is refused — the
    /// container carrier's reader is as unforgiving as the attribute one.
    /// </summary>
    /// <param name="text">The text to read.</param>
    [TestMethod]
    [DataRow("", DisplayName = "no text")]
    [DataRow("not base 64 at all!!", DisplayName = "text that is not base 64")]
    [DataRow("AAAA", DisplayName = "base 64 of octets that are not a self-description")]
    public void ExtensionTextThatIsNotOneSelfDescriptionIsRefused(string text)
    {
        Assert.IsFalse(EArkEvidenceSelfDescription.TryReadExtensionText(text, BaseMemoryPool.Shared, out EArkEvidenceSelfDescription? read));
        Assert.IsNull(read);
    }


    /// <summary>
    /// Every status vocabulary this convention declares reserves zero for the unset value, so a
    /// default-initialised field never reads as an artifact kind or a carrier something really used.
    /// </summary>
    [TestMethod]
    public void NoDefaultInitialisedValueOfThisConventionReadsAsSomethingStated()
    {
        Assert.AreEqual(nameof(EArkEvidenceKind.NotEvaluated), Enum.GetName(default(EArkEvidenceKind)));
        Assert.AreEqual(nameof(EArkEvidenceSelfDescriptionCarrier.NotEvaluated), Enum.GetName(default(EArkEvidenceSelfDescriptionCarrier)));
        Assert.IsNull(EArkEvidenceWellKnown.MediaTypeOf(default), "A kind nothing stated names no media type.");
    }


    /// <summary>
    /// Builds a manifest carrying exactly one extension: this convention's self-description.
    /// </summary>
    /// <param name="extensionText">The base-64 text the extension carries.</param>
    /// <returns>The manifest. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the digest, the reference and the extension built here transfers to the returned manifest, whose own Dispose releases them and which the caller disposes.")]
    private static async Task<AsicManifest> BuildManifestAsync(string extensionText)
    {
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            Encoding.UTF8.GetBytes(ArchivedContent),
            PkiDigestAlgorithm.Sha256.OutputByteLength,
            PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared).ConfigureAwait(false);

        return new AsicManifest
        {
            SignatureReference = new AsicSignatureReference { Uri = "META-INF/signature1.p7s", MimeType = EArkEvidenceWellKnown.SignedDataObjectMediaType },
            DataObjectReferences =
            [
                new AsicDataObjectReference
                {
                    Uri = "provenance.xml",
                    DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                    Digest = digest,
                }
            ],
            Extensions = [EArkEvidenceSource.BuildSelfDescriptionExtension(extensionText)],
        };
    }


    /// <summary>
    /// Reads a whole <c>Attribute</c> encoding with a reader written here, so that what the carrier tests compare
    /// is the octets rather than the surface that produced them.
    /// </summary>
    /// <param name="encodedAttribute">The whole encoding of one <c>Attribute</c>.</param>
    /// <returns>The attribute's type and its single value's whole encoding.</returns>
    private static (string AttributeType, byte[] AttributeValue) ReadAttribute(ReadOnlySpan<byte> encodedAttribute)
    {
        var reader = new AsnReader(encodedAttribute.ToArray(), AsnEncodingRules.DER);
        AsnReader attribute = reader.ReadSequence();
        string attributeType = attribute.ReadObjectIdentifier();
        AsnReader values = attribute.ReadSetOf();
        byte[] value = values.ReadEncodedValue().ToArray();

        Assert.IsFalse(values.HasData, "The convention states one value, so the set holds exactly one.");
        Assert.IsFalse(attribute.HasData);
        Assert.IsFalse(reader.HasData);

        return (attributeType, value);
    }


    /// <summary>
    /// Builds one malformed value of the named shape, each written by an independent writer rather than by the
    /// encoder under test.
    /// </summary>
    /// <param name="shape">Which shape to build.</param>
    /// <returns>The octets.</returns>
    private static byte[] MalformedValue(string shape)
    {
        return shape switch
        {
            "empty" => [],
            "not-asn1" => Encoding.UTF8.GetBytes("this is not a DER value at all"),
            "trailing" => Concatenate(WellFormed(), [0x05, 0x00]),
            "out-of-order" => WriteFields([(2, "urn:example:profile"), (0, "urn:example:service")]),
            "repeated" => WriteFields([(1, "urn:example:policy"), (1, "urn:example:policy-again")]),
            "not-a-sequence" => WriteOctetString(),
            "unknown-field" => WriteFields([(0, "urn:example:service"), (3, "urn:example:unknown")]),
            "over-the-value-bound" => WriteFields([(0, new string('a', EArkEvidenceSelfDescription.MaximumValueByteLength))]),
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "No such malformed shape is stated.")
        };

        //One well-formed value, written by the same independent writer the malformed ones are.
        static byte[] WellFormed() => WriteFields([(0, "urn:example:service")]);

        //A SEQUENCE carrying the stated context-tagged strings in the stated order, whatever order that is.
        static byte[] WriteFields((int Tag, string Value)[] fields)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using(writer.PushSequence())
            {
                for(int i = 0; i < fields.Length; ++i)
                {
                    writer.WriteCharacterString(
                        UniversalTagNumber.UTF8String, fields[i].Value, new Asn1Tag(TagClass.ContextSpecific, fields[i].Tag));
                }
            }

            return writer.Encode();
        }

        //A DER value that is well formed and is not the outer SEQUENCE the model states.
        static byte[] WriteOctetString()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteOctetString("a value of the wrong type"u8);

            return writer.Encode();
        }

        //Two octet runs one after the other, which is what makes trailing octets trailing.
        static byte[] Concatenate(byte[] first, byte[] second)
        {
            var joined = new List<byte>(first.Length + second.Length);
            joined.AddRange(first);
            joined.AddRange(second);

            return [.. joined];
        }
    }
}

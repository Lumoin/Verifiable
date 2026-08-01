using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the three attributes for preservation evidences of Annex H of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>, with the ASN.1 module of Annex I: their object identifiers, their encoding, and
/// the two carriers clause H.1 puts them in — an archive time-stamp's <c>attributes</c> field and a signer's
/// unsigned attributes.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Everything is attached through the shipped splice primitives.</strong> An Evidence Record is minted by
/// the shipped creation surface and re-encoded through
/// <see cref="EvidenceRecords.EncodeArchiveTimeStamp(AlgorithmIdentifier?, IReadOnlyList{CmsAttribute}, IReadOnlyList{EvidenceRecordPartialHashtree}, ReadOnlyMemory{byte}, BaseMemoryPool)"/>,
/// and a Signed Data Object is augmented through
/// <see cref="CmsSignedDataAugmentation.AppendUnsignedAttributes"/> — the same extension points every other
/// unsigned attribute of this repository rides in. Nothing new is spliced for these three.
/// </para>
/// <para>
/// <strong>The attribute octets are read back independently.</strong> The value each attribute carries is decoded
/// in this file with an <see cref="AsnReader"/> written against Annex I's own module, so the encoding is checked
/// against the specification rather than against the reader that produced it.
/// </para>
/// <para>
/// <strong>These attributes and this wave's house self-description say the same three things</strong>, which the
/// bridge tests state outright: an evidence carrying Annex H's attributes reads back as the same record the
/// placement rules already consume.
/// </para>
/// </remarks>
[TestClass]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "Each attribute built here is disposed by the using that holds it or by the loop that disposes the list it was added to; a Signed Data Object produced by an augmentation supersedes the one it augmented, which is disposed as soon as it is superseded.")]
internal sealed class PreservationEvidenceAttributeTests
{
    /// <summary>The preservation service identifier the tests state.</summary>
    private static string ServiceIdentifier { get; } = "https://preservation.example.test/service/1";

    /// <summary>The preservation evidence policy identifier the tests state.</summary>
    private static string PolicyIdentifier { get; } = "https://preservation.example.test/policy/1";

    /// <summary>The preservation profile identifier the tests state.</summary>
    private static string ProfileIdentifier { get; } = "https://preservation.example.test/profile/1";

    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = default!;


    /// <summary>The three object identifiers are the children of the arc Annex I declares.</summary>
    [TestMethod]
    public void TheThreeAttributeTypesAreTheChildrenOfTheArcAnnexIDeclares()
    {
        Assert.AreEqual("0.4.0.19512.1", PreservationEvidenceAttributeWellKnown.AttributeArc);
        Assert.AreEqual("0.4.0.19512.1.1", PreservationEvidenceAttributeWellKnown.PreservationServiceIdentifierAttributeType);
        Assert.AreEqual("0.4.0.19512.1.2", PreservationEvidenceAttributeWellKnown.PreservationEvidencePolicyAttributeType);
        Assert.AreEqual("0.4.0.19512.1.3", PreservationEvidenceAttributeWellKnown.PreservationProfileAttributeType);

        Assert.AreEqual(
            PreservationEvidenceAttributeWellKnown.PreservationServiceIdentifierAttributeType,
            PreservationEvidenceAttributeWellKnown.AttributeTypeOf(PreservationEvidenceAttributeKind.PreservationServiceIdentifier));

        Assert.AreEqual(
            PreservationEvidenceAttributeKind.PreservationEvidencePolicy,
            PreservationEvidenceAttributeWellKnown.KindOf("0.4.0.19512.1.2"));

        Assert.AreEqual(PreservationEvidenceAttributeKind.None, PreservationEvidenceAttributeWellKnown.KindOf("0.4.0.19512.1.4"));
        Assert.AreEqual(PreservationEvidenceAttributeKind.None, PreservationEvidenceAttributeWellKnown.KindOf(null));
        Assert.IsTrue(PreservationEvidenceAttributeWellKnown.IsPreservationEvidenceAttribute("0.4.0.19512.1.3"));
        Assert.IsFalse(PreservationEvidenceAttributeWellKnown.IsPreservationEvidenceAttribute("1.2.840.113549.1.9.16.2.14"));

        Assert.AreEqual(nameof(PreservationEvidenceAttributeKind.None), Enum.GetName(default(PreservationEvidenceAttributeKind)));
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => PreservationEvidenceAttributeWellKnown.AttributeTypeOf(PreservationEvidenceAttributeKind.None));
    }


    /// <summary>Each attribute has the XML twin its own clause declares.</summary>
    [TestMethod]
    public void EachAttributeHasTheXmlElementItsClauseDeclares()
    {
        Assert.AreEqual(
            "PreservationServiceIdentifier",
            PreservationEvidenceAttributeWellKnown.ElementNameOf(PreservationEvidenceAttributeKind.PreservationServiceIdentifier));

        Assert.AreEqual(
            "PreservationEvidencePolicy",
            PreservationEvidenceAttributeWellKnown.ElementNameOf(PreservationEvidenceAttributeKind.PreservationEvidencePolicy));

        Assert.AreEqual(
            "PreservationProfile",
            PreservationEvidenceAttributeWellKnown.ElementNameOf(PreservationEvidenceAttributeKind.PreservationProfile));

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => PreservationEvidenceAttributeWellKnown.ElementNameOf((PreservationEvidenceAttributeKind)42));
    }


    /// <summary>
    /// An attribute is one <c>IA5String</c> under the type its clause names, which an independent reader written
    /// from Annex I's module reads back.
    /// </summary>
    [TestMethod]
    [DataRow(PreservationEvidenceAttributeKind.PreservationServiceIdentifier, "0.4.0.19512.1.1")]
    [DataRow(PreservationEvidenceAttributeKind.PreservationEvidencePolicy, "0.4.0.19512.1.2")]
    [DataRow(PreservationEvidenceAttributeKind.PreservationProfile, "0.4.0.19512.1.3")]
    public void AnAttributeIsOneStringUnderTheTypeItsClauseNames(PreservationEvidenceAttributeKind kind, string attributeType)
    {
        using CmsAttribute attribute = PreservationEvidenceAttributes.Create(kind, ServiceIdentifier, BaseMemoryPool.Shared);

        (string readType, string readValue) = ReadAttribute(attribute.AsReadOnlySpan().ToArray());
        Assert.AreEqual(attributeType, readType);
        Assert.AreEqual(ServiceIdentifier, readValue);

        Assert.IsTrue(PreservationEvidenceAttributes.TryReadFromAttributes([attribute.AsReadOnlyMemory()], kind, out string? value));
        Assert.AreEqual(ServiceIdentifier, value);

        //An attribute of another type is not this one, however well-formed it is.
        PreservationEvidenceAttributeKind other = kind == PreservationEvidenceAttributeKind.PreservationProfile
            ? PreservationEvidenceAttributeKind.PreservationServiceIdentifier
            : PreservationEvidenceAttributeKind.PreservationProfile;

        Assert.IsFalse(PreservationEvidenceAttributes.TryReadFromAttributes([attribute.AsReadOnlyMemory()], other, out string? notFound));
        Assert.IsNull(notFound);
    }


    /// <summary>Writing refuses what this library will not read back, and refuses what the string type does not admit.</summary>
    [TestMethod]
    public void WritingRefusesWhatCannotBeReadBack()
    {
        Assert.AreEqual(1024, PreservationEvidenceAttributes.MaximumValueLength);

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => PreservationEvidenceAttributes.Create(
            PreservationEvidenceAttributeKind.PreservationProfile,
            new string('u', PreservationEvidenceAttributes.MaximumValueLength + 1),
            BaseMemoryPool.Shared));

        //Annex I types the attribute as an IA5String, which has no room for a character outside the seven-bit
        //repertoire; a value carrying one is refused where it is written rather than encoded into something a
        //conformant reader rejects.
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => PreservationEvidenceAttributes.Create(
            PreservationEvidenceAttributeKind.PreservationProfile,
            "https://preservation.example.test/profile/ä",
            BaseMemoryPool.Shared));

        _ = Assert.ThrowsExactly<ArgumentException>(() => PreservationEvidenceAttributes.Create(
            PreservationEvidenceAttributeKind.PreservationProfile, string.Empty, BaseMemoryPool.Shared));

        _ = Assert.ThrowsExactly<ArgumentNullException>(() => PreservationEvidenceAttributes.Create(
            PreservationEvidenceAttributeKind.PreservationProfile, ProfileIdentifier, null!));
    }


    /// <summary>Reading refuses octets that are not one string within the bound, by status rather than by exception.</summary>
    [TestMethod]
    public void ReadingRefusesOctetsThatAreNotOneStringWithinTheBound()
    {
        Assert.IsFalse(PreservationEvidenceAttributes.TryDecodeValue(ReadOnlyMemory<byte>.Empty, out string? empty));
        Assert.IsNull(empty);

        Assert.IsFalse(PreservationEvidenceAttributes.TryDecodeValue(new byte[] { 0x16, 0x05, 0x61 }, out _), "A truncated value is refused.");

        //A value of another string type is not the type Annex I states.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, ServiceIdentifier);
        Assert.IsFalse(PreservationEvidenceAttributes.TryDecodeValue(writer.Encode(), out _));

        //Octets after the value are not part of it.
        var trailing = new AsnWriter(AsnEncodingRules.DER);
        trailing.WriteCharacterString(UniversalTagNumber.IA5String, ServiceIdentifier);
        byte[] encoded = trailing.Encode();
        byte[] withTrailing = new byte[encoded.Length + 1];
        encoded.CopyTo(withTrailing, 0);
        Assert.IsFalse(PreservationEvidenceAttributes.TryDecodeValue(withTrailing, out _));

        _ = Assert.ThrowsExactly<ArgumentNullException>(
            () => PreservationEvidenceAttributes.TryReadFromAttributes(null!, PreservationEvidenceAttributeKind.PreservationProfile, out _));
    }


    /// <summary>
    /// An Evidence Record carries the three attributes in the <c>attributes</c> field of its archive time-stamp,
    /// where a renewal goes on to protect them — and they are located and read through that same field.
    /// </summary>
    [TestMethod]
    public async Task AnEvidenceRecordCarriesTheAttributesInItsArchiveTimeStamp()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        ReadOnlyMemory<byte> dataObject = Encoding.UTF8.GetBytes("preserved");

        using EvidenceRecord plain = await MintRecordAsync([dataObject], authority);
        using EvidenceRecord described = CarryAttributes(plain);

        Assert.IsTrue(PreservationEvidenceAttributes.TryReadFromEvidenceRecord(
            described, PreservationEvidenceAttributeKind.PreservationServiceIdentifier, out string? service));
        Assert.AreEqual(ServiceIdentifier, service);

        Assert.IsTrue(PreservationEvidenceAttributes.TryReadFromEvidenceRecord(
            described, PreservationEvidenceAttributeKind.PreservationEvidencePolicy, out string? policy));
        Assert.AreEqual(PolicyIdentifier, policy);

        Assert.IsTrue(PreservationEvidenceAttributes.TryReadFromEvidenceRecord(
            described, PreservationEvidenceAttributeKind.PreservationProfile, out string? profile));
        Assert.AreEqual(ProfileIdentifier, profile);

        //A record carrying none of them says so rather than answering with something.
        Assert.IsFalse(PreservationEvidenceAttributes.TryReadFromEvidenceRecord(
            plain, PreservationEvidenceAttributeKind.PreservationProfile, out string? none));
        Assert.IsNull(none);

        //The rewritten record still verifies, which is what makes the attributes' carrier usable at all: the
        //reduced hash tree and the token are untouched by what was placed beside them.
        using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext { EvidenceRecord = described, DataObject = dataObject },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status);
    }


    /// <summary>
    /// A Hash-Tree Renewal carries the earlier chain forward octet for octet, which is what makes an attribute
    /// placed in it cryptographically protected — the reason clause H.1 puts them there.
    /// </summary>
    [TestMethod]
    public async Task ARenewalCarriesTheAttributesForwardAndProtectsThem()
    {
        using PreservationTimestampAuthority initialAuthority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        ReadOnlyMemory<byte> dataObject = Encoding.UTF8.GetBytes("preserved");

        using EvidenceRecord plain = await MintRecordAsync([dataObject], initialAuthority);
        using EvidenceRecord described = CarryAttributes(plain);

        using PreservationTimestampAuthority renewalAuthority = PreservationProfileSource.MintAuthority(PreservationProfileSource.RenewalArchiveTime);
        using EvidenceRecordRenewal renewal = await EvidenceRecords.RenewHashTreeAsync(
            new EvidenceRecordHashTreeRenewalContext
            {
                DataObjectGroups = [new EvidenceRecordHashTreeRenewalGroup { EvidenceRecord = described, DataObjects = [dataObject] }],
                DigestAlgorithm = PkiDigestAlgorithm.Sha512,
                TsaUri = renewalAuthority.Address,
                FetchTimestampResponse = renewalAuthority.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        using EvidenceRecord renewed = EvidenceRecord.Read(renewal.EvidenceRecords[0].AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.IsTrue(PreservationEvidenceAttributes.TryReadFromEvidenceRecord(
            renewed, PreservationEvidenceAttributeKind.PreservationEvidencePolicy, out string? policy));
        Assert.AreEqual(PolicyIdentifier, policy);

        //The renewal hashes the whole encoded sequence of the earlier chains, so the earlier chain — and the
        //attributes inside it — is what the new chain's token proves.
        OracleEvidenceRecord parsedBefore = EvidenceRecordOracle.ParseEvidenceRecord(described.AsReadOnlySpan().ToArray());
        OracleEvidenceRecord parsedAfter = EvidenceRecordOracle.ParseEvidenceRecord(renewed.AsReadOnlySpan().ToArray());

        Assert.HasCount(1, parsedBefore.Chains);
        Assert.HasCount(2, parsedAfter.Chains);
        Assert.IsTrue(
            parsedBefore.ChainEncodings[0].AsSpan().SequenceEqual(parsedAfter.ChainEncodings[0]),
            "The chain carrying the attributes is carried forward octet for octet, which is what the renewal's own token then covers.");
    }


    /// <summary>
    /// A Signed Data Object carries the attributes as unsigned attributes of its signer, located and read through
    /// the shipped splice primitives.
    /// </summary>
    [TestMethod]
    public async Task ASignedDataObjectCarriesTheAttributesAsUnsignedAttributes()
    {
        using CmsSignedData plain = await EArkEvidenceSource.MintSignedDataObjectAsync(
            Encoding.UTF8.GetBytes("signed content"),
            selfDescription: null,
            withArchiveTimestamp: false,
            TestContext.CancellationToken);

        var attributes = new List<CmsAttribute>(3);
        try
        {
            attributes.Add(PreservationEvidenceAttributes.Create(
                PreservationEvidenceAttributeKind.PreservationServiceIdentifier, ServiceIdentifier, BaseMemoryPool.Shared));
            attributes.Add(PreservationEvidenceAttributes.Create(
                PreservationEvidenceAttributeKind.PreservationEvidencePolicy, PolicyIdentifier, BaseMemoryPool.Shared));
            attributes.Add(PreservationEvidenceAttributes.Create(
                PreservationEvidenceAttributeKind.PreservationProfile, ProfileIdentifier, BaseMemoryPool.Shared));

            using CmsSignedData described = CmsSignedDataAugmentation.AppendUnsignedAttributes(plain, 0, attributes, BaseMemoryPool.Shared);

            Assert.IsTrue(PreservationEvidenceAttributes.TryReadFromSignedData(
                described, 0, PreservationEvidenceAttributeKind.PreservationServiceIdentifier, out string? service));
            Assert.AreEqual(ServiceIdentifier, service);

            Assert.IsTrue(PreservationEvidenceAttributes.TryReadFromSignedData(
                described, 0, PreservationEvidenceAttributeKind.PreservationProfile, out string? profile));
            Assert.AreEqual(ProfileIdentifier, profile);

            //Located through the same primitive a validator uses, which is what shows the attributes really sit
            //in the unsigned set rather than somewhere this library invented.
            IReadOnlyList<CmsUnsignedAttributeValueLocation> locations =
                CmsSignedDataAugmentation.LocateUnsignedAttributeValues(described, 0);

            int found = 0;
            for(int i = 0; i < locations.Count; ++i)
            {
                if(PreservationEvidenceAttributeWellKnown.IsPreservationEvidenceAttribute(locations[i].AttributeType))
                {
                    ++found;
                }
            }

            Assert.AreEqual(3, found, "All three attributes are locatable by their own types in the signer's unsigned attributes.");

            Assert.IsFalse(PreservationEvidenceAttributes.TryReadFromSignedData(
                plain, 0, PreservationEvidenceAttributeKind.PreservationProfile, out string? none));
            Assert.IsNull(none);
        }
        finally
        {
            for(int i = 0; i < attributes.Count; ++i)
            {
                attributes[i].Dispose();
            }
        }
    }


    /// <summary>
    /// The standardised attributes and this wave's house self-description state the same three identifiers, and
    /// convert into one another.
    /// </summary>
    [TestMethod]
    public async Task TheStandardisedAttributesAndTheHouseSelfDescriptionSayTheSameThreeThings()
    {
        using PreservationTimestampAuthority authority = PreservationProfileSource.MintAuthority(PreservationProfileSource.InitialArchiveTime);
        ReadOnlyMemory<byte> dataObject = Encoding.UTF8.GetBytes("preserved");

        using EvidenceRecord plain = await MintRecordAsync([dataObject], authority);
        using EvidenceRecord described = CarryAttributes(plain);

        EArkEvidenceSelfDescription? read = PreservationEvidenceAttributes.ReadSelfDescription(described);

        Assert.IsNotNull(read);
        Assert.AreEqual(ServiceIdentifier, read.PreservationServiceIdentifier);
        Assert.AreEqual(PolicyIdentifier, read.EvidencePolicyIdentifier);
        Assert.AreEqual(ProfileIdentifier, read.PreservationProfileIdentifier);
        Assert.IsTrue(read.IsStated);

        //And the other way: a self-description states itself as the three attributes the annex defines.
        IReadOnlyList<CmsAttribute> attributes = PreservationEvidenceAttributes.ToAttributes(read, BaseMemoryPool.Shared);
        try
        {
            Assert.HasCount(3, attributes);
            (string firstType, string firstValue) = ReadAttribute(attributes[0].AsReadOnlySpan().ToArray());
            Assert.AreEqual(PreservationEvidenceAttributeWellKnown.PreservationServiceIdentifierAttributeType, firstType);
            Assert.AreEqual(ServiceIdentifier, firstValue);
        }
        finally
        {
            for(int i = 0; i < attributes.Count; ++i)
            {
                attributes[i].Dispose();
            }
        }

        //A self-description stating only one identifier produces only that attribute.
        var partial = new EArkEvidenceSelfDescription { EvidencePolicyIdentifier = PolicyIdentifier };
        IReadOnlyList<CmsAttribute> partialAttributes = PreservationEvidenceAttributes.ToAttributes(partial, BaseMemoryPool.Shared);
        try
        {
            Assert.HasCount(1, partialAttributes);
            (string type, string value) = ReadAttribute(partialAttributes[0].AsReadOnlySpan().ToArray());
            Assert.AreEqual(PreservationEvidenceAttributeWellKnown.PreservationEvidencePolicyAttributeType, type);
            Assert.AreEqual(PolicyIdentifier, value);
        }
        finally
        {
            for(int i = 0; i < partialAttributes.Count; ++i)
            {
                partialAttributes[i].Dispose();
            }
        }

        //A record carrying none of the three states nothing, rather than an empty self-description.
        Assert.IsNull(PreservationEvidenceAttributes.ReadSelfDescription(plain));

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => PreservationEvidenceAttributes.ToAttributes(new EArkEvidenceSelfDescription(), BaseMemoryPool.Shared));

        _ = Assert.ThrowsExactly<ArgumentNullException>(
            () => PreservationEvidenceAttributes.ToAttributes(null!, BaseMemoryPool.Shared));
    }


    /// <summary>A Signed Data Object's attributes read back as the same house record too.</summary>
    [TestMethod]
    public async Task ASignedDataObjectsAttributesReadBackAsTheHouseRecord()
    {
        using CmsSignedData plain = await EArkEvidenceSource.MintSignedDataObjectAsync(
            Encoding.UTF8.GetBytes("signed content"),
            selfDescription: null,
            withArchiveTimestamp: false,
            TestContext.CancellationToken);

        using CmsAttribute policy = PreservationEvidenceAttributes.Create(
            PreservationEvidenceAttributeKind.PreservationEvidencePolicy, PolicyIdentifier, BaseMemoryPool.Shared);

        using CmsSignedData described = CmsSignedDataAugmentation.AppendUnsignedAttributes(plain, 0, [policy], BaseMemoryPool.Shared);

        EArkEvidenceSelfDescription? read = PreservationEvidenceAttributes.ReadSelfDescription(described, 0);

        Assert.IsNotNull(read);
        Assert.IsNull(read.PreservationServiceIdentifier);
        Assert.AreEqual(PolicyIdentifier, read.EvidencePolicyIdentifier);
        Assert.IsNull(read.PreservationProfileIdentifier);

        Assert.IsNull(PreservationEvidenceAttributes.ReadSelfDescription(plain, 0));
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => PreservationEvidenceAttributes.ReadSelfDescription(described, -1));
    }


    /// <summary>
    /// Reads one whole <c>Attribute</c> encoding with a reader written from Annex I's own module, independently of
    /// the surface that produced it.
    /// </summary>
    /// <param name="encodedAttribute">The whole DER encoding of one attribute.</param>
    /// <returns>The attribute type and the single value it carries.</returns>
    private static (string AttributeType, string Value) ReadAttribute(byte[] encodedAttribute)
    {
        var reader = new AsnReader(encodedAttribute, AsnEncodingRules.DER);
        AsnReader attribute = reader.ReadSequence();
        string attributeType = attribute.ReadObjectIdentifier();
        AsnReader values = attribute.ReadSetOf();
        string value = values.ReadCharacterString(UniversalTagNumber.IA5String);

        Assert.IsFalse(values.HasData, "Clauses H.2.2, H.3.2 and H.4.2 make the attribute carry exactly one value.");
        Assert.IsFalse(attribute.HasData);
        Assert.IsFalse(reader.HasData);

        return (attributeType, value);
    }


    /// <summary>
    /// Rewrites a record's one archive time-stamp with the three attributes in its <c>attributes</c> field,
    /// leaving the reduced hash tree and the token exactly as the creation surface wrote them.
    /// </summary>
    /// <param name="evidenceRecord">The record to rewrite, which the caller still owns.</param>
    /// <returns>The rewritten record. The caller owns and disposes it.</returns>
    private static EvidenceRecord CarryAttributes(EvidenceRecord evidenceRecord)
    {
        EvidenceRecordArchiveTimeStamp stamp = evidenceRecord.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps[0];

        var attributes = new List<CmsAttribute>(3);
        try
        {
            attributes.Add(PreservationEvidenceAttributes.Create(
                PreservationEvidenceAttributeKind.PreservationServiceIdentifier, ServiceIdentifier, BaseMemoryPool.Shared));
            attributes.Add(PreservationEvidenceAttributes.Create(
                PreservationEvidenceAttributeKind.PreservationEvidencePolicy, PolicyIdentifier, BaseMemoryPool.Shared));
            attributes.Add(PreservationEvidenceAttributes.Create(
                PreservationEvidenceAttributeKind.PreservationProfile, ProfileIdentifier, BaseMemoryPool.Shared));

            using PooledMemory rewrittenStamp = EvidenceRecords.EncodeArchiveTimeStamp(
                stamp.DigestAlgorithm, attributes, stamp.ReducedHashtree, stamp.TimeStamp, BaseMemoryPool.Shared);

            using PooledMemory rewrittenChain = EvidenceRecords.EncodeArchiveTimeStampChain(
                [rewrittenStamp.AsReadOnlyMemory()], BaseMemoryPool.Shared);

            return EvidenceRecord.Create(
                evidenceRecord.DigestAlgorithms, cryptoInfos: null, [rewrittenChain.AsReadOnlyMemory()], BaseMemoryPool.Shared);
        }
        finally
        {
            for(int i = 0; i < attributes.Count; ++i)
            {
                attributes[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Mints an Evidence Record over one data object group through the shipped creation surface.
    /// </summary>
    /// <param name="dataObjects">The octets the record is to prove, as one group.</param>
    /// <param name="authority">The authority the record's initial archive time-stamp is taken from.</param>
    /// <returns>The record. The caller owns and disposes it.</returns>
    private async ValueTask<EvidenceRecord> MintRecordAsync(
        IReadOnlyList<ReadOnlyMemory<byte>> dataObjects,
        PreservationTimestampAuthority authority)
    {
        using EvidenceRecordCreation creation = await EvidenceRecords.CreateInitialAsync(
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = [new EvidenceRecordDataObjectGroup { DataObjects = dataObjects }],
                DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = authority.Address,
                FetchTimestampResponse = authority.Responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);

        return EvidenceRecord.Read(creation.EvidenceRecords[0].AsReadOnlySpan(), BaseMemoryPool.Shared);
    }
}

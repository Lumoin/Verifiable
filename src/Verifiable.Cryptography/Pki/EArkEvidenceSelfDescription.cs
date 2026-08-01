using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What an evidential artifact says about its own provenance: the preservation service that produced it, the
/// preservation evidence policy it was produced under, and the preservation profile that policy names.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The requirement, and the gap it names.</strong>
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1 clause 6.5</see> requirement <c>OVR-6.5-09</c> asks an evidence policy to state
/// "whether and how the preservation evidence carries explicit information of" a) the applicable preservation
/// service, b) the preservation evidence policy, or c) the preservation profile; clause 9.2 requirement
/// <c>OVR-9.2-04</c> asks that, when the policy cannot be identified from context, it be included in the
/// evidence itself, and <c>OVR-9.2-05</c> asks an embedded one to be cryptographically protected. No format the
/// specification names carries a field for this — the three fields below are what fills that gap, and they are
/// stated once here rather than three times, one per carrier.
/// </para>
/// <para>
/// <strong>One value, three carriers.</strong> The canonical form is the DER encoding of
/// </para>
/// <code>
/// PreservationEvidenceSelfDescription ::= SEQUENCE {
///   preservationService  [0] UTF8String OPTIONAL,
///   evidencePolicy       [1] UTF8String OPTIONAL,
///   preservationProfile  [2] UTF8String OPTIONAL }
/// </code>
/// <para>
/// which the two attribute-shaped extension points carry verbatim as the single value of a CMS attribute of
/// type <see cref="EArkEvidenceWellKnown.SelfDescriptionAttributeType"/> — the <c>attributes [1]</c> field of an
/// <c>ArchiveTimeStamp</c> (<see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.1">IETF RFC 4998 clause
/// 4.1</see>) and the <c>unsignedAttrs</c> field of a <c>SignerInfo</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">IETF RFC 5652 clause 5.3</see>) — and which
/// the container extension point carries as the same octets in base 64, because an <c>Extension</c>'s content is
/// XML and this project references no XML package.
/// </para>
/// <para>
/// <strong>Where the Evidence Record carrier places it, and why.</strong> RFC 4998 offers two attribute-shaped
/// fields. <c>cryptoInfos</c> of clause 3.1 is the wrong one: the clause states outright that "this data is not
/// protected within any timestamp", which is the opposite of what <c>OVR-9.2-05</c> asks for. The
/// <c>attributes</c> field of an <c>ArchiveTimeStamp</c> is the right one: clause 5.2's Hash-Tree Renewal hashes
/// the whole encoded <c>ArchiveTimeStampSequence</c>, so every attribute of every earlier archive time-stamp is
/// inside what the next renewal proves. The self-description therefore becomes cryptographically protected by
/// the same act that keeps the evidence itself alive.
/// </para>
/// <para>
/// <strong>Reading never throws on what a producer wrote.</strong> An artifact arrives from whoever made it, so
/// every way a self-description can be malformed is a <see langword="false"/> from a <c>Try</c> method rather
/// than an exception, and no partially populated instance is ever produced. Writing is the other way round: an
/// instance stating nothing at all is a generator fault and refuses.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EArkEvidenceSelfDescription
{
    /// <summary>
    /// The identifier of the preservation service that produced the evidence — item a) of <c>OVR-6.5-09</c> —
    /// or <see langword="null"/> when the artifact states none.
    /// </summary>
    /// <remarks>
    /// In a consumer's provenance graph this is the <c>prov:Agent</c> the creation activity was
    /// <c>prov:wasAssociatedWith</c>.
    /// </remarks>
    public string? PreservationServiceIdentifier { get; init; }

    /// <summary>
    /// The identifier of the preservation evidence policy the evidence was produced under — item b) of
    /// <c>OVR-6.5-09</c>, and the value <c>OVR-9.2-04</c> asks to be present when context does not supply it —
    /// or <see langword="null"/> when the artifact states none.
    /// </summary>
    /// <remarks>
    /// In a consumer's provenance graph this is a <c>prov:Plan</c> the creation activity's
    /// <c>prov:Association</c> <c>prov:hadPlan</c>.
    /// </remarks>
    public string? EvidencePolicyIdentifier { get; init; }

    /// <summary>
    /// The identifier of the preservation profile that policy names — item c) of <c>OVR-6.5-09</c> — or
    /// <see langword="null"/> when the artifact states none.
    /// </summary>
    /// <remarks>
    /// In a consumer's provenance graph this is a second <c>prov:Plan</c>, the one the policy itself refers to.
    /// </remarks>
    public string? PreservationProfileIdentifier { get; init; }


    /// <summary>Gets whether the self-description states anything at all.</summary>
    public bool IsStated =>
        PreservationServiceIdentifier is not null
        || EvidencePolicyIdentifier is not null
        || PreservationProfileIdentifier is not null;


    /// <summary>
    /// The largest number of octets one identifier is read with. The syntax bounds none of them; an artifact
    /// arrives from whoever produced it, and a self-description costs a reader memory and buys it nothing that
    /// is authenticated until the evidence around it verifies.
    /// </summary>
    public static int MaximumIdentifierByteLength { get; } = 1024;

    /// <summary>The largest number of octets a whole encoded self-description is read with.</summary>
    public static int MaximumValueByteLength { get; } = 4096;


    /// <summary>The <c>[0]</c> context tag of the preservation-service field.</summary>
    private static Asn1Tag PreservationServiceTag { get; } = new(TagClass.ContextSpecific, 0);

    /// <summary>The <c>[1]</c> context tag of the evidence-policy field.</summary>
    private static Asn1Tag EvidencePolicyTag { get; } = new(TagClass.ContextSpecific, 1);

    /// <summary>The <c>[2]</c> context tag of the preservation-profile field.</summary>
    private static Asn1Tag PreservationProfileTag { get; } = new(TagClass.ContextSpecific, 2);


    /// <summary>
    /// Encodes the canonical DER form — the one <c>AttributeValue</c> both attribute-shaped carriers hold and
    /// the octets the container carrier holds in base 64.
    /// </summary>
    /// <param name="pool">The memory pool the encoded value is rented from.</param>
    /// <returns>The encoded value. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// When the instance states no identifier at all, which would encode a value saying nothing, or when an
    /// identifier is longer than <see cref="MaximumIdentifierByteLength"/> — a value this library would refuse
    /// to read back.
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    public PooledMemory EncodeValue(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(!IsStated)
        {
            throw new InvalidOperationException(
                "A self-description states at least one of the preservation service, the evidence policy and the preservation profile (ETSI TS 119 511 V1.2.1 OVR-6.5-09).");
        }

        EnsureWithinBound(PreservationServiceIdentifier, nameof(PreservationServiceIdentifier));
        EnsureWithinBound(EvidencePolicyIdentifier, nameof(EvidencePolicyIdentifier));
        EnsureWithinBound(PreservationProfileIdentifier, nameof(PreservationProfileIdentifier));

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            WriteOptional(writer, PreservationServiceIdentifier, PreservationServiceTag);
            WriteOptional(writer, EvidencePolicyIdentifier, EvidencePolicyTag);
            WriteOptional(writer, PreservationProfileIdentifier, PreservationProfileTag);
        }

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out int written);

            return new PooledMemory(owner, written, EArkTags.EvidenceSelfDescription);
        }
        catch
        {
            owner.Dispose();

            throw;
        }

        //One optional field, written only when the caller stated it, which is what makes an absent field absent
        //rather than an empty string.
        static void WriteOptional(AsnWriter writer, string? value, Asn1Tag tag)
        {
            if(value is not null)
            {
                writer.WriteCharacterString(UniversalTagNumber.UTF8String, value, tag);
            }
        }

        //An identifier this library would refuse to read back is refused where it is written, so a package this
        //library produces is always one it can read.
        static void EnsureWithinBound(string? value, string fieldName)
        {
            if(value is not null && Encoding.UTF8.GetByteCount(value) > MaximumIdentifierByteLength)
            {
                throw new InvalidOperationException(
                    $"The {fieldName} is longer than the {MaximumIdentifierByteLength} octets a self-description is read with.");
            }
        }
    }


    /// <summary>
    /// Encodes the canonical form as a CMS attribute — the shape both attribute-shaped carriers take.
    /// </summary>
    /// <param name="pool">The memory pool the attribute is rented from.</param>
    /// <returns>The attribute. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When the instance states nothing, or an identifier is over the bound.</exception>
    public CmsAttribute ToAttribute(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        using PooledMemory value = EncodeValue(pool);

        return CmsAttribute.Create(EArkEvidenceWellKnown.SelfDescriptionAttributeType, value.AsReadOnlySpan(), pool);
    }


    /// <summary>
    /// Encodes the canonical form as the text content of the container-extension carrier's element: the same
    /// octets in base 64.
    /// </summary>
    /// <param name="pool">The memory pool the intermediate encoding is rented from.</param>
    /// <returns>The text a caller places inside <see cref="EArkEvidenceWellKnown.SelfDescriptionElementName"/>.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When the instance states nothing, or an identifier is over the bound.</exception>
    /// <remarks>
    /// The octets are the value; the container carrier differs from the other two only in that the octets travel
    /// through a text node, which is what an <c>Extension</c>'s <c>AnyType</c> content admits without this
    /// project acquiring an XML dependency.
    /// </remarks>
    public string ToExtensionText(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        using PooledMemory value = EncodeValue(pool);

        return Convert.ToBase64String(value.AsReadOnlySpan());
    }


    /// <summary>
    /// Reads the canonical DER form.
    /// </summary>
    /// <param name="value">The <c>AttributeValue</c> octets, or the octets a base-64 text node carried.</param>
    /// <param name="selfDescription">The self-description read, or <see langword="null"/> when the octets are not one.</param>
    /// <returns><see langword="true"/> when the octets are exactly one self-description this library states.</returns>
    /// <remarks>
    /// Malformed input, trailing octets, a field out of order, a repeated field, an identifier over the bound
    /// and a value stating nothing all answer <see langword="false"/>. Nothing partially populated is ever
    /// produced, so a caller acting on a <see langword="true"/> is acting on a whole value.
    /// </remarks>
    public static bool TryDecodeValue(ReadOnlyMemory<byte> value, [NotNullWhen(true)] out EArkEvidenceSelfDescription? selfDescription)
    {
        selfDescription = null;
        if(value.IsEmpty || value.Length > MaximumValueByteLength)
        {
            return false;
        }

        try
        {
            var reader = new AsnReader(value, AsnEncodingRules.DER);
            AsnReader sequence = reader.ReadSequence();
            if(reader.HasData)
            {
                return false;
            }

            string? service = ReadOptional(sequence, PreservationServiceTag);
            string? policy = ReadOptional(sequence, EvidencePolicyTag);
            string? profile = ReadOptional(sequence, PreservationProfileTag);
            if(sequence.HasData)
            {
                return false;
            }

            var candidate = new EArkEvidenceSelfDescription
            {
                PreservationServiceIdentifier = service,
                EvidencePolicyIdentifier = policy,
                PreservationProfileIdentifier = profile
            };

            if(!candidate.IsStated)
            {
                return false;
            }

            selfDescription = candidate;

            return true;
        }
        catch(AsnContentException)
        {
            return false;
        }

        //One optional field, present only when the next value carries its tag, which is what makes the three
        //fields distinguishable without a length-prefixed discriminator.
        static string? ReadOptional(AsnReader sequence, Asn1Tag tag)
        {
            if(!sequence.HasData || sequence.PeekTag() != tag)
            {
                return null;
            }

            string read = sequence.ReadCharacterString(UniversalTagNumber.UTF8String, tag);

            return Encoding.UTF8.GetByteCount(read) > MaximumIdentifierByteLength
                ? throw new AsnContentException("A self-description identifier is longer than this library reads.")
                : read;
        }
    }


    /// <summary>
    /// Reads the self-description out of the whole encodings of a set of CMS attributes — the shape an
    /// <c>ArchiveTimeStamp</c>'s <c>attributes</c> field surfaces on
    /// <see cref="EvidenceRecordArchiveTimeStamp.Attributes"/>.
    /// </summary>
    /// <param name="encodedAttributes">The whole encodings of the attributes, each a complete <c>Attribute</c> SEQUENCE.</param>
    /// <param name="selfDescription">The self-description read, or <see langword="null"/> when none is present.</param>
    /// <returns><see langword="true"/> when exactly one attribute of this convention's type carried one this library can read.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="encodedAttributes"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// An attribute of the convention's type carrying more than one value, or a value this library cannot read,
    /// answers <see langword="false"/>: the convention states one value, and a producer that placed several has
    /// stated something this library does not know how to read as one self-description.
    /// </remarks>
    public static bool TryReadFromAttributes(
        IReadOnlyList<ReadOnlyMemory<byte>> encodedAttributes,
        [NotNullWhen(true)] out EArkEvidenceSelfDescription? selfDescription)
    {
        ArgumentNullException.ThrowIfNull(encodedAttributes);

        selfDescription = null;
        for(int i = 0; i < encodedAttributes.Count; ++i)
        {
            if(!TryReadAttributeValue(encodedAttributes[i], out ReadOnlyMemory<byte> attributeValue))
            {
                continue;
            }

            if(TryDecodeValue(attributeValue, out EArkEvidenceSelfDescription? read))
            {
                selfDescription = read;

                return true;
            }

            return false;
        }

        return false;
    }


    /// <summary>
    /// Reads the self-description an Evidence Record carries in the <c>attributes</c> field of one of its
    /// archive time-stamps.
    /// </summary>
    /// <param name="evidenceRecord">The Evidence Record.</param>
    /// <param name="selfDescription">The self-description read, or <see langword="null"/> when none is present.</param>
    /// <returns><see langword="true"/> when an archive time-stamp of the record carries one.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="evidenceRecord"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// The chains are walked newest first, because a renewal states the policy in force when it ran and that is
    /// what a reader asking "under what policy is this evidence being kept" wants; an earlier chain's answer is
    /// still there and is still covered by every later renewal.
    /// </remarks>
    public static bool TryReadFromEvidenceRecord(
        EvidenceRecord evidenceRecord,
        [NotNullWhen(true)] out EArkEvidenceSelfDescription? selfDescription)
    {
        ArgumentNullException.ThrowIfNull(evidenceRecord);

        selfDescription = null;
        IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains = evidenceRecord.ArchiveTimeStampSequence.Chains;
        for(int chainIndex = chains.Count - 1; chainIndex >= 0; --chainIndex)
        {
            IReadOnlyList<EvidenceRecordArchiveTimeStamp> archiveTimeStamps = chains[chainIndex].ArchiveTimeStamps;
            for(int stampIndex = archiveTimeStamps.Count - 1; stampIndex >= 0; --stampIndex)
            {
                if(TryReadFromAttributes(archiveTimeStamps[stampIndex].Attributes, out EArkEvidenceSelfDescription? read))
                {
                    selfDescription = read;

                    return true;
                }
            }
        }

        return false;
    }


    /// <summary>
    /// Reads the self-description a Signed Data Object carries as an unsigned attribute of one of its signers.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <param name="selfDescription">The self-description read, or <see langword="null"/> when none is present.</param>
    /// <returns><see langword="true"/> when the signer carries one.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    public static bool TryReadFromSignedData(
        CmsSignedData signedData,
        int signerIndex,
        [NotNullWhen(true)] out EArkEvidenceSelfDescription? selfDescription)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        selfDescription = null;
        IReadOnlyList<CmsUnsignedAttributeValueLocation> locations =
            CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex);

        for(int i = 0; i < locations.Count; ++i)
        {
            if(!string.Equals(locations[i].AttributeType, EArkEvidenceWellKnown.SelfDescriptionAttributeType, StringComparison.Ordinal))
            {
                continue;
            }

            ReadOnlyMemory<byte> value = CmsSignedDataAugmentation.ReadUnsignedAttributeValue(
                signedData, signerIndex, locations[i].AttributeIndex, locations[i].ValueIndex);

            if(TryDecodeValue(value, out EArkEvidenceSelfDescription? read))
            {
                selfDescription = read;

                return true;
            }

            return false;
        }

        return false;
    }


    /// <summary>
    /// Reads the self-description a container manifest's extension carried as base-64 text.
    /// </summary>
    /// <param name="text">The text content of the extension's element, or <see langword="null"/>.</param>
    /// <param name="pool">The memory pool the decoded octets are rented from for the duration of the call.</param>
    /// <param name="selfDescription">The self-description read, or <see langword="null"/> when the text is not one.</param>
    /// <returns><see langword="true"/> when the text decodes to exactly one self-description this library states.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// This is the half of the container carrier that lives in this project. Extracting the text from the
    /// <c>Extension</c> element's own octets is the serialisation seam's business, as everywhere else in this
    /// wave — the manifest parse and encode delegates are where XML is met.
    /// </remarks>
    public static bool TryReadExtensionText(
        string? text,
        BaseMemoryPool pool,
        [NotNullWhen(true)] out EArkEvidenceSelfDescription? selfDescription)
    {
        ArgumentNullException.ThrowIfNull(pool);

        selfDescription = null;
        if(string.IsNullOrEmpty(text))
        {
            return false;
        }

        //Base 64 expands three octets into four characters, so a text over the ceiling cannot decode to a value
        //within it and is refused without renting for it.
        if(text.Length > (((MaximumValueByteLength + 2) / 3 * 4) + 4))
        {
            return false;
        }

        using IMemoryOwner<byte> owner = pool.Rent(MaximumValueByteLength);
        if(!Convert.TryFromBase64String(text, owner.Memory.Span[..MaximumValueByteLength], out int written))
        {
            return false;
        }

        return TryDecodeValue(owner.Memory[..written], out selfDescription);
    }


    /// <summary>
    /// Reads the single <c>AttributeValue</c> of a whole <c>Attribute</c> encoding whose <c>attrType</c> is this
    /// convention's.
    /// </summary>
    /// <param name="encodedAttribute">The whole encoding of one <c>Attribute</c>.</param>
    /// <param name="attributeValue">The single value's whole encoding, or empty when the attribute is not one of this convention's.</param>
    /// <returns><see langword="true"/> when the attribute is this convention's and carries exactly one value.</returns>
    private static bool TryReadAttributeValue(ReadOnlyMemory<byte> encodedAttribute, out ReadOnlyMemory<byte> attributeValue)
    {
        attributeValue = ReadOnlyMemory<byte>.Empty;
        if(encodedAttribute.IsEmpty)
        {
            return false;
        }

        try
        {
            var reader = new AsnReader(encodedAttribute, AsnEncodingRules.DER);
            AsnReader attribute = reader.ReadSequence();
            if(!string.Equals(attribute.ReadObjectIdentifier(), EArkEvidenceWellKnown.SelfDescriptionAttributeType, StringComparison.Ordinal))
            {
                return false;
            }

            AsnReader values = attribute.ReadSetOf();
            attributeValue = values.ReadEncodedValue();

            return !values.HasData;
        }
        catch(AsnContentException)
        {
            return false;
        }
    }


    /// <summary>A short debugger string showing which of the three identifiers the self-description states.</summary>
    private string DebuggerDisplay =>
        $"EArkEvidenceSelfDescription(service {PreservationServiceIdentifier ?? "unstated"}, policy {EvidencePolicyIdentifier ?? "unstated"}, profile {PreservationProfileIdentifier ?? "unstated"})";
}

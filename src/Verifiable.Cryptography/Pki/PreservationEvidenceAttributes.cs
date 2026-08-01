using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which of the three attributes for preservation evidences of Annex H of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> a value is.
/// </summary>
/// <remarks>
/// <see cref="None"/> occupies zero so a default-initialised value never reads as one of the three.
/// </remarks>
public enum PreservationEvidenceAttributeKind
{
    /// <summary>No attribute stated. The value of an unset field, by design.</summary>
    None = 0,

    /// <summary>The <c>preservation-service-identifier</c> attribute of clause H.2 — which preservation service produced the evidence.</summary>
    PreservationServiceIdentifier = 1,

    /// <summary>The <c>preservation-evidence-policy</c> attribute of clause H.3 — under which preservation evidence policy it was produced.</summary>
    PreservationEvidencePolicy = 2,

    /// <summary>The <c>preservation-profile</c> attribute of clause H.4 — which preservation profile that policy names.</summary>
    PreservationProfile = 3
}


/// <summary>
/// The object identifiers, the XML element names and the recognition helpers of the three attributes for
/// preservation evidences that Annex H of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> defines and Annex I gives the ASN.1 module for.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The arc is the specification's own.</strong> Annex I declares
/// <c>id-pres-preservation-evidence-attributes</c> as
/// <c>{ itu-t(0) identified-organization(4) etsi(0) preservation(19512) attributes(1) }</c> and the three
/// attributes as its children 1, 2 and 3, which is what the dotted-decimal values below spell. Annex H.2.2 states
/// that Annex I's definitions take precedence over the copies inside Annex H on any discrepancy, and the two
/// agree here.
/// </para>
/// <para>
/// <strong>Each attribute has an XML twin.</strong> Clauses H.2.3, H.3.3 and H.4.3 declare an element of the same
/// name, of type <c>anyURI</c>, in this protocol's own namespace
/// (<see cref="PreservationWellKnown.PreservationNamespace"/>) — for insertion into an XML-syntax evidence record
/// or an XML-syntax signature, which are the carriers this library does not produce. The names are stated so a
/// reader of such a document can recognise them.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
    Justification = "An attribute type is an object identifier in dotted-decimal form, not a locator, and is compared as an exact character sequence.")]
public static class PreservationEvidenceAttributeWellKnown
{
    /// <summary>The arc every attribute of Annex I is a child of, <c>0.4.0.19512.1</c>.</summary>
    public static string AttributeArc { get; } = "0.4.0.19512.1";

    /// <summary>The <c>id-pres-preservation-service-identifier</c> object identifier, <c>0.4.0.19512.1.1</c> (Annex H.2.2).</summary>
    public static string PreservationServiceIdentifierAttributeType { get; } = "0.4.0.19512.1.1";

    /// <summary>The <c>id-pres-preservation-evidence-policy</c> object identifier, <c>0.4.0.19512.1.2</c> (Annex H.3.2).</summary>
    public static string PreservationEvidencePolicyAttributeType { get; } = "0.4.0.19512.1.2";

    /// <summary>The <c>id-pres-preservation-profile</c> object identifier, <c>0.4.0.19512.1.3</c> (Annex H.4.2).</summary>
    public static string PreservationProfileAttributeType { get; } = "0.4.0.19512.1.3";


    /// <summary>The <c>PreservationServiceIdentifier</c> XML element name (clause H.2.3).</summary>
    public static string PreservationServiceIdentifierElementName { get; } = "PreservationServiceIdentifier";

    /// <summary>The <c>PreservationEvidencePolicy</c> XML element name (clause H.3.3).</summary>
    public static string PreservationEvidencePolicyElementName { get; } = "PreservationEvidencePolicy";

    /// <summary>The <c>PreservationProfile</c> XML element name (clause H.4.3).</summary>
    public static string PreservationProfileElementName { get; } = "PreservationProfile";


    /// <summary>
    /// States the object identifier of one attribute.
    /// </summary>
    /// <param name="kind">Which attribute.</param>
    /// <returns>The attribute type.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="kind"/> is not one of the three.</exception>
    public static string AttributeTypeOf(PreservationEvidenceAttributeKind kind) => kind switch
    {
        PreservationEvidenceAttributeKind.PreservationServiceIdentifier => PreservationServiceIdentifierAttributeType,
        PreservationEvidenceAttributeKind.PreservationEvidencePolicy => PreservationEvidencePolicyAttributeType,
        PreservationEvidenceAttributeKind.PreservationProfile => PreservationProfileAttributeType,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Annex H defines three attributes for preservation evidences and no others.")
    };


    /// <summary>
    /// States the XML element name of one attribute.
    /// </summary>
    /// <param name="kind">Which attribute.</param>
    /// <returns>The element name.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="kind"/> is not one of the three.</exception>
    public static string ElementNameOf(PreservationEvidenceAttributeKind kind) => kind switch
    {
        PreservationEvidenceAttributeKind.PreservationServiceIdentifier => PreservationServiceIdentifierElementName,
        PreservationEvidenceAttributeKind.PreservationEvidencePolicy => PreservationEvidencePolicyElementName,
        PreservationEvidenceAttributeKind.PreservationProfile => PreservationProfileElementName,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Annex H defines three attributes for preservation evidences and no others.")
    };


    /// <summary>
    /// Classifies an attribute type.
    /// </summary>
    /// <param name="attributeType">The <c>attrType</c> of an attribute, or <see langword="null"/>.</param>
    /// <returns>Which attribute it is, or <see cref="PreservationEvidenceAttributeKind.None"/>.</returns>
    public static PreservationEvidenceAttributeKind KindOf(string? attributeType) => attributeType switch
    {
        var type when string.Equals(type, PreservationServiceIdentifierAttributeType, StringComparison.Ordinal) => PreservationEvidenceAttributeKind.PreservationServiceIdentifier,
        var type when string.Equals(type, PreservationEvidencePolicyAttributeType, StringComparison.Ordinal) => PreservationEvidenceAttributeKind.PreservationEvidencePolicy,
        var type when string.Equals(type, PreservationProfileAttributeType, StringComparison.Ordinal) => PreservationEvidenceAttributeKind.PreservationProfile,
        _ => PreservationEvidenceAttributeKind.None
    };


    /// <summary>Determines whether an attribute type is one of Annex H's three.</summary>
    /// <param name="attributeType">The <c>attrType</c> of an attribute, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when it is.</returns>
    public static bool IsPreservationEvidenceAttribute(string? attributeType) =>
        KindOf(attributeType) != PreservationEvidenceAttributeKind.None;
}


/// <summary>
/// The three attributes for preservation evidences of Annex H of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>: writing one as a CMS attribute, and reading one out of the carriers clause H.1
/// puts them in.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Where they go, in the specification's own words.</strong> Clause H.1: the ASN.1-based attributes
/// "shall be inserted as attribute in an ASN.1-based evidence record according to IETF RFC 4998 … or as unsigned
/// attribute of a CAdES digital signature … before an <c>archive-time-stamp-v3</c> attribute is applied". Those
/// are exactly two extension points this library already ships — the <c>attributes [1]</c> field of an
/// <c>ArchiveTimeStamp</c>, reached through
/// <see cref="EvidenceRecords.EncodeArchiveTimeStamp(AlgorithmIdentifier?, IReadOnlyList{CmsAttribute}, IReadOnlyList{EvidenceRecordPartialHashtree}, ReadOnlyMemory{byte}, BaseMemoryPool)"/>
/// and surfaced on <see cref="EvidenceRecordArchiveTimeStamp.Attributes"/>, and a <c>SignerInfo</c>'s
/// <c>unsignedAttrs</c>, reached through
/// <see cref="CmsSignedDataAugmentation.AppendUnsignedAttributes"/> and located through
/// <see cref="CmsSignedDataAugmentation.LocateUnsignedAttributeValues"/>. Nothing new is spliced here.
/// </para>
/// <para>
/// <strong>The value is one <c>IA5String</c>.</strong> Annex I types all three as <c>IA5String</c> and clauses
/// H.2.1, H.3.1 and H.4.1 require the content to be "a URI according to IETF RFC 3986", each attribute carrying
/// "exactly one component of <c>AttributeValue</c> type". Writing therefore refuses a value with a character
/// outside the string type's own repertoire rather than encoding something a conformant reader would reject, and
/// reading refuses an attribute carrying more than one value.
/// </para>
/// <para>
/// <strong>These attributes and this wave's evidence self-description say the same three things.</strong> The
/// house convention of <see cref="EArkEvidenceSelfDescription"/> was written for
/// <c>OVR-6.5-09</c> items a), b) and c) of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see>, and these three attributes are those same three identifiers with identifiers
/// this specification assigns. <see cref="ReadSelfDescription(EvidenceRecord)"/> and
/// <see cref="ToAttributes(EArkEvidenceSelfDescription, BaseMemoryPool)"/> convert between the two so a package
/// may carry the standardised attributes and still be read by the shipped placement rules, and so a package
/// carrying the house value can be re-stated in the standardised form.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
    Justification = "The value is written into an IA5String and compared as the exact character sequence the producer stated; System.Uri normalises case and escaping, which would change what the evidence says about itself. Nothing here is dereferenced.")]
public static class PreservationEvidenceAttributes
{
    /// <summary>
    /// The largest number of characters one attribute value is written or read with, 1 024. The specification
    /// bounds none of them; an evidence arrives from whoever produced it, and a self-description costs a reader
    /// memory while buying it nothing until the evidence around it verifies.
    /// </summary>
    public static int MaximumValueLength { get; } = 1024;

    /// <summary>The largest number of octets a whole encoded attribute value is read from, 4 096.</summary>
    public static int MaximumEncodedValueByteLength { get; } = 4096;

    /// <summary>
    /// The largest character the <c>IA5String</c> type Annex I gives every one of these attributes admits — the
    /// last of the seven-bit repertoire that string type is defined over.
    /// </summary>
    public static char LargestIa5Character { get; } = (char)127;


    /// <summary>
    /// Writes one attribute of Annex H.
    /// </summary>
    /// <param name="kind">Which of the three attributes to write.</param>
    /// <param name="value">The uniform resource identifier the attribute carries.</param>
    /// <param name="pool">The memory pool the attribute is rented from.</param>
    /// <returns>The attribute. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the value is absent or empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="kind"/> is not one of the three.</exception>
    /// <exception cref="InvalidOperationException">
    /// When the value is longer than <see cref="MaximumValueLength"/> — a value this library would refuse to read
    /// back — or carries a character the <c>IA5String</c> type does not admit.
    /// </exception>
    public static CmsAttribute Create(PreservationEvidenceAttributeKind kind, string value, BaseMemoryPool pool)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        ArgumentNullException.ThrowIfNull(pool);

        string attributeType = PreservationEvidenceAttributeWellKnown.AttributeTypeOf(kind);
        if(value.Length > MaximumValueLength)
        {
            throw new InvalidOperationException(
                $"The value is longer than the {MaximumValueLength} characters an Annex H attribute is read with.");
        }

        for(int i = 0; i < value.Length; ++i)
        {
            if(value[i] > LargestIa5Character)
            {
                throw new InvalidOperationException(
                    "Annex I types every attribute for preservation evidences as an IA5String, which admits no character above the seven-bit repertoire.");
            }
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.IA5String, value);

        //The encoded value is copied into the attribute the factory builds, so this rental is a scratch buffer of
        //this call rather than something the returned attribute goes on to own.
        int encodedLength = writer.GetEncodedLength();
        using IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        _ = writer.TryEncode(owner.Memory.Span, out int written);

        return CmsAttribute.Create(attributeType, owner.Memory.Span[..written], pool);
    }


    /// <summary>
    /// Writes the attributes of Annex H that a self-description states — the standardised spelling of the same
    /// three identifiers.
    /// </summary>
    /// <param name="selfDescription">The self-description to state as attributes.</param>
    /// <param name="pool">The memory pool the attributes are rented from.</param>
    /// <returns>One attribute per identifier the self-description states, in the order the annex numbers them. The caller owns and disposes them.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">When the self-description states nothing, or a value is one <see cref="Create"/> refuses.</exception>
    /// <remarks>
    /// A self-description stating nothing produces no attributes, which is a value that says nothing — refused
    /// here for the same reason <see cref="EArkEvidenceSelfDescription.EncodeValue"/> refuses to encode one.
    /// </remarks>
    public static IReadOnlyList<CmsAttribute> ToAttributes(EArkEvidenceSelfDescription selfDescription, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(selfDescription);
        ArgumentNullException.ThrowIfNull(pool);

        if(!selfDescription.IsStated)
        {
            throw new InvalidOperationException(
                "A self-description states at least one of the preservation service, the evidence policy and the preservation profile (ETSI TS 119 511 V1.2.1 OVR-6.5-09).");
        }

        var attributes = new List<CmsAttribute>(3);
        try
        {
            Add(attributes, PreservationEvidenceAttributeKind.PreservationServiceIdentifier, selfDescription.PreservationServiceIdentifier, pool);
            Add(attributes, PreservationEvidenceAttributeKind.PreservationEvidencePolicy, selfDescription.EvidencePolicyIdentifier, pool);
            Add(attributes, PreservationEvidenceAttributeKind.PreservationProfile, selfDescription.PreservationProfileIdentifier, pool);

            return attributes;
        }
        catch
        {
            for(int i = 0; i < attributes.Count; ++i)
            {
                attributes[i].Dispose();
            }

            throw;
        }

        //One attribute per stated identifier, so an identifier the self-description leaves unstated produces no
        //attribute at all rather than one carrying an empty value.
        static void Add(List<CmsAttribute> attributes, PreservationEvidenceAttributeKind kind, string? value, BaseMemoryPool pool)
        {
            if(value is not null)
            {
                attributes.Add(Create(kind, value, pool));
            }
        }
    }


    /// <summary>
    /// Reads the value of one encoded <c>AttributeValue</c>.
    /// </summary>
    /// <param name="encodedValue">The whole DER encoding of one <c>AttributeValue</c>.</param>
    /// <param name="value">The value read, or <see langword="null"/> when the octets are not one.</param>
    /// <returns><see langword="true"/> when the octets are exactly one <c>IA5String</c> within this library's bound.</returns>
    /// <remarks>
    /// Malformed input, trailing octets, another string type and a value over the bound all answer
    /// <see langword="false"/>: an evidence arrives from whoever produced it, so every way a value can be wrong
    /// is a status rather than an exception.
    /// </remarks>
    public static bool TryDecodeValue(ReadOnlyMemory<byte> encodedValue, [NotNullWhen(true)] out string? value)
    {
        value = null;
        if(encodedValue.IsEmpty || encodedValue.Length > MaximumEncodedValueByteLength)
        {
            return false;
        }

        try
        {
            var reader = new AsnReader(encodedValue, AsnEncodingRules.DER);
            string read = reader.ReadCharacterString(UniversalTagNumber.IA5String);
            if(reader.HasData || read.Length == 0 || read.Length > MaximumValueLength)
            {
                return false;
            }

            value = read;

            return true;
        }
        catch(AsnContentException)
        {
            return false;
        }
    }


    /// <summary>
    /// Reads one attribute of Annex H out of the whole encodings of a set of CMS attributes — the shape an
    /// <c>ArchiveTimeStamp</c>'s <c>attributes</c> field surfaces on
    /// <see cref="EvidenceRecordArchiveTimeStamp.Attributes"/>.
    /// </summary>
    /// <param name="encodedAttributes">The whole encodings of the attributes, each a complete <c>Attribute</c> SEQUENCE.</param>
    /// <param name="kind">Which of the three attributes to read.</param>
    /// <param name="value">The value read, or <see langword="null"/> when the set carries none.</param>
    /// <returns><see langword="true"/> when exactly one attribute of that type carried exactly one readable value.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="encodedAttributes"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="kind"/> is not one of the three.</exception>
    /// <remarks>
    /// An attribute of the requested type carrying more than one value answers <see langword="false"/>: clauses
    /// H.2.2, H.3.2 and H.4.2 each state that the attribute "shall contain exactly one component of
    /// <c>AttributeValue</c> type", so a producer that placed several has stated something this library does not
    /// read as one value.
    /// </remarks>
    public static bool TryReadFromAttributes(
        IReadOnlyList<ReadOnlyMemory<byte>> encodedAttributes,
        PreservationEvidenceAttributeKind kind,
        [NotNullWhen(true)] out string? value)
    {
        ArgumentNullException.ThrowIfNull(encodedAttributes);

        string attributeType = PreservationEvidenceAttributeWellKnown.AttributeTypeOf(kind);
        value = null;
        for(int i = 0; i < encodedAttributes.Count; ++i)
        {
            if(!TryReadSingleAttributeValue(encodedAttributes[i], attributeType, out ReadOnlyMemory<byte> attributeValue))
            {
                continue;
            }

            return TryDecodeValue(attributeValue, out value);
        }

        return false;
    }


    /// <summary>
    /// Reads one attribute of Annex H out of an Evidence Record's archive time-stamps.
    /// </summary>
    /// <param name="evidenceRecord">The Evidence Record.</param>
    /// <param name="kind">Which of the three attributes to read.</param>
    /// <param name="value">The value read, or <see langword="null"/> when the record carries none.</param>
    /// <returns><see langword="true"/> when an archive time-stamp of the record carries it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="evidenceRecord"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="kind"/> is not one of the three.</exception>
    /// <remarks>
    /// The chains are walked newest first, because a renewal states what was in force when it ran; an earlier
    /// chain's answer is still there and is still covered by every later renewal, since clause 5.2's Hash-Tree
    /// Renewal hashes the whole encoded <c>ArchiveTimeStampSequence</c>.
    /// </remarks>
    public static bool TryReadFromEvidenceRecord(
        EvidenceRecord evidenceRecord,
        PreservationEvidenceAttributeKind kind,
        [NotNullWhen(true)] out string? value)
    {
        ArgumentNullException.ThrowIfNull(evidenceRecord);

        value = null;
        IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains = evidenceRecord.ArchiveTimeStampSequence.Chains;
        for(int chainIndex = chains.Count - 1; chainIndex >= 0; --chainIndex)
        {
            IReadOnlyList<EvidenceRecordArchiveTimeStamp> archiveTimeStamps = chains[chainIndex].ArchiveTimeStamps;
            for(int stampIndex = archiveTimeStamps.Count - 1; stampIndex >= 0; --stampIndex)
            {
                if(TryReadFromAttributes(archiveTimeStamps[stampIndex].Attributes, kind, out value))
                {
                    return true;
                }
            }
        }

        return false;
    }


    /// <summary>
    /// Reads one attribute of Annex H out of a Signed Data Object's unsigned attributes.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <param name="kind">Which of the three attributes to read.</param>
    /// <param name="value">The value read, or <see langword="null"/> when the signer carries none.</param>
    /// <returns><see langword="true"/> when the signer carries it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative, or <paramref name="kind"/> is not one of the three.</exception>
    public static bool TryReadFromSignedData(
        CmsSignedData signedData,
        int signerIndex,
        PreservationEvidenceAttributeKind kind,
        [NotNullWhen(true)] out string? value)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        string attributeType = PreservationEvidenceAttributeWellKnown.AttributeTypeOf(kind);
        value = null;
        IReadOnlyList<CmsUnsignedAttributeValueLocation> locations =
            CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex);

        for(int i = 0; i < locations.Count; ++i)
        {
            if(!string.Equals(locations[i].AttributeType, attributeType, StringComparison.Ordinal))
            {
                continue;
            }

            ReadOnlyMemory<byte> attributeValue = CmsSignedDataAugmentation.ReadUnsignedAttributeValue(
                signedData, signerIndex, locations[i].AttributeIndex, locations[i].ValueIndex);

            return TryDecodeValue(attributeValue, out value);
        }

        return false;
    }


    /// <summary>
    /// Reads whatever the three attributes of Annex H say about an Evidence Record, as the self-description
    /// record this wave's placement rules read.
    /// </summary>
    /// <param name="evidenceRecord">The Evidence Record.</param>
    /// <returns>The self-description, or <see langword="null"/> when the record carries none of the three attributes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="evidenceRecord"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// This is the bridge between the standardised spelling and the house one: an evidence carrying Annex H's
    /// attributes answers <c>OVR-6.5-09</c> exactly as one carrying the house value does, and a rule that reads
    /// the self-description should not have to know which spelling it met.
    /// </remarks>
    public static EArkEvidenceSelfDescription? ReadSelfDescription(EvidenceRecord evidenceRecord)
    {
        ArgumentNullException.ThrowIfNull(evidenceRecord);

        _ = TryReadFromEvidenceRecord(evidenceRecord, PreservationEvidenceAttributeKind.PreservationServiceIdentifier, out string? service);
        _ = TryReadFromEvidenceRecord(evidenceRecord, PreservationEvidenceAttributeKind.PreservationEvidencePolicy, out string? policy);
        _ = TryReadFromEvidenceRecord(evidenceRecord, PreservationEvidenceAttributeKind.PreservationProfile, out string? profile);

        return StateSelfDescription(service, policy, profile);
    }


    /// <summary>
    /// Reads whatever the three attributes of Annex H say about a Signed Data Object's signer, as the
    /// self-description record this wave's placement rules read.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <returns>The self-description, or <see langword="null"/> when the signer carries none of the three attributes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    public static EArkEvidenceSelfDescription? ReadSelfDescription(CmsSignedData signedData, int signerIndex)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        _ = TryReadFromSignedData(signedData, signerIndex, PreservationEvidenceAttributeKind.PreservationServiceIdentifier, out string? service);
        _ = TryReadFromSignedData(signedData, signerIndex, PreservationEvidenceAttributeKind.PreservationEvidencePolicy, out string? policy);
        _ = TryReadFromSignedData(signedData, signerIndex, PreservationEvidenceAttributeKind.PreservationProfile, out string? profile);

        return StateSelfDescription(service, policy, profile);
    }


    /// <summary>
    /// Builds the self-description three read values state, or nothing when they state nothing.
    /// </summary>
    /// <param name="service">The preservation service identifier read, or <see langword="null"/>.</param>
    /// <param name="policy">The preservation evidence policy identifier read, or <see langword="null"/>.</param>
    /// <param name="profile">The preservation profile identifier read, or <see langword="null"/>.</param>
    /// <returns>The self-description, or <see langword="null"/>.</returns>
    private static EArkEvidenceSelfDescription? StateSelfDescription(string? service, string? policy, string? profile)
    {
        if(service is null && policy is null && profile is null)
        {
            return null;
        }

        return new EArkEvidenceSelfDescription
        {
            PreservationServiceIdentifier = service,
            EvidencePolicyIdentifier = policy,
            PreservationProfileIdentifier = profile
        };
    }


    /// <summary>
    /// Reads the single <c>AttributeValue</c> of a whole <c>Attribute</c> encoding whose <c>attrType</c> is the
    /// one asked for.
    /// </summary>
    /// <param name="encodedAttribute">The whole encoding of one <c>Attribute</c>.</param>
    /// <param name="attributeType">The attribute type wanted.</param>
    /// <param name="attributeValue">The single value's whole encoding, or empty when the attribute is another one.</param>
    /// <returns><see langword="true"/> when the attribute is the one asked for and carries exactly one value.</returns>
    private static bool TryReadSingleAttributeValue(
        ReadOnlyMemory<byte> encodedAttribute,
        string attributeType,
        out ReadOnlyMemory<byte> attributeValue)
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
            if(!string.Equals(attribute.ReadObjectIdentifier(), attributeType, StringComparison.Ordinal))
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
}

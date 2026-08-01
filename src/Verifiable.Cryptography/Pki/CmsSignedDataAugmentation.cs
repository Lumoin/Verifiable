using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Adds material to an existing CMS <c>SignedData</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see>) without re-encoding
/// any component that is already there — unsigned attributes, certificates, revocation information, and the
/// replacement of one attribute value — plus the structural reads those operations and their callers address
/// material by. This is the augmentation primitive every level-raising step of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.5.3</see> is built on.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why appending, and not re-encoding, is the whole design.</strong> Clause 5.5.3 states it
/// normatively: "The augmentation shall preserve the binary encoding of already present unsigned attributes
/// and any component contributing to the archive time-stamp's message imprint computation input", and NOTE 7
/// gives the consequence — an encoding change to any element an <c>ats-hash-index-v3</c> protects (a BER to
/// DER re-encoding is the example the specification names) makes that archive time-stamp fail to validate,
/// because the verifier's recomputed hash is no longer among the hashes the index holds. A signature that
/// has been archive-time-stamped is therefore not a structure to decode and re-emit; it is a byte sequence to
/// splice. This operation copies every octet of the input through to the output except the length octets of
/// the containers that must grow to hold the new attributes, and appends new material that is itself DER, as
/// clause 5.5.3 requires of anything an augmentation adds.
/// </para>
/// <para>
/// <strong>The containers that grow.</strong> Adding octets inside a <c>SignerInfo</c>'s <c>unsignedAttrs</c>
/// lengthens exactly the chain that encloses it: <c>ContentInfo</c>, its <c>[0] EXPLICIT</c> content, the
/// <c>SignedData</c> sequence, the <c>signerInfos</c> set, the chosen <c>SignerInfo</c>, and, when it is
/// already there, the <c>unsignedAttrs</c> set itself. Every other octet — the encapsulated content, the
/// certificates, the CRLs, the sibling <c>SignerInfo</c> structures, the signed attributes, the signature
/// value, and each unsigned attribute already present — is copied verbatim. None of the rewritten length
/// octets is covered by an <c>archive-time-stamp-v3</c>: clause 5.5.3's message imprint concatenates the
/// <c>SignerInfo</c> <em>fields</em>, never the enclosing headers, and clause 5.5.2's hash index covers
/// whole certificates, whole revocation entries, and attribute type and value octets, never the set headers
/// that enclose them. That is what makes appending safe by construction.
/// </para>
/// <para>
/// <strong>Indefinite-length wrappers are preserved.</strong> A CMS structure met in the wild may carry BER
/// indefinite-length outer wrappers. An indefinite-length container has no length octets to grow — its
/// end-of-contents octets already terminate whatever it holds — so such a container is passed through
/// untouched and the growth flows outward to the next definite-length container. Preserving those wrappers
/// is preservation in exactly clause 5.5.3's sense; rewriting them into definite-length DER would be the
/// re-encoding NOTE 7 warns about.
/// </para>
/// <para>
/// <strong>This preservation is knowingly narrower than the syntax it accepts.</strong> BER indefinite-length
/// wrappers are read and passed through so a Signed Data Object minted elsewhere — one a third-party verifier
/// may still need to check byte-for-byte — is never rejected or silently normalised on its way through an
/// augmentation. This library's own <c>ats-hash-index-v3</c> index and message imprint computation
/// (<see cref="ArchiveTimestampV3.ComputeHashIndexAsync"/>,
/// <see cref="ArchiveTimestampV3.BuildMessageImprintInputAsync"/>, clause 4.7.2) requires a DER-encoded Signed
/// Data Object and reports <see cref="CAdESAugmentationFailureKind.SignedDataMalformed"/> for an
/// indefinite-length BER input rather than normalising it — normalising would itself be the re-encoding NOTE 7
/// warns against. An archive time-stamp CAdES-A signature built with legal indefinite-length BER framing is
/// therefore not self-validatable by this library's own ATSv3 coverage computation, though it remains a
/// conformant ETSI EN 319 122-1 signature a differently-scoped verifier could still check; this documented gap
/// is recorded as a requirements-matrix row rather than closed by widening the verify chain to BER, which is a
/// separate arc if ever wanted.
/// </para>
/// <para>
/// <strong>Ordering of the unsigned attributes.</strong> New attributes are appended after the ones already
/// present. The set is not re-sorted, because reordering would change the encoding of a component the
/// preservation rule protects; the standard's own readers accept an unsigned-attribute set in the order it
/// arrives, and clause 5.5.2's hash index is a membership test over each attribute type and value, so order
/// carries no meaning there either. When the <c>SignerInfo</c> has no <c>unsignedAttrs</c> yet, the set is
/// created as one DER <c>[1] IMPLICIT SET OF</c>, sorted as DER requires.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> The Signed Data Object arrives from a network location or a
/// document. Every structure is read through <see cref="AsnDecoder"/> under
/// <see cref="AsnEncodingRules.BER"/> with an explicit end bound, the walk is straight-line with no
/// recursion, octets after the outer <c>ContentInfo</c> are rejected rather than ignored, and the number of
/// <c>SignerInfo</c> structures traversed and attributes appended is bounded. A structure that cannot be
/// walked yields a typed failure and no output at all, never a partially spliced buffer.
/// </para>
/// <para>
/// An RFC 3161 time-stamp token is itself a CMS <c>SignedData</c>, so grafting an attribute into a token a
/// time-stamping authority returned is this same operation over the token's octets.
/// </para>
/// </remarks>
public static class CmsSignedDataAugmentation
{
    /// <summary>The id-signedData content type (RFC 5652 §5.1).</summary>
    private const string SignedDataOid = "1.2.840.113549.1.7.2";

    /// <summary>The <c>message-digest</c> attribute type (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-11.2">RFC 5652 §11.2</see>), read for the parallel-signer content cross-check.</summary>
    private const string MessageDigestAttributeOid = "1.2.840.113549.1.9.4";

    /// <summary>
    /// The largest number of <c>SignerInfo</c> structures traversed while looking for the chosen signer. The
    /// set is unbounded in the syntax, so the traversal an attacker can provoke is bounded here.
    /// </summary>
    private const int MaximumSignerInfos = 64;

    /// <summary>The largest number of attributes one call appends, bounding the work a single augmentation costs.</summary>
    private const int MaximumAppendedAttributes = 64;

    /// <summary>
    /// The longest enclosing chain: ContentInfo, [0] content, SignedData, signerInfos, SignerInfo,
    /// unsignedAttrs, Attribute, attrValues — the chain that encloses one <c>AttributeValue</c>, which is the
    /// deepest region any operation here addresses.
    /// </summary>
    private const int MaximumChainLength = 8;

    /// <summary>The largest number of unsigned attributes walked, matching the bound the CAdES facts binding surfaces attributes within.</summary>
    private const int MaximumUnsignedAttributes = 64;

    /// <summary>The largest number of unsigned attribute values walked across all attributes of one signer.</summary>
    private const int MaximumUnsignedAttributeValues = 256;

    /// <summary>The largest number of members walked in a <c>certificates</c> or <c>crls</c> set, matching the bound the CAdES facts binding reads them within.</summary>
    private const int MaximumEmbeddedObjects = 256;

    /// <summary>The BER indefinite-length octet (X.690 clause 8.1.3.6), which stands in place of a length.</summary>
    private const byte IndefiniteLengthOctet = 0x80;

    /// <summary>The long-form length flag of the leading length octet (X.690 clause 8.1.3.5).</summary>
    private const byte LongFormLengthFlag = 0x80;

    /// <summary>The universal <c>OCTET STRING</c> tag number, the tag of <c>SignerInfo.signature</c> (RFC 5652 §5.3).</summary>
    private const int OctetStringTagNumber = 4;

    /// <summary>
    /// The <c>CMSVersion</c> a <c>SignedData</c> shall carry once its <c>certificates</c> set holds an
    /// <c>OtherCertificateFormat</c> member or its <c>crls</c> set holds an <c>OtherRevocationInfoFormat</c>
    /// member (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see>).
    /// </summary>
    private const byte OtherFormatSignedDataVersion = 5;

    /// <summary>The <c>[0]</c> constructed context tag: <c>ContentInfo.content</c>, <c>SignedData.certificates</c>, and <c>SignerInfo.signedAttrs</c>.</summary>
    private static Asn1Tag ContextConstructed0 { get; } = new(TagClass.ContextSpecific, 0, isConstructed: true);

    /// <summary>The <c>[1]</c> constructed context tag: <c>SignedData.crls</c>, <c>SignerInfo.unsignedAttrs</c>, and the <c>other</c> alternative <c>OtherRevocationInfoFormat</c> of a <c>crls</c> member (RFC 5652 §10.2.1).</summary>
    private static Asn1Tag ContextConstructed1 { get; } = new(TagClass.ContextSpecific, 1, isConstructed: true);

    /// <summary>
    /// The <c>[3]</c> constructed context tag of <c>CertificateChoices.other</c>, an
    /// <c>OtherCertificateFormat</c> (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-10.2.2">RFC 5652
    /// §10.2.2</see>) — the alternative whose presence in <c>SignedData.certificates</c> raises the version.
    /// </summary>
    private static Asn1Tag OtherCertificateFormatTag { get; } = new(TagClass.ContextSpecific, 3, isConstructed: true);


    /// <summary>
    /// Appends unsigned attributes to one <c>SignerInfo</c> of a CMS <c>SignedData</c>, preserving every
    /// other octet of the input exactly.
    /// </summary>
    /// <param name="signedData">The Signed Data Object to augment. Not modified; the result is a new carrier.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> within <c>SignedData.signerInfos</c>.</param>
    /// <param name="attributes">The attributes to append, each a complete DER-encoded <c>Attribute</c>.</param>
    /// <param name="pool">The memory pool the result and the intermediate encoding are rented from.</param>
    /// <returns>The augmented Signed Data Object. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/>, <paramref name="attributes"/>, one of its entries, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="ArgumentException">When no attribute is supplied or more than the supported count is.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData this operation can preserve, or it holds no <c>SignerInfo</c> at <paramref name="signerIndex"/>.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, or carries octets after the outer ContentInfo.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    public static CmsSignedData AppendUnsignedAttributes(
        CmsSignedData signedData,
        int signerIndex,
        IReadOnlyList<CmsAttribute> attributes,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(attributes);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);
        if(attributes.Count == 0)
        {
            throw new ArgumentException("An augmentation appends at least one unsigned attribute.", nameof(attributes));
        }

        if(attributes.Count > MaximumAppendedAttributes)
        {
            throw new ArgumentException($"An augmentation appends at most {MaximumAppendedAttributes} unsigned attributes in one call.", nameof(attributes));
        }

        for(int i = 0; i < attributes.Count; ++i)
        {
            ArgumentNullException.ThrowIfNull(attributes[i], nameof(attributes));
        }

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SpliceTarget target = LocateTarget(source, signerIndex);

        using PooledMemory newMaterial = target.HasUnsignedAttributes
            ? ConcatenateAttributes(attributes, pool)
            : EncodeUnsignedAttributesSet(attributes, pool);

        return Splice(source, target.Chain, target.ChainLength, target.InsertionOffset, target.InsertionOffset, newMaterial.AsReadOnlySpan(), pool);
    }


    /// <summary>
    /// Produces a Signed Data Object in which one region of the input has been replaced by new octets and every
    /// other octet is the input's own, with only the length octets of the enclosing containers recomputed.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="chain">The containers enclosing the replaced region, outermost first.</param>
    /// <param name="chainLength">The number of meaningful entries in <paramref name="chain"/>.</param>
    /// <param name="replacedStart">The offset of the first replaced octet; equal to <paramref name="replacedEnd"/> for a pure insertion.</param>
    /// <param name="replacedEnd">The offset one past the last replaced octet.</param>
    /// <param name="newMaterial">The octets the replaced region becomes.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <param name="versionValueOffset">
    /// The source offset of the single <c>SignedData.version</c> content octet to raise to
    /// <see cref="OtherFormatSignedDataVersion"/>, or <c>-1</c> for no version change. RFC 5652 §5.1 mandates
    /// version 5 once the splice places an other-format certificate or revocation member; the substitution is
    /// one octet and length-preserving, so it neither moves any imprint-contributing component (clause 5.5.3's
    /// message imprint concatenates the <c>SignerInfo</c> fields, never the <c>SignedData</c> prefix that holds
    /// the version) nor alters any of clause 5.5.2's three hash indexes (which cover whole certificates, whole
    /// revocation entries, and attribute values, never the version field).
    /// </param>
    /// <returns>The spliced Signed Data Object. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static CmsSignedData Splice(
        ReadOnlySpan<byte> source,
        CmsElement[] chain,
        int chainLength,
        int replacedStart,
        int replacedEnd,
        ReadOnlySpan<byte> newMaterial,
        MemoryPool<byte> pool,
        int versionValueOffset = -1)
    {
        //The chain lengths are recomputed from the innermost container outwards, because a container's own
        //header may itself grow once its content has, and that growth is what its parent has to absorb.
        Span<int> newHeaderLengths = stackalloc int[MaximumChainLength];
        Span<int> newContentLengths = stackalloc int[MaximumChainLength];
        int growth = newMaterial.Length - (replacedEnd - replacedStart);
        for(int i = chainLength - 1; i >= 0; --i)
        {
            CmsElement element = chain[i];
            if(element.IsIndefinite)
            {
                //An indefinite-length container states no length to grow: its end-of-contents octets already
                //close whatever it holds, so its header is preserved and the growth passes through unchanged.
                newHeaderLengths[i] = element.HeaderLength;
                newContentLengths[i] = element.ContentLength;

                continue;
            }

            int newContentLength = element.ContentLength + growth;
            int lengthOctetCount = ChooseLengthOctetCount(newContentLength, element.HeaderLength - element.TagLength);
            newHeaderLengths[i] = element.TagLength + lengthOctetCount;
            newContentLengths[i] = newContentLength;
            growth += newHeaderLengths[i] - element.HeaderLength;
        }

        int outputLength = source.Length + growth;
        IMemoryOwner<byte> owner = pool.Rent(outputLength);
        try
        {
            Span<byte> output = owner.Memory.Span[..outputLength];
            int written = 0;
            int read = 0;
            for(int i = 0; i < chainLength; ++i)
            {
                CmsElement element = chain[i];

                //Whatever precedes this container inside its parent — the content type object identifier, the
                //SignedData fields before signerInfos, the SignerInfo structures before the chosen one — is
                //copied octet for octet.
                source[read..element.Start].CopyTo(output[written..]);
                written += element.Start - read;

                source.Slice(element.Start, element.TagLength).CopyTo(output[written..]);
                written += element.TagLength;
                written += WriteLength(output[written..], newContentLengths[i], newHeaderLengths[i] - element.TagLength, element.IsIndefinite);
                read = element.ContentStart;
            }

            source[read..replacedStart].CopyTo(output[written..]);
            written += replacedStart - read;
            newMaterial.CopyTo(output[written..]);
            written += newMaterial.Length;

            //Everything from the replaced region onwards — the sibling SignerInfo structures, every
            //end-of-contents pair of an indefinite-length wrapper — is unchanged by construction.
            source[replacedEnd..].CopyTo(output[written..]);
            written += source.Length - replacedEnd;

            if(versionValueOffset >= 0)
            {
                //The SignedData.version octet was copied verbatim above, before the insertion point; it sits at
                //its source offset shifted only by the header growth of the containers that enclose it, which the
                //length recomputation already sized. Overwriting that one octet (RFC 5652 §5.1: version 5 once an
                //other-format member is present) preserves every length octet, so no archive time-stamp is
                //disturbed — see the parameter's own remark.
                int shift = 0;
                for(int i = 0; i < chainLength; ++i)
                {
                    if(chain[i].ContentStart <= versionValueOffset && versionValueOffset < chain[i].ContentEnd)
                    {
                        shift += newHeaderLengths[i] - chain[i].HeaderLength;
                    }
                }

                output[versionValueOffset + shift] = OtherFormatSignedDataVersion;
            }

            Debug.Assert(written == outputLength, "The spliced output fills exactly the length the chain recomputation predicted.");

            return new CmsSignedData(owner, CryptoTags.CmsEncodedSignedData);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Counts the <c>SignerInfo</c> structures a Signed Data Object carries, so a caller that has to inspect
    /// every signer — as the placement rules of ETSI EN 319 122-1 clause 5.5.3 require of a signature being
    /// augmented — knows how many there are.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <returns>The number of <c>SignerInfo</c> structures, at most the bound this class traverses within.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, or carries trailing octets.</exception>
    public static int CountSigners(CmsSignedData signedData)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SignedDataLayout layout = LocateSignedDataLayout(source);

        return ReadSetMembers(source, layout.SignerInfos, MaximumSignerInfos, "signerInfos").Count;
    }


    /// <summary>
    /// Returns the content octets of one <c>SignerInfo</c>'s <c>signature</c> field — the value octets alone,
    /// without the tag and length — which is what the message imprint of a <c>signature-time-stamp</c> is
    /// computed over: ETSI EN 319 122-1 clause 5.3 states the imprint is the hash of "the signature field
    /// within SignerInfo ... without the ASN.1 tag and length".
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <returns>A view of the signature value octets within <paramref name="signedData"/>'s own memory, valid while it is.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a <c>SignerInfo</c> at that index.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, or carries trailing octets.</exception>
    /// <remarks>
    /// This convention — the raw value, no tag and no length — is the one clause 5.2.8 also states for
    /// <c>content-time-stamp</c>, and it is deliberately <em>not</em> the convention of clause 5.5.3, whose
    /// archive time-stamp imprint concatenates whole encodings, tag and length octets included. The two are
    /// never computed by one shared helper.
    /// </remarks>
    public static ReadOnlyMemory<byte> ReadSignatureValue(CmsSignedData signedData, int signerIndex)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        SpliceTarget target = LocateTarget(signedData.AsReadOnlySpan(), signerIndex);

        return signedData.AsReadOnlyMemory()[target.SignatureValue.ContentStart..target.SignatureValue.ContentEnd];
    }


    /// <summary>
    /// Returns the whole encoding of the single <c>AttributeValue</c> a signed attribute of the given type
    /// carries — the read half of a signed attribute this file never splices, since <c>signedAttrs</c> is
    /// covered by the signature and immutable once produced.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <param name="attributeType">The attribute's <c>attrType</c> object identifier.</param>
    /// <returns>A view of the value's octets within <paramref name="signedData"/>'s own memory, or <see langword="null"/> when the signer carries no <c>signedAttrs</c> field or no attribute of that type.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a SignerInfo at that index, or the attribute carries more than one <c>AttributeValue</c> (every signed attribute this binding reads has exactly one, RFC 5652 §5.3).</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries trailing octets, or exceeds the bounds this walk stays within.</exception>
    public static ReadOnlyMemory<byte>? ReadSignedAttributeValue(CmsSignedData signedData, int signerIndex, string attributeType)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentException.ThrowIfNullOrEmpty(attributeType);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SignedDataLayout layout = LocateSignedDataLayout(source);
        CmsElement signerInfo = LocateSignerInfo(source, layout.SignerInfos, signerIndex);
        _ = LocateUnsignedAttributes(source, signerInfo, out _, out _, out CmsElement signedAttributes, out bool hasSignedAttributes);
        if(!hasSignedAttributes)
        {
            return null;
        }

        List<UnsignedAttributeValueSite> sites = WalkUnsignedAttributeValues(source, signedAttributes);
        UnsignedAttributeValueSite? match = null;
        for(int i = 0; i < sites.Count; ++i)
        {
            if(string.Equals(sites[i].AttributeType, attributeType, StringComparison.Ordinal))
            {
                if(match is not null)
                {
                    throw new CryptographicException(
                        $"The CMS SignerInfo carries more than one AttributeValue for signed attribute '{attributeType}' (RFC 5652 §5.3).");
                }

                match = sites[i];
            }
        }

        //Deliberately not a `match is { } site ? signedData.AsReadOnlyMemory()[...] : null` conditional
        //expression: the compiler would resolve the expression's type from the non-nullable ReadOnlyMemory<byte>
        //true branch and convert the null false branch to THAT type's default (an empty ReadOnlyMemory<byte>,
        //not an absent one) before converting the whole expression to the declared nullable return type — so
        //"no attribute of this type" would silently become "a present, zero-length value" (the exact trap
        //TimestampAcquisition.cs's ReadTimeStampResp documents and was caught by a test for).
        if(match is not { } site)
        {
            return null;
        }

        return signedData.AsReadOnlyMemory()[site.Value.Start..site.Value.End];
    }


    /// <summary>
    /// Returns the whole encoding of every <c>AttributeValue</c> of every signed attribute one <c>SignerInfo</c>
    /// carries, in encoding order — the read that answers whether one object's octets are among the signed
    /// attribute values <c>signedAttrs</c> binds as a single whole.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <returns>Views of the values' octets within <paramref name="signedData"/>'s own memory, valid while it is, or an empty list when the signer carries no <c>signedAttrs</c> field.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a <c>SignerInfo</c> at that index.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries trailing octets, or exceeds the bounds this walk stays within.</exception>
    /// <remarks>
    /// <c>signedAttrs</c> is covered by the signature and never spliced by this file, so this is a read alone.
    /// It isolates the same <c>signedAttrs</c> element <see cref="ReadSignedAttributeValue"/> does and enumerates
    /// it through the one <c>WalkUnsignedAttributeValues</c> walker, so no second CMS descent is introduced. It
    /// carries the per-value granularity of <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC
    /// 5652 §5.3</see> because a signed attribute may hold several values — a <c>content-time-stamp</c> (ETSI
    /// EN 319 122-1 clause 5.2.8) carries one <c>AttributeValue</c> per token — and any one of them is covered by
    /// step 3) of clause 5.5.3's archive-time-stamp-v3 imprint, which concatenates the whole <c>signedAttrs</c>
    /// TLV verbatim.
    /// </remarks>
    public static IReadOnlyList<ReadOnlyMemory<byte>> ReadSignedAttributeValues(CmsSignedData signedData, int signerIndex)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SignedDataLayout layout = LocateSignedDataLayout(source);
        CmsElement signerInfo = LocateSignerInfo(source, layout.SignerInfos, signerIndex);
        _ = LocateUnsignedAttributes(source, signerInfo, out _, out _, out CmsElement signedAttributes, out bool hasSignedAttributes);
        if(!hasSignedAttributes)
        {
            return [];
        }

        List<UnsignedAttributeValueSite> sites = WalkUnsignedAttributeValues(source, signedAttributes);
        ReadOnlyMemory<byte> whole = signedData.AsReadOnlyMemory();
        var values = new List<ReadOnlyMemory<byte>>(sites.Count);
        for(int i = 0; i < sites.Count; ++i)
        {
            values.Add(whole[sites[i].Value.Start..sites[i].Value.End]);
        }

        return values;
    }


    /// <summary>
    /// Reads what each signer of a Signed Data Object commits to: its <c>digestAlgorithm</c>'s algorithm
    /// object identifier and, when its <c>signedAttrs</c> carries the <c>message-digest</c> attribute
    /// (RFC 5652 §11.2), that attribute's digest octets — the per-signer content commitment a joining
    /// parallel signer's own digest is held against
    /// (<see cref="CAdESSignatureCreation.PrepareParallelSignatureAsync"/>).
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <returns>One commitment per <c>SignerInfo</c>, in encoding order; a signer with no <c>signedAttrs</c>, no <c>message-digest</c> attribute, or a value that is not one primitive OCTET STRING states none.</returns>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData, or a <c>SignerInfo</c> is not of the syntax's shape down to its <c>digestAlgorithm</c>.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries trailing octets, or exceeds the bounds this walk stays within.</exception>
    internal static List<SignerContentCommitment> ReadSignerContentCommitments(CmsSignedData signedData)
    {
        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SignedDataLayout layout = LocateSignedDataLayout(source);
        List<CmsElement> members = ReadSetMembers(source, layout.SignerInfos, MaximumSignerInfos, "signerInfos");
        ReadOnlyMemory<byte> whole = signedData.AsReadOnlyMemory();
        var commitments = new List<SignerContentCommitment>(members.Count);
        for(int i = 0; i < members.Count; ++i)
        {
            CmsElement member = members[i];
            if(member.Tag != Asn1Tag.Sequence)
            {
                throw new CryptographicException("A CMS signerInfos set holds SignerInfo SEQUENCE structures (RFC 5652 §5.1).");
            }

            CmsElement version = ReadElement(source, member.ContentStart, member.ContentEnd);
            CmsElement signerIdentifier = ReadElement(source, version.End, member.ContentEnd);
            CmsElement digestAlgorithm = ReadElement(source, signerIdentifier.End, member.ContentEnd);
            if(digestAlgorithm.Tag != Asn1Tag.Sequence || digestAlgorithm.ContentLength == 0)
            {
                throw new CryptographicException("A CMS SignerInfo carries its digestAlgorithm as an AlgorithmIdentifier SEQUENCE (RFC 5652 §5.3).");
            }

            CmsElement algorithmOidElement = ReadElement(source, digestAlgorithm.ContentStart, digestAlgorithm.ContentEnd);
            if(algorithmOidElement.Tag != Asn1Tag.ObjectIdentifier)
            {
                throw new CryptographicException("An AlgorithmIdentifier opens with its algorithm object identifier (RFC 5652 §10.1.1).");
            }

            string algorithmOid = AsnDecoder.ReadObjectIdentifier(source[algorithmOidElement.Start..algorithmOidElement.End], AsnEncodingRules.BER, out _);
            CmsElement candidate = ReadElement(source, digestAlgorithm.End, member.ContentEnd);
            if(candidate.Tag != ContextConstructed0)
            {
                commitments.Add(new SignerContentCommitment(algorithmOid, ReadOnlyMemory<byte>.Empty, HasMessageDigest: false));

                continue;
            }

            commitments.Add(LocateMessageDigestCommitment(source, whole, candidate, algorithmOid));
        }

        return commitments;


        //Finds the signer's message-digest attribute value among its signed attributes: the commitment is its
        //OCTET STRING content octets, and a value of any other shape states none.
        static SignerContentCommitment LocateMessageDigestCommitment(ReadOnlySpan<byte> source, ReadOnlyMemory<byte> whole, CmsElement signedAttributes, string algorithmOid)
        {
            List<UnsignedAttributeValueSite> sites = WalkUnsignedAttributeValues(source, signedAttributes);
            for(int i = 0; i < sites.Count; ++i)
            {
                if(!string.Equals(sites[i].AttributeType, MessageDigestAttributeOid, StringComparison.Ordinal))
                {
                    continue;
                }

                CmsElement value = sites[i].Value;
                bool isPrimitiveOctetString = value.Tag.TagClass == TagClass.Universal
                    && value.Tag.TagValue == OctetStringTagNumber
                    && !value.Tag.IsConstructed;

                return isPrimitiveOctetString
                    ? new SignerContentCommitment(algorithmOid, whole[value.ContentStart..value.ContentEnd], HasMessageDigest: true)
                    : new SignerContentCommitment(algorithmOid, ReadOnlyMemory<byte>.Empty, HasMessageDigest: false);
            }

            return new SignerContentCommitment(algorithmOid, ReadOnlyMemory<byte>.Empty, HasMessageDigest: false);
        }
    }


    /// <summary>
    /// One signer's content commitment: the digest algorithm its <c>SignerInfo</c> states and, when present,
    /// the <c>message-digest</c> attribute's digest octets (RFC 5652 §11.2).
    /// </summary>
    /// <param name="DigestAlgorithmOid">The signer's <c>digestAlgorithm</c> algorithm object identifier in dotted-decimal form.</param>
    /// <param name="MessageDigest">A view of the <c>message-digest</c> value's content octets within the Signed Data Object's own memory, valid while it is; empty when <paramref name="HasMessageDigest"/> does not hold.</param>
    /// <param name="HasMessageDigest">Whether the signer states a <c>message-digest</c> commitment at all.</param>
    [DebuggerDisplay("SignerContentCommitment({DigestAlgorithmOid}, {HasMessageDigest ? \"committed\" : \"none\",nq})")]
    internal readonly record struct SignerContentCommitment(string DigestAlgorithmOid, ReadOnlyMemory<byte> MessageDigest, bool HasMessageDigest);


    /// <summary>
    /// Enumerates every <c>AttributeValue</c> of every unsigned attribute one <c>SignerInfo</c> carries, in
    /// encoding order, with the attribute type each belongs to.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <returns>The locations, or an empty list when the signer carries no <c>unsignedAttrs</c> field.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a <c>SignerInfo</c> at that index.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries trailing octets, or holds more attributes or values than this walk stays within.</exception>
    /// <remarks>
    /// The enumeration is per value rather than per attribute because that is the granularity the placement
    /// and coverage rules of ETSI EN 319 122-1 work at: clause 5.5.2 indexes one hash per <c>AttributeValue</c>,
    /// and clause 5.5.3's strategy for a signature carrying legacy long-term-availability attributes addresses
    /// one archive time-stamp token, which is one <c>AttributeValue</c> of one attribute.
    /// </remarks>
    public static IReadOnlyList<CmsUnsignedAttributeValueLocation> LocateUnsignedAttributeValues(CmsSignedData signedData, int signerIndex)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SpliceTarget target = LocateTarget(source, signerIndex);
        if(!target.HasUnsignedAttributes)
        {
            return [];
        }

        List<UnsignedAttributeValueSite> sites = WalkUnsignedAttributeValues(source, target.UnsignedAttributes);
        var locations = new List<CmsUnsignedAttributeValueLocation>(sites.Count);
        for(int i = 0; i < sites.Count; ++i)
        {
            locations.Add(new CmsUnsignedAttributeValueLocation(sites[i].AttributeIndex, sites[i].ValueIndex, sites[i].AttributeType));
        }

        return locations;
    }


    /// <summary>
    /// Returns the whole encoding of one <c>AttributeValue</c> of one unsigned attribute — tag, length, and
    /// value octets — as it stands in the Signed Data Object.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <param name="attributeIndex">The zero-based index of the <c>Attribute</c> within <c>unsignedAttrs</c>.</param>
    /// <param name="valueIndex">The zero-based index of the value within that attribute's <c>attrValues</c>.</param>
    /// <returns>A view of the value's octets within <paramref name="signedData"/>'s own memory, valid while it is.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When an index is negative.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding that signer, attribute, and value.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries trailing octets, or exceeds the bounds this walk stays within.</exception>
    public static ReadOnlyMemory<byte> ReadUnsignedAttributeValue(CmsSignedData signedData, int signerIndex, int attributeIndex, int valueIndex)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);
        ArgumentOutOfRangeException.ThrowIfNegative(attributeIndex);
        ArgumentOutOfRangeException.ThrowIfNegative(valueIndex);

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SpliceTarget target = LocateTarget(source, signerIndex);
        UnsignedAttributeValueSite site = SelectSite(source, target, attributeIndex, valueIndex);

        return signedData.AsReadOnlyMemory()[site.Value.Start..site.Value.End];
    }


    /// <summary>
    /// Replaces the octets of one <c>AttributeValue</c> of one unsigned attribute, preserving every other octet
    /// of the input exactly — the operation clause 5.5.3 of ETSI EN 319 122-1 calls for when validation material
    /// has to be provided "within the <c>TimeStampToken</c> of the latest archive time-stamp" rather than in the
    /// root <c>SignedData</c>.
    /// </summary>
    /// <param name="signedData">The Signed Data Object to augment. Not modified; the result is a new carrier.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c>.</param>
    /// <param name="attributeIndex">The zero-based index of the <c>Attribute</c> within <c>unsignedAttrs</c>.</param>
    /// <param name="valueIndex">The zero-based index of the value within that attribute's <c>attrValues</c>.</param>
    /// <param name="replacementValue">The whole encoding of the value the attribute is to carry instead.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The augmented Signed Data Object. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When an index is negative.</exception>
    /// <exception cref="ArgumentException">When <paramref name="replacementValue"/> is not exactly one DER value.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding that signer, attribute, and value.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries trailing octets, or exceeds the bounds this walk stays within.</exception>
    /// <remarks>
    /// Replacing an attribute value is not a preservation-neutral act the way appending is: an archive
    /// time-stamp whose <c>ats-hash-index-v3</c> covers the replaced value stops matching it. Clause 5.5.3
    /// nonetheless directs validation material into the <em>latest</em> archive time-stamp's token precisely
    /// because no later archive time-stamp covers it, and the caller is responsible for addressing that value
    /// and no earlier one.
    /// </remarks>
    public static CmsSignedData ReplaceUnsignedAttributeValue(
        CmsSignedData signedData,
        int signerIndex,
        int attributeIndex,
        int valueIndex,
        ReadOnlySpan<byte> replacementValue,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);
        ArgumentOutOfRangeException.ThrowIfNegative(attributeIndex);
        ArgumentOutOfRangeException.ThrowIfNegative(valueIndex);

        AsnDecoder.ReadEncodedValue(replacementValue, AsnEncodingRules.DER, out _, out _, out int consumed);
        if(consumed != replacementValue.Length)
        {
            throw new ArgumentException("A replacement attribute value is exactly one DER value (RFC 5652 §5.3).", nameof(replacementValue));
        }

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SpliceTarget target = LocateTarget(source, signerIndex);
        UnsignedAttributeValueSite site = SelectSite(source, target, attributeIndex, valueIndex);

        CmsElement[] chain = target.Chain;
        chain[6] = site.Attribute;
        chain[7] = site.Values;

        return Splice(source, chain, chainLength: 8, site.Value.Start, site.Value.End, replacementValue, pool);
    }


    /// <summary>
    /// Adds certificates to <c>SignedData.certificates</c>, preserving every octet already there — the
    /// placement ETSI EN 319 122-1 Table 1 requirements a) to e) and clause 5.5.3's first strategy state for a
    /// signature carrying no legacy long-term-availability attribute.
    /// </summary>
    /// <param name="signedData">The Signed Data Object to augment. Not modified; the result is a new carrier.</param>
    /// <param name="certificates">The whole encodings of the <c>CertificateChoices</c> instances to add.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The augmented Signed Data Object, or an untouched copy when every candidate was already there. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When no certificate is supplied, more than the supported count is, or one of them is not exactly one DER value.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, or carries trailing octets.</exception>
    /// <remarks>
    /// A candidate whose encoding is already a member of the set is skipped, which is requirement e)'s
    /// "duplication of certificate values should be avoided" applied by construction. New members are appended
    /// after the existing ones rather than the set being re-sorted, for the same reason the unsigned attributes
    /// are not re-sorted: re-ordering would change the encoding of components the preservation rule protects,
    /// and clause 5.5.2's hash index is a membership test in which position carries no meaning.
    /// </remarks>
    public static CmsSignedData AddCertificates(CmsSignedData signedData, IReadOnlyList<ReadOnlyMemory<byte>> certificates, MemoryPool<byte> pool) =>
        AddToOptionalSet(signedData, certificates, ContextConstructed0, pool);


    /// <summary>
    /// Adds revocation information to <c>SignedData.crls</c>, preserving every octet already there — the
    /// placement ETSI EN 319 122-1 Table 1 requirements q) and r) state, a CRL as the <c>crl</c> alternative of
    /// <c>RevocationInfoChoice</c> and an OCSP response as the <c>other</c> alternative of that same choice.
    /// </summary>
    /// <param name="signedData">The Signed Data Object to augment. Not modified; the result is a new carrier.</param>
    /// <param name="revocationInformation">The whole encodings of the <c>RevocationInfoChoice</c> instances to add.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The augmented Signed Data Object, or an untouched copy when every candidate was already there. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When no entry is supplied, more than the supported count is, or one of them is not exactly one DER value.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, or carries trailing octets.</exception>
    /// <remarks>
    /// A candidate whose encoding is already a member of the set is skipped, which is requirement p)'s
    /// "duplication of revocation values should be avoided" applied by construction.
    /// </remarks>
    public static CmsSignedData AddRevocationInformation(CmsSignedData signedData, IReadOnlyList<ReadOnlyMemory<byte>> revocationInformation, MemoryPool<byte> pool) =>
        AddToOptionalSet(signedData, revocationInformation, ContextConstructed1, pool);


    /// <summary>
    /// Adds one parallel <c>SignerInfo</c> to <c>SignedData.signerInfos</c>, preserving every octet already
    /// there — the multi-signer shape of <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652
    /// §5.1</see>, where several signers sign the same encapsulated content side by side, as distinct from a
    /// countersignature (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-11.4">§11.4</see>), which
    /// signs another signature's value and lives inside that signature's unsigned attributes.
    /// </summary>
    /// <param name="signedData">The Signed Data Object to augment. Not modified; the result is a new carrier.</param>
    /// <param name="signerInfo">The whole DER-encoded <c>SignerInfo</c> to add, as the completion surfaces produce it.</param>
    /// <param name="certificates">The whole encodings of <c>CertificateChoices</c> instances to place alongside — the new signer's own certificate and chain (ETSI EN 319 122-1 Table 1 requirements a and d) — or <see langword="null"/> to add none.</param>
    /// <param name="pool">The memory pool the result and every intermediate are rented from.</param>
    /// <returns>The augmented Signed Data Object. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/>, <paramref name="signerInfo"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="signerInfo"/> is not exactly one DER <c>SignerInfo</c> this operation places (see the remarks), or the structure already carries the identical <c>SignerInfo</c>.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData this operation can preserve.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries octets after the outer ContentInfo, or holds more members than this walk stays within.</exception>
    /// <remarks>
    /// <para>
    /// <strong>Placement keeps a DER structure DER.</strong> The strict reader of this library's own managed
    /// backend reads <c>signerInfos</c> and <c>digestAlgorithms</c> as DER <c>SET OF</c> structures, whose
    /// members X.690 clause 11.6 orders by their encoded octets. The new member is therefore inserted at its
    /// clause 11.6 position rather than appended: a set that was DER-sorted stays DER-sorted, every existing
    /// member keeps its own octets and its relative order either way, and a BER structure met in the wild —
    /// where the clause does not apply — is only ever changed by the insertion itself and the enclosing length
    /// octets, exactly as the class remarks state for every splice here.
    /// </para>
    /// <para>
    /// <strong>The digest algorithm travels with the signer.</strong> RFC 5652 §5.1 has <c>digestAlgorithms</c>
    /// as the collection "intended to list" each signer's digest algorithm, so the new signer's whole
    /// <c>DigestAlgorithmIdentifier</c> encoding is unioned into that set when its exact octets are not already
    /// a member — read out of the supplied <c>SignerInfo</c> itself rather than passed beside it, so the pair
    /// cannot disagree.
    /// </para>
    /// <para>
    /// <strong>Only a version 1 <c>SignerInfo</c> is placed.</strong> RFC 5652 §5.1's version rule raises
    /// <c>SignedData.version</c> to 3 once any <c>SignerInfo</c> is version 3 (a <c>subjectKeyIdentifier</c>
    /// signer identifier, §5.3). This operation refuses such a member rather than rewriting the version octet
    /// of a structure it otherwise preserves: every <c>SignerInfo</c> this library's creation surfaces produce
    /// is version 1 with an <c>IssuerAndSerialNumber</c> identifier, and a widening that places version 3
    /// members and applies §5.1's rule is separate work if ever wanted.
    /// </para>
    /// <para>
    /// <strong>Adding a signer changes what whole-structure evidence covers.</strong> An archive time-stamp or
    /// an Evidence Record whose imprint covers the whole Signed Data Object octets no longer matches the
    /// augmented structure — the same caution ETSI EN 319 122-1 clause 5.5.3 NOTE 6 gives for adding to a
    /// protected structure. Parallel signers are placed before such whole-object evidence is, not after.
    /// </para>
    /// </remarks>
    public static CmsSignedData AddSignerInfo(
        CmsSignedData signedData,
        PooledMemory signerInfo,
        IReadOnlyList<ReadOnlyMemory<byte>>? certificates,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(signerInfo);
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> addition = signerInfo.AsReadOnlySpan();
        CmsElement additionDigestAlgorithm = ValidateSignerInfoAddition(addition, nameof(signerInfo));
        ReadOnlySpan<byte> algorithmEncoding = addition[additionDigestAlgorithm.Start..additionDigestAlgorithm.End];

        CmsSignedData? withAlgorithm = null;
        CmsSignedData? withSigner = null;
        try
        {
            withAlgorithm = InsertDigestAlgorithmIfAbsent(signedData.AsReadOnlySpan(), algorithmEncoding, pool);
            withSigner = InsertSignerInfoMember((withAlgorithm ?? signedData).AsReadOnlySpan(), addition, nameof(signerInfo), pool);
            if(certificates is null)
            {
                CmsSignedData signerResult = withSigner;
                withSigner = null;

                return signerResult;
            }

            return AddCertificates(withSigner, certificates, pool);
        }
        finally
        {
            withAlgorithm?.Dispose();
            withSigner?.Dispose();
        }
    }


    /// <summary>
    /// Validates that a parallel-signer addition is exactly one DER <c>SignerInfo</c> this operation places —
    /// the whole field walk of <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC 5652
    /// §5.3</see>, the same order <see cref="LocateUnsignedAttributes"/> enforces when this class reads: a
    /// SEQUENCE whose <c>version</c> is 1, whose <c>sid</c> is the <c>IssuerAndSerialNumber</c> alternative
    /// (the one combination that leaves <c>SignedData.version</c> untouched under §5.1's version rule), whose
    /// <c>digestAlgorithm</c> opens with its algorithm object identifier (its whole octets are what the
    /// <c>digestAlgorithms</c> union carries), and whose mandatory <c>signatureAlgorithm</c> and
    /// <c>signature</c> follow the optional <c>signedAttrs</c>, with an optional <c>unsignedAttrs</c> closing
    /// the SEQUENCE exactly — so nothing this class's own readers would then throw on is ever spliced in.
    /// </summary>
    /// <param name="addition">The offered <c>SignerInfo</c> octets.</param>
    /// <param name="parameterName">The caller's parameter name for the refusal messages.</param>
    /// <returns>The <c>digestAlgorithm</c> <c>AlgorithmIdentifier</c> element within <paramref name="addition"/>.</returns>
    /// <exception cref="ArgumentException">When the offered octets are not such a <c>SignerInfo</c>.</exception>
    private static CmsElement ValidateSignerInfoAddition(ReadOnlySpan<byte> addition, string parameterName)
    {
        if(addition.IsEmpty)
        {
            throw new ArgumentException("A parallel-signer addition places one whole DER SignerInfo (RFC 5652 §5.3).", parameterName);
        }

        AsnDecoder.ReadEncodedValue(addition, AsnEncodingRules.DER, out _, out _, out int consumed);
        if(consumed != addition.Length)
        {
            throw new ArgumentException("A parallel-signer addition is exactly one DER value (RFC 5652 §5.3).", parameterName);
        }

        CmsElement element = ReadElement(addition, 0, addition.Length);
        if(element.Tag != Asn1Tag.Sequence)
        {
            throw new ArgumentException("A SignerInfo is a SEQUENCE (RFC 5652 §5.3).", parameterName);
        }

        CmsElement version = ReadElement(addition, element.ContentStart, element.ContentEnd);
        if(version.Tag != Asn1Tag.Integer || version.ContentLength != 1 || addition[version.ContentStart] != 1)
        {
            throw new ArgumentException(
                "A parallel-signer addition places a version 1 SignerInfo only: any other version changes what RFC 5652 §5.1's version rule assigns to SignedData.version, which this preserving operation does not rewrite.",
                parameterName);
        }

        CmsElement signerIdentifier = ReadElement(addition, version.End, element.ContentEnd);
        if(signerIdentifier.Tag != Asn1Tag.Sequence)
        {
            throw new ArgumentException(
                "A version 1 SignerInfo carries the IssuerAndSerialNumber signer identifier alternative (RFC 5652 §5.3).",
                parameterName);
        }

        CmsElement digestAlgorithm = ReadElement(addition, signerIdentifier.End, element.ContentEnd);
        if(digestAlgorithm.Tag != Asn1Tag.Sequence)
        {
            throw new ArgumentException("A SignerInfo carries its digestAlgorithm as a SEQUENCE (RFC 5652 §5.3).", parameterName);
        }

        if(digestAlgorithm.ContentLength == 0 || ReadElement(addition, digestAlgorithm.ContentStart, digestAlgorithm.ContentEnd).Tag != Asn1Tag.ObjectIdentifier)
        {
            throw new ArgumentException(
                "A SignerInfo digestAlgorithm is an AlgorithmIdentifier opening with its algorithm object identifier (RFC 5652 §5.3), and its whole octets are what the digestAlgorithms union carries.",
                parameterName);
        }

        //signedAttrs [0] IMPLICIT is optional and precedes signatureAlgorithm (RFC 5652 §5.3).
        CmsElement candidate = ReadElement(addition, digestAlgorithm.End, element.ContentEnd);
        if(candidate.Tag == ContextConstructed0)
        {
            candidate = ReadElement(addition, candidate.End, element.ContentEnd);
        }

        if(candidate.Tag != Asn1Tag.Sequence)
        {
            throw new ArgumentException("A SignerInfo carries its signatureAlgorithm as a SEQUENCE (RFC 5652 §5.3).", parameterName);
        }

        CmsElement signature = ReadElement(addition, candidate.End, element.ContentEnd);
        bool isPrimitiveOctetString = signature.Tag.TagClass == TagClass.Universal
            && signature.Tag.TagValue == OctetStringTagNumber
            && !signature.Tag.IsConstructed;
        if(!isPrimitiveOctetString)
        {
            throw new ArgumentException("A SignerInfo carries its signature as a primitive OCTET STRING (RFC 5652 §5.3; X.690 clause 8.7).", parameterName);
        }

        if(signature.End != element.ContentEnd)
        {
            CmsElement unsignedAttributes = ReadElement(addition, signature.End, element.ContentEnd);
            if(unsignedAttributes.Tag != ContextConstructed1 || unsignedAttributes.End != element.ContentEnd)
            {
                throw new ArgumentException(
                    "A SignerInfo ends with its optional unsignedAttrs [1] IMPLICIT field and nothing after it (RFC 5652 §5.3).",
                    parameterName);
            }
        }

        return digestAlgorithm;
    }


    /// <summary>
    /// Splices a new signer's <c>DigestAlgorithmIdentifier</c> into <c>SignedData.digestAlgorithms</c> at its
    /// X.690 clause 11.6 position, or reports the union already holds it.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="algorithmEncoding">The whole <c>AlgorithmIdentifier</c> encoding to union in.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The spliced Signed Data Object, or <see langword="null"/> when the exact octets are already a member. The caller owns and disposes a returned carrier.</returns>
    private static CmsSignedData? InsertDigestAlgorithmIfAbsent(ReadOnlySpan<byte> source, ReadOnlySpan<byte> algorithmEncoding, MemoryPool<byte> pool)
    {
        SignedDataLayout layout = LocateSignedDataLayout(source);
        List<CmsElement> members = ReadSetMembers(source, layout.DigestAlgorithms, MaximumEmbeddedObjects, "digestAlgorithms");
        int insertionOffset = layout.DigestAlgorithms.ContentEnd;
        bool positioned = false;
        for(int i = 0; i < members.Count; ++i)
        {
            ReadOnlySpan<byte> member = source[members[i].Start..members[i].End];
            if(member.SequenceEqual(algorithmEncoding))
            {
                return null;
            }

            if(!positioned && CompareSetOfMemberOrder(algorithmEncoding, member) < 0)
            {
                insertionOffset = members[i].Start;
                positioned = true;
            }
        }

        var chain = new CmsElement[MaximumChainLength];
        chain[0] = layout.ContentInfo;
        chain[1] = layout.ExplicitContent;
        chain[2] = layout.SignedData;
        chain[3] = layout.DigestAlgorithms;

        return Splice(source, chain, chainLength: 4, insertionOffset, insertionOffset, algorithmEncoding, pool);
    }


    /// <summary>
    /// Splices a whole <c>SignerInfo</c> into <c>SignedData.signerInfos</c> at its X.690 clause 11.6 position.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="addition">The whole <c>SignerInfo</c> encoding to place.</param>
    /// <param name="parameterName">The caller's parameter name for the duplicate refusal.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The spliced Signed Data Object. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">When the structure already carries the identical <c>SignerInfo</c>.</exception>
    /// <exception cref="AsnContentException">When the set already holds as many members as this walk stays within.</exception>
    private static CmsSignedData InsertSignerInfoMember(ReadOnlySpan<byte> source, ReadOnlySpan<byte> addition, string parameterName, MemoryPool<byte> pool)
    {
        SignedDataLayout layout = LocateSignedDataLayout(source);
        List<CmsElement> members = ReadSetMembers(source, layout.SignerInfos, MaximumSignerInfos, "signerInfos");
        if(members.Count == MaximumSignerInfos)
        {
            throw new AsnContentException($"A CMS 'signerInfos' field is walked with at most {MaximumSignerInfos} members, which the set already holds.");
        }

        int insertionOffset = layout.SignerInfos.ContentEnd;
        bool positioned = false;
        for(int i = 0; i < members.Count; ++i)
        {
            ReadOnlySpan<byte> member = source[members[i].Start..members[i].End];
            if(member.SequenceEqual(addition))
            {
                throw new ArgumentException("The Signed Data Object already carries this exact SignerInfo; a SET OF holds distinct values (X.690 clause 11.6).", parameterName);
            }

            if(!positioned && CompareSetOfMemberOrder(addition, member) < 0)
            {
                insertionOffset = members[i].Start;
                positioned = true;
            }
        }

        var chain = new CmsElement[MaximumChainLength];
        chain[0] = layout.ContentInfo;
        chain[1] = layout.ExplicitContent;
        chain[2] = layout.SignedData;
        chain[3] = layout.SignerInfos;

        return Splice(source, chain, chainLength: 4, insertionOffset, insertionOffset, addition, pool);
    }


    /// <summary>
    /// Orders two <c>SET OF</c> member encodings as X.690 clause 11.6 does for DER: compared as octet strings
    /// in ascending order, the shorter one padded at its trailing end with zero octets.
    /// </summary>
    /// <param name="left">One member encoding.</param>
    /// <param name="right">The other member encoding.</param>
    /// <returns>A negative value when <paramref name="left"/> orders first, positive when <paramref name="right"/> does, zero when the padded encodings are equal.</returns>
    private static int CompareSetOfMemberOrder(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        int sharedLength = Math.Min(left.Length, right.Length);
        int order = left[..sharedLength].SequenceCompareTo(right[..sharedLength]);
        if(order != 0 || left.Length == right.Length)
        {
            return order;
        }

        //An equal prefix defers to the tail of the longer encoding against the shorter one's zero padding:
        //any non-zero tail octet orders the longer encoding after the padded shorter one.
        ReadOnlySpan<byte> tail = left.Length > right.Length ? left[sharedLength..] : right[sharedLength..];
        for(int i = 0; i < tail.Length; ++i)
        {
            if(tail[i] != 0)
            {
                return left.Length > right.Length ? 1 : -1;
            }
        }

        return 0;
    }


    /// <summary>
    /// Returns what <c>SignedData.encapContentInfo</c> states: the content type, and — for the attached form —
    /// a view of the <c>eContent</c> octets a parallel signer's <c>message-digest</c> attribute is computed
    /// over (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.2">RFC 5652 §5.2</see>).
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <returns>The content type and, when the content travels attached, a view of its octets within <paramref name="signedData"/>'s own memory, valid while it is.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData, or its <c>eContent</c> is not one primitive definite-length OCTET STRING — the constructed or indefinite-length BER forms state the same content in an encoding this read does not reassemble, the same DER scope <see cref="ArchiveTimestampV3"/> already applies.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, or carries octets after the outer ContentInfo.</exception>
    public static CmsEncapsulatedContent ReadEncapsulatedContentInfo(CmsSignedData signedData)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SignedDataLayout layout = LocateSignedDataLayout(source);
        CmsElement contentType = ReadElement(source, layout.EncapContentInfo.ContentStart, layout.EncapContentInfo.ContentEnd);
        if(contentType.Tag != Asn1Tag.ObjectIdentifier)
        {
            throw new CryptographicException("A CMS EncapsulatedContentInfo begins with its eContentType object identifier (RFC 5652 §5.2).");
        }

        string contentTypeOid = AsnDecoder.ReadObjectIdentifier(source[contentType.Start..contentType.End], AsnEncodingRules.BER, out _);
        if(contentType.End == layout.EncapContentInfo.ContentEnd)
        {
            return new CmsEncapsulatedContent(contentTypeOid, null);
        }

        CmsElement explicitEContent = ReadElement(source, contentType.End, layout.EncapContentInfo.ContentEnd);
        if(explicitEContent.Tag != ContextConstructed0 || explicitEContent.End != layout.EncapContentInfo.ContentEnd)
        {
            throw new CryptographicException("A CMS EncapsulatedContentInfo ends with its optional eContent [0] EXPLICIT field (RFC 5652 §5.2).");
        }

        CmsElement octets = ReadElement(source, explicitEContent.ContentStart, explicitEContent.ContentEnd);
        bool isPrimitiveOctetString = octets.Tag.TagClass == TagClass.Universal
            && octets.Tag.TagValue == OctetStringTagNumber
            && !octets.Tag.IsConstructed;
        if(!isPrimitiveOctetString || octets.IsIndefinite || octets.End != explicitEContent.ContentEnd)
        {
            throw new CryptographicException(
                "A CMS eContent is read as one primitive definite-length OCTET STRING; a constructed or indefinite-length BER form is not reassembled here (RFC 5652 §5.2; X.690 clause 8.7).");
        }

        return new CmsEncapsulatedContent(contentTypeOid, signedData.AsReadOnlyMemory()[octets.ContentStart..octets.ContentEnd]);
    }


    /// <summary>
    /// Returns the whole encoding of every member of <c>SignedData.certificates</c>, in encoding order.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <returns>Views of the members within <paramref name="signedData"/>'s own memory, valid while it is, or an empty list when the field is absent.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries trailing octets, or holds more members than this walk stays within.</exception>
    public static IReadOnlyList<ReadOnlyMemory<byte>> ReadCertificates(CmsSignedData signedData) =>
        ReadOptionalSet(signedData, ContextConstructed0);


    /// <summary>
    /// Returns the whole encoding of every member of <c>SignedData.crls</c>, in encoding order — CRLs and, per
    /// clause 5.4.2.2 of ETSI EN 319 122-1, OCSP responses alike, since both are alternatives of one
    /// <c>RevocationInfoChoice</c>.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <returns>Views of the members within <paramref name="signedData"/>'s own memory, valid while it is, or an empty list when the field is absent.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries trailing octets, or holds more members than this walk stays within.</exception>
    public static IReadOnlyList<ReadOnlyMemory<byte>> ReadRevocationInformation(CmsSignedData signedData) =>
        ReadOptionalSet(signedData, ContextConstructed1);


    /// <summary>
    /// Returns the members of one of the two optional implicitly tagged sets of a <c>SignedData</c>.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <param name="setTag">The implicit tag the field carries.</param>
    /// <returns>Views of the members, or an empty list when the field is absent.</returns>
    private static List<ReadOnlyMemory<byte>> ReadOptionalSet(CmsSignedData signedData, Asn1Tag setTag)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SignedDataLayout layout = LocateSignedDataLayout(source);
        (CmsElement set, bool present) = setTag == ContextConstructed0
            ? (layout.Certificates, layout.HasCertificates)
            : (layout.RevocationInformation, layout.HasRevocationInformation);
        if(!present)
        {
            return [];
        }

        List<CmsElement> members = ReadSetMembers(source, set, MaximumEmbeddedObjects, setTag == ContextConstructed0 ? "certificates" : "crls");
        ReadOnlyMemory<byte> whole = signedData.AsReadOnlyMemory();
        var encodings = new List<ReadOnlyMemory<byte>>(members.Count);
        for(int i = 0; i < members.Count; ++i)
        {
            encodings.Add(whole[members[i].Start..members[i].End]);
        }

        return encodings;
    }


    /// <summary>
    /// Adds members to one of the two optional implicitly tagged sets of a <c>SignedData</c>, creating the set
    /// when it is absent and appending to it when it is present.
    /// </summary>
    /// <param name="signedData">The Signed Data Object to augment.</param>
    /// <param name="members">The whole encodings of the members to add.</param>
    /// <param name="setTag">The implicit tag of the field: <c>[0]</c> for <c>certificates</c>, <c>[1]</c> for <c>crls</c>.</param>
    /// <param name="pool">The memory pool the result and the intermediate encoding are rented from.</param>
    /// <returns>The augmented Signed Data Object. The caller owns and disposes it.</returns>
    private static CmsSignedData AddToOptionalSet(
        CmsSignedData signedData,
        IReadOnlyList<ReadOnlyMemory<byte>> members,
        Asn1Tag setTag,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(members);
        ArgumentNullException.ThrowIfNull(pool);
        string fieldName = setTag == ContextConstructed0 ? "certificates" : "crls";
        if(members.Count == 0)
        {
            throw new ArgumentException($"An addition to a SignedData '{fieldName}' field adds at least one member.", nameof(members));
        }

        if(members.Count > MaximumEmbeddedObjects)
        {
            throw new ArgumentException($"An addition to a SignedData '{fieldName}' field adds at most {MaximumEmbeddedObjects} members in one call.", nameof(members));
        }

        for(int i = 0; i < members.Count; ++i)
        {
            AsnDecoder.ReadEncodedValue(members[i].Span, AsnEncodingRules.DER, out _, out _, out int consumed);
            if(consumed != members[i].Length)
            {
                throw new ArgumentException($"Each member added to a SignedData '{fieldName}' field is exactly one DER value (RFC 5652 §5.1).", nameof(members));
            }
        }

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        SignedDataLayout layout = LocateSignedDataLayout(source);
        (CmsElement set, bool present) = setTag == ContextConstructed0
            ? (layout.Certificates, layout.HasCertificates)
            : (layout.RevocationInformation, layout.HasRevocationInformation);

        List<ReadOnlyMemory<byte>> additions = present
            ? SelectAbsentMembers(source, ReadSetMembers(source, set, MaximumEmbeddedObjects, fieldName), members)
            : [.. members];
        if(additions.Count == 0)
        {
            //Every candidate was already a member, so requirement e)/p)'s avoidance of duplication leaves the
            //object exactly as it stood; the copy keeps the caller's ownership contract the same either way.
            return CmsSignedData.FromBytes(source, pool);
        }

        var chain = new CmsElement[MaximumChainLength];
        chain[0] = layout.ContentInfo;
        chain[1] = layout.ExplicitContent;
        chain[2] = layout.SignedData;
        int chainLength = 3;
        int insertionOffset;
        using PooledMemory newMaterial = present
            ? ConcatenateEncodings(additions, pool)
            : EncodeImplicitSet(setTag, additions, pool);
        if(present)
        {
            chain[3] = set;
            chainLength = 4;
            insertionOffset = set.ContentEnd;
        }
        else
        {
            //An absent field is created in its syntax position: certificates directly after encapContentInfo,
            //crls after certificates when one is there, and both before signerInfos (RFC 5652 §5.1).
            insertionOffset = setTag == ContextConstructed1 && layout.HasCertificates
                ? layout.Certificates.End
                : layout.EncapContentInfo.End;
        }

        int versionValueOffset = RaisesVersionForOtherFormatMembers(source, layout, setTag, additions)
            ? layout.Version.ContentStart
            : -1;

        return Splice(source, chain, chainLength, insertionOffset, insertionOffset, newMaterial.AsReadOnlySpan(), pool, versionValueOffset);
    }


    /// <summary>
    /// States whether adding these members raises <c>SignedData.version</c> to
    /// <see cref="OtherFormatSignedDataVersion"/>: <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">
    /// RFC 5652 §5.1</see> mandates version 5 once the <c>certificates</c> set gains a <c>[3]</c>
    /// <c>OtherCertificateFormat</c> member or the <c>crls</c> set gains a <c>[1]</c>
    /// <c>OtherRevocationInfoFormat</c> member. A version already at 5 (or the atypical multi-octet encoding a
    /// small integer never uses) is left exactly as it stands, so a certificates-only or a CRL-only addition
    /// keeps the version it had.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="layout">The located outer envelope, whose <c>Version</c> element states the current version octet.</param>
    /// <param name="setTag">The implicit tag of the field being added to: <c>[0]</c> for <c>certificates</c>, <c>[1]</c> for <c>crls</c>.</param>
    /// <param name="additions">The members actually being spliced in (duplicates already skipped).</param>
    /// <returns><see langword="true"/> when at least one addition carries the other-format tag of its field and the current version is below 5.</returns>
    private static bool RaisesVersionForOtherFormatMembers(ReadOnlySpan<byte> source, SignedDataLayout layout, Asn1Tag setTag, List<ReadOnlyMemory<byte>> additions)
    {
        if(layout.Version.ContentLength != 1 || source[layout.Version.ContentStart] >= OtherFormatSignedDataVersion)
        {
            return false;
        }

        //The certificates set's other alternative is [3] OtherCertificateFormat; the crls set's is [1]
        //OtherRevocationInfoFormat — the same [1] the crls field itself carries, met here one nesting level in,
        //on the member rather than the set (RFC 5652 §10.2.1/§10.2.2).
        Asn1Tag otherFormatTag = setTag == ContextConstructed0 ? OtherCertificateFormatTag : ContextConstructed1;
        for(int i = 0; i < additions.Count; ++i)
        {
            if(Asn1Tag.Decode(additions[i].Span, out _) == otherFormatTag)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Returns the candidates whose encoding is not already a member of a set, which is how the avoidance of
    /// duplication that ETSI EN 319 122-1 Table 1 requirements e) and p) ask for is applied.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="existing">The members already in the set.</param>
    /// <param name="candidates">The whole encodings offered for addition.</param>
    /// <returns>The candidates not already present, in the order they were offered, each offered at most once.</returns>
    private static List<ReadOnlyMemory<byte>> SelectAbsentMembers(
        ReadOnlySpan<byte> source,
        List<CmsElement> existing,
        IReadOnlyList<ReadOnlyMemory<byte>> candidates)
    {
        List<ReadOnlyMemory<byte>> additions = [];
        for(int i = 0; i < candidates.Count; ++i)
        {
            ReadOnlySpan<byte> candidate = candidates[i].Span;
            bool alreadyPresent = false;
            for(int j = 0; j < existing.Count && !alreadyPresent; ++j)
            {
                alreadyPresent = source[existing[j].Start..existing[j].End].SequenceEqual(candidate);
            }

            for(int j = 0; j < additions.Count && !alreadyPresent; ++j)
            {
                alreadyPresent = additions[j].Span.SequenceEqual(candidate);
            }

            if(!alreadyPresent)
            {
                additions.Add(candidates[i]);
            }
        }

        return additions;
    }


    /// <summary>
    /// Selects one <c>AttributeValue</c> of one unsigned attribute by its indices.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="target">The walked signer.</param>
    /// <param name="attributeIndex">The zero-based index of the <c>Attribute</c>.</param>
    /// <param name="valueIndex">The zero-based index of the value within that attribute.</param>
    /// <returns>The addressed value's site.</returns>
    /// <exception cref="CryptographicException">When the signer carries no such attribute or value.</exception>
    private static UnsignedAttributeValueSite SelectSite(ReadOnlySpan<byte> source, SpliceTarget target, int attributeIndex, int valueIndex)
    {
        if(!target.HasUnsignedAttributes)
        {
            throw new CryptographicException("The CMS SignerInfo carries no unsignedAttrs field (RFC 5652 §5.3).");
        }

        List<UnsignedAttributeValueSite> sites = WalkUnsignedAttributeValues(source, target.UnsignedAttributes);
        for(int i = 0; i < sites.Count; ++i)
        {
            if(sites[i].AttributeIndex == attributeIndex && sites[i].ValueIndex == valueIndex)
            {
                return sites[i];
            }
        }

        throw new CryptographicException($"The CMS SignerInfo carries no unsigned attribute {attributeIndex} with a value {valueIndex} (RFC 5652 §5.3).");
    }


    /// <summary>
    /// Walks an <c>unsignedAttrs</c> set, yielding one site per <c>AttributeValue</c> with the enclosing
    /// <c>Attribute</c> and <c>attrValues</c> containers a replacement has to lengthen.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="unsignedAttributes">The <c>unsignedAttrs</c> set.</param>
    /// <returns>The sites, in encoding order.</returns>
    /// <exception cref="CryptographicException">When an attribute is not of the syntax's shape.</exception>
    /// <exception cref="AsnContentException">When the set is malformed or holds more attributes or values than this walk stays within.</exception>
    /// <remarks>Visible to <see cref="CmsSignedDataReduction"/>, which removes the very sites this walk reports.</remarks>
    internal static List<UnsignedAttributeValueSite> WalkUnsignedAttributeValues(ReadOnlySpan<byte> source, CmsElement unsignedAttributes)
    {
        List<UnsignedAttributeValueSite> sites = [];
        int position = unsignedAttributes.ContentStart;
        int attributeIndex = 0;
        while(position < unsignedAttributes.ContentEnd)
        {
            if(attributeIndex == MaximumUnsignedAttributes)
            {
                throw new AsnContentException($"A CMS unsignedAttrs set is walked with at most {MaximumUnsignedAttributes} attributes.");
            }

            CmsElement attribute = ReadElement(source, position, unsignedAttributes.ContentEnd);
            if(attribute.Tag != Asn1Tag.Sequence)
            {
                throw new CryptographicException("A CMS unsignedAttrs set holds Attribute SEQUENCE structures (RFC 5652 §5.3).");
            }

            CmsElement attributeType = ReadElement(source, attribute.ContentStart, attribute.ContentEnd);
            if(attributeType.Tag != Asn1Tag.ObjectIdentifier)
            {
                throw new CryptographicException("A CMS Attribute begins with its attrType object identifier (RFC 5652 §5.3).");
            }

            string oid = AsnDecoder.ReadObjectIdentifier(source[attributeType.Start..attributeType.End], AsnEncodingRules.BER, out _);
            CmsElement values = ReadElement(source, attributeType.End, attribute.ContentEnd);
            if(values.Tag != Asn1Tag.SetOf)
            {
                throw new CryptographicException("A CMS Attribute carries its attrValues as a SET (RFC 5652 §5.3).");
            }

            int valuePosition = values.ContentStart;
            int valueIndex = 0;
            while(valuePosition < values.ContentEnd)
            {
                if(sites.Count == MaximumUnsignedAttributeValues)
                {
                    throw new AsnContentException($"A CMS unsignedAttrs set is walked with at most {MaximumUnsignedAttributeValues} attribute values.");
                }

                CmsElement value = ReadElement(source, valuePosition, values.ContentEnd);
                sites.Add(new UnsignedAttributeValueSite(attributeIndex, valueIndex, oid, value, attribute, values));
                valuePosition = value.End;
                ++valueIndex;
            }

            position = attribute.End;
            ++attributeIndex;
        }

        return sites;
    }


    /// <summary>
    /// Returns every member of a set, in encoding order.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="set">The set container.</param>
    /// <param name="maximumMembers">The largest number of members walked.</param>
    /// <param name="fieldName">The field's name, for the message of a bound failure.</param>
    /// <returns>The members.</returns>
    /// <exception cref="AsnContentException">When the set is malformed or holds more members than the bound admits.</exception>
    private static List<CmsElement> ReadSetMembers(ReadOnlySpan<byte> source, CmsElement set, int maximumMembers, string fieldName)
    {
        List<CmsElement> members = [];
        int position = set.ContentStart;
        while(position < set.ContentEnd)
        {
            if(members.Count == maximumMembers)
            {
                throw new AsnContentException($"A CMS '{fieldName}' field is walked with at most {maximumMembers} members.");
            }

            CmsElement member = ReadElement(source, position, set.ContentEnd);
            members.Add(member);
            position = member.End;
        }

        return members;
    }


    /// <summary>
    /// Copies encodings end to end, the form appended inside a set that already exists.
    /// </summary>
    /// <param name="encodings">The encodings to concatenate.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <returns>The concatenated octets. The caller disposes them.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static PooledMemory ConcatenateEncodings(List<ReadOnlyMemory<byte>> encodings, MemoryPool<byte> pool)
    {
        int total = 0;
        for(int i = 0; i < encodings.Count; ++i)
        {
            total += encodings[i].Length;
        }

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            Span<byte> destination = owner.Memory.Span;
            int written = 0;
            for(int i = 0; i < encodings.Count; ++i)
            {
                encodings[i].Span.CopyTo(destination[written..]);
                written += encodings[i].Length;
            }

            return new PooledMemory(owner, written, CryptoTags.CmsEncodedAttribute);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Encodes members as a complete DER implicitly tagged <c>SET OF</c>, the form appended when the field is
    /// absent from the <c>SignedData</c> altogether.
    /// </summary>
    /// <param name="setTag">The implicit tag the field carries.</param>
    /// <param name="members">The members the new set holds.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <returns>The encoded set. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static PooledMemory EncodeImplicitSet(Asn1Tag setTag, List<ReadOnlyMemory<byte>> members, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSetOf(setTag))
        {
            for(int i = 0; i < members.Count; ++i)
            {
                writer.WriteEncodedValue(members[i].Span);
            }
        }

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out int written);

            return new PooledMemory(owner, written, CryptoTags.CmsEncodedAttribute);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Walks the Signed Data Object down to the chosen <c>SignerInfo</c>, collecting the containers that
    /// enclose its <c>unsignedAttrs</c> and the offset new attributes are inserted at.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> to augment.</param>
    /// <returns>The enclosing chain and the insertion offset.</returns>
    /// <exception cref="CryptographicException">When the structure is not a CMS SignedData with a SignerInfo at that index.</exception>
    /// <exception cref="AsnContentException">When the structure is malformed, truncated, or carries trailing octets.</exception>
    /// <remarks>
    /// Visible to <see cref="CmsSignedDataReduction"/> so the removal primitive walks the structure with this
    /// walk and not a second one of its own: an insertion and its inverse must agree on where the containers
    /// are, or the inverse is not one.
    /// </remarks>
    internal static SpliceTarget LocateTarget(ReadOnlySpan<byte> source, int signerIndex)
    {
        SignedDataLayout layout = LocateSignedDataLayout(source);
        CmsElement signerInfo = LocateSignerInfo(source, layout.SignerInfos, signerIndex);
        CmsElement unsignedAttributes = LocateUnsignedAttributes(
            source, signerInfo, out CmsElement signature, out bool hasUnsignedAttributes, out _, out _);

        var chain = new CmsElement[MaximumChainLength];
        chain[0] = layout.ContentInfo;
        chain[1] = layout.ExplicitContent;
        chain[2] = layout.SignedData;
        chain[3] = layout.SignerInfos;
        chain[4] = signerInfo;
        int chainLength = 5;
        int insertionOffset = signerInfo.ContentEnd;
        if(hasUnsignedAttributes)
        {
            chain[5] = unsignedAttributes;
            chainLength = 6;
            insertionOffset = unsignedAttributes.ContentEnd;
        }

        return new SpliceTarget(chain, chainLength, insertionOffset, hasUnsignedAttributes, unsignedAttributes, signature);
    }


    /// <summary>
    /// Walks the outer envelope down to the <c>SignedData</c> fields, locating the containers every splice this
    /// class performs has to lengthen and the two optional sets validation material is placed in.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <returns>The located fields.</returns>
    /// <exception cref="CryptographicException">When the structure is not a CMS SignedData.</exception>
    /// <exception cref="AsnContentException">When the structure is malformed, truncated, or carries trailing octets.</exception>
    private static SignedDataLayout LocateSignedDataLayout(ReadOnlySpan<byte> source)
    {
        CmsElement contentInfo = ReadElement(source, 0, source.Length);
        if(contentInfo.Tag != Asn1Tag.Sequence)
        {
            throw new CryptographicException("A CMS ContentInfo is a SEQUENCE (RFC 5652 §3).");
        }

        if(contentInfo.End != source.Length)
        {
            throw new AsnContentException("The Signed Data Object carries octets after its ContentInfo (RFC 5652 §3).");
        }

        CmsElement contentType = ReadElement(source, contentInfo.ContentStart, contentInfo.ContentEnd);
        if(contentType.Tag != Asn1Tag.ObjectIdentifier)
        {
            throw new CryptographicException("A CMS ContentInfo begins with its contentType object identifier (RFC 5652 §3).");
        }

        string contentTypeOid = AsnDecoder.ReadObjectIdentifier(source[contentType.Start..contentType.End], AsnEncodingRules.BER, out _);
        if(!string.Equals(contentTypeOid, SignedDataOid, StringComparison.Ordinal))
        {
            throw new CryptographicException($"The CMS content type '{contentTypeOid}' is not id-signedData (RFC 5652 §5.1).");
        }

        CmsElement explicitContent = ReadElement(source, contentType.End, contentInfo.ContentEnd);
        if(explicitContent.Tag != ContextConstructed0 || explicitContent.End != contentInfo.ContentEnd)
        {
            throw new CryptographicException("A CMS ContentInfo carries its content as the final [0] EXPLICIT field (RFC 5652 §3).");
        }

        CmsElement signedDataSequence = ReadElement(source, explicitContent.ContentStart, explicitContent.ContentEnd);
        if(signedDataSequence.Tag != Asn1Tag.Sequence || signedDataSequence.End != explicitContent.ContentEnd)
        {
            throw new CryptographicException("A CMS SignedData is the single SEQUENCE inside the ContentInfo content (RFC 5652 §5.1).");
        }

        CmsElement version = ReadElement(source, signedDataSequence.ContentStart, signedDataSequence.ContentEnd);
        if(version.Tag != Asn1Tag.Integer)
        {
            throw new CryptographicException("A CMS SignedData begins with its version INTEGER (RFC 5652 §5.1).");
        }

        CmsElement digestAlgorithms = ReadElement(source, version.End, signedDataSequence.ContentEnd);
        if(digestAlgorithms.Tag != Asn1Tag.SetOf)
        {
            throw new CryptographicException("A CMS SignedData carries its digestAlgorithms as a SET (RFC 5652 §5.1).");
        }

        CmsElement encapContentInfo = ReadElement(source, digestAlgorithms.End, signedDataSequence.ContentEnd);
        if(encapContentInfo.Tag != Asn1Tag.Sequence)
        {
            throw new CryptographicException("A CMS SignedData carries its encapContentInfo as a SEQUENCE (RFC 5652 §5.1).");
        }

        //certificates [0] IMPLICIT and crls [1] IMPLICIT are optional and precede signerInfos.
        CmsElement certificates = default;
        CmsElement revocationInformation = default;
        bool hasCertificates = false;
        bool hasRevocationInformation = false;
        CmsElement candidate = ReadElement(source, encapContentInfo.End, signedDataSequence.ContentEnd);
        if(candidate.Tag == ContextConstructed0)
        {
            certificates = candidate;
            hasCertificates = true;
            candidate = ReadElement(source, candidate.End, signedDataSequence.ContentEnd);
        }

        if(candidate.Tag == ContextConstructed1)
        {
            revocationInformation = candidate;
            hasRevocationInformation = true;
            candidate = ReadElement(source, candidate.End, signedDataSequence.ContentEnd);
        }

        if(candidate.Tag != Asn1Tag.SetOf || candidate.End != signedDataSequence.ContentEnd)
        {
            throw new CryptographicException("A CMS SignedData ends with its signerInfos SET (RFC 5652 §5.1).");
        }

        return new SignedDataLayout(
            contentInfo,
            explicitContent,
            signedDataSequence,
            version,
            digestAlgorithms,
            encapContentInfo,
            certificates,
            hasCertificates,
            revocationInformation,
            hasRevocationInformation,
            candidate);
    }


    /// <summary>
    /// Returns the <c>SignerInfo</c> at <paramref name="signerIndex"/> within a <c>signerInfos</c> set.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="signerInfos">The <c>signerInfos</c> set.</param>
    /// <param name="signerIndex">The zero-based index of the signer to augment.</param>
    /// <returns>The chosen <c>SignerInfo</c> SEQUENCE.</returns>
    /// <exception cref="CryptographicException">When the set holds no SignerInfo at that index, or an entry is not a SEQUENCE.</exception>
    /// <exception cref="AsnContentException">When the structure is malformed or truncated.</exception>
    private static CmsElement LocateSignerInfo(ReadOnlySpan<byte> source, CmsElement signerInfos, int signerIndex)
    {
        int position = signerInfos.ContentStart;
        for(int index = 0; index <= Math.Min(signerIndex, MaximumSignerInfos); ++index)
        {
            if(position >= signerInfos.ContentEnd)
            {
                break;
            }

            CmsElement candidate = ReadElement(source, position, signerInfos.ContentEnd);
            if(candidate.Tag != Asn1Tag.Sequence)
            {
                throw new CryptographicException("A CMS signerInfos set holds SignerInfo SEQUENCE structures (RFC 5652 §5.1).");
            }

            if(index == signerIndex)
            {
                return candidate;
            }

            position = candidate.End;
        }

        throw new CryptographicException($"The CMS SignedData holds no SignerInfo at index {signerIndex} (RFC 5652 §5.1), or the index exceeds the {MaximumSignerInfos} structures this augmentation traverses.");
    }


    /// <summary>
    /// Reads the <c>SignerInfo</c> fields in their syntax order and returns its <c>unsignedAttrs</c> set when
    /// one is present (RFC 5652 §5.3).
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="signerInfo">The <c>SignerInfo</c> SEQUENCE.</param>
    /// <param name="signatureValue">Receives the <c>signature</c> OCTET STRING, whose content octets are what the signature-time-stamp imprint of ETSI EN 319 122-1 clause 5.3 is computed over.</param>
    /// <param name="hasUnsignedAttributes">Receives whether the <c>SignerInfo</c> already carries an <c>unsignedAttrs</c> field.</param>
    /// <param name="signedAttributes">Receives the <c>signedAttrs [0] IMPLICIT</c> set, meaningful only when <paramref name="hasSignedAttributes"/> holds — read once here since this walk already passes over it, so <see cref="ReadSignedAttributeValue"/> does not open a second field-by-field walk of the fixed <c>SignerInfo</c> prefix.</param>
    /// <param name="hasSignedAttributes">Receives whether the <c>SignerInfo</c> carries a <c>signedAttrs</c> field.</param>
    /// <returns>The <c>unsignedAttrs</c> set, or the default when there is none.</returns>
    /// <exception cref="CryptographicException">When a field is absent or not of the syntax's type.</exception>
    /// <exception cref="AsnContentException">When the structure is malformed or truncated.</exception>
    private static CmsElement LocateUnsignedAttributes(
        ReadOnlySpan<byte> source, CmsElement signerInfo, out CmsElement signatureValue, out bool hasUnsignedAttributes,
        out CmsElement signedAttributes, out bool hasSignedAttributes)
    {
        CmsElement version = ReadElement(source, signerInfo.ContentStart, signerInfo.ContentEnd);
        if(version.Tag != Asn1Tag.Integer)
        {
            throw new CryptographicException("A CMS SignerInfo begins with its version INTEGER (RFC 5652 §5.3).");
        }

        //SignerIdentifier is either an issuerAndSerialNumber SEQUENCE or a [0] subjectKeyIdentifier.
        CmsElement signerIdentifier = ReadElement(source, version.End, signerInfo.ContentEnd);
        if(signerIdentifier.Tag != Asn1Tag.Sequence && signerIdentifier.Tag.TagClass != TagClass.ContextSpecific)
        {
            throw new CryptographicException("A CMS SignerInfo carries a SignerIdentifier CHOICE (RFC 5652 §5.3).");
        }

        CmsElement digestAlgorithm = ReadElement(source, signerIdentifier.End, signerInfo.ContentEnd);
        if(digestAlgorithm.Tag != Asn1Tag.Sequence)
        {
            throw new CryptographicException("A CMS SignerInfo carries its digestAlgorithm as a SEQUENCE (RFC 5652 §5.3).");
        }

        //signedAttrs [0] IMPLICIT is optional and precedes signatureAlgorithm.
        CmsElement candidate = ReadElement(source, digestAlgorithm.End, signerInfo.ContentEnd);
        if(candidate.Tag == ContextConstructed0)
        {
            signedAttributes = candidate;
            hasSignedAttributes = true;
            candidate = ReadElement(source, candidate.End, signerInfo.ContentEnd);
        }
        else
        {
            signedAttributes = default;
            hasSignedAttributes = false;
        }

        if(candidate.Tag != Asn1Tag.Sequence)
        {
            throw new CryptographicException("A CMS SignerInfo carries its signatureAlgorithm as a SEQUENCE (RFC 5652 §5.3).");
        }

        CmsElement signature = ReadElement(source, candidate.End, signerInfo.ContentEnd);
        if(signature.Tag.TagClass != TagClass.Universal || signature.Tag.TagValue != OctetStringTagNumber)
        {
            throw new CryptographicException("A CMS SignerInfo carries its signature as an OCTET STRING (RFC 5652 §5.3).");
        }

        signatureValue = signature;
        if(signature.End == signerInfo.ContentEnd)
        {
            hasUnsignedAttributes = false;

            return default;
        }

        CmsElement unsignedAttributes = ReadElement(source, signature.End, signerInfo.ContentEnd);
        if(unsignedAttributes.Tag != ContextConstructed1 || unsignedAttributes.End != signerInfo.ContentEnd)
        {
            throw new CryptographicException("A CMS SignerInfo ends with its optional unsignedAttrs [1] IMPLICIT field (RFC 5652 §5.3).");
        }

        hasUnsignedAttributes = true;

        return unsignedAttributes;
    }


    /// <summary>
    /// Reads one encoded value starting at <paramref name="start"/> and bounded by <paramref name="limit"/>,
    /// under BER so that indefinite-length containers are recognised rather than rejected.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="start">The offset of the value's first tag octet.</param>
    /// <param name="limit">The offset one past the last octet the value may occupy.</param>
    /// <returns>The located element.</returns>
    /// <exception cref="AsnContentException">When the value is absent, malformed, or runs past <paramref name="limit"/>.</exception>
    /// <remarks>Visible to <see cref="CmsSignedDataReduction"/>, which reads the same elements to remove them.</remarks>
    internal static CmsElement ReadElement(ReadOnlySpan<byte> source, int start, int limit)
    {
        if(start >= limit)
        {
            throw new AsnContentException("The CMS structure ends before a field the syntax requires (RFC 5652 §5).");
        }

        ReadOnlySpan<byte> window = source[start..limit];
        Asn1Tag tag = Asn1Tag.Decode(window, out int tagLength);
        AsnDecoder.ReadEncodedValue(window, AsnEncodingRules.BER, out int contentOffset, out int contentLength, out int bytesConsumed);

        return new CmsElement(
            Start: start,
            TagLength: tagLength,
            HeaderLength: contentOffset,
            ContentStart: start + contentOffset,
            ContentLength: contentLength,
            ContentEnd: start + contentOffset + contentLength,
            End: start + bytesConsumed,
            IsIndefinite: window[tagLength] == IndefiniteLengthOctet,
            Tag: tag);
    }


    /// <summary>
    /// Copies the attributes end to end, the form appended inside an <c>unsignedAttrs</c> set that already
    /// exists: each attribute keeps the octets it was encoded with, and the set's existing members keep
    /// theirs.
    /// </summary>
    /// <param name="attributes">The attributes to append.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <returns>The concatenated attribute octets. The caller disposes them.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static PooledMemory ConcatenateAttributes(IReadOnlyList<CmsAttribute> attributes, MemoryPool<byte> pool)
    {
        int total = 0;
        for(int i = 0; i < attributes.Count; ++i)
        {
            total += attributes[i].Length;
        }

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            Span<byte> destination = owner.Memory.Span;
            int written = 0;
            for(int i = 0; i < attributes.Count; ++i)
            {
                attributes[i].AsReadOnlySpan().CopyTo(destination[written..]);
                written += attributes[i].Length;
            }

            return new PooledMemory(owner, written, CryptoTags.CmsEncodedAttribute);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Encodes the attributes as a complete DER <c>[1] IMPLICIT SET OF Attribute</c>, the form appended when
    /// the <c>SignerInfo</c> has no <c>unsignedAttrs</c> field yet.
    /// </summary>
    /// <param name="attributes">The attributes the new set holds.</param>
    /// <param name="pool">The memory pool the buffer is rented from.</param>
    /// <returns>The encoded set. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static PooledMemory EncodeUnsignedAttributesSet(IReadOnlyList<CmsAttribute> attributes, MemoryPool<byte> pool)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSetOf(ContextConstructed1))
        {
            for(int i = 0; i < attributes.Count; ++i)
            {
                writer.WriteEncodedValue(attributes[i].AsReadOnlySpan());
            }
        }

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out int written);

            return new PooledMemory(owner, written, CryptoTags.CmsEncodedAttribute);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Writes a container's length octets: the indefinite-length octet when the container had one, otherwise
    /// the new content length in the number of octets chosen for it.
    /// </summary>
    /// <param name="destination">The output span positioned at the first length octet.</param>
    /// <param name="contentLength">The container's new content length.</param>
    /// <param name="lengthOctetCount">The number of length octets to write.</param>
    /// <param name="isIndefinite">Whether the container carried an indefinite length.</param>
    /// <returns>The number of octets written.</returns>
    /// <remarks>Visible to <see cref="CmsSignedDataReduction"/>, whose containers shrink where these grow.</remarks>
    internal static int WriteLength(Span<byte> destination, int contentLength, int lengthOctetCount, bool isIndefinite)
    {
        if(isIndefinite)
        {
            destination[0] = IndefiniteLengthOctet;

            return 1;
        }

        if(lengthOctetCount == 1)
        {
            destination[0] = (byte)contentLength;

            return 1;
        }

        int valueOctetCount = lengthOctetCount - 1;
        destination[0] = (byte)(LongFormLengthFlag | valueOctetCount);
        for(int i = 0; i < valueOctetCount; ++i)
        {
            destination[1 + i] = (byte)(contentLength >>> (8 * (valueOctetCount - 1 - i)));
        }

        return lengthOctetCount;
    }


    /// <summary>
    /// Chooses how many octets a container's new length is written in: the count it already used when that
    /// still holds the new length — which keeps a definite-length header the same size, and keeps a
    /// non-minimal BER length exactly as it was — and otherwise the minimal count DER prescribes. For a
    /// container that was already minimal, the new length's minimal count is what this returns.
    /// </summary>
    /// <param name="newContentLength">The container's new content length.</param>
    /// <param name="originalLengthOctetCount">The number of length octets the container was encoded with.</param>
    /// <returns>The number of length octets to write.</returns>
    private static int ChooseLengthOctetCount(int newContentLength, int originalLengthOctetCount)
    {
        int minimal = MinimalLengthOctetCount(newContentLength);

        return originalLengthOctetCount >= minimal ? originalLengthOctetCount : minimal;
    }


    /// <summary>
    /// The number of octets DER's minimal length encoding uses for a content length (X.690 clause 8.1.3).
    /// </summary>
    /// <param name="contentLength">The content length.</param>
    /// <returns>The octet count, including the leading long-form octet when one is needed.</returns>
    /// <remarks>
    /// Visible to <see cref="CmsSignedDataReduction"/>, which re-derives a shrinking container's length in
    /// exactly this count — the inverse of what an insertion grew it to.
    /// </remarks>
    internal static int MinimalLengthOctetCount(int contentLength) => contentLength switch
    {
        < 0x80 => 1,
        <= 0xFF => 2,
        <= 0xFFFF => 3,
        <= 0xFFFFFF => 4,
        _ => 5
    };


    /// <summary>
    /// One located element of the Signed Data Object: where its tag, length, and content octets are, whether
    /// it carried an indefinite length, and what its tag is.
    /// </summary>
    /// <param name="Start">The offset of the first tag octet.</param>
    /// <param name="TagLength">The number of tag octets.</param>
    /// <param name="HeaderLength">The number of tag and length octets together.</param>
    /// <param name="ContentStart">The offset of the first content octet.</param>
    /// <param name="ContentLength">The number of content octets.</param>
    /// <param name="ContentEnd">The offset one past the last content octet, before any end-of-contents octets.</param>
    /// <param name="End">The offset one past the whole element, end-of-contents octets included.</param>
    /// <param name="IsIndefinite">Whether the element carried a BER indefinite length.</param>
    /// <param name="Tag">The element's tag.</param>
    /// <remarks>Visible to <see cref="CmsSignedDataReduction"/>, which addresses the same located elements.</remarks>
    internal readonly record struct CmsElement(
        int Start,
        int TagLength,
        int HeaderLength,
        int ContentStart,
        int ContentLength,
        int ContentEnd,
        int End,
        bool IsIndefinite,
        Asn1Tag Tag);


    /// <summary>
    /// The result of the walk: the containers enclosing the insertion point, outermost first, and the offset
    /// the new octets go at.
    /// </summary>
    /// <param name="Chain">The enclosing containers, outermost first; only the first <paramref name="ChainLength"/> entries are meaningful.</param>
    /// <param name="ChainLength">The number of meaningful entries in <paramref name="Chain"/>.</param>
    /// <param name="InsertionOffset">The offset in the input the new octets are inserted at.</param>
    /// <param name="HasUnsignedAttributes">Whether the chosen <c>SignerInfo</c> already carries an <c>unsignedAttrs</c> set.</param>
    /// <param name="UnsignedAttributes">The <c>unsignedAttrs</c> set, meaningful only when <paramref name="HasUnsignedAttributes"/> holds.</param>
    /// <param name="SignatureValue">The chosen <c>SignerInfo</c>'s <c>signature</c> OCTET STRING.</param>
    /// <remarks>Visible to <see cref="CmsSignedDataReduction"/>, which splices the same chain the other way.</remarks>
    internal readonly record struct SpliceTarget(
        CmsElement[] Chain,
        int ChainLength,
        int InsertionOffset,
        bool HasUnsignedAttributes,
        CmsElement UnsignedAttributes,
        CmsElement SignatureValue);


    /// <summary>
    /// The located fields of the outer envelope: every container a splice lengthens, and the two optional sets
    /// long-term validation material is placed in (RFC 5652 §5.1).
    /// </summary>
    /// <param name="ContentInfo">The outer <c>ContentInfo</c> SEQUENCE.</param>
    /// <param name="ExplicitContent">The <c>[0] EXPLICIT</c> content field of the <c>ContentInfo</c>.</param>
    /// <param name="SignedData">The <c>SignedData</c> SEQUENCE.</param>
    /// <param name="Version">The <c>version</c> <c>CMSVersion</c> INTEGER, the first field of the <c>SignedData</c>, whose one content octet a validation-data placement raises to 5 when it adds an other-format member (RFC 5652 §5.1).</param>
    /// <param name="DigestAlgorithms">The <c>digestAlgorithms</c> SET, which a parallel-signer addition unions the new signer's digest algorithm into (RFC 5652 §5.1: "the collection of message digest algorithms" is "intended to list" each signer's).</param>
    /// <param name="EncapContentInfo">The <c>encapContentInfo</c> SEQUENCE, which the optional sets follow.</param>
    /// <param name="Certificates">The <c>certificates [0] IMPLICIT</c> set, meaningful only when <paramref name="HasCertificates"/> holds.</param>
    /// <param name="HasCertificates">Whether the <c>SignedData</c> carries a <c>certificates</c> field.</param>
    /// <param name="RevocationInformation">The <c>crls [1] IMPLICIT</c> set, meaningful only when <paramref name="HasRevocationInformation"/> holds.</param>
    /// <param name="HasRevocationInformation">Whether the <c>SignedData</c> carries a <c>crls</c> field.</param>
    /// <param name="SignerInfos">The final <c>signerInfos</c> set.</param>
    private readonly record struct SignedDataLayout(
        CmsElement ContentInfo,
        CmsElement ExplicitContent,
        CmsElement SignedData,
        CmsElement Version,
        CmsElement DigestAlgorithms,
        CmsElement EncapContentInfo,
        CmsElement Certificates,
        bool HasCertificates,
        CmsElement RevocationInformation,
        bool HasRevocationInformation,
        CmsElement SignerInfos);


    /// <summary>
    /// One located <c>AttributeValue</c> of an unsigned attribute, with the two containers a replacement of it
    /// has to lengthen.
    /// </summary>
    /// <param name="AttributeIndex">The zero-based index of the <c>Attribute</c> within the <c>unsignedAttrs</c> set.</param>
    /// <param name="ValueIndex">The zero-based index of the value within that attribute's <c>attrValues</c> set.</param>
    /// <param name="AttributeType">The attribute's <c>attrType</c> object identifier.</param>
    /// <param name="Value">The <c>AttributeValue</c> itself.</param>
    /// <param name="Attribute">The <c>Attribute</c> SEQUENCE enclosing it.</param>
    /// <param name="Values">The <c>attrValues</c> SET enclosing it.</param>
    /// <remarks>Visible to <see cref="CmsSignedDataReduction"/>, which removes the sites this describes.</remarks>
    internal readonly record struct UnsignedAttributeValueSite(
        int AttributeIndex,
        int ValueIndex,
        string AttributeType,
        CmsElement Value,
        CmsElement Attribute,
        CmsElement Values);
}


/// <summary>
/// Where one <c>AttributeValue</c> of one unsigned attribute sits within a <c>SignerInfo</c>: which attribute
/// of the <c>unsignedAttrs</c> set carries it, which of that attribute's values it is, and what attribute type
/// the attribute states (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC 5652 §5.3</see>).
/// </summary>
/// <param name="AttributeIndex">The zero-based index of the <c>Attribute</c> within the <c>unsignedAttrs</c> set, in encoding order.</param>
/// <param name="ValueIndex">The zero-based index of the <c>AttributeValue</c> within that attribute's <c>attrValues</c> set, in encoding order.</param>
/// <param name="AttributeType">The attribute's <c>attrType</c> object identifier in dotted-decimal form.</param>
/// <remarks>
/// The indices address a value without exposing where its octets are, which is what
/// <see cref="CmsSignedDataAugmentation.ReadUnsignedAttributeValue"/> and
/// <see cref="CmsSignedDataAugmentation.ReplaceUnsignedAttributeValue"/> take: the walk that produced the
/// location is repeated rather than an offset into a buffer being handed around.
/// </remarks>
[DebuggerDisplay("CmsUnsignedAttributeValueLocation({AttributeType}, attribute {AttributeIndex}, value {ValueIndex})")]
public readonly record struct CmsUnsignedAttributeValueLocation(int AttributeIndex, int ValueIndex, string AttributeType);


/// <summary>
/// What <c>SignedData.encapContentInfo</c> states (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.2">
/// RFC 5652 §5.2</see>): the content type, and — for the attached form — the <c>eContent</c> octets a signer's
/// <c>message-digest</c> attribute is computed over.
/// </summary>
/// <param name="ContentType">The <c>eContentType</c> object identifier in dotted-decimal form.</param>
/// <param name="Content">A view of the <c>eContent</c> OCTET STRING content octets within the Signed Data Object's own memory, valid while that carrier is; <see langword="null"/> for the detached form, whose content travels by other means (§5.2).</param>
[DebuggerDisplay("CmsEncapsulatedContent({ContentType}, {Content == null ? \"detached\" : \"attached\",nq})")]
public readonly record struct CmsEncapsulatedContent(string ContentType, ReadOnlyMemory<byte>? Content);

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using CmsElement = Verifiable.Cryptography.Pki.CmsSignedDataAugmentation.CmsElement;
using SpliceTarget = Verifiable.Cryptography.Pki.CmsSignedDataAugmentation.SpliceTarget;
using UnsignedAttributeValueSite = Verifiable.Cryptography.Pki.CmsSignedDataAugmentation.UnsignedAttributeValueSite;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Removes unsigned attribute values from an existing CMS <c>SignedData</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC 5652 §5.3</see>) while every octet that
/// is not part of what was removed, and not a length octet of a container that had to shrink, stays
/// bit-identical — the inverse of <see cref="CmsSignedDataAugmentation.AppendUnsignedAttributes"/> and the
/// operation <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">IETF RFC 4998 Appendix A</see>
/// requires before an embedded Evidence Record can be verified.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What the appendix asks for.</strong> "In case of verification, if only one EvidenceRecord is
/// contained in the CMS object, the hash value must be generated over the CMS object without the one
/// EvidenceRecord. This means that the attribute has to be removed before verification. The length of fields
/// containing tags has to be adapted. Apart from that, the existing coding must not be modified." The middle
/// sentence is doing quiet work: a definite-length encoding states an exact octet count in every enclosing
/// container, so removing octets from an <c>unsignedAttrs</c> set shortens that set, its <c>SignerInfo</c>, the
/// <c>signerInfos</c> set, the <c>SignedData</c>, the <c>[0]</c> content field and the outer
/// <c>ContentInfo</c> — a re-derivation cascade up every ancestor whose length changed, and nothing else.
/// </para>
/// <para>
/// <strong>Why the lengths are re-derived minimally.</strong> This operation is the exact inverse of the
/// appending splice, and that splice writes a container's new length in the minimal number of octets whenever
/// the count it had no longer holds it. Undoing an append therefore means writing the minimal count again. A
/// container whose <em>original</em> definite length is written in more octets than X.690 clause 8.1.3.3 needs
/// is refused rather than guessed at: nothing states whether the coding before the attribute was added was the
/// same non-minimal count or the minimal one, and Appendix A forbids modifying the existing coding, so a
/// reconstruction that had to pick would not be a reconstruction.
/// </para>
/// <para>
/// <strong>Indefinite-length containers are passed through untouched.</strong> An indefinite-length container
/// states no length to re-derive; its end-of-contents octets already close whatever it holds, so its header
/// survives verbatim and the shrink flows outward to the next definite-length container. Third-party CMS
/// objects carrying Evidence Records really are encoded this way, and their records only verify when those
/// <c>0x80</c> length octets are left exactly as they are — the same preservation
/// <see cref="CmsSignedDataAugmentation"/> applies from the other direction.
/// </para>
/// <para>
/// <strong>An emptied container disappears rather than being written empty.</strong> Removing every value of an
/// <c>Attribute</c> removes the whole <c>Attribute</c>, because <c>attrValues</c> is a
/// <c>SET SIZE (1..MAX)</c>; removing every <c>Attribute</c> of the <c>unsignedAttrs</c> set removes the whole
/// optional <c>[1] IMPLICIT</c> field, because <c>UnsignedAttributes</c> is a <c>SET SIZE (1..MAX)</c> too and
/// because a field that was created by the append being undone did not exist before it. Third-party objects
/// whose Evidence Record attribute is the only unsigned attribute confirm this reading: their records bind the
/// object with the field gone, not with an empty set in its place.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> The Signed Data Object arrives from a network location or a
/// document. Every structure is read through the same bounded, non-recursive walk the appending splice uses,
/// the number of removed values is bounded, a structure that cannot be walked yields a typed failure and no
/// output at all, and a request to remove a value the structure does not carry is refused rather than ignored.
/// </para>
/// </remarks>
public static class CmsSignedDataReduction
{
    /// <summary>The largest number of attribute values one call removes, bounding the work a single reduction costs.</summary>
    private const int MaximumRemovedValues = 64;

    /// <summary>The largest number of unsigned attributes counted while deciding whether the whole set is being emptied.</summary>
    private const int MaximumUnsignedAttributes = 64;

    /// <summary>The largest number of <c>SignerInfo</c> structures the per-signer projection walks, matching the bound the augmentation surface traverses the same set within.</summary>
    private const int MaximumSignerInfos = 64;


    /// <summary>
    /// Produces the Signed Data Object that stands after the addressed unsigned attribute values have been
    /// removed, with the definite lengths of every container whose content shrank re-derived and every other
    /// octet of the input carried through unchanged.
    /// </summary>
    /// <param name="signedData">The Signed Data Object to reduce. Not modified; the result is a new carrier.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> within <c>SignedData.signerInfos</c>.</param>
    /// <param name="locations">The values to remove, as <see cref="CmsSignedDataAugmentation.LocateUnsignedAttributeValues"/> reports them. An empty list produces a copy of the input.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The reduced Signed Data Object. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/>, <paramref name="locations"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative or a location carries a negative index.</exception>
    /// <exception cref="ArgumentException">When more values than this operation removes in one call are addressed.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a <c>SignerInfo</c> at that index, it carries no <c>unsignedAttrs</c> field, an addressed value is not there, or a container whose length has to be re-derived carries a non-minimally encoded definite length.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries octets after the outer ContentInfo, or exceeds the bounds this walk stays within.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    public static CmsSignedData RemoveUnsignedAttributeValues(
        CmsSignedData signedData,
        int signerIndex,
        IReadOnlyList<CmsUnsignedAttributeValueLocation> locations,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(locations);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);
        if(locations.Count > MaximumRemovedValues)
        {
            throw new ArgumentException($"A reduction removes at most {MaximumRemovedValues} unsigned attribute values in one call.", nameof(locations));
        }

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();
        if(locations.Count == 0)
        {
            return CmsSignedData.FromBytes(source, pool);
        }

        SpliceTarget target = CmsSignedDataAugmentation.LocateTarget(source, signerIndex);
        if(!target.HasUnsignedAttributes)
        {
            throw new CryptographicException("The CMS SignerInfo carries no unsignedAttrs field, so there is no attribute value to remove (RFC 5652 §5.3).");
        }

        List<UnsignedAttributeValueSite> sites = CmsSignedDataAugmentation.WalkUnsignedAttributeValues(source, target.UnsignedAttributes);
        bool[] removed = SelectRemovedSites(sites, locations);

        //An Attribute survives only when at least one of its values does; the whole unsignedAttrs field survives
        //only when at least one Attribute does. Both containers are SET SIZE (1..MAX), so an emptied one is not
        //written empty — it is not written at all.
        int attributeCount = CountAttributes(source, target.UnsignedAttributes);
        var partial = new List<PartialAttribute>();
        var edits = new List<ReductionEdit>();
        int emptiedAttributeCount = 0;
        int attributeIndex = 0;
        while(attributeIndex < attributeCount)
        {
            int total = 0;
            int removedHere = 0;
            int valuesShrink = 0;
            UnsignedAttributeValueSite first = default;
            for(int i = 0; i < sites.Count; ++i)
            {
                if(sites[i].AttributeIndex != attributeIndex)
                {
                    continue;
                }

                if(total == 0)
                {
                    first = sites[i];
                }

                ++total;
                if(removed[i])
                {
                    ++removedHere;
                    valuesShrink += sites[i].Value.End - sites[i].Value.Start;
                }
            }

            if(removedHere == 0)
            {
                ++attributeIndex;

                continue;
            }

            if(removedHere == total)
            {
                edits.Add(ReductionEdit.Removal(first.Attribute.Start, first.Attribute.End));
                ++emptiedAttributeCount;
                ++attributeIndex;

                continue;
            }

            for(int i = 0; i < sites.Count; ++i)
            {
                if(sites[i].AttributeIndex == attributeIndex && removed[i])
                {
                    edits.Add(ReductionEdit.Removal(sites[i].Value.Start, sites[i].Value.End));
                }
            }

            partial.Add(new PartialAttribute(first.Attribute, first.Values, valuesShrink));
            ++attributeIndex;
        }

        bool wholeFieldGoes = emptiedAttributeCount == attributeCount && partial.Count == 0;

        //The chain the shrink cascades up: the outer envelope down to the unsignedAttrs set, or one container
        //less when that set is itself what disappears.
        int chainLength = wholeFieldGoes ? target.ChainLength - 1 : target.ChainLength;
        int shrink;
        if(wholeFieldGoes)
        {
            edits.Clear();
            edits.Add(ReductionEdit.Removal(target.UnsignedAttributes.Start, target.UnsignedAttributes.End));
            shrink = target.UnsignedAttributes.End - target.UnsignedAttributes.Start;
        }
        else
        {
            shrink = 0;
            for(int i = 0; i < edits.Count; ++i)
            {
                shrink += edits[i].End - edits[i].Start;
            }

            //Each partially emptied Attribute shrinks its own attrValues SET and then itself, and the header
            //octets those two containers give up shrink the unsignedAttrs set by that much more.
            for(int i = 0; i < partial.Count; ++i)
            {
                ReductionEdit values = RewriteHeader(partial[i].Values, partial[i].ValuesShrink);
                int valuesHeaderShrink = partial[i].Values.HeaderLength - HeaderLength(partial[i].Values, values);
                ReductionEdit attribute = RewriteHeader(partial[i].Attribute, partial[i].ValuesShrink + valuesHeaderShrink);
                shrink += valuesHeaderShrink + (partial[i].Attribute.HeaderLength - HeaderLength(partial[i].Attribute, attribute));
                edits.Add(values);
                edits.Add(attribute);
            }
        }

        return ApplyReduction(source, edits, target.Chain, chainLength, shrink, pool);
    }


    /// <summary>
    /// Produces the Signed Data Object that carries only the addressed <c>SignerInfo</c>, every other member of
    /// <c>signerInfos</c> removed and every remaining octet the input's own — the per-signer projection that
    /// lets a single-signature verifier (a registered <see cref="VerifyCmsSignedDataDelegate"/> backend) verify
    /// exactly the addressed signer of a multi-signer structure
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see>).
    /// </summary>
    /// <param name="signedData">The Signed Data Object to project. Not modified; the result is a new carrier.</param>
    /// <param name="signerIndex">The zero-based index of the <c>SignerInfo</c> to keep, in encoding order.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The projected Signed Data Object, or an untouched copy when the addressed signer is already the only one. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="signedData"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="signerIndex"/> is negative.</exception>
    /// <exception cref="CryptographicException">When the input is not a CMS SignedData holding a <c>SignerInfo</c> at that index, or a container whose length has to be re-derived carries a non-minimally encoded definite length.</exception>
    /// <exception cref="AsnContentException">When the input is malformed, truncated, carries octets after the outer ContentInfo, or exceeds the bounds this walk stays within.</exception>
    /// <remarks>
    /// <para>
    /// <strong>Why a projection and not a wider verify seam.</strong> Each <c>SignerInfo</c> stands alone:
    /// its signature covers its own signed attributes and the shared encapsulated content, never a sibling
    /// (RFC 5652 §5.4/§5.6), and ETSI EN 319 102-1 validates one signature at a time. Keeping one member and
    /// removing the others therefore changes no octet any remaining signature covers, and every already
    /// registered backend verifies the addressed signer with no seam change.
    /// </para>
    /// <para>
    /// <strong>What stays.</strong> <c>digestAlgorithms</c> and <c>certificates</c> keep every member,
    /// including those only the removed signers used: RFC 5652 §5.1 words both as collections that may hold
    /// more than a reader needs, and removing only the sibling <c>SignerInfo</c> members keeps this walk to
    /// the one set it addresses. Removing members of a DER-sorted <c>signerInfos</c> set leaves it DER-sorted;
    /// a BER structure keeps its members' order the same way.
    /// </para>
    /// <para>
    /// The projection serves verification addressing. It is not the structure whole-object evidence was
    /// computed over — an archive time-stamp or Evidence Record covering the full multi-signer octets is
    /// verified against those octets, not against a projection.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the write pass disposes it on a partial failure.")]
    public static CmsSignedData SelectSigner(CmsSignedData signedData, int signerIndex, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signedData);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);

        ReadOnlySpan<byte> source = signedData.AsReadOnlySpan();

        //The insertion walk locates the same containers a removal has to shrink and refuses an index the
        //structure does not carry; its chain holds the outer envelope down to the signerInfos set.
        SpliceTarget target = CmsSignedDataAugmentation.LocateTarget(source, signerIndex);
        CmsElement signerInfos = target.Chain[3];

        var edits = new List<ReductionEdit>();
        int shrink = 0;
        int memberIndex = 0;
        int position = signerInfos.ContentStart;
        while(position < signerInfos.ContentEnd)
        {
            if(memberIndex == MaximumSignerInfos)
            {
                throw new AsnContentException($"A CMS 'signerInfos' field is walked with at most {MaximumSignerInfos} members.");
            }

            CmsElement member = CmsSignedDataAugmentation.ReadElement(source, position, signerInfos.ContentEnd);
            if(member.Tag != Asn1Tag.Sequence)
            {
                throw new CryptographicException("A CMS signerInfos set holds SignerInfo SEQUENCE structures (RFC 5652 §5.1).");
            }

            if(memberIndex != signerIndex)
            {
                edits.Add(ReductionEdit.Removal(member.Start, member.End));
                shrink += member.End - member.Start;
            }

            position = member.End;
            ++memberIndex;
        }

        if(edits.Count == 0)
        {
            //The addressed signer is already the only member, so the projection is the input itself; the copy
            //keeps the caller's ownership contract the same either way.
            return CmsSignedData.FromBytes(source, pool);
        }

        //The chain the shrink cascades up ends at the signerInfos set: the kept member and everything outside
        //the removed regions is copied verbatim.
        return ApplyReduction(source, edits, target.Chain, chainLength: 4, shrink, pool);
    }


    /// <summary>
    /// Applies assembled removal and header-rewrite edits: cascades the shrink up the enclosing
    /// <paramref name="chain"/>, orders every edit by offset, and writes the output with each unedited octet
    /// of the input carried through unchanged.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="edits">The removals and inner header rewrites; this call adds the chain's own rewrites.</param>
    /// <param name="chain">The containers enclosing the edited region, outermost first.</param>
    /// <param name="chainLength">The number of meaningful entries in <paramref name="chain"/>.</param>
    /// <param name="shrink">The number of content octets the innermost enclosing container loses.</param>
    /// <param name="pool">The memory pool the result is rented from.</param>
    /// <returns>The reduced Signed Data Object. The caller owns and disposes it.</returns>
    /// <exception cref="CryptographicException">When a container whose length has to be re-derived carries a non-minimally encoded definite length.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned carrier, which the caller disposes; the catch disposes it on a partial failure.")]
    private static CmsSignedData ApplyReduction(
        ReadOnlySpan<byte> source,
        List<ReductionEdit> edits,
        CmsElement[] chain,
        int chainLength,
        int shrink,
        MemoryPool<byte> pool)
    {
        int growth = -shrink;
        for(int i = chainLength - 1; i >= 0; --i)
        {
            CmsElement element = chain[i];
            if(element.IsIndefinite)
            {
                //An indefinite-length container states no length to re-derive, so its header is not an edit at
                //all and the shrink passes through it unchanged.
                continue;
            }

            ReductionEdit rewritten = RewriteHeader(element, -growth);
            growth += element.TagLength + rewritten.NewLengthOctetCount - element.HeaderLength;
            edits.Add(rewritten);
        }

        edits.Sort(static (left, right) => left.Start.CompareTo(right.Start));

        int outputLength = source.Length + growth;
        IMemoryOwner<byte> owner = pool.Rent(outputLength);
        try
        {
            Span<byte> output = owner.Memory.Span[..outputLength];
            int written = 0;
            int read = 0;
            for(int i = 0; i < edits.Count; ++i)
            {
                ReductionEdit edit = edits[i];
                source[read..edit.Start].CopyTo(output[written..]);
                written += edit.Start - read;
                if(!edit.IsRemoval)
                {
                    source.Slice(edit.Start, edit.TagLength).CopyTo(output[written..]);
                    written += edit.TagLength;
                    written += CmsSignedDataAugmentation.WriteLength(output[written..], edit.NewContentLength, edit.NewLengthOctetCount, edit.IsIndefinite);
                }

                read = edit.End;
            }

            source[read..].CopyTo(output[written..]);
            written += source.Length - read;

            Debug.Assert(written == outputLength, "The reduced output fills exactly the length the chain re-derivation predicted.");

            return new CmsSignedData(owner, CryptoTags.CmsEncodedSignedData);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Marks which of the walked sites the caller addressed, refusing an address the structure does not carry.
    /// </summary>
    /// <param name="sites">Every attribute value the signer carries, in encoding order.</param>
    /// <param name="locations">The addressed values.</param>
    /// <returns>One flag per site, set for the addressed ones.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a location carries a negative index.</exception>
    /// <exception cref="CryptographicException">When a location addresses a value the signer does not carry.</exception>
    private static bool[] SelectRemovedSites(List<UnsignedAttributeValueSite> sites, IReadOnlyList<CmsUnsignedAttributeValueLocation> locations)
    {
        bool[] removed = new bool[sites.Count];
        for(int i = 0; i < locations.Count; ++i)
        {
            CmsUnsignedAttributeValueLocation location = locations[i];
            ArgumentOutOfRangeException.ThrowIfNegative(location.AttributeIndex, nameof(locations));
            ArgumentOutOfRangeException.ThrowIfNegative(location.ValueIndex, nameof(locations));

            bool found = false;
            for(int j = 0; j < sites.Count && !found; ++j)
            {
                if(sites[j].AttributeIndex == location.AttributeIndex && sites[j].ValueIndex == location.ValueIndex)
                {
                    removed[j] = true;
                    found = true;
                }
            }

            if(!found)
            {
                throw new CryptographicException(
                    $"The CMS SignerInfo carries no unsigned attribute {location.AttributeIndex} with a value {location.ValueIndex} to remove (RFC 5652 §5.3).");
            }
        }

        return removed;
    }


    /// <summary>
    /// Counts the <c>Attribute</c> structures an <c>unsignedAttrs</c> set holds, including any that carry no
    /// value at all — a shape the syntax forbids but an attacker-supplied structure may still state, and one
    /// that would otherwise make an emptied set look emptier than it is.
    /// </summary>
    /// <param name="source">The Signed Data Object octets.</param>
    /// <param name="unsignedAttributes">The <c>unsignedAttrs</c> set.</param>
    /// <returns>The number of attributes.</returns>
    /// <exception cref="AsnContentException">When the set is malformed or holds more attributes than this walk stays within.</exception>
    private static int CountAttributes(ReadOnlySpan<byte> source, CmsElement unsignedAttributes)
    {
        int count = 0;
        int position = unsignedAttributes.ContentStart;
        while(position < unsignedAttributes.ContentEnd)
        {
            if(count == MaximumUnsignedAttributes)
            {
                throw new AsnContentException($"A CMS unsignedAttrs set is walked with at most {MaximumUnsignedAttributes} attributes.");
            }

            CmsElement attribute = CmsSignedDataAugmentation.ReadElement(source, position, unsignedAttributes.ContentEnd);
            ++count;
            position = attribute.End;
        }

        return count;
    }


    /// <summary>
    /// Produces the header rewrite one shrinking container needs: its tag octets stay, its definite length is
    /// re-derived minimally for the content it has left, and an indefinite length is left as it stands.
    /// </summary>
    /// <param name="element">The container.</param>
    /// <param name="contentShrink">How many content octets the container loses.</param>
    /// <returns>The edit that rewrites the container's header.</returns>
    /// <exception cref="CryptographicException">When the container carries a non-minimally encoded definite length.</exception>
    private static ReductionEdit RewriteHeader(CmsElement element, int contentShrink)
    {
        if(element.IsIndefinite)
        {
            return new ReductionEdit(element.Start, element.ContentStart, element.TagLength, element.ContentLength, element.HeaderLength - element.TagLength, IsIndefinite: true, IsRemoval: false);
        }

        RequireMinimalLength(element);
        int newContentLength = element.ContentLength - contentShrink;

        return new ReductionEdit(
            element.Start,
            element.ContentStart,
            element.TagLength,
            newContentLength,
            CmsSignedDataAugmentation.MinimalLengthOctetCount(newContentLength),
            IsIndefinite: false,
            IsRemoval: false);
    }


    /// <summary>
    /// The header length one rewritten container ends up with.
    /// </summary>
    /// <param name="element">The container as it stands.</param>
    /// <param name="edit">The rewrite of its header.</param>
    /// <returns>The number of tag and length octets the rewritten header occupies.</returns>
    private static int HeaderLength(CmsElement element, ReductionEdit edit) =>
        element.IsIndefinite ? element.HeaderLength : edit.TagLength + edit.NewLengthOctetCount;


    /// <summary>
    /// Refuses a container whose definite length is written in more octets than X.690 clause 8.1.3.3 requires,
    /// because the coding that stood before the removed octets were added cannot then be reconstructed: RFC 4998
    /// Appendix A permits adapting the length of fields containing tags and nothing else, and a non-minimal
    /// length leaves the adapted value ambiguous.
    /// </summary>
    /// <param name="element">The container.</param>
    /// <exception cref="CryptographicException">When the length is definite and non-minimally encoded.</exception>
    private static void RequireMinimalLength(CmsElement element)
    {
        if(element.IsIndefinite)
        {
            return;
        }

        int lengthOctetCount = element.HeaderLength - element.TagLength;
        if(lengthOctetCount != CmsSignedDataAugmentation.MinimalLengthOctetCount(element.ContentLength))
        {
            throw new CryptographicException(
                "A container whose length has to be re-derived carries a non-minimally encoded definite length, which leaves the coding before the removal ambiguous (RFC 4998 Appendix A; X.690 clause 8.1.3.3).");
        }
    }


    /// <summary>
    /// One partially emptied <c>Attribute</c>: the containers that shrink and by how much their content does.
    /// </summary>
    /// <param name="Attribute">The <c>Attribute</c> SEQUENCE.</param>
    /// <param name="Values">Its <c>attrValues</c> SET.</param>
    /// <param name="ValuesShrink">The number of content octets the <c>attrValues</c> SET loses.</param>
    private readonly record struct PartialAttribute(CmsElement Attribute, CmsElement Values, int ValuesShrink);


    /// <summary>
    /// One edit the write pass applies at an offset of the input: either a region that is not copied through,
    /// or a container header that is rewritten with a re-derived length.
    /// </summary>
    /// <param name="Start">The offset the edit begins at.</param>
    /// <param name="End">The offset the write pass resumes copying from.</param>
    /// <param name="TagLength">The number of tag octets copied through for a header rewrite.</param>
    /// <param name="NewContentLength">The content length a rewritten header states.</param>
    /// <param name="NewLengthOctetCount">The number of length octets a rewritten header is written in.</param>
    /// <param name="IsIndefinite">Whether a rewritten header carried a BER indefinite length.</param>
    /// <param name="IsRemoval">Whether the edit removes the region instead of rewriting a header.</param>
    [DebuggerDisplay("ReductionEdit({Start}..{End}, removal={IsRemoval})")]
    private readonly record struct ReductionEdit(
        int Start,
        int End,
        int TagLength,
        int NewContentLength,
        int NewLengthOctetCount,
        bool IsIndefinite,
        bool IsRemoval)
    {
        /// <summary>
        /// The edit that removes a region of the input.
        /// </summary>
        /// <param name="start">The offset of the first removed octet.</param>
        /// <param name="end">The offset one past the last removed octet.</param>
        /// <returns>The edit.</returns>
        internal static ReductionEdit Removal(int start, int end) =>
            new(start, end, TagLength: 0, NewContentLength: 0, NewLengthOctetCount: 0, IsIndefinite: false, IsRemoval: true);
    }
}

using System;
using System.Collections.Generic;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The bounds of one tag-length-value element inside a CMS structure, as the independent
/// <see cref="CmsStructureOracle"/> walker reports them.
/// </summary>
/// <param name="Start">The offset of the first tag octet.</param>
/// <param name="TagLength">The number of tag octets.</param>
/// <param name="HeaderLength">The number of tag and length octets together.</param>
/// <param name="ContentStart">The offset of the first content octet.</param>
/// <param name="ContentLength">The number of content octets.</param>
/// <param name="ContentEnd">The offset one past the last content octet, before any end-of-contents octets.</param>
/// <param name="End">The offset one past the whole element, end-of-contents octets included.</param>
/// <param name="IsIndefinite">Whether the element carried a BER indefinite length.</param>
internal readonly record struct CmsTlvBounds(
    int Start,
    int TagLength,
    int HeaderLength,
    int ContentStart,
    int ContentLength,
    int ContentEnd,
    int End,
    bool IsIndefinite);


/// <summary>
/// An independent walker over the octets of a CMS SignedData, written for the augmentation tests from the
/// X.690 encoding rules and the RFC 5652 §5 structure alone: it parses tag and length octets by hand and
/// navigates by position (the content is the last field of a ContentInfo, the SignedData is the only field of
/// that content, the signerInfos set is the last field of the SignedData, and the unsignedAttrs set is the
/// last field of a SignerInfo) rather than by calling the library surface under test.
/// </summary>
/// <remarks>
/// This exists so the byte-preservation assertions have their own notion of "which octets the augmentation is
/// allowed to rewrite". If it agreed with the production walker by construction it would assert nothing; it
/// therefore shares no code with it. It also mints the BER indefinite-length variant of a signature, so the
/// preservation of such wrappers can be tested against structures the framework's own DER signer never emits.
/// </remarks>
internal static class CmsStructureOracle
{
    /// <summary>The BER indefinite-length octet (X.690 clause 8.1.3.6).</summary>
    private const byte IndefiniteLengthOctet = 0x80;

    /// <summary>The <c>[0]</c> constructed context tag octet of a ContentInfo's content field.</summary>
    private const byte ContextConstructed0Octet = 0xA0;

    /// <summary>The <c>[1]</c> constructed context tag octet of a SignerInfo's unsignedAttrs field.</summary>
    private const byte ContextConstructed1Octet = 0xA1;


    /// <summary>
    /// Locates the containers that enclose the insertion point of an unsigned attribute for one signer,
    /// outermost first: the ContentInfo, its content field, the SignedData, the signerInfos set, the chosen
    /// SignerInfo, and, when the signer already has one, its unsignedAttrs set.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer.</param>
    /// <returns>The enclosing chain, outermost first.</returns>
    public static List<CmsTlvBounds> LocateLengthChain(byte[] signedData, int signerIndex)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        CmsTlvBounds contentInfo = ReadElement(signedData, 0);
        List<CmsTlvBounds> contentInfoChildren = Children(signedData, contentInfo);
        CmsTlvBounds content = contentInfoChildren[^1];
        CmsTlvBounds signedDataSequence = Children(signedData, content)[0];
        CmsTlvBounds signerInfos = Children(signedData, signedDataSequence)[^1];
        CmsTlvBounds signerInfo = Children(signedData, signerInfos)[signerIndex];

        var chain = new List<CmsTlvBounds>(6) { contentInfo, content, signedDataSequence, signerInfos, signerInfo };
        List<CmsTlvBounds> signerFields = Children(signedData, signerInfo);
        if(signedData[signerFields[^1].Start] == ContextConstructed1Octet)
        {
            chain.Add(signerFields[^1]);
        }

        return chain;
    }


    /// <summary>
    /// The offset new unsigned-attribute octets are inserted at for one signer: the end of the existing
    /// unsignedAttrs content when there is one, otherwise the end of the SignerInfo content.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer.</param>
    /// <returns>The insertion offset.</returns>
    public static int InsertionOffset(byte[] signedData, int signerIndex) =>
        LocateLengthChain(signedData, signerIndex)[^1].ContentEnd;


    /// <summary>
    /// The children of a constructed element, in the order they appear.
    /// </summary>
    /// <param name="buffer">The octets the element lives in.</param>
    /// <param name="parent">The constructed element.</param>
    /// <returns>The child elements.</returns>
    public static List<CmsTlvBounds> Children(byte[] buffer, CmsTlvBounds parent)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        var children = new List<CmsTlvBounds>();
        int position = parent.ContentStart;
        while(position < parent.ContentEnd)
        {
            CmsTlvBounds child = ReadElement(buffer, position);
            children.Add(child);
            position = child.End;
        }

        return children;
    }


    /// <summary>
    /// The SignerInfo fields of one signer, in the order they appear (RFC 5652 §5.3).
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer.</param>
    /// <returns>The SignerInfo's child elements.</returns>
    public static List<CmsTlvBounds> SignerFields(byte[] signedData, int signerIndex) =>
        Children(signedData, LocateLengthChain(signedData, signerIndex)[4]);


    /// <summary>
    /// The unsigned attributes of one signer, each as its own complete element, or an empty list when the
    /// signer carries no unsignedAttrs field.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer.</param>
    /// <returns>The unsigned attribute elements.</returns>
    public static List<CmsTlvBounds> UnsignedAttributes(byte[] signedData, int signerIndex)
    {
        List<CmsTlvBounds> chain = LocateLengthChain(signedData, signerIndex);

        return chain.Count == 6 ? Children(signedData, chain[^1]) : [];
    }


    /// <summary>
    /// Decides whether an augmented Signed Data Object preserved every octet of the original except the length
    /// octets of the containers that enclose the insertion point: each enclosing container's tag octets are
    /// compared, then the octets between one container's content start and the next container's tag start, then
    /// the octets from the insertion point to the end of the structure.
    /// </summary>
    /// <param name="original">The Signed Data Object before augmentation.</param>
    /// <param name="spliced">The Signed Data Object after augmentation.</param>
    /// <param name="signerIndex">The zero-based index of the signer that was augmented.</param>
    /// <returns><see langword="true"/> when every octet outside the enclosing containers' length octets is unchanged.</returns>
    public static bool PreservesEveryOctetOutsideTheLengthChain(byte[] original, byte[] spliced, int signerIndex)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(spliced);

        List<CmsTlvBounds> originalChain = LocateLengthChain(original, signerIndex);
        List<CmsTlvBounds> splicedChain = LocateLengthChain(spliced, signerIndex);
        if(splicedChain.Count < originalChain.Count)
        {
            return false;
        }

        int originalInsertion = originalChain[^1].ContentEnd;
        for(int i = 0; i < originalChain.Count; ++i)
        {
            if(originalChain[i].TagLength != splicedChain[i].TagLength)
            {
                return false;
            }

            if(!original.AsSpan(originalChain[i].Start, originalChain[i].TagLength).SequenceEqual(spliced.AsSpan(splicedChain[i].Start, splicedChain[i].TagLength)))
            {
                return false;
            }

            int segmentLength = i + 1 < originalChain.Count
                ? originalChain[i + 1].Start - originalChain[i].ContentStart
                : originalInsertion - originalChain[i].ContentStart;
            if(segmentLength < 0 || splicedChain[i].ContentStart + segmentLength > spliced.Length)
            {
                return false;
            }

            if(!original.AsSpan(originalChain[i].ContentStart, segmentLength).SequenceEqual(spliced.AsSpan(splicedChain[i].ContentStart, segmentLength)))
            {
                return false;
            }
        }

        int tailLength = original.Length - originalInsertion;

        return spliced.Length >= tailLength
            && original.AsSpan(originalInsertion, tailLength).SequenceEqual(spliced.AsSpan(spliced.Length - tailLength, tailLength));
    }


    /// <summary>
    /// Re-encodes the two outer wrappers of a Signed Data Object — the ContentInfo and its content field — as
    /// BER indefinite-length constructed values, leaving every inner octet exactly as it was. Structures like
    /// this occur in the wild; the framework's own signer emits definite-length DER only.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The same structure with indefinite-length outer wrappers.</returns>
    public static byte[] ToIndefiniteOuterWrappers(byte[] signedData)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        CmsTlvBounds contentInfo = ReadElement(signedData, 0);
        List<CmsTlvBounds> contentInfoChildren = Children(signedData, contentInfo);
        CmsTlvBounds contentType = contentInfoChildren[0];
        CmsTlvBounds content = contentInfoChildren[^1];

        ReadOnlySpan<byte> contentTypeOctets = signedData.AsSpan(contentType.Start, contentType.End - contentType.Start);
        ReadOnlySpan<byte> contentOctets = signedData.AsSpan(content.ContentStart, content.ContentEnd - content.ContentStart);

        var rewritten = new List<byte>(signedData.Length + 8)
        {
            signedData[contentInfo.Start],
            IndefiniteLengthOctet
        };

        rewritten.AddRange(contentTypeOctets);
        rewritten.Add(ContextConstructed0Octet);
        rewritten.Add(IndefiniteLengthOctet);
        rewritten.AddRange(contentOctets);
        rewritten.AddRange([0x00, 0x00, 0x00, 0x00]);

        return [.. rewritten];
    }


    /// <summary>
    /// Reads one element's full bounds, resolving an indefinite length by scanning forward to its matching
    /// end-of-contents octets.
    /// </summary>
    /// <param name="buffer">The octets the element lives in.</param>
    /// <param name="offset">The offset of the element's first tag octet.</param>
    /// <returns>The element's bounds.</returns>
    public static CmsTlvBounds ReadElement(byte[] buffer, int offset)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        CmsTlvBounds header = ReadHeader(buffer, offset);
        if(!header.IsIndefinite)
        {
            return header;
        }

        int contentEnd = FindEndOfContents(buffer, header.ContentStart);

        return header with { ContentLength = contentEnd - header.ContentStart, ContentEnd = contentEnd, End = contentEnd + 2 };
    }


    /// <summary>
    /// Reads one element's tag and length octets without resolving an indefinite length, so that the
    /// end-of-contents scan can use it without recursing.
    /// </summary>
    /// <param name="buffer">The octets the element lives in.</param>
    /// <param name="offset">The offset of the element's first tag octet.</param>
    /// <returns>The element's bounds, with the content end unresolved when the length is indefinite.</returns>
    private static CmsTlvBounds ReadHeader(byte[] buffer, int offset)
    {
        int tagLength = 1;
        if((buffer[offset] & 0x1F) == 0x1F)
        {
            while((buffer[offset + tagLength] & 0x80) != 0)
            {
                ++tagLength;
            }

            ++tagLength;
        }

        int lengthOffset = offset + tagLength;
        byte firstLengthOctet = buffer[lengthOffset];
        if(firstLengthOctet == IndefiniteLengthOctet)
        {
            int indefiniteContentStart = lengthOffset + 1;

            return new CmsTlvBounds(offset, tagLength, tagLength + 1, indefiniteContentStart, 0, indefiniteContentStart, indefiniteContentStart, true);
        }

        if(firstLengthOctet < IndefiniteLengthOctet)
        {
            int shortContentStart = lengthOffset + 1;

            return new CmsTlvBounds(offset, tagLength, tagLength + 1, shortContentStart, firstLengthOctet, shortContentStart + firstLengthOctet, shortContentStart + firstLengthOctet, false);
        }

        int lengthOctetCount = firstLengthOctet & 0x7F;
        int contentLength = 0;
        for(int i = 1; i <= lengthOctetCount; ++i)
        {
            contentLength = (contentLength << 8) | buffer[lengthOffset + i];
        }

        int contentStart = lengthOffset + 1 + lengthOctetCount;

        return new CmsTlvBounds(offset, tagLength, tagLength + 1 + lengthOctetCount, contentStart, contentLength, contentStart + contentLength, contentStart + contentLength, false);
    }


    /// <summary>
    /// Scans forward from an indefinite-length element's content start to its matching end-of-contents
    /// octets, counting nested indefinite-length elements with an explicit depth rather than recursion.
    /// </summary>
    /// <param name="buffer">The octets the element lives in.</param>
    /// <param name="contentStart">The offset of the first content octet.</param>
    /// <returns>The offset of the matching end-of-contents octets.</returns>
    private static int FindEndOfContents(byte[] buffer, int contentStart)
    {
        int position = contentStart;
        int depth = 0;
        while(true)
        {
            if(buffer[position] == 0x00 && buffer[position + 1] == 0x00)
            {
                if(depth == 0)
                {
                    return position;
                }

                --depth;
                position += 2;

                continue;
            }

            CmsTlvBounds child = ReadHeader(buffer, position);
            if(child.IsIndefinite)
            {
                ++depth;
                position = child.ContentStart;

                continue;
            }

            position = child.ContentEnd;
        }
    }
}

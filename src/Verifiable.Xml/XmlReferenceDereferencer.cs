using System.Buffers;
using System.Text;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The outcome of dereferencing a <c>URI</c> attribute value: either the same-document node-set the URI
/// identifies, over the same <see cref="XmlNodeTable"/> the URI was resolved against, or the octets an
/// external URI resolved to through the caller's <see cref="XmlReferenceResolver"/>. Exactly one of
/// <see cref="NodeSet"/> and <see cref="ExternalOctets"/> is meaningful, selected by <see cref="IsNodeSet"/> —
/// the same two-shape data flow section 4.3.3.2 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> describes as "either an octet stream or an XPath node-set."
/// </summary>
/// <remarks>
/// A node-set result owns nothing: it is a view over the caller's already-open <see cref="XmlNodeTable"/>.
/// An external-octets result owns a <see cref="PooledMemory"/> the resolver rented, which the caller of
/// <see cref="XmlReferenceDereferencer.TryDereference"/> takes ownership of and must dispose once the
/// transform chain has consumed it.
/// </remarks>
internal readonly struct XmlDereferenceResult
{
    /// <summary>Whether the result is a node-set (<see langword="true"/>) or external octets (<see langword="false"/>).</summary>
    public bool IsNodeSet { get; }

    /// <summary>The node-set, meaningful only when <see cref="IsNodeSet"/> is <see langword="true"/>.</summary>
    public XmlNodeSet NodeSet { get; }

    /// <summary>The external octets, meaningful only when <see cref="IsNodeSet"/> is <see langword="false"/>.</summary>
    public PooledMemory? ExternalOctets { get; }


    private XmlDereferenceResult(bool isNodeSet, XmlNodeSet nodeSet, PooledMemory? externalOctets)
    {
        IsNodeSet = isNodeSet;
        NodeSet = nodeSet;
        ExternalOctets = externalOctets;
    }


    /// <summary>Wraps a same-document node-set result.</summary>
    /// <param name="nodeSet">The dereferenced node-set.</param>
    /// <returns>The wrapped result.</returns>
    internal static XmlDereferenceResult FromNodeSet(XmlNodeSet nodeSet)
    {
        return new XmlDereferenceResult(isNodeSet: true, nodeSet, externalOctets: null);
    }


    /// <summary>Wraps an external-octets result.</summary>
    /// <param name="externalOctets">The octets the resolver produced; ownership passes to the caller.</param>
    /// <returns>The wrapped result.</returns>
    internal static XmlDereferenceResult FromExternalOctets(PooledMemory externalOctets)
    {
        return new XmlDereferenceResult(isNodeSet: false, nodeSet: default, externalOctets);
    }
}


/// <summary>
/// Resolves a <c>URI</c> attribute value into the <see cref="XmlDereferenceResult"/> section 4.3.3.1–4.3.3.3
/// of <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> defines for it. Consumed internally by the reference-processing/transform-chain engine; not part
/// of this leaf's public surface.
/// </summary>
/// <remarks>
/// <para>
/// A same-document reference — defined at line 751 as "a URI-Reference that consists of a hash sign ('#')
/// followed by a fragment or alternatively consists of an empty URI" — resolves to a node-set entirely
/// inside this leaf, per the four-form table below: the null URI and the three recognized fragment forms
/// (bare-name/shortname XPointer, <c>#xpointer(/)</c>, <c>#xpointer(id(...))</c>). Any other fragment is
/// <see cref="XmlSignatureProcessingFailure.UnsupportedXPointer"/>: the MUST set of section 4.3.3.2 plus the
/// two RECOMMENDED scheme-based forms this leaf needs to support the six 6.3(d) with-comments
/// canonicalization algorithms, and nothing beyond that discouraged surface (line 763).
/// </para>
/// <para>
/// A non-same-document (external) reference never touches the network or the filesystem here — the house
/// rule against I/O inside a library leaf — and dereferences only through a caller-supplied
/// <see cref="XmlReferenceResolver"/>; a missing resolver or one that returns <see langword="false"/> both
/// surface identically as <see cref="XmlSignatureProcessingFailure.ExternalReferenceUnresolved"/>, satisfying
/// the section 4.3.3.2 MUST that such a dereference "MUST be an octet stream" by construction — the resolver
/// signature has no node-set return shape at all.
/// </para>
/// </remarks>
internal static class XmlReferenceDereferencer
{
    /// <summary>The literal fragment of the whole-document, comments-retained scheme-based XPointer.</summary>
    private static ReadOnlySpan<byte> XPointerRootFragment => "xpointer(/)"u8;

    /// <summary>The literal prefix of the by-id, comments-retained scheme-based XPointer.</summary>
    private static ReadOnlySpan<byte> XPointerIdPrefix => "xpointer(id("u8;

    /// <summary>The literal suffix of the by-id, comments-retained scheme-based XPointer.</summary>
    private static ReadOnlySpan<byte> XPointerIdSuffix => "))"u8;


    /// <summary>
    /// Dereferences a <c>Reference</c>'s <c>URI</c> attribute into the node-set or external octets it
    /// identifies.
    /// </summary>
    /// <param name="table">The document the <paramref name="reference"/> was read from.</param>
    /// <param name="reference">The reference whose <c>URI</c> is dereferenced.</param>
    /// <param name="resolver">The external-dereference delegate, or <see langword="null"/> when the caller
    /// supplies none — every external reference then refuses with
    /// <see cref="XmlSignatureProcessingFailure.ExternalReferenceUnresolved"/>.</param>
    /// <param name="pool">The pool an external resolver's octets are rented from.</param>
    /// <param name="result">The dereferenced result on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the URI dereferenced.</returns>
    internal static bool TryDereference(XmlNodeTable table, XmlReference reference, XmlReferenceResolver? resolver, BaseMemoryPool pool, out XmlDereferenceResult result, out XmlSignatureProcessingError error)
    {
        return TryDereference(table, reference.HasUri, reference.Uri, resolver, pool, out result, out error);
    }


    /// <summary>
    /// Dereferences a <c>URI</c> attribute value into the node-set or external octets it identifies, per the
    /// four-form table below.
    /// </summary>
    /// <param name="table">The document the <c>URI</c> attribute is read against for same-document forms.</param>
    /// <param name="hasUri">Whether the <c>URI</c> attribute is present at all.</param>
    /// <param name="uri">The <c>URI</c> attribute value, exact-character; meaningless when
    /// <paramref name="hasUri"/> is <see langword="false"/>.</param>
    /// <param name="resolver">The external-dereference delegate, or <see langword="null"/>.</param>
    /// <param name="pool">The pool an external resolver's octets are rented from.</param>
    /// <param name="result">The dereferenced result on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XmlSignatureProcessingFailure.UriOmitted"/> when <paramref name="hasUri"/> is
    /// <see langword="false"/> (the section 4.3.3.1 "application context" case, refused here);
    /// <see cref="XmlSignatureProcessingFailure.UnsupportedXPointer"/> for an unrecognized same-document
    /// fragment; <see cref="XmlSignatureProcessingFailure.IdNotFound"/>/<see cref="XmlSignatureProcessingFailure.DuplicateId"/>
    /// from <see cref="XmlNodeTable.TryFindElementById"/> for a by-id form; and
    /// <see cref="XmlSignatureProcessingFailure.ExternalReferenceUnresolved"/> for a non-same-document
    /// reference the resolver could not, or was not asked to, resolve.</param>
    /// <returns><see langword="true"/> when the URI dereferenced.</returns>
    internal static bool TryDereference(XmlNodeTable table, bool hasUri, ReadOnlySpan<byte> uri, XmlReferenceResolver? resolver, BaseMemoryPool pool, out XmlDereferenceResult result, out XmlSignatureProcessingError error)
    {
        result = default;
        if(!hasUri)
        {
            error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.UriOmitted, 0);

            return false;
        }

        if(!IsSameDocumentReference(uri))
        {
            PooledMemory? externalOctets = null;
            bool isResolved = resolver is not null && resolver(uri, pool, out externalOctets);
            if(!isResolved || externalOctets is null)
            {
                //A misbehaving resolver that returns true with null octets is treated identically to one
                //that returns false: this leaf never trusts a resolver's own success signal blindly.
                externalOctets?.Dispose();
                error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.ExternalReferenceUnresolved, 0);

                return false;
            }

            result = XmlDereferenceResult.FromExternalOctets(externalOctets);
            error = default;

            return true;
        }

        if(uri.IsEmpty)
        {
            //Chapeau of section 4.3.3.3: the null URI MUST result in a node-set that includes every
            //non-comment node of the document — the "no fragment identifier" branch of step 4.
            result = XmlDereferenceResult.FromNodeSet(XmlNodeSet.WholeDocument(table).WithoutComments());
            error = default;

            return true;
        }

        ReadOnlySpan<byte> fragment = uri[1..];
        if(fragment.SequenceEqual(XPointerRootFragment))
        {
            //'#xpointer(/)' MUST be interpreted to identify the root node (section 4.3.3.2); scheme-based,
            //so step 4 of section 4.3.3.3 does not delete comments.
            result = XmlDereferenceResult.FromNodeSet(XmlNodeSet.WholeDocument(table));
            error = default;

            return true;
        }

        if(TryParseXPointerIdFragment(fragment, out ReadOnlySpan<byte> byIdValue))
        {
            //The quoted literal itself validates as NCName — the same production
            //IsNcNameFragment enforces on the bare-name path below, since '#element(ID)' (section 4.3.3.2,
            //which '#xpointer(id('ID'))' MUST be interpreted to identify the same way as) identifies an
            //element by its XML Signature Id, and no Id this leaf ever recognizes (an un-prefixed
            //Id attribute or xml:id, both typed NCName-shaped by their own schemas) can BE anything an
            //NCName is not. An empty or non-NCName literal — '#xpointer(id(''))' included — therefore
            //refuses here rather than reaching TryFindElementById with an identifier no legitimate document
            //could ever carry.
            if(!IsNcNameFragment(byIdValue))
            {
                error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.UnsupportedXPointer, 0);

                return false;
            }

            //'#xpointer(id('ID'))' MUST be interpreted to identify the element node identified by
            //'#element(ID)' (section 4.3.3.2); scheme-based, so comments are retained.
            if(!table.TryFindElementById(byIdValue, out int byIdElementIndex, out error))
            {
                return false;
            }

            result = XmlDereferenceResult.FromNodeSet(XmlNodeSet.ElementSubtree(table, byIdElementIndex));
            error = default;

            return true;
        }

        if(IsNcNameFragment(fragment))
        {
            //A bare-name (shortname) XPointer: MUST-support form (section 4.3.3.2), and the shortname
            //branch of step 4 (section 4.3.3.3) deletes comments.
            //
            //RECORDED DEVIATION: the fragment matches an Id value LITERALLY, with no
            //percent-decoding, even though section 4.3.3.1 requires "the mapping from this attribute's
            //value to a URI reference MUST be performed as specified in section 3.2.17 of [XMLSCHEMA
            //Datatypes]" — under that mapping 'URI="#%C3%A4"' would name the element whose Id is 'ä'.
            //Grounds: exact-character discipline governs every identifier comparison in this leaf (the same
            //posture this library applies to Id attribute names themselves), and percent-decoding a same-document
            //fragment before an Id lookup is a second, decoder-dependent reading of attacker-controlled
            //bytes with no XML Signature security benefit — fail-closed against it rather than reproduce
            //it. The consequence is refusal (IsNcNameFragment rejects '%'), never a wrong match.
            if(!table.TryFindElementById(fragment, out int bareNameElementIndex, out error))
            {
                return false;
            }

            result = XmlDereferenceResult.FromNodeSet(XmlNodeSet.ElementSubtree(table, bareNameElementIndex).WithoutComments());
            error = default;

            return true;
        }

        error = new XmlSignatureProcessingError(XmlSignatureProcessingFailure.UnsupportedXPointer, 0);

        return false;
    }


    /// <summary>
    /// Tells whether a <c>URI</c> attribute value is a same-document reference per the definition at line
    /// 751: an empty URI, or a URI consisting of a hash sign followed by a fragment. A fragment preceded by
    /// other URI content (for example <c>somefile.xml#chapter1</c>) is NOT same-document — its fragment
    /// meaning is the external resource's own, outside this leaf's dereferencing (section 4.3.3.2's
    /// RECOMMEND against relying on such fragments at all).
    /// </summary>
    /// <param name="uri">The <c>URI</c> attribute value.</param>
    /// <returns><see langword="true"/> when the value is a same-document reference.</returns>
    private static bool IsSameDocumentReference(ReadOnlySpan<byte> uri)
    {
        return uri.IsEmpty || uri[0] == (byte)'#';
    }


    /// <summary>
    /// Parses the <c>xpointer(id(...))</c> scheme-based by-id fragment, accepting both XPath 1.0
    /// <c>Literal</c> quote kinds per the XPointer syntax: <c>xpointer(id('ID'))</c> or
    /// <c>xpointer(id("ID"))</c>, with no whitespace tolerance beyond this exact shape — whitespace variance
    /// is a refusal, not a tolerance.
    /// </summary>
    /// <param name="fragment">The fragment octets after the leading <c>#</c>.</param>
    /// <param name="idValue">The quoted identifier's content on success.</param>
    /// <returns><see langword="true"/> when the fragment matches the by-id scheme-based form exactly.</returns>
    private static bool TryParseXPointerIdFragment(ReadOnlySpan<byte> fragment, out ReadOnlySpan<byte> idValue)
    {
        idValue = default;
        if(!fragment.StartsWith(XPointerIdPrefix) || !fragment.EndsWith(XPointerIdSuffix))
        {
            return false;
        }

        ReadOnlySpan<byte> inner = fragment[XPointerIdPrefix.Length..^XPointerIdSuffix.Length];
        if(inner.Length < 2)
        {
            return false;
        }

        byte quote = inner[0];
        bool isQuoteCharacter = quote == (byte)'\'' || quote == (byte)'"';
        if(!isQuoteCharacter || inner[^1] != quote)
        {
            return false;
        }

        ReadOnlySpan<byte> candidate = inner[1..^1];
        if(candidate.IndexOf(quote) >= 0)
        {
            //An unescaped occurrence of the delimiting quote inside the literal has no legal reading under
            //the XPath 1.0 Literal production (no escape mechanism); refused rather than guessed at.
            return false;
        }

        idValue = candidate;

        return true;
    }


    /// <summary>
    /// Tells whether the fragment matches production <c>NCName</c> of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3 — the bare-name (shortname) XPointer form: a non-empty, colon-free name.
    /// Shared with <see cref="XAdESIncludeUriProcessing"/>'s clause 5.1.4.4.2.2 processing model:
    /// XAdES's <c>Include</c> mechanism recognizes exactly this same bare-name form,
    /// so its fragment validation reuses this production check rather than a second implementation of it.
    /// </summary>
    /// <param name="fragment">The fragment octets after the leading <c>#</c>.</param>
    /// <returns><see langword="true"/> when the fragment is a well-formed <c>NCName</c>.</returns>
    internal static bool IsNcNameFragment(ReadOnlySpan<byte> fragment)
    {
        if(fragment.IsEmpty)
        {
            return false;
        }

        int index = 0;
        bool isFirst = true;
        while(index < fragment.Length)
        {
            if(Rune.DecodeFromUtf8(fragment[index..], out Rune rune, out int consumed) != OperationStatus.Done)
            {
                return false;
            }

            bool isValid = isFirst ? XmlCharacters.IsNameStartCharacter(rune.Value) : XmlCharacters.IsNameCharacter(rune.Value);
            if(!isValid)
            {
                return false;
            }

            index += consumed;
            isFirst = false;
        }

        return true;
    }
}
